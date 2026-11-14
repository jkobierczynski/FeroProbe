//! Raw-socket TCP port scans: SYN, and the scans that send other flag
//! combinations (FIN, NULL, Xmas, ACK, Window, Maimon, or any `--scanflags`).
//!
//! The SYN ("half-open") scan sends a bare SYN to each port:
//!
//! - **open**: the host replied SYN-ACK (the kernel then resets the half-open
//!   connection for us, since no local socket owns it)
//! - **closed**: the host replied with a RST
//! - **filtered**: no reply after all retries, or an ICMP unreachable error
//!
//! The other scans rely on RFC 793: a closed port answers any segment
//! without SYN or RST with a reset, while an open port drops one that has no
//! SYN, RST or ACK. So FIN, NULL (no flags), Xmas (FIN, PSH, URG) and Maimon
//! (FIN, ACK) scans report **closed** on a reset and **open|filtered** on
//! silence. The ACK scan maps firewall rules instead: a reset means
//! **unfiltered** (open or closed), silence means **filtered**. The Window
//! scan sends the same ACK but calls a port **open** when the reset carries a
//! non-zero window, which some systems do for listening ports. Windows and
//! some other stacks reset every port, so FIN, NULL and Xmas show them all as
//! closed; most systems other than old BSDs reset Maimon probes too.
//!
//! None of them complete a handshake. They need root (or `CAP_NET_RAW`).
//! IPv4 and IPv6 targets can be mixed. Linux only: other systems do not
//! deliver TCP replies to raw sockets.

use std::io;

use crate::model::{HostResult, PortState, ScanConfig, reason};
use crate::packet::{self, TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN, TCP_URG};
use crate::target::Target;

/// Which raw TCP scan to run. Besides the flags sent by default, this
/// decides how answers are read, also when `--scanflags` overrides the flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TcpScanKind {
    /// `-sS`: SYN.
    Syn,
    /// `-sF`: FIN.
    Fin,
    /// `-sN`: no flags at all.
    Null,
    /// `-sX`: FIN, PSH and URG, "lit up like a Christmas tree".
    Xmas,
    /// `-sA`: ACK, to map firewall rules.
    Ack,
    /// `-sW`: ACK, reading the window size of the reset.
    Window,
    /// `-sM`: FIN and ACK.
    Maimon,
}

impl TcpScanKind {
    /// The flags this scan sends unless `--scanflags` says otherwise.
    pub fn default_flags(self) -> u8 {
        match self {
            TcpScanKind::Syn => TCP_SYN,
            TcpScanKind::Fin => TCP_FIN,
            TcpScanKind::Null => 0,
            TcpScanKind::Xmas => TCP_FIN | TCP_PSH | TCP_URG,
            TcpScanKind::Ack | TcpScanKind::Window => TCP_ACK,
            TcpScanKind::Maimon => TCP_FIN | TCP_ACK,
        }
    }

    /// nmap's name for the scan, as in the XML `scaninfo` element.
    pub fn name(self) -> &'static str {
        match self {
            TcpScanKind::Syn => "syn",
            TcpScanKind::Fin => "fin",
            TcpScanKind::Null => "null",
            TcpScanKind::Xmas => "xmas",
            TcpScanKind::Ack => "ack",
            TcpScanKind::Window => "window",
            TcpScanKind::Maimon => "maimon",
        }
    }

    /// The state of a port that never answered.
    pub fn no_response(self) -> PortState {
        match self {
            TcpScanKind::Syn | TcpScanKind::Ack | TcpScanKind::Window => PortState::Filtered,
            TcpScanKind::Fin | TcpScanKind::Null | TcpScanKind::Xmas | TcpScanKind::Maimon => {
                PortState::OpenFiltered
            }
        }
    }

    /// What a TCP answer to one of our probes says about the port, or
    /// `None` if this scan does not use that kind of answer.
    pub fn classify(self, tcp: &packet::Tcp) -> Option<(PortState, &'static str)> {
        if tcp.flags & (TCP_SYN | TCP_ACK) == TCP_SYN | TCP_ACK {
            return (self == TcpScanKind::Syn).then_some((PortState::Open, reason::SYN_ACK));
        }
        if tcp.flags & TCP_RST == 0 {
            return None;
        }
        let state = match self {
            TcpScanKind::Ack => PortState::Unfiltered,
            TcpScanKind::Window if tcp.window > 0 => PortState::Open,
            _ => PortState::Closed,
        };
        Some((state, reason::RESET))
    }
}

/// A raw TCP scan: how to read the answers, and the flags to send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawTcpScan {
    pub kind: TcpScanKind,
    pub flags: u8,
}

impl RawTcpScan {
    /// The scan with its usual flags.
    pub fn new(kind: TcpScanKind) -> Self {
        Self {
            kind,
            flags: kind.default_flags(),
        }
    }

    /// Whether a TCP segment from the target answers our probe. A host
    /// resets a segment that carries an ACK with that acknowledgment number
    /// as its sequence number, and acknowledges any other segment just past
    /// our sequence number: by one for each of SYN and FIN it took into
    /// account, which for odd combinations like SYN+FIN varies by system.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))] // only the Linux scanner reads replies
    fn answers(&self, tcp: &packet::Tcp, sport: u16, cookie: u32) -> bool {
        if tcp.dport != sport {
            return false;
        }
        if self.flags & TCP_ACK != 0 {
            tcp.seq == cookie
        } else {
            let max = u32::from(self.flags & TCP_SYN != 0) + u32::from(self.flags & TCP_FIN != 0);
            tcp.ack.wrapping_sub(cookie) <= max
        }
    }
}

/// Parse nmap's `--scanflags` value: flag names run together in any order
/// and case ("SYNFIN", "urgpshfin"), or a number ("9", "0x29").
pub fn parse_scanflags(s: &str) -> Result<u8, String> {
    let s = s.trim();
    let number = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(u8::from_str_radix(hex, 16))
    } else if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
        Some(s.parse::<u8>())
    } else {
        None
    };
    if let Some(n) = number {
        return n.map_err(|_| format!("--scanflags: {s} is not a number from 0 to 255"));
    }
    const NAMES: [(&str, u8); 8] = [
        ("FIN", packet::TCP_FIN),
        ("SYN", packet::TCP_SYN),
        ("RST", packet::TCP_RST),
        ("PSH", packet::TCP_PSH),
        ("ACK", packet::TCP_ACK),
        ("URG", packet::TCP_URG),
        ("ECE", packet::TCP_ECE),
        ("CWR", packet::TCP_CWR),
    ];
    let upper = s.to_ascii_uppercase();
    let mut rest = upper.as_str();
    let mut flags = 0;
    while !rest.is_empty() {
        let Some((name, bit)) = NAMES.iter().find(|(n, _)| rest.starts_with(n)) else {
            return Err(format!(
                "--scanflags: unknown flag in {s:?}; use URG, ACK, PSH, RST, SYN, FIN, ECE, CWR or a number"
            ));
        };
        flags |= bit;
        rest = &rest[name.len()..];
    }
    if s.is_empty() {
        return Err("--scanflags: give flag names like SYNFIN or a number".into());
    }
    Ok(flags)
}

/// The reason an ICMP destination-unreachable error gives, for the codes
/// nmap treats as "filtered" for TCP probes. IPv4 type 3, IPv6 type 1.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))] // only the Linux scanner reads replies
fn unreach_reason(v6: bool, code: u8) -> Option<&'static str> {
    if v6 {
        Some(match code {
            0 => reason::NET_UNREACH,
            3 => reason::HOST_UNREACH,
            4 => reason::PORT_UNREACH,
            _ => reason::ADMIN_PROHIBITED,
        })
    } else {
        match code {
            0 => Some(reason::NET_UNREACH),
            1 => Some(reason::HOST_UNREACH),
            2 => Some(reason::PROTO_UNREACH),
            3 => Some(reason::PORT_UNREACH),
            9 | 10 | 13 => Some(reason::ADMIN_PROHIBITED),
            _ => None,
        }
    }
}

/// The TCP probe an ICMP unreachable error is about: its destination,
/// source port, destination port and sequence number, with the reason.
/// `data` is what a raw ICMP socket returns: the IPv4 header and message,
/// or for ICMPv6 the message alone.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))] // only the Linux scanner reads replies
pub(crate) fn parse_tcp_unreach(
    data: &[u8],
    v6: bool,
) -> Option<(std::net::IpAddr, u16, u16, u32, &'static str)> {
    let e = packet::parse_icmp_tcp_error(data, v6)?;
    let unreach = if v6 {
        packet::ICMPV6_DEST_UNREACH
    } else {
        packet::ICMP_DEST_UNREACH
    };
    if e.kind != unreach {
        return None;
    }
    let why = unreach_reason(v6, e.code)?;
    Some((e.dst, e.sport, e.dport, e.seq, why))
}

/// Run a SYN scan of every port on every target.
pub async fn syn_scan(
    targets: &[Target],
    ports: &[u16],
    cfg: &ScanConfig,
) -> io::Result<Vec<HostResult>> {
    raw_tcp_scan(targets, ports, cfg, RawTcpScan::new(TcpScanKind::Syn)).await
}

/// Run a raw TCP scan (SYN, FIN, NULL, Xmas, ACK, Window, Maimon or custom
/// flags) of every port on every target.
pub async fn raw_tcp_scan(
    targets: &[Target],
    ports: &[u16],
    cfg: &ScanConfig,
    scan: RawTcpScan,
) -> io::Result<Vec<HostResult>> {
    let (targets, ports, cfg) = (targets.to_vec(), ports.to_vec(), cfg.clone());
    tokio::task::spawn_blocking(move || imp::scan_blocking(&targets, &ports, &cfg, scan))
        .await
        .map_err(io::Error::other)?
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::*;

    pub(super) fn scan_blocking(
        _: &[Target],
        _: &[u16],
        _: &ScanConfig,
        scan: RawTcpScan,
    ) -> io::Result<Vec<HostResult>> {
        let what = match scan.kind {
            TcpScanKind::Syn => "SYN scan is",
            _ => "Raw TCP scans (-sF, -sN, -sX, -sA, -sW, -sM) are",
        };
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("{what} only supported on Linux for now; use a connect scan (-sT)"),
        ))
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;

    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use socket2::{Domain, Protocol as SockProto, SockAddr, Socket};

    use crate::connect::is_network_error;
    use crate::model::{PortResult, Protocol};
    use crate::raw::{Pacer, Rng, raw_socket_in, receive_loop, send_with_backoff, source_addr_for};
    use crate::target::socket_addr;

    /// An answer seen by a receiver thread: host index, port, state,
    /// reason, time.
    type Answer = (usize, u16, PortState, &'static str, Instant);

    fn result(
        port: u16,
        state: PortState,
        reason: &'static str,
        rtt_ms: Option<f64>,
    ) -> PortResult {
        PortResult {
            port,
            protocol: Protocol::Tcp,
            state,
            reason,
            rtt_ms,
            service: None,
        }
    }

    pub(super) fn scan_blocking(
        targets: &[Target],
        ports: &[u16],
        cfg: &ScanConfig,
        scan: RawTcpScan,
    ) -> io::Result<Vec<HostResult>> {
        let addrs: Vec<IpAddr> = targets.iter().map(|t| t.addr).collect();
        let index: Arc<HashMap<IpAddr, usize>> =
            Arc::new(addrs.iter().enumerate().map(|(i, a)| (*a, i)).collect());

        // A send and a receive socket for each address family in use.
        let open = |domain: Domain| -> io::Result<(Socket, Socket)> {
            let send = raw_socket_in(domain, SockProto::TCP)?;
            let recv = raw_socket_in(domain, SockProto::TCP)?;
            recv.set_read_timeout(Some(Duration::from_millis(50)))?;
            let _ = recv.set_recv_buffer_size(8 << 20);
            Ok((send, recv))
        };
        let v4 = if addrs.iter().any(IpAddr::is_ipv4) {
            Some(open(Domain::IPV4)?)
        } else {
            None
        };
        let v6 = if addrs.iter().any(IpAddr::is_ipv6) {
            match open(Domain::IPV6) {
                Ok(pair) => Some(pair),
                // No IPv6 on this system: its targets are unreachable, and
                // are marked so below when no source address is found.
                Err(e) if e.raw_os_error() == Some(libc::EAFNOSUPPORT) => None,
                Err(e) => return Err(e),
            }
        } else {
            None
        };
        // ICMP errors only refine "no answer" into a reason, so a family
        // whose ICMP socket cannot be opened is scanned without them.
        let icmp = |domain: Domain, proto: SockProto| -> Option<Socket> {
            let sock = raw_socket_in(domain, proto).ok()?;
            sock.set_read_timeout(Some(Duration::from_millis(50)))
                .ok()?;
            Some(sock)
        };
        let icmp4 = v4
            .is_some()
            .then(|| icmp(Domain::IPV4, SockProto::ICMPV4))
            .flatten();
        let icmp6 = v6
            .is_some()
            .then(|| icmp(Domain::IPV6, SockProto::ICMPV6))
            .flatten();

        let mut rng = Rng::new();
        let sport = 40000 + (rng.next_u32() % 20000) as u16;
        let cookie = rng.next_u32();
        let ack = if scan.flags & TCP_ACK != 0 { cookie } else { 0 };
        let no_answer = scan.kind.no_response();

        let mut results: HashMap<(usize, u16), PortResult> = HashMap::new();

        // Hosts we cannot route to get every port marked filtered up front.
        let mut sources: Vec<Option<IpAddr>> = Vec::with_capacity(addrs.len());
        for (h, addr) in addrs.iter().enumerate() {
            match source_addr_for(*addr) {
                Ok(src) => sources.push(Some(src)),
                Err(e) if is_network_error(&e) => {
                    sources.push(None);
                    for &p in ports {
                        results.insert(
                            (h, p),
                            result(p, PortState::Filtered, reason::UNREACHABLE, None),
                        );
                    }
                }
                Err(e) => return Err(e),
            }
        }

        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel::<Answer>();
        let mut send_socks: [Option<Socket>; 2] = [None, None];
        let mut receivers = Vec::new();
        for (slot, pair) in [v4, v6].into_iter().enumerate() {
            let Some((send, recv)) = pair else { continue };
            send_socks[slot] = Some(send);
            let (stop, index, tx) = (Arc::clone(&stop), Arc::clone(&index), tx.clone());
            receivers.push(std::thread::spawn(move || {
                receive_loop(recv, &stop, &tx, |data, from, at| {
                    let (h, port, state, why) =
                        tcp_answer(data, from, &index, &scan, sport, cookie)?;
                    Some((h, port, state, why, at))
                });
            }));
        }
        for (v6, sock) in [(false, icmp4), (true, icmp6)] {
            let Some(sock) = sock else { continue };
            let (stop, index, tx) = (Arc::clone(&stop), Arc::clone(&index), tx.clone());
            receivers.push(std::thread::spawn(move || {
                receive_loop(sock, &stop, &tx, |data, _, at| {
                    let (dst, sp, dp, seq, why) = parse_tcp_unreach(data, v6)?;
                    if sp != sport || seq != cookie {
                        return None;
                    }
                    Some((*index.get(&dst)?, dp, PortState::Filtered, why, at))
                });
            }));
        }
        drop(tx);

        let mut sent_at: HashMap<(usize, u16), Instant> = HashMap::new();

        // Port-major order spreads the probes across hosts.
        let mut pending: Vec<(usize, u16)> = ports
            .iter()
            .flat_map(|&p| (0..addrs.len()).map(move |h| (h, p)))
            .filter(|k| !results.contains_key(k))
            .collect();

        // Probes settled before any is sent (no route) count as done.
        crate::progress::tick((addrs.len() * ports.len() - pending.len()) as u64);

        let outcome = (|| -> io::Result<()> {
            for round in 0..=cfg.retries {
                let mut pacer = Pacer::for_config(cfg);
                for &(h, p) in &pending {
                    if round == 0 {
                        crate::progress::tick(1);
                    }
                    if cfg.expired() {
                        return Err(ScanConfig::timed_out());
                    }
                    let Some(src) = sources[h] else { continue };
                    // Answered by a reply that came in during this round.
                    if results.contains_key(&(h, p)) {
                        continue;
                    }
                    let Some(send_sock) = send_socks[usize::from(addrs[h].is_ipv6())].as_ref()
                    else {
                        // No socket for this family (no IPv6 here).
                        results.entry((h, p)).or_insert(result(
                            p,
                            PortState::Filtered,
                            reason::UNREACHABLE,
                            None,
                        ));
                        continue;
                    };
                    pacer.wait();
                    // A slow template can wait long enough for an answer to
                    // the previous round's probe to arrive: record it against
                    // the old send time and do not send again.
                    while let Ok(a) = rx.try_recv() {
                        record(&mut results, &sent_at, a);
                    }
                    if results.contains_key(&(h, p)) {
                        continue;
                    }
                    sent_at.insert((h, p), Instant::now());
                    let to = socket_addr(addrs[h], 0);
                    // The SYN scan keeps its MSS option, which makes the
                    // probe look like an ordinary connection attempt.
                    let sent = if scan.flags == TCP_SYN {
                        let pkt = packet::tcp_syn(src, addrs[h], sport, p, cookie);
                        send_with_backoff(send_sock, &pkt, to)
                    } else {
                        let pkt =
                            packet::tcp_probe(src, addrs[h], sport, p, cookie, ack, scan.flags);
                        send_with_backoff(send_sock, &pkt, to)
                    };
                    match sent {
                        Ok(()) => {}
                        Err(e) if is_network_error(&e) => {
                            results.entry((h, p)).or_insert(result(
                                p,
                                PortState::Filtered,
                                reason::UNREACHABLE,
                                None,
                            ));
                        }
                        Err(e) => return Err(e),
                    }
                    while let Ok(a) = rx.try_recv() {
                        record(&mut results, &sent_at, a);
                    }
                }
                // Wait for stragglers, but stop as soon as every probe is answered.
                let mut unanswered = pending.iter().filter(|k| !results.contains_key(k)).count();
                let mut deadline = Instant::now() + cfg.timeout;
                if let Some(limit) = cfg.deadline {
                    deadline = deadline.min(limit);
                }
                while unanswered > 0
                    && let Some(left) = deadline.checked_duration_since(Instant::now())
                {
                    match rx.recv_timeout(left) {
                        Ok(a) => {
                            if record(&mut results, &sent_at, a) {
                                unanswered -= 1;
                            }
                        }
                        Err(_) => break,
                    }
                }
                pending.retain(|k| !results.contains_key(k));
                if pending.is_empty() {
                    break;
                }
                if cfg.expired() {
                    return Err(ScanConfig::timed_out());
                }
            }
            Ok(())
        })();

        stop.store(true, Ordering::Relaxed);
        for r in receivers {
            let _ = r.join();
        }
        outcome?;

        Ok(targets
            .iter()
            .enumerate()
            .map(|(h, t)| {
                let mut host = HostResult::new(t.addr, t.hostname.clone());
                host.ports = ports
                    .iter()
                    .map(|&p| {
                        results
                            .remove(&(h, p))
                            .unwrap_or_else(|| result(p, no_answer, reason::NO_RESPONSE, None))
                    })
                    .collect();
                host.sort_ports();
                host
            })
            .collect())
    }

    /// Store the first answer for a probe, with its round-trip time.
    /// Returns whether it was new.
    fn record(
        results: &mut HashMap<(usize, u16), PortResult>,
        sent_at: &HashMap<(usize, u16), Instant>,
        (h, p, state, why, at): Answer,
    ) -> bool {
        if results.contains_key(&(h, p)) {
            return false;
        }
        let rtt_ms = sent_at.get(&(h, p)).map(|s| {
            (at.saturating_duration_since(*s).as_secs_f64() * 1_000_000.0).round() / 1000.0
        });
        results.insert((h, p), result(p, state, why, rtt_ms));
        true
    }

    /// A TCP segment off the raw socket, if it answers one of our probes:
    /// from a target, to our source port, matching our sequence cookie.
    /// IPv4 raw sockets return the IP header, IPv6 ones only the segment,
    /// with the sender's address.
    fn tcp_answer(
        data: &[u8],
        from: &SockAddr,
        index: &HashMap<IpAddr, usize>,
        scan: &RawTcpScan,
        sport: u16,
        cookie: u32,
    ) -> Option<(usize, u16, PortState, &'static str)> {
        let (src, segment) = match from.as_socket() {
            Some(sa) if sa.is_ipv6() => (sa.ip(), data),
            _ => {
                let ip = packet::parse_ipv4(data)?;
                if ip.protocol != packet::IPPROTO_TCP {
                    return None;
                }
                (IpAddr::V4(ip.src), ip.payload)
            }
        };
        let tcp = packet::parse_tcp(segment)?;
        if !scan.answers(&tcp, sport, cookie) {
            return None;
        }
        let &h = index.get(&src)?;
        let (state, why) = scan.kind.classify(&tcp)?;
        Some((h, tcp.sport, state, why))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::raw::raw_sockets_available;

        /// Raw sockets need root. CI runs the tests with sudo and sets
        /// FEROPROBE_REQUIRE_RAW=1 so these cannot silently pass there.
        fn privileged() -> bool {
            let ok = raw_sockets_available();
            if !ok {
                assert!(
                    std::env::var_os("FEROPROBE_REQUIRE_RAW").is_none(),
                    "FEROPROBE_REQUIRE_RAW is set but raw sockets are unavailable"
                );
                eprintln!("note: no raw-socket privileges, SYN scan test not run");
            }
            ok
        }

        #[test]
        fn syn_scan_localhost() {
            if !privileged() {
                return;
            }
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let open = listener.local_addr().unwrap().port();
            let closed = {
                let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                l.local_addr().unwrap().port()
            };
            let cfg = ScanConfig {
                timeout: Duration::from_millis(500),
                ..Default::default()
            };
            let target = Target::new("127.0.0.1".parse().unwrap());
            let hosts = scan_blocking(
                &[target],
                &[open, closed],
                &cfg,
                RawTcpScan::new(TcpScanKind::Syn),
            )
            .unwrap();
            let state_of = |p| hosts[0].ports.iter().find(|r| r.port == p).unwrap().clone();
            assert_eq!(state_of(open).state, PortState::Open);
            assert_eq!(state_of(open).reason, reason::SYN_ACK);
            assert_eq!(state_of(closed).state, PortState::Closed);
            assert_eq!(state_of(closed).reason, reason::RESET);
        }

        #[test]
        fn deadline_stops_the_scan() {
            if !privileged() {
                return;
            }
            let cfg = ScanConfig {
                deadline: Some(Instant::now()),
                ..Default::default()
            };
            let target = Target::new("127.0.0.1".parse().unwrap());
            let err = scan_blocking(
                &[target],
                &[1, 2, 3],
                &cfg,
                RawTcpScan::new(TcpScanKind::Syn),
            )
            .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        }

        #[test]
        fn flag_scans_localhost() {
            if !privileged() {
                return;
            }
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let open = listener.local_addr().unwrap().port();
            let closed = {
                let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                l.local_addr().unwrap().port()
            };
            let cfg = ScanConfig {
                timeout: Duration::from_millis(300),
                retries: 0,
                ..Default::default()
            };
            let target = Target::new("127.0.0.1".parse().unwrap());
            // What Linux does: it drops FIN, NULL and Xmas probes to a
            // listening port, resets everything else, always with window 0.
            let open_filtered = (PortState::OpenFiltered, reason::NO_RESPONSE);
            let reset = (PortState::Closed, reason::RESET);
            let unfiltered = (PortState::Unfiltered, reason::RESET);
            let cases = [
                (TcpScanKind::Fin, open_filtered, reset),
                (TcpScanKind::Null, open_filtered, reset),
                (TcpScanKind::Xmas, open_filtered, reset),
                (TcpScanKind::Ack, unfiltered, unfiltered),
                (TcpScanKind::Window, reset, reset),
                (TcpScanKind::Maimon, reset, reset),
            ];
            for (kind, want_open, want_closed) in cases {
                let hosts = scan_blocking(
                    std::slice::from_ref(&target),
                    &[open, closed],
                    &cfg,
                    RawTcpScan::new(kind),
                )
                .unwrap();
                let got = |p| {
                    let r = hosts[0].ports.iter().find(|r| r.port == p).unwrap();
                    (r.state, r.reason)
                };
                assert_eq!(got(open), want_open, "{kind:?} open port");
                assert_eq!(got(closed), want_closed, "{kind:?} closed port");
            }
            // Custom flags read as a SYN scan: SYN+PSH still opens. (Linux
            // drops SYN+FIN to a listening port, so that would be filtered.)
            let custom = RawTcpScan {
                kind: TcpScanKind::Syn,
                flags: TCP_SYN | TCP_PSH,
            };
            let hosts = scan_blocking(&[target], &[open, closed], &cfg, custom).unwrap();
            let state_of = |p| hosts[0].ports.iter().find(|r| r.port == p).unwrap().state;
            assert_eq!(state_of(open), PortState::Open);
            assert_eq!(state_of(closed), PortState::Closed);
        }

        #[test]
        fn syn_scan_ipv6_and_ipv4_together() {
            if !privileged() || !crate::testutil::ipv6_loopback() {
                return;
            }
            // One listener per family, so the test does not rely on
            // dual-stack sockets (net.ipv6.bindv6only).
            let v6 = std::net::TcpListener::bind("[::1]:0").unwrap();
            let v4 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let open6 = v6.local_addr().unwrap().port();
            let open4 = v4.local_addr().unwrap().port();
            // A port free on IPv4 may be the IPv6 listener's, so skip both.
            let closed = std::iter::repeat_with(|| {
                let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                l.local_addr().unwrap().port()
            })
            .find(|p| *p != open4 && *p != open6)
            .unwrap();
            let cfg = ScanConfig {
                timeout: Duration::from_millis(500),
                ..Default::default()
            };
            let targets = [
                Target::new("::1".parse().unwrap()),
                Target::new("127.0.0.1".parse().unwrap()),
            ];
            let hosts = scan_blocking(
                &targets,
                &[open6, open4, closed],
                &cfg,
                RawTcpScan::new(TcpScanKind::Syn),
            )
            .unwrap();
            for host in &hosts {
                let state_of = |p| host.ports.iter().find(|r| r.port == p).unwrap().state;
                let open = if host.addr.is_ipv6() { open6 } else { open4 };
                assert_eq!(state_of(open), PortState::Open, "{}", host.addr);
                assert_eq!(state_of(closed), PortState::Closed, "{}", host.addr);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{TCP_ECE, Tcp};

    fn tcp(seq: u32, ack: u32, flags: u8, window: u16) -> Tcp {
        Tcp {
            sport: 80,
            dport: 41000,
            seq,
            ack,
            flags,
            window,
        }
    }

    #[test]
    fn scanflags_names_and_numbers() {
        assert_eq!(parse_scanflags("SYNFIN"), Ok(TCP_SYN | TCP_FIN));
        assert_eq!(
            parse_scanflags("urgpshfin"),
            Ok(TCP_URG | TCP_PSH | TCP_FIN)
        );
        assert_eq!(parse_scanflags("ECEACK"), Ok(TCP_ECE | TCP_ACK));
        assert_eq!(parse_scanflags("9"), Ok(9));
        assert_eq!(parse_scanflags("0x29"), Ok(0x29));
        assert!(parse_scanflags("SYNFOO").is_err());
        assert!(parse_scanflags("256").is_err());
        assert!(parse_scanflags("").is_err());
    }

    #[test]
    fn answers_match_the_probe() {
        let cookie = 1000;
        // No ACK in the probe: the reply acknowledges our sequence number
        // plus one for SYN and one for FIN.
        let syn = RawTcpScan::new(TcpScanKind::Syn);
        assert!(syn.answers(&tcp(5, 1001, TCP_SYN | TCP_ACK, 100), 41000, cookie));
        assert!(!syn.answers(&tcp(5, 1002, TCP_RST | TCP_ACK, 0), 41000, cookie));
        assert!(!syn.answers(&tcp(5, 999, TCP_RST | TCP_ACK, 0), 41000, cookie));
        assert!(!syn.answers(&tcp(5, 1001, TCP_RST | TCP_ACK, 0), 40999, cookie));
        let null = RawTcpScan::new(TcpScanKind::Null);
        assert!(null.answers(&tcp(0, 1000, TCP_RST | TCP_ACK, 0), 41000, cookie));
        assert!(!null.answers(&tcp(0, 1001, TCP_RST | TCP_ACK, 0), 41000, cookie));
        let xmas = RawTcpScan::new(TcpScanKind::Xmas);
        assert!(xmas.answers(&tcp(0, 1001, TCP_RST | TCP_ACK, 0), 41000, cookie));
        let synfin = RawTcpScan {
            kind: TcpScanKind::Syn,
            flags: TCP_SYN | TCP_FIN,
        };
        assert!(synfin.answers(&tcp(0, 1002, TCP_RST | TCP_ACK, 0), 41000, cookie));
        assert!(synfin.answers(&tcp(0, 1001, TCP_SYN | TCP_ACK, 9), 41000, cookie));
        assert!(!synfin.answers(&tcp(0, 1003, TCP_RST | TCP_ACK, 0), 41000, cookie));
        // An ACK in the probe: the reset's sequence number is our ack.
        for kind in [TcpScanKind::Ack, TcpScanKind::Window, TcpScanKind::Maimon] {
            let scan = RawTcpScan::new(kind);
            assert!(
                scan.answers(&tcp(1000, 0, TCP_RST, 0), 41000, cookie),
                "{kind:?}"
            );
            assert!(
                !scan.answers(&tcp(999, 0, TCP_RST, 0), 41000, cookie),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn classify_by_scan_kind() {
        let rst = tcp(0, 0, TCP_RST, 0);
        let rst_window = tcp(0, 0, TCP_RST, 512);
        let synack = tcp(0, 0, TCP_SYN | TCP_ACK, 512);
        use TcpScanKind::*;
        assert_eq!(
            Syn.classify(&synack),
            Some((PortState::Open, reason::SYN_ACK))
        );
        assert_eq!(Syn.classify(&rst), Some((PortState::Closed, reason::RESET)));
        assert_eq!(Fin.classify(&synack), None);
        for kind in [Fin, Null, Xmas, Maimon] {
            assert_eq!(
                kind.classify(&rst),
                Some((PortState::Closed, reason::RESET))
            );
            assert_eq!(kind.no_response(), PortState::OpenFiltered);
        }
        assert_eq!(Ack.classify(&rst_window).unwrap().0, PortState::Unfiltered);
        assert_eq!(Ack.no_response(), PortState::Filtered);
        assert_eq!(Window.classify(&rst).unwrap().0, PortState::Closed);
        assert_eq!(Window.classify(&rst_window).unwrap().0, PortState::Open);
        assert_eq!(Syn.classify(&tcp(0, 0, TCP_ACK, 0)), None);
    }

    /// An ICMP error quoting a TCP probe from 10.0.0.1:41000 to
    /// 10.0.0.9:443 with sequence number 77.
    fn icmp4_error(kind: u8, code: u8) -> Vec<u8> {
        let mut quoted = vec![0u8; 28];
        quoted[0] = 0x45;
        quoted[9] = packet::IPPROTO_TCP;
        quoted[12..16].copy_from_slice(&[10, 0, 0, 1]);
        quoted[16..20].copy_from_slice(&[10, 0, 0, 9]);
        quoted[20..22].copy_from_slice(&41000u16.to_be_bytes());
        quoted[22..24].copy_from_slice(&443u16.to_be_bytes());
        quoted[24..28].copy_from_slice(&77u32.to_be_bytes());
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&((20 + 8 + quoted.len()) as u16).to_be_bytes());
        pkt[9] = packet::IPPROTO_ICMP;
        pkt[12..16].copy_from_slice(&[192, 0, 2, 1]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 1]);
        pkt.extend_from_slice(&[kind, code, 0, 0, 0, 0, 0, 0]);
        pkt.extend_from_slice(&quoted);
        pkt
    }

    #[test]
    fn icmp_unreachable_quotes_the_probe() {
        let dst: std::net::IpAddr = "10.0.0.9".parse().unwrap();
        assert_eq!(
            parse_tcp_unreach(&icmp4_error(3, 13), false),
            Some((dst, 41000, 443, 77, reason::ADMIN_PROHIBITED))
        );
        assert_eq!(
            parse_tcp_unreach(&icmp4_error(3, 1), false).unwrap().4,
            reason::HOST_UNREACH
        );
        // Fragmentation needed is not a filter, and echo replies are not errors.
        assert_eq!(parse_tcp_unreach(&icmp4_error(3, 4), false), None);
        assert_eq!(parse_tcp_unreach(&icmp4_error(0, 0), false), None);

        // ICMPv6 destination unreachable, administratively prohibited.
        let mut msg = vec![1u8, 1, 0, 0, 0, 0, 0, 0];
        let mut ip6 = vec![0u8; 40];
        ip6[0] = 0x60;
        ip6[6] = packet::IPPROTO_TCP;
        let dst6: std::net::Ipv6Addr = "2001:db8::9".parse().unwrap();
        ip6[24..40].copy_from_slice(&dst6.octets());
        msg.extend_from_slice(&ip6);
        msg.extend_from_slice(&41000u16.to_be_bytes());
        msg.extend_from_slice(&22u16.to_be_bytes());
        msg.extend_from_slice(&5u32.to_be_bytes());
        assert_eq!(
            parse_tcp_unreach(&msg, true),
            Some((dst6.into(), 41000, 22, 5, reason::ADMIN_PROHIBITED))
        );
    }
}
