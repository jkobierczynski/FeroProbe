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
    #[cfg(test)]
    fn answers(&self, tcp: &packet::Tcp, sport: u16, cookie: u32) -> bool {
        self.answered_try(tcp, sport, cookie).is_some()
    }

    /// Which try of our probe a TCP segment from the target answers, if
    /// any: each try carries its number in our sequence number (see
    /// [`try_seq`]), and so in the number the target sends back.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))] // only the Linux scanner reads replies
    fn answered_try(&self, tcp: &packet::Tcp, sport: u16, cookie: u32) -> Option<u32> {
        if tcp.dport != sport {
            return None;
        }
        let (echoed, max) = if self.flags & TCP_ACK != 0 {
            (tcp.seq, 0)
        } else {
            // The --data bytes count too: a reset acknowledges them all.
            let data = crate::packet_opts::get()
                .data
                .as_ref()
                .map_or(0, |d| d.len() as u32);
            let max =
                u32::from(self.flags & TCP_SYN != 0) + u32::from(self.flags & TCP_FIN != 0) + data;
            (tcp.ack, max)
        };
        let off = echoed.wrapping_sub(cookie);
        (off & 0xffff <= max).then_some(off >> 16)
    }
}

/// The sequence number (or, for probes with ACK set, the acknowledgment
/// number) of try `tryno` of a probe: the scan's random cookie with the try
/// number in its upper half, so an answer tells which try it answers, as
/// nmap's do. Resends can then be timed, and an answer to the first copy
/// that comes after a resend still counts as an answer to the first copy.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn try_seq(cookie: u32, tryno: u32) -> u32 {
    cookie.wrapping_add(tryno.min(0xffff) << 16)
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
    raw_tcp_scan_until(targets, ports, cfg, scan, None).await
}

/// Hosts already proven up, so a raw scan used as a discovery probe sends
/// them nothing more. Target `h` of the scan is done once `flags[index[h]]`
/// (set by other probes, such as ICMP) or `tcp[index[h]]` (set when a raw
/// TCP, SCTP or IP protocol probe draws an answer) is set. The two are kept
/// apart so such an answer does not stop an ICMP reply from being reported
/// as the reason.
#[derive(Clone)]
pub(crate) struct HostsDone {
    pub flags: std::sync::Arc<Vec<std::sync::atomic::AtomicBool>>,
    pub tcp: std::sync::Arc<Vec<std::sync::atomic::AtomicBool>>,
    pub index: Vec<usize>,
}

impl HostsDone {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn is_done(&self, h: usize) -> bool {
        use std::sync::atomic::Ordering::Relaxed;
        let i = self.index[h];
        self.flags[i].load(Relaxed) || self.tcp[i].load(Relaxed)
    }

    /// Mark target `h` of the scan done: it answered a raw probe (TCP,
    /// SCTP or IP protocol).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn mark(&self, h: usize) {
        self.tcp[self.index[h]].store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// [`raw_tcp_scan`], skipping the probes still pending for hosts that
/// `done` marks as finished. Their skipped ports come back as no answer.
pub(crate) async fn raw_tcp_scan_until(
    targets: &[Target],
    ports: &[u16],
    cfg: &ScanConfig,
    scan: RawTcpScan,
    done: Option<HostsDone>,
) -> io::Result<Vec<HostResult>> {
    let (targets, ports, cfg) = (targets.to_vec(), ports.to_vec(), cfg.clone());
    tokio::task::spawn_blocking(move || {
        imp::scan_blocking(&targets, &ports, &cfg, scan, done.as_ref())
    })
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
        _: Option<&HostsDone>,
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
    use crate::raw::{
        Pacer, Rng, nmap_ip_header, raw_socket_in, receive_loop, send_with_backoff_until,
        source_addr_for,
    };
    use crate::rtt::{Flight, Next};
    use crate::target::socket_addr;

    /// An answer seen by a receiver thread: host index, port, state,
    /// reason, time.
    /// Host, port, state, reason, receive time and the try it answers.
    type Answer = (usize, u16, PortState, &'static str, Instant, u32);

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

    /// Send one raw-TCP probe with the scan's evasion options applied:
    /// build the probe from each source address (the decoys plus the real
    /// or spoofed source), wrap each in a complete IPv4 packet, fragment it
    /// if asked, and send every piece on the `IPPROTO_RAW` socket. IPv4
    /// only; the command-line layer guarantees that.
    #[allow(clippy::too_many_arguments)]
    fn send_evasion(
        sock: &Socket,
        real_src: IpAddr,
        dst: IpAddr,
        sport: u16,
        dport: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        cfg: &ScanConfig,
    ) -> io::Result<()> {
        let IpAddr::V4(dst4) = dst else {
            return Ok(());
        };
        for (i, source) in cfg.evasion.source_addrs(real_src).into_iter().enumerate() {
            let IpAddr::V4(src4) = source else { continue };
            let seg = if flags == TCP_SYN {
                packet::tcp_syn(source, dst, sport, dport, seq).to_vec()
            } else {
                packet::tcp_probe(source, dst, sport, dport, seq, ack, flags).to_vec()
            };
            let seg = crate::packet_opts::get().finish(packet::IPPROTO_TCP, source, dst, seg, true);
            // A distinct identification per datagram; fragments of one
            // datagram share it, as reassembly needs.
            let id = (seq as u16) ^ dport ^ (i as u16);
            let (pkt, hop) =
                crate::packet_opts::ipv4_probe(src4, dst4, packet::IPPROTO_TCP, id, &seg);
            let to = socket_addr(IpAddr::V4(hop), 0);
            let frags = match cfg.evasion.fragment {
                Some(f) => crate::evasion::fragment_ipv4(&pkt, f),
                None => vec![pkt],
            };
            for frag in &frags {
                send_with_backoff_until(sock, frag, to, cfg.deadline)?;
            }
        }
        Ok(())
    }

    pub(super) fn scan_blocking(
        targets: &[Target],
        ports: &[u16],
        cfg: &ScanConfig,
        scan: RawTcpScan,
        done: Option<&HostsDone>,
    ) -> io::Result<Vec<HostResult>> {
        let is_done = |h: usize| done.is_some_and(|d| d.is_done(h));
        // A TCP answer (not an ICMP error) proves the host up for the other
        // discovery probes too.
        let no_answer = scan.kind.no_response();
        // Not for discovery pings: --defeat-rst-ratelimit is a port-scan option.
        let defeat_rst = cfg.defeat_rst_ratelimit && done.is_none();
        let record = |results: &mut HashMap<(usize, u16), PortResult>,
                      flight: &mut Flight<u16>,
                      a: Answer| {
            let proof = done.is_some() && a.2 != PortState::Filtered;
            if let Some(d) = done
                && proof
            {
                d.mark(a.0);
                // As a discovery probe, a TCP answer is proof of life, so it
                // replaces an ICMP error stored earlier for the same probe.
                if results
                    .get(&(a.0, a.1))
                    .is_some_and(|r| r.state == PortState::Filtered)
                {
                    results.remove(&(a.0, a.1));
                }
            }
            let host = a.0;
            let recorded = record(results, flight, no_answer, defeat_rst, a);
            if proof {
                flight.retire_host(host);
            }
            recorded
        };
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
        let sport = crate::raw::probe_sport(cfg, &mut rng);
        let cookie = rng.next_u32();
        let has_ack = scan.flags & TCP_ACK != 0;

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
                    let (h, port, state, why, tryno) =
                        tcp_answer(data, from, &index, &scan, sport, cookie)?;
                    Some((h, port, state, why, at, tryno))
                });
            }));
        }
        for (v6, sock) in [(false, icmp4), (true, icmp6)] {
            let Some(sock) = sock else { continue };
            let (stop, index, tx) = (Arc::clone(&stop), Arc::clone(&index), tx.clone());
            receivers.push(std::thread::spawn(move || {
                receive_loop(sock, &stop, &tx, |data, _, at| {
                    let (dst, sp, dp, seq, why) = parse_tcp_unreach(data, v6)?;
                    let off = seq.wrapping_sub(cookie);
                    if sp != sport || off & 0xffff != 0 {
                        return None;
                    }
                    Some((
                        *index.get(&dst)?,
                        dp,
                        PortState::Filtered,
                        why,
                        at,
                        off >> 16,
                    ))
                });
            }));
        }
        drop(tx);

        // Evasion (fragmentation, decoys, spoofed source) sends complete
        // IPv4 packets, so it needs an IPPROTO_RAW socket. The command-line
        // layer only lets evasion through for private IPv4 targets.
        let evasion_sock: Option<Socket> = if cfg.evasion.is_active() {
            Some(raw_socket_in(
                Domain::IPV4,
                SockProto::from(libc::IPPROTO_RAW),
            )?)
        } else {
            None
        };

        // Port-major order spreads the probes across hosts.
        let pending: Vec<(usize, u16)> = ports
            .iter()
            .flat_map(|&p| (0..addrs.len()).map(move |h| (h, p)))
            .filter(|k| !results.contains_key(k))
            .collect();

        // Probes settled before any is sent (no route) count as done.
        crate::progress::tick((addrs.len() * ports.len() - pending.len()) as u64);

        let mut per_host = vec![0; addrs.len()];
        for &(h, _) in &pending {
            per_host[h] += 1;
        }
        let mut flight: Flight<u16> = Flight::new(cfg, &addrs, per_host);
        // As a discovery probe, stop waiting for hosts that other probes
        // proved up. Checked on a timer, not per answer, to stay cheap on
        // large sweeps.
        let mut retired = vec![false; addrs.len()];
        // Looking costs a pass over the targets: at most every
        // RETIRE_EVERY (this scan's own answers retire their host at once).
        let mut looked = Instant::now();
        let mut retire_done = |flight: &mut Flight<u16>| {
            if done.is_none() || looked.elapsed() < crate::rawscan::RETIRE_EVERY {
                return;
            }
            looked = Instant::now();
            for (h, r) in retired.iter_mut().enumerate() {
                if !*r && is_done(h) {
                    *r = true;
                    flight.retire_host(h);
                }
            }
        };
        // As a discovery probe, hosts can be proven up by other probes
        // while we wait: wake up regularly to notice.
        let slice = if done.is_some() {
            Duration::from_millis(100)
        } else {
            Duration::MAX
        };

        let outcome = (|| -> io::Result<()> {
            // Resends go out as their probes time out, as often as each
            // host's losses call for, up to cfg.retries (see Flight).
            let mut pacer = Pacer::for_config(cfg);
            flight.start(pending.iter().copied());
            loop {
                if cfg.expired() {
                    return Err(ScanConfig::timed_out());
                }
                // Answers already in first: one may raise its host's allowance
                // before its other probes are timed out and benched.
                while let Ok(a) = rx.try_recv() {
                    record(&mut results, &mut flight, a);
                }
                let (h, p) = match flight.next(Instant::now()) {
                    Next::Idle => break,
                    Next::Send(h, p) => (h, p),
                    // Every window is full, or only probes waiting for
                    // their answers are left: wait for an answer or a
                    // timeout or (as a discovery probe) for the host to be
                    // proven up.
                    Next::Wait(until) => {
                        let until = cfg.deadline.map_or(until, |d| until.min(d));
                        let left = until.saturating_duration_since(Instant::now()).min(slice);
                        match rx.recv_timeout(left) {
                            Ok(a) => {
                                record(&mut results, &mut flight, a);
                            }
                            Err(mpsc::RecvTimeoutError::Timeout) => {}
                            Err(mpsc::RecvTimeoutError::Disconnected) => std::thread::sleep(left),
                        }
                        retire_done(&mut flight);
                        continue;
                    }
                };
                let resend = flight.is_resend(h, p);
                if !resend {
                    crate::progress::tick(1);
                }
                let Some(src) = sources[h] else {
                    flight.settle(h, p);
                    continue;
                };
                // Answered by a reply that came in meanwhile, or (on a
                // resend) the host is already known to be up. First tries
                // always go out: nmap sends a host all its discovery probes
                // in one burst, so an early ICMP reply does not hold back
                // the SYN or ACK.
                if results.contains_key(&(h, p)) || (resend && is_done(h)) {
                    flight.settle(h, p);
                    continue;
                }
                let Some(send_sock) = send_socks[usize::from(addrs[h].is_ipv6())].as_ref() else {
                    // No socket for this family (no IPv6 here).
                    results.entry((h, p)).or_insert(result(
                        p,
                        PortState::Filtered,
                        reason::UNREACHABLE,
                        None,
                    ));
                    flight.settle(h, p);
                    continue;
                };
                // The wait gives up at the host deadline.
                if !pacer.wait_until(cfg.deadline) {
                    return Err(ScanConfig::timed_out());
                }
                // A slow template can wait long enough for an answer to the
                // earlier copy of a resent probe to arrive: record it
                // against the old send time and do not send again.
                while let Ok(a) = rx.try_recv() {
                    record(&mut results, &mut flight, a);
                }
                // Another probe may have proven the host up meanwhile.
                if results.contains_key(&(h, p)) || (resend && is_done(h)) {
                    flight.settle(h, p);
                    continue;
                }
                flight.sent(h, p, Instant::now());
                let seq = try_seq(cookie, flight.tryno(h, p));
                let ack = if has_ack { seq } else { 0 };
                let to = socket_addr(addrs[h], 0);
                // The SYN scan keeps its MSS option, which makes the
                // probe look like an ordinary connection attempt.
                let sent = if let Some(raw) = evasion_sock.as_ref().filter(|_| addrs[h].is_ipv4()) {
                    send_evasion(raw, src, addrs[h], sport, p, seq, ack, scan.flags, cfg)
                } else {
                    let pkt = if scan.flags == TCP_SYN {
                        packet::tcp_syn(src, addrs[h], sport, p, seq).to_vec()
                    } else {
                        packet::tcp_probe(src, addrs[h], sport, p, seq, ack, scan.flags).to_vec()
                    };
                    // --data, --data-length and --badsum, as in nmap.
                    let pkt = crate::packet_opts::get().finish(
                        packet::IPPROTO_TCP,
                        src,
                        addrs[h],
                        pkt,
                        true,
                    );
                    nmap_ip_header(send_sock, addrs[h].is_ipv6());
                    send_with_backoff_until(send_sock, &pkt, to, cfg.deadline)
                };
                match sent {
                    Ok(()) => {}
                    // The send gave up at the host deadline.
                    Err(_) if cfg.expired() => return Err(ScanConfig::timed_out()),
                    Err(e) if is_network_error(&e) => {
                        results.entry((h, p)).or_insert(result(
                            p,
                            PortState::Filtered,
                            reason::UNREACHABLE,
                            None,
                        ));
                        flight.settle(h, p);
                    }
                    Err(e) => return Err(e),
                }
                while let Ok(a) = rx.try_recv() {
                    record(&mut results, &mut flight, a);
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

    /// Store the first answer for a probe, with its round-trip time, and
    /// feed it to the flight's timeouts and windows. Returns whether it was
    /// new.
    fn record(
        results: &mut HashMap<(usize, u16), PortResult>,
        flight: &mut Flight<u16>,
        no_answer: PortState,
        defeat_rst: bool,
        (h, p, state, why, at, tryno): Answer,
    ) -> bool {
        if results.contains_key(&(h, p)) {
            return false;
        }
        // An ICMP error moves no window on a retry when silence already
        // means filtered (see `rtt::Outcome::FilteredError`).
        // With --defeat-rst-ratelimit a RST (closed) is treated the same,
        // as nmap does, so rate-limited RSTs do not slow the scan.
        let filtered_error = (no_answer == PortState::Filtered && state == PortState::Filtered)
            || (defeat_rst && state == PortState::Closed);
        let Some(rtt) = flight.answered(h, p, at, filtered_error, Some(tryno)) else {
            return false;
        };
        let rtt_ms = (rtt.as_secs_f64() * 1_000_000.0).round() / 1000.0;
        results.insert((h, p), result(p, state, why, Some(rtt_ms)));
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
    ) -> Option<(usize, u16, PortState, &'static str, u32)> {
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
        let tryno = scan.answered_try(&tcp, sport, cookie)?;
        let &h = index.get(&src)?;
        let (state, why) = scan.kind.classify(&tcp)?;
        Some((h, tcp.sport, state, why, tryno))
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
        fn done_hosts_get_no_more_probes() {
            if !privileged() {
                return;
            }
            use std::sync::Arc;
            use std::sync::atomic::AtomicBool;
            let closed = {
                let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                l.local_addr().unwrap().port()
            };
            let cfg = ScanConfig {
                rtt: crate::rtt::RttTimeouts::fixed(Duration::from_secs(5)),
                ..Default::default()
            };
            let target = Target::new("127.0.0.1".parse().unwrap());
            let syn = RawTcpScan::new(TcpScanKind::Syn);
            // Already proven up: the first probe still goes out (nmap sends
            // a host's discovery probes in one burst), but the scan does
            // not wait for its answer.
            let done = HostsDone {
                flags: Arc::new(vec![AtomicBool::new(false), AtomicBool::new(true)]),
                tcp: Arc::new(vec![AtomicBool::new(false), AtomicBool::new(false)]),
                index: vec![1],
            };
            let started = Instant::now();
            let hosts = scan_blocking(
                std::slice::from_ref(&target),
                &[closed],
                &cfg,
                syn,
                Some(&done),
            )
            .unwrap();
            assert!(started.elapsed() < Duration::from_secs(2));
            assert_eq!(hosts[0].ports.len(), 1);
            // Not yet up: probed, and the reset marks the host done.
            let done = HostsDone {
                flags: Arc::new(vec![AtomicBool::new(false)]),
                tcp: Arc::new(vec![AtomicBool::new(false)]),
                index: vec![0],
            };
            let hosts = scan_blocking(&[target], &[closed], &cfg, syn, Some(&done)).unwrap();
            assert_eq!(hosts[0].ports[0].state, PortState::Closed);
            assert!(done.is_done(0));

            // Two hosts, one already up: both get their first probe, and the
            // other still gets its answer counted, with no retry to fall
            // back on.
            let cfg = ScanConfig { retries: 0, ..cfg };
            let a = Target::new("127.0.0.1".parse().unwrap());
            let b = Target::new("127.0.0.2".parse().unwrap());
            let done = HostsDone {
                flags: Arc::new(vec![AtomicBool::new(true), AtomicBool::new(false)]),
                tcp: Arc::new(vec![AtomicBool::new(false), AtomicBool::new(false)]),
                index: vec![0, 1],
            };
            let hosts = scan_blocking(&[a, b], &[closed], &cfg, syn, Some(&done)).unwrap();
            assert_eq!(hosts[0].ports.len(), 1);
            assert_eq!(hosts[1].ports[0].state, PortState::Closed);
        }

        /// Hosts A and B both have a probe out; ICMP proves A up, then A's
        /// delayed TCP reply arrives. That reply must not use up B's count.
        #[test]
        fn late_reply_from_done_host_keeps_waiting_for_others() {
            let cfg = ScanConfig::default();
            let addrs: Vec<IpAddr> = vec!["10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap()];
            let mut flight: Flight<u16> = Flight::new(&cfg, &addrs, vec![1, 1]);
            let mut results = HashMap::new();
            let now = Instant::now();
            flight.start([(0, 80), (1, 80)]);
            while let Next::Send(h, p) = flight.next(now) {
                flight.sent(h, p, now);
            }
            assert!(flight.any_waiting());
            // ICMP proves A up: A no longer counts as waiting, B still does.
            flight.retire_host(0);
            assert!(flight.any_waiting());
            // A's delayed TCP reply is still recorded ...
            let later = now + Duration::from_millis(5);
            assert!(record(
                &mut results,
                &mut flight,
                PortState::Filtered,
                false,
                (0, 80, PortState::Closed, reason::RESET, later, 0)
            ));
            // ... but does not stand in for B's answer.
            assert!(flight.any_waiting());
            assert!(record(
                &mut results,
                &mut flight,
                PortState::Filtered,
                false,
                (1, 80, PortState::Closed, reason::RESET, later, 0),
            ));
            assert!(!flight.any_waiting());
            // Only the first answer counts.
            assert!(!record(
                &mut results,
                &mut flight,
                PortState::Filtered,
                false,
                (1, 80, PortState::Open, reason::SYN_ACK, later, 0),
            ));
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
                rtt: crate::rtt::RttTimeouts::fixed(Duration::from_millis(500)),
                ..Default::default()
            };
            let target = Target::new("127.0.0.1".parse().unwrap());
            let hosts = scan_blocking(
                &[target],
                &[open, closed],
                &cfg,
                RawTcpScan::new(TcpScanKind::Syn),
                None,
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
                None,
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
                rtt: crate::rtt::RttTimeouts::fixed(Duration::from_millis(300)),
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
                    None,
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
            let hosts = scan_blocking(&[target], &[open, closed], &cfg, custom, None).unwrap();
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
                rtt: crate::rtt::RttTimeouts::fixed(Duration::from_millis(500)),
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
                None,
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
    fn answers_name_their_try() {
        let tcp = |seq, ack, flags| packet::Tcp {
            sport: 80,
            dport: 41000,
            seq,
            ack,
            flags,
            window: 0,
        };
        let cookie = 0xffff_fff0;
        let syn = RawTcpScan::new(TcpScanKind::Syn);
        for tryno in [0, 1, 2, 9] {
            let seq = try_seq(cookie, tryno);
            let rst = tcp(0, seq.wrapping_add(1), TCP_RST | TCP_ACK);
            assert_eq!(syn.answered_try(&rst, 41000, cookie), Some(tryno));
            assert_eq!(
                syn.answered_try(&tcp(0, seq.wrapping_add(2), TCP_RST), 41000, cookie),
                None
            );
        }
        // An ACK scan's reset echoes the acknowledgment number as its
        // sequence number.
        let ack = RawTcpScan::new(TcpScanKind::Ack);
        let rst = tcp(try_seq(cookie, 3), 0, TCP_RST);
        assert_eq!(ack.answered_try(&rst, 41000, cookie), Some(3));
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
