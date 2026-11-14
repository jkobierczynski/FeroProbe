//! TCP SYN ("half-open") scanning over raw sockets.
//!
//! Sends a bare SYN to each port and reads the answers off a raw socket:
//!
//! - **open**: the host replied SYN-ACK (the kernel then resets the half-open
//!   connection for us, since no local socket owns it)
//! - **closed**: the host replied with a RST
//! - **filtered**: no reply after all retries
//!
//! It never completes a handshake, so it is faster and quieter than a connect
//! scan, but it needs root (or `CAP_NET_RAW`). IPv4 and IPv6 targets can be
//! mixed. Linux only: other systems do not deliver TCP replies to raw
//! sockets.

use std::io;

use crate::model::{HostResult, ScanConfig};
use crate::target::Target;

/// Run a SYN scan of every port on every target.
pub async fn syn_scan(
    targets: &[Target],
    ports: &[u16],
    cfg: &ScanConfig,
) -> io::Result<Vec<HostResult>> {
    let (targets, ports, cfg) = (targets.to_vec(), ports.to_vec(), cfg.clone());
    tokio::task::spawn_blocking(move || imp::syn_scan_blocking(&targets, &ports, &cfg))
        .await
        .map_err(io::Error::other)?
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::*;

    pub(super) fn syn_scan_blocking(
        _: &[Target],
        _: &[u16],
        _: &ScanConfig,
    ) -> io::Result<Vec<HostResult>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "SYN scan is only supported on Linux for now; use a connect scan (-sT)",
        ))
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;

    use std::collections::HashMap;
    use std::mem::MaybeUninit;
    use std::net::IpAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use socket2::{Domain, Protocol as SockProto, Socket};

    use crate::connect::is_network_error;
    use crate::model::{PortResult, PortState, Protocol, reason};
    use crate::packet::{self, TCP_ACK, TCP_RST, TCP_SYN};
    use crate::raw::{Pacer, Rng, raw_socket_in, send_with_backoff, source_addr_for};
    use crate::target::socket_addr;

    /// An answer seen by the receiver thread: host index, port, state, time.
    type Answer = (usize, u16, PortState, Instant);

    pub(super) fn syn_scan_blocking(
        targets: &[Target],
        ports: &[u16],
        cfg: &ScanConfig,
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

        let mut rng = Rng::new();
        let sport = 40000 + (rng.next_u32() % 20000) as u16;
        let cookie = rng.next_u32();

        let mut results: HashMap<(usize, u16), PortResult> = HashMap::new();
        let result = |port, state, reason, rtt_ms| PortResult {
            port,
            protocol: Protocol::Tcp,
            state,
            reason,
            rtt_ms,
            service: None,
        };

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
                receive_loop(recv, &index, sport, cookie, &stop, &tx);
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

        let outcome = (|| -> io::Result<()> {
            for _round in 0..=cfg.retries {
                let mut pacer = Pacer::for_config(cfg);
                for &(h, p) in &pending {
                    let Some(src) = sources[h] else { continue };
                    // Answered by a reply that came in during this round.
                    if results.contains_key(&(h, p)) {
                        continue;
                    }
                    let pkt = packet::tcp_syn(src, addrs[h], sport, p, cookie);
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
                    match send_with_backoff(send_sock, &pkt, socket_addr(addrs[h], 0)) {
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
                let deadline = Instant::now() + cfg.timeout;
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
                        results.remove(&(h, p)).unwrap_or_else(|| {
                            result(p, PortState::Filtered, reason::NO_RESPONSE, None)
                        })
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
        (h, p, state, at): Answer,
    ) -> bool {
        if results.contains_key(&(h, p)) {
            return false;
        }
        let rtt_ms = sent_at.get(&(h, p)).map(|s| {
            (at.saturating_duration_since(*s).as_secs_f64() * 1_000_000.0).round() / 1000.0
        });
        let reason = if state == PortState::Open {
            reason::SYN_ACK
        } else {
            reason::RESET
        };
        results.insert(
            (h, p),
            PortResult {
                port: p,
                protocol: Protocol::Tcp,
                state,
                reason,
                rtt_ms,
                service: None,
            },
        );
        true
    }

    /// Read TCP segments off the raw socket and report the ones that answer
    /// our probes: addressed to our source port, from a target, and
    /// acknowledging our sequence cookie. IPv4 raw sockets return the IP
    /// header, IPv6 ones only the segment, with the sender's address.
    fn receive_loop(
        sock: Socket,
        index: &HashMap<IpAddr, usize>,
        sport: u16,
        cookie: u32,
        stop: &AtomicBool,
        tx: &mpsc::Sender<Answer>,
    ) {
        let mut buf = vec![MaybeUninit::<u8>::uninit(); 65536];
        while !stop.load(Ordering::Relaxed) {
            let (n, from) = match sock.recv_from(&mut buf) {
                Ok(r) => r,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                Err(_) => return,
            };
            let at = Instant::now();
            // SAFETY: recv_from initialised the first `n` bytes.
            let data = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), n) };
            let (src, segment) = match from.as_socket() {
                Some(sa) if sa.is_ipv6() => (sa.ip(), data),
                _ => match packet::parse_ipv4(data) {
                    Some(ip) if ip.protocol == packet::IPPROTO_TCP => {
                        (IpAddr::V4(ip.src), ip.payload)
                    }
                    _ => continue,
                },
            };
            let Some(tcp) = packet::parse_tcp(segment) else {
                continue;
            };
            if tcp.dport != sport || tcp.ack != cookie.wrapping_add(1) {
                continue;
            }
            let Some(&h) = index.get(&src) else {
                continue;
            };
            let state = if tcp.flags & (TCP_SYN | TCP_ACK) == TCP_SYN | TCP_ACK {
                PortState::Open
            } else if tcp.flags & TCP_RST != 0 {
                PortState::Closed
            } else {
                continue;
            };
            if tx.send((h, tcp.sport, state, at)).is_err() {
                return;
            }
        }
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
            let hosts = syn_scan_blocking(&[target], &[open, closed], &cfg).unwrap();
            let state_of = |p| hosts[0].ports.iter().find(|r| r.port == p).unwrap().clone();
            assert_eq!(state_of(open).state, PortState::Open);
            assert_eq!(state_of(open).reason, reason::SYN_ACK);
            assert_eq!(state_of(closed).state, PortState::Closed);
            assert_eq!(state_of(closed).reason, reason::RESET);
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
            let hosts = syn_scan_blocking(&targets, &[open6, open4, closed], &cfg).unwrap();
            for host in &hosts {
                let state_of = |p| host.ports.iter().find(|r| r.port == p).unwrap().state;
                let open = if host.addr.is_ipv6() { open6 } else { open4 };
                assert_eq!(state_of(open), PortState::Open, "{}", host.addr);
                assert_eq!(state_of(closed), PortState::Closed, "{}", host.addr);
            }
        }
    }
}
