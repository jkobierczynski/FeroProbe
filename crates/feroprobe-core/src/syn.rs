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
//! scan, but it needs root (or `CAP_NET_RAW`). Currently Linux and IPv4 only:
//! other systems do not deliver TCP replies to raw sockets.

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
    use std::io::Read;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use socket2::Protocol as SockProto;

    use crate::connect::is_network_error;
    use crate::model::{PortResult, PortState, Protocol, reason};
    use crate::packet::{self, TCP_ACK, TCP_RST, TCP_SYN};
    use crate::raw::{Pacer, Rng, raw_socket, send_with_backoff, source_addr_for};

    /// An answer seen by the receiver thread: host index, port, state, time.
    type Answer = (usize, u16, PortState, Instant);

    pub(super) fn syn_scan_blocking(
        targets: &[Target],
        ports: &[u16],
        cfg: &ScanConfig,
    ) -> io::Result<Vec<HostResult>> {
        let addrs: Vec<Ipv4Addr> = targets
            .iter()
            .map(|t| match t.addr {
                IpAddr::V4(a) => Ok(a),
                IpAddr::V6(a) => Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("SYN scan supports IPv4 only for now; use -sT for {a}"),
                )),
            })
            .collect::<io::Result<_>>()?;
        let index: HashMap<Ipv4Addr, usize> =
            addrs.iter().enumerate().map(|(i, a)| (*a, i)).collect();

        let send_sock = raw_socket(SockProto::TCP)?;
        let recv_sock = raw_socket(SockProto::TCP)?;
        recv_sock.set_read_timeout(Some(Duration::from_millis(50)))?;
        let _ = recv_sock.set_recv_buffer_size(8 << 20);

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
        let mut sources: Vec<Option<Ipv4Addr>> = Vec::with_capacity(addrs.len());
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
        let receiver = {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                receive_loop(recv_sock, &index, sport, cookie, &stop, &tx);
            })
        };

        let mut sent_at: HashMap<(usize, u16), Instant> = HashMap::new();

        // Port-major order spreads the probes across hosts.
        let mut pending: Vec<(usize, u16)> = ports
            .iter()
            .flat_map(|&p| (0..addrs.len()).map(move |h| (h, p)))
            .filter(|k| !results.contains_key(k))
            .collect();

        let outcome = (|| -> io::Result<()> {
            for _round in 0..=cfg.retries {
                let mut pacer = Pacer::new(cfg.max_rate);
                for &(h, p) in &pending {
                    let Some(src) = sources[h] else { continue };
                    let pkt = packet::tcp_syn(src, addrs[h], sport, p, cookie);
                    sent_at.insert((h, p), Instant::now());
                    match send_with_backoff(&send_sock, &pkt, addrs[h]) {
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
                    pacer.tick();
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
        let _ = receiver.join();
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
    /// acknowledging our sequence cookie.
    fn receive_loop(
        sock: socket2::Socket,
        index: &HashMap<Ipv4Addr, usize>,
        sport: u16,
        cookie: u32,
        stop: &AtomicBool,
        tx: &mpsc::Sender<Answer>,
    ) {
        let mut sock = sock;
        let mut buf = vec![0u8; 65536];
        while !stop.load(Ordering::Relaxed) {
            let n = match sock.read(&mut buf) {
                Ok(n) => n,
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
            let Some(ip) = packet::parse_ipv4(&buf[..n]) else {
                continue;
            };
            if ip.protocol != packet::IPPROTO_TCP {
                continue;
            }
            let Some(tcp) = packet::parse_tcp(ip.payload) else {
                continue;
            };
            if tcp.dport != sport || tcp.ack != cookie.wrapping_add(1) {
                continue;
            }
            let Some(&h) = index.get(&ip.src) else {
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
        fn rejects_ipv6() {
            let target = Target::new("::1".parse().unwrap());
            let err = syn_scan_blocking(&[target], &[80], &ScanConfig::default()).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        }
    }
}
