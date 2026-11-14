//! Traceroute (`--traceroute`): the routers between us and each host.
//!
//! After the port scan, each host gets TCP SYN probes with IP time-to-live
//! (hop limit, for IPv6) 1, 2, 3 and so on, all sent at once. A router that
//! drops a probe because its TTL ran out answers with ICMP "time exceeded",
//! which names that hop; the host itself answers the first probe that
//! reaches it with a SYN-ACK or reset, which gives its distance. Each probe
//! has its own source port, and the ICMP errors quote it, so every answer
//! maps back to its TTL.
//!
//! The probe goes to a port the scan found open, else one it found closed
//! (both make the host answer), else port 80. Hops that never answer are
//! listed without an address, like nmap's `...`. Raw sockets: Linux, root
//! or `CAP_NET_RAW`.

use std::io;
use std::net::IpAddr;

use serde::Serialize;

use crate::model::{HostResult, PortState, Protocol, ScanConfig};

/// The most hops probed, as in nmap.
pub const MAX_HOPS: u8 = 30;

/// One hop on the way to a host.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Hop {
    pub ttl: u8,
    /// Who answered at this distance; `None` if nobody did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addr: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<f64>,
}

/// The route to one host.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Trace {
    /// The TCP port the probes went to.
    pub port: u16,
    pub protocol: Protocol,
    /// Hops 1, 2, ... up to the host itself (the last hop) when it
    /// answered, else up to the last hop that answered. Empty if nothing
    /// answered.
    pub hops: Vec<Hop>,
    /// Whether the host itself answered, so the last hop is the host.
    pub reached: bool,
}

/// The port to trace a host with: open, else closed, else 80.
fn trace_port(host: &HostResult) -> u16 {
    let tcp = |state| {
        host.ports
            .iter()
            .find(|p| p.protocol == Protocol::Tcp && p.state == state)
            .map(|p| p.port)
    };
    tcp(PortState::Open)
        .or_else(|| tcp(PortState::Closed))
        .unwrap_or(80)
}

/// What came back for one probe: the host index, TTL, who answered, whether
/// it was the host itself, and the round-trip time in ms.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq)]
struct HopAnswer {
    host: usize,
    ttl: u8,
    from: IpAddr,
    reached: bool,
    rtt_ms: Option<f64>,
}

/// Turn the answers for one host into its route: hops up to the host's
/// distance (the lowest TTL the host itself answered), or up to the last
/// answering hop if it never did.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn build_trace(port: u16, answers: &[HopAnswer]) -> Trace {
    let distance = answers.iter().filter(|a| a.reached).map(|a| a.ttl).min();
    let last = distance.or_else(|| answers.iter().map(|a| a.ttl).max());
    let hops = (1..=last.unwrap_or(0))
        .map(|ttl| {
            // At the host's distance, prefer the host's own answer.
            let a = answers
                .iter()
                .filter(|a| a.ttl == ttl)
                .max_by_key(|a| a.reached);
            Hop {
                ttl,
                addr: a.map(|a| a.from),
                rtt_ms: a.and_then(|a| a.rtt_ms),
            }
        })
        .collect();
    Trace {
        port,
        protocol: Protocol::Tcp,
        hops,
        reached: distance.is_some(),
    }
}

/// Trace the route to every host that is up, and store it in `trace`.
pub async fn traceroute(hosts: &mut [HostResult], cfg: &ScanConfig) -> io::Result<()> {
    let jobs: Vec<(usize, IpAddr, u16)> = hosts
        .iter()
        .enumerate()
        .filter(|(_, h)| h.is_up())
        .map(|(i, h)| (i, h.addr, trace_port(h)))
        .collect();
    if jobs.is_empty() {
        return Ok(());
    }
    let cfg = cfg.clone();
    let probe_jobs = jobs.clone();
    let answers = tokio::task::spawn_blocking(move || imp::trace_blocking(&probe_jobs, &cfg))
        .await
        .map_err(io::Error::other)??;
    for (j, &(h, _, port)) in jobs.iter().enumerate() {
        let mine: Vec<HopAnswer> = answers.iter().filter(|a| a.host == j).copied().collect();
        hosts[h].trace = Some(build_trace(port, &mine));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::*;

    pub(super) fn trace_blocking(
        _: &[(usize, IpAddr, u16)],
        _: &ScanConfig,
    ) -> io::Result<Vec<HopAnswer>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "--traceroute is only supported on Linux for now",
        ))
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;

    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use socket2::{Domain, Protocol as SockProto, Socket};

    use crate::connect::is_network_error;
    use crate::packet::{self, TCP_ACK, TCP_RST, TCP_SYN};
    use crate::raw::{Pacer, Rng, raw_socket_in, receive_loop, send_with_backoff, source_addr_for};
    use crate::target::socket_addr;

    /// Job index, TTL, who answered, whether it was the host, when.
    type Raw = (usize, u8, IpAddr, bool, Instant);

    pub(super) fn trace_blocking(
        jobs: &[(usize, IpAddr, u16)],
        cfg: &ScanConfig,
    ) -> io::Result<Vec<HopAnswer>> {
        let index: Arc<HashMap<IpAddr, usize>> = Arc::new(
            jobs.iter()
                .enumerate()
                .map(|(j, &(_, addr, _))| (addr, j))
                .collect(),
        );
        let mut rng = Rng::new();
        // Source ports base+1 ..= base+MAX_HOPS stand for TTLs 1 ..= MAX_HOPS.
        let base = 40000 + (rng.next_u32() % 20000) as u16;
        let cookie = rng.next_u32();
        let ttl_of = move |sport: u16| -> Option<u8> {
            let ttl = sport.checked_sub(base)?;
            (1..=u16::from(MAX_HOPS))
                .contains(&ttl)
                .then_some(ttl as u8)
        };

        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel::<Raw>();
        let mut send_socks: [Option<Socket>; 2] = [None, None];
        let mut receivers = Vec::new();
        for (slot, v6) in [false, true].into_iter().enumerate() {
            if !jobs.iter().any(|j| j.1.is_ipv6() == v6) {
                continue;
            }
            let domain = if v6 { Domain::IPV6 } else { Domain::IPV4 };
            let send = match raw_socket_in(domain, SockProto::TCP) {
                Ok(s) => s,
                // No IPv6 here: those hosts get an empty trace.
                Err(e) if v6 && e.raw_os_error() == Some(libc::EAFNOSUPPORT) => continue,
                Err(e) => return Err(e),
            };
            send_socks[slot] = Some(send);
            let tcp = raw_socket_in(domain, SockProto::TCP)?;
            let icmp_proto = if v6 {
                SockProto::ICMPV6
            } else {
                SockProto::ICMPV4
            };
            let icmp = raw_socket_in(domain, icmp_proto)?;
            for sock in [&tcp, &icmp] {
                sock.set_read_timeout(Some(Duration::from_millis(50)))?;
            }
            // The host's own answers: SYN-ACK or reset to one of our ports.
            let (stop2, index2, tx2) = (Arc::clone(&stop), Arc::clone(&index), tx.clone());
            receivers.push(std::thread::spawn(move || {
                receive_loop(tcp, &stop2, &tx2, |data, from, at| {
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
                    let t = packet::parse_tcp(segment)?;
                    let answered = t.flags & (TCP_SYN | TCP_ACK) == TCP_SYN | TCP_ACK
                        || t.flags & TCP_RST != 0;
                    if !answered || t.ack != cookie.wrapping_add(1) {
                        return None;
                    }
                    Some((*index2.get(&src)?, ttl_of(t.dport)?, src, true, at))
                });
            }));
            // Routers' (and the host's) ICMP errors quoting a probe.
            let (stop2, index2, tx2) = (Arc::clone(&stop), Arc::clone(&index), tx.clone());
            receivers.push(std::thread::spawn(move || {
                receive_loop(icmp, &stop2, &tx2, |data, from, at| {
                    let e = packet::parse_icmp_tcp_error(data, v6)?;
                    if e.seq != cookie {
                        return None;
                    }
                    let &j = index2.get(&e.dst)?;
                    let src = e.src.or_else(|| from.as_socket().map(|sa| sa.ip()))?;
                    Some((j, ttl_of(e.sport)?, src, src == e.dst, at))
                });
            }));
        }
        drop(tx);

        let sources: Vec<Option<IpAddr>> = jobs
            .iter()
            .map(|j| match source_addr_for(j.1) {
                Ok(a) => Ok(Some(a)),
                Err(e) if is_network_error(&e) => Ok(None),
                Err(e) => Err(e),
            })
            .collect::<io::Result<_>>()?;

        let mut sent_at: HashMap<(usize, u8), Instant> = HashMap::new();
        let mut first: HashMap<(usize, u8), Raw> = HashMap::new();
        let record = |first: &mut HashMap<(usize, u8), Raw>, a: Raw| {
            first.entry((a.0, a.1)).or_insert(a);
        };
        // The host's distance, once known, caps the TTLs worth retrying.
        let limit = |first: &HashMap<(usize, u8), Raw>, j: usize| -> u8 {
            first
                .values()
                .filter(|a| a.0 == j && a.3)
                .map(|a| a.1)
                .min()
                .unwrap_or(MAX_HOPS)
        };

        let outcome = (|| -> io::Result<()> {
            for _round in 0..=cfg.retries {
                let mut pacer = Pacer::for_config(cfg);
                let mut sent_any = false;
                for (j, &(_, addr, port)) in jobs.iter().enumerate() {
                    let (Some(src), Some(sock)) =
                        (sources[j], send_socks[usize::from(addr.is_ipv6())].as_ref())
                    else {
                        continue;
                    };
                    let cap = limit(&first, j);
                    for ttl in 1..=cap {
                        if first.contains_key(&(j, ttl)) {
                            continue;
                        }
                        pacer.wait();
                        while let Ok(a) = rx.try_recv() {
                            record(&mut first, a);
                        }
                        if addr.is_ipv6() {
                            sock.set_unicast_hops_v6(u32::from(ttl))?;
                        } else {
                            sock.set_ttl_v4(u32::from(ttl))?;
                        }
                        let sport = base + u16::from(ttl);
                        let pkt = packet::tcp_syn(src, addr, sport, port, cookie);
                        sent_at.entry((j, ttl)).or_insert_with(Instant::now);
                        sent_any = true;
                        match send_with_backoff(sock, &pkt, socket_addr(addr, 0)) {
                            Ok(()) => {}
                            Err(e) if is_network_error(&e) => break,
                            Err(e) => return Err(e),
                        }
                    }
                }
                if !sent_any {
                    break;
                }
                let deadline = Instant::now() + cfg.timeout;
                while let Some(left) = deadline.checked_duration_since(Instant::now()) {
                    match rx.recv_timeout(left) {
                        Ok(a) => record(&mut first, a),
                        Err(_) => break,
                    }
                }
            }
            Ok(())
        })();

        stop.store(true, Ordering::Relaxed);
        for r in receivers {
            let _ = r.join();
        }
        outcome?;
        while let Ok(a) = rx.try_recv() {
            record(&mut first, a);
        }

        Ok(first
            .into_values()
            .map(|(j, ttl, from, reached, at)| HopAnswer {
                host: j,
                ttl,
                from,
                reached,
                rtt_ms: sent_at.get(&(j, ttl)).map(|s| {
                    (at.saturating_duration_since(*s).as_secs_f64() * 1_000_000.0).round() / 1000.0
                }),
            })
            .collect())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::raw::raw_sockets_available;

        #[test]
        fn trace_localhost_is_one_hop() {
            if !raw_sockets_available() {
                assert!(
                    std::env::var_os("FEROPROBE_REQUIRE_RAW").is_none(),
                    "FEROPROBE_REQUIRE_RAW is set but raw sockets are unavailable"
                );
                return;
            }
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let cfg = ScanConfig {
                timeout: Duration::from_millis(300),
                retries: 0,
                ..Default::default()
            };
            let addr: IpAddr = "127.0.0.1".parse().unwrap();
            let answers = trace_blocking(&[(0, addr, port)], &cfg).unwrap();
            let trace = build_trace(port, &answers);
            assert!(trace.reached, "{answers:?}");
            assert_eq!(trace.hops.len(), 1);
            assert_eq!(trace.hops[0].addr, Some(addr));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{PortResult, reason};

    fn a(ttl: u8, from: &str, reached: bool) -> HopAnswer {
        HopAnswer {
            host: 0,
            ttl,
            from: from.parse().unwrap(),
            reached,
            rtt_ms: Some(f64::from(ttl)),
        }
    }

    #[test]
    fn route_stops_at_the_host() {
        // Probes past the host's distance reach it too; hop 2 stayed silent.
        let answers = [
            a(1, "192.0.2.1", false),
            a(3, "198.51.100.7", false),
            a(4, "203.0.113.5", true),
            a(5, "203.0.113.5", true),
            a(9, "203.0.113.5", true),
        ];
        let t = build_trace(443, &answers);
        assert!(t.reached);
        assert_eq!(t.hops.len(), 4);
        assert_eq!(t.hops[1].addr, None);
        assert_eq!(t.hops[1].ttl, 2);
        assert_eq!(t.hops[3].addr, Some("203.0.113.5".parse().unwrap()));
        assert_eq!(t.hops[3].rtt_ms, Some(4.0));
    }

    #[test]
    fn unreached_host_keeps_answering_hops() {
        let t = build_trace(80, &[a(1, "192.0.2.1", false), a(2, "192.0.2.9", false)]);
        assert!(!t.reached);
        assert_eq!(t.hops.len(), 2);
        assert!(build_trace(80, &[]).hops.is_empty());
    }

    #[test]
    fn picks_open_then_closed_then_80() {
        let port = |p, state| PortResult {
            port: p,
            protocol: Protocol::Tcp,
            state,
            reason: reason::RESET,
            rtt_ms: None,
            service: None,
        };
        let mut h = HostResult::new("10.0.0.1".parse().unwrap(), None);
        assert_eq!(trace_port(&h), 80);
        h.ports.push(port(23, PortState::Filtered));
        h.ports.push(port(25, PortState::Closed));
        assert_eq!(trace_port(&h), 25);
        h.ports.push(port(22, PortState::Open));
        assert_eq!(trace_port(&h), 22);
    }
}
