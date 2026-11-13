//! Host discovery: find out which targets are up before port scanning them.
//!
//! Like nmap's default ping, several probes are sent to every host and any
//! answer counts:
//!
//! - an ICMP echo request ("ping"), when the process may send ICMP: with raw
//!   sockets (root), or an unprivileged ICMP socket where the OS allows one
//!   (not on Windows)
//! - TCP connects to ports 443 and 80, where a completed handshake or a
//!   reset both prove the host exists
//!
//! Hosts that answer none of them are reported as down and not scanned
//! (unless discovery is skipped with `-Pn`).

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use futures::stream::{self, StreamExt};

use crate::connect::probe_port;
use crate::model::{HostResult, PortState, ScanConfig, reason};
use crate::target::Target;

/// TCP ports probed during discovery.
pub const DISCOVERY_PORTS: [u16; 2] = [443, 80];

/// Probe every target and return one [`HostResult`] per target, in order,
/// with `up_reason` set for the hosts that answered.
pub async fn discover(targets: &[Target], cfg: &ScanConfig) -> io::Result<Vec<HostResult>> {
    let v4: Vec<Ipv4Addr> = targets
        .iter()
        .filter_map(|t| match t.addr {
            IpAddr::V4(a) => Some(a),
            IpAddr::V6(_) => None,
        })
        .collect();

    let icmp = {
        let cfg = cfg.clone();
        tokio::task::spawn_blocking(move || icmp::sweep(&v4, &cfg))
    };

    let mut hosts: Vec<HostResult> = targets
        .iter()
        .map(|t| HostResult::new(t.addr, t.hostname.clone()))
        .collect();

    let jobs = DISCOVERY_PORTS
        .iter()
        .flat_map(|&port| (0..targets.len()).map(move |h| (h, port)));
    let mut probes = stream::iter(jobs)
        .map(|(h, port)| {
            let addr = SocketAddr::new(targets[h].addr, port);
            async move { (h, probe_port(addr, cfg).await) }
        })
        .buffer_unordered(cfg.concurrency.max(1));
    while let Some((h, r)) = probes.next().await {
        let r = r?;
        let host = &mut hosts[h];
        if matches!(r.state, PortState::Open | PortState::Closed) && host.up_reason.is_none() {
            host.up_reason = Some(r.reason);
            host.latency_ms = r.rtt_ms;
        }
    }

    // ICMP is best effort: if the OS does not let us ping (no privileges, or
    // a platform without usable ICMP sockets), the TCP probes decide alone.
    let replies: HashMap<Ipv4Addr, f64> = icmp.await.map_err(io::Error::other)?.unwrap_or_default();
    for host in &mut hosts {
        if let IpAddr::V4(a) = host.addr
            && let Some(&rtt) = replies.get(&a)
        {
            // An echo reply is the most direct proof; prefer its latency.
            host.up_reason = Some(reason::ECHO_REPLY);
            host.latency_ms = Some(rtt);
        }
    }
    Ok(hosts)
}

/// Whether this process can send ICMP echo requests at all.
pub fn icmp_available() -> bool {
    icmp::open().is_ok()
}

mod icmp {
    use std::collections::{HashMap, HashSet};
    use std::io::{self, Read};
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    use socket2::{Domain, Protocol, Socket, Type};

    use crate::model::ScanConfig;
    use crate::packet::{self, ICMP_ECHO_REPLY};
    use crate::raw::{Pacer, send_with_backoff};

    /// Open an ICMP socket: raw if privileged, otherwise the unprivileged
    /// "ping socket" that Linux (within `ping_group_range`) and macOS offer.
    /// Returns the socket and whether the kernel rewrites the echo id.
    pub(super) fn open() -> io::Result<(Socket, bool)> {
        // Windows raw sockets cannot reliably receive ICMP replies.
        if cfg!(windows) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "ICMP discovery is not supported on Windows",
            ));
        }
        match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) {
            Ok(s) => Ok((s, false)),
            Err(raw_err) => Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))
                .map(|s| (s, true))
                .map_err(|_| raw_err),
        }
    }

    /// Ping every address and return the ones that replied, with RTT in ms.
    pub(super) fn sweep(
        addrs: &[Ipv4Addr],
        cfg: &ScanConfig,
    ) -> io::Result<HashMap<Ipv4Addr, f64>> {
        // Echo sequence numbers are 16 bits and identify the host when the
        // reply carries no IP header, so ping at most 65536 hosts per round.
        let mut replies = HashMap::new();
        for chunk in addrs.chunks(1 << 16) {
            replies.extend(sweep_chunk(chunk, cfg)?);
        }
        Ok(replies)
    }

    fn sweep_chunk(addrs: &[Ipv4Addr], cfg: &ScanConfig) -> io::Result<HashMap<Ipv4Addr, f64>> {
        let mut replies = HashMap::new();
        if addrs.is_empty() {
            return Ok(replies);
        }
        let (sock, id_rewritten) = open()?;
        sock.set_read_timeout(Some(Duration::from_millis(50)))?;
        let sock = Arc::new(sock);
        let id = (std::process::id() & 0xffff) as u16;
        let targets: HashSet<Ipv4Addr> = addrs.iter().copied().collect();

        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = std::sync::mpsc::channel::<(Ipv4Addr, u16, Instant)>();
        let receiver = {
            let (sock, stop) = (Arc::clone(&sock), Arc::clone(&stop));
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 65536];
                while !stop.load(Ordering::Relaxed) {
                    let n = match (&*sock).read(&mut buf) {
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
                    // Raw sockets (and macOS ping sockets) include the IP
                    // header; Linux ping sockets do not. An echo reply starts
                    // with type 0, never with an IPv4 version nibble of 4.
                    let (src, icmp) = match packet::parse_ipv4(&buf[..n]) {
                        Some(ip) if ip.protocol == packet::IPPROTO_ICMP => {
                            (Some(ip.src), ip.payload)
                        }
                        Some(_) => continue,
                        None => (None, &buf[..n]),
                    };
                    let Some(msg) = packet::parse_icmp(icmp) else {
                        continue;
                    };
                    if msg.kind != ICMP_ECHO_REPLY || (!id_rewritten && msg.id != id) {
                        continue;
                    }
                    // Without an IP header the sequence number tells us who answered.
                    let _ = tx.send((src.unwrap_or(Ipv4Addr::UNSPECIFIED), msg.seq, at));
                }
            })
        };

        let mut sent_at: HashMap<u16, (Ipv4Addr, Instant)> = HashMap::new();
        let mut pending: Vec<(u16, Ipv4Addr)> = addrs
            .iter()
            .enumerate()
            .map(|(i, a)| (i as u16, *a))
            .collect();
        let record = |(src, seq, at): (Ipv4Addr, u16, Instant),
                      sent_at: &HashMap<u16, (Ipv4Addr, Instant)>,
                      replies: &mut HashMap<Ipv4Addr, f64>| {
            let Some(&(dst, sent)) = sent_at.get(&seq) else {
                return;
            };
            let from = if src.is_unspecified() { dst } else { src };
            if targets.contains(&from) {
                let rtt = (at.saturating_duration_since(sent).as_secs_f64() * 1e6).round() / 1000.0;
                replies.entry(from).or_insert(rtt);
            }
        };

        let outcome = (|| -> io::Result<()> {
            for _ in 0..=cfg.retries {
                let mut pacer = Pacer::new(cfg.max_rate);
                for &(seq, addr) in &pending {
                    let pkt = packet::icmp_echo(id, seq, b"feroprobe");
                    sent_at.insert(seq, (addr, Instant::now()));
                    if let Err(e) = send_with_backoff(&sock, &pkt, addr)
                        && !crate::connect::is_network_error(&e)
                    {
                        return Err(e);
                    }
                    pacer.tick();
                    while let Ok(r) = rx.try_recv() {
                        record(r, &sent_at, &mut replies);
                    }
                }
                // Wait for late replies, but stop once every host has answered.
                let deadline = Instant::now() + cfg.timeout;
                while replies.len() < targets.len()
                    && let Some(left) = deadline.checked_duration_since(Instant::now())
                {
                    match rx.recv_timeout(left) {
                        Ok(r) => record(r, &sent_at, &mut replies),
                        Err(_) => break,
                    }
                }
                pending.retain(|(_, a)| !replies.contains_key(a));
                if pending.is_empty() {
                    break;
                }
            }
            Ok(())
        })();

        stop.store(true, Ordering::Relaxed);
        let _ = receiver.join();
        outcome.map(|()| replies)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn localhost_is_up() {
        let cfg = ScanConfig {
            timeout: Duration::from_millis(500),
            ..Default::default()
        };
        let hosts = discover(&[Target::new("127.0.0.1".parse().unwrap())], &cfg)
            .await
            .unwrap();
        // Either the ping or a TCP reset from 443/80 proves localhost is up.
        assert!(hosts[0].is_up(), "{:?}", hosts[0]);
        assert!(hosts[0].up_reason.is_some());
    }
}
