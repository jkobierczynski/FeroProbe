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
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use futures::stream::{self, StreamExt};

use crate::connect::probe_port;
use crate::model::{HostResult, PortState, ScanConfig, reason};
use crate::target::Target;

/// TCP ports probed during discovery.
pub const DISCOVERY_PORTS: [u16; 2] = [443, 80];

/// Sets a flag when dropped, so the blocking ICMP sweep stops even if
/// discovery returns early with an error or its future is dropped.
struct CancelOnDrop(Arc<AtomicBool>);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// Probe every target and return one [`HostResult`] per target, in order,
/// with `up_reason` set for the hosts that answered.
pub async fn discover(targets: &[Target], cfg: &ScanConfig) -> io::Result<Vec<HostResult>> {
    let index: HashMap<IpAddr, usize> = targets
        .iter()
        .enumerate()
        .map(|(i, t)| (t.addr, i))
        .collect();
    let v4: Vec<Ipv4Addr> = targets
        .iter()
        .filter_map(|t| match t.addr {
            IpAddr::V4(a) => Some(a),
            IpAddr::V6(_) => None,
        })
        .collect();

    // The ICMP sweep runs on a blocking thread and streams replies back, so
    // hosts that answer a ping skip their TCP probes.
    let cancel = CancelOnDrop(Arc::new(AtomicBool::new(false)));
    let (reply_tx, mut replies) = tokio::sync::mpsc::unbounded_channel::<(Ipv4Addr, f64)>();
    let icmp = {
        let (cfg, cancel) = (cfg.clone(), Arc::clone(&cancel.0));
        tokio::task::spawn_blocking(move || {
            icmp::sweep(&v4, &cfg, &cancel, &mut |addr, rtt| {
                let _ = reply_tx.send((addr, rtt));
            })
        })
    };

    let mut hosts: Vec<HostResult> = targets
        .iter()
        .map(|t| HostResult::new(t.addr, t.hostname.clone()))
        .collect();
    let pinged: Vec<AtomicBool> = targets.iter().map(|_| AtomicBool::new(false)).collect();

    // An echo reply is the most direct proof of life; prefer its latency.
    let mark_pinged = |hosts: &mut Vec<HostResult>, (addr, rtt): (Ipv4Addr, f64)| {
        if let Some(&h) = index.get(&IpAddr::V4(addr)) {
            pinged[h].store(true, Ordering::Relaxed);
            hosts[h].up_reason = Some(reason::ECHO_REPLY);
            hosts[h].latency_ms = Some(rtt);
        }
    };

    let jobs = DISCOVERY_PORTS
        .iter()
        .flat_map(|&port| (0..targets.len()).map(move |h| (h, port)));
    let mut probes = stream::iter(jobs)
        // Checked when a probe is about to start: skip hosts already pinged.
        .filter(|&(h, _)| std::future::ready(!pinged[h].load(Ordering::Relaxed)))
        .map(|(h, port)| {
            let addr = SocketAddr::new(targets[h].addr, port);
            async move { (h, probe_port(addr, cfg).await) }
        })
        .buffer_unordered(cfg.concurrency.max(1));

    let mut replies_open = true;
    loop {
        tokio::select! {
            probe = probes.next() => {
                let Some((h, r)) = probe else { break };
                let r = r?;
                let host = &mut hosts[h];
                if matches!(r.state, PortState::Open | PortState::Closed) && host.up_reason.is_none() {
                    host.up_reason = Some(r.reason);
                    host.latency_ms = r.rtt_ms;
                }
            }
            reply = replies.recv(), if replies_open => match reply {
                Some(reply) => mark_pinged(&mut hosts, reply),
                None => replies_open = false,
            },
        }
    }
    drop(probes);

    // Late echo replies still count until the sweep's own timeout ends.
    while let Some(reply) = replies.recv().await {
        mark_pinged(&mut hosts, reply);
    }
    // ICMP is best effort: if the OS does not let us ping (no privileges, or
    // a platform without usable ICMP sockets), the TCP probes decide alone.
    let _ = icmp.await.map_err(io::Error::other)?;
    Ok(hosts)
}

/// Whether this process can send ICMP echo requests at all.
pub fn icmp_available() -> bool {
    icmp::open().is_ok()
}

mod icmp {
    use std::collections::{HashMap, HashSet};
    use std::io;
    use std::mem::MaybeUninit;
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

    /// Callback for each host that answered, with its RTT in ms.
    pub(super) type OnReply<'a> = &'a mut dyn FnMut(Ipv4Addr, f64);

    /// Ping every address, calling `on_reply` once per host that answers.
    /// Stops early when `cancel` is set.
    pub(super) fn sweep(
        addrs: &[Ipv4Addr],
        cfg: &ScanConfig,
        cancel: &AtomicBool,
        on_reply: OnReply<'_>,
    ) -> io::Result<()> {
        // Echo sequence numbers are 16 bits and identify the probe, so ping
        // at most 65536 hosts per round.
        for chunk in addrs.chunks(1 << 16) {
            sweep_chunk(chunk, cfg, cancel, on_reply)?;
        }
        Ok(())
    }

    fn sweep_chunk(
        addrs: &[Ipv4Addr],
        cfg: &ScanConfig,
        cancel: &AtomicBool,
        on_reply: OnReply<'_>,
    ) -> io::Result<()> {
        let mut replies: HashMap<Ipv4Addr, f64> = HashMap::new();
        if addrs.is_empty() || cancel.load(Ordering::Relaxed) {
            return Ok(());
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
                let mut buf = vec![MaybeUninit::<u8>::uninit(); 65536];
                while !stop.load(Ordering::Relaxed) {
                    let (n, sender) = match sock.recv_from(&mut buf) {
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
                    // SAFETY: recv_from initialised the first `n` bytes.
                    let data = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), n) };
                    // The kernel reports who sent the datagram even when the
                    // ICMP message comes without an IP header.
                    let Some(sender) = sender.as_socket_ipv4().map(|a| *a.ip()) else {
                        continue;
                    };
                    let at = Instant::now();
                    // Raw sockets (and macOS ping sockets) include the IP
                    // header; Linux ping sockets do not. An echo reply starts
                    // with type 0, never with an IPv4 version nibble of 4.
                    let icmp = match packet::parse_ipv4(data) {
                        Some(ip) if ip.protocol == packet::IPPROTO_ICMP => ip.payload,
                        Some(_) => continue,
                        None => data,
                    };
                    let Some(msg) = packet::parse_icmp(icmp) else {
                        continue;
                    };
                    if msg.kind != ICMP_ECHO_REPLY || (!id_rewritten && msg.id != id) {
                        continue;
                    }
                    let _ = tx.send((sender, msg.seq, at));
                }
            })
        };

        let mut sent_at: HashMap<u16, (Ipv4Addr, Instant)> = HashMap::new();
        let mut pending: Vec<(u16, Ipv4Addr)> = addrs
            .iter()
            .enumerate()
            .map(|(i, a)| (i as u16, *a))
            .collect();
        let mut record = |(src, seq, at): (Ipv4Addr, u16, Instant),
                          sent_at: &HashMap<u16, (Ipv4Addr, Instant)>,
                          replies: &mut HashMap<Ipv4Addr, f64>| {
            // Only count a reply from the host this sequence number was sent
            // to, so one host cannot vouch for another by echoing its sequence.
            let Some(&(dst, sent)) = sent_at.get(&seq) else {
                return;
            };
            if src == dst && !replies.contains_key(&dst) {
                let rtt = (at.saturating_duration_since(sent).as_secs_f64() * 1e6).round() / 1000.0;
                replies.insert(dst, rtt);
                on_reply(dst, rtt);
            }
        };

        let outcome = (|| -> io::Result<()> {
            for _ in 0..=cfg.retries {
                let mut pacer = Pacer::new(cfg.max_rate);
                for &(seq, addr) in &pending {
                    if cancel.load(Ordering::Relaxed) {
                        return Ok(());
                    }
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
                    && !cancel.load(Ordering::Relaxed)
                    && let Some(left) = deadline.checked_duration_since(Instant::now())
                {
                    // Wake up regularly to notice cancellation.
                    match rx.recv_timeout(left.min(Duration::from_millis(100))) {
                        Ok(r) => record(r, &sent_at, &mut replies),
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
                if cancel.load(Ordering::Relaxed) {
                    return Ok(());
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
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn localhost_is_up() {
        let cfg = ScanConfig {
            timeout: Duration::from_secs(5),
            ..Default::default()
        };
        // Long enough for Windows, which reports a refused connect only ~2s
        // after the reset (there, only the TCP probes run).
        let hosts = discover(&[Target::new("127.0.0.1".parse().unwrap())], &cfg)
            .await
            .unwrap();
        // Either the ping or a TCP reset from 443/80 proves localhost is up.
        assert!(hosts[0].is_up(), "{:?}", hosts[0]);
        assert!(hosts[0].up_reason.is_some());
    }
}
