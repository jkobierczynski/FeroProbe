//! Host discovery: find out which targets are up before port scanning them.
//!
//! Targets on a directly connected Ethernet network are asked for their MAC
//! address with ARP (IPv4, see [`crate::arp`]) or neighbour discovery (IPv6,
//! see [`crate::ndp`]), when the process may use raw sockets on Linux. Their
//! answer, or its absence, decides them alone.
//!
//! For every other target, like nmap's default ping, several probes are sent
//! and any answer counts:
//!
//! - an ICMP or ICMPv6 echo request ("ping"), when the process may send
//!   ICMP: with raw sockets (root), or an unprivileged ICMP socket where the
//!   OS allows one (not on Windows)
//! - TCP connects to ports 443 and 80, where a completed handshake or a
//!   reset both prove the host exists
//!
//! Hosts that answer none of them are reported as down and not scanned
//! (unless discovery is skipped with `-Pn`).

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use futures::stream::{self, StreamExt};

use crate::arp::{self, MacAddr, MacInfo};
use crate::connect::probe_port;
use crate::model::{HostResult, PortState, ScanConfig, reason};
use crate::ndp;
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
    let mut hosts: Vec<HostResult> = targets
        .iter()
        .map(|t| HostResult::new(t.addr, t.hostname.clone()))
        .collect();
    // Hosts that ARP or NDP already settled, up or down, skip the other
    // probes.
    let decided = if cfg.arp_ping {
        neighbour_phase(targets, cfg, &mut hosts).await?
    } else {
        vec![false; targets.len()]
    };

    let index: HashMap<IpAddr, usize> = targets
        .iter()
        .enumerate()
        .map(|(i, t)| (t.addr, i))
        .collect();
    let undecided = |v6: bool| -> Vec<IpAddr> {
        targets
            .iter()
            .zip(&decided)
            .filter(|(t, d)| !**d && t.addr.is_ipv6() == v6)
            .map(|(t, _)| t.addr)
            .collect()
    };

    // The ICMP sweeps (one per address family) run on blocking threads and
    // stream replies back, so hosts that answer a ping skip their TCP probes.
    let cancel = CancelOnDrop(Arc::new(AtomicBool::new(false)));
    let (reply_tx, mut replies) = tokio::sync::mpsc::unbounded_channel::<(IpAddr, f64)>();
    let mut icmp = Vec::new();
    for addrs in [undecided(false), undecided(true)] {
        if addrs.is_empty() {
            continue;
        }
        let (cfg, cancel, reply_tx) = (cfg.clone(), Arc::clone(&cancel.0), reply_tx.clone());
        icmp.push(tokio::task::spawn_blocking(move || {
            icmp::sweep(&addrs, &cfg, &cancel, &mut |addr, rtt| {
                let _ = reply_tx.send((addr, rtt));
            })
        }));
    }
    drop(reply_tx);

    let pinged: Vec<AtomicBool> = decided.iter().map(|&d| AtomicBool::new(d)).collect();

    // An echo reply is the most direct proof of life; prefer its latency.
    let mark_pinged = |hosts: &mut Vec<HostResult>, (addr, rtt): (IpAddr, f64)| {
        if let Some(&h) = index.get(&addr)
            && !decided[h]
        {
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
            let addr = crate::target::socket_addr(targets[h].addr, port);
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
    for sweep in icmp {
        let _ = sweep.await.map_err(io::Error::other)?;
    }
    Ok(hosts)
}

/// Ask every target that sits on a local Ethernet network for its MAC
/// address: with ARP for IPv4 and neighbour discovery for IPv6. Fills in the
/// hosts that answered and returns, per target, whether it was decided. A
/// network where this cannot run (no privileges, not Linux) decides nothing,
/// so those targets fall back to the ICMP and TCP probes.
async fn neighbour_phase(
    targets: &[Target],
    cfg: &ScanConfig,
    hosts: &mut [HostResult],
) -> io::Result<Vec<bool>> {
    let mut decided = vec![false; targets.len()];
    let nets = arp::local_networks().unwrap_or_default();
    let links = ndp::local_links().unwrap_or_default();
    // Group the targets by the local network they are on.
    let mut arp_groups: Vec<(arp::LocalNet, Vec<Ipv4Addr>)> = Vec::new();
    let mut nd_groups: Vec<(ndp::LocalLink, Vec<Ipv6Addr>)> = Vec::new();
    let mut seen: HashSet<IpAddr> = HashSet::new();
    for t in targets {
        if !seen.insert(t.addr) {
            continue;
        }
        match t.addr {
            IpAddr::V4(ip) => {
                if let Some(net) = arp::local_net_for(ip, &nets) {
                    add_to_group(&mut arp_groups, net, ip);
                }
            }
            IpAddr::V6(ip) => {
                if let Some(link) = ndp::link_for(ip, &links) {
                    add_to_group(&mut nd_groups, link, ip);
                }
            }
        }
    }
    if arp_groups.is_empty() && nd_groups.is_empty() {
        return Ok(decided);
    }

    let cancel = CancelOnDrop(Arc::new(AtomicBool::new(false)));
    let (cfg2, flag) = (cfg.clone(), Arc::clone(&cancel.0));
    let (settled, replies) = tokio::task::spawn_blocking(move || {
        let mut settled: HashSet<IpAddr> = HashSet::new();
        let mut replies: HashMap<IpAddr, (Option<MacAddr>, f64, &'static str)> = HashMap::new();
        for (net, ips) in &arp_groups {
            let r = arp::sweep(net, ips, &cfg2, &flag, &mut |ip, mac, rtt| {
                replies.insert(ip.into(), (Some(mac), rtt, reason::ARP_RESPONSE));
            });
            if r.is_ok() {
                settled.extend(ips.iter().map(|&ip| IpAddr::from(ip)));
            }
        }
        for (link, ips) in &nd_groups {
            let r = ndp::sweep(link, ips, &cfg2, &flag, &mut |ip, mac, rtt| {
                replies.insert(ip.into(), (mac, rtt, reason::ND_RESPONSE));
            });
            if r.is_ok() {
                settled.extend(ips.iter().map(|&ip| IpAddr::from(ip)));
            }
        }
        (settled, replies)
    })
    .await
    .map_err(io::Error::other)?;

    for (i, t) in targets.iter().enumerate() {
        decided[i] = settled.contains(&t.addr);
        if let Some(&(mac, rtt, why)) = replies.get(&t.addr) {
            hosts[i].up_reason = Some(why);
            hosts[i].latency_ms = Some(rtt);
            hosts[i].mac = mac.map(MacInfo::new);
            // An answer counts even if a later network failed mid-sweep.
            decided[i] = true;
        }
    }
    Ok(decided)
}

/// Add `ip` to the group for `net`, starting one if needed.
fn add_to_group<N: Clone + PartialEq, A>(groups: &mut Vec<(N, Vec<A>)>, net: &N, ip: A) {
    match groups.iter_mut().find(|(n, _)| n == net) {
        Some((_, ips)) => ips.push(ip),
        None => groups.push((net.clone(), vec![ip])),
    }
}

/// Whether this process can send ICMP (IPv4) echo requests at all.
pub fn icmp_available() -> bool {
    icmp::open(false).is_ok()
}

mod icmp {
    use std::collections::{HashMap, HashSet};
    use std::io;
    use std::mem::MaybeUninit;
    use std::net::IpAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    use socket2::{Domain, Protocol, Socket, Type};

    use crate::model::ScanConfig;
    use crate::packet::{self, ICMP_ECHO_REPLY, ICMPV6_ECHO_REPLY};
    use crate::raw::{Pacer, send_with_backoff};
    use crate::target::socket_addr;

    /// Open an ICMP (or, with `v6`, ICMPv6) socket: raw if privileged,
    /// otherwise the unprivileged "ping socket" that Linux (within
    /// `ping_group_range`) and macOS offer. Returns the socket and whether
    /// the kernel rewrites the echo id.
    pub(super) fn open(v6: bool) -> io::Result<(Socket, bool)> {
        // Windows raw sockets cannot reliably receive ICMP replies.
        if cfg!(windows) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "ICMP discovery is not supported on Windows",
            ));
        }
        let (domain, proto) = if v6 {
            (Domain::IPV6, Protocol::ICMPV6)
        } else {
            (Domain::IPV4, Protocol::ICMPV4)
        };
        match Socket::new(domain, Type::RAW, Some(proto)) {
            Ok(s) => Ok((s, false)),
            Err(raw_err) => Socket::new(domain, Type::DGRAM, Some(proto))
                .map(|s| (s, true))
                .map_err(|_| raw_err),
        }
    }

    /// Callback for each host that answered, with its RTT in ms.
    pub(super) type OnReply<'a> = &'a mut dyn FnMut(IpAddr, f64);

    /// Ping every address (all of one family), calling `on_reply` once per
    /// host that answers. Stops early when `cancel` is set.
    pub(super) fn sweep(
        addrs: &[IpAddr],
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
        addrs: &[IpAddr],
        cfg: &ScanConfig,
        cancel: &AtomicBool,
        on_reply: OnReply<'_>,
    ) -> io::Result<()> {
        let mut replies: HashMap<IpAddr, f64> = HashMap::new();
        if addrs.is_empty() || cancel.load(Ordering::Relaxed) {
            return Ok(());
        }
        let v6 = addrs[0].is_ipv6();
        debug_assert!(addrs.iter().all(|a| a.is_ipv6() == v6));
        let (sock, id_rewritten) = open(v6)?;
        sock.set_read_timeout(Some(Duration::from_millis(50)))?;
        let sock = Arc::new(sock);
        let id = (std::process::id() & 0xffff) as u16;
        let targets: HashSet<IpAddr> = addrs.iter().copied().collect();

        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = std::sync::mpsc::channel::<(IpAddr, u16, Instant)>();
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
                    let Some(sender) = sender.as_socket().map(|a| a.ip()) else {
                        continue;
                    };
                    let at = Instant::now();
                    // IPv4 raw sockets (and macOS ping sockets) include the
                    // IP header; Linux ping sockets do not, and IPv6 sockets
                    // never do. An echo reply starts with type 0, never with
                    // an IPv4 version nibble of 4.
                    let icmp = match packet::parse_ipv4(data) {
                        _ if v6 => data,
                        Some(ip) if ip.protocol == packet::IPPROTO_ICMP => ip.payload,
                        Some(_) => continue,
                        None => data,
                    };
                    let Some(msg) = packet::parse_icmp(icmp) else {
                        continue;
                    };
                    let reply = if v6 {
                        ICMPV6_ECHO_REPLY
                    } else {
                        ICMP_ECHO_REPLY
                    };
                    if msg.kind != reply || (!id_rewritten && msg.id != id) {
                        continue;
                    }
                    let _ = tx.send((sender, msg.seq, at));
                }
            })
        };

        let mut sent_at: HashMap<u16, (IpAddr, Instant)> = HashMap::new();
        let mut pending: Vec<(u16, IpAddr)> = addrs
            .iter()
            .enumerate()
            .map(|(i, a)| (i as u16, *a))
            .collect();
        let mut record = |(src, seq, at): (IpAddr, u16, Instant),
                          sent_at: &HashMap<u16, (IpAddr, Instant)>,
                          replies: &mut HashMap<IpAddr, f64>| {
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
                let mut pacer = Pacer::for_config(cfg);
                for &(seq, addr) in &pending {
                    let pkt = if v6 {
                        packet::icmpv6_echo(id, seq, b"feroprobe")
                    } else {
                        packet::icmp_echo(id, seq, b"feroprobe")
                    };
                    if !pacer.wait_or_cancel(cancel) {
                        return Ok(());
                    }
                    sent_at.insert(seq, (addr, Instant::now()));
                    if let Err(e) = send_with_backoff(&sock, &pkt, socket_addr(addr, 0))
                        && !crate::connect::is_network_error(&e)
                    {
                        return Err(e);
                    }
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

    #[tokio::test]
    async fn ipv6_localhost_is_up() {
        if !crate::testutil::ipv6_loopback() {
            return;
        }
        let cfg = ScanConfig {
            timeout: Duration::from_secs(5),
            ..Default::default()
        };
        let targets = [
            Target::new("::1".parse().unwrap()),
            Target::new("127.0.0.1".parse().unwrap()),
        ];
        let hosts = discover(&targets, &cfg).await.unwrap();
        assert!(hosts.iter().all(HostResult::is_up), "{hosts:?}");
        // On Linux with raw sockets the ICMPv6 echo is sure to run, and its
        // answer wins over a TCP reset. Elsewhere only the TCP probes may run.
        if cfg!(target_os = "linux") && crate::raw::raw_ipv6_available() {
            assert_eq!(hosts[0].up_reason, Some(reason::ECHO_REPLY), "{hosts:?}");
        }
    }
}
