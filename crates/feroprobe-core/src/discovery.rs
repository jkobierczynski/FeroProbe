//! Host discovery: find out which targets are up before port scanning them.
//!
//! With raw sockets, a target that is this machine (a loopback address, or
//! one of its own addresses, which Linux routes over `lo`) is marked up
//! without any probe, with the reason `localhost-response`, as nmap does.
//!
//! Targets on a directly connected Ethernet network are asked for their MAC
//! address with ARP (IPv4, see [`crate::arp`]) or neighbour discovery (IPv6,
//! see [`crate::ndp`]), when the process may use raw sockets on Linux. Their
//! answer, or its absence, decides them alone.
//!
//! Every other target gets the probes in [`PingProbes`], and any answer
//! counts. By default they are nmap's (see [`PingProbes::nmap_default`]):
//!
//! - with raw sockets (root on Linux): an ICMP or ICMPv6 echo request, a
//!   bare TCP SYN to port 443, a bare TCP ACK to port 80, and an ICMP
//!   timestamp request (IPv4 only)
//! - without them: TCP connects to ports 80 and 443, where a completed
//!   handshake or a reset both prove the host exists, plus an ICMP echo
//!   request through an unprivileged ping socket where the OS offers one
//!   (nmap has no such socket, so it sends no ICMP here)
//!
//! nmap's `-P` options pick other probes: TCP SYNs to chosen ports (`-PS`),
//! bare TCP ACKs that a live host answers with a reset (`-PA`), UDP
//! datagrams that draw an answer or a port unreachable (`-PU`), and ICMP
//! echo, timestamp and address mask requests (`-PE`, `-PP`, `-PM`; the last
//! two need raw sockets and IPv4), SCTP INITs that a live host answers
//! with an INIT-ACK or an ABORT (`-PY`), and IP protocol pings (`-PO`: by
//! default ICMP, IGMP and IP-in-IP packets, any answer in the same protocol
//! or an ICMP protocol unreachable from the host proving it). The TCP
//! probes are raw packets when raw sockets are available on Linux, and
//! connects otherwise, as in nmap; `-PY` and `-PO` need raw sockets on
//! Linux.
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
use crate::connect::probe_port_in;
use crate::model::{HostResult, PortState, ScanConfig, reason};
use crate::ndp;
use crate::raw::{raw_ipv6_available, raw_sockets_available};
use crate::rtt::AsyncWindow;
use crate::syn::{HostsDone, RawTcpScan, TcpScanKind, raw_tcp_scan_until};
use crate::target::Target;
use crate::udp::probe_udp_in;

/// TCP ports connected to during default discovery without raw sockets
/// (nmap's `DEFAULT_PING_CONNECT_PORT_SPEC`).
pub const DISCOVERY_PORTS: [u16; 2] = [80, 443];

/// The port the default raw TCP SYN probe goes to, as in nmap.
pub const DEFAULT_SYN_PING_PORT: u16 = 443;

/// The port the default raw TCP ACK probe goes to, as in nmap.
pub const DEFAULT_ACK_PING_PORT: u16 = 80;

/// The port `-PS` and `-PA` probe when no ports are given, as in nmap.
pub const DEFAULT_TCP_PING_PORT: u16 = 80;

/// The port `-PU` probes when no ports are given: nmap's choice, unlikely
/// to be open, so a live host answers with a port unreachable.
pub const DEFAULT_UDP_PING_PORT: u16 = 40125;

/// The port `-PY` probes when no ports are given, as in nmap.
pub const DEFAULT_SCTP_PING_PORT: u16 = 80;

/// The protocols `-PO` probes when none are given, as in nmap: ICMP, IGMP
/// and IP-in-IP.
pub const DEFAULT_PROTO_PINGS: [u8; 3] = [1, 2, 4];

/// Which probes host discovery sends, like nmap's `-P` options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PingProbes {
    /// `-PE`: ICMP (or ICMPv6) echo request.
    pub echo: bool,
    /// `-PP`: ICMP timestamp request (IPv4, raw sockets).
    pub timestamp: bool,
    /// `-PM`: ICMP address mask request (IPv4, raw sockets).
    pub mask: bool,
    /// `-PS`: TCP ports to send a SYN to; a SYN/ACK or a reset proves the
    /// host. Raw SYNs on Linux with raw sockets, else a connect.
    pub syn: Vec<u16>,
    /// `-PA`: TCP ports to send a bare ACK to, which a live host answers
    /// with a reset. Needs raw sockets on Linux; elsewhere these ports get a
    /// connect, as nmap does without privileges.
    pub ack: Vec<u16>,
    /// `-PU`: UDP ports to send a datagram to; an answer or a port
    /// unreachable proves the host.
    pub udp: Vec<u16>,
    /// `-PY`: SCTP ports to send an INIT to; an INIT-ACK or an ABORT proves
    /// the host. Raw sockets on Linux only.
    pub sctp: Vec<u16>,
    /// `-PO`: IP protocols to send a packet of; an answer in the same
    /// protocol, or the host's own protocol or port unreachable, proves it.
    /// Raw sockets on Linux only.
    pub proto: Vec<u8>,
}

impl Default for PingProbes {
    /// The unprivileged default: see [`PingProbes::nmap_default`].
    fn default() -> Self {
        Self::nmap_default(false)
    }
}

impl PingProbes {
    /// nmap's default probes. With raw TCP probes (`raw`, see
    /// [`raw_tcp_pings`]): ICMP echo, a SYN to 443, an ACK to 80 and an ICMP
    /// timestamp request (sent to IPv4 targets only). Without: connects to
    /// 80 and 443, plus an ICMP echo that goes out only if the OS offers an
    /// unprivileged ping socket.
    pub fn nmap_default(raw: bool) -> Self {
        if raw {
            Self {
                echo: true,
                timestamp: true,
                syn: vec![DEFAULT_SYN_PING_PORT],
                ack: vec![DEFAULT_ACK_PING_PORT],
                ..Self::none()
            }
        } else {
            Self {
                echo: true,
                syn: DISCOVERY_PORTS.to_vec(),
                ..Self::none()
            }
        }
    }

    /// No probes at all, to add chosen ones to.
    pub fn none() -> Self {
        Self {
            echo: false,
            timestamp: false,
            mask: false,
            syn: Vec::new(),
            ack: Vec::new(),
            udp: Vec::new(),
            sctp: Vec::new(),
            proto: Vec::new(),
        }
    }

    /// Whether any probe needs raw sockets on Linux whatever the fallback:
    /// `-PY` and `-PO` have none, as in nmap.
    pub fn needs_raw(&self) -> bool {
        !self.sctp.is_empty() || !self.proto.is_empty()
    }
}

/// One TCP or UDP discovery probe to a port.
#[derive(Debug, Clone, Copy)]
enum PortProbe {
    Tcp(u16),
    Udp(u16),
}

/// Sets a flag when dropped, so the blocking ICMP sweep stops even if
/// discovery returns early with an error or its future is dropped.
struct CancelOnDrop(Arc<AtomicBool>);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// Whether discovery sends its TCP probes (`-PS`, `-PA`) as raw SYN and
/// ACK packets, as nmap does with privileges: raw sockets on Linux, for
/// IPv6 too when any target needs it. Otherwise they are connects.
pub fn raw_tcp_pings(targets: &[Target]) -> bool {
    cfg!(target_os = "linux")
        && raw_sockets_available()
        && (!targets.iter().any(|t| t.addr.is_ipv6()) || raw_ipv6_available())
}

/// Whether `addr` is this machine: a loopback address, or one of its own
/// addresses (the OS picks it as the source to reach itself; Linux routes
/// that traffic over `lo`). nmap skips the ping for these targets when it
/// runs privileged, since they route over the loopback interface.
pub fn is_localhost(addr: IpAddr) -> bool {
    #[cfg(target_os = "linux")]
    let own =
        || !addr.is_unspecified() && crate::raw::source_addr_for(addr).is_ok_and(|src| src == addr);
    // Elsewhere only loopback addresses count.
    #[cfg(not(target_os = "linux"))]
    let own = || false;
    addr.is_loopback() || own()
}

/// Probe every target and return one [`HostResult`] per target, in order,
/// with `up_reason` set for the hosts that answered.
pub async fn discover(
    targets: &[Target],
    cfg: &ScanConfig,
    probes: &PingProbes,
) -> io::Result<Vec<HostResult>> {
    discover_with(targets, cfg, probes, raw_sockets_available()).await
}

/// What `-Pn` still does, as nmap does: ask the targets on a local
/// Ethernet network for their MAC address with ARP or neighbour discovery
/// (unless `--disable-arp-ping`), for the report's MAC address and latency
/// and the port scan's first timeouts. Every target is scanned whatever
/// comes back; those that answer get the answer's reason.
pub async fn neighbours_only(targets: &[Target], cfg: &ScanConfig) -> io::Result<Vec<HostResult>> {
    let mut hosts: Vec<HostResult> = targets
        .iter()
        .map(|t| HostResult::new(t.addr, t.hostname.clone()))
        .collect();
    if cfg.arp_ping && raw_sockets_available() {
        // This machine itself needs no request.
        let mut decided: Vec<bool> = targets.iter().map(|t| is_localhost(t.addr)).collect();
        neighbour_phase(targets, cfg, &mut hosts, &mut decided).await?;
    }
    Ok(hosts)
}

/// [`discover`], with the localhost shortcut on or off (`localhost_up`),
/// so tests can still send probes to 127.0.0.1 when running as root.
async fn discover_with(
    targets: &[Target],
    cfg: &ScanConfig,
    probes: &PingProbes,
    localhost_up: bool,
) -> io::Result<Vec<HostResult>> {
    let mut hosts: Vec<HostResult> = targets
        .iter()
        .map(|t| HostResult::new(t.addr, t.hostname.clone()))
        .collect();
    // Hosts already settled, up or down, skip the other probes. Like nmap
    // with privileges, this machine itself is up without a probe.
    let mut decided = vec![false; targets.len()];
    if localhost_up {
        for (h, t) in targets.iter().enumerate() {
            if is_localhost(t.addr) {
                hosts[h].up_reason = Some(reason::LOCALHOST);
                decided[h] = true;
            }
        }
    }
    // Then ARP or NDP for hosts on a local Ethernet network.
    if cfg.arp_ping {
        neighbour_phase(targets, cfg, &mut hosts, &mut decided).await?;
    }
    let decided = decided;

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

    // The ICMP sweeps (one per query type and address family) run on
    // blocking threads and stream replies back, so hosts that answer one
    // skip their TCP and UDP probes.
    let cancel = CancelOnDrop(Arc::new(AtomicBool::new(false)));
    let (reply_tx, mut replies) =
        tokio::sync::mpsc::unbounded_channel::<(IpAddr, f64, &'static str)>();
    let mut icmp = Vec::new();
    let queries = [
        (probes.echo, icmp::Query::Echo),
        (probes.timestamp, icmp::Query::Timestamp),
        (probes.mask, icmp::Query::Mask),
    ];
    for (_, query) in queries.into_iter().filter(|(on, _)| *on) {
        for v6 in [false, true] {
            let addrs = undecided(v6);
            // Timestamp and address mask requests exist only in ICMPv4.
            if addrs.is_empty() || (v6 && query != icmp::Query::Echo) {
                continue;
            }
            let (cfg, cancel, reply_tx) = (cfg.clone(), Arc::clone(&cancel.0), reply_tx.clone());
            icmp.push(tokio::task::spawn_blocking(move || {
                icmp::sweep(&addrs, &cfg, query, &cancel, &mut |addr, rtt| {
                    let _ = reply_tx.send((addr, rtt, query.reason()));
                })
            }));
        }
    }
    drop(reply_tx);

    // Hosts proven up (or settled before the probes): later probes skip
    // them, the raw SYN and ACK scans included.
    let pinged: Arc<Vec<AtomicBool>> =
        Arc::new(decided.iter().map(|&d| AtomicBool::new(d)).collect());

    // An ICMP reply is the most direct proof of life; prefer its latency
    // over a TCP probe's, and keep the first one that came.
    let mark_pinged = |hosts: &mut Vec<HostResult>,
                       (addr, rtt, why): (IpAddr, f64, &'static str)| {
        if let Some(&h) = index.get(&addr)
            && !decided[h]
            && !pinged[h].swap(true, Ordering::Relaxed)
        {
            hosts[h].up_reason = Some(why);
            hosts[h].latency_ms = Some(rtt);
        }
    };

    // With raw sockets on Linux, -PS and -PA send bare SYNs and ACKs, as
    // nmap does when privileged. Without them nmap connects to both port
    // lists instead, and so do we.
    let live_index: Vec<usize> = (0..targets.len()).filter(|&h| !decided[h]).collect();
    let live: Vec<Target> = live_index.iter().map(|&h| targets[h].clone()).collect();
    let done = HostsDone {
        flags: Arc::clone(&pinged),
        tcp: Arc::new(targets.iter().map(|_| AtomicBool::new(false)).collect()),
        index: live_index,
    };
    let raw_tcp = !live.is_empty() && raw_tcp_pings(&live);
    let raw_scans: Vec<_> = [
        (TcpScanKind::Syn, &probes.syn),
        (TcpScanKind::Ack, &probes.ack),
    ]
    .into_iter()
    .filter(|(_, ports)| raw_tcp && !ports.is_empty())
    .map(|(kind, ports)| {
        let (live, ports, cfg, done) = (live.clone(), ports.clone(), cfg.clone(), done.clone());
        tokio::spawn(async move {
            raw_tcp_scan_until(&live, &ports, &cfg, RawTcpScan::new(kind), Some(done)).await
        })
    })
    .collect();
    // -PY and -PO: raw SCTP INITs and IP protocol packets, read off the
    // packet capture like the -sY and -sO scans.
    let sctp_ping = (!live.is_empty() && !probes.sctp.is_empty()).then(|| {
        let (live, ports, cfg, done) =
            (live.clone(), probes.sctp.clone(), cfg.clone(), done.clone());
        tokio::spawn(async move { crate::sctp::sctp_ping(&live, &ports, &cfg, Some(done)).await })
    });
    let proto_ping = (!live.is_empty() && !probes.proto.is_empty()).then(|| {
        let (live, protos, cfg, done) = (
            live.clone(),
            probes.proto.clone(),
            cfg.clone(),
            done.clone(),
        );
        tokio::spawn(async move {
            crate::ipproto::ip_proto_ping(&live, &protos, &cfg, Some(done)).await
        })
    });

    let mut tcp_ports = Vec::new();
    if !raw_tcp {
        tcp_ports.extend(&probes.syn);
        tcp_ports.extend(&probes.ack);
    }
    let mut seen_ports = HashSet::new();
    tcp_ports.retain(|p| seen_ports.insert(*p));
    let port_probes: Vec<PortProbe> = tcp_ports
        .into_iter()
        .map(PortProbe::Tcp)
        .chain(probes.udp.iter().map(|&p| PortProbe::Udp(p)))
        .collect();
    let jobs = port_probes
        .iter()
        .flat_map(|&probe| (0..targets.len()).map(move |h| (h, probe)));
    // The probes share congestion windows, as in the port scans.
    // A probe waiting for its place is dropped once its host is proven up
    // meanwhile, by ICMP or a raw TCP answer, as well as before it starts.
    let (up_icmp, up_tcp) = (pinged.clone(), done.tcp.clone());
    let window =
        AsyncWindow::new(cfg, vec![port_probes.len(); targets.len()]).with_skip(move |h| {
            up_icmp[h].load(Ordering::Relaxed) || up_tcp[h].load(Ordering::Relaxed)
        });
    let window = &window;
    let mut probes = stream::iter(jobs)
        // Checked when a probe is about to start: skip hosts already proven
        // up by ICMP (pinged) or by a raw TCP answer (done.tcp).
        .filter(|&(h, _)| {
            let up = pinged[h].load(Ordering::Relaxed) || done.tcp[h].load(Ordering::Relaxed);
            if up {
                window.settled(h);
            }
            std::future::ready(!up)
        })
        .map(|(h, probe)| async move {
            let r = match probe {
                PortProbe::Tcp(port) => {
                    let addr = crate::target::socket_addr(targets[h].addr, port);
                    probe_port_in(addr, cfg, Some((window, h))).await
                }
                PortProbe::Udp(port) => {
                    let addr = crate::target::socket_addr(targets[h].addr, port);
                    probe_udp_in(addr, cfg, Some((window, h))).await
                }
            };
            (h, r)
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

    // Late ICMP replies still count until the sweep's own timeout ends.
    while let Some(reply) = replies.recv().await {
        mark_pinged(&mut hosts, reply);
    }
    // A SYN/ACK or reset to a bare SYN (open or closed), or a reset to a
    // bare ACK (unfiltered), proves the host is there.
    for scan in raw_scans {
        let answered = scan.await.map_err(io::Error::other)??;
        let undecided_hosts = (0..targets.len()).filter(|&h| !decided[h]);
        for (h, r) in undecided_hosts.zip(answered) {
            let host = &mut hosts[h];
            if host.up_reason.is_none()
                && let Some(p) = r.ports.iter().find(|p| p.state != PortState::Filtered)
            {
                host.up_reason = Some(p.reason);
                host.latency_ms = p.rtt_ms;
            }
        }
    }
    // The SCTP and IP protocol pings mark each answer that proves its host
    // up as open (see sctp::sctp_ping, ipproto::ip_proto_ping).
    for ping in [sctp_ping, proto_ping].into_iter().flatten() {
        let answered = ping.await.map_err(io::Error::other)??;
        let undecided_hosts = (0..targets.len()).filter(|&h| !decided[h]);
        for (h, r) in undecided_hosts.zip(answered) {
            let host = &mut hosts[h];
            if host.up_reason.is_none()
                && let Some(p) = r.ports.iter().find(|p| p.state == PortState::Open)
            {
                host.up_reason = Some(p.reason);
                host.latency_ms = p.rtt_ms;
            }
        }
    }
    // ICMP is best effort: if the OS does not let us ping (no privileges, or
    // a platform without usable ICMP sockets), the TCP probes decide alone.
    for sweep in icmp {
        let _ = sweep.await.map_err(io::Error::other)?;
    }
    Ok(hosts)
}

/// Ask every target not yet decided that sits on a local Ethernet network
/// for its MAC address: with ARP for IPv4 and neighbour discovery for IPv6.
/// Fills in the hosts that answered and marks, per target, whether it is
/// now decided. A network where this cannot run (no privileges, not Linux)
/// decides nothing, so those targets fall back to the ICMP and TCP probes.
async fn neighbour_phase(
    targets: &[Target],
    cfg: &ScanConfig,
    hosts: &mut [HostResult],
    decided: &mut [bool],
) -> io::Result<()> {
    let nets = arp::local_networks().unwrap_or_default();
    let links = ndp::local_links().unwrap_or_default();
    // Group the targets by the local network they are on.
    let mut arp_groups: Vec<(arp::LocalNet, Vec<Ipv4Addr>)> = Vec::new();
    let mut nd_groups: Vec<(ndp::LocalLink, Vec<Ipv6Addr>)> = Vec::new();
    let mut seen: HashSet<IpAddr> = HashSet::new();
    for (t, _) in targets.iter().zip(decided.iter()).filter(|(_, d)| !**d) {
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
        return Ok(());
    }

    let cancel = CancelOnDrop(Arc::new(AtomicBool::new(false)));
    let (cfg2, flag) = (cfg.clone(), Arc::clone(&cancel.0));
    let (settled, replies) = tokio::task::spawn_blocking(move || {
        let mut settled: HashSet<IpAddr> = HashSet::new();
        let mut replies: HashMap<IpAddr, (Option<MacAddr>, f64, &'static str)> = HashMap::new();
        for (net, ips) in &arp_groups {
            let r = arp::sweep(net, ips, &cfg2, &flag, &mut |ip, mac, rtt| {
                // The round trip times the port scan's first probes, as in
                // nmap: without it they wait the full initial timeout until
                // a port answers.
                cfg2.observe_rtt(ip.into(), std::time::Duration::from_secs_f64(rtt / 1000.0));
                replies.insert(ip.into(), (Some(mac), rtt, reason::ARP_RESPONSE));
            });
            if r.is_ok() {
                settled.extend(ips.iter().map(|&ip| IpAddr::from(ip)));
            }
        }
        for (link, ips) in &nd_groups {
            let r = ndp::sweep(link, ips, &cfg2, &flag, &mut |ip, mac, rtt| {
                // The round trip times the port scan's first probes, as in
                // nmap: without it they wait the full initial timeout until
                // a port answers.
                cfg2.observe_rtt(ip.into(), std::time::Duration::from_secs_f64(rtt / 1000.0));
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
        if decided[i] {
            continue;
        }
        decided[i] = settled.contains(&t.addr);
        if let Some(&(mac, rtt, why)) = replies.get(&t.addr) {
            hosts[i].up_reason = Some(why);
            hosts[i].latency_ms = Some(rtt);
            hosts[i].mac = mac.map(MacInfo::new);
            // An answer counts even if a later network failed mid-sweep.
            decided[i] = true;
        }
    }
    Ok(())
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

    use crate::model::{ScanConfig, reason};
    use crate::packet::{self, ICMP_ECHO_REPLY, ICMPV6_ECHO_REPLY};

    /// The ICMP query a sweep sends.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum Query {
        Echo,
        Timestamp,
        Mask,
    }

    impl Query {
        /// The request to send, with a valid checksum (ICMPv6 leaves that
        /// to the kernel).
        fn request(self, v6: bool, id: u16, seq: u16) -> Vec<u8> {
            match self {
                Query::Echo if v6 => packet::icmpv6_echo(id, seq, packet::ECHO_MARKER),
                Query::Echo => packet::icmp_echo(id, seq, packet::ECHO_MARKER),
                // Originate, receive and transmit timestamps.
                Query::Timestamp => packet::icmp_query(packet::ICMP_TIMESTAMP, id, seq, 12),
                Query::Mask => packet::icmp_query(packet::ICMP_ADDRESS_MASK, id, seq, 4),
            }
        }

        /// The ICMP type of the answer.
        fn reply(self, v6: bool) -> u8 {
            match self {
                Query::Echo if v6 => ICMPV6_ECHO_REPLY,
                Query::Echo => ICMP_ECHO_REPLY,
                Query::Timestamp => packet::ICMP_TIMESTAMP_REPLY,
                Query::Mask => packet::ICMP_ADDRESS_MASK_REPLY,
            }
        }

        pub(super) fn reason(self) -> &'static str {
            match self {
                Query::Echo => reason::ECHO_REPLY,
                Query::Timestamp => reason::TIMESTAMP_REPLY,
                Query::Mask => reason::MASK_REPLY,
            }
        }
    }
    use crate::raw::{Pacer, nmap_ip_header, send_with_backoff};
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
        let (sock, rewrites_id) = match Socket::new(domain, Type::RAW, Some(proto)) {
            Ok(s) => (s, false),
            Err(raw_err) => Socket::new(domain, Type::DGRAM, Some(proto))
                .map(|s| (s, true))
                .map_err(|_| raw_err)?,
        };
        crate::netif::bind_socket(&sock, v6)?;
        Ok((sock, rewrites_id))
    }

    /// Callback for each host that answered, with its RTT in ms.
    pub(super) type OnReply<'a> = &'a mut dyn FnMut(IpAddr, f64);

    /// Ping every address (all of one family), calling `on_reply` once per
    /// host that answers. Stops early when `cancel` is set.
    pub(super) fn sweep(
        addrs: &[IpAddr],
        cfg: &ScanConfig,
        query: Query,
        cancel: &AtomicBool,
        on_reply: OnReply<'_>,
    ) -> io::Result<()> {
        // Sequence numbers are 16 bits and identify the probe, so query at
        // most 65536 hosts per round.
        for chunk in addrs.chunks(1 << 16) {
            sweep_chunk(chunk, cfg, query, cancel, on_reply)?;
        }
        Ok(())
    }

    fn sweep_chunk(
        addrs: &[IpAddr],
        cfg: &ScanConfig,
        query: Query,
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
        // Unprivileged ping sockets only carry echo requests.
        if id_rewritten && query != Query::Echo {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "ICMP timestamp and address mask requests need raw sockets",
            ));
        }
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
                    if msg.kind != query.reply(v6) || (!id_rewritten && msg.id != id) {
                        continue;
                    }
                    crate::packet_trace::log("RCVD", || {
                        let proto = if v6 { 58 } else { packet::IPPROTO_ICMP };
                        crate::packet_trace::describe_received(proto, data, sender)
                    });
                    let _ = tx.send((sender, msg.seq, at));
                }
            })
        };

        let mut sent_at: HashMap<u16, (IpAddr, Instant, bool)> = HashMap::new();
        let mut pending: Vec<(u16, IpAddr)> = addrs
            .iter()
            .enumerate()
            .map(|(i, a)| (i as u16, *a))
            .collect();
        let mut record = |(src, seq, at): (IpAddr, u16, Instant),
                          sent_at: &HashMap<u16, (IpAddr, Instant, bool)>,
                          replies: &mut HashMap<IpAddr, f64>| {
            // Only count a reply from the host this sequence number was sent
            // to, so one host cannot vouch for another by echoing its sequence.
            let Some(&(dst, sent, resent)) = sent_at.get(&seq) else {
                return;
            };
            if src == dst && !replies.contains_key(&dst) {
                let rtt = at.saturating_duration_since(sent);
                // A reply to a resent request may answer either copy, so
                // its round trip is left out of the estimate (Karn).
                if !resent {
                    cfg.observe_rtt(dst, rtt);
                }
                let rtt = (rtt.as_secs_f64() * 1e6).round() / 1000.0;
                replies.insert(dst, rtt);
                on_reply(dst, rtt);
            }
        };

        let outcome = (|| -> io::Result<()> {
            for _ in 0..=cfg.first_retries() {
                let mut pacer = Pacer::for_config(cfg);
                for &(seq, addr) in &pending {
                    let pkt = query.request(v6, id, seq);
                    if !pacer.wait_or_cancel(cancel) {
                        return Ok(());
                    }
                    let resent = sent_at.contains_key(&seq);
                    sent_at.insert(seq, (addr, Instant::now(), resent));
                    nmap_ip_header(&sock, v6);
                    if let Err(e) = send_with_backoff(&sock, &pkt, socket_addr(addr, 0))
                        && !crate::connect::is_network_error(&e)
                    {
                        return Err(e);
                    }
                    while let Ok(r) = rx.try_recv() {
                        record(r, &sent_at, &mut replies);
                    }
                }
                // Wait for late replies, but stop once every host has
                // answered, or each unanswered request has waited out its
                // host's adaptive timeout (see `crate::rtt`).
                let last_expiry =
                    |sent_at: &HashMap<u16, (IpAddr, Instant, bool)>,
                     replies: &HashMap<IpAddr, f64>| {
                        pending
                            .iter()
                            .filter(|(_, a)| !replies.contains_key(a))
                            .filter_map(|(seq, _)| sent_at.get(seq))
                            .map(|&(a, at, _)| at + cfg.probe_timeout(a))
                            .max()
                    };
                let mut deadline = last_expiry(&sent_at, &replies);
                loop {
                    if replies.len() >= targets.len() || cancel.load(Ordering::Relaxed) {
                        break;
                    }
                    let mut left = deadline.and_then(|d| d.checked_duration_since(Instant::now()));
                    if left.is_none() {
                        // A reply since the last look may have lengthened
                        // the timeouts: look again before giving up.
                        deadline = last_expiry(&sent_at, &replies);
                        left = deadline.and_then(|d| d.checked_duration_since(Instant::now()));
                    }
                    let Some(left) = left else { break };
                    // Wake up regularly to notice cancellation.
                    match rx.recv_timeout(left.min(Duration::from_millis(100))) {
                        Ok(r) => record(r, &sent_at, &mut replies),
                        // Timeouts move with each reply: look again.
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                            deadline = last_expiry(&sent_at, &replies);
                        }
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
            rtt: crate::rtt::RttTimeouts::fixed(Duration::from_secs(5)),
            ..Default::default()
        };
        // Long enough for Windows, which reports a refused connect only ~2s
        // after the reset (there, only the TCP probes run).
        let targets = [Target::new("127.0.0.1".parse().unwrap())];
        let hosts = discover(&targets, &cfg, &PingProbes::default())
            .await
            .unwrap();
        // As root it is up without a probe (localhost-response); otherwise
        // the ping or a TCP reset from 80/443 proves it.
        assert!(hosts[0].is_up(), "{:?}", hosts[0]);
        assert!(hosts[0].up_reason.is_some());
    }

    #[tokio::test]
    async fn localhost_shortcut_sends_nothing() {
        // As nmap does when privileged: this machine is up without a probe,
        // even with no probes to send at all.
        let targets = [
            Target::new("127.0.0.1".parse().unwrap()),
            Target::new("127.0.0.2".parse().unwrap()),
        ];
        let cfg = ScanConfig::default();
        let hosts = discover_with(&targets, &cfg, &PingProbes::none(), true)
            .await
            .unwrap();
        for h in &hosts {
            assert_eq!(h.up_reason, Some(reason::LOCALHOST), "{h:?}");
            assert_eq!(h.latency_ms, None);
        }
    }

    #[test]
    fn localhost_addresses() {
        assert!(is_localhost("127.0.0.1".parse().unwrap()));
        assert!(is_localhost("127.1.2.3".parse().unwrap()));
        assert!(is_localhost("::1".parse().unwrap()));
        assert!(!is_localhost("0.0.0.0".parse().unwrap()));
        // Documentation range: never one of our own addresses.
        assert!(!is_localhost("192.0.2.1".parse().unwrap()));
    }

    #[test]
    fn nmap_default_probes() {
        // nmap as root: -PE -PS443 -PA80 -PP.
        let root = PingProbes::nmap_default(true);
        assert!(root.echo && root.timestamp && !root.mask);
        assert_eq!((root.syn, root.ack), (vec![443], vec![80]));
        assert!(root.udp.is_empty());
        // nmap without privileges: connects to 80 and 443.
        let user = PingProbes::nmap_default(false);
        assert_eq!(user.syn, vec![80, 443]);
        assert!(user.ack.is_empty() && !user.timestamp);
        assert_eq!(user, PingProbes::default());
    }

    #[tokio::test]
    async fn chosen_ping_probes() {
        let cfg = ScanConfig {
            rtt: crate::rtt::RttTimeouts::fixed(Duration::from_secs(5)),
            ..Default::default()
        };
        let targets = [Target::new("127.0.0.1".parse().unwrap())];
        let raw = cfg!(target_os = "linux") && crate::raw::raw_sockets_available();
        let run = |probes: PingProbes| {
            let cfg = cfg.clone();
            let targets = targets.clone();
            // The probes themselves, without the localhost shortcut that
            // skips them as root.
            async move {
                discover_with(&targets, &cfg, &probes, false)
                    .await
                    .unwrap()
                    .remove(0)
            }
        };

        // A closed port answers a SYN (raw, or a connect) with a reset.
        let host = run(PingProbes {
            syn: vec![1],
            ..PingProbes::none()
        })
        .await;
        let want = if raw {
            reason::RESET
        } else {
            reason::CONN_REFUSED
        };
        assert_eq!(host.up_reason, Some(want), "{host:?}");

        // A bare ACK draws a reset; without raw sockets it is a connect.
        let host = run(PingProbes {
            ack: vec![1],
            ..PingProbes::none()
        })
        .await;
        let want = if raw {
            reason::RESET
        } else {
            reason::CONN_REFUSED
        };
        assert_eq!(host.up_reason, Some(want), "{host:?}");

        // A datagram to a closed UDP port draws a port unreachable.
        if cfg!(unix) {
            let host = run(PingProbes {
                udp: vec![DEFAULT_UDP_PING_PORT],
                ..PingProbes::none()
            })
            .await;
            assert_eq!(host.up_reason, Some(reason::PORT_UNREACH), "{host:?}");
        }

        // -PO: Linux has no handler for protocol 253 (reserved for
        // experiments), so it answers with a protocol unreachable; IGMP
        // draws nothing back on loopback, so 253 decides.
        if raw {
            let host = run(PingProbes {
                proto: vec![2, 253],
                ..PingProbes::none()
            })
            .await;
            assert_eq!(host.up_reason, Some(reason::PROTO_UNREACH), "{host:?}");
        }

        // Linux answers ICMP timestamp requests, but not address mask ones.
        if raw {
            let host = run(PingProbes {
                timestamp: true,
                ..PingProbes::none()
            })
            .await;
            assert_eq!(host.up_reason, Some(reason::TIMESTAMP_REPLY), "{host:?}");
        }

        // No probes at all: nothing can answer.
        let host = run(PingProbes::none()).await;
        assert!(!host.is_up(), "{host:?}");
    }

    #[tokio::test]
    async fn ipv6_localhost_is_up() {
        if !crate::testutil::ipv6_loopback() {
            return;
        }
        let cfg = ScanConfig {
            rtt: crate::rtt::RttTimeouts::fixed(Duration::from_secs(5)),
            ..Default::default()
        };
        let targets = [
            Target::new("::1".parse().unwrap()),
            Target::new("127.0.0.1".parse().unwrap()),
        ];
        // Without the localhost shortcut, so the probes run even as root.
        let hosts = discover_with(&targets, &cfg, &PingProbes::default(), false)
            .await
            .unwrap();
        assert!(hosts.iter().all(HostResult::is_up), "{hosts:?}");
        // On Linux with raw sockets the ICMPv6 echo is sure to run, and its
        // answer wins over a TCP reset. Elsewhere only the TCP probes may run.
        if cfg!(target_os = "linux") && crate::raw::raw_ipv6_available() {
            assert_eq!(hosts[0].up_reason, Some(reason::ECHO_REPLY), "{hosts:?}");
        }
    }
}
