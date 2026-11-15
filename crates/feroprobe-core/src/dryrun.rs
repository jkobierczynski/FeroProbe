//! `--dry-run`: work out every probe a scan would send and print it, in the
//! layout of the `--packet-trace` SENT lines, without sending anything.
//!
//! Nothing here opens a raw socket or puts a packet on the wire. The probes
//! are built with the same packet builders the scanners use, so the lines
//! show the real flags, sequence numbers, window, payload lengths and (with
//! `-f`/`--mtu`, `-D`, `-S`) the real fragments and source addresses. The
//! only lookup done is the routing table's choice of local address for each
//! target (a UDP socket "connect", which sends nothing), so the source shown
//! is the one a real run would use.
//!
//! Because nothing is sent, nothing is received: there are no RCVD lines and
//! no port states. Steps that depend on answers (which hosts are up, which
//! ports are open) cannot be predicted, so the dry run assumes every target
//! is up and lists the port-scan probes for all of them, and it only names
//! the follow-up steps (`-sV`, `-O`, `--traceroute`) that a real run would
//! start on the open ports it found. Retransmissions only happen for probes
//! that go unanswered, so only the first attempt of each probe is listed.

use std::collections::HashSet;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};

use crate::arp;
use crate::discovery::PingProbes;
use crate::evasion::Evasion;
use crate::ipproto::Probe as ProtoProbe;
use crate::ndp;
use crate::packet;
use crate::packet_trace;
use crate::sctp::SctpScanKind;
use crate::syn::RawTcpScan;
use crate::target::Target;
use crate::udp::payload_for;

/// The prefix of every probe line: nmap's packet trace says `SENT (time)`;
/// a dry run sends nothing, and says so on every line.
pub const PREFIX: &str = "NOT SENT (dry run)";

/// How host discovery would run.
#[derive(Debug, Clone)]
pub struct DryDiscovery {
    /// The `-P` probes (or the defaults).
    pub probes: PingProbes,
    /// Raw sockets are available (root or `CAP_NET_RAW` on Linux): decides
    /// ARP/ND, bare `-PA` ACKs, and ICMP timestamp/mask requests.
    pub privileged: bool,
    /// ICMP echo can be sent (raw, or an unprivileged ping socket).
    pub icmp: bool,
    /// ARP and neighbour discovery are on (no `--disable-arp-ping`).
    pub arp_ping: bool,
}

/// The TCP port scan.
#[derive(Debug, Clone, Copy)]
pub enum DryTcp {
    /// `-sT`: the kernel makes the connection.
    Connect,
    /// A raw-socket scan (`-sS`, `-sF`, ..., `--scanflags`).
    Raw(RawTcpScan),
}

/// Everything a dry run lays out, as the scan would run it.
#[derive(Debug, Clone)]
pub struct DryRun<'a> {
    pub targets: &'a [Target],
    /// `None` with `-Pn`.
    pub discovery: Option<DryDiscovery>,
    /// The TCP scan and its ports, in the order they would go out.
    pub tcp: Option<(DryTcp, &'a [u16])>,
    /// The UDP ports, in the order they would go out.
    pub udp: &'a [u16],
    /// The SCTP scan and its ports.
    pub sctp: Option<(SctpScanKind, &'a [u16])>,
    /// `-sO`: the IP protocol numbers.
    pub protocols: &'a [u8],
    pub evasion: &'a Evasion,
    /// Unanswered probes are sent this many more times in a real run.
    pub retries: u32,
    /// Extra lines for the header: steps the dry run cannot show, what a
    /// real run would need, and so on.
    pub notes: Vec<String>,
    /// What nmap, given the same options, would send in addition or
    /// instead. Printed in a box at the top, because a dry run is no
    /// preview of an nmap command.
    pub nmap_differences: Vec<String>,
}

/// How many probes the dry run listed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Summary {
    /// Host-discovery probes (ARP and ND requests included).
    pub discovery: u64,
    /// Port-scan probes; with `-f`/`--mtu` each fragment counts, with `-D`
    /// each decoy copy counts.
    pub scan: u64,
}

/// Fixed per-run values (source port, sequence cookie, ...) that a real
/// scan picks at random. Seeded from the clock like the scanners' own.
struct Values {
    sport: u16,
    cookie: u32,
    icmp_id: u16,
    ipid: u16,
}

impl Values {
    fn new() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let mut x = (nanos ^ (u64::from(std::process::id()) << 32)) | 1;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 32) as u32
        };
        Self {
            sport: 40000 + (next() % 20000) as u16,
            cookie: next(),
            icmp_id: (next() as u16) | 1,
            ipid: (next() as u16) | 1,
        }
    }
}

/// The local address the OS would use to reach `dst`. Connecting a UDP
/// socket only consults the routing table; nothing is sent.
pub fn route_source(dst: IpAddr) -> Option<IpAddr> {
    let sock = match dst {
        IpAddr::V4(_) => UdpSocket::bind("0.0.0.0:0"),
        IpAddr::V6(_) => UdpSocket::bind("[::]:0"),
    }
    .ok()?;
    sock.connect(crate::target::socket_addr(dst, 53)).ok()?;
    Some(sock.local_addr().ok()?.ip())
}

fn host_port(ip: Option<IpAddr>, port: Option<u16>) -> String {
    let port = port.map_or_else(|| "*".to_string(), |p| p.to_string());
    match ip {
        Some(IpAddr::V6(v6)) => format!("[{v6}]:{port}"),
        Some(ip) => format!("{ip}:{port}"),
        None => format!("*:{port}"),
    }
}

/// The dry run's output, with the counts kept as it goes.
struct Out<'w> {
    w: &'w mut dyn Write,
    count: u64,
}

impl Out<'_> {
    fn probe(&mut self, line: &str) -> io::Result<()> {
        self.count += 1;
        writeln!(self.w, "{PREFIX} {line}")
    }

    fn note(&mut self, line: &str) -> io::Result<()> {
        writeln!(self.w, "# {line}")
    }
}

/// Write the dry run to `w` and return how many probes it listed.
pub fn write(run: &DryRun<'_>, w: &mut dyn Write) -> io::Result<Summary> {
    let v = Values::new();
    let sources: Vec<Option<IpAddr>> = run.targets.iter().map(|t| route_source(t.addr)).collect();
    let mut out = Out { w, count: 0 };
    out.note("Dry run (--dry-run): these are the probes the scan would send. Nothing is sent.")?;
    not_nmap_banner(&mut out, &run.nmap_differences)?;
    for n in &run.notes {
        out.note(n)?;
    }
    for (t, src) in run.targets.iter().zip(&sources) {
        let name = t
            .hostname
            .as_deref()
            .map_or_else(String::new, |n| format!(" ({n})"));
        let via = src.map_or_else(
            || " [no route: a real scan marks it unreachable]".to_string(),
            |s| format!(" from {s}"),
        );
        out.note(&format!("Target {}{name}{via}", t.addr))?;
    }

    let mut summary = Summary::default();
    match &run.discovery {
        None => out.note("Host discovery: skipped (-Pn), every target is treated as up")?,
        Some(d) => {
            discovery(&mut out, run, d, &sources, &v)?;
            summary.discovery = out.count;
        }
    }
    let before = out.count;
    let any_scan =
        run.tcp.is_some() || !run.udp.is_empty() || run.sctp.is_some() || !run.protocols.is_empty();
    if any_scan {
        if run.discovery.is_some() {
            out.note(
                "Port scan: no replies in a dry run, so every target is shown as if it were up; \
                 a real scan only scans the hosts discovery finds",
            )?;
        }
        if let Some((kind, ports)) = run.tcp {
            tcp_scan(&mut out, run, kind, ports, &sources, &v)?;
        }
        if !run.udp.is_empty() {
            out.note("UDP scan (-sU)")?;
            // Port-major, like the raw scans: spreads the probes over hosts.
            for &port in run.udp {
                for (t, src) in run.targets.iter().zip(&sources) {
                    out.probe(&udp_line(*src, t.addr, port))?;
                }
            }
        }
        if let Some((kind, ports)) = run.sctp {
            out.note(match kind {
                SctpScanKind::Init => "SCTP INIT scan (-sY)",
                SctpScanKind::CookieEcho => "SCTP COOKIE ECHO scan (-sZ)",
            })?;
            for &port in ports {
                for (t, src) in run.targets.iter().zip(&sources) {
                    let chunk = match kind {
                        SctpScanKind::Init => packet::sctp_init(v.sport, port, v.cookie, v.cookie),
                        SctpScanKind::CookieEcho => {
                            packet::sctp_cookie_echo(v.sport, port, v.cookie, v.cookie)
                        }
                    };
                    out.probe(&packet_trace::describe(
                        packet::IPPROTO_SCTP,
                        &chunk,
                        *src,
                        Some(t.addr),
                    ))?;
                }
            }
        }
        if !run.protocols.is_empty() {
            out.note("IP protocol scan (-sO)")?;
            let probe = ProtoProbe {
                sport: v.sport,
                seq: v.cookie,
                ipid: v.ipid,
                icmp_id: v.icmp_id,
            };
            for &proto in run.protocols {
                for (t, src) in run.targets.iter().zip(&sources) {
                    let line = match src {
                        Some(s) if s.is_ipv4() == t.addr.is_ipv4() => {
                            let body = probe.body(proto, *s, t.addr);
                            packet_trace::describe(proto, &body, Some(*s), Some(t.addr))
                        }
                        _ => format!(
                            "{} * > {} (no route)",
                            crate::ports::ip_protocol_name(proto).to_uppercase(),
                            t.addr
                        ),
                    };
                    out.probe(&line)?;
                }
            }
        }
    }
    summary.scan = out.count - before;
    let retry = if run.retries > 0 {
        format!(
            "; a real run resends unanswered probes up to {} more time{}",
            run.retries,
            if run.retries == 1 { "" } else { "s" }
        )
    } else {
        String::new()
    };
    out.note(&format!(
        "Dry run done: {} discovery and {} port-scan probe{} for {} host{} listed, nothing sent{retry}. \
         These are FeroProbe's probes, not nmap's",
        summary.discovery,
        summary.scan,
        if summary.scan == 1 { "" } else { "s" },
        run.targets.len(),
        if run.targets.len() == 1 { "" } else { "s" },
    ))?;
    Ok(summary)
}

/// The warning at the top of every dry run: this lists FeroProbe's probes,
/// and nmap run with the same options sends different ones. People may use
/// a dry run to check a command before running it with nmap, so it is a
/// box rather than small print, followed by what nmap would do differently.
fn not_nmap_banner(out: &mut Out<'_>, differences: &[String]) -> io::Result<()> {
    const RULE: &str = "=======================================================================";
    out.note(RULE)?;
    out.note("NOT A PREVIEW OF NMAP. These are FeroProbe's probes. nmap run with the same")?;
    out.note("options sends different packets, sometimes to ports outside -p. Do not use")?;
    out.note("this list to check what an nmap command will send.")?;
    if !differences.is_empty() {
        out.note("What nmap would send differently with these options:")?;
        for d in differences {
            out.note(&format!("  - {d}"))?;
        }
    }
    out.note(RULE)
}

/// The UDP datagram a UDP probe sends; the kernel picks the source port.
fn udp_line(src: Option<IpAddr>, dst: IpAddr, port: u16) -> String {
    format!(
        "UDP {} > {} len={}",
        host_port(src, None),
        host_port(Some(dst), Some(port)),
        payload_for(port).len()
    )
}

/// A TCP connect: the kernel builds the SYN, like nmap's CONN lines.
fn conn_line(dst: IpAddr, port: u16) -> String {
    format!("CONN TCP localhost > {}", host_port(Some(dst), Some(port)))
}

fn tcp_scan(
    out: &mut Out<'_>,
    run: &DryRun<'_>,
    kind: DryTcp,
    ports: &[u16],
    sources: &[Option<IpAddr>],
    v: &Values,
) -> io::Result<()> {
    match kind {
        DryTcp::Connect => {
            out.note("TCP connect scan (-sT)")?;
            for &port in ports {
                for t in run.targets {
                    out.probe(&conn_line(t.addr, port))?;
                }
            }
        }
        DryTcp::Raw(scan) => {
            let flags = packet_trace::tcp_flags(scan.flags);
            out.note(&format!(
                "TCP scan with raw packets, flags {}",
                if flags.is_empty() { "none" } else { &flags }
            ))?;
            if run.evasion.is_active() {
                out.note(&evasion_note(run.evasion))?;
            }
            let ack = if scan.flags & packet::TCP_ACK != 0 {
                v.cookie
            } else {
                0
            };
            for &port in ports {
                for (t, src) in run.targets.iter().zip(sources) {
                    let Some(src) = *src else {
                        out.probe(&format!(
                            "TCP * > {} (no route)",
                            host_port(Some(t.addr), Some(port))
                        ))?;
                        continue;
                    };
                    if run.evasion.is_active()
                        && let (IpAddr::V4(dst4), IpAddr::V4(_)) = (t.addr, src)
                    {
                        for line in evasion_lines(run.evasion, src, dst4, port, v, ack, scan.flags)
                        {
                            out.probe(&line)?;
                        }
                        continue;
                    }
                    let seg = tcp_segment(src, t.addr, port, v, ack, scan.flags);
                    out.probe(&packet_trace::describe(
                        packet::IPPROTO_TCP,
                        &seg,
                        Some(src),
                        Some(t.addr),
                    ))?;
                }
            }
        }
    }
    Ok(())
}

/// The segment a raw TCP scan sends, as `syn.rs` builds it: a plain SYN
/// keeps its MSS option, any other flags get a bare header.
fn tcp_segment(src: IpAddr, dst: IpAddr, port: u16, v: &Values, ack: u32, flags: u8) -> Vec<u8> {
    if flags == packet::TCP_SYN {
        packet::tcp_syn(src, dst, v.sport, port, v.cookie).to_vec()
    } else {
        packet::tcp_probe(src, dst, v.sport, port, v.cookie, ack, flags).to_vec()
    }
}

fn evasion_note(ev: &Evasion) -> String {
    let mut parts = Vec::new();
    if let Some(f) = ev.fragment {
        parts.push(match f {
            crate::evasion::Fragment::Eight => "fragmented into 8-byte pieces (-f)".to_string(),
            crate::evasion::Fragment::Mtu(n) => format!("fragmented at --mtu {n}"),
        });
    }
    if !ev.decoys.is_empty() {
        let list: Vec<String> = ev.decoys.iter().map(ToString::to_string).collect();
        parts.push(format!(
            "one copy from each decoy ({}) before the real one (-D)",
            list.join(", ")
        ));
    }
    if let Some(s) = ev.spoof_source {
        parts.push(format!("source address spoofed as {s} (-S)"));
    }
    format!("Evasion: {}", parts.join("; "))
}

/// The packets `syn.rs`'s `send_evasion` would put on the wire for one
/// probe: one IPv4 datagram per source address (decoys first, then the real
/// or spoofed source), each split into fragments if asked.
fn evasion_lines(
    ev: &Evasion,
    real_src: IpAddr,
    dst: Ipv4Addr,
    port: u16,
    v: &Values,
    ack: u32,
    flags: u8,
) -> Vec<String> {
    let to = SocketAddr::new(IpAddr::V4(dst), 0);
    let mut lines = Vec::new();
    for (i, source) in ev.source_addrs(real_src).into_iter().enumerate() {
        let IpAddr::V4(src4) = source else { continue };
        let seg = tcp_segment(source, IpAddr::V4(dst), port, v, ack, flags);
        let id = (v.cookie as u16) ^ port ^ (i as u16);
        let pkt = packet::ipv4_packet(src4, dst, packet::IPPROTO_TCP, 64, id, &seg);
        let frags = match ev.fragment {
            Some(f) => crate::evasion::fragment_ipv4(&pkt, f),
            None => vec![pkt],
        };
        for frag in &frags {
            lines.push(packet_trace::describe_raw_ipv4(frag, to));
        }
    }
    lines
}

/// Host discovery's probes, as `discovery::discover` would send them.
fn discovery(
    out: &mut Out<'_>,
    run: &DryRun<'_>,
    d: &DryDiscovery,
    sources: &[Option<IpAddr>],
    v: &Values,
) -> io::Result<()> {
    out.note("Host discovery")?;
    let mut decided = vec![false; run.targets.len()];
    // Like nmap with privileges, this machine itself is up without a probe.
    if d.privileged {
        for (i, t) in run.targets.iter().enumerate() {
            if crate::discovery::is_localhost(t.addr) {
                decided[i] = true;
                out.note(&format!(
                    "{} is this machine: up without a probe (localhost-response)",
                    t.addr
                ))?;
            }
        }
    }
    // ARP and neighbour discovery settle the targets on local networks; no
    // other probe goes to them. They need raw sockets on Linux.
    let neighbour = d.arp_ping && d.privileged && cfg!(target_os = "linux");
    let (nets, links) = if neighbour {
        (
            arp::local_networks().unwrap_or_default(),
            ndp::local_links().unwrap_or_default(),
        )
    } else {
        Default::default()
    };
    let before_neighbour = decided.clone();
    let mut seen = HashSet::new();
    for (i, t) in run.targets.iter().enumerate() {
        if decided[i] {
            continue;
        }
        let line = match t.addr {
            IpAddr::V4(ip) => arp::local_net_for(ip, &nets)
                .map(|n| format!("ARP who-has {ip} tell {} ({}, {})", n.addr, n.ifname, n.mac)),
            IpAddr::V6(ip) => ndp::link_for(ip, &links).map(|l| {
                format!(
                    "ICMPv6 [{} > {} Neighbor solicitation (type=135/code=0) for {ip}] ({})",
                    l.addr,
                    packet::solicited_node(ip),
                    l.ifname
                )
            }),
        };
        if let Some(line) = line {
            decided[i] = true;
            if seen.insert(t.addr) {
                out.probe(&line)?;
            }
        }
    }
    if decided != before_neighbour {
        out.note(
            "Targets on a local network are settled by the ARP/ND answer alone and get no other probe",
        )?;
    }
    let rest: Vec<(&Target, Option<IpAddr>)> = run
        .targets
        .iter()
        .zip(sources)
        .zip(&decided)
        .filter(|(_, d)| !**d)
        .map(|((t, s), _)| (t, *s))
        .collect();
    if rest.is_empty() {
        return Ok(());
    }
    let p = &d.probes;
    if p.echo && !d.icmp {
        out.note("ICMP echo skipped: no raw socket and no unprivileged ping socket here")?;
    }
    let queries = [
        (p.echo && d.icmp, packet::ICMP_ECHO_REQUEST, true),
        (p.timestamp, packet::ICMP_TIMESTAMP, false),
        (p.mask, packet::ICMP_ADDRESS_MASK, false),
    ];
    for (on, kind, any_family) in queries {
        if !on {
            continue;
        }
        if !any_family && !d.privileged {
            out.note("ICMP timestamp/address mask requests skipped: they need raw sockets")?;
            continue;
        }
        for (seq, (t, src)) in rest.iter().enumerate() {
            let v6 = t.addr.is_ipv6();
            // Timestamp and address mask requests exist only in ICMPv4.
            if v6 && !any_family {
                continue;
            }
            let seq = seq as u16;
            let (proto, msg) = match kind {
                packet::ICMP_ECHO_REQUEST if v6 => (
                    packet::IPPROTO_ICMPV6,
                    packet::icmpv6_echo(v.icmp_id, seq, b"feroprobe"),
                ),
                packet::ICMP_ECHO_REQUEST => (
                    packet::IPPROTO_ICMP,
                    packet::icmp_echo(v.icmp_id, seq, b"feroprobe"),
                ),
                packet::ICMP_TIMESTAMP => (
                    packet::IPPROTO_ICMP,
                    packet::icmp_query(kind, v.icmp_id, seq, 12),
                ),
                _ => (
                    packet::IPPROTO_ICMP,
                    packet::icmp_query(kind, v.icmp_id, seq, 4),
                ),
            };
            out.probe(&packet_trace::describe(proto, &msg, *src, Some(t.addr)))?;
        }
    }
    // With raw sockets on Linux, -PS and -PA send bare SYNs and ACKs, as
    // nmap does when privileged (discovery::raw_tcp_pings); otherwise both
    // port lists get a connect.
    let raw_tcp = cfg!(target_os = "linux")
        && d.privileged
        && (!rest.iter().any(|(t, _)| t.addr.is_ipv6()) || crate::raw::raw_ipv6_available());
    if raw_tcp {
        for (flags, ports) in [(packet::TCP_SYN, &p.syn), (packet::TCP_ACK, &p.ack)] {
            let ack = if flags == packet::TCP_ACK {
                v.cookie
            } else {
                0
            };
            for &port in ports {
                for (t, src) in &rest {
                    // The raw SYN/ACK pings go through the same raw TCP
                    // scanner, so -f/--mtu, -D and -S apply to them too.
                    if run.evasion.is_active()
                        && let (Some(s @ IpAddr::V4(_)), IpAddr::V4(dst4)) = (src, t.addr)
                    {
                        for line in evasion_lines(run.evasion, *s, dst4, port, v, ack, flags) {
                            out.probe(&line)?;
                        }
                        continue;
                    }
                    let line = match src {
                        Some(s) => {
                            let seg = tcp_segment(*s, t.addr, port, v, ack, flags);
                            packet_trace::describe(
                                packet::IPPROTO_TCP,
                                &seg,
                                Some(*s),
                                Some(t.addr),
                            )
                        }
                        None => format!(
                            "TCP * > {} {} (no route)",
                            host_port(Some(t.addr), Some(port)),
                            packet_trace::tcp_flags(flags)
                        ),
                    };
                    out.probe(&line)?;
                }
            }
        }
    } else {
        let mut tcp_ports = p.syn.clone();
        tcp_ports.extend(&p.ack);
        let mut seen_ports = HashSet::new();
        tcp_ports.retain(|port| seen_ports.insert(*port));
        for &port in &tcp_ports {
            for (t, _) in &rest {
                out.probe(&conn_line(t.addr, port))?;
            }
        }
    }
    for &port in &p.udp {
        for (t, src) in &rest {
            out.probe(&udp_line(*src, t.addr, port))?;
        }
    }
    out.note("A real run stops probing a host as soon as one probe proves it is up")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evasion::Fragment;
    use crate::syn::TcpScanKind;

    fn target(s: &str) -> Target {
        Target::new(s.parse().unwrap())
    }

    fn run_to_string(run: &DryRun<'_>) -> (String, Summary) {
        let mut buf = Vec::new();
        let summary = write(run, &mut buf).unwrap();
        (String::from_utf8(buf).unwrap(), summary)
    }

    fn base<'a>(targets: &'a [Target], ev: &'a Evasion) -> DryRun<'a> {
        DryRun {
            targets,
            discovery: None,
            tcp: None,
            udp: &[],
            sctp: None,
            protocols: &[],
            evasion: ev,
            retries: 1,
            notes: Vec::new(),
            nmap_differences: Vec::new(),
        }
    }

    #[test]
    fn syn_scan_lines_look_like_the_packet_trace() {
        let targets = [target("127.0.0.1")];
        let ev = Evasion::default();
        let ports = [22, 80];
        let run = DryRun {
            tcp: Some((DryTcp::Raw(RawTcpScan::new(TcpScanKind::Syn)), &ports)),
            ..base(&targets, &ev)
        };
        let (text, summary) = run_to_string(&run);
        assert_eq!(
            summary,
            Summary {
                discovery: 0,
                scan: 2
            }
        );
        let probes: Vec<&str> = text.lines().filter(|l| l.starts_with(PREFIX)).collect();
        assert_eq!(probes.len(), 2, "{text}");
        assert!(probes[0].contains("TCP 127.0.0.1:"), "{text}");
        assert!(probes[0].contains("> 127.0.0.1:22 S seq="), "{text}");
        // The anti-abuse window marker is on the probe, as on the wire.
        assert!(probes[0].ends_with("win=65109"), "{text}");
        assert!(text.contains("skipped (-Pn)"), "{text}");
        assert!(text.contains("nothing sent"), "{text}");
        assert!(text.contains("up to 1 more time"), "{text}");
        // No receive side at all.
        assert!(!text.contains("RCVD"), "{text}");
    }

    #[test]
    fn flag_scans_use_their_flags() {
        let targets = [target("127.0.0.1")];
        let ev = Evasion::default();
        let ports = [80];
        for (kind, flags) in [
            (TcpScanKind::Fin, " F "),
            (TcpScanKind::Xmas, " FPU "),
            (TcpScanKind::Ack, " A "),
        ] {
            let run = DryRun {
                tcp: Some((DryTcp::Raw(RawTcpScan::new(kind)), &ports)),
                ..base(&targets, &ev)
            };
            let (text, _) = run_to_string(&run);
            assert!(text.contains(flags), "{kind:?}: {text}");
        }
    }

    #[test]
    fn connect_udp_sctp_and_protocol_scans() {
        let targets = [target("127.0.0.1"), target("127.0.0.2")];
        let ev = Evasion::default();
        let (tcp, udp, sctp, protos) = ([80u16], [53u16, 9999], [2905u16], [1u8, 47]);
        let run = DryRun {
            tcp: Some((DryTcp::Connect, &tcp)),
            udp: &udp,
            sctp: Some((SctpScanKind::Init, &sctp)),
            protocols: &protos,
            ..base(&targets, &ev)
        };
        let (text, summary) = run_to_string(&run);
        // 2 hosts x (1 TCP + 2 UDP + 1 SCTP + 2 protocols).
        assert_eq!(summary.scan, 12, "{text}");
        assert!(text.contains("CONN TCP localhost > 127.0.0.2:80"), "{text}");
        // The DNS probe and the generic marker payload.
        assert!(text.contains("> 127.0.0.1:53 len=17"), "{text}");
        let marker = packet::UDP_MARKER.len();
        assert!(
            text.contains(&format!("> 127.0.0.1:9999 len={marker}")),
            "{text}"
        );
        assert!(text.contains("> 127.0.0.1:2905 INIT"), "{text}");
        assert!(text.contains("Echo request"), "{text}");
        assert!(text.contains("GRE 127.0.0.1 > 127.0.0.2"), "{text}");
    }

    #[test]
    fn evasion_expands_into_decoys_and_fragments() {
        let targets = [target("127.0.0.1")];
        let ev = Evasion {
            decoys: vec!["10.0.0.5".parse().unwrap()],
            spoof_source: None,
            fragment: Some(Fragment::Eight),
        };
        let ports = [80];
        let run = DryRun {
            tcp: Some((DryTcp::Raw(RawTcpScan::new(TcpScanKind::Syn)), &ports)),
            ..base(&targets, &ev)
        };
        let (text, summary) = run_to_string(&run);
        // A 24-byte SYN in 8-byte fragments is 3 pieces, from 2 sources.
        assert_eq!(summary.scan, 6, "{text}");
        assert!(text.contains("TCP 10.0.0.5:"), "{text}");
        assert!(text.contains("TCP 127.0.0.1:"), "{text}");
        assert!(text.contains("frag offset=8"), "{text}");
        assert!(
            text.contains("Evasion: fragmented into 8-byte pieces (-f)"),
            "{text}"
        );
        // The decoy goes first, the real source last.
        let decoy = text.find("TCP 10.0.0.5:").unwrap();
        let real = text.find("TCP 127.0.0.1:").unwrap();
        assert!(decoy < real, "{text}");

        let spoof = Evasion {
            spoof_source: Some("10.9.9.9".parse().unwrap()),
            ..Evasion::default()
        };
        let run = DryRun {
            tcp: Some((DryTcp::Raw(RawTcpScan::new(TcpScanKind::Syn)), &ports)),
            ..base(&targets, &spoof)
        };
        let (text, summary) = run_to_string(&run);
        assert_eq!(summary.scan, 1, "{text}");
        assert!(text.contains("TCP 10.9.9.9:"), "{text}");
        assert!(text.contains("spoofed as 10.9.9.9 (-S)"), "{text}");
    }

    #[test]
    fn discovery_follows_privileges() {
        // A documentation address: not this machine, so it gets probes.
        let targets = [target("192.0.2.9")];
        let ev = Evasion::default();
        let disc = |probes: PingProbes, privileged| DryDiscovery {
            probes,
            privileged,
            icmp: true,
            // Keep the host's own networks out of the test.
            arp_ping: false,
        };
        // Unprivileged: nmap's default is an echo plus connects to 80, 443.
        let run = DryRun {
            discovery: Some(disc(PingProbes::nmap_default(false), false)),
            ..base(&targets, &ev)
        };
        let (text, summary) = run_to_string(&run);
        assert_eq!(summary.discovery, 3, "{text}");
        assert!(
            text.contains("CONN TCP localhost > 192.0.2.9:443"),
            "{text}"
        );
        assert!(text.contains("Echo request"), "{text}");
        // -PA and -PP without raw sockets: the ACK becomes a connect, and
        // the timestamp request is skipped.
        let probes = PingProbes {
            ack: vec![8080],
            timestamp: true,
            udp: vec![40125],
            ..PingProbes::none()
        };
        let run = DryRun {
            discovery: Some(disc(probes, false)),
            ..base(&targets, &ev)
        };
        let (text, summary) = run_to_string(&run);
        assert_eq!(summary.discovery, 2, "{text}");
        assert!(
            text.contains("CONN TCP localhost > 192.0.2.9:8080"),
            "{text}"
        );
        assert!(
            text.contains("timestamp/address mask requests skipped"),
            "{text}"
        );

        // Privileged: nmap's default is echo, a raw SYN to 443, a raw ACK
        // to 80 and a timestamp request, and no connects (on Linux).
        let run = DryRun {
            discovery: Some(disc(PingProbes::nmap_default(true), true)),
            ..base(&targets, &ev)
        };
        let (text, summary) = run_to_string(&run);
        assert_eq!(summary.discovery, 4, "{text}");
        assert!(text.contains("Timestamp request"), "{text}");
        if cfg!(target_os = "linux") {
            assert!(!text.contains("CONN"), "{text}");
            assert!(text.contains("192.0.2.9:443 S"), "{text}");
            assert!(text.contains("192.0.2.9:80 A"), "{text}");
        }
    }

    #[test]
    fn evasion_applies_to_raw_discovery_pings() {
        if !cfg!(target_os = "linux") {
            return;
        }
        let targets = [target("10.255.0.9")];
        let ev = Evasion {
            decoys: vec!["10.0.0.5".parse().unwrap()],
            spoof_source: None,
            fragment: Some(Fragment::Eight),
        };
        let probes = PingProbes {
            ack: vec![80],
            ..PingProbes::none()
        };
        let run = DryRun {
            discovery: Some(DryDiscovery {
                probes,
                privileged: true,
                icmp: true,
                arp_ping: false,
            }),
            ..base(&targets, &ev)
        };
        let (text, summary) = run_to_string(&run);
        if !text.contains("10.255.0.9 from") {
            // No route to the test address here: nothing to expand.
            return;
        }
        // A 20-byte ACK in 8-byte fragments is 3 pieces, from 2 sources.
        assert_eq!(summary.discovery, 6, "{text}");
        assert!(text.contains("TCP 10.0.0.5:"), "{text}");
        assert!(text.contains("frag offset=8"), "{text}");
    }

    #[test]
    fn localhost_needs_no_probe_when_privileged() {
        let targets = [target("127.0.0.1")];
        let ev = Evasion::default();
        let disc = |privileged| DryDiscovery {
            probes: PingProbes::nmap_default(privileged),
            privileged,
            icmp: true,
            arp_ping: true,
        };
        let run = DryRun {
            discovery: Some(disc(true)),
            ..base(&targets, &ev)
        };
        let (text, summary) = run_to_string(&run);
        assert_eq!(summary.discovery, 0, "{text}");
        assert!(text.contains("localhost-response"), "{text}");
        // Unprivileged, nmap pings it like any other host.
        let run = DryRun {
            discovery: Some(disc(false)),
            ..base(&targets, &ev)
        };
        let (text, summary) = run_to_string(&run);
        assert_eq!(summary.discovery, 3, "{text}");
        assert!(!text.contains("localhost-response"), "{text}");
    }

    #[test]
    fn ipv6_targets() {
        let targets = [target("::1")];
        let ev = Evasion::default();
        let ports = [443];
        let run = DryRun {
            tcp: Some((DryTcp::Connect, &ports)),
            ..base(&targets, &ev)
        };
        let (text, _) = run_to_string(&run);
        assert!(text.contains("CONN TCP localhost > [::1]:443"), "{text}");
    }
}
