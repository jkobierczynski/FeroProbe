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
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::arp;
use crate::discovery::PingProbes;
use crate::evasion::Evasion;
use crate::ipproto::Probe as ProtoProbe;
use crate::ndp;
use crate::packet;
use crate::packet_opts;
use crate::packet_trace;
use crate::sctp::SctpScanKind;
use crate::syn::RawTcpScan;
use crate::target::Target;

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
    /// `-b`: an FTP bounce scan through the relay at this address.
    Bounce(SocketAddr),
}

/// Everything a dry run lays out, as the scan would run it.
#[derive(Debug, Clone)]
pub struct DryRun<'a> {
    pub targets: &'a [Target],
    /// `None` with `-Pn`.
    pub discovery: Option<DryDiscovery>,
    /// With `-Pn`: targets on a local network still get an ARP or ND
    /// request, as in nmap (privileged, no `--disable-arp-ping`).
    pub pn_neighbours: bool,
    /// The TCP scan and its ports, in the order they would go out.
    pub tcp: Option<(DryTcp, &'a [u16])>,
    /// The UDP ports, in the order they would go out.
    pub udp: &'a [u16],
    /// The SCTP scan and its ports.
    pub sctp: Option<(SctpScanKind, &'a [u16])>,
    /// `-sO`: the IP protocol numbers.
    pub protocols: &'a [u8],
    pub evasion: &'a Evasion,
    /// The most times unanswered probes are resent in a real run.
    pub retries: u32,
    /// OS detection (`-O`), if it runs.
    pub os: Option<crate::os::OsOptions>,
    /// `-g`: the source port of raw and UDP probes (random when `None`).
    pub source_port: Option<u16>,
    /// Extra lines for the header: steps the dry run cannot show, what a
    /// real run would need, and so on.
    pub notes: Vec<String>,
}

/// How many probes the dry run listed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Summary {
    /// Host-discovery probes (ARP and ND requests included).
    pub discovery: u64,
    /// Port-scan probes; with `-f`/`--mtu` each fragment counts, with `-D`
    /// each decoy copy counts.
    pub scan: u64,
    /// OS-detection probes of one try, for every target.
    pub os: u64,
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
    fn new(source_port: Option<u16>) -> Self {
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
            sport: source_port.unwrap_or(40000 + (next() % 20000) as u16),
            cookie: next(),
            icmp_id: (next() as u16) | 1,
            ipid: (next() as u16) | 1,
        }
    }
}

/// The local address the OS would use to reach `dst` (through the `-e`
/// interface, if one was chosen). Connecting a UDP socket only consults
/// the routing table; nothing is sent.
pub fn route_source(dst: IpAddr) -> Option<IpAddr> {
    crate::netif::route_source(dst).ok()
}

fn host_port(ip: Option<IpAddr>, port: Option<u16>) -> String {
    let port = port.map_or_else(|| "*".to_string(), |p| p.to_string());
    match ip {
        Some(IpAddr::V6(v6)) => format!("[{v6}]:{port}"),
        Some(ip) => format!("{ip}:{port}"),
        None => format!("*:{port}"),
    }
}

/// What `--ttl`, `--ip-options` and `--badsum` add to the trace line of a
/// probe (`seg`, of IP protocol `proto`) whose IP header the kernel writes.
fn opts_note(proto: u8, src: Option<IpAddr>, dst: IpAddr, seg: &[u8]) -> String {
    let opts = packet_opts::get();
    let bad = src.is_some_and(|s| packet_opts::checksum_is_bad(proto, s, dst, seg));
    packet_trace::kernel_header_note(opts.ttl, &opts.ip_options, dst, bad)
}

/// A probe line for `seg` with its packet options.
fn line(proto: u8, seg: &[u8], src: Option<IpAddr>, dst: IpAddr) -> String {
    format!(
        "{}{}",
        packet_trace::describe(proto, seg, src, Some(dst)),
        opts_note(proto, src, dst, seg)
    )
}

/// The packet options in effect, for the header, or `None` without any.
fn packet_options_note() -> Option<String> {
    let opts = packet_opts::get();
    let mut parts = Vec::new();
    if let Some(d) = &opts.data {
        parts.push(format!(
            "{} byte{} of --data after each raw TCP, SCTP, ICMP and IP protocol probe, \
             instead of the usual UDP and ICMP echo payloads",
            d.len(),
            if d.len() == 1 { "" } else { "s" }
        ));
    }
    if let Some(t) = opts.ttl {
        parts.push(format!("TTL {t} (--ttl)"));
    }
    if !opts.ip_options.is_empty() {
        parts.push(format!(
            "IPv4 options {{{}}} (--ip-options)",
            packet_opts::describe_ip_options(&opts.ip_options).trim_start()
        ));
    }
    if opts.badsum {
        parts.push("wrong checksums (--badsum)".to_string());
    }
    (!parts.is_empty()).then(|| format!("Packet options: {}", parts.join("; ")))
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
    let v = Values::new(run.source_port);
    let sources: Vec<Option<IpAddr>> = run.targets.iter().map(|t| route_source(t.addr)).collect();
    let mut out = Out { w, count: 0 };
    out.note("Dry run (--dry-run): these are the probes the scan would send. Nothing is sent.")?;
    for n in &run.notes {
        out.note(n)?;
    }
    if let Some(n) = packet_options_note() {
        out.note(&n)?;
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
        None => {
            out.note("Host discovery: skipped (-Pn), every target is treated as up")?;
            if run.pn_neighbours {
                let mut decided: Vec<bool> = run
                    .targets
                    .iter()
                    .map(|t| crate::discovery::is_localhost(t.addr))
                    .collect();
                let before = decided.clone();
                neighbour_requests(&mut out, run.targets, &mut decided)?;
                if decided != before {
                    out.note(
                        "As in nmap, targets on a local network still get an ARP/ND request, \
                         for their MAC address and latency",
                    )?;
                }
                summary.discovery = out.count;
            }
        }
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
                    out.probe(&udp_line(*src, run.source_port, t.addr, port))?;
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
                    let chunk = match src {
                        Some(s) => {
                            packet_opts::get().finish(packet::IPPROTO_SCTP, *s, t.addr, chunk, true)
                        }
                        None => chunk,
                    };
                    out.probe(&line(packet::IPPROTO_SCTP, &chunk, *src, t.addr))?;
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
                            line(proto, &body, Some(*s), t.addr)
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
    if let Some(opts) = &run.os
        && let Some((tcp, ports)) = &run.tcp
    {
        let before = out.count;
        // OS detection needs a port the scan reports open: -sA, -sF, -sN,
        // -sX and -sM never do, so no host would be fingerprinted.
        let finds_open = match tcp {
            DryTcp::Connect | DryTcp::Bounce(_) => true,
            DryTcp::Raw(scan) => matches!(
                scan.kind,
                crate::syn::TcpScanKind::Syn | crate::syn::TcpScanKind::Window
            ),
        };
        let distinct = ports
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        if finds_open {
            os_probes(&mut out, run, opts, distinct, &sources, &v)?;
        } else {
            out.note(
                "OS detection (-O): no host is fingerprinted, because this TCP scan type never \
                 reports a port open and OS detection needs an open one",
            )?;
        }
        summary.os = out.count - before;
    }
    let retry = if run.retries > 0 {
        format!(
            "; a real run resends unanswered probes once{}",
            if run.retries > 1 {
                format!(", or up to {} times to hosts that lose probes", run.retries)
            } else {
                String::new()
            }
        )
    } else {
        String::new()
    };
    let os = if run.os.is_some() && run.tcp.is_some() {
        format!(", {} OS-detection probes (one try)", summary.os)
    } else {
        String::new()
    };
    out.note(&format!(
        "Dry run done: {} discovery and {} port-scan probe{}{os} for {} host{} listed, nothing sent{retry}",
        summary.discovery,
        summary.scan,
        if summary.scan == 1 { "" } else { "s" },
        run.targets.len(),
        if run.targets.len() == 1 { "" } else { "s" },
    ))?;
    Ok(summary)
}

/// The OS-detection probes of one try, per target. The ports are the ones
/// the scan finds, so they show as `<open>` and `<closed>`.
fn os_probes(
    out: &mut Out<'_>,
    run: &DryRun<'_>,
    opts: &crate::os::OsOptions,
    ports: usize,
    sources: &[Option<IpAddr>],
    v: &Values,
) -> io::Result<()> {
    use crate::os::probes::{self, Target};
    // One scanned port can be open or closed, never both: there is no
    // closed port to probe, and --osscan-limit skips every host.
    let closed = ports >= 2;
    if opts.limit && !closed {
        return out.note(
            "OS detection (-O --osscan-limit): no host is fingerprinted, because the scan \
             covers only one TCP port and so cannot find both an open and a closed one",
        );
    }
    let max = opts.max_tries.max(1);
    let tries = if closed {
        max
    } else {
        max.min(crate::os::UNIDEAL_TRIES)
    };
    out.note(&format!(
        "OS detection (-O): only for hosts where the scan finds an open TCP port{}. {} \
         The four SYNs to <open> go 100 ms apart. A host without a perfect match is tried \
         again, up to {tries} tr{} in all{}",
        if opts.limit {
            " and a closed (or unfiltered) one (--osscan-limit)"
        } else {
            ""
        },
        if closed {
            "<open> and <closed> stand for an open and a closed TCP port the scan finds among \
             the ports above; the probes to <closed> go only if it finds one."
        } else {
            "<open> stands for the scanned port when the scan finds it open. With one TCP \
             port there is no closed port to probe."
        },
        if tries == 1 { "y" } else { "ies" },
        if closed && max > crate::os::UNIDEAL_TRIES {
            " (two when the scan finds no closed port)"
        } else {
            ""
        },
    ))?;
    if opts.icmp_echo {
        out.note("The echo request is sent because this command's host discovery sends ICMP echo requests")?;
    }
    let keys = probes::Keys {
        sport: v.sport,
        seq: v.cookie,
        ack: v.cookie.rotate_left(16),
        tsval: v.cookie.rotate_left(8),
        icmp_id: v.icmp_id,
        fixed: run.source_port.is_some(),
    };
    for (t, src) in run.targets.iter().zip(sources) {
        for i in probes::plan(closed, opts.icmp_echo) {
            let v6 = t.addr.is_ipv6();
            let Some(src) = src.filter(|s| s.is_ipv6() == v6) else {
                out.probe(&format!("{} * > {} (no route)", NAMES_UPPER[i], t.addr))?;
                continue;
            };
            let line = match probes::target_of(i) {
                Target::Icmp => {
                    let proto = if v6 {
                        packet::IPPROTO_ICMPV6
                    } else {
                        packet::IPPROTO_ICMP
                    };
                    probes::describe(proto, &probes::echo(v6, &keys), Some(src), t.addr)
                }
                target => {
                    let seg = probes::tcp_segment(i, src, t.addr, 0, &keys);
                    let placeholder = if target == Target::Open {
                        "<open>"
                    } else {
                        "<closed>"
                    };
                    probes::describe(packet::IPPROTO_TCP, &seg, Some(src), t.addr).replacen(
                        &host_port(Some(t.addr), Some(0)),
                        &host_port(Some(t.addr), None).replace('*', placeholder),
                        1,
                    )
                }
            };
            out.probe(&line)?;
        }
    }
    Ok(())
}

/// The protocol of each OS probe, for a line without a route.
const NAMES_UPPER: [&str; crate::os::probes::PROBES] = [
    "TCP", "TCP", "TCP", "TCP", "TCP", "TCP", "TCP", "TCP", "ICMP",
];

/// The UDP datagram a UDP probe sends; the kernel picks the source port
/// unless `-g` gave one.
fn udp_line(src: Option<IpAddr>, sport: Option<u16>, dst: IpAddr, port: u16) -> String {
    let sport = crate::udp::effective_sport(sport, crate::target::socket_addr(dst, port));
    let opts = packet_opts::get();
    format!(
        "UDP {} > {} len={}{}",
        host_port(src, sport),
        host_port(Some(dst), Some(port)),
        opts.udp_payload(port).len(),
        packet_trace::kernel_header_note(opts.ttl, &opts.ip_options, dst, opts.badsum)
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
        DryTcp::Bounce(relay) => {
            out.note(&format!(
                "FTP bounce scan (-b) through the FTP server at {relay}: after logging in, one \
                 PORT command and one LIST per port, sent to the server over a single \
                 connection; the server, not this machine, connects to the targets"
            ))?;
            for t in run.targets {
                let IpAddr::V4(dst) = t.addr else {
                    out.note(&format!(
                        "{} is not IPv4, so the bounce scan skips it",
                        t.addr
                    ))?;
                    continue;
                };
                for &port in ports {
                    out.probe(&format!(
                        "FTP {relay} {} + LIST (server connects to {})",
                        crate::ftp_bounce::port_command(dst, port),
                        host_port(Some(t.addr), Some(port))
                    ))?;
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
                    out.probe(&line(packet::IPPROTO_TCP, &seg, Some(src), t.addr))?;
                }
            }
        }
    }
    Ok(())
}

/// The segment a raw TCP scan sends, as `syn.rs` builds it: a plain SYN
/// keeps its MSS option, any other flags get a bare header; then the
/// `--data` bytes and `--badsum`.
fn tcp_segment(src: IpAddr, dst: IpAddr, port: u16, v: &Values, ack: u32, flags: u8) -> Vec<u8> {
    let seg = if flags == packet::TCP_SYN {
        packet::tcp_syn(src, dst, v.sport, port, v.cookie).to_vec()
    } else {
        packet::tcp_probe(src, dst, v.sport, port, v.cookie, ack, flags).to_vec()
    };
    packet_opts::get().finish(packet::IPPROTO_TCP, src, dst, seg, true)
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
    let mut lines = Vec::new();
    for (i, source) in ev.source_addrs(real_src).into_iter().enumerate() {
        let IpAddr::V4(src4) = source else { continue };
        let seg = tcp_segment(source, IpAddr::V4(dst), port, v, ack, flags);
        let id = (v.cookie as u16) ^ port ^ (i as u16);
        let (pkt, hop) = packet_opts::ipv4_probe(src4, dst, packet::IPPROTO_TCP, id, &seg);
        let to = SocketAddr::new(IpAddr::V4(hop), 0);
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

/// The ARP and ND requests to the targets not yet `decided` that sit on a
/// local network; marks them decided.
fn neighbour_requests(
    out: &mut Out<'_>,
    targets: &[Target],
    decided: &mut [bool],
) -> io::Result<()> {
    let nets = arp::local_networks().unwrap_or_default();
    let links = ndp::local_links().unwrap_or_default();
    let mut seen = HashSet::new();
    for (i, t) in targets.iter().enumerate() {
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
    Ok(())
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
    let before_neighbour = decided.clone();
    if neighbour {
        neighbour_requests(out, run.targets, &mut decided)?;
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
            // As discovery builds them: --data replaces the echo payload
            // and follows the timestamp and mask bodies.
            let opts = packet_opts::get();
            let icmp = |msg: Vec<u8>, data: bool| {
                opts.finish(packet::IPPROTO_ICMP, t.addr, t.addr, msg, data)
            };
            let (proto, msg) = match kind {
                packet::ICMP_ECHO_REQUEST if v6 => (
                    packet::IPPROTO_ICMPV6,
                    packet::icmpv6_echo(v.icmp_id, seq, opts.echo_payload()),
                ),
                packet::ICMP_ECHO_REQUEST => (
                    packet::IPPROTO_ICMP,
                    icmp(
                        packet::icmp_echo(v.icmp_id, seq, opts.echo_payload()),
                        false,
                    ),
                ),
                packet::ICMP_TIMESTAMP => (
                    packet::IPPROTO_ICMP,
                    icmp(packet::icmp_query(kind, v.icmp_id, seq, 12), true),
                ),
                _ => (
                    packet::IPPROTO_ICMP,
                    icmp(packet::icmp_query(kind, v.icmp_id, seq, 4), true),
                ),
            };
            out.probe(&line(proto, &msg, *src, t.addr))?;
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
                            line(packet::IPPROTO_TCP, &seg, Some(*s), t.addr)
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
            out.probe(&udp_line(*src, run.source_port, t.addr, port))?;
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
            pn_neighbours: false,
            tcp: None,
            udp: &[],
            sctp: None,
            protocols: &[],
            evasion: ev,
            retries: 1,
            os: None,
            source_port: None,
            notes: Vec::new(),
        }
    }

    #[test]
    fn os_detection_probes_use_placeholders() {
        let targets = [target("127.0.0.1")];
        let ev = Evasion::default();
        let ports = [22, 80];
        let run = DryRun {
            tcp: Some((DryTcp::Raw(RawTcpScan::new(TcpScanKind::Syn)), &ports)),
            os: Some(crate::os::OsOptions::default()),
            ..base(&targets, &ev)
        };
        let (text, summary) = run_to_string(&run);
        // Eight TCP probes, no echo (discovery sends none).
        assert_eq!(summary.os, 8, "{text}");
        assert!(text.contains("> 127.0.0.1:<open> S seq="), "{text}");
        assert!(text.contains("> 127.0.0.1:<open> SEC seq="), "{text}");
        assert!(text.contains("> 127.0.0.1:<closed> A seq="), "{text}");
        assert!(text.contains("<mss 1460,sackOK,timestamp"), "{text}");
        assert!(!text.contains("ICMP"), "{text}");
        assert!(text.contains("up to 5 tries"), "{text}");
        assert!(text.contains("8 OS-detection probes"), "{text}");

        let echo = crate::os::OsOptions {
            icmp_echo: true,
            max_tries: 1,
            ..Default::default()
        };
        let run = DryRun {
            os: Some(echo),
            ..run
        };
        let (text, summary) = run_to_string(&run);
        assert_eq!(summary.os, 9, "{text}");
        assert!(text.contains("echo request"), "{text}");
        assert!(text.contains("up to 1 try in all"), "{text}");

        // One scanned port cannot be both open and closed: no <closed> probes,
        // and --osscan-limit fingerprints nothing.
        // The same port twice is still one port.
        let one = [22, 22];
        let run = DryRun {
            tcp: Some((DryTcp::Raw(RawTcpScan::new(TcpScanKind::Syn)), &one)),
            os: Some(crate::os::OsOptions::default()),
            ..base(&targets, &ev)
        };
        let (text, summary) = run_to_string(&run);
        assert_eq!(summary.os, 6, "{text}");
        assert!(!text.contains("<closed>"), "{text}");
        let run = DryRun {
            os: Some(crate::os::OsOptions {
                limit: true,
                ..Default::default()
            }),
            ..run
        };
        let (text, summary) = run_to_string(&run);
        assert_eq!(summary.os, 0, "{text}");
        assert!(text.contains("no host is fingerprinted"), "{text}");

        // An ACK scan never finds a port open: nothing to fingerprint.
        let run = DryRun {
            tcp: Some((DryTcp::Raw(RawTcpScan::new(TcpScanKind::Ack)), &ports)),
            os: Some(crate::os::OsOptions::default()),
            ..base(&targets, &ev)
        };
        let (text, summary) = run_to_string(&run);
        assert_eq!(summary.os, 0, "{text}");
        assert!(text.contains("never reports a port open"), "{text}");
    }

    #[test]
    fn source_port_shows_on_raw_and_udp_probes() {
        let targets = [target("127.0.0.1")];
        let ev = Evasion::default();
        let (tcp, udp) = ([22, 80], [53]);
        let run = DryRun {
            tcp: Some((DryTcp::Raw(RawTcpScan::new(TcpScanKind::Syn)), &tcp)),
            udp: &udp,
            source_port: Some(53),
            ..base(&targets, &ev)
        };
        let (text, _) = run_to_string(&run);
        assert!(text.contains("TCP 127.0.0.1:53 > 127.0.0.1:22 S"), "{text}");
        assert!(text.contains("TCP 127.0.0.1:53 > 127.0.0.1:80 S"), "{text}");
        // This machine's own -g port is probed from a random port, as in a
        // real run (and on Windows -g does not apply to UDP at all).
        assert!(text.contains("UDP 127.0.0.1:* > 127.0.0.1:53"), "{text}");
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
                scan: 2,
                os: 0
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
        assert!(text.contains("resends unanswered probes once"), "{text}");
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
