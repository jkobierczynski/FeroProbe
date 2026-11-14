//! `feroprobe`: an nmap-style network scanner, written natively in Rust.

mod output;
mod xml;

use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result, bail};
use clap::{Parser, ValueEnum};
use feroprobe_core::{
    HostResult, IpVersion, RawTcpScan, ScanConfig, Target, TcpScanKind, Timing, connect_scan,
    detect_services, discover, os_detect, parse_ports, parse_scanflags, raw_ipv6_available,
    raw_sockets_available, raw_tcp_scan, resolve_targets_with, top_ports, top_udp_ports, udp_scan,
};

use output::RunInfo;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ScanType {
    /// -sS: TCP SYN scan (raw sockets, needs root; default when root on Linux)
    #[value(name = "S")]
    Syn,
    /// -sT: TCP connect scan (no privileges needed)
    #[value(name = "T")]
    Connect,
    /// -sF: TCP FIN scan (raw sockets)
    #[value(name = "F")]
    Fin,
    /// -sN: TCP NULL scan, no flags set (raw sockets)
    #[value(name = "N")]
    Null,
    /// -sX: TCP Xmas scan, FIN, PSH and URG (raw sockets)
    #[value(name = "X")]
    Xmas,
    /// -sA: TCP ACK scan, maps firewall rules (raw sockets)
    #[value(name = "A")]
    Ack,
    /// -sW: TCP Window scan (raw sockets)
    #[value(name = "W")]
    Window,
    /// -sM: TCP Maimon scan, FIN and ACK (raw sockets)
    #[value(name = "M")]
    Maimon,
    /// -sU: UDP scan
    #[value(name = "U")]
    Udp,
    /// -sn: host discovery only, no port scan
    #[value(name = "n")]
    PingOnly,
    /// -sV: detect service and version on open ports
    #[value(name = "V")]
    Version,
}

impl ScanType {
    /// The TCP scans; one of them can run at a time.
    const TCP: [ScanType; 8] = [
        ScanType::Syn,
        ScanType::Connect,
        ScanType::Fin,
        ScanType::Null,
        ScanType::Xmas,
        ScanType::Ack,
        ScanType::Window,
        ScanType::Maimon,
    ];

    /// The raw-socket scan this is, if it is one.
    fn raw_kind(self) -> Option<TcpScanKind> {
        Some(match self {
            ScanType::Syn => TcpScanKind::Syn,
            ScanType::Fin => TcpScanKind::Fin,
            ScanType::Null => TcpScanKind::Null,
            ScanType::Xmas => TcpScanKind::Xmas,
            ScanType::Ack => TcpScanKind::Ack,
            ScanType::Window => TcpScanKind::Window,
            ScanType::Maimon => TcpScanKind::Maimon,
            _ => return None,
        })
    }

    fn flag(self) -> &'static str {
        match self {
            ScanType::Syn => "-sS",
            ScanType::Connect => "-sT",
            ScanType::Fin => "-sF",
            ScanType::Null => "-sN",
            ScanType::Xmas => "-sX",
            ScanType::Ack => "-sA",
            ScanType::Window => "-sW",
            ScanType::Maimon => "-sM",
            ScanType::Udp => "-sU",
            ScanType::PingOnly => "-sn",
            ScanType::Version => "-sV",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum PingMode {
    /// -Pn: skip host discovery and treat every host as up
    #[value(name = "n")]
    Skip,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Format {
    /// Human-readable table, like nmap's normal output
    Table,
    /// Machine-readable JSON
    Json,
    /// XML in nmap's layout, for tools that read nmap's -oX output
    Xml,
}

/// Fast, native network scanner with an nmap-style command line.
///
/// Examples:
///   feroprobe 192.168.1.0/24
///   sudo feroprobe -sS -p 1-65535 10.0.0.5
///   feroprobe -sT -sU -p 53,123,161 scanme.example.org
///   feroprobe -sn 192.168.1.0/24
///   sudo feroprobe -sn 192.168.1.0/24   (ARP on a local network, shows MAC vendors)
///   feroprobe -sV -p 22,80,443 10.0.0.5
///   sudo feroprobe -O 10.0.0.5
///   feroprobe -Pn --top-ports 1000 --open -o json 10.0.0.1-50
///   feroprobe -T4 -p- 10.0.0.5             (aggressive timing)
///   sudo feroprobe -sA -p 1-1024 10.0.0.5   (which ports does a firewall let through?)
///   sudo feroprobe -sF -p 22,80 10.0.0.5    (FIN scan; also -sN, -sX, -sW, -sM)
///   sudo feroprobe --scanflags SYNFIN -p 80 10.0.0.5
///   feroprobe -T2 --scan-delay 1s 10.0.0.5
///   sudo feroprobe -6 -sn fe80::1%eth0 2001:db8::/120   (IPv6, NDP on the local link)
///   feroprobe -6 -p 22,443 scanme.example.org          (use the name's IPv6 address)
#[derive(Debug, Parser)]
#[command(version, verbatim_doc_comment)]
struct Args {
    /// Targets: IPv4 or IPv6 addresses, CIDR blocks (10.0.0.0/24, 2001:db8::/120),
    /// ranges (10.0.0.1-20), link-local addresses with their interface
    /// (fe80::1%eth0) or hostnames
    #[arg(required = true)]
    targets: Vec<String>,

    /// -6: use the IPv6 address of each hostname target (IPv4 is preferred
    /// otherwise). Address targets are scanned as given, IPv4 or IPv6
    #[arg(short = '6')]
    ipv6: bool,

    /// Scan technique, nmap style: -sS (SYN), -sT (connect), -sU (UDP), -sn (no port scan),
    /// -sV (also detect service versions on open ports), and the raw TCP scans
    /// -sF (FIN), -sN (NULL), -sX (Xmas), -sA (ACK), -sW (Window), -sM (Maimon).
    /// Can be repeated, e.g. -sS -sU -sV, with one TCP scan at most.
    /// Default: -sS when run as root on Linux, else -sT
    #[arg(
        short = 's',
        value_name = "TYPE",
        value_enum,
        hide_possible_values = true
    )]
    scan: Vec<ScanType>,

    /// TCP flags to send instead of the scan's own: names run together, e.g.
    /// SYNFIN or URGPSHFIN (URG, ACK, PSH, RST, SYN, FIN, ECE, CWR), or a
    /// number. Answers are read as the chosen raw scan reads them, as a SYN
    /// scan's when none is chosen
    #[arg(long, value_name = "FLAGS", value_parser = parse_scanflags)]
    scanflags: Option<u8>,

    /// -Pn: skip host discovery and scan every target as if it were up
    #[arg(short = 'P', value_name = "n", value_enum, hide_possible_values = true)]
    ping: Option<PingMode>,

    /// Don't use ARP (IPv4) or neighbour discovery (IPv6) for targets on a
    /// local Ethernet network; ping them with ICMP and TCP probes like
    /// remote hosts
    #[arg(long)]
    disable_arp_ping: bool,

    /// IEEE OUI list for MAC vendor names (oui.txt, oui.csv, Wireshark manuf).
    /// Default: the first of /usr/share/hwdata/oui.txt, /usr/share/ieee-data/oui.txt
    /// and similar system locations that exists, else a small built-in table
    #[arg(long, value_name = "FILE")]
    oui_file: Option<std::path::PathBuf>,

    /// -O: guess each host's operating system (raw sockets: Linux, root or CAP_NET_RAW)
    #[arg(short = 'O')]
    os: bool,

    /// Ports to scan, e.g. "22", "1-1024", "22,80,443", "-" for all
    #[arg(short = 'p', long, conflicts_with = "top_ports")]
    ports: Option<String>,

    /// Scan the N most common ports (default 100 for TCP, 20 for UDP)
    #[arg(long, value_name = "N")]
    top_ports: Option<usize>,

    /// Timing template: 0-5 or paranoid, sneaky, polite, normal, aggressive,
    /// insane (-T4 = aggressive). Sets timeout, retries, concurrency, rate and
    /// scan delay; those flags still override it. [default: 3, normal]
    #[arg(short = 'T', value_name = "0-5", value_parser = parse_timing)]
    timing: Option<Timing>,

    /// Per-probe timeout in milliseconds [default: from -T; normally 1500, or 3000 on Windows]
    #[arg(long, value_name = "MS")]
    timeout: Option<u64>,

    /// Maximum connect/UDP probes in flight at once [default: from -T; normally 500]
    #[arg(short = 'c', long, value_name = "N")]
    concurrency: Option<usize>,

    /// Maximum packets per second for raw-socket probes (SYN, ICMP, ARP, NDP) [default: from -T; normally 5000]
    #[arg(long, value_name = "PPS")]
    max_rate: Option<u32>,

    /// Minimum time between probes, e.g. 500ms, 2s, 5m (a bare number is seconds)
    /// [default: from -T; normally none]
    #[arg(long, value_name = "TIME", value_parser = feroprobe_core::timing::parse_duration)]
    scan_delay: Option<Duration>,

    /// With -sV, how long to wait for each service reply, in milliseconds
    #[arg(long, value_name = "MS", default_value_t = 3000)]
    version_timeout: u64,

    /// Extra attempts for probes that get no answer [default: from -T; normally 1]
    #[arg(long, value_name = "N")]
    retries: Option<u32>,

    /// Only show open (and open|filtered, unfiltered) ports
    #[arg(long)]
    open: bool,

    /// Show why each port got its state (syn-ack, reset, port-unreach, ...)
    #[arg(long)]
    reason: bool,

    /// In XML output, write scanner="nmap" for tools that only accept
    /// nmap's own reports (FeroProbe is still named in a comment)
    #[arg(long)]
    nmap_label: bool,

    /// Output format
    #[arg(short = 'o', long, value_enum, default_value_t = Format::Table)]
    output: Format,
}

/// What to run, after applying nmap's defaults to the flags.
#[derive(Debug, PartialEq, Eq)]
struct Plan {
    tcp: Option<ScanType>,
    udp: bool,
    version: bool,
    ping_only: bool,
    discovery: bool,
}

/// `syn_ok` says whether a SYN scan can serve as the default: the process is
/// privileged, and the system has IPv6 if any target needs it.
fn plan(scan: &[ScanType], ping: Option<PingMode>, syn_ok: bool, scanflags: bool) -> Result<Plan> {
    let has = |t| scan.contains(&t);
    let tcp_types: Vec<ScanType> = ScanType::TCP.into_iter().filter(|&t| has(t)).collect();
    if tcp_types.len() > 1 {
        let flags: Vec<&str> = tcp_types.iter().map(|t| t.flag()).collect();
        bail!("choose one TCP scan type, not {}", flags.join(" and "));
    }
    let ping_only = has(ScanType::PingOnly);
    if ping_only && scan.len() > 1 {
        bail!("-sn (no port scan) cannot be combined with other scan types");
    }
    if ping_only && ping.is_some() {
        bail!("-sn with -Pn would do nothing");
    }
    if scanflags {
        if ping_only {
            bail!("--scanflags needs a port scan, so it cannot be combined with -sn");
        }
        if has(ScanType::Connect) {
            bail!("--scanflags sends raw packets, so it cannot be combined with -sT");
        }
    }
    let tcp = if let Some(&t) = tcp_types.first() {
        Some(t)
    } else if scanflags {
        // nmap reads custom flags as a SYN scan unless told otherwise.
        Some(ScanType::Syn)
    } else if !has(ScanType::Udp) && !ping_only {
        // nmap's default: SYN scan when privileged, connect scan otherwise.
        Some(if syn_ok && cfg!(target_os = "linux") {
            ScanType::Syn
        } else {
            ScanType::Connect
        })
    } else {
        None
    };
    Ok(Plan {
        tcp,
        udp: has(ScanType::Udp),
        version: has(ScanType::Version),
        ping_only,
        discovery: ping.is_none(),
    })
}

fn parse_timing(s: &str) -> Result<Timing, String> {
    s.parse()
}

/// The timing template's settings, with any explicit flags on top.
fn scan_config(args: &Args) -> ScanConfig {
    let base = args.timing.unwrap_or_default().config();
    ScanConfig {
        timeout: args.timeout.map_or(base.timeout, Duration::from_millis),
        concurrency: args.concurrency.unwrap_or(base.concurrency).max(1),
        retries: args.retries.unwrap_or(base.retries),
        max_rate: args.max_rate.unwrap_or(base.max_rate).max(1),
        scan_delay: args.scan_delay.unwrap_or(base.scan_delay),
        arp_ping: !args.disable_arp_ping,
    }
}

/// The run's label for a raw TCP scan, as listed in `scan_types`.
fn tcp_scan_label(kind: TcpScanKind) -> &'static str {
    match kind {
        TcpScanKind::Syn => "tcp-syn",
        TcpScanKind::Fin => "tcp-fin",
        TcpScanKind::Null => "tcp-null",
        TcpScanKind::Xmas => "tcp-xmas",
        TcpScanKind::Ack => "tcp-ack",
        TcpScanKind::Window => "tcp-window",
        TcpScanKind::Maimon => "tcp-maimon",
    }
}

/// Add each scan's port results to the matching host in `hosts`.
fn merge(hosts: &mut [HostResult], scanned: &[usize], results: Vec<HostResult>) {
    for (&idx, r) in scanned.iter().zip(results) {
        hosts[idx].ports.extend(r.ports);
        hosts[idx].sort_ports();
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let version = if args.ipv6 {
        IpVersion::V6
    } else {
        IpVersion::PreferV4
    };
    let targets = resolve_targets_with(&args.targets, version)
        .await
        .context("resolving targets")?;
    let any_ipv6 = targets.iter().any(|t| t.addr.is_ipv6());
    let syn_ok = raw_sockets_available() && (!any_ipv6 || raw_ipv6_available());
    let plan = plan(&args.scan, args.ping, syn_ok, args.scanflags.is_some())?;
    if args.os {
        if plan.ping_only {
            bail!("-O needs a port scan, so it cannot be combined with -sn");
        }
        if !raw_sockets_available() {
            bail!("-O sends raw packets: run as root or grant CAP_NET_RAW");
        }
    }

    let tcp_ports = match (&args.ports, args.top_ports) {
        (Some(spec), _) => parse_ports(spec)?,
        (None, n) => top_ports(n.unwrap_or(100)),
    };
    let udp_ports = match (&args.ports, args.top_ports) {
        (Some(_), _) => tcp_ports.clone(),
        (None, n) => top_udp_ports(n.unwrap_or(20)),
    };
    if !plan.ping_only && tcp_ports.is_empty() {
        bail!("no ports to scan");
    }

    let cfg = scan_config(&args);

    if let Some(path) = &args.oui_file {
        feroprobe_core::oui::use_file(path)
            .with_context(|| format!("reading OUI list {}", path.display()))?;
    }

    let started = Instant::now();
    let start_time = SystemTime::now();
    let mut hosts: Vec<HostResult> = if plan.discovery {
        discover(&targets, &cfg)
            .await
            .context("host discovery failed")?
    } else {
        targets
            .iter()
            .map(|t| HostResult::new(t.addr, t.hostname.clone()))
            .collect()
    };

    let mut scan_types = Vec::new();
    if !plan.ping_only {
        // Only scan hosts that discovery found (all of them with -Pn).
        let scanned: Vec<usize> = (0..hosts.len())
            .filter(|&i| !plan.discovery || hosts[i].is_up())
            .collect();
        let live: Vec<Target> = scanned.iter().map(|&i| targets[i].clone()).collect();
        let hint = "scan aborted (try a lower --concurrency)";

        match plan.tcp.map(|t| (t, t.raw_kind())) {
            Some((t, Some(kind))) => {
                scan_types.push(tcp_scan_label(kind));
                let mut scan = RawTcpScan::new(kind);
                if let Some(flags) = args.scanflags {
                    scan.flags = flags;
                }
                let r = raw_tcp_scan(&live, &tcp_ports, &cfg, scan)
                    .await
                    .with_context(|| format!("TCP {} scan ({}) failed", kind.name(), t.flag()))?;
                merge(&mut hosts, &scanned, r);
            }
            Some((_, None)) => {
                scan_types.push("tcp-connect");
                let r = connect_scan(&live, &tcp_ports, &cfg).await.context(hint)?;
                merge(&mut hosts, &scanned, r);
            }
            None => {}
        }
        if plan.udp {
            scan_types.push("udp");
            let r = udp_scan(&live, &udp_ports, &cfg).await.context(hint)?;
            merge(&mut hosts, &scanned, r);
        }
        if plan.version {
            scan_types.push("version");
            let wait = Duration::from_millis(args.version_timeout);
            detect_services(&mut hosts, &cfg, wait).await;
        }
        if args.os {
            scan_types.push("os");
            os_detect(&mut hosts, &cfg)
                .await
                .context("OS detection failed")?;
        }
    } else {
        scan_types.push("ping");
    }

    let ports_per_host =
        plan.tcp.map_or(0, |_| tcp_ports.len()) + if plan.udp { udp_ports.len() } else { 0 };
    let info = RunInfo {
        args: std::env::args().collect::<Vec<_>>().join(" "),
        start: start_time,
        scan_types,
        tcp_ports: if plan.tcp.is_some() && !plan.ping_only {
            tcp_ports
        } else {
            Vec::new()
        },
        udp_ports: if plan.udp { udp_ports } else { Vec::new() },
        ports_per_host,
        elapsed: started.elapsed(),
        only_open: args.open,
        show_reason: args.reason,
        show_version: plan.version,
        show_os: args.os,
        assume_up: !plan.discovery,
        ping_only: plan.ping_only,
        nmap_label: args.nmap_label,
    };
    match args.output {
        Format::Table => output::print_table(&hosts, &info),
        Format::Json => output::print_json(&hosts, &info)?,
        Format::Xml => print!("{}", xml::render(&hosts, &info)),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(scan: &[ScanType], ping: Option<PingMode>, syn_ok: bool) -> Result<Plan> {
        plan(scan, ping, syn_ok, false)
    }

    #[test]
    fn default_scan_type_depends_on_privileges() {
        let plan = p(&[], None, false).unwrap();
        assert_eq!(plan.tcp, Some(ScanType::Connect));
        assert!(plan.discovery && !plan.udp && !plan.ping_only);
        let expect = if cfg!(target_os = "linux") {
            ScanType::Syn
        } else {
            ScanType::Connect
        };
        assert_eq!(p(&[], None, true).unwrap().tcp, Some(expect));
    }

    #[test]
    fn udp_only_and_combined() {
        let plan = p(&[ScanType::Udp], None, true).unwrap();
        assert_eq!((plan.tcp, plan.udp), (None, true));
        let plan = p(
            &[ScanType::Connect, ScanType::Udp],
            Some(PingMode::Skip),
            true,
        )
        .unwrap();
        assert_eq!(
            (plan.tcp, plan.udp, plan.discovery),
            (Some(ScanType::Connect), true, false)
        );
    }

    #[test]
    fn version_detection_keeps_default_tcp_scan() {
        let plan = p(&[ScanType::Version], None, false).unwrap();
        assert_eq!((plan.tcp, plan.version), (Some(ScanType::Connect), true));
        let plan = p(&[ScanType::Udp, ScanType::Version], None, false).unwrap();
        assert_eq!((plan.tcp, plan.udp, plan.version), (None, true, true));
        let a = Args::try_parse_from(["feroprobe", "-sV", "10.0.0.1"]).unwrap();
        assert_eq!(a.scan, vec![ScanType::Version]);
    }

    #[test]
    fn rejects_conflicts() {
        assert!(p(&[ScanType::Syn, ScanType::Connect], None, true).is_err());
        assert!(p(&[ScanType::PingOnly, ScanType::Udp], None, true).is_err());
        assert!(p(&[ScanType::PingOnly], Some(PingMode::Skip), true).is_err());
        assert!(p(&[ScanType::PingOnly, ScanType::Version], None, true).is_err());
    }

    #[test]
    fn timing_templates_and_overrides() {
        let a = Args::try_parse_from(["feroprobe", "-T4", "10.0.0.1"]).unwrap();
        assert_eq!(a.timing, Some(Timing::Aggressive));
        let cfg = scan_config(&a);
        assert_eq!(cfg.concurrency, Timing::Aggressive.config().concurrency);
        assert_eq!(cfg.timeout, Timing::Aggressive.config().timeout);

        // Explicit flags win over the template.
        let a = Args::try_parse_from([
            "feroprobe",
            "-T",
            "sneaky",
            "-c",
            "50",
            "--timeout",
            "800",
            "--scan-delay",
            "250ms",
            "10.0.0.1",
        ])
        .unwrap();
        let cfg = scan_config(&a);
        assert_eq!(cfg.concurrency, 50);
        assert_eq!(cfg.timeout, Duration::from_millis(800));
        assert_eq!(cfg.scan_delay, Duration::from_millis(250));
        assert_eq!(cfg.retries, Timing::Sneaky.config().retries);

        // No -T means the normal template, which is the old default.
        let a = Args::try_parse_from(["feroprobe", "10.0.0.1"]).unwrap();
        let (cfg, d) = (scan_config(&a), ScanConfig::default());
        assert_eq!(
            (
                cfg.timeout,
                cfg.concurrency,
                cfg.retries,
                cfg.max_rate,
                cfg.scan_delay
            ),
            (
                d.timeout,
                d.concurrency,
                d.retries,
                d.max_rate,
                d.scan_delay
            )
        );
        // -sT and -T stay distinct.
        let a = Args::try_parse_from(["feroprobe", "-sT", "-T5", "10.0.0.1"]).unwrap();
        assert_eq!(
            (a.scan[0], a.timing),
            (ScanType::Connect, Some(Timing::Insane))
        );
        assert!(Args::try_parse_from(["feroprobe", "-T9", "10.0.0.1"]).is_err());
    }

    #[test]
    fn nmap_style_flags_parse() {
        let a = Args::try_parse_from(["feroprobe", "-sS", "-sU", "-Pn", "-p", "22", "10.0.0.1"])
            .unwrap();
        assert_eq!(a.scan, vec![ScanType::Syn, ScanType::Udp]);
        assert_eq!(a.ping, Some(PingMode::Skip));
        let a = Args::try_parse_from(["feroprobe", "-sn", "10.0.0.0/24"]).unwrap();
        assert_eq!(a.scan, vec![ScanType::PingOnly]);
        assert!(Args::try_parse_from(["feroprobe", "-sZ", "10.0.0.1"]).is_err());
        let a = Args::try_parse_from([
            "feroprobe",
            "--disable-arp-ping",
            "--oui-file",
            "/tmp/oui.txt",
            "10.0.0.1",
        ])
        .unwrap();
        assert!(a.disable_arp_ping);
        assert_eq!(
            a.oui_file.as_deref(),
            Some(std::path::Path::new("/tmp/oui.txt"))
        );
    }

    #[test]
    fn raw_tcp_scan_types() {
        // -sN is the NULL scan, -sn is ping only: case matters.
        let a = Args::try_parse_from([
            "feroprobe",
            "-sF",
            "-sN",
            "-sX",
            "-sA",
            "-sW",
            "-sM",
            "-sn",
            "10.0.0.1",
        ])
        .unwrap();
        use ScanType::*;
        assert_eq!(a.scan, vec![Fin, Null, Xmas, Ack, Window, Maimon, PingOnly]);
        for t in [Fin, Null, Xmas, Ack, Window, Maimon] {
            let plan = p(&[t, Udp], None, false).unwrap();
            assert_eq!((plan.tcp, plan.udp), (Some(t), true));
        }
        let err = p(&[Fin, Ack], None, true).unwrap_err().to_string();
        assert!(err.contains("-sF and -sA"), "{err}");
        assert!(p(&[Xmas, Connect], None, true).is_err());
        assert_eq!(Ack.raw_kind(), Some(TcpScanKind::Ack));
        assert_eq!(Connect.raw_kind(), None);
    }

    #[test]
    fn scanflags_choose_a_raw_scan() {
        let a = Args::try_parse_from(["feroprobe", "--scanflags", "SYNFIN", "10.0.0.1"]).unwrap();
        assert_eq!(a.scanflags, Some(0x03));
        assert!(Args::try_parse_from(["feroprobe", "--scanflags", "BOGUS", "10.0.0.1"]).is_err());
        // Read as a SYN scan by default, even when unprivileged, and as the
        // chosen scan otherwise.
        use ScanType::*;
        assert_eq!(plan(&[], None, false, true).unwrap().tcp, Some(Syn));
        assert_eq!(plan(&[Ack], None, false, true).unwrap().tcp, Some(Ack));
        assert!(plan(&[Connect], None, true, true).is_err());
        assert!(plan(&[PingOnly], None, true, true).is_err());
    }
}
