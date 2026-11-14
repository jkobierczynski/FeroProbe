//! `feroprobe`: an nmap-style network scanner, written natively in Rust.

mod grep;
mod output;
mod xml;

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result, bail};
use clap::{Parser, ValueEnum};
use feroprobe_core::discovery::{DEFAULT_TCP_PING_PORT, DEFAULT_UDP_PING_PORT};
use feroprobe_core::timing::parse_duration;
use feroprobe_core::{
    Exclusions, HostResult, IpVersion, PingProbes, PortLists, RawTcpScan, ScanConfig, Target,
    TcpScanKind, Timing, connect_scan, detect_services, discover, os_detect, parse_port_lists,
    parse_ports, parse_scanflags, raw_ipv6_available, raw_sockets_available, raw_tcp_scan,
    resolve_targets_with, reverse_lookup, top_ports, top_udp_ports, traceroute, udp_scan,
};
use futures::StreamExt;

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

/// One `-P` option: how to look for live hosts, or `-Pn` to not look.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PingArg {
    Skip,
    Syn(Vec<u16>),
    Ack(Vec<u16>),
    Udp(Vec<u16>),
    Echo,
    Timestamp,
    Mask,
}

/// Parse what follows `-P`: `n`, `E`, `P`, `M`, or `S`, `A`, `U` with an
/// optional port list run on, as nmap writes them (`-PS22,443`).
fn parse_ping(s: &str) -> Result<PingArg, String> {
    let kind = s.chars().next().unwrap_or(' ');
    let rest = &s[kind.len_utf8().min(s.len())..];
    let ports = |default: u16| -> Result<Vec<u16>, String> {
        if rest.is_empty() {
            Ok(vec![default])
        } else {
            parse_ports(rest).map_err(|e| e.to_string())
        }
    };
    let alone = |arg: PingArg| {
        if rest.is_empty() {
            Ok(arg)
        } else {
            Err(format!("-P{kind} takes no ports"))
        }
    };
    match kind {
        // -P0 is nmap's old spelling of -Pn.
        'n' | '0' => alone(PingArg::Skip),
        'E' => alone(PingArg::Echo),
        'P' => alone(PingArg::Timestamp),
        'M' => alone(PingArg::Mask),
        'S' => Ok(PingArg::Syn(ports(DEFAULT_TCP_PING_PORT)?)),
        'A' => Ok(PingArg::Ack(ports(DEFAULT_TCP_PING_PORT)?)),
        'U' => Ok(PingArg::Udp(ports(DEFAULT_UDP_PING_PORT)?)),
        'O' | 'Y' | 'R' => Err(format!(
            "-P{kind} is not supported; use -PS, -PA, -PU, -PE, -PP or -PM"
        )),
        _ => Err(format!(
            "unknown ping type -P{s}; use -Pn, -PS, -PA, -PU, -PE, -PP or -PM"
        )),
    }
}

/// The discovery probes the `-P` options ask for: `None` for the default
/// set, and an error if `-Pn` comes with probe types.
fn ping_probes(args: &[PingArg]) -> Result<Option<PingProbes>> {
    let skip = args.contains(&PingArg::Skip);
    let chosen: Vec<&PingArg> = args.iter().filter(|a| **a != PingArg::Skip).collect();
    if chosen.is_empty() {
        return Ok(None);
    }
    if skip {
        bail!("-Pn skips host discovery, so it cannot be combined with other -P options");
    }
    let mut probes = PingProbes::none();
    for arg in chosen {
        match arg {
            PingArg::Syn(p) => probes.syn.extend(p),
            PingArg::Ack(p) => probes.ack.extend(p),
            PingArg::Udp(p) => probes.udp.extend(p),
            PingArg::Echo => probes.echo = true,
            PingArg::Timestamp => probes.timestamp = true,
            PingArg::Mask => probes.mask = true,
            PingArg::Skip => {}
        }
    }
    for ports in [&mut probes.syn, &mut probes.ack, &mut probes.udp] {
        let mut seen = std::collections::HashSet::new();
        ports.retain(|p| seen.insert(*p));
    }
    Ok(Some(probes))
}

/// A DNS server for `--dns-servers`: an address, with port 53 unless one
/// is given (`192.0.2.53:5353`, `[2001:db8::53]:53`).
fn parse_dns_server(s: &str) -> Result<SocketAddr, String> {
    s.parse::<SocketAddr>()
        .or_else(|_| s.parse::<IpAddr>().map(|ip| SocketAddr::new(ip, 53)))
        .map_err(|_| format!("{s} is not an IP address"))
}

/// Shuffle `items` in place (Fisher-Yates) with a small xorshift generator
/// seeded from the clock, for --randomize-hosts. Not for cryptography.
fn shuffle<T>(items: &mut [T]) {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64);
    let mut state = (nanos ^ (u64::from(std::process::id()) << 32)) | 1;
    for i in (1..items.len()).rev() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        items.swap(i, (state % (i as u64 + 1)) as usize);
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Format {
    /// Human-readable table, like nmap's normal output
    Table,
    /// Machine-readable JSON
    Json,
    /// XML in nmap's layout, for tools that read nmap's -oX output
    Xml,
    /// One line per host, like nmap's -oG output
    Grepable,
}

fn render(format: Format, hosts: &[HostResult], info: &RunInfo) -> Result<String> {
    Ok(match format {
        Format::Table => output::render_table(hosts, info),
        Format::Json => output::render_json(hosts, info)?,
        Format::Xml => xml::render(hosts, info),
        Format::Grepable => grep::render(hosts, info),
    })
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
///   feroprobe -iL hosts.txt --exclude 10.0.0.1 -oA scan   (scan.nmap, scan.xml, scan.gnmap)
///   feroprobe -v -oG - 10.0.0.0/24                     (grepable on stdout, progress on stderr)
///   sudo feroprobe -A 10.0.0.5              (-sV -O --traceroute)
///   sudo feroprobe --traceroute -p 443 example.org
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
    #[arg(required_unless_present = "input_file")]
    targets: Vec<String>,

    /// -iL FILE: read more targets from FILE (one or more per line, # starts
    /// a comment; "-" reads standard input)
    #[arg(long = "input-file", value_name = "FILE")]
    input_file: Option<String>,

    /// Leave these hosts out: comma-separated addresses, CIDR blocks,
    /// ranges or hostnames
    #[arg(long, value_name = "HOSTS", value_delimiter = ',')]
    exclude: Vec<String>,

    /// Leave out the hosts listed in FILE (same format as -iL)
    #[arg(long, value_name = "FILE")]
    excludefile: Option<String>,

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

    /// Host discovery, nmap style. -Pn: skip it and scan every target as if
    /// it were up. Otherwise pick the probes (default: ICMP echo plus TCP
    /// connects to 443 and 80): -PS[ports] TCP connect (default 80),
    /// -PA[ports] TCP ACK (raw sockets on Linux, else a connect; default 80),
    /// -PU[ports] UDP (default 40125), -PE ICMP echo, -PP ICMP timestamp,
    /// -PM ICMP address mask (the last two IPv4 with raw sockets).
    /// Ports run on without a space: -PS22,443. Can be repeated
    #[arg(short = 'P', value_name = "TYPE", value_parser = parse_ping)]
    ping: Vec<PingArg>,

    /// -n: never look up the names of the addresses (reverse DNS)
    #[arg(short = 'n', conflicts_with = "always_resolve")]
    no_resolve: bool,

    /// -R: look up the names of all targets, not only the hosts that are up
    #[arg(short = 'R')]
    always_resolve: bool,

    /// Reverse DNS servers to ask, comma-separated (default: the system
    /// resolver), e.g. 192.0.2.53,192.0.2.54:5353
    #[arg(
        long,
        value_name = "ADDRS",
        value_delimiter = ',',
        value_parser = parse_dns_server
    )]
    dns_servers: Vec<SocketAddr>,

    /// Scan the targets in random order
    #[arg(long)]
    randomize_hosts: bool,

    /// Don't use ARP (IPv4) or neighbour discovery (IPv6) for targets on a
    /// local Ethernet network; ping them with the -P probes like remote
    /// hosts. Without it, ARP decides for local hosts and -P probes go only
    /// to the rest. --send-ip does the same, like nmap's
    #[arg(long, visible_alias = "send-ip")]
    disable_arp_ping: bool,

    /// IEEE OUI list for MAC vendor names (oui.txt, oui.csv, Wireshark manuf).
    /// Default: the first of /usr/share/hwdata/oui.txt, /usr/share/ieee-data/oui.txt
    /// and similar system locations that exists, else a small built-in table
    #[arg(long, value_name = "FILE")]
    oui_file: Option<std::path::PathBuf>,

    /// -O: guess each host's operating system (raw sockets: Linux, root or CAP_NET_RAW)
    #[arg(short = 'O')]
    os: bool,

    /// Trace the route to each host that is up, after the port scan
    /// (raw sockets: Linux, root or CAP_NET_RAW)
    #[arg(long)]
    traceroute: bool,

    /// -A: aggressive detection, the same as -sV -O --traceroute. Without
    /// raw-socket privileges only -sV runs, with a warning
    #[arg(short = 'A')]
    aggressive: bool,

    /// Ports to scan, e.g. "22", "1-1024", "22,80,443", "-" for all.
    /// T: and U: mark TCP and UDP ports: "22,U:53,T:80" (unmarked ports
    /// are both)
    #[arg(short = 'p', long, conflicts_with = "top_ports")]
    ports: Option<String>,

    /// Scan the N most common ports (default 100 for TCP, 20 for UDP)
    #[arg(long, value_name = "N")]
    top_ports: Option<usize>,

    /// -F: fast mode, the 100 most common TCP and UDP ports
    #[arg(short = 'F', conflicts_with_all = ["ports", "top_ports"])]
    fast: bool,

    /// Leave these ports out, written like -p (T: and U: work too)
    #[arg(long, value_name = "PORTS")]
    exclude_ports: Option<String>,

    /// -r: scan ports in order (by default their order is shuffled, like
    /// nmap's)
    #[arg(short = 'r')]
    ordered_ports: bool,

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

    /// Send at least this many probes per second: raises --max-rate and
    /// the connect/UDP parallelism as needed, and shortens a template's
    /// scan delay
    #[arg(long, value_name = "PPS")]
    min_rate: Option<u32>,

    /// Minimum time between probes, e.g. 500ms, 2s, 5m (a bare number is seconds)
    /// [default: from -T; normally none]
    #[arg(long, value_name = "TIME", value_parser = parse_duration)]
    scan_delay: Option<Duration>,

    /// Give up on a host whose port scan and detection take longer than
    /// this, e.g. 30s or 5m; it is reported without results
    #[arg(long, value_name = "TIME", value_parser = parse_duration)]
    host_timeout: Option<Duration>,

    /// Print a progress line to standard error at this interval, e.g. 10s
    #[arg(long, value_name = "TIME", value_parser = parse_duration)]
    stats_every: Option<Duration>,

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

    /// Output format on standard output
    #[arg(short = 'o', long, value_enum, default_value_t = Format::Table)]
    output: Format,

    /// -oN FILE: also write the normal (table) report to FILE ("-" for stdout)
    #[arg(long = "output-normal", value_name = "FILE")]
    out_normal: Option<String>,

    /// -oX FILE: also write the XML report to FILE ("-" for stdout)
    #[arg(long = "output-xml", value_name = "FILE")]
    out_xml: Option<String>,

    /// -oG FILE: also write the grepable report to FILE ("-" for stdout)
    #[arg(long = "output-grepable", value_name = "FILE")]
    out_grep: Option<String>,

    /// -oJ FILE: also write the JSON report to FILE ("-" for stdout)
    #[arg(long = "output-json", value_name = "FILE")]
    out_json: Option<String>,

    /// -oA BASE: write BASE.nmap, BASE.xml and BASE.gnmap (normal, XML and
    /// grepable) at once
    #[arg(long = "output-all", value_name = "BASE")]
    out_all: Option<String>,

    /// -v: report progress on standard error (each phase with its time,
    /// and the open ports each scan found when it finishes); -vv for more
    #[arg(short = 'v', action = clap::ArgAction::Count)]
    verbose: u8,
}

/// nmap's two-letter options (`-iL`, `-oN`, `-oX`, `-oG`, `-oA`) clash with
/// clap's short flags, so they are renamed to their long forms before
/// parsing. Only whole arguments before `--` are touched.
fn nmap_style_args(argv: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = false;
    for a in argv {
        if rest {
            out.push(a);
            continue;
        }
        let long = match a.as_str() {
            "--" => {
                rest = true;
                None
            }
            "-iL" => Some("--input-file"),
            "-oN" => Some("--output-normal"),
            "-oX" => Some("--output-xml"),
            "-oG" => Some("--output-grepable"),
            "-oJ" => Some("--output-json"),
            "-oA" => Some("--output-all"),
            _ => None,
        };
        out.push(long.map_or(a, str::to_string));
    }
    out
}

/// Host specs from a target list file: whitespace-separated, with `#`
/// comments. `-` reads standard input.
fn read_host_list(path: &str) -> Result<Vec<String>> {
    let text = if path == "-" {
        std::io::read_to_string(std::io::stdin()).context("reading targets from stdin")?
    } else {
        std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?
    };
    Ok(parse_host_list(&text))
}

fn parse_host_list(text: &str) -> Vec<String> {
    text.lines()
        .flat_map(|line| {
            let line = line.split('#').next().unwrap_or("");
            line.split_whitespace().map(str::to_string)
        })
        .collect()
}

/// Where each report goes, from -oN/-oX/-oG/-oJ/-oA. A path of `-` means
/// standard output, which then carries that report instead of the usual one.
#[derive(Debug, Default, PartialEq)]
struct Outputs {
    normal: Vec<String>,
    xml: Vec<String>,
    grep: Vec<String>,
    json: Vec<String>,
}

/// The real location a report path names, so that `r`, `./r`, `sub/../r`
/// and symbolic links to the same file all compare equal. A report file
/// usually doesn't exist yet, so its directory is resolved instead.
fn report_key(path: &str) -> std::path::PathBuf {
    let p = std::path::Path::new(path);
    if let Ok(real) = p.canonicalize() {
        return real;
    }
    let dir = match p.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => std::path::Path::new("."),
    };
    match (dir.canonicalize(), p.file_name()) {
        (Ok(real), Some(name)) => real.join(name),
        _ => std::path::absolute(p).unwrap_or_else(|_| p.into()),
    }
}

impl Outputs {
    fn from_args(args: &Args) -> Result<Self> {
        let mut o = Outputs::default();
        let push = |v: &mut Vec<String>, p: &Option<String>| v.extend(p.iter().cloned());
        push(&mut o.normal, &args.out_normal);
        push(&mut o.xml, &args.out_xml);
        push(&mut o.grep, &args.out_grep);
        push(&mut o.json, &args.out_json);
        if let Some(base) = &args.out_all {
            if base == "-" {
                bail!("-oA needs a file name base, not -");
            }
            o.normal.push(format!("{base}.nmap"));
            o.xml.push(format!("{base}.xml"));
            o.grep.push(format!("{base}.gnmap"));
        }
        let to_stdout = [&o.normal, &o.xml, &o.grep, &o.json]
            .iter()
            .flat_map(|v| v.iter())
            .filter(|p| *p == "-")
            .count();
        if to_stdout > 1 {
            bail!("only one report can go to standard output (-)");
        }
        // Two reports in one file would leave only the last one written.
        let mut seen = std::collections::HashSet::new();
        for path in o.files() {
            if !seen.insert(report_key(path)) {
                bail!("two reports would be written to {path}; give each its own file");
            }
        }
        Ok(o)
    }

    fn files(&self) -> impl Iterator<Item = &String> {
        [&self.normal, &self.xml, &self.grep, &self.json]
            .into_iter()
            .flat_map(|v| v.iter())
            .filter(|p| *p != "-")
    }

    /// Open (creating, not truncating) every report file before the scan,
    /// as nmap does. This catches unwritable paths up front, and then
    /// compares the files themselves, so that aliases a path can't show
    /// (a link whose target doesn't exist yet, a hard link, or another
    /// spelling on a case-insensitive file system) can't make two reports
    /// share one file. On Unix the file's device and inode decide; on other
    /// systems the canonical path of the now existing file, which on Windows
    /// comes back in the case stored on disk.
    fn open_files(&self) -> Result<()> {
        let mut seen = std::collections::HashSet::new();
        for path in self.files() {
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .open(path)
                .with_context(|| format!("opening {path}"))?;
            #[cfg(unix)]
            let id = {
                use std::os::unix::fs::MetadataExt;
                let m = file.metadata().with_context(|| format!("reading {path}"))?;
                (m.dev(), m.ino())
            };
            #[cfg(not(unix))]
            let id = {
                drop(file);
                std::fs::canonicalize(path).with_context(|| format!("resolving {path}"))?
            };
            if !seen.insert(id) {
                bail!("two reports would be written to {path}; give each its own file");
            }
        }
        Ok(())
    }

    /// Whether some -o option took over standard output.
    fn stdout_taken(&self) -> bool {
        [&self.normal, &self.xml, &self.grep, &self.json]
            .iter()
            .any(|v| v.iter().any(|p| p == "-"))
    }
}

/// Progress on standard error for -v.
/// Progress reports on standard error: `-v` messages, and the phase that
/// `--stats-every` names.
#[derive(Clone, Copy)]
struct Progress {
    level: u8,
    /// Whether this run's phases are the ones `--stats-every` reports. Off
    /// for the per-host scans of `--host-timeout`, which share one count.
    track: bool,
}

/// The phase `--stats-every` reports.
static PHASE: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());

fn set_phase(what: &str, probes: usize) {
    *PHASE.lock().unwrap_or_else(|e| e.into_inner()) = what.to_string();
    feroprobe_core::progress::reset(probes as u64);
}

impl Progress {
    fn say(&self, level: u8, msg: impl FnOnce() -> String) {
        if self.level >= level {
            eprintln!("{}", msg());
        }
    }

    /// Start a phase; the returned closure reports it done.
    fn phase(&self, what: &str, hosts: usize) -> impl FnOnce(&Progress) + use<> {
        self.phase_of(what, hosts, 0)
    }

    /// Start a phase that sends `probes` probes (0 if unknown), counted for
    /// `--stats-every`.
    fn phase_of(&self, what: &str, hosts: usize, probes: usize) -> impl FnOnce(&Progress) + use<> {
        if self.track {
            set_phase(what, probes);
        }
        let what = what.to_string();
        let start = Instant::now();
        self.say(1, || {
            format!("Initiating {what} of {hosts} host{}", plural(hosts))
        });
        move |p: &Progress| {
            p.say(1, || {
                format!("Completed {what} in {:.2}s", start.elapsed().as_secs_f64())
            })
        }
    }

    /// Announce the open ports a scan found, like nmap's -v.
    fn found(&self, results: &[HostResult]) {
        for h in results {
            for p in h
                .ports
                .iter()
                .filter(|p| p.state == feroprobe_core::PortState::Open)
            {
                self.say(1, || {
                    format!(
                        "Discovered open port {}/{} on {}",
                        p.port, p.protocol, h.addr
                    )
                });
            }
        }
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
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
fn plan(scan: &[ScanType], skip_discovery: bool, syn_ok: bool, scanflags: bool) -> Result<Plan> {
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
        discovery: !skip_discovery,
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
        deadline: None,
    }
}

/// Apply `--min-rate` on top of the timing settings. Raw-socket scans send
/// as fast as `max_rate` and the scan delay allow, so those must allow the
/// minimum; connect and UDP probes need enough of them in flight to keep
/// the rate up even when every probe waits out its timeout. Returns
/// warnings for what cannot be guaranteed.
fn apply_min_rate(
    cfg: &mut ScanConfig,
    args: &Args,
    open_files: Option<u64>,
) -> Result<Vec<String>> {
    let Some(min) = args.min_rate else {
        return Ok(Vec::new());
    };
    if min == 0 {
        bail!("--min-rate must be at least 1");
    }
    match args.max_rate {
        Some(max) if max < min => bail!("--min-rate {min} is above --max-rate {max}"),
        _ => cfg.max_rate = cfg.max_rate.max(min),
    }
    let gap = Duration::from_secs_f64(1.0 / f64::from(min));
    if cfg.scan_delay > gap {
        if args.scan_delay.is_some() {
            bail!(
                "--scan-delay {:?} allows fewer than --min-rate {min} probes per second",
                cfg.scan_delay
            );
        }
        // A template's delay gives way, as in nmap.
        cfg.scan_delay = gap;
    }
    let mut warnings = Vec::new();
    let needed = (f64::from(min) * cfg.timeout.as_secs_f64()).ceil() as usize;
    if needed > cfg.concurrency {
        if let Some(c) = args.concurrency {
            warnings.push(format!(
                "--concurrency {c} may keep connect and UDP scans below --min-rate {min} \
                 ({needed} probes can be waiting for an answer at once)"
            ));
        } else {
            // Leave room for the process's other files.
            let cap = open_files.map_or(usize::MAX, |n| n.saturating_sub(64).max(1) as usize);
            if needed > cap {
                warnings.push(format!(
                    "the open file limit (ulimit -n) allows {cap} connect or UDP probes at once, \
                     which may keep those scans below --min-rate {min}"
                ));
            }
            cfg.concurrency = needed.min(cap).max(cfg.concurrency);
        }
    }
    Ok(warnings)
}

/// The TCP and UDP ports to scan, sorted: from -p, -F or --top-ports, less
/// --exclude-ports.
fn port_lists(args: &Args) -> Result<PortLists> {
    let mut lists = match &args.ports {
        Some(spec) => parse_port_lists(spec)?,
        None => {
            let n = if args.fast { Some(100) } else { args.top_ports };
            PortLists {
                tcp: top_ports(n.unwrap_or(100)),
                udp: top_udp_ports(n.unwrap_or(20)),
            }
        }
    };
    if let Some(spec) = &args.exclude_ports {
        let ex = parse_port_lists(spec).context("reading --exclude-ports")?;
        lists.tcp.retain(|p| ex.tcp.binary_search(p).is_err());
        lists.udp.retain(|p| ex.udp.binary_search(p).is_err());
    }
    Ok(lists)
}

/// Take the `--exclude-ports` ports out of the discovery probes, as nmap
/// does, with nmap's warning for a probe type left without ports.
fn exclude_ping_ports(probes: &mut PingProbes, ex: &PortLists) -> Vec<String> {
    let had_tcp = !probes.syn.is_empty() || !probes.ack.is_empty();
    let had_udp = !probes.udp.is_empty();
    probes.syn.retain(|p| ex.tcp.binary_search(p).is_err());
    probes.ack.retain(|p| ex.tcp.binary_search(p).is_err());
    probes.udp.retain(|p| ex.udp.binary_search(p).is_err());
    let mut warnings = Vec::new();
    if had_tcp && probes.syn.is_empty() && probes.ack.is_empty() {
        warnings.push(
            "a TCP ping was asked for, but --exclude-ports removed all its ports; skipping it"
                .to_string(),
        );
    }
    if had_udp && probes.udp.is_empty() {
        warnings.push(
            "a UDP ping was asked for, but --exclude-ports removed all its ports; skipping it"
                .to_string(),
        );
    }
    warnings
}

/// Warnings for `-p` ports marked for a protocol this scan does not use,
/// like nmap's: `-sS -p U:53` scans no UDP port.
fn protocol_warnings(spec: &str, tcp_scan: bool, udp_scan: bool) -> Vec<String> {
    let marked = |prefix: &str| {
        spec.split(',').any(|part| {
            part.trim()
                .get(..2)
                .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
        })
    };
    let mut warnings = Vec::new();
    if marked("U:") && !udp_scan {
        warnings
            .push("your ports include \"U:\" but you haven't asked for a UDP scan with -sU".into());
    }
    if marked("T:") && !tcp_scan {
        warnings.push("your ports include \"T:\" but you haven't asked for a TCP scan".into());
    }
    warnings
}

/// "1:02:03" for an elapsed time, like nmap's stats lines.
fn clock(d: Duration) -> String {
    let s = d.as_secs();
    format!("{}:{:02}:{:02}", s / 3600, s / 60 % 60, s % 60)
}

/// The `--stats-every` line for the current phase.
fn stats_line(elapsed: Duration) -> String {
    let phase = PHASE.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let (done, total) = feroprobe_core::progress::snapshot();
    let mut line = format!("Stats: {} elapsed", clock(elapsed));
    if !phase.is_empty() {
        line.push_str("; ");
        line.push_str(&phase);
        if total > 0 {
            let pct = done as f64 * 100.0 / total as f64;
            line.push_str(&format!(": {pct:.2}% done ({done} of {total} probes)"));
        }
    }
    line
}

/// Apply `-A`: version detection, plus OS detection and traceroute when
/// raw sockets are available (with a warning when they are not). Returns
/// whether OS detection and traceroute run.
fn aggressive(plan: &mut Plan, args: &Args, privileged: bool) -> Result<(bool, bool)> {
    if !args.aggressive {
        return Ok((args.os, args.traceroute));
    }
    if plan.ping_only {
        bail!("-A needs a port scan, so it cannot be combined with -sn");
    }
    plan.version = true;
    if privileged {
        return Ok((true, true));
    }
    eprintln!(
        "Warning: -A without root runs only -sV; OS detection and traceroute need raw sockets"
    );
    Ok((args.os, args.traceroute))
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
fn merge(hosts: &mut [HostResult], results: Vec<HostResult>) {
    for (host, r) in hosts.iter_mut().zip(results) {
        host.ports.extend(r.ports);
        host.sort_ports();
    }
}

/// The port scans and detection to run on the hosts that are up.
struct ScanJob<'a> {
    plan: &'a Plan,
    /// The ports, in the order to probe them.
    tcp: &'a [u16],
    udp: &'a [u16],
    scanflags: Option<u8>,
    version_wait: Duration,
    os: bool,
}

/// How many hosts `--host-timeout` scans at once, each on its own clock.
const HOST_GROUP: usize = 32;

impl ScanJob<'_> {
    /// The run's scan types, as the reports list them.
    fn scan_types(&self) -> Vec<&'static str> {
        let mut types = Vec::new();
        match self.plan.tcp.map(|t| t.raw_kind()) {
            Some(Some(kind)) => types.push(tcp_scan_label(kind)),
            Some(None) => types.push("tcp-connect"),
            None => {}
        }
        if self.plan.udp {
            types.push("udp");
        }
        if self.plan.version {
            types.push("version");
        }
        if self.os {
            types.push("os");
        }
        types
    }

    /// Scan `live` together, adding the results to `hosts` (one per target).
    async fn run(
        &self,
        live: &[Target],
        hosts: &mut [HostResult],
        cfg: &ScanConfig,
        progress: Progress,
    ) -> Result<()> {
        let hint = "scan aborted (try a lower --concurrency)";
        match self.plan.tcp.map(|t| (t, t.raw_kind())) {
            Some((t, Some(kind))) => {
                let mut scan = RawTcpScan::new(kind);
                if let Some(flags) = self.scanflags {
                    scan.flags = flags;
                }
                let done = progress.phase_of(
                    &format!("TCP {} scan", kind.name().to_uppercase()),
                    live.len(),
                    live.len() * self.tcp.len(),
                );
                let r = raw_tcp_scan(live, self.tcp, cfg, scan)
                    .await
                    .with_context(|| format!("TCP {} scan ({}) failed", kind.name(), t.flag()))?;
                progress.found(&r);
                done(&progress);
                merge(hosts, r);
            }
            Some((_, None)) => {
                let done =
                    progress.phase_of("TCP connect scan", live.len(), live.len() * self.tcp.len());
                let r = connect_scan(live, self.tcp, cfg).await.context(hint)?;
                progress.found(&r);
                done(&progress);
                merge(hosts, r);
            }
            None => {}
        }
        if self.plan.udp {
            let done = progress.phase_of("UDP scan", live.len(), live.len() * self.udp.len());
            let r = udp_scan(live, self.udp, cfg).await.context(hint)?;
            progress.found(&r);
            done(&progress);
            merge(hosts, r);
        }
        if self.plan.version {
            let done = progress.phase("service detection", live.len());
            detect_services(hosts, cfg, self.version_wait).await;
            done(&progress);
        }
        if self.os {
            let done = progress.phase("OS detection", live.len());
            os_detect(hosts, cfg).await.context("OS detection failed")?;
            done(&progress);
        }
        Ok(())
    }

    /// Scan each host on its own clock (`--host-timeout`): a host whose
    /// scans take longer than `limit` is marked timed out and loses its
    /// port and OS results. Up to [`HOST_GROUP`] hosts run at once, sharing
    /// the parallelism and packet rate.
    async fn run_each(
        &self,
        live: &[Target],
        hosts: &mut [HostResult],
        cfg: &ScanConfig,
        limit: Duration,
        progress: Progress,
    ) -> Result<()> {
        let group = host_group(live.len(), cfg);
        let mut shared = cfg.clone();
        shared.concurrency = (cfg.concurrency / group).max(1);
        shared.max_rate = (cfg.max_rate / group as u32).max(1);
        let probes = self.plan.tcp.map_or(0, |_| self.tcp.len())
            + if self.plan.udp { self.udp.len() } else { 0 };
        let done = progress.phase_of(
            "port scan (each host on its own clock)",
            live.len(),
            live.len() * probes,
        );
        let quiet = Progress {
            level: 0,
            track: false,
        };
        let start: Vec<HostResult> = hosts.to_vec();
        let jobs = live.iter().zip(start).enumerate().map(|(i, (t, host))| {
            let shared = &shared;
            async move {
                let mut cfg = shared.clone();
                // A limit too far out to represent never expires.
                cfg.deadline = Instant::now().checked_add(limit);
                let mut one = [host];
                let outcome = tokio::time::timeout(
                    limit,
                    self.run(std::slice::from_ref(t), &mut one, &cfg, quiet),
                )
                .await;
                let [host] = one;
                (i, host, outcome)
            }
        });
        let mut results = futures::stream::iter(jobs).buffer_unordered(group);
        while let Some((i, host, outcome)) = results.next().await {
            let timed_out = match outcome {
                Ok(Ok(())) => false,
                Ok(Err(e)) if is_host_timeout(&e) => true,
                Ok(Err(e)) => return Err(e),
                Err(_) => true,
            };
            if timed_out {
                progress.say(1, || {
                    format!("Skipping host {} due to host timeout", host.addr)
                });
                let h = &mut hosts[i];
                h.ports.clear();
                h.os = None;
                h.timed_out = true;
            } else {
                progress.found(std::slice::from_ref(&host));
                hosts[i] = host;
            }
        }
        done(&progress);
        Ok(())
    }
}

/// How many hosts `--host-timeout` scans at once: at most [`HOST_GROUP`],
/// and fewer when the budgets are small, so that every host gets at least
/// one probe in flight and one packet per second while the totals stay
/// within `--concurrency` and `--max-rate`.
fn host_group(hosts: usize, cfg: &ScanConfig) -> usize {
    hosts
        .min(HOST_GROUP)
        .min(cfg.concurrency)
        .min(cfg.max_rate as usize)
        .max(1)
}

/// Whether a scan error is the `--host-timeout` deadline passing.
fn is_host_timeout(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        c.downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::TimedOut)
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse_from(nmap_style_args(std::env::args()));
    let outputs = Outputs::from_args(&args)?;
    outputs.open_files()?;
    let progress = Progress {
        level: args.verbose,
        track: true,
    };
    let version = if args.ipv6 {
        IpVersion::V6
    } else {
        IpVersion::PreferV4
    };
    if args.input_file.as_deref() == Some("-") && args.excludefile.as_deref() == Some("-") {
        bail!("-iL - and --excludefile - cannot both read standard input; put one list in a file");
    }
    let mut specs = args.targets.clone();
    if let Some(path) = &args.input_file {
        specs.extend(read_host_list(path)?);
    }
    if specs.is_empty() {
        bail!("no targets given");
    }
    let mut excluded = args.exclude.clone();
    if let Some(path) = &args.excludefile {
        excluded.extend(read_host_list(path)?);
    }
    let exclusions = Exclusions::parse(&excluded)
        .await
        .context("reading --exclude")?;
    let mut targets = resolve_targets_with(&specs, version)
        .await
        .context("resolving targets")?;
    if !exclusions.is_empty() {
        let before = targets.len();
        targets.retain(|t| !exclusions.excludes(t));
        progress.say(1, || format!("Excluded {} host(s)", before - targets.len()));
        if targets.is_empty() {
            bail!("every target is excluded");
        }
    }
    if args.randomize_hosts {
        shuffle(&mut targets);
    }
    let any_ipv6 = targets.iter().any(|t| t.addr.is_ipv6());
    let syn_ok = raw_sockets_available() && (!any_ipv6 || raw_ipv6_available());
    let mut probes = ping_probes(&args.ping)?.unwrap_or_default();
    if let Some(spec) = &args.exclude_ports {
        let ex = parse_port_lists(spec).context("reading --exclude-ports")?;
        for w in exclude_ping_ports(&mut probes, &ex) {
            eprintln!("Warning: {w}");
        }
    }
    let skip_discovery = args.ping.contains(&PingArg::Skip);
    let mut plan = plan(&args.scan, skip_discovery, syn_ok, args.scanflags.is_some())?;
    let (mut os, trace) = aggressive(&mut plan, &args, raw_sockets_available())?;
    if os {
        if plan.ping_only {
            bail!("-O needs a port scan, so it cannot be combined with -sn");
        }
        if !raw_sockets_available() {
            bail!("-O sends raw packets: run as root or grant CAP_NET_RAW");
        }
    }

    let PortLists {
        tcp: tcp_ports,
        udp: udp_ports,
    } = port_lists(&args)?;
    if plan.ping_only && !plan.discovery && !trace {
        bail!("-sn with -Pn would do nothing (add --traceroute to only trace the route)");
    }
    if trace && !raw_sockets_available() {
        bail!("--traceroute sends raw packets: run as root or grant CAP_NET_RAW");
    }
    if !plan.ping_only
        && let Some(spec) = &args.ports
    {
        for w in protocol_warnings(spec, plan.tcp.is_some(), plan.udp) {
            eprintln!("Warning: {w}");
        }
    }
    if !plan.ping_only {
        // Like nmap: a scan type left without ports is skipped, not an error.
        if plan.tcp.is_some() && tcp_ports.is_empty() {
            eprintln!(
                "Warning: a TCP scan was asked for, but no TCP ports were given; skipping it"
            );
            plan.tcp = None;
        }
        if plan.udp && udp_ports.is_empty() {
            eprintln!(
                "Warning: a UDP scan was asked for, but no UDP ports were given; skipping it"
            );
            plan.udp = false;
        }
        if plan.tcp.is_none() && !plan.udp {
            plan.ping_only = true;
            plan.version = false;
            if os {
                eprintln!("Warning: skipping OS detection, which needs a port scan");
                os = false;
            }
        }
    }
    // The order probes go out in; reports keep the sorted lists.
    let (mut tcp_order, mut udp_order) = (tcp_ports.clone(), udp_ports.clone());
    if !args.ordered_ports {
        shuffle(&mut tcp_order);
        shuffle(&mut udp_order);
    }

    let mut cfg = scan_config(&args);
    let warnings = apply_min_rate(&mut cfg, &args, feroprobe_core::connect::open_file_limit())?;
    // The warnings are about connect and UDP probes.
    let sockets = !plan.ping_only && (plan.udp || plan.tcp.is_some_and(|t| t.raw_kind().is_none()));
    for w in warnings.iter().filter(|_| sockets) {
        eprintln!("Warning: {w}");
    }

    if let Some(path) = &args.oui_file {
        feroprobe_core::oui::use_file(path)
            .with_context(|| format!("reading OUI list {}", path.display()))?;
    }

    let started = Instant::now();
    let start_time = SystemTime::now();
    let stats = args.stats_every.filter(|d| !d.is_zero()).map(|every| {
        tokio::spawn(async move {
            let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
            loop {
                tick.tick().await;
                eprintln!("{}", stats_line(started.elapsed()));
            }
        })
    });
    let mut hosts: Vec<HostResult> = if plan.discovery {
        let done = progress.phase("host discovery", targets.len());
        let hosts = discover(&targets, &cfg, &probes)
            .await
            .context("host discovery failed")?;
        done(&progress);
        let up = hosts.iter().filter(|h| h.is_up()).count();
        progress.say(1, || {
            format!("{up} of {} host{} up", hosts.len(), plural(hosts.len()))
        });
        hosts
    } else {
        targets
            .iter()
            .map(|t| HostResult::new(t.addr, t.hostname.clone()))
            .collect()
    };

    if !args.no_resolve {
        // Like nmap: the hosts that are up (all of them with -Pn), or every
        // target with -R.
        let addrs: Vec<IpAddr> = hosts
            .iter()
            .filter(|h| args.always_resolve || !plan.discovery || h.is_up())
            .map(|h| h.addr)
            .collect();
        if !addrs.is_empty() {
            let done = progress.phase("reverse DNS", addrs.len());
            let names = reverse_lookup(&addrs, &args.dns_servers, &cfg)
                .await
                .context("reverse DNS failed")?;
            done(&progress);
            for h in &mut hosts {
                h.rdns = names.get(&h.addr).cloned();
            }
        }
    }

    let mut scan_types = Vec::new();
    if !plan.ping_only {
        let job = ScanJob {
            plan: &plan,
            tcp: &tcp_order,
            udp: &udp_order,
            scanflags: args.scanflags,
            version_wait: Duration::from_millis(args.version_timeout),
            os,
        };
        scan_types = job.scan_types();
        // Only scan hosts that discovery found (all of them with -Pn).
        let scanned: Vec<usize> = (0..hosts.len())
            .filter(|&i| !plan.discovery || hosts[i].is_up())
            .collect();
        let live: Vec<Target> = scanned.iter().map(|&i| targets[i].clone()).collect();
        let mut results: Vec<HostResult> = scanned.iter().map(|&i| hosts[i].clone()).collect();
        // As in nmap, a host timeout of 0 means none.
        match args.host_timeout.filter(|d| !d.is_zero()) {
            None => job.run(&live, &mut results, &cfg, progress).await?,
            Some(limit) => {
                job.run_each(&live, &mut results, &cfg, limit, progress)
                    .await?
            }
        }
        for (&i, h) in scanned.iter().zip(results) {
            hosts[i] = h;
        }
    } else {
        scan_types.push("ping");
    }
    if trace {
        scan_types.push("traceroute");
        // Hosts without a scanned port are traced with the first -p port.
        let fallback = if args.ports.is_some() {
            tcp_ports.first().copied().unwrap_or(80)
        } else {
            80
        };
        // Hosts given up on by --host-timeout are not traced either.
        let keep: Vec<usize> = (0..hosts.len()).filter(|&i| !hosts[i].timed_out).collect();
        let mut traced: Vec<HostResult> = keep.iter().map(|&i| hosts[i].clone()).collect();
        let done = progress.phase("traceroute", traced.len());
        traceroute(&mut traced, &cfg, !plan.discovery, fallback)
            .await
            .context("traceroute failed")?;
        done(&progress);
        for (&i, h) in keep.iter().zip(traced) {
            hosts[i] = h;
        }
    }

    if let Some(task) = stats {
        task.abort();
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
        show_os: os,
        show_trace: trace,
        assume_up: !plan.discovery,
        ping_only: plan.ping_only,
        nmap_label: args.nmap_label,
        verbosity: args.verbose,
    };
    if !outputs.stdout_taken() {
        print!("{}", render(args.output, &hosts, &info)?);
    }
    for (format, paths) in [
        (Format::Table, &outputs.normal),
        (Format::Xml, &outputs.xml),
        (Format::Grepable, &outputs.grep),
        (Format::Json, &outputs.json),
    ] {
        if paths.is_empty() {
            continue;
        }
        let text = render(format, &hosts, &info)?;
        for path in paths {
            if path == "-" {
                print!("{text}");
            } else {
                std::fs::write(path, &text).with_context(|| format!("writing {path}"))?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(scan: &[ScanType], skip: bool, syn_ok: bool) -> Result<Plan> {
        plan(scan, skip, syn_ok, false)
    }

    #[test]
    fn default_scan_type_depends_on_privileges() {
        let plan = p(&[], false, false).unwrap();
        assert_eq!(plan.tcp, Some(ScanType::Connect));
        assert!(plan.discovery && !plan.udp && !plan.ping_only);
        let expect = if cfg!(target_os = "linux") {
            ScanType::Syn
        } else {
            ScanType::Connect
        };
        assert_eq!(p(&[], false, true).unwrap().tcp, Some(expect));
    }

    #[test]
    fn udp_only_and_combined() {
        let plan = p(&[ScanType::Udp], false, true).unwrap();
        assert_eq!((plan.tcp, plan.udp), (None, true));
        let plan = p(&[ScanType::Connect, ScanType::Udp], true, true).unwrap();
        assert_eq!(
            (plan.tcp, plan.udp, plan.discovery),
            (Some(ScanType::Connect), true, false)
        );
    }

    #[test]
    fn version_detection_keeps_default_tcp_scan() {
        let plan = p(&[ScanType::Version], false, false).unwrap();
        assert_eq!((plan.tcp, plan.version), (Some(ScanType::Connect), true));
        let plan = p(&[ScanType::Udp, ScanType::Version], false, false).unwrap();
        assert_eq!((plan.tcp, plan.udp, plan.version), (None, true, true));
        let a = Args::try_parse_from(["feroprobe", "-sV", "10.0.0.1"]).unwrap();
        assert_eq!(a.scan, vec![ScanType::Version]);
    }

    #[test]
    fn rejects_conflicts() {
        assert!(p(&[ScanType::Syn, ScanType::Connect], false, true).is_err());
        assert!(p(&[ScanType::PingOnly, ScanType::Udp], false, true).is_err());
        assert!(p(&[ScanType::PingOnly, ScanType::Version], false, true).is_err());
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
        assert_eq!(a.ping, vec![PingArg::Skip]);
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
        let a = Args::try_parse_from(["feroprobe", "--send-ip", "10.0.0.1"]).unwrap();
        assert!(a.disable_arp_ping);
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
            let plan = p(&[t, Udp], false, false).unwrap();
            assert_eq!((plan.tcp, plan.udp), (Some(t), true));
        }
        let err = p(&[Fin, Ack], false, true).unwrap_err().to_string();
        assert!(err.contains("-sF and -sA"), "{err}");
        assert!(p(&[Xmas, Connect], false, true).is_err());
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
        assert_eq!(plan(&[], false, false, true).unwrap().tcp, Some(Syn));
        assert_eq!(plan(&[Ack], false, false, true).unwrap().tcp, Some(Ack));
        assert!(plan(&[Connect], false, true, true).is_err());
        assert!(plan(&[PingOnly], false, true, true).is_err());
    }

    #[test]
    fn aggressive_turns_on_detection() {
        let args = |argv: &[&str]| Args::try_parse_from(argv).unwrap();
        let a = args(&["feroprobe", "-A", "10.0.0.1"]);
        let mut pl = p(&a.scan, a.ping.contains(&PingArg::Skip), true).unwrap();
        assert_eq!(aggressive(&mut pl, &a, true).unwrap(), (true, true));
        assert!(pl.version);
        // Unprivileged: only version detection.
        let mut pl = p(&a.scan, a.ping.contains(&PingArg::Skip), false).unwrap();
        assert_eq!(aggressive(&mut pl, &a, false).unwrap(), (false, false));
        assert!(pl.version);
        // -A is not -sA.
        let a = args(&["feroprobe", "-sA", "--traceroute", "10.0.0.1"]);
        assert!(!a.aggressive);
        let mut pl = p(&a.scan, a.ping.contains(&PingArg::Skip), true).unwrap();
        assert_eq!(aggressive(&mut pl, &a, true).unwrap(), (false, true));
        assert!(!pl.version);
        let a = args(&["feroprobe", "-A", "-sn", "10.0.0.1"]);
        let mut pl = p(&a.scan, a.ping.contains(&PingArg::Skip), true).unwrap();
        assert!(aggressive(&mut pl, &a, true).is_err());
    }

    #[test]
    fn nmap_two_letter_options() {
        let argv = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            nmap_style_args(argv(&[
                "feroprobe",
                "-iL",
                "t.txt",
                "-oA",
                "out",
                "-oX",
                "-",
                "--",
                "-oN"
            ])),
            argv(&[
                "feroprobe",
                "--input-file",
                "t.txt",
                "--output-all",
                "out",
                "--output-xml",
                "-",
                "--",
                "-oN"
            ])
        );
        let a = Args::parse_from(nmap_style_args(argv(&[
            "feroprobe",
            "-iL",
            "t.txt",
            "-oG",
            "-",
            "-vv",
            "--exclude",
            "10.0.0.1,10.0.0.2",
            "-o",
            "json",
        ])));
        assert!(a.targets.is_empty());
        assert_eq!(a.input_file.as_deref(), Some("t.txt"));
        assert_eq!(a.exclude, ["10.0.0.1", "10.0.0.2"]);
        assert_eq!(a.verbose, 2);
        assert!(matches!(a.output, Format::Json));
        let o = Outputs::from_args(&a).unwrap();
        assert_eq!(o.grep, ["-"]);
        assert!(o.stdout_taken());
        // Targets are required unless -iL gives them.
        assert!(Args::try_parse_from(["feroprobe", "-p", "22"]).is_err());
    }

    #[test]
    fn output_all_and_stdout_conflicts() {
        let parse = |v: &[&str]| Args::parse_from(nmap_style_args(v.iter().map(|s| s.to_string())));
        let o = Outputs::from_args(&parse(&["feroprobe", "-oA", "scan", "10.0.0.1"])).unwrap();
        assert_eq!(o.normal, ["scan.nmap"]);
        assert_eq!(o.xml, ["scan.xml"]);
        assert_eq!(o.grep, ["scan.gnmap"]);
        assert!(!o.stdout_taken());
        assert!(
            Outputs::from_args(&parse(&["feroprobe", "-oX", "-", "-oG", "-", "10.0.0.1"])).is_err()
        );
        assert!(Outputs::from_args(&parse(&["feroprobe", "-oA", "-", "10.0.0.1"])).is_err());
        // Two reports in one file.
        assert!(
            Outputs::from_args(&parse(&["feroprobe", "-oN", "r", "-oX", "r", "10.0.0.1"])).is_err()
        );
        assert!(
            Outputs::from_args(&parse(&[
                "feroprobe",
                "-oA",
                "scan",
                "-oX",
                "scan.nmap",
                "10.0.0.1"
            ]))
            .is_err()
        );
        assert!(
            Outputs::from_args(&parse(&["feroprobe", "-oN", "a", "-oX", "b", "10.0.0.1"])).is_ok()
        );
    }

    #[test]
    fn report_paths_compare_by_real_location() {
        // A fresh name, created exclusively and private to this user, so the
        // test never writes through a directory or link someone else made.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("feroprobe-out-{}-{nanos}", std::process::id()));
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut std::fs::DirBuilder::new(), 0o700)
            .create(&dir)
            .unwrap();
        #[cfg(not(unix))]
        std::fs::DirBuilder::new().create(&dir).unwrap();
        std::fs::create_dir(dir.join("sub")).unwrap();
        let plain = dir.join("r").display().to_string();
        let dotted = dir.join("sub").join("..").join("r").display().to_string();
        assert_eq!(report_key(&plain), report_key(&dotted));
        assert_ne!(
            report_key(&plain),
            report_key(&dir.join("s").display().to_string())
        );
        #[cfg(unix)]
        {
            std::fs::write(&plain, "").unwrap();
            let link = dir.join("link");
            let _ = std::fs::remove_file(&link);
            std::os::unix::fs::symlink(&plain, &link).unwrap();
            assert_eq!(report_key(&plain), report_key(&link.display().to_string()));

            // Aliases only the files themselves reveal: a link to a report
            // that doesn't exist yet, and a hard link.
            let out = |normal: &std::path::Path, xml: &std::path::Path| Outputs {
                normal: vec![normal.display().to_string()],
                xml: vec![xml.display().to_string()],
                ..Default::default()
            };
            let dangling = dir.join("dangling");
            std::os::unix::fs::symlink(dir.join("later"), &dangling).unwrap();
            let o = out(&dangling, &dir.join("later"));
            assert!(o.open_files().is_err());
            let hard = dir.join("hard");
            std::fs::hard_link(&plain, &hard).unwrap();
            assert!(
                out(&hard, std::path::Path::new(&plain))
                    .open_files()
                    .is_err()
            );
            assert!(out(&dir.join("a"), &dir.join("b")).open_files().is_ok());
        }
        // Windows file systems ignore case: report and REPORT are one file.
        #[cfg(windows)]
        {
            let o = Outputs {
                normal: vec![dir.join("report").display().to_string()],
                xml: vec![dir.join("REPORT").display().to_string()],
                ..Default::default()
            };
            assert!(o.open_files().is_err());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ping_options() {
        let args = |v: &[&str]| Args::try_parse_from(v.iter().copied());
        let a = args(&[
            "feroprobe",
            "-PS22,443",
            "-PA",
            "-PU",
            "-PE",
            "-PP",
            "-PM",
            "x",
        ])
        .unwrap();
        assert_eq!(
            a.ping,
            vec![
                PingArg::Syn(vec![22, 443]),
                PingArg::Ack(vec![80]),
                PingArg::Udp(vec![40125]),
                PingArg::Echo,
                PingArg::Timestamp,
                PingArg::Mask,
            ]
        );
        let probes = ping_probes(&a.ping).unwrap().unwrap();
        assert_eq!(
            (probes.syn, probes.ack, probes.udp),
            (vec![22, 443], vec![80], vec![40125])
        );
        assert!(probes.echo && probes.timestamp && probes.mask);

        // Only -Pn, or nothing: the default probes.
        assert_eq!(ping_probes(&[]).unwrap(), None);
        assert_eq!(ping_probes(&[PingArg::Skip]).unwrap(), None);
        assert_eq!(
            args(&["feroprobe", "-P0", "x"]).unwrap().ping,
            vec![PingArg::Skip]
        );
        // Ports repeat across options without repeating probes.
        let p = ping_probes(&[PingArg::Syn(vec![22, 80]), PingArg::Syn(vec![80])])
            .unwrap()
            .unwrap();
        assert_eq!(p.syn, vec![22, 80]);
        assert!(!p.echo);

        assert!(ping_probes(&[PingArg::Skip, PingArg::Echo]).is_err());
        assert!(args(&["feroprobe", "-PE22", "x"]).is_err());
        assert!(args(&["feroprobe", "-PO", "x"]).is_err());
        assert!(args(&["feroprobe", "-PZ", "x"]).is_err());
        assert!(args(&["feroprobe", "-PS70000", "x"]).is_err());
    }

    #[test]
    fn name_resolution_options() {
        let a = Args::try_parse_from([
            "feroprobe",
            "-R",
            "--dns-servers",
            "192.0.2.53,[2001:db8::53]:5353",
            "--randomize-hosts",
            "x",
        ])
        .unwrap();
        assert!(a.always_resolve && !a.no_resolve && a.randomize_hosts);
        assert_eq!(
            a.dns_servers,
            vec![
                "192.0.2.53:53".parse::<SocketAddr>().unwrap(),
                "[2001:db8::53]:5353".parse().unwrap()
            ]
        );
        assert!(
            Args::try_parse_from(["feroprobe", "-n", "x"])
                .unwrap()
                .no_resolve
        );
        assert!(Args::try_parse_from(["feroprobe", "-n", "-R", "x"]).is_err());
        assert!(Args::try_parse_from(["feroprobe", "--dns-servers", "ns.example", "x"]).is_err());
    }

    fn args(argv: &[&str]) -> Args {
        let mut all = vec!["feroprobe"];
        all.extend_from_slice(argv);
        all.push("10.0.0.1");
        Args::try_parse_from(nmap_style_args(all.iter().map(|s| s.to_string()))).unwrap()
    }

    #[test]
    fn port_selection() {
        let lists = |argv: &[&str]| port_lists(&args(argv)).unwrap();
        let fast = lists(&["-F"]);
        assert_eq!((fast.tcp.len(), fast.udp.len()), (100, 100));
        assert_eq!(lists(&[]).udp.len(), 20);
        let l = lists(&["-p", "22,U:53,161,T:80"]);
        assert_eq!((l.tcp, l.udp), (vec![22, 80], vec![22, 53, 161]));
        let l = lists(&["-p", "20-25,U:50-55", "--exclude-ports", "21-23,U:53"]);
        assert_eq!(l.tcp, vec![20, 24, 25]);
        assert_eq!(l.udp, vec![20, 24, 25, 50, 51, 52, 54, 55]);
        let l = lists(&["--top-ports", "10", "--exclude-ports", "T:80"]);
        assert!(!l.tcp.contains(&80) && l.tcp.len() == 9, "{:?}", l.tcp);
        assert!(port_lists(&args(&["--exclude-ports", "S:1"])).is_err());
        // --exclude-ports also thins the discovery probes, like nmap.
        let ex = parse_port_lists("80,U:53").unwrap();
        let mut probes = PingProbes::default();
        assert!(exclude_ping_ports(&mut probes, &ex).is_empty());
        assert_eq!(probes.syn, vec![443]);
        assert!(probes.echo);
        let mut probes = PingProbes {
            ack: vec![80],
            udp: vec![53],
            ..PingProbes::none()
        };
        let w = exclude_ping_ports(&mut probes, &ex);
        assert_eq!(w.len(), 2);
        assert!(w[0].contains("TCP") && w[1].contains("UDP"));
        assert_eq!(protocol_warnings("77,U:44,T:33", true, false).len(), 1);
        assert!(protocol_warnings("77,u:44", true, false)[0].contains("-sU"));
        assert!(protocol_warnings("77,U:44,T:33", true, true).is_empty());
        assert!(protocol_warnings("T:33", false, true)[0].contains("TCP"));
        assert!(protocol_warnings("22,80", true, false).is_empty());
        for bad in [&["-F", "-p", "22"][..], &["-F", "--top-ports", "5"]] {
            let mut argv = vec!["feroprobe"];
            argv.extend_from_slice(bad);
            argv.push("10.0.0.1");
            assert!(Args::try_parse_from(argv).is_err(), "{bad:?}");
        }
        assert!(args(&["-r"]).ordered_ports);
        assert!(!args(&[]).ordered_ports);
    }

    #[test]
    fn min_rate_raises_the_limits() {
        let tuned = |argv: &[&str], files| {
            let a = args(argv);
            let mut cfg = scan_config(&a);
            apply_min_rate(&mut cfg, &a, files).map(|w| (cfg, w))
        };
        // 1000 probes/s with 1.5 s timeouts needs 1500 in flight.
        let (cfg, w) = tuned(&["--min-rate", "1000", "--timeout", "1500"], None).unwrap();
        assert_eq!(cfg.concurrency, 1500);
        assert_eq!(cfg.max_rate, 5000);
        assert!(w.is_empty());
        let (cfg, w) = tuned(&["--min-rate", "9000", "--timeout", "100"], Some(1024)).unwrap();
        assert_eq!((cfg.max_rate, cfg.concurrency), (9000, 900));
        assert!(w.is_empty());
        // The open-file limit caps the parallelism, with a warning.
        let (cfg, w) = tuned(&["--min-rate", "2000", "--timeout", "1000"], Some(1024)).unwrap();
        assert_eq!(cfg.concurrency, 960);
        assert_eq!(w.len(), 1, "{w:?}");
        // An explicit --concurrency is kept, with a warning.
        let (cfg, w) = tuned(&["--min-rate", "1000", "-c", "10"], None).unwrap();
        assert_eq!(cfg.concurrency, 10);
        assert_eq!(w.len(), 1);
        // A template's scan delay gives way; an explicit one is an error.
        let (cfg, _) = tuned(&["-T2", "--min-rate", "100"], None).unwrap();
        assert_eq!(cfg.scan_delay, Duration::from_millis(10));
        assert!(tuned(&["--scan-delay", "1s", "--min-rate", "10"], None).is_err());
        assert!(tuned(&["--max-rate", "10", "--min-rate", "20"], None).is_err());
        assert!(tuned(&["--min-rate", "0"], None).is_err());
        let (cfg, w) = tuned(&[], None).unwrap();
        assert_eq!(cfg.concurrency, ScanConfig::default().concurrency);
        assert!(w.is_empty());
    }

    #[test]
    fn stats_lines() {
        assert_eq!(clock(Duration::from_secs(3723)), "1:02:03");
        assert_eq!(clock(Duration::from_millis(59_900)), "0:00:59");
        set_phase("TCP SYN scan", 200);
        let line = stats_line(Duration::from_secs(5));
        assert!(
            line.starts_with("Stats: 0:00:05 elapsed; TCP SYN scan: "),
            "{line}"
        );
        assert!(line.ends_with(" of 200 probes)"), "{line}");
        set_phase("host discovery", 0);
        assert_eq!(
            stats_line(Duration::from_secs(1)),
            "Stats: 0:00:01 elapsed; host discovery"
        );
        assert!(args(&["--stats-every", "10s"]).stats_every == Some(Duration::from_secs(10)));
    }

    #[test]
    fn host_groups_keep_the_budgets() {
        let cfg = |concurrency, max_rate| ScanConfig {
            concurrency,
            max_rate,
            ..ScanConfig::default()
        };
        assert_eq!(host_group(100, &cfg(500, 5000)), HOST_GROUP);
        assert_eq!(host_group(5, &cfg(500, 5000)), 5);
        assert_eq!(host_group(100, &cfg(1, 5000)), 1);
        assert_eq!(host_group(100, &cfg(500, 1)), 1);
        assert_eq!(host_group(100, &cfg(10, 4)), 4);
        assert_eq!(host_group(0, &cfg(10, 4)), 1);
        // Each host's share times the group stays within the totals.
        for (c, r) in [(1, 1), (10, 4), (33, 100), (500, 5000)] {
            let g = host_group(100, &cfg(c, r));
            assert!((c / g).max(1) * g <= c, "{c} {r}");
            assert!((r as usize / g).max(1) * g <= r as usize, "{c} {r}");
        }
    }

    #[tokio::test]
    async fn host_timeout_drops_slow_hosts() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let open = listener.local_addr().unwrap().port();
        let plan = Plan {
            tcp: Some(ScanType::Connect),
            udp: false,
            version: false,
            ping_only: false,
            discovery: false,
        };
        let job = ScanJob {
            plan: &plan,
            tcp: &[open],
            udp: &[],
            scanflags: None,
            version_wait: Duration::from_secs(1),
            os: false,
        };
        let target = Target {
            addr: "127.0.0.1".parse().unwrap(),
            hostname: None,
        };
        let quiet = Progress {
            level: 0,
            track: false,
        };
        let fresh = || vec![HostResult::new(target.addr, None)];
        let cfg = ScanConfig::default();
        let mut hosts = fresh();
        job.run_each(
            std::slice::from_ref(&target),
            &mut hosts,
            &cfg,
            Duration::from_secs(30),
            quiet,
        )
        .await
        .unwrap();
        assert!(!hosts[0].timed_out);
        assert_eq!(hosts[0].ports.len(), 1);
        // Thousands of probes, a few at a time, cannot finish in 1 ms.
        let many: Vec<u16> = (1..=5000).collect();
        let slow = ScanJob { tcp: &many, ..job };
        let cfg = ScanConfig {
            concurrency: 4,
            ..ScanConfig::default()
        };
        let mut hosts = fresh();
        hosts[0].ports.push(feroprobe_core::PortResult {
            port: 1,
            protocol: feroprobe_core::Protocol::Tcp,
            state: feroprobe_core::PortState::Open,
            reason: "stale",
            rtt_ms: None,
            service: None,
        });
        slow.run_each(
            std::slice::from_ref(&target),
            &mut hosts,
            &cfg,
            Duration::from_millis(1),
            quiet,
        )
        .await
        .unwrap();
        assert!(hosts[0].timed_out);
        assert!(hosts[0].ports.is_empty());
        drop(listener);
    }

    #[test]
    fn shuffle_keeps_every_item() {
        let mut v: Vec<u32> = (0..1000).collect();
        shuffle(&mut v);
        assert_ne!(v, (0..1000).collect::<Vec<_>>(), "1000 items left in order");
        v.sort();
        assert_eq!(v, (0..1000).collect::<Vec<_>>());
        let mut one = [7];
        shuffle(&mut one);
        shuffle::<u8>(&mut []);
    }

    #[test]
    fn host_list_files() {
        assert_eq!(
            parse_host_list("10.0.0.1 10.0.0.2\n# comment\n\nexample.org # web\n  10.1.0.0/24\n"),
            ["10.0.0.1", "10.0.0.2", "example.org", "10.1.0.0/24"]
        );
    }
}
