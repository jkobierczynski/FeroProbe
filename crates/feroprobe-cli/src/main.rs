//! `feroprobe`: an nmap-style network scanner, written natively in Rust.

mod config;
mod debugging;
mod explain;
mod grep;
mod groups;
mod help;
mod keys;
mod output;
mod privdrop;
mod report;
mod resume;
mod xml;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result, bail};
use clap::{Parser, ValueEnum};
use feroprobe_core::discovery::{
    DEFAULT_PROTO_PINGS, DEFAULT_SCTP_PING_PORT, DEFAULT_TCP_PING_PORT, DEFAULT_UDP_PING_PORT,
};
use feroprobe_core::timing::parse_duration;
use feroprobe_core::{
    Evasion, Exclusions, Fragment, HostResult, IpVersion, OsOptions, PingProbes, PortLists,
    RawTcpScan, RttTimeouts, ScanConfig, SctpScanKind, Target, TcpScanKind, Timing, VersionScan,
    connect_scan, detect_services, discover, ip_protocol_scan, os_detect, parse_port_lists,
    parse_ports, parse_protocols, parse_scanflags, raw_ipv6_available, raw_sockets_available,
    raw_tcp_scan, resolve_targets_lenient, reverse_lookup, sctp_scan, top_ports, top_sctp_ports,
    top_udp_ports, traceroute, udp_scan,
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
    /// -sY: SCTP INIT scan (raw sockets)
    #[value(name = "Y")]
    SctpInit,
    /// -sZ: SCTP COOKIE ECHO scan (raw sockets)
    #[value(name = "Z")]
    SctpCookie,
    /// -sO: IP protocol scan (raw sockets)
    #[value(name = "O")]
    IpProto,
    /// -sU: UDP scan
    #[value(name = "U")]
    Udp,
    /// -sn: host discovery only, no port scan
    #[value(name = "n")]
    PingOnly,
    /// -sL: list the targets (with reverse DNS), send them nothing
    #[value(name = "L")]
    List,
    /// -sV: detect service and version on open ports
    #[value(name = "V")]
    Version,
    /// -sC: run the default scripts, the same as --script=default
    #[value(name = "C")]
    Scripts,
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
            ScanType::SctpInit => "-sY",
            ScanType::SctpCookie => "-sZ",
            ScanType::IpProto => "-sO",
            ScanType::Udp => "-sU",
            ScanType::PingOnly => "-sn",
            ScanType::List => "-sL",
            ScanType::Version => "-sV",
            ScanType::Scripts => "-sC",
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
    Sctp(Vec<u16>),
    Proto(Vec<u8>),
    /// `-PR`: deprecated in nmap and a no-op there, since ARP (and
    /// neighbour discovery) always runs where it can.
    Arp,
}

/// Parse what follows `-P`: `n`, `E`, `P`, `M`, `R`, or `S`, `A`, `U`, `Y`
/// with an optional port list run on, as nmap writes them (`-PS22,443`),
/// or `O` with an optional IP protocol list (`-PO1,2,4`).
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
        'Y' => Ok(PingArg::Sctp(ports(DEFAULT_SCTP_PING_PORT)?)),
        'O' if rest.is_empty() => Ok(PingArg::Proto(DEFAULT_PROTO_PINGS.to_vec())),
        'O' => {
            let protos = parse_protocols(rest).map_err(|e| e.to_string())?;
            // parse_protocols keeps to 0-255.
            Ok(PingArg::Proto(
                protos.into_iter().map(|p| p as u8).collect(),
            ))
        }
        'R' => alone(PingArg::Arp),
        _ => Err(format!(
            "unknown ping type -P{s}; use -Pn, -PS, -PA, -PU, -PY, -PO, -PE, -PP, -PM or -PR"
        )),
    }
}

/// The discovery probes the `-P` options ask for: `None` for the default
/// set, and an error if `-Pn` comes with probe types.
fn ping_probes(args: &[PingArg]) -> Result<Option<PingProbes>> {
    let skip = args.contains(&PingArg::Skip);
    // -PR picks no probe (see PingArg::Arp).
    let chosen: Vec<&PingArg> = args
        .iter()
        .filter(|a| !matches!(a, PingArg::Skip | PingArg::Arp))
        .collect();
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
            PingArg::Sctp(p) => probes.sctp.extend(p),
            PingArg::Proto(p) => probes.proto.extend(p),
            PingArg::Skip | PingArg::Arp => {}
        }
    }
    for ports in [
        &mut probes.syn,
        &mut probes.ack,
        &mut probes.udp,
        &mut probes.sctp,
    ] {
        let mut seen = std::collections::HashSet::new();
        ports.retain(|p| seen.insert(*p));
    }
    let mut seen = std::collections::HashSet::new();
    probes.proto.retain(|p| seen.insert(*p));
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

/// Fast, native network scanner with an nmap-style command line. The help
/// page is [`help::HELP`], laid out like nmap's.
#[derive(Debug, Parser)]
#[command(version, override_help = help::HELP, arg_required_else_help = true)]
struct Args {
    /// Targets: IPv4 or IPv6 addresses, CIDR blocks (10.0.0.0/24, 2001:db8::/120),
    /// ranges (10.0.0.1-20), link-local addresses with their interface
    /// (fe80::1%eth0) or hostnames
    #[arg(required_unless_present_any = ["input_file", "iflist", "resume", "script_help"])]
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

    /// -6: use the IPv6 address of each hostname target (otherwise its IPv4
    /// address, like nmap). Address targets are scanned as given
    #[arg(short = '6')]
    ipv6: bool,

    /// Scan technique, nmap style: -sS (SYN), -sT (connect), -sU (UDP), -sn (no port scan),
    /// -sL (list the targets and send them nothing),
    /// -sV (also detect service versions on open ports), -sC (also run the
    /// default scripts, as --script=default), and the raw TCP scans
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

    /// Evasion: fragment raw IPv4 probe packets into 8-byte pieces (nmap's
    /// -f). For testing your own firewall or IDS. Refused against public
    /// targets unless --allow-public-evasion is given. Needs a raw TCP scan
    /// (-sS/-sF/-sN/-sX/-sA/-sW/-sM). Conflicts with --mtu
    #[arg(short = 'f', conflicts_with = "mtu")]
    fragment: bool,

    /// Evasion: fragment raw IPv4 probe packets to this payload size per
    /// fragment, a positive multiple of 8 (nmap's --mtu). Public targets need
    /// --allow-public-evasion, like -f
    #[arg(long, value_name = "N")]
    mtu: Option<u16>,

    /// Evasion: decoy source addresses, comma-separated, so the target sees
    /// probes from these alongside the real scan (nmap's -D). The token ME
    /// marks where the real probe sits; it is added at the end if omitted.
    /// Public targets need --allow-public-evasion
    #[arg(short = 'D', long = "decoys", value_name = "a,b,ME,c")]
    decoys: Option<String>,

    /// Evasion: send raw IPv4 probes from this forged source address (nmap's
    /// -S). Replies go to it, not to you, so the scan is blind unless
    /// FeroProbe is on the path back. Public targets need
    /// --allow-public-evasion
    #[arg(short = 'S', long = "source", value_name = "ADDR")]
    spoof_source: Option<String>,

    /// Evasion: authorize the evasion options (-f/--mtu, -D, -S) against
    /// public addresses. Without it, FeroProbe refuses them for any public
    /// target, decoy or spoofed source, as an anti-abuse safeguard. Pass it
    /// only for targets you have permission to test. Private ranges never
    /// need it
    #[arg(long = "allow-public-evasion")]
    allow_public_evasion: bool,

    /// -b [user[:pass]@]server[:port]: FTP bounce scan: ask this FTP
    /// server to connect to each target port (default login anonymous,
    /// port 21). IPv4 only. Private targets and relay, or
    /// --allow-public-evasion
    #[arg(short = 'b', value_name = "FTP_RELAY")]
    bounce: Option<String>,

    /// Evasion: send IPv4 probes and ARP requests in Ethernet frames from
    /// this MAC address: a whole address, its first bytes (the rest random),
    /// a vendor name, or 0 for a random one (nmap's --spoof-mac). Linux,
    /// raw sockets. Public targets need --allow-public-evasion
    #[arg(long = "spoof-mac", value_name = "MAC")]
    spoof_mac: Option<String>,

    /// --data HEX: add these bytes to raw probes (0xAABB, \xAA\xBB or
    /// AABB). They replace the UDP scan's and ICMP echo's usual payloads
    #[arg(long = "data", value_name = "HEX", value_parser = parse_data_hex,
          conflicts_with_all = ["data_string", "data_length"])]
    data: Option<Bytes>,

    /// --data-string TEXT: add this text to raw probes, like --data
    #[arg(
        long = "data-string",
        value_name = "TEXT",
        conflicts_with = "data_length"
    )]
    data_string: Option<String>,

    /// --data-length N: add N random bytes to raw probes, like --data
    #[arg(long = "data-length", value_name = "N", value_parser = parse_data_length)]
    data_length: Option<usize>,

    /// --ttl N: send probes with this IP time-to-live (IPv6 hop limit),
    /// 0-255, instead of a random one from 37 to 59
    #[arg(long, value_name = "N")]
    ttl: Option<u8>,

    /// --ip-options OPTS: IPv4 header options: R (record route), T or U
    /// (timestamps), L or S followed by hop addresses (loose or strict
    /// source route), or bytes like \x01\x07 (IPv4 only)
    #[arg(long = "ip-options", value_name = "OPTS", value_parser = parse_ip_options_arg)]
    ip_options: Option<Bytes>,

    /// --badsum: send TCP, UDP, SCTP and ICMP probes with a wrong checksum
    /// (needs raw sockets)
    #[arg(long)]
    badsum: bool,

    /// --privileged: assume raw sockets work (for CAP_NET_RAW set up in a
    /// way FeroProbe cannot detect)
    #[arg(long, overrides_with = "unprivileged")]
    privileged: bool,

    /// --unprivileged: act as an ordinary user: no raw sockets, so a connect
    /// scan and connect pings by default
    #[arg(long, overrides_with = "privileged")]
    unprivileged: bool,

    /// --keep-root: under sudo, stay root for the whole run instead of
    /// becoming the invoking user once the settings are read (needed only
    /// to read or write files that only root can reach)
    #[arg(long = "keep-root")]
    keep_root: bool,

    /// --system-dns: resolve names with the system resolver (FeroProbe's
    /// default already; it also overrides --dns-servers)
    #[arg(long)]
    system_dns: bool,

    /// --defeat-rst-ratelimit: in a SYN scan, don't slow down for hosts
    /// that rate-limit their RSTs; some closed ports may show as filtered
    #[arg(long)]
    defeat_rst_ratelimit: bool,

    /// -e IFACE: send and receive on this network interface (nmap's -e):
    /// every socket of the scan is bound to it, its address is the source,
    /// and only its networks count as local for ARP and neighbour discovery
    #[arg(short = 'e', value_name = "IFACE")]
    interface: Option<String>,

    /// -g PORT: send raw TCP, UDP and SCTP probes (port scan, discovery
    /// pings, OS detection) and UDP scan probes from this source port, like
    /// nmap's -g. Connect scans, version detection, traceroute and DNS keep
    /// their own ports
    #[arg(short = 'g', long = "source-port", value_name = "PORT")]
    source_port: Option<u16>,

    /// Host discovery, nmap style. -Pn: skip it and scan every target as if
    /// it were up. Otherwise pick the probes (default as nmap's: as root,
    /// ICMP echo and timestamp, a TCP SYN to 443 and an ACK to 80; else TCP
    /// connects to 80 and 443): -PS[ports] TCP SYN (default 80),
    /// -PA[ports] TCP ACK (default 80; both raw on Linux, else a connect),
    /// -PU[ports] UDP (default 40125), -PY[ports] SCTP INIT (default 80),
    /// -PO[protocols] IP protocol ping (default 1,2,4: ICMP, IGMP,
    /// IP-in-IP), -PE ICMP echo, -PP ICMP timestamp, -PM ICMP address mask
    /// (-PY, -PO, -PP and -PM need raw sockets; the last two IPv4 only).
    /// -PR (ARP) changes nothing, as in nmap: local targets always get ARP
    /// or neighbour discovery. Ports run on without a space: -PS22,443. Can
    /// be repeated
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

    /// Limit OS detection to hosts with at least one open and one closed TCP port
    #[arg(long)]
    osscan_limit: bool,

    /// Report near OS matches too ("aggressive guesses"); --fuzzy is the same
    #[arg(long, alias = "fuzzy")]
    osscan_guess: bool,

    /// OS detection tries for a host without a perfect match (default 5)
    #[arg(long, value_name = "tries", value_parser = clap::value_parser!(u32).range(1..))]
    max_os_tries: Option<u32>,

    /// Trace the route to each host that is up, after the port scan
    /// (raw sockets: Linux, root or CAP_NET_RAW)
    #[arg(long)]
    traceroute: bool,

    /// -A: aggressive detection, the same as -sV -O -sC --traceroute.
    /// Without raw-socket privileges only -sV and -sC run, with a warning
    #[arg(short = 'A')]
    aggressive: bool,

    /// Run this once despite `ics_protection = true` in a settings file,
    /// allowing -sV, -O, -A, -sC and --script. Prints a warning naming what it allowed.
    /// The settings file is not changed
    #[arg(long = "override-ics-protection")]
    override_ics_protection: bool,

    /// Run these Lua scripts after the scan: a comma-separated list of
    /// script names (with * wildcards), categories, script files,
    /// directories (ending in /) and expressions such as "safe and not
    /// intrusive". A + before one runs it whatever its rules say. Given
    /// more than once, the lists add up
    #[arg(long, value_name = "SCRIPTS")]
    script: Vec<String>,

    /// Arguments for the scripts: name=value pairs, bare flags and {...}
    /// tables, comma-separated, as in nmap
    #[arg(long = "script-args", value_name = "ARGS")]
    script_args: Option<String>,

    /// Read script arguments from FILE (same syntax; newlines separate them
    /// too). --script-args are added after them
    #[arg(long = "script-args-file", value_name = "FILE")]
    script_args_file: Option<String>,

    /// Show the name, categories and description of these scripts (chosen
    /// as with --script), then stop. Needs no target
    #[arg(long = "script-help", value_name = "SCRIPTS")]
    script_help: Vec<String>,

    /// Stop a script that runs longer than this against one host or port,
    /// e.g. 30s or 5m [default: none; 10m with -T5, as in nmap]
    #[arg(long = "script-timeout", value_name = "TIME", value_parser = parse_duration)]
    script_timeout: Option<Duration>,

    /// Ports to scan, e.g. "22", "1-1024", "22,80,443", "-" for all.
    /// T: and U: mark TCP and UDP ports: "22,U:53,T:80" (unmarked ports
    /// are both)
    #[arg(short = 'p', long, conflicts_with = "top_ports")]
    ports: Option<String>,

    /// Scan the N most common ports (default 1000 for TCP and UDP, as in
    /// nmap, and 50 for SCTP)
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
    /// insane (-T4 = aggressive). Sets the RTT timeouts, retries,
    /// concurrency, rate and scan delay; those flags still override it.
    /// [default: 3, normal]
    /// Given more than once, the last one wins, as in nmap.
    #[arg(short = 'T', value_name = "0-5", value_parser = parse_timing, overrides_with = "timing")]
    timing: Option<Timing>,

    /// A fixed per-probe timeout in milliseconds: sets the minimum, maximum
    /// and initial RTT timeouts all to this, so the timeout no longer adapts
    /// [default: adaptive, see --min-rtt-timeout]
    #[arg(long, value_name = "MS")]
    timeout: Option<u64>,

    /// The shortest a probe's adaptive timeout may get, e.g. 100ms
    /// (a bare number is seconds) [default: from -T; normally 100ms]
    #[arg(long, value_name = "TIME", value_parser = parse_min_rtt)]
    min_rtt_timeout: Option<Duration>,

    /// The longest a probe's adaptive timeout may get, e.g. 2s
    /// [default: from -T; normally 10s]
    #[arg(long, value_name = "TIME", value_parser = parse_max_rtt)]
    max_rtt_timeout: Option<Duration>,

    /// How long a probe waits before any round-trip time is measured,
    /// e.g. 500ms [default: from -T; normally 1s]
    #[arg(long, value_name = "TIME", value_parser = parse_initial_rtt)]
    initial_rtt_timeout: Option<Duration>,

    /// Most probes waiting for an answer at once, and the ceiling of the
    /// congestion window [default: from -T; normally 500].
    /// nmap's names --max-parallelism and -M work too
    #[arg(
        short = 'c',
        long,
        value_name = "N",
        short_alias = 'M',
        visible_alias = "max-parallelism",
        value_parser = parse_parallelism
    )]
    concurrency: Option<usize>,

    /// At least this many connect/UDP probes in flight at once: raises the
    /// template's parallelism (nmap's --min-parallelism)
    #[arg(long, value_name = "N", value_parser = parse_parallelism)]
    min_parallelism: Option<usize>,

    /// Port-scan and report at least this many hosts at a time (nmap's
    /// --min-hostgroup; default 1)
    #[arg(long, value_name = "N")]
    min_hostgroup: Option<usize>,

    /// Port-scan and report at most this many hosts at a time (nmap's
    /// --max-hostgroup; default 100000)
    #[arg(long, value_name = "N")]
    max_hostgroup: Option<usize>,

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

    /// The longest delay between probes the scan may set on its own for a
    /// host that loses many probes, e.g. 100ms [default: from -T; normally 1s]
    #[arg(long, value_name = "TIME", value_parser = parse_max_scan_delay)]
    max_scan_delay: Option<Duration>,

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

    /// With -sV, how hard to try, 0-9 [default: 7]: probes rarer than this
    /// are only sent to their own ports. The last of --version-intensity,
    /// --version-light and --version-all wins, as in nmap
    #[arg(
        long,
        value_name = "0-9",
        value_parser = clap::value_parser!(u8).range(0..=9),
        overrides_with_all = ["version_intensity", "version_light", "version_all"]
    )]
    version_intensity: Option<u8>,

    /// With -sV, only the most likely probes (intensity 2)
    #[arg(long, overrides_with_all = ["version_intensity", "version_light", "version_all"])]
    version_light: bool,

    /// With -sV, try every probe (intensity 9)
    #[arg(long, overrides_with_all = ["version_intensity", "version_light", "version_all"])]
    version_all: bool,

    /// With -sV, print each service probe, its reply and the rule that
    /// matched it
    #[arg(long)]
    version_trace: bool,

    /// With -sV, read the probes and match rules from FILE instead of the
    /// built-in ones (FeroProbe's own format; see the manual)
    #[arg(long, value_name = "FILE")]
    service_rules: Option<std::path::PathBuf>,

    /// Extra attempts for probes that get no answer [default: from -T; normally 1].
    /// nmap's name --max-retries works too
    #[arg(long, value_name = "N", visible_alias = "max-retries")]
    retries: Option<u32>,

    /// Only show open (and open|filtered, unfiltered) ports
    #[arg(long)]
    open: bool,

    /// Before scanning, print the plan made from the command line, step by
    /// step, with the reason for each choice (to standard error)
    #[arg(long)]
    explain: bool,

    /// Print every probe sent and every answer received (SENT/RCVD/CONN
    /// lines on standard output), like nmap's --packet-trace
    #[arg(long)]
    packet_trace: bool,

    /// Send nothing: print every probe the scan would send (host discovery
    /// and port scan, with -f/--mtu, -D and -S applied) as NOT SENT lines in
    /// the --packet-trace layout, then stop. No replies, so no port states,
    /// and no root needed. Hostnames are still resolved
    #[arg(long = "dry-run")]
    dry_run: bool,

    /// Carry on with an aborted scan from its -oN, -oG or -oX report: the
    /// command line is read from the file, the hosts it finished are
    /// skipped and the reports are appended to (only files that already
    /// hold that scan's report). Takes no other options except --keep-root,
    /// --allow-public-evasion and --override-ics-protection
    #[arg(long, value_name = "FILE")]
    resume: Option<String>,

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

    /// -oS FILE: also write the normal report in "script kiddie" spelling
    /// to FILE ("-" for stdout), as nmap's -oS does
    #[arg(long = "output-skid", value_name = "FILE")]
    out_skid: Option<String>,

    /// Append to the report files instead of overwriting them
    #[arg(long)]
    append_output: bool,

    /// Reference this XSL stylesheet (a path or URL) from the XML report
    #[arg(long, value_name = "PATH/URL", overrides_with_all = ["stylesheet", "webxml", "no_stylesheet"])]
    stylesheet: Option<String>,

    /// Reference the published copy of FeroProbe's stylesheet from the XML
    /// report, for viewing it on machines without FeroProbe installed
    #[arg(long, overrides_with_all = ["stylesheet", "webxml", "no_stylesheet"])]
    webxml: bool,

    /// Leave the stylesheet reference out of the XML report
    #[arg(long, overrides_with_all = ["stylesheet", "webxml", "no_stylesheet"])]
    no_stylesheet: bool,

    /// -v: report progress on standard error (each phase with its time,
    /// and the open ports each scan found when it finishes); -vv for more
    #[arg(short = 'v', action = clap::ArgAction::Count)]
    verbose: u8,

    /// -d: raise the debugging level (and the verbosity) by one; -dd by
    /// two, and so on; -d<level> sets both to <level> (0 to 10). Also turns
    /// on --reason, as in nmap
    #[arg(
        long = "debug",
        value_name = "LEVEL",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "",
        action = clap::ArgAction::Append
    )]
    debug: Vec<String>,

    /// Print the host's interfaces and routes, then stop
    #[arg(long)]
    iflist: bool,

    /// Do not read keys from the terminal while the scan runs (v/V, d/D,
    /// p/P, ? and any other key for a status line)
    #[arg(long)]
    noninteractive: bool,
}

/// nmap's two-letter options (`-iL`, `-oN`, `-oX`, `-oG`, `-oA`) clash with
/// clap's short flags, so they are renamed to their long forms before
/// parsing. Only whole arguments before `--` are touched.
/// The letters of the `-s` scan types, for combined ones such as `-sCV`.
const SCAN_LETTERS: &str = "STFNXAWMYZOUnLVC";

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
            "-oS" => Some("--output-skid"),
            // -d, -dd, -d3: nmap's debug option takes its argument only
            // when attached, so `-d host` keeps `host` as a target.
            "-d" => Some("--debug"),
            d if d.starts_with("-d") => {
                out.push(format!("--debug={}", &d[2..]));
                continue;
            }
            // nmap reads -sCV, -sSU and the like as one -s per letter.
            s if s.len() > 3
                && s.starts_with("-s")
                && s[2..].chars().all(|c| SCAN_LETTERS.contains(c)) =>
            {
                out.extend(s[2..].chars().map(|c| format!("-s{c}")));
                continue;
            }
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
    /// `-oS`: the normal report in "script kiddie" spelling.
    skid: Vec<String>,
    /// `--append-output`: add to the files instead of replacing them.
    append: bool,
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
        push(&mut o.skid, &args.out_skid);
        o.append = args.append_output;
        if let Some(base) = &args.out_all {
            if base == "-" {
                bail!("-oA needs a file name base, not -");
            }
            o.normal.push(format!("{base}.nmap"));
            o.xml.push(format!("{base}.xml"));
            o.grep.push(format!("{base}.gnmap"));
        }
        let to_stdout = [&o.normal, &o.xml, &o.grep, &o.json, &o.skid]
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
        self.files_by_kind().map(|(_, p)| p)
    }

    /// The report files, each with the kind of report `--resume` checks it
    /// holds.
    fn files_by_kind(&self) -> impl Iterator<Item = (resume::FileKind, &String)> {
        use resume::FileKind::{Json, Recorded, Skid};
        [
            (Recorded, &self.normal),
            (Recorded, &self.xml),
            (Recorded, &self.grep),
            (Json, &self.json),
            (Skid, &self.skid),
        ]
        .into_iter()
        .flat_map(|(k, v)| v.iter().map(move |p| (k, p)))
        .filter(|(_, p)| *p != "-")
    }

    /// Open (creating, not truncating) every report file before the scan,
    /// as nmap does. This catches unwritable paths up front, and then
    /// compares the files themselves, so that aliases a path can't show
    /// (a link whose target doesn't exist yet, a hard link, or another
    /// spelling on a case-insensitive file system) can't make two reports
    /// share one file. On Unix the file's device and inode decide; on other
    /// systems the canonical path of the now existing file, which on Windows
    /// comes back in the case stored on disk.
    ///
    /// The handles are kept and the reports are written through them, so
    /// the path is never looked up a second time: what was checked here is
    /// what gets written, even if someone swaps the path for a link while
    /// the scan runs. With `--append-output` the files are opened for
    /// appending (nmap's `fopen(..., "a")`); otherwise each file is emptied
    /// only when its report is written, so a scan that fails leaves the old
    /// report in place.
    ///
    /// A resumed scan (`resumed` holds the command line its report records)
    /// only appends to files that already hold that scan's report: see
    /// [`resume::continues_scan`]. They are opened without being created,
    /// and checked through the handle the report is then written to.
    fn open_files(&self, resumed: Option<&[String]>) -> Result<ReportFiles> {
        let mut seen = std::collections::HashSet::new();
        let mut files = ReportFiles {
            append: self.append,
            ..Default::default()
        };
        for (kind, path) in self.files_by_kind() {
            let mode = if resumed.is_some() {
                OpenMode::Resume
            } else {
                OpenMode::Create {
                    append: self.append,
                }
            };
            let file = open_report(path, mode)?;
            if let Some(args) = resumed {
                check_resumed_file(&file, path, kind, args)?;
            }
            #[cfg(unix)]
            let id = {
                use std::os::unix::fs::MetadataExt;
                let m = file.metadata().with_context(|| format!("reading {path}"))?;
                (m.dev(), m.ino())
            };
            #[cfg(not(unix))]
            let id = std::fs::canonicalize(path).with_context(|| format!("resolving {path}"))?;
            if !seen.insert(id) {
                bail!("two reports would be written to {path}; give each its own file");
            }
            files.handles.insert(path.clone(), file);
        }
        Ok(files)
    }

    /// Whether some -o option took over standard output.
    fn stdout_taken(&self) -> bool {
        [&self.normal, &self.xml, &self.grep, &self.json, &self.skid]
            .iter()
            .any(|v| v.iter().any(|p| p == "-"))
    }
}

/// The report files [`Outputs::open_files`] opened, by path.
#[derive(Default)]
struct ReportFiles {
    handles: std::collections::HashMap<String, std::fs::File>,
    append: bool,
    /// The files written to so far.
    written: std::collections::HashSet<String>,
}

impl ReportFiles {
    /// Write the next part of the report to `path`. The first part replaces
    /// what the file held, or with `--append-output` is added to it; later
    /// parts (the report is written a host group at a time) follow it.
    fn write(&mut self, path: &str, text: &str) -> Result<()> {
        use std::io::{Seek, Write};
        let file = self
            .handles
            .get_mut(path)
            .with_context(|| format!("{path} was not opened"))?;
        // Only a regular file can be emptied: /dev/null, a named pipe or a
        // terminal is written to as it is.
        let regular = file.metadata().is_ok_and(|m| m.is_file());
        if !self.append && regular && self.written.insert(path.to_string()) {
            file.set_len(0)
                .with_context(|| format!("emptying {path}"))?;
            file.rewind().with_context(|| format!("writing {path}"))?;
        }
        file.write_all(text.as_bytes())
            .and_then(|()| file.flush())
            .with_context(|| format!("writing {path}"))
    }
}

/// How [`open_report`] opens a report file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpenMode {
    /// Create it if needed, never truncate; append with `--append-output`.
    Create { append: bool },
    /// `--resume`: the file must exist; open it to read and append.
    Resume,
}

/// The paths of the system's own non-file outputs that a resumed command
/// line may name as a report: there is nothing in them to check.
const RESUME_DEVICES: [&str; 3] = ["/dev/null", "/dev/stdout", "/dev/stderr"];

/// `--resume`: refuse to append to `file` (opened from `path`) unless it
/// already holds the report of the scan being resumed. The recorded
/// command line could have been written by anyone, and its report paths
/// could otherwise name any file the user (or root) can write.
fn check_resumed_file(
    file: &std::fs::File,
    path: &str,
    kind: resume::FileKind,
    args: &[String],
) -> Result<()> {
    let refuse = |why: &str| -> Result<()> {
        bail!(
            "the scan being resumed names {path} as a report file, but {why}. \
             --resume only appends to the existing reports of the scan it resumes; \
             run the scan again instead"
        )
    };
    // Where the standard streams go is the person's own choice (a
    // redirection to a new, empty file included).
    if RESUME_DEVICES.contains(&path) {
        return Ok(());
    }
    let meta = file.metadata().with_context(|| format!("reading {path}"))?;
    if !meta.is_file() {
        return refuse("it is not a regular file");
    }
    // The whole file: with --append-output it may hold earlier scans first.
    let mut text = Vec::with_capacity(meta.len() as usize);
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let at = text.len() as u64;
        #[cfg(unix)]
        let n = {
            use std::os::unix::fs::FileExt;
            file.read_at(&mut buf, at)
        };
        #[cfg(windows)]
        let n = {
            use std::os::windows::fs::FileExt;
            file.seek_read(&mut buf, at)
        };
        match n.with_context(|| format!("reading {path}"))? {
            0 => break,
            n => text.extend_from_slice(&buf[..n]),
        }
    }
    if !resume::continues_scan(kind, &String::from_utf8_lossy(&text), args) {
        return refuse("it does not hold that scan's report");
    }
    Ok(())
}

/// Open (creating, not truncating) one report file.
///
/// As root (`--keep-root`, root without sudo, or a failed hand-over), see
/// [`open_report_as_root`]. Without root nothing changes: a report goes
/// wherever the path leads.
fn open_report(path: &str, mode: OpenMode) -> Result<std::fs::File> {
    let missing = |e: anyhow::Error| -> anyhow::Error {
        let not_found = e
            .root_cause()
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound);
        if mode == OpenMode::Resume && not_found {
            anyhow::anyhow!(
                "the scan being resumed names {path} as a report file, but it does not exist. \
                 --resume only appends to the existing reports of the scan it resumes; \
                 run the scan again instead"
            )
        } else {
            e
        }
    };
    #[cfg(unix)]
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        return open_report_as_root(path, mode).map_err(missing);
    }
    let resume = mode == OpenMode::Resume;
    std::fs::OpenOptions::new()
        .read(resume)
        .write(true)
        .append(resume || mode == OpenMode::Create { append: true })
        .truncate(false)
        .create(!resume)
        .open(path)
        .with_context(|| format!("opening {path}"))
        .map_err(missing)
}

/// [`open_report`] as root. The path is walked one component at a time
/// with `openat` and `O_NOFOLLOW`, so no symbolic link anywhere in it is
/// followed, in a directory or as the file itself, unless root owns both
/// the link and the directory holding it and no one else can write to that
/// directory (as with `/dev/stdout`). An approved link's target is walked
/// the same way, so a link it leads through is checked too; only the
/// kernel's own links in `/proc` are left to the kernel. Someone else's link, or any link in a
/// shared directory such as `/tmp`, could otherwise aim root's write at a
/// system file; and since each step opens what it checked, a link swapped
/// in meanwhile is refused too. A file root creates under `sudo` is handed
/// to the invoking user (`SUDO_UID`/`SUDO_GID`), so the report is theirs.
#[cfg(unix)]
fn open_report_as_root(path: &str, mode: OpenMode) -> Result<std::fs::File> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Component;

    let open_at = |dir: libc::c_int, name: &CString, flags: libc::c_int| {
        // SAFETY: name is a valid C string; the descriptor is checked.
        let fd = unsafe { libc::openat(dir, name.as_ptr(), flags | libc::O_CLOEXEC, 0o666) };
        if fd < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            // SAFETY: a new descriptor that nothing else owns.
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        }
    };
    // lstat of `name` in `dir`.
    let stat_at = |dir: &OwnedFd, name: &CString| {
        // SAFETY: stat is plain data that fstatat fills in.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: valid descriptor, C string and stat buffer.
        let rc = unsafe {
            libc::fstatat(
                dir.as_raw_fd(),
                name.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        (rc == 0).then_some(st)
    };
    let is_link = |st: &libc::stat| st.st_mode & libc::S_IFMT == libc::S_IFLNK;
    // Whether `dir` is on the /proc file system (Linux only).
    let on_procfs = |dir: &OwnedFd| {
        #[cfg(target_os = "linux")]
        {
            // SAFETY: statfs is plain data that fstatfs fills in.
            let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
            // SAFETY: valid descriptor and buffer.
            let ok = unsafe { libc::fstatfs(dir.as_raw_fd(), &mut fs) } == 0;
            // f_type's integer type differs between architectures.
            #[allow(clippy::unnecessary_cast)]
            let proc = fs.f_type as i64 == libc::PROC_SUPER_MAGIC as i64;
            ok && proc
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = dir;
            false
        }
    };
    // A link may be followed only if root owns it and its directory, and no
    // one else can write to that directory.
    let check_link = |dir: &OwnedFd, link: &libc::stat, shown: &str| -> Result<()> {
        // SAFETY: stat is plain data that fstat fills in.
        let mut d: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: valid descriptor and stat buffer.
        let dir_ok = unsafe { libc::fstat(dir.as_raw_fd(), &mut d) } == 0
            && d.st_uid == 0
            && d.st_mode & 0o022 == 0;
        if link.st_uid != 0 || !dir_ok {
            bail!(
                "{shown} is a symbolic link {}; running as root, FeroProbe does not write a \
                 report through it. Give the real path",
                if link.st_uid != 0 {
                    "owned by another user"
                } else {
                    "in a directory other users can write to"
                }
            );
        }
        Ok(())
    };
    let cstr = |b: &[u8]| CString::new(b).with_context(|| format!("{path} contains a NUL byte"));
    // Push a path's components onto the front of the queue.
    let push_front = |queue: &mut std::collections::VecDeque<Vec<u8>>, p: &std::path::Path| {
        for part in p.components().rev() {
            match part {
                Component::Normal(n) => queue.push_front(n.as_bytes().to_vec()),
                Component::ParentDir => queue.push_front(b"..".to_vec()),
                _ => {}
            }
        }
    };

    let p = std::path::Path::new(path);
    // A trailing "/" or "/." asks for a directory; components() would drop it.
    if path.ends_with('/') || path.ends_with("/.") {
        bail!("{path} does not name a file");
    }
    if !matches!(p.components().next_back(), Some(Component::Normal(_))) {
        bail!("{path} does not name a file");
    }
    let dir_flags = libc::O_RDONLY | libc::O_DIRECTORY;
    let root = cstr(b"/")?;
    let start = if p.has_root() {
        root.clone()
    } else {
        cstr(b".")?
    };
    let mut dir =
        open_at(libc::AT_FDCWD, &start, dir_flags).with_context(|| format!("opening {path}"))?;
    let mut queue = std::collections::VecDeque::new();
    push_front(&mut queue, p);
    // Walk the queue; an approved link's target is put back on it, so the
    // links it leads through are checked too.
    let mut links = 0;
    let (name, follow) = loop {
        let Some(part) = queue.pop_front() else {
            bail!("{path} does not name a file");
        };
        let name = cstr(&part)?;
        let last = queue.is_empty();
        let shown = String::from_utf8_lossy(&part).into_owned();
        if let Some(st) = stat_at(&dir, &name).filter(&is_link) {
            check_link(&dir, &st, &format!("{path} (at {shown})"))?;
            // Links in /proc (/dev/stdout leads to /proc/self/fd/1) are the
            // kernel's own and may name no path at all: let it follow them.
            if on_procfs(&dir) {
                if last {
                    break (name, true);
                }
                dir = open_at(dir.as_raw_fd(), &name, dir_flags)
                    .with_context(|| format!("opening {path}"))?;
                continue;
            }
            links += 1;
            if links > 40 {
                bail!("{path}: too many levels of symbolic links");
            }
            let mut buf = vec![0u8; libc::PATH_MAX as usize];
            // SAFETY: valid descriptor, C string and buffer of buf.len().
            let n = unsafe {
                libc::readlinkat(
                    dir.as_raw_fd(),
                    name.as_ptr(),
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                )
            };
            if n < 0 {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("reading the link {shown} in {path}"));
            }
            buf.truncate(n as usize);
            if buf.ends_with(b"/") || buf.ends_with(b"/.") {
                if last {
                    bail!("{path}: the link {shown} does not lead to a file");
                }
                // A directory link's target may end in "/": drop it.
                while buf.len() > 1 && (buf.ends_with(b"/") || buf.ends_with(b"/.")) {
                    let cut = if buf.ends_with(b"/.") { 2 } else { 1 };
                    buf.truncate((buf.len() - cut).max(1));
                }
            }
            let target = std::path::Path::new(std::ffi::OsStr::from_bytes(&buf));
            if target.has_root() {
                dir = open_at(libc::AT_FDCWD, &root, dir_flags)
                    .with_context(|| format!("opening {path}"))?;
            }
            push_front(&mut queue, target);
            if queue.is_empty() {
                bail!("{path}: the link {shown} does not lead to a file");
            }
            continue;
        }
        if last {
            if part == b".." {
                bail!("{path} does not name a file");
            }
            break (name, false);
        }
        dir = open_at(dir.as_raw_fd(), &name, dir_flags | libc::O_NOFOLLOW).map_err(|e| {
            if e.raw_os_error() == Some(libc::ELOOP) {
                anyhow::anyhow!("{path}: {shown} turned into a symbolic link while being opened")
            } else {
                anyhow::Error::new(e).context(format!("opening {path}"))
            }
        })?;
    };
    let mut flags = match mode {
        OpenMode::Create { append: false } => libc::O_WRONLY,
        OpenMode::Create { append: true } => libc::O_WRONLY | libc::O_APPEND,
        OpenMode::Resume => libc::O_RDWR | libc::O_APPEND,
    };
    if !follow {
        flags |= libc::O_NOFOLLOW;
    }
    let refused = |e: std::io::Error| -> anyhow::Error {
        if e.raw_os_error() == Some(libc::ELOOP) {
            anyhow::anyhow!(
                "{path} is a symbolic link; running as root, FeroProbe does not write a report \
                 through it. Give the real path"
            )
        } else {
            anyhow::Error::new(e).context(format!("opening {path}"))
        }
    };
    // A resumed scan never creates a report.
    if mode == OpenMode::Resume {
        return Ok(std::fs::File::from(
            open_at(dir.as_raw_fd(), &name, flags).map_err(refused)?,
        ));
    }
    // Create it ourselves if we can, to know whether to hand it over.
    let fd = match open_at(dir.as_raw_fd(), &name, flags | libc::O_CREAT | libc::O_EXCL) {
        Ok(fd) => {
            if let Some((uid, gid)) = privdrop::sudo_ids() {
                // SAFETY: a valid open descriptor.
                if unsafe { libc::fchown(fd.as_raw_fd(), uid, gid) } != 0 {
                    return Err(std::io::Error::last_os_error())
                        .with_context(|| format!("handing {path} to SUDO_UID {uid}"));
                }
            }
            fd
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            open_at(dir.as_raw_fd(), &name, flags).map_err(refused)?
        }
        Err(e) => return Err(refused(e)),
    };
    Ok(std::fs::File::from(fd))
}

/// Progress on standard error for -v.
/// Progress reports on standard error: `-v` messages, and the phase that
/// `--stats-every` names.
#[derive(Clone, Copy)]
struct Progress {
    /// Say nothing, whatever the verbosity (the per-host jobs of
    /// `--host-timeout`, which report as one).
    quiet: bool,
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
        if !self.quiet {
            feroprobe_core::debug::verbose(level, msg);
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

    /// Announce the open ports a scan found, like nmap's -v; from -d2 on,
    /// the ports in every state, as nmap does.
    fn found(&self, results: &[HostResult]) {
        if self.quiet {
            return;
        }
        // nmap: open ports at -v, every port at -d2, whatever the other
        // level (the keys change them independently).
        // Read per port, so a key pressed meanwhile takes effect at once.
        let every = || feroprobe_core::debug::debugging() > 1;
        let open = || feroprobe_core::debug::verbosity() > 0;
        for h in results {
            for p in h
                .ports
                .iter()
                .filter(|p| every() || (open() && p.state == feroprobe_core::PortState::Open))
            {
                eprintln!(
                    "Discovered {} port {}/{} on {}",
                    p.state, p.port, p.protocol, h.addr
                );
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
    /// The SCTP scan to run (`-sY` or `-sZ`), if any.
    sctp: Option<SctpScanKind>,
    /// The IP protocol scan (`-sO`).
    ip_proto: bool,
    version: bool,
    ping_only: bool,
    discovery: bool,
    /// `-sL`: list the targets, send them nothing (also sets `ping_only`
    /// and clears `discovery`).
    list: bool,
}

/// `syn_ok` says whether a SYN scan can serve as the default: the process is
/// privileged, and the system has IPv6 if any target needs it.
fn plan(scan: &[ScanType], skip_discovery: bool, syn_ok: bool, scanflags: bool) -> Result<Plan> {
    // -sC chooses scripts, not a scan: like nmap, it rides along with -sn
    // (host scripts). Only -sL, which sends nothing, refuses it.
    let list_asked = scan.contains(&ScanType::List);
    let scan: Vec<ScanType> = scan
        .iter()
        .copied()
        .filter(|&t| t != ScanType::Scripts || list_asked)
        .collect();
    let scan = scan.as_slice();
    let has = |t| scan.contains(&t);
    let tcp_types: Vec<ScanType> = ScanType::TCP.into_iter().filter(|&t| has(t)).collect();
    if tcp_types.len() > 1 {
        let flags: Vec<&str> = tcp_types.iter().map(|t| t.flag()).collect();
        bail!("choose one TCP scan type, not {}", flags.join(" and "));
    }
    let list = has(ScanType::List);
    // nmap lets -sn ride along with -sL: the list scan wins.
    if list
        && let Some(other) = scan
            .iter()
            .find(|&&t| t != ScanType::List && t != ScanType::PingOnly)
    {
        bail!(
            "-sL lists the targets and sends them nothing, so it cannot be combined with {}",
            other.flag()
        );
    }
    let ping_only = has(ScanType::PingOnly) || list;
    if ping_only && !list && scan.len() > 1 {
        bail!("-sn (no port scan) cannot be combined with other scan types");
    }
    if scanflags {
        if list {
            bail!("--scanflags needs a port scan, so it cannot be combined with -sL");
        }
        if ping_only {
            bail!("--scanflags needs a port scan, so it cannot be combined with -sn");
        }
        if has(ScanType::Connect) {
            bail!("--scanflags sends raw packets, so it cannot be combined with -sT");
        }
    }
    let sctp = match (has(ScanType::SctpInit), has(ScanType::SctpCookie)) {
        (true, true) => bail!("choose one SCTP scan type, not -sY and -sZ"),
        (true, false) => Some(SctpScanKind::Init),
        (false, true) => Some(SctpScanKind::CookieEcho),
        (false, false) => None,
    };
    let ip_proto = has(ScanType::IpProto);
    // Only pull in the default TCP scan when no scan type was asked for at
    // all; an explicit -sU, -sY, -sZ or -sO stands on its own, like nmap.
    let any_explicit = !tcp_types.is_empty() || has(ScanType::Udp) || sctp.is_some() || ip_proto;
    let tcp = if let Some(&t) = tcp_types.first() {
        Some(t)
    } else if scanflags {
        // nmap reads custom flags as a SYN scan unless told otherwise.
        Some(ScanType::Syn)
    } else if !any_explicit && !ping_only {
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
        sctp,
        ip_proto,
        version: has(ScanType::Version),
        ping_only,
        discovery: !skip_discovery && !list,
        list,
    })
}

/// What `-sL` cannot work with: like nmap, no `-p`/`-F` (nothing is
/// scanned), and no option that sends probes (`-O`, `-A`,
/// `--traceroute`, which nmap rejects or quietly drops). Returns warnings
/// for the `-P` options, which a list scan ignores (nmap ignores them
/// silently).
fn list_scan_checks(args: &Args) -> Result<Vec<String>> {
    if args.ports.is_some() || args.fast || args.top_ports.is_some() {
        bail!("-sL scans no ports, so it cannot be combined with -p, -F or --top-ports");
    }
    for (given, option) in [
        (args.aggressive, "-A"),
        (args.os, "-O"),
        (args.traceroute, "--traceroute"),
        (!args.script.is_empty(), "--script"),
    ] {
        if given {
            bail!("-sL sends nothing to the targets, so it cannot be combined with {option}");
        }
    }
    let mut seen = Vec::new();
    for p in &args.ping {
        let flag = match p {
            PingArg::Skip => continue,
            PingArg::Syn(_) => "-PS",
            PingArg::Ack(_) => "-PA",
            PingArg::Udp(_) => "-PU",
            PingArg::Echo => "-PE",
            PingArg::Timestamp => "-PP",
            PingArg::Mask => "-PM",
            PingArg::Sctp(_) => "-PY",
            PingArg::Proto(_) => "-PO",
            PingArg::Arp => "-PR",
        };
        if !seen.contains(&flag) {
            seen.push(flag);
        }
    }
    Ok(seen
        .into_iter()
        .map(|flag| format!("-sL sends nothing to the targets, so {flag} is ignored"))
        .collect())
}

/// What `-PY` and `-PO` need: raw sockets on Linux, as nmap requires root
/// for them. Without, a real run refuses them rather than quietly dropping
/// them (a dry run only says so).
fn raw_ping_check(probes: &PingProbes, raw: bool) -> Result<()> {
    if raw {
        return Ok(());
    }
    for (asked, what) in [
        (!probes.sctp.is_empty(), "-PY (SCTP INIT ping)"),
        (!probes.proto.is_empty(), "-PO (IP protocol ping)"),
    ] {
        if asked {
            if !cfg!(target_os = "linux") {
                bail!("{what} is only supported on Linux for now");
            }
            bail!("{what} sends raw packets: run as root or grant CAP_NET_RAW");
        }
    }
    Ok(())
}

/// nmap's note for `-PR`, which it prints with `-v`: ARP needs no option.
const PR_NOTE: &str = "-PR changes nothing: as in nmap, where the option is deprecated, \
    targets on a local Ethernet network always get an ARP (IPv4) or neighbour discovery \
    (IPv6) request unless --disable-arp-ping is given, and other targets get the usual probes";

fn parse_timing(s: &str) -> Result<Timing, String> {
    s.parse()
}

/// A parallelism (`-c`/`-M`/`--max-parallelism`, `--min-parallelism`):
/// at least 1, as nmap requires.
fn parse_parallelism(s: &str) -> Result<usize, String> {
    match s.trim().parse::<usize>() {
        Ok(0) => Err("must be at least 1".to_string()),
        Ok(n) => Ok(n),
        Err(e) => Err(e.to_string()),
    }
}

/// Apply `--min-parallelism`: raise the parallelism to it, or fail like
/// nmap when an explicit `-c`/`--max-parallelism` is lower. Returns nmap's
/// warning for a very high value.
fn apply_min_parallelism(cfg: &mut ScanConfig, args: &Args) -> Result<Vec<String>> {
    let Some(min) = args.min_parallelism else {
        return Ok(Vec::new());
    };
    if let Some(max) = args.concurrency
        && min > max
    {
        bail!("--min-parallelism={min} must be less than or equal to --max-parallelism={max}");
    }
    cfg.concurrency = cfg.concurrency.max(min);
    cfg.min_parallelism = min;
    Ok(if min > 100 {
        vec![format!(
            "a --min-parallelism of {min} is pretty high, which can hurt reliability"
        )]
    } else {
        Vec::new()
    })
}

/// nmap's warnings for `-g`: a connect scan cannot use it, and port 0 may
/// not work (UDP probes, which go through the system's sockets, cannot
/// send from it at all).
fn source_port_warnings(port: u16, connect_scan: bool, udp: bool) -> Vec<String> {
    let mut w = Vec::new();
    if connect_scan {
        w.push(
            "-g is incompatible with the connect scan (-sT), which keeps the system's source \
             ports. Use a raw scan such as -sS if you want to set the source port"
                .to_string(),
        );
    }
    if udp && cfg!(windows) {
        w.push(
            "-g does not apply to UDP probes on Windows, which cannot share a source port \
             between them; they use random ports"
                .to_string(),
        );
    } else if port == 0 {
        let udp = if udp {
            "; UDP probes cannot be sent from port 0 and use a random port instead"
        } else {
            ""
        };
        w.push(format!(
            "a source port of zero may not work on all systems{udp}"
        ));
    }
    w
}

/// An RTT timeout option's value, checked like nmap's: a bare number is
/// seconds, and one of 50000 or more was almost surely meant as
/// milliseconds (nmap's unit before 2010), so it is refused with a hint.
fn parse_rtt(s: &str, name: &str) -> Result<Duration, String> {
    let d = parse_duration(s)?;
    let bare = s.trim().chars().all(|c| c.is_ascii_digit() || c == '.');
    if bare && d >= Duration::from_secs(50_000) {
        let t = s.trim();
        return Err(format!(
            "a bare number is seconds, so {t} is {} seconds; use {t}ms for milliseconds \
             ({name} follows nmap, whose unit has been seconds since 2010)",
            d.as_secs()
        ));
    }
    Ok(d)
}

fn parse_max_scan_delay(s: &str) -> Result<Duration, String> {
    parse_rtt(s, "--max-scan-delay")
}

fn parse_min_rtt(s: &str) -> Result<Duration, String> {
    parse_rtt(s, "--min-rtt-timeout")
}

fn parse_max_rtt(s: &str) -> Result<Duration, String> {
    let d = parse_rtt(s, "--max-rtt-timeout")?;
    if d < Duration::from_millis(5) {
        return Err("must be at least 5ms".to_string());
    }
    Ok(d)
}

fn parse_initial_rtt(s: &str) -> Result<Duration, String> {
    let d = parse_rtt(s, "--initial-rtt-timeout")?;
    if d.is_zero() {
        return Err("must be positive".to_string());
    }
    Ok(d)
}

/// The probe timeout limits: the template's, then `--timeout` (all three
/// fixed), then the three RTT options, applied in nmap's order (initial,
/// minimum, maximum), each moving the others where they would cross.
fn rtt_timeouts(args: &Args) -> RttTimeouts {
    let mut rtt = args.timing.unwrap_or_default().rtt_timeouts();
    if let Some(ms) = args.timeout {
        rtt = RttTimeouts::fixed(Duration::from_millis(ms));
    }
    if let Some(d) = args.initial_rtt_timeout {
        rtt.set_initial(d);
    }
    if let Some(d) = args.min_rtt_timeout {
        rtt.set_min(d);
    }
    if let Some(d) = args.max_rtt_timeout {
        rtt.set_max(d);
    }
    rtt
}

/// The timing template's settings, with any explicit flags on top.
fn scan_config(args: &Args) -> ScanConfig {
    let base = args.timing.unwrap_or_default().config();
    let scan_delay = args.scan_delay.unwrap_or(base.scan_delay);
    ScanConfig {
        rtt: rtt_timeouts(args),
        // One set of RTT estimates for the whole run, like nmap's per-target
        // timing: the port scan starts from what discovery measured.
        rtt_state: feroprobe_core::RttState::new(),
        timing_level: base.timing_level,
        min_rate: args.min_rate.unwrap_or(0),
        // Set by apply_min_parallelism.
        min_parallelism: 0,
        concurrency: args.concurrency.unwrap_or(base.concurrency).max(1),
        retries: args.retries.unwrap_or(base.retries),
        max_rate: args.max_rate.map(|r| r.max(1)).or(base.max_rate),
        scan_delay,
        // Like nmap: an explicit --scan-delay above the template's cap
        // raises it, and --max-scan-delay replaces it. The scan never goes
        // below --scan-delay whatever the cap.
        max_scan_delay: args
            .max_scan_delay
            .unwrap_or(base.max_scan_delay)
            .max(scan_delay),
        max_udp_scan_delay: args
            .max_scan_delay
            .unwrap_or(base.max_udp_scan_delay)
            .max(scan_delay),
        arp_ping: !args.disable_arp_ping,
        deadline: None,
        // One --max-rate for the whole run, like nmap's, however many scans
        // and host jobs send side by side or one after another.
        rate_schedule: Some(feroprobe_core::timing::RateSchedule::new()),
        // Set later by configure_evasion once the targets are known.
        evasion: Evasion::default(),
        source_port: args.source_port,
        // nmap's --open implies --defeat-rst-ratelimit: closed and
        // filtered ports are not shown, so telling them apart is not
        // worth slowing down for.
        defeat_rst_ratelimit: args.defeat_rst_ratelimit || args.open,
    }
}

/// Build the evasion options from the command-line flags, failing on
/// malformed input. Does not check whether they are allowed for the
/// targets; [`gate_evasion`] does that.
fn evasion_from_args(args: &Args) -> Result<Evasion> {
    let mut ev = Evasion::default();
    if args.fragment {
        ev.fragment = Some(Fragment::Eight);
    }
    if let Some(n) = args.mtu {
        if n == 0 || n % 8 != 0 {
            bail!("--mtu must be a positive multiple of 8");
        }
        ev.fragment = Some(Fragment::Mtu(n));
    }
    if let Some(list) = &args.decoys {
        for tok in list.split(',') {
            let tok = tok.trim();
            // ME marks the real scanner's slot among the decoys. FeroProbe
            // always sends the real probe last, so ME is accepted but has no
            // effect on ordering.
            if tok.eq_ignore_ascii_case("ME") {
                continue;
            }
            if tok.is_empty() {
                bail!("-D has an empty decoy in its list");
            }
            let ip: Ipv4Addr = tok
                .parse()
                .map_err(|_| anyhow::anyhow!("decoy '{tok}' is not an IPv4 address"))?;
            ev.decoys.push(IpAddr::V4(ip));
        }
        if ev.decoys.is_empty() {
            bail!("-D needs at least one decoy address");
        }
    }
    if let Some(s) = &args.spoof_source {
        let ip: Ipv4Addr = s
            .parse()
            .map_err(|_| anyhow::anyhow!("--source '{s}' is not an IPv4 address"))?;
        ev.spoof_source = Some(IpAddr::V4(ip));
    }
    Ok(ev)
}

/// Bytes from an option's value (clap would read a bare `Vec<u8>` as a
/// list of values).
#[derive(Debug, Clone)]
struct Bytes(Vec<u8>);

/// `--data`: hex bytes, as nmap reads them.
fn parse_data_hex(s: &str) -> Result<Bytes, String> {
    feroprobe_core::packet_opts::parse_hex(s).map(Bytes)
}

/// `--data-length`: 0 to nmap's maximum payload.
fn parse_data_length(s: &str) -> Result<usize, String> {
    let max = feroprobe_core::packet_opts::MAX_PAYLOAD;
    match s.trim().parse::<usize>() {
        Ok(n) if n <= max => Ok(n),
        _ => Err(format!("data-length must be between 0 and {max}")),
    }
}

/// `--ip-options`, in nmap's notation.
fn parse_ip_options_arg(s: &str) -> Result<Bytes, String> {
    feroprobe_core::packet_opts::parse_ip_options(s).map(Bytes)
}

/// The packet options from the command line (`--data*`, `--ttl`,
/// `--ip-options`, `--badsum`).
fn packet_options(args: &Args) -> Result<feroprobe_core::PacketOptions> {
    let max = feroprobe_core::packet_opts::MAX_PAYLOAD;
    let data = if let Some(d) = &args.data {
        Some(d.0.clone())
    } else if let Some(text) = &args.data_string {
        if text.len() > max {
            bail!("string length must be between 0 and {max}");
        }
        Some(text.as_bytes().to_vec())
    } else {
        args.data_length
            .map(feroprobe_core::packet_opts::random_bytes)
    };
    Ok(feroprobe_core::PacketOptions {
        ttl: args.ttl,
        data,
        badsum: args.badsum,
        ip_options: args.ip_options.clone().map(|b| b.0).unwrap_or_default(),
    })
}

/// What the packet options cannot do in this scan, as warnings: nmap's
/// for a large payload and for raw options a connect scan or an
/// unprivileged run cannot honour, and FeroProbe's for the IPv4-only
/// `--ip-options` against IPv6 targets. `--badsum` is dropped when it
/// cannot be honoured, so the dry run does not claim it.
fn packet_option_warnings(
    opts: &mut feroprobe_core::PacketOptions,
    plan: &Plan,
    targets: &[Target],
    privileged: bool,
) -> Vec<String> {
    let mut w = Vec::new();
    if opts
        .data
        .as_ref()
        .is_some_and(|d| d.len() > feroprobe_core::packet_opts::PAYLOAD_WARN)
    {
        w.push("Payloads bigger than 1400 bytes may not be sent successfully.".to_string());
    }
    if !opts.is_active() {
        return w;
    }
    let mut named = Vec::new();
    if opts.data.is_some() {
        named.push("--data");
    }
    if opts.ttl.is_some() {
        named.push("--ttl");
    }
    if !opts.ip_options.is_empty() {
        named.push("--ip-options");
    }
    if opts.badsum {
        named.push("--badsum");
    }
    if opts.ttl == Some(0) && targets.iter().any(|t| t.addr.is_ipv4()) {
        w.push(
            "--ttl 0: the system refuses TTL 0 for IPv4 probes whose header it writes, so those \
             go with TTL 1; probes FeroProbe builds whole (-sO, -f, --mtu, -D, -S) and IPv6 \
             probes carry 0"
                .to_string(),
        );
    }
    if !plan.ping_only && plan.tcp == Some(ScanType::Connect) {
        w.push(format!(
            "{} will not be honored for the TCP connect scan (-sT), whose packets the system builds",
            named.join(", ")
        ));
    }
    if opts.badsum && !privileged {
        w.push(
            "--badsum needs raw sockets, so it will not be honored without the necessary \
             privileges"
                .to_string(),
        );
        opts.badsum = false;
    }
    if !opts.ip_options.is_empty()
        && let Some(t) = targets.iter().find(|t| t.addr.is_ipv6())
    {
        w.push(format!(
            "--ip-options are IPv4 header options, so probes to IPv6 targets such as {} go without them",
            t.addr
        ));
    }
    if !opts.ip_options.is_empty() && !cfg!(target_os = "linux") {
        w.push(
            "--ip-options are set only on Linux for probes whose IP header the system writes; \
             here only probes FeroProbe builds whole (-sO, -f, --mtu, -D, -S) carry them"
                .to_string(),
        );
    }
    w
}

/// The command line for reports, with the password of an FTP bounce
/// relay (`-b user:pass@server`) masked, so saved output does not carry it.
/// `secret` is the password the relay login actually uses: wherever it
/// appears as `:secret@`, in whatever grouping of short options (`-vb`),
/// it is masked too.
fn redact_args(args: impl IntoIterator<Item = String>, secret: Option<&str>) -> Vec<String> {
    let mask = |v: &str| match v.rsplit_once('@') {
        Some((login, server)) => match login.split_once(':') {
            Some((user, _)) => format!("{user}:****@{server}"),
            None => v.to_string(),
        },
        None => v.to_string(),
    };
    let mut out = Vec::new();
    let mut relay_next = false;
    for a in args {
        if relay_next {
            out.push(mask(&a));
            relay_next = false;
        } else if a == "-b" {
            out.push(a);
            relay_next = true;
        } else if let Some(v) = a.strip_prefix("-b").filter(|v| v.contains('@')) {
            out.push(format!("-b{}", mask(v)));
        } else {
            out.push(a);
        }
    }
    match secret.filter(|s| !s.is_empty()) {
        Some(s) => out
            .into_iter()
            .map(|a| a.replace(&format!(":{s}@"), ":****@"))
            .collect(),
        None => out,
    }
}

/// Check and parse `--spoof-mac`, and say what it will and will not
/// change, as nmap's "Spoofing MAC address" line and our warnings.
fn spoof_mac(
    arg: &str,
    args: &Args,
    plan: &Plan,
    targets: &[Target],
) -> Result<feroprobe_core::arp::MacAddr> {
    if !cfg!(target_os = "linux") {
        bail!("--spoof-mac sends Ethernet frames, which FeroProbe does only on Linux");
    }
    if !args.allow_public_evasion {
        let addrs: Vec<IpAddr> = targets.iter().map(|t| t.addr).collect();
        if let Some(public) = feroprobe_core::scope::first_public(&addrs) {
            bail!(
                "--spoof-mac is refused against public addresses, but {public} is a public \
                 address. Pass --allow-public-evasion to authorize this against targets you \
                 have permission to test. This is a deliberate FeroProbe safeguard: see \
                 docs/responsible-use.md."
            );
        }
    }
    let mut rng = rand_bytes();
    let mac = feroprobe_core::spoofmac::parse(arg, &mut rng).map_err(anyhow::Error::msg)?;
    if !args.dry_run && !raw_sockets_available() {
        bail!("--spoof-mac sends raw Ethernet frames: run as root or grant CAP_NET_RAW");
    }
    eprintln!(
        "Spoofing MAC address {mac} ({})",
        feroprobe_core::arp::vendor(mac).unwrap_or("No registered vendor")
    );
    for w in spoof_mac_warnings(plan, targets, args.bounce.is_some(), args.dry_run) {
        eprintln!("Warning: {w}");
    }
    Ok(mac)
}

/// What `--spoof-mac` does not cover in this run.
fn spoof_mac_warnings(plan: &Plan, targets: &[Target], bounce: bool, dry_run: bool) -> Vec<String> {
    let mut w = Vec::new();
    if let Some(t) = targets.iter().find(|t| t.addr.is_ipv6()) {
        w.push(format!(
            "--spoof-mac covers IPv4 only, so probes to IPv6 targets such as {} keep this host's MAC address",
            t.addr
        ));
    }
    let mut system = Vec::new();
    if !plan.ping_only && plan.tcp == Some(ScanType::Connect) {
        system.push("the TCP connect scan (-sT)");
    }
    if !plan.ping_only && plan.version {
        system.push("version detection (-sV)");
    }
    if bounce {
        system.push("the FTP bounce scan (-b)");
    }
    if !system.is_empty() {
        w.push(format!(
            "--spoof-mac will not be honored for {}, whose packets the system sends",
            system.join(" and ")
        ));
    }
    if !dry_run && let Some(r) = feroprobe_core::spoofmac::relay_warning() {
        w.push(r);
    }
    w
}

/// Random bytes for `--spoof-mac`, from the system's random source.
fn rand_bytes() -> impl FnMut() -> u8 {
    let mut state = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0x9e37_79b9_7f4a_7c15, |d| d.as_nanos() as u64)
        ^ u64::from(std::process::id()) << 32;
    let mut seed = [0u8; 8];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut seed))
        .is_ok()
    {
        state ^= u64::from_le_bytes(seed);
    }
    move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        (state >> 24) as u8
    }
}

/// Refuse evasion options unless they are allowed: a raw TCP scan, raw
/// sockets available, and IPv4-only targets. A public target, decoy or
/// spoofed source is refused unless `allow_public` is set (the
/// `--allow-public-evasion` flag). The default public-target refusal is a
/// deliberate anti-abuse safeguard and a departure from nmap, which allows
/// these options against any target.
fn gate_evasion(ev: &Evasion, targets: &[Target], plan: &Plan, allow_public: bool) -> Result<()> {
    if !ev.is_active() {
        return Ok(());
    }
    if plan.tcp.and_then(ScanType::raw_kind).is_none() {
        bail!(
            "evasion options (-f/--mtu, -D, -S) need a raw TCP scan: \
             -sS, -sF, -sN, -sX, -sA, -sW or -sM"
        );
    }
    if let Some(t) = targets.iter().find(|t| t.addr.is_ipv6()) {
        bail!(
            "evasion options are IPv4 only, but target {} is IPv6",
            t.addr
        );
    }
    // The anti-abuse safeguard. Checked before the privilege check so a
    // public address is refused whether or not raw sockets are available.
    // The decoy (-D) and spoofed-source (-S) addresses count too: a public
    // one there would make the target answer a public host, which is the
    // same abuse the safeguard is meant to stop. --allow-public-evasion
    // (allow_public) is the deliberate opt-in for authorized public tests.
    if !allow_public {
        let addrs: Vec<IpAddr> = targets
            .iter()
            .map(|t| t.addr)
            .chain(ev.decoys.iter().copied())
            .chain(ev.spoof_source)
            .collect();
        if let Some(public) = feroprobe_core::scope::first_public(&addrs) {
            bail!(
                "evasion options (fragmentation, decoys, spoofed source) are refused \
                 against public addresses, but {public} is a public address (a target, \
                 a decoy, or the spoofed source). Pass --allow-public-evasion to authorize \
                 this against targets you have permission to test. This is a deliberate \
                 FeroProbe safeguard: see docs/responsible-use.md."
            );
        }
    }
    Ok(())
}

/// Apply `--min-rate` on top of the timing settings. Raw-socket scans send
/// as fast as `max_rate` and the scan delay allow, so those must allow the
/// minimum; connect and UDP probes need enough of them in flight to keep
/// the rate up even when every probe waits out its initial timeout. The
/// congestion window lets probes through past its limit to keep the rate
/// (see `ScanConfig::min_rate`). Returns
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
        _ => cfg.max_rate = cfg.max_rate.map(|r| r.max(min)),
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
        // An explicit cap was floored at the template's delay: floor it
        // at the lowered one instead.
        if let Some(cap) = args.max_scan_delay {
            cfg.max_scan_delay = cap.max(gap);
            cfg.max_udp_scan_delay = cap.max(gap);
        }
    }
    let mut warnings = Vec::new();
    // A silent port holds its place for a whole wait: the initial timeout,
    // and on Windows at least the connect scan's longer floor.
    let wait = if cfg!(windows) {
        cfg.rtt
            .initial
            .max(feroprobe_core::connect::WINDOWS_MIN_CONNECT_WAIT)
    } else {
        cfg.rtt.initial
    };
    let needed = (f64::from(min) * wait.as_secs_f64()).ceil() as usize;
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
fn port_lists(args: &Args, ip_proto: bool, port_scan: bool) -> Result<PortLists> {
    let mut lists = match &args.ports {
        Some(spec) => parse_port_lists(spec, ip_proto, port_scan)?,
        None => {
            let n = if args.fast { Some(100) } else { args.top_ports };
            PortLists {
                tcp: top_ports(n.unwrap_or(1000)),
                udp: top_udp_ports(n.unwrap_or(1000)),
                sctp: top_sctp_ports(n.unwrap_or(50)),
                // -sO with no -p scans every IP protocol.
                protocols: (0..=255).collect(),
            }
        }
    };
    if let Some(spec) = &args.exclude_ports {
        let ex = parse_port_lists(spec, ip_proto, port_scan).context("reading --exclude-ports")?;
        lists.tcp.retain(|p| ex.tcp.binary_search(p).is_err());
        lists.udp.retain(|p| ex.udp.binary_search(p).is_err());
        lists.sctp.retain(|p| ex.sctp.binary_search(p).is_err());
        lists
            .protocols
            .retain(|p| ex.protocols.binary_search(p).is_err());
    }
    Ok(lists)
}

/// A resolver message as nmap prints it: "Failed to resolve" lines stand
/// alone, the rest are warnings.
fn nmap_warning(w: &str) -> String {
    if w.starts_with("Failed to resolve") {
        w.to_string()
    } else {
        format!("Warning: {w}")
    }
}

/// nmap's warnings about option values that will likely hurt the scan.
fn option_warnings(args: &Args, open_files: Option<u64>) -> Vec<String> {
    let mut warnings = Vec::new();
    if let Some(ms) = args.timeout
        && ms < 20
    {
        warnings.push(format!(
            "a probe timeout of {ms} ms is extraordinarily small; accuracy may suffer"
        ));
    }
    if let Some(d) = args.max_rtt_timeout
        && d < Duration::from_millis(20)
    {
        warnings.push(format!(
            "a --max-rtt-timeout of {} ms is extraordinarily small; accuracy may suffer",
            d.as_millis()
        ));
    }
    if let Some(c) = args.concurrency {
        if c > 900 {
            warnings.push(format!(
                "a --concurrency of {c} is extraordinarily high, which can hurt reliability"
            ));
        }
        if let Some(limit) = open_files
            && (c as u64) > limit
        {
            warnings.push(format!(
                "--concurrency is {c}, but this system may only allow {limit} open sockets; trying anyway"
            ));
        }
    }
    warnings
}

/// Take the `--exclude-ports` ports out of the discovery probes, as nmap
/// does, with nmap's warning for a probe type left without ports.
fn exclude_ping_ports(probes: &mut PingProbes, ex: &PortLists) -> Vec<String> {
    let had_tcp = !probes.syn.is_empty() || !probes.ack.is_empty();
    let had_udp = !probes.udp.is_empty();
    let had_sctp = !probes.sctp.is_empty();
    let had_proto = !probes.proto.is_empty();
    probes.syn.retain(|p| ex.tcp.binary_search(p).is_err());
    probes.ack.retain(|p| ex.tcp.binary_search(p).is_err());
    probes.udp.retain(|p| ex.udp.binary_search(p).is_err());
    probes.sctp.retain(|p| ex.sctp.binary_search(p).is_err());
    probes
        .proto
        .retain(|p| ex.protocols.binary_search(&u16::from(*p)).is_err());
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
    if had_sctp && probes.sctp.is_empty() {
        warnings.push(
            "an SCTP ping was asked for, but --exclude-ports removed all its ports; skipping it"
                .to_string(),
        );
    }
    if had_proto && probes.proto.is_empty() {
        warnings.push(
            "an IP protocol ping was asked for, but --exclude-ports removed all its protocols; \
             skipping it"
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

/// The `-sV` settings: intensity, trace and rules.
fn version_scan(args: &Args) -> Result<VersionScan> {
    let mut vs = VersionScan::new(Duration::from_millis(args.version_timeout));
    vs.intensity = version_intensity(args);
    vs.trace = args.version_trace;
    // nmap prints the trace to standard output; keep it off a
    // machine-readable report there.
    let outputs = Outputs::from_args(args)?;
    vs.trace_to_stderr = if outputs.stdout_taken() {
        outputs.normal.iter().all(|p| p != "-")
    } else {
        !matches!(args.output, Format::Table)
    };
    if let Some(path) = &args.service_rules {
        let db = feroprobe_core::ServiceDb::load(path)
            .map_err(|e| anyhow::anyhow!("reading service rules {}: {e}", path.display()))?;
        vs.db = std::sync::Arc::new(db);
    }
    Ok(vs)
}

/// The `-sV` intensity from `--version-intensity`, `--version-light` and
/// `--version-all`; clap leaves only the last of the three set.
fn version_intensity(args: &Args) -> u8 {
    if let Some(level) = args.version_intensity {
        level
    } else if args.version_light {
        VersionScan::LIGHT
    } else if args.version_all {
        VersionScan::ALL
    } else {
        VersionScan::DEFAULT_INTENSITY
    }
}

/// The first `-sV` option given, for the warning when there is no `-sV`.
fn version_option(args: &Args) -> Option<&'static str> {
    [
        (args.version_intensity.is_some(), "--version-intensity"),
        (args.version_light, "--version-light"),
        (args.version_all, "--version-all"),
        (args.version_trace, "--version-trace"),
        (args.service_rules.is_some(), "--service-rules"),
    ]
    .into_iter()
    .find_map(|(given, name)| given.then_some(name))
}

/// Apply `-A`: version detection, plus OS detection and traceroute when
/// raw sockets are available (with a warning when they are not). Returns
/// whether OS detection and traceroute run. Its default scripts (`-sC`)
/// come from [`script_selection`], since they load before the scan.
fn aggressive(plan: &mut Plan, args: &Args, privileged: bool) -> Result<(bool, bool)> {
    if !args.aggressive {
        return Ok((args.os, args.traceroute));
    }
    if plan.ping_only {
        bail!(
            "-A needs a port scan, so it cannot be combined with {}",
            if plan.list { "-sL" } else { "-sn" }
        );
    }
    plan.version = true;
    if privileged {
        return Ok((true, true));
    }
    eprintln!("Warning: {}", AGGRESSIVE_UNPRIVILEGED);
    Ok((args.os, args.traceroute))
}

/// The `-O` options. The echo probe is in scope only when the command's
/// host discovery sends ICMP echo requests (the default as root, or `-PE`).
fn os_options(args: &Args, plan: &Plan, probes: &PingProbes) -> OsOptions {
    OsOptions {
        limit: args.osscan_limit,
        guess: args.osscan_guess,
        max_tries: args
            .max_os_tries
            .unwrap_or(feroprobe_core::os::DEFAULT_TRIES),
        icmp_echo: plan.discovery && probes.echo,
    }
}

/// Warnings for `-O` options given without `-O`, which do nothing then.
fn os_option_warnings(args: &Args, os: bool) -> Vec<String> {
    if os {
        return Vec::new();
    }
    [
        (args.osscan_limit, "--osscan-limit"),
        (args.osscan_guess, "--osscan-guess"),
        (args.max_os_tries.is_some(), "--max-os-tries"),
    ]
    .iter()
    .filter(|(given, _)| *given)
    .map(|(_, name)| format!("{name} has no effect without OS detection (-O or -A)"))
    .collect()
}

/// nmap's script timeout under `-T5`: ten minutes.
const INSANE_SCRIPT_TIMEOUT: Duration = Duration::from_secs(600);

/// Whether the default scripts run: `-sC`, or `-A`, which includes it as
/// in nmap.
fn default_scripts(args: &Args) -> bool {
    args.scan.contains(&ScanType::Scripts) || args.aggressive
}

/// The script selection of the command line: the `--script` lists, plus
/// `default` for `-sC` or `-A` (nmap adds it the same way, so `-sC
/// --script banner` runs both).
fn script_selection(args: &Args) -> Vec<String> {
    let mut chosen = args.script.clone();
    if default_scripts(args) {
        chosen.push("default".to_string());
    }
    chosen
}

/// The scripts `--script`, `-sC` or `-A` choose, loaded with their
/// `--script-args`, or `None` when no script was asked for.
fn script_scan(args: &Args) -> Result<Option<feroprobe_core::script::ScriptScan>> {
    use feroprobe_core::script;
    let selection = script_selection(args);
    if selection.is_empty() {
        for (given, option) in [
            (args.script_args.is_some(), "--script-args"),
            (args.script_args_file.is_some(), "--script-args-file"),
            (args.script_timeout.is_some(), "--script-timeout"),
        ] {
            if given {
                eprintln!("Warning: {option} has no effect without --script or -sC");
            }
        }
        return Ok(None);
    }
    let chosen =
        script::choose(&selection.join(",")).map_err(|e| anyhow::anyhow!("--script: {e}"))?;
    let file = args
        .script_args_file
        .as_ref()
        .map(|path| {
            std::fs::read_to_string(path)
                .with_context(|| format!("reading --script-args-file {path}"))
        })
        .transpose()?;
    let table = script::args::parse_combined(file.as_deref(), args.script_args.as_deref())
        .map_err(|e| anyhow::anyhow!("--script-args did not parse: {e}"))?;
    feroprobe_core::debug::debug(1, || {
        format!(
            "Script arguments: {}",
            [file.as_deref(), args.script_args.as_deref()]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(",")
        )
    });
    // As in nmap: 0 is no limit, and -T5 limits scripts to ten minutes.
    let timeout = match args.script_timeout {
        Some(d) => Some(d).filter(|d| !d.is_zero()),
        None => matches!(args.timing, Some(Timing::Insane)).then_some(INSANE_SCRIPT_TIMEOUT),
    };
    let engine = script::ScriptScan::new(chosen, table, timeout)
        .map_err(|e| anyhow::anyhow!("--script: {e}"))?;
    Ok(Some(engine))
}

/// The options that send probes able to upset fragile OT/ICS devices
/// (PLCs, RTUs, protocol gateways), in the order they appear in the help.
/// Version detection talks application protocols (HTTP, TLS, ...) to
/// whatever answers; OS detection sends a raw SYN loaded with TCP options.
/// Scripts talk to whatever answers in whatever way they are written to.
fn device_hostile_options(args: &Args) -> Vec<&'static str> {
    let mut found = Vec::new();
    if args.scan.contains(&ScanType::Version) {
        found.push("-sV");
    }
    if args.os {
        found.push("-O");
    }
    if args.aggressive {
        found.push("-A");
    }
    if args.scan.contains(&ScanType::Scripts) {
        found.push("-sC");
    }
    if !args.script.is_empty() {
        found.push("--script");
    }
    found
}

/// Where `ics_protection` was switched on, for messages.
fn ics_source(settings: &config::Settings) -> String {
    if settings.ics_built_in && settings.ics_protection_source.is_none() {
        return "built into this FeroProbe".to_string();
    }
    settings.ics_protection_source.as_ref().map_or_else(
        || "ics_protection = true".to_string(),
        |p| format!("ics_protection = true in {}", p.display()),
    )
}

/// The ICS protection guard. With `ics_protection` on, refuse a run that
/// asks for a device-hostile option, unless `--override-ics-protection`
/// lets it through with a warning. A `--dry-run` is never refused, since
/// it sends nothing, but gets a warning naming what a real run would
/// refuse. Returns the lines to print.
fn gate_ics(settings: &config::Settings, args: &Args) -> Result<Vec<String>> {
    if !settings.ics_protection {
        if args.override_ics_protection {
            return Ok(vec![
                "Warning: --override-ics-protection has no effect: ICS protection is off"
                    .to_string(),
            ]);
        }
        return Ok(Vec::new());
    }
    let hostile = device_hostile_options(args);
    if hostile.is_empty() {
        return Ok(Vec::new());
    }
    let list = hostile.join(", ");
    if !args.override_ics_protection && args.dry_run {
        // A dry run sends nothing, so it is allowed, but says what a real
        // run would do: the habit is the thing to teach.
        return Ok(vec![format!(
            "Warning: ICS protection is on ({}): a real run with {list} would be refused, \
             since version detection, OS detection and scripts send probes that can hang \
             or crash fragile OT/ICS devices such as PLCs. This dry run sends nothing, so it goes ahead. \
             For the real scan, leave out {list} or pass --override-ics-protection",
            ics_source(settings)
        )]);
    }
    if !args.override_ics_protection {
        bail!(
            "ICS protection is on ({}), so {list} is refused: version detection, OS \
             detection and scripts send probes that can hang or crash fragile OT/ICS \
             devices such as PLCs. \
             Leave out {list}, or pass --override-ics-protection to run this once anyway",
            ics_source(settings)
        );
    }
    Ok(vec![
        "WARNING: ************************************************************".to_string(),
        format!(
            "WARNING: --override-ics-protection: running {list} although ICS protection is on ({})",
            ics_source(settings)
        ),
        "WARNING: these probes can hang or crash fragile OT/ICS devices such as PLCs".to_string(),
        "WARNING: ************************************************************".to_string(),
    ])
}

/// Well-known OT/ICS ports: (port, TCP, UDP, protocol).
const OT_PORTS: &[(u16, bool, bool, &str)] = &[
    (102, true, false, "S7comm"),
    (502, true, false, "Modbus"),
    (20000, true, true, "DNP3"),
    (44818, true, true, "EtherNet/IP"),
    (47808, false, true, "BACnet"),
];

/// With ICS protection on, the warning for a port scan that includes
/// well-known OT ports. Port scans are not refused; this is a reminder.
fn ot_port_warning(tcp: &[u16], udp: &[u16]) -> Option<String> {
    let hits: Vec<String> = OT_PORTS
        .iter()
        .flat_map(|&(port, t, u, name)| {
            let tcp_hit = (t && tcp.contains(&port)).then(|| format!("{port}/tcp {name}"));
            let udp_hit = (u && udp.contains(&port)).then(|| format!("{port}/udp {name}"));
            [tcp_hit, udp_hit]
        })
        .flatten()
        .collect();
    (!hits.is_empty()).then(|| {
        format!(
            "ICS protection: the scan includes well-known OT ports ({}); keep it gentle on control devices (e.g. -T2, -sT)",
            hits.join(", ")
        )
    })
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

/// What `-A` drops without raw sockets. nmap drops the same parts but says
/// nothing; FeroProbe names them, so the downgrade is never a surprise.
const AGGRESSIVE_UNPRIVILEGED: &str = "-A without root or CAP_NET_RAW skips OS detection (-O) \
     and traceroute (--traceroute), which send raw packets; only version detection (-sV) and \
     the default scripts (-sC) run. Run as root, or grant CAP_NET_RAW, to include them";

/// The TCP port traceroute falls back to for a host where the scan found
/// no open or closed TCP port: always one the command names (-p, the scan or discovery), so
/// traceroute never reaches outside the scan. In order: the first TCP port
/// of the TCP scan; with `-sn`, the first TCP port given with `-p`; else
/// the first TCP port of host discovery (`-PS`, `-PA`, or the defaults).
/// `None` when the command probes no TCP port at all: such hosts are not
/// traced. (FeroProbe used to fall back to port 80 whatever the scope.)
fn trace_fallback_port(
    args: &Args,
    plan: &Plan,
    tcp_ports: &[u16],
    probes: &PingProbes,
) -> Option<u16> {
    let scan_port = if plan.ping_only {
        args.ports.as_ref().and_then(|_| tcp_ports.first().copied())
    } else if plan.tcp.is_some() {
        tcp_ports.first().copied()
    } else {
        None
    };
    scan_port.or_else(|| {
        plan.discovery
            .then(|| probes.syn.first().or(probes.ack.first()).copied())
            .flatten()
    })
}

/// Why a host with no open or closed TCP port is not traced.
const TRACE_NO_PORT: &str = "traceroute sends TCP SYN probes, and this command probes no TCP \
     port to send them to; FeroProbe does not trace through a port outside the scan. Scan a TCP \
     port too to trace (for example -sS -sU -p U:53,T:443)";

/// The same for `-sn`, where `-p` names the port to trace through.
const TRACE_NO_PORT_SN: &str = "traceroute sends TCP SYN probes, and this command probes no TCP \
     port to send them to; FeroProbe does not trace through a port outside the scan. Name one \
     with -p (for example -p 443)";

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
    sctp: &'a [u16],
    /// IP protocol numbers for `-sO`.
    protocols: &'a [u8],
    scanflags: Option<u8>,
    version: VersionScan,
    os: bool,
    os_opts: OsOptions,
    /// `-b`: the FTP relay's address and login.
    bounce: Option<(SocketAddr, feroprobe_core::ftp_bounce::FtpRelay)>,
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
            None if self.bounce.is_some() => types.push("bounce"),
            None => {}
        }
        if self.plan.udp {
            types.push("udp");
        }
        match self.plan.sctp {
            Some(SctpScanKind::Init) => types.push("sctp-init"),
            Some(SctpScanKind::CookieEcho) => types.push("sctp-cookie"),
            None => {}
        }
        if self.plan.ip_proto {
            types.push("ipproto");
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
        if let Some((addr, relay)) = &self.bounce {
            let done =
                progress.phase_of("FTP bounce scan", live.len(), live.len() * self.tcp.len());
            let r = feroprobe_core::ftp_bounce::bounce_scan(*addr, relay, live, self.tcp, cfg)
                .await
                .context("FTP bounce scan (-b) failed")?;
            progress.found(&r);
            done(&progress);
            merge(hosts, r);
        }
        if self.plan.udp {
            let done = progress.phase_of("UDP scan", live.len(), live.len() * self.udp.len());
            let r = udp_scan(live, self.udp, cfg).await.context(hint)?;
            progress.found(&r);
            done(&progress);
            merge(hosts, r);
        }
        if let Some(kind) = self.plan.sctp {
            let name = match kind {
                SctpScanKind::Init => "SCTP INIT scan",
                SctpScanKind::CookieEcho => "SCTP COOKIE ECHO scan",
            };
            let done = progress.phase_of(name, live.len(), live.len() * self.sctp.len());
            let r = sctp_scan(live, self.sctp, cfg, kind)
                .await
                .with_context(|| format!("{name} failed"))?;
            progress.found(&r);
            done(&progress);
            merge(hosts, r);
        }
        if self.plan.ip_proto {
            let done = progress.phase_of(
                "IP protocol scan",
                live.len(),
                live.len() * self.protocols.len(),
            );
            let r = ip_protocol_scan(live, self.protocols, cfg)
                .await
                .context("IP protocol scan failed")?;
            progress.found(&r);
            done(&progress);
            merge(hosts, r);
        }
        if self.plan.version {
            let done = progress.phase("service detection", live.len());
            detect_services(hosts, cfg, &self.version).await;
            done(&progress);
        }
        if self.os {
            if self.os_opts.limit {
                let all = OsOptions {
                    limit: false,
                    ..self.os_opts
                };
                for (i, h) in hosts.iter().enumerate() {
                    if feroprobe_core::os::job_for(i, h, &self.os_opts).is_none()
                        && feroprobe_core::os::job_for(i, h, &all).is_some()
                    {
                        progress.say(1, || {
                            format!(
                                "Skipping OS Scan against {} due to absence of open (or perhaps closed) ports",
                                h.addr
                            )
                        });
                    }
                }
            }
            let done = progress.phase("OS detection", live.len());
            os_detect(hosts, cfg, &self.os_opts)
                .await
                .context("OS detection failed")?;
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
        // Likewise the --min-parallelism floor, which must stay within
        // each job's share.
        shared.min_parallelism = cfg.min_parallelism.min(shared.concurrency);
        // The hosts share one --max-rate schedule (set in scan_config), so
        // each may use the whole rate.
        let probes = self
            .plan
            .tcp
            .map(|_| ())
            .or(self.bounce.as_ref().map(|_| ()))
            .map_or(0, |_| self.tcp.len())
            + if self.plan.udp { self.udp.len() } else { 0 }
            + self.plan.sctp.map_or(0, |_| self.sctp.len())
            + if self.plan.ip_proto {
                self.protocols.len()
            } else {
                0
            };
        let done = progress.phase_of(
            "port scan (each host on its own clock)",
            live.len(),
            live.len() * probes,
        );
        let quiet = Progress {
            quiet: true,
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
/// one probe in flight while the total stays within `--concurrency`. The
/// hosts share one `--max-rate` schedule; capping the group by it keeps
/// very low rates from spreading over many half-started hosts.
fn host_group(hosts: usize, cfg: &ScanConfig) -> usize {
    hosts
        .min(HOST_GROUP)
        .min(cfg.concurrency)
        .min(cfg.max_rate.map_or(usize::MAX, |r| r as usize))
        .max(1)
}

/// Whether a scan error is the `--host-timeout` deadline passing.
fn is_host_timeout(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        c.downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::TimedOut)
    })
}

/// What every host group of a run shares.
struct GroupRun<'a> {
    args: &'a Args,
    plan: &'a Plan,
    cfg: &'a ScanConfig,
    job: &'a ScanJob<'a>,
    trace: bool,
    trace_fallback: Option<u16>,
    progress: Progress,
    /// `--script`: the scripts to run once the group is scanned.
    scripts: Option<&'a feroprobe_core::script::ScriptScan>,
}

/// Resolve names, port-scan, trace and run scripts on one host group: `targets` and their
/// discovery results `hosts`, one per target. Returns how many hosts could
/// not be traced for want of a port.
async fn scan_group(
    targets: &[Target],
    hosts: &mut [HostResult],
    g: &GroupRun<'_>,
) -> Result<usize> {
    let (args, plan, cfg, progress) = (g.args, g.plan, g.cfg, g.progress);
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
            // --system-dns uses the system resolver, not --dns-servers.
            let servers: &[SocketAddr] = if args.system_dns {
                &[]
            } else {
                &args.dns_servers
            };
            let names = reverse_lookup(&addrs, servers, cfg)
                .await
                .context("reverse DNS failed")?;
            done(&progress);
            for h in hosts.iter_mut() {
                h.rdns = names.get(&h.addr).cloned();
            }
        }
    }

    // Only scan hosts that discovery found (all of them with -Pn).
    let scanned: Vec<usize> = (0..hosts.len())
        .filter(|&i| !plan.discovery || hosts[i].is_up())
        .collect();
    if !plan.ping_only && !scanned.is_empty() {
        let live: Vec<Target> = scanned.iter().map(|&i| targets[i].clone()).collect();
        let mut results: Vec<HostResult> = scanned.iter().map(|&i| hosts[i].clone()).collect();
        // As in nmap, a host timeout of 0 means none.
        match args.host_timeout.filter(|d| !d.is_zero()) {
            None => g.job.run(&live, &mut results, cfg, progress).await?,
            Some(limit) => {
                g.job
                    .run_each(&live, &mut results, cfg, limit, progress)
                    .await?
            }
        }
        for (&i, h) in scanned.iter().zip(results) {
            hosts[i] = h;
        }
        // A host discovery did not time (-Pn, or a TCP connect that only
        // got a refusal) gets the latency the scans measured, as in nmap.
        for h in hosts.iter_mut().filter(|h| h.latency_ms.is_none()) {
            h.latency_ms = cfg
                .rtt_state
                .srtt(h.addr)
                .map(|d| (d.as_secs_f64() * 1e6).round() / 1000.0);
        }
        for &i in &scanned {
            let addr = hosts[i].addr;
            if let Some((srtt, rttvar, to)) = cfg.rtt_state.times(addr) {
                feroprobe_core::debug::debug(1, || {
                    format!("Final times for host {addr}: srtt: {srtt} rttvar: {rttvar}  to: {to}")
                });
            }
        }
    }
    let mut untraced = 0;
    if g.trace {
        // Hosts without an open or closed TCP port are traced through a
        // TCP port the command names, or not at all.
        // Hosts given up on by --host-timeout are not traced either.
        let keep: Vec<usize> = (0..hosts.len()).filter(|&i| !hosts[i].timed_out).collect();
        let mut traced: Vec<HostResult> = keep.iter().map(|&i| hosts[i].clone()).collect();
        let done = progress.phase("traceroute", traced.len());
        untraced = traceroute(&mut traced, cfg, !plan.discovery, g.trace_fallback)
            .await
            .context("traceroute failed")?;
        done(&progress);
        for (&i, h) in keep.iter().zip(traced) {
            hosts[i] = h;
        }
    }
    if let Some(engine) = g.scripts.filter(|e| e.has_host_scripts()) {
        // Like nmap, the scripts run last, on the hosts that are up (all
        // of them with -Pn) and were not given up on by --host-timeout.
        let keep: Vec<usize> = (0..hosts.len())
            .filter(|&i| (!plan.discovery || hosts[i].is_up()) && !hosts[i].timed_out)
            .collect();
        if !keep.is_empty() {
            let mut group: Vec<HostResult> = keep.iter().map(|&i| hosts[i].clone()).collect();
            let done = progress.phase("script scan", group.len());
            engine.scan_hosts(&mut group).await;
            done(&progress);
            for (&i, h) in keep.iter().zip(group) {
                hosts[i] = h;
            }
        }
    }
    Ok(untraced)
}

/// `--min-hostgroup` and `--max-hostgroup`, checked as nmap does.
fn hostgroup_limits(args: &Args) -> Result<(usize, usize)> {
    let min = args.min_hostgroup.unwrap_or(groups::DEFAULT_MIN);
    let max = args.max_hostgroup.unwrap_or(groups::DEFAULT_MAX);
    if max == 0 {
        bail!("--max-hostgroup must be at least 1");
    }
    if min > max {
        bail!("--min-hostgroup ({min}) may not be greater than --max-hostgroup ({max})");
    }
    if min > 100 {
        eprintln!("Warning: You specified a highly aggressive --min-hostgroup.");
    }
    Ok((min, max))
}

/// The options `--resume` accepts beside it: `--keep-root`, and the two
/// authorizations, which a recorded one needs given again; given, they apply.
const RESUME_ALSO: [&str; 3] = [
    "--keep-root",
    "--allow-public-evasion",
    "--override-ics-protection",
];

/// `s` with control characters (a terminal's escape sequences among them)
/// shown as `?`, for text from a file that is printed to the terminal.
fn printable(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// `--resume`: drop the targets the aborted run finished, up to and
/// including the last host its report lists, as nmap does.
fn resume_targets(
    path: &str,
    last: Option<IpAddr>,
    targets: &mut Vec<Target>,
    args: &Args,
    outputs: &Outputs,
    progress: Progress,
) {
    if args.randomize_hosts {
        eprintln!(
            "Warning: the scan being resumed used --randomize-hosts, so the targets now come in a different order: \
             some hosts it finished may be scanned again and some it had not reached may be skipped"
        );
    }
    if !outputs.json.is_empty() {
        eprintln!(
            "Warning: the JSON report (-oJ) is written only when a run ends, so it will list only the hosts scanned from here on"
        );
    }
    let Some(last) = last else {
        eprintln!("Warning: {path} lists no finished host, so the scan starts from the beginning");
        return;
    };
    match resume::skip_finished(targets, last) {
        Some(n) => progress.say(0, || {
            format!(
                "Resuming the scan in {path}: skipping {n} target{} up to {last}, already done",
                plural(n)
            )
        }),
        None => {
            // nmap skips every target then too, without saying so.
            eprintln!(
                "Warning: the last host {path} lists, {last}, is not among the targets, so none are left to scan"
            );
            targets.clear();
        }
    }
}

/// The probe order and follow-up steps a dry run lays out.
struct DryOrder<'a> {
    tcp: &'a [u16],
    udp: &'a [u16],
    sctp: &'a [u16],
    protocols: &'a [u8],
    os: bool,
    trace: bool,
    /// See [`trace_fallback_port`].
    trace_fallback: Option<u16>,
    /// The `-sV` settings, to describe its probes.
    version: &'a VersionScan,
    /// `-b`: the FTP relay's address.
    bounce: Option<SocketAddr>,
    /// `--script`: the scripts a real run would run.
    scripts: Option<&'a feroprobe_core::script::ScriptScan>,
}

/// The notes a dry run prints above its probes: what it cannot show (steps
/// that depend on replies) and what a real run of the same command needs.
fn dry_run_notes(args: &Args, plan: &Plan, d: &DryOrder, privileged: bool) -> Vec<String> {
    let mut notes = Vec::new();
    let mut follow = Vec::new();
    if plan.version && !plan.ping_only {
        follow.push("service detection (-sV)");
    }
    if d.trace {
        follow.push("traceroute (--traceroute)");
    }
    if !follow.is_empty() {
        notes.push(format!(
            "Not shown: {} would run on the hosts and open ports the scan finds, so its probes \
             depend on replies a dry run does not get",
            follow.join(", ")
        ));
    }
    if plan.version && !plan.ping_only {
        let tcp = if plan.tcp.is_some() { d.tcp } else { &[] };
        let udp = if plan.udp { d.udp } else { &[] };
        notes.extend(feroprobe_core::service::dry_run_lines(d.version, tcp, udp));
    }
    if d.trace {
        notes.push(match d.trace_fallback {
            Some(port) => format!(
                "Traceroute would send TCP SYNs to an open or closed TCP port the scan finds on \
                 each host, else to TCP port {port}, which this command names"
            ),
            None => format!(
                "Traceroute would use an open or closed TCP port the scan finds; a directly \
                 connected host gets a one-hop trace without probes, and other hosts without \
                 such a port are not traced: {}",
                if plan.ping_only {
                    TRACE_NO_PORT_SN
                } else {
                    TRACE_NO_PORT
                }
            ),
        });
    }
    if let Some(engine) = d.scripts {
        notes.extend(script_dry_run_lines(engine, plan, d));
    }
    if !args.no_resolve {
        notes.push(if plan.list {
            "Not shown: reverse DNS of every target, which is all a list scan does (no DNS query \
             is made)"
                .into()
        } else {
            "Not shown: reverse DNS of the hosts found up (no DNS query is made)".into()
        });
    }
    let raw_scan = plan.tcp.is_some_and(|t| t.raw_kind().is_some())
        || plan.sctp.is_some()
        || plan.ip_proto
        || d.os
        || d.trace;
    if raw_scan && !privileged {
        notes.push(
            "A real run of this scan sends raw packets: run it as root or grant CAP_NET_RAW".into(),
        );
    }
    let explicit_tcp =
        args.scan.iter().any(|s| ScanType::TCP.contains(s)) || args.scanflags.is_some();
    if plan.tcp == Some(ScanType::Connect) && !explicit_tcp && !privileged {
        notes.push(
            "No raw sockets here, so the default TCP scan is a connect scan (-sT); as root it \
             would be a SYN scan (-sS), as in nmap"
                .into(),
        );
    }
    notes
}

/// What a dry run says about `--script`: which scripts would load, when
/// they would run, and where their sockets could go. What they send is
/// not shown: it depends on what the scan finds and on the replies they
/// get.
fn script_dry_run_lines(
    engine: &feroprobe_core::script::ScriptScan,
    plan: &Plan,
    d: &DryOrder,
) -> Vec<String> {
    let list: Vec<String> = engine
        .scripts()
        .iter()
        .map(|s| {
            let forced = if s.forced { ", forced with +" } else { "" };
            format!("{} ({}{forced})", s.id, s.rules.names().join(", "))
        })
        .collect();
    let mut lines = vec![format!(
        "Scripts (--script, -sC or -A) a real run would load: {}",
        list.join(", ")
    )];
    let mut ports = Vec::new();
    let scan = !plan.ping_only;
    if scan && (plan.tcp.is_some() || d.bounce.is_some()) {
        ports.push(format!("{} TCP", d.tcp.len()));
    }
    if scan && plan.udp {
        ports.push(format!("{} UDP", d.udp.len()));
    }
    let scope = if ports.is_empty() {
        "no ports at all, since this scan probes no TCP or UDP port".to_string()
    } else {
        format!(
            "the {} port(s) this scan probes on that host",
            ports.join(" and ")
        )
    };
    lines.push(format!(
        "Not shown: what the scripts send. Their rules pick the hosts and ports they run \
         on from what the scan finds, and what they send depends on the replies they get. \
         A script may connect only to the host it runs against, and only to {scope}; \
         prerule and postrule scripts get no network access"
    ));
    lines
}

/// `--dry-run`: print the probes and stop. Nothing is sent and no report
/// is written, since there are no results to report.
#[allow(clippy::too_many_arguments)]
fn dry_run(
    args: &Args,
    outputs: &Outputs,
    targets: &[Target],
    plan: &Plan,
    probes: &PingProbes,
    cfg: &ScanConfig,
    d: &DryOrder,
) -> Result<()> {
    use feroprobe_core::dryrun::{self, DryDiscovery, DryRun, DryTcp};
    use std::io::Write;
    if outputs.files().next().is_some() {
        eprintln!(
            "Warning: --dry-run sends nothing, so no report is written (-oN/-oX/-oS/-oG/-oJ/-oA ignored)"
        );
    }
    let privileged = raw_sockets_available();
    let tcp = (!plan.ping_only)
        .then_some(plan.tcp)
        .flatten()
        .map(|t| match t.raw_kind() {
            None => DryTcp::Connect,
            Some(kind) => {
                let mut scan = RawTcpScan::new(kind);
                if let Some(flags) = args.scanflags {
                    scan.flags = flags;
                }
                DryTcp::Raw(scan)
            }
        })
        .or(d.bounce.filter(|_| !plan.ping_only).map(DryTcp::Bounce));
    let scan = !plan.ping_only;
    let run = DryRun {
        targets,
        list: plan.list,
        discovery: plan.discovery.then(|| DryDiscovery {
            probes: probes.clone(),
            privileged,
            icmp: feroprobe_core::icmp_available(),
            arp_ping: cfg.arp_ping,
        }),
        pn_neighbours: !plan.discovery
            && !plan.list
            && cfg.arp_ping
            && privileged
            && cfg!(target_os = "linux"),
        tcp: tcp.map(|t| (t, d.tcp)),
        udp: if scan && plan.udp { d.udp } else { &[] },
        sctp: plan.sctp.filter(|_| scan).map(|k| (k, d.sctp)),
        protocols: if scan && plan.ip_proto {
            d.protocols
        } else {
            &[]
        },
        evasion: &cfg.evasion,
        retries: cfg.retries,
        os: (d.os && scan).then(|| os_options(args, plan, probes)),
        source_port: cfg.source_port,
        notes: dry_run_notes(args, plan, d, privileged),
    };
    let stdout = std::io::stdout();
    let mut w = std::io::BufWriter::new(stdout.lock());
    dryrun::write(&run, &mut w)?;
    w.flush()?;
    Ok(())
}

fn main() -> Result<()> {
    let raw: Vec<String> = std::env::args().collect();
    let first = debugging::parse_args(nmap_style_args(raw.clone()));
    // Settings files first, while still root (root's own file may be
    // readable by root only), then give root up before any other file is
    // opened and before the runtime starts its threads.
    let settings = config::load()?;
    let privileges = privdrop::drop_to_invoking_user(first.keep_root)?;
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the async runtime")?
        .block_on(run(raw, first, settings, privileges))
}

async fn run(
    raw: Vec<String>,
    first: Args,
    settings: config::Loaded,
    privileges: privdrop::Outcome,
) -> Result<()> {
    // --resume: the rest of the command line comes from the report.
    let (args, command, resumed) = match &first.resume {
        None => (first, raw, None),
        Some(path) => {
            // Like nmap, --resume takes no other options: the file has them.
            // The exceptions: --keep-root decides, before the report is
            // read, whether root is given up for the resumed run; and the
            // two authorizations are given again (see below).
            let rest: Vec<&String> = raw[1..]
                .iter()
                .filter(|a| !RESUME_ALSO.contains(&a.as_str()))
                .collect();
            let alone = rest.len() == 2 || (rest.len() == 1 && rest[0].starts_with("--resume="));
            if !alone {
                bail!(
                    "--resume cannot be combined with other options (except {}). \
                     Usage: feroprobe [--keep-root] [--allow-public-evasion] \
                     [--override-ics-protection] --resume FILE",
                    RESUME_ALSO.join(", ")
                );
            }
            let r = resume::read(path)?;
            // As nmap: the recorded command line, appending to its reports.
            let mut command = vec![raw[0].clone(), "--append-output".to_string()];
            command.extend(r.args.iter().filter(|a| *a != "--append-output").cloned());
            let mut args = debugging::parse_args(nmap_style_args(command.clone()));
            // Anyone can write a report, so say what is about to run.
            eprintln!(
                "Resuming the scan recorded in {path}: {}",
                printable(&resume::join_quoted(&command))
            );
            // The deliberate opt-ins are not taken from a file: the person
            // resuming gives them again (a nmap divergence).
            for (recorded, given, flag) in [
                (
                    args.allow_public_evasion,
                    first.allow_public_evasion,
                    "--allow-public-evasion",
                ),
                (
                    args.override_ics_protection,
                    first.override_ics_protection,
                    "--override-ics-protection",
                ),
            ] {
                if recorded && !given {
                    bail!(
                        "the scan recorded in {path} was authorized with {flag}; \
                         an authorization is not taken from a file, so give it again \
                         if you mean it: feroprobe {flag} --resume {path}"
                    );
                }
            }
            // An authorization given beside --resume applies to the resumed
            // scan, as it would to the command typed again. The recorded
            // command line (which the report checks compare) is unchanged.
            args.allow_public_evasion |= first.allow_public_evasion;
            args.override_ics_protection |= first.override_ics_protection;
            // Reports mask the FTP relay password, so it cannot be resumed
            // from them: say so rather than log in with "****".
            if args.bounce.as_deref().is_some_and(|b| b.contains(":****@")) {
                bail!(
                    "{path} records an FTP bounce scan (-b) whose relay password FeroProbe \
                     masks in its reports, so it cannot be resumed. Run the scan again \
                     with the password"
                );
            }
            (args, command, Some((path.clone(), r.last)))
        }
    };
    if args.iflist {
        let debug = feroprobe_core::debug::debugging() > 0;
        use feroprobe_core::iflist;
        print!(
            "{}",
            iflist::render(&iflist::interfaces(), &iflist::routes(), debug)
        );
        return Ok(());
    }
    // Settings files (read in main), then the ICS guard: before anything
    // is resolved or sent.
    for w in &settings.warnings {
        eprintln!("Warning: {w}");
    }
    if !args.script_help.is_empty() {
        let chosen = feroprobe_core::script::choose(&args.script_help.join(","))
            .map_err(|e| anyhow::anyhow!("--script-help: {e}"))?;
        print!("{}", feroprobe_core::script::help_text(&chosen));
        return Ok(());
    }
    for w in gate_ics(&settings.settings, &args)? {
        eprintln!("{w}");
    }
    // Load the scripts now, so a bad one fails before anything is sent.
    let scripts = script_scan(&args)?;
    let outputs = Outputs::from_args(&args)?;
    if args.packet_trace {
        feroprobe_core::packet_trace::enable();
    }
    // Like nmap, packet tracing or debugging shows the IPv4 options up
    // front: the bytes (once there is room for an address) and their reading.
    if let Some(o) = args
        .ip_options
        .as_ref()
        .filter(|_| args.packet_trace || feroprobe_core::debug::debugging() > 0)
    {
        let o = &o.0;
        if o.len() >= 8 {
            eprint!(
                "Binary ip options to be sent:\n{}",
                feroprobe_core::packet_opts::hex_ip_options(o)
            );
        }
        eprintln!(
            "Parsed ip options to be sent:\n{}",
            feroprobe_core::packet_opts::describe_ip_options(o)
        );
    }
    // A dry run writes no report, so it does not create the files either.
    let report_files = if args.dry_run {
        ReportFiles::default()
    } else {
        outputs.open_files(resumed.as_ref().map(|_| &command[1..]))?
    };
    let group_limits = hostgroup_limits(&args)?;
    let progress = Progress {
        quiet: false,
        track: true,
    };
    progress.say(1, || {
        let files: Vec<String> = settings
            .files
            .iter()
            .map(|f| f.display().to_string())
            .collect();
        let read = if files.is_empty() {
            "no settings file found".to_string()
        } else {
            format!("settings read from {}", files.join(", "))
        };
        let ics = if settings.settings.ics_protection {
            format!("on ({})", ics_source(&settings.settings))
        } else {
            "off".to_string()
        };
        format!("ICS protection {ics}; {read}")
    });
    if let Some(line) = privileges.describe() {
        progress.say(1, || line);
    }
    if let Some(s) = &scripts {
        let n = s.scripts().len();
        progress.say(1, || {
            format!("Loaded {n} script{} for scanning.", plural(n))
        });
    }
    // --privileged / --unprivileged: before anything checks for raw sockets.
    if args.unprivileged {
        feroprobe_core::assume_privileged(Some(false));
    } else if args.privileged {
        feroprobe_core::assume_privileged(Some(true));
    }
    // -e: every socket from here on is bound to the interface.
    if let Some(name) = &args.interface {
        let ifc = feroprobe_core::netif::use_interface(name).context("-e")?;
        progress.say(1, || {
            format!("Using interface {} (index {})", ifc.name, ifc.index)
        });
    }
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
    // Like nmap, a name that does not resolve is skipped with a warning.
    let resolved = resolve_targets_lenient(&specs, version)
        .await
        .context("resolving targets")?;
    for w in &resolved.warnings {
        eprintln!("{}", nmap_warning(w));
    }
    for note in &resolved.notes {
        progress.say(2, || format!("Warning: {note}"));
    }
    let mut targets = resolved.targets;
    let mut excluded = 0;
    if !exclusions.is_empty() {
        let before = targets.len();
        targets.retain(|t| !exclusions.excludes(t));
        excluded = before - targets.len();
        progress.say(1, || format!("Excluded {} host(s)", before - targets.len()));
    }
    if targets.is_empty() {
        eprintln!("Warning: no targets were left to scan, so 0 hosts scanned.");
    }
    for w in option_warnings(&args, feroprobe_core::connect::open_file_limit()) {
        eprintln!("Warning: {w}");
    }
    if args.randomize_hosts {
        shuffle(&mut targets);
    }
    if let Some((path, last)) = &resumed {
        resume_targets(path, *last, &mut targets, &args, &outputs, progress);
    }
    let any_ipv6 = targets.iter().any(|t| t.addr.is_ipv6());
    let syn_ok = raw_sockets_available() && (!any_ipv6 || raw_ipv6_available());
    // nmap's default probes depend on privileges: raw SYN/ACK plus ICMP
    // echo and timestamp as root, TCP connects otherwise.
    let raw_pings = feroprobe_core::raw_tcp_pings(&targets);
    let skip_discovery = args.ping.contains(&PingArg::Skip);
    let mut plan = plan(&args.scan, skip_discovery, syn_ok, args.scanflags.is_some())?;
    // -sL sends nothing, so its -P options are only warned about (in
    // list_scan_checks), never checked against each other.
    let mut probes = if plan.list {
        PingProbes::none()
    } else {
        ping_probes(&args.ping)?.unwrap_or_else(|| PingProbes::nmap_default(raw_pings))
    };
    if plan.list {
        for w in list_scan_checks(&args)? {
            eprintln!("Warning: {w}");
        }
    } else if args.ping.contains(&PingArg::Arp) {
        eprintln!("Warning: {PR_NOTE}");
    }
    // -b: the FTP bounce scan is a TCP scan of its own, as in nmap.
    let bounce = match &args.bounce {
        Some(spec) => {
            let explicit_tcp = args.scan.iter().any(|t| ScanType::TCP.contains(t));
            if explicit_tcp || args.scanflags.is_some() {
                bail!(
                    "You specified more than one type of TCP scan. Please choose only one of \
                     -sA, -b, -sT, -sF, -sM, -sN, -sS, -sW, and -sX"
                );
            }
            if plan.list {
                bail!("-b is a port scan, so it cannot be combined with -sL");
            }
            if plan.ping_only {
                bail!("-b is a port scan, so it cannot be combined with -sn");
            }
            let relay = feroprobe_core::ftp_bounce::FtpRelay::parse(spec)
                .map_err(|e| anyhow::anyhow!(e))?;
            let addr = tokio::net::lookup_host((relay.server.as_str(), relay.port))
                .await
                .ok()
                .and_then(|mut a| a.find(SocketAddr::is_ipv4))
                .with_context(|| {
                    format!(
                        "Failed to resolve FTP bounce proxy hostname/IP: {}",
                        relay.server
                    )
                })?;
            progress.say(1, || {
                format!(
                    "Resolved FTP bounce attack proxy to {} ({}).",
                    relay.server,
                    addr.ip()
                )
            });
            if let Some(t) = targets.iter().find(|t| t.addr.is_ipv6()) {
                bail!(
                    "the FTP bounce scan (-b) is IPv4 only, but target {} is IPv6",
                    t.addr
                );
            }
            if !args.allow_public_evasion {
                let addrs: Vec<IpAddr> = targets
                    .iter()
                    .map(|t| t.addr)
                    .chain(std::iter::once(addr.ip()))
                    .collect();
                if let Some(public) = feroprobe_core::scope::first_public(&addrs) {
                    bail!(
                        "the FTP bounce scan (-b) is refused against public addresses, but \
                         {public} is a public address (a target or the FTP relay). Pass \
                         --allow-public-evasion to authorize this against targets and a relay \
                         you have permission to use. This is a deliberate FeroProbe safeguard: \
                         see docs/responsible-use.md."
                    );
                }
            }
            // The default TCP scan gives way to the bounce scan.
            plan.tcp = None;
            if plan.discovery {
                eprintln!(
                    "Hint: if your bounce scan target hosts aren't reachable from here, remember \
                     to use -Pn so we don't try and ping them prior to the scan"
                );
            }
            Some((addr, relay))
        }
        None => None,
    };
    if args.defeat_rst_ratelimit && plan.tcp != Some(ScanType::Syn) && !args.open {
        bail!("Option --defeat-rst-ratelimit works only with a SYN scan (-sS)");
    }
    let (mut os, trace) = aggressive(&mut plan, &args, raw_sockets_available())?;
    for w in os_option_warnings(&args, os) {
        eprintln!("Warning: {w}");
    }
    // Read --service-rules now, so a bad file fails before anything is sent.
    let version_scan = version_scan(&args)?;
    if !plan.version
        && let Some(option) = version_option(&args)
    {
        eprintln!("Warning: {option} has no effect without -sV or -A");
    }
    if os {
        if plan.ping_only {
            bail!("-O needs a port scan, so it cannot be combined with -sn");
        }
        if !raw_sockets_available() && !args.dry_run {
            bail!("-O sends raw packets: run as root or grant CAP_NET_RAW");
        }
    }

    let port_scan = plan.tcp.is_some() || bounce.is_some() || plan.udp || plan.sctp.is_some();
    let PortLists {
        tcp: tcp_ports,
        udp: udp_ports,
        sctp: sctp_ports,
        protocols,
    } = port_lists(&args, plan.ip_proto, port_scan)?;
    // -sO's "ports" are IP protocol numbers, 0-255 (validated on parse).
    let protocols: Vec<u8> = protocols.iter().map(|&p| p as u8).collect();
    // Thin the discovery probes by --exclude-ports, read the same way the
    // scan reads -p, so -sO's protocol exclusions (0 among them) parse
    // rather than being rejected as ports. Only TCP/UDP ping ports match.
    if let Some(spec) = &args.exclude_ports {
        let ex =
            parse_port_lists(spec, plan.ip_proto, port_scan).context("reading --exclude-ports")?;
        for w in exclude_ping_ports(&mut probes, &ex) {
            eprintln!("Warning: {w}");
        }
    }
    // After the exclusions: only the probes left need raw sockets.
    if plan.discovery && !plan.list && !args.dry_run {
        raw_ping_check(
            &probes,
            cfg!(target_os = "linux") && raw_sockets_available(),
        )?;
    }
    if plan.ping_only && !plan.list && !plan.discovery && !trace {
        bail!("-sn with -Pn would do nothing (add --traceroute to only trace the route)");
    }
    let trace_fallback = trace_fallback_port(&args, &plan, &tcp_ports, &probes);
    if trace && !raw_sockets_available() && !args.dry_run {
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
        if bounce.is_some() && tcp_ports.is_empty() {
            bail!("the FTP bounce scan (-b) needs TCP ports, but none were given");
        }
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
        if plan.sctp.is_some() && sctp_ports.is_empty() {
            eprintln!(
                "Warning: an SCTP scan was asked for, but no SCTP ports were given; skipping it"
            );
            plan.sctp = None;
        }
        if plan.ip_proto && protocols.is_empty() {
            eprintln!(
                "Warning: an IP protocol scan was asked for, but no protocols were given; skipping it"
            );
            plan.ip_proto = false;
        }
        if plan.tcp.is_none()
            && bounce.is_none()
            && !plan.udp
            && plan.sctp.is_none()
            && !plan.ip_proto
        {
            plan.ping_only = true;
            plan.version = false;
            if os {
                eprintln!("Warning: skipping OS detection, which needs a port scan");
                os = false;
            }
        }
    }
    if settings.settings.ics_protection && !plan.ping_only {
        let tcp: &[u16] = if plan.tcp.is_some() || bounce.is_some() {
            &tcp_ports
        } else {
            &[]
        };
        let udp: &[u16] = if plan.udp { &udp_ports } else { &[] };
        if let Some(w) = ot_port_warning(tcp, udp) {
            eprintln!("Warning: {w}");
        }
    }
    // The order probes go out in; reports keep the sorted lists.
    let (mut tcp_order, mut udp_order) = (tcp_ports.clone(), udp_ports.clone());
    let mut sctp_order = sctp_ports.clone();
    if !args.ordered_ports {
        shuffle(&mut tcp_order);
        shuffle(&mut udp_order);
        shuffle(&mut sctp_order);
    }

    let mut cfg = scan_config(&args);
    for w in apply_min_parallelism(&mut cfg, &args)? {
        eprintln!("Warning: {w}");
    }
    let warnings = apply_min_rate(&mut cfg, &args, feroprobe_core::connect::open_file_limit())?;
    // Evasion options are refused unless every target is private; see
    // gate_evasion. Parsed and checked before the scan sends anything.
    let evasion = evasion_from_args(&args)?;
    gate_evasion(&evasion, &targets, &plan, args.allow_public_evasion)?;
    // Checked after the scope safeguard, so a public address is refused
    // whatever the privileges. A dry run sends nothing and needs none.
    if evasion.is_active() && !args.dry_run && !raw_sockets_available() {
        bail!("evasion options send raw packets: run as root or grant CAP_NET_RAW");
    }
    cfg.evasion = evasion;
    // --data*, --ttl, --ip-options, --badsum: set once for every probe
    // builder, before anything is sent or shown by --dry-run.
    let mut packet_opts = packet_options(&args)?;
    for w in packet_option_warnings(&mut packet_opts, &plan, &targets, raw_sockets_available()) {
        eprintln!("Warning: {w}");
    }
    feroprobe_core::packet_opts::set(packet_opts);
    // Loaded before --spoof-mac, which can name a vendor from this list.
    if let Some(path) = &args.oui_file {
        feroprobe_core::oui::use_file(path)
            .with_context(|| format!("reading OUI list {}", path.display()))?;
    }
    if let Some(arg) = &args.spoof_mac {
        let mac = spoof_mac(arg, &args, &plan, &targets)?;
        feroprobe_core::spoofmac::set(mac);
    }
    if args.system_dns && !args.dns_servers.is_empty() {
        eprintln!("Warning: --system-dns uses the system resolver, so --dns-servers is ignored");
    }
    if let Some(port) = args.source_port {
        let connect = !plan.ping_only && plan.tcp.is_some_and(|t| t.raw_kind().is_none());
        let udp = (!plan.ping_only && plan.udp) || (plan.discovery && !probes.udp.is_empty());
        for w in source_port_warnings(port, connect, udp) {
            eprintln!("Warning: {w}");
        }
    }
    // The warnings are about connect and UDP probes.
    let sockets = !plan.ping_only && (plan.udp || plan.tcp.is_some_and(|t| t.raw_kind().is_none()));
    for w in warnings.iter().filter(|_| sockets) {
        eprintln!("Warning: {w}");
    }

    if args.explain {
        let privileged = raw_sockets_available();
        // As root, targets that are this machine skip discovery, so ARP
        // and the ping probes only see the others.
        let (localhost, others): (Vec<Target>, Vec<Target>) = targets
            .iter()
            .cloned()
            .partition(|t| privileged && feroprobe_core::is_localhost(t.addr));
        let facts = explain::Facts {
            targets: &targets,
            excluded,
            plan: &plan,
            probes: &probes,
            privileged,
            icmp: feroprobe_core::icmp_available(),
            raw_pings,
            localhost: localhost.len(),
            local: if plan.discovery && privileged && cfg.arp_ping {
                explain::local_targets(&others)
            } else {
                Default::default()
            },
            tcp_ports: if plan.tcp.is_some() || bounce.is_some() {
                &tcp_ports
            } else {
                &[]
            },
            bounce: bounce
                .as_ref()
                .map(|(addr, relay)| format!("{}:{} ({})", relay.server, relay.port, addr.ip())),
            udp_ports: if plan.udp { &udp_ports } else { &[] },
            sctp_ports: if plan.sctp.is_some() {
                &sctp_ports
            } else {
                &[]
            },
            protocols: if plan.ip_proto { &protocols } else { &[] },
            cfg: &cfg,
            os,
            trace,
        };
        for line in explain::explain(&args, &facts) {
            eprintln!("{line}");
        }
    }

    if args.dry_run {
        return dry_run(
            &args,
            &outputs,
            &targets,
            &plan,
            &probes,
            &cfg,
            &DryOrder {
                tcp: &tcp_order,
                udp: &udp_order,
                sctp: &sctp_order,
                protocols: &protocols,
                os,
                trace,
                trace_fallback,
                version: &version_scan,
                bounce: bounce.as_ref().map(|(a, _)| *a),
                scripts: scripts.as_ref(),
            },
        );
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
    feroprobe_core::debug::debug(1, || {
        debugging::timing_report(&cfg, group_limits.0, group_limits.1, args.host_timeout)
    });
    // Keys typed while the scan runs (v/V, d/D, p/P, ?, status).
    let keys = if args.noninteractive {
        None
    } else {
        keys::start(started)
    };
    let job = ScanJob {
        plan: &plan,
        tcp: &tcp_order,
        udp: &udp_order,
        sctp: &sctp_order,
        protocols: &protocols,
        scanflags: args.scanflags,
        version: version_scan.clone(),
        os,
        os_opts: os_options(&args, &plan, &probes),
        bounce: bounce.clone(),
    };
    let mut scan_types = if plan.list {
        vec!["list"]
    } else if plan.ping_only {
        vec!["ping"]
    } else {
        job.scan_types()
    };
    if trace {
        scan_types.push("traceroute");
    }
    let ports_per_host = plan
        .tcp
        .or(bounce.as_ref().map(|_| ScanType::Connect))
        .map_or(0, |_| tcp_ports.len())
        + if plan.udp { udp_ports.len() } else { 0 }
        + plan.sctp.map_or(0, |_| sctp_ports.len())
        + if plan.ip_proto { protocols.len() } else { 0 };
    let group_facts = groups::GroupFacts {
        tcp_ports: plan
            .tcp
            .filter(|_| !plan.ping_only)
            .map(|_| tcp_ports.len()),
        udp: plan.udp && !plan.ping_only,
        sctp: plan.sctp.is_some() && !plan.ping_only,
        timing_level: cfg.timing_level,
        min: group_limits.0,
        max: group_limits.1,
    };
    let mut info = RunInfo {
        // The password of an FTP bounce relay is masked in the reports.
        args: resume::join_quoted(&redact_args(
            command.iter().cloned(),
            bounce.as_ref().map(|(_, relay)| relay.pass.as_str()),
        )),
        start: start_time,
        scan_types,
        tcp_ports: if (plan.tcp.is_some() || bounce.is_some()) && !plan.ping_only {
            tcp_ports
        } else {
            Vec::new()
        },
        udp_ports: if plan.udp { udp_ports } else { Vec::new() },
        sctp_ports: if plan.sctp.is_some() {
            sctp_ports
        } else {
            Vec::new()
        },
        protocols: if plan.ip_proto {
            protocols.iter().map(|&p| u16::from(p)).collect()
        } else {
            Vec::new()
        },
        ports_per_host,
        elapsed: Duration::ZERO,
        only_open: args.open,
        show_reason: args.reason || feroprobe_core::debug::debugging() > 0,
        show_version: plan.version,
        show_os: os,
        os_guess: args.osscan_guess,
        show_trace: trace,
        assume_up: !plan.discovery,
        ping_only: plan.ping_only,
        list_scan: plan.list,
        nmap_label: args.nmap_label,
        defeat_rst: cfg.defeat_rst_ratelimit && plan.tcp.is_some(),
        verbosity: feroprobe_core::debug::verbosity(),
        stylesheet: xml::stylesheet(args.stylesheet.as_deref(), args.webxml, args.no_stylesheet),
    };
    let mut reports = report::Reports::new(resumed.is_some(), report_files);
    if !outputs.stdout_taken() {
        reports.add(report::Kind::Format(args.output), None);
    }
    for (kind, paths) in [
        (report::Kind::Format(Format::Table), &outputs.normal),
        (report::Kind::Format(Format::Xml), &outputs.xml),
        (report::Kind::Format(Format::Grepable), &outputs.grep),
        (report::Kind::Format(Format::Json), &outputs.json),
        (report::Kind::Skid, &outputs.skid),
    ] {
        for path in paths {
            reports.add(kind, Some(path).filter(|p| *p != "-").cloned());
        }
    }
    reports.start(&info)?;
    if let Some(engine) = &scripts {
        let pre = engine.pre_scan().await;
        reports.run_scripts(report::RunScripts::Pre, &pre)?;
    }

    // Like nmap: discovery takes the targets a batch at a time, and the
    // hosts are then scanned and reported a group at a time.
    let ping_group = groups::PING_GROUP.max(group_limits.0);
    let mut done_hosts = 0;
    let mut untraced = 0;
    for batch in targets.chunks(ping_group) {
        let mut hosts: Vec<HostResult> = if plan.list {
            // -sL: nothing goes to the targets, not even ARP.
            batch
                .iter()
                .map(|t| HostResult::new(t.addr, t.hostname.clone()))
                .collect()
        } else if plan.discovery {
            let done = progress.phase("host discovery", batch.len());
            let hosts = discover(batch, &cfg, &probes)
                .await
                .context("host discovery failed")?;
            done(&progress);
            let up = hosts.iter().filter(|h| h.is_up()).count();
            progress.say(1, || {
                format!("{up} of {} host{} up", hosts.len(), plural(hosts.len()))
            });
            hosts
        } else {
            // -Pn: every target is scanned, but those on a local network are
            // still asked for their MAC address, as in nmap.
            feroprobe_core::discovery::neighbours_only(batch, &cfg)
                .await
                .context("ARP or neighbour discovery failed")?
        };
        let mut from = 0;
        while from < batch.len() {
            // The group: the next `size` hosts to scan, with the hosts
            // found down among them.
            let size = groups::scan_group_size(done_hosts, &group_facts);
            let (mut to, mut n) = (from, 0);
            while to < batch.len() && n < size {
                if !plan.discovery || hosts[to].is_up() {
                    n += 1;
                }
                to += 1;
            }
            let group_start = SystemTime::now();
            untraced += scan_group(
                &batch[from..to],
                &mut hosts[from..to],
                &GroupRun {
                    args: &args,
                    plan: &plan,
                    cfg: &cfg,
                    job: &job,
                    trace,
                    trace_fallback,
                    progress,
                    scripts: scripts.as_ref(),
                },
            )
            .await?;
            info.elapsed = started.elapsed();
            // The keys (v/V, d/D) may have changed the levels meanwhile.
            info.verbosity = feroprobe_core::debug::verbosity();
            info.show_reason = args.reason || feroprobe_core::debug::debugging() > 0;
            reports.group(&hosts[from..to], &info, group_start, SystemTime::now())?;
            done_hosts += to - from;
            from = to;
        }
    }
    if untraced > 0 {
        // A directly connected host needs no port (it gets no probes),
        // so only the hosts further away are left untraced.
        let why = if plan.ping_only {
            TRACE_NO_PORT_SN
        } else {
            TRACE_NO_PORT
        };
        eprintln!(
            "Warning: {untraced} host{} not traced: {why}",
            if untraced == 1 { "" } else { "s" }
        );
    }

    if let Some(task) = stats {
        task.abort();
    }
    if let Some(k) = keys {
        k.stop();
    }
    if let Some(engine) = &scripts {
        let post = engine.post_scan().await;
        reports.run_scripts(report::RunScripts::Post, &post)?;
    }
    info.elapsed = started.elapsed();
    reports.finish(&info)?;
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
    fn sctp_and_ip_protocol_scans() {
        let y = p(&[ScanType::SctpInit], false, true).unwrap();
        assert_eq!(y.sctp, Some(SctpScanKind::Init));
        // An explicit -sY does not pull in a default TCP scan.
        assert_eq!((y.tcp, y.udp, y.ip_proto), (None, false, false));
        let o = p(&[ScanType::IpProto], false, true).unwrap();
        assert!(o.ip_proto && o.tcp.is_none());
        // -sS and -sO run side by side.
        let both = p(&[ScanType::Syn, ScanType::IpProto], false, true).unwrap();
        assert_eq!((both.tcp, both.ip_proto), (Some(ScanType::Syn), true));
        assert!(p(&[ScanType::SctpInit, ScanType::SctpCookie], false, true).is_err());
    }

    #[test]
    fn rejects_conflicts() {
        assert!(p(&[ScanType::Syn, ScanType::Connect], false, true).is_err());
        assert!(p(&[ScanType::PingOnly, ScanType::Udp], false, true).is_err());
        assert!(p(&[ScanType::PingOnly, ScanType::Version], false, true).is_err());
    }

    #[test]
    fn nmap_tuning_names() {
        let parse = |args: &[&str]| {
            let mut v = vec!["feroprobe"];
            v.extend_from_slice(args);
            v.push("10.0.0.1");
            Args::try_parse_from(v)
        };
        let a = parse(&["--max-retries", "4"]).unwrap();
        assert_eq!(scan_config(&a).retries, 4);
        for flag in ["-c", "-M", "--concurrency", "--max-parallelism"] {
            let a = parse(&[flag, "7"]).unwrap();
            assert_eq!(scan_config(&a).concurrency, 7, "{flag}");
        }
        // nmap: the argument to -M must be at least 1.
        assert!(parse(&["-M", "0"]).is_err());
        assert!(parse(&["--min-parallelism", "0"]).is_err());

        // --min-parallelism raises the template's parallelism...
        let a = parse(&["-T2", "--min-parallelism", "40"]).unwrap();
        let mut cfg = scan_config(&a);
        assert!(apply_min_parallelism(&mut cfg, &a).unwrap().is_empty());
        assert_eq!(cfg.concurrency, 40);
        // ... never lowers it ...
        let a = parse(&["--min-parallelism", "3"]).unwrap();
        let mut cfg = scan_config(&a);
        apply_min_parallelism(&mut cfg, &a).unwrap();
        assert_eq!(cfg.concurrency, ScanConfig::default().concurrency);
        // ... warns when very high, like nmap ...
        let a = parse(&["--min-parallelism", "150"]).unwrap();
        let mut cfg = scan_config(&a);
        assert_eq!(apply_min_parallelism(&mut cfg, &a).unwrap().len(), 1);
        // ... and may not exceed an explicit maximum.
        let a = parse(&["--min-parallelism", "20", "--max-parallelism", "10"]).unwrap();
        let mut cfg = scan_config(&a);
        let e = apply_min_parallelism(&mut cfg, &a).unwrap_err().to_string();
        assert!(e.contains("--min-parallelism=20"), "{e}");
    }

    #[test]
    fn interface_and_source_port_options() {
        let a = Args::try_parse_from(["feroprobe", "-e", "eth0", "-g", "53", "10.0.0.1"]).unwrap();
        assert_eq!(a.interface.as_deref(), Some("eth0"));
        assert_eq!(scan_config(&a).source_port, Some(53));
        let a = Args::try_parse_from(["feroprobe", "--source-port", "20", "10.0.0.1"]).unwrap();
        assert_eq!(a.source_port, Some(20));
        assert!(Args::try_parse_from(["feroprobe", "-g", "70000", "10.0.0.1"]).is_err());
        assert_eq!(
            scan_config(&Args::try_parse_from(["feroprobe", "x"]).unwrap()).source_port,
            None
        );

        let w = source_port_warnings(53, true, false);
        assert!(w.len() == 1 && w[0].contains("connect scan"), "{w:?}");
        let w = source_port_warnings(0, false, true);
        assert!(w.len() == 1 && w[0].contains("UDP"), "{w:?}");
        if cfg!(windows) {
            assert_eq!(source_port_warnings(53, false, true).len(), 1);
            return;
        }
        assert!(source_port_warnings(53, false, true).is_empty());
        let w = source_port_warnings(0, false, false);
        assert!(w.len() == 1 && !w[0].contains("UDP"), "{w:?}");
    }

    #[test]
    fn rtt_timeout_options() {
        let ms = Duration::from_millis;
        let cfg = |args: &[&str]| {
            let mut all = vec!["feroprobe"];
            all.extend_from_slice(args);
            all.push("10.0.0.1");
            scan_config(&Args::try_parse_from(all).unwrap()).rtt
        };
        // The defaults and the templates are nmap's.
        assert_eq!(cfg(&[]), RttTimeouts::default());
        assert_eq!(cfg(&["-T5"]), Timing::Insane.rtt_timeouts());
        // A bare number is seconds, as in nmap.
        assert_eq!(cfg(&["--initial-rtt-timeout", "2"]).initial, ms(2000));
        // Each moves the others like nmap's setters, applied in nmap's
        // order (initial, min, max) whatever the command-line order.
        let r = cfg(&[
            "--max-rtt-timeout",
            "200ms",
            "--initial-rtt-timeout",
            "500ms",
        ]);
        assert_eq!((r.min, r.max, r.initial), (ms(100), ms(200), ms(200)));
        let r = cfg(&["-T4", "--min-rtt-timeout", "2s"]);
        assert_eq!((r.min, r.max, r.initial), (ms(2000), ms(2000), ms(2000)));
        // --timeout fixes all three; the RTT options still apply on top.
        assert_eq!(
            cfg(&["-T5", "--timeout", "800"]),
            RttTimeouts::fixed(ms(800))
        );
        let r = cfg(&["--timeout", "800", "--max-rtt-timeout", "2s"]);
        assert_eq!((r.min, r.max, r.initial), (ms(800), ms(2000), ms(800)));
        // nmap's checks.
        let bad = |args: &[&str]| {
            let mut all = vec!["feroprobe"];
            all.extend_from_slice(args);
            all.push("10.0.0.1");
            Args::try_parse_from(all).is_err()
        };
        assert!(bad(&["--max-rtt-timeout", "4ms"]));
        assert!(bad(&["--initial-rtt-timeout", "0"]));
        assert!(bad(&["--min-rtt-timeout", "60000"]));
        assert!(!bad(&["--min-rtt-timeout", "60000ms"]));
        let a =
            Args::try_parse_from(["feroprobe", "--max-rtt-timeout", "10ms", "10.0.0.1"]).unwrap();
        assert!(
            option_warnings(&a, None)
                .iter()
                .any(|w| w.contains("--max-rtt-timeout of 10 ms"))
        );
        // --min-rate reaches the congestion windows.
        let a = Args::try_parse_from(["feroprobe", "--min-rate", "300", "10.0.0.1"]).unwrap();
        assert_eq!(scan_config(&a).min_rate, 300);
    }

    #[test]
    fn timing_templates_and_overrides() {
        let a = Args::try_parse_from(["feroprobe", "-T4", "10.0.0.1"]).unwrap();
        assert_eq!(a.timing, Some(Timing::Aggressive));
        // Like nmap, a repeated -T is not an error: the last one wins.
        let b = Args::try_parse_from(["feroprobe", "-T2", "-T4", "10.0.0.1"]).unwrap();
        assert_eq!(b.timing, Some(Timing::Aggressive));
        let cfg = scan_config(&a);
        assert_eq!(cfg.concurrency, Timing::Aggressive.config().concurrency);
        assert_eq!(cfg.rtt, Timing::Aggressive.config().rtt);
        assert_eq!(cfg.timing_level, 4);

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
        assert_eq!(cfg.rtt, RttTimeouts::fixed(Duration::from_millis(800)));
        assert_eq!(cfg.scan_delay, Duration::from_millis(250));
        assert_eq!(cfg.retries, Timing::Sneaky.config().retries);

        // No -T means the normal template, which is the old default.
        let a = Args::try_parse_from(["feroprobe", "10.0.0.1"]).unwrap();
        let (cfg, d) = (scan_config(&a), ScanConfig::default());
        assert_eq!(
            (
                cfg.rtt,
                cfg.concurrency,
                cfg.retries,
                cfg.max_rate,
                cfg.scan_delay
            ),
            (d.rtt, d.concurrency, d.retries, d.max_rate, d.scan_delay)
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
        let a = Args::try_parse_from(["feroprobe", "-sZ", "10.0.0.1"]).unwrap();
        assert_eq!(a.scan, vec![ScanType::SctpCookie]);
        let a = Args::try_parse_from(["feroprobe", "-sO", "10.0.0.1"]).unwrap();
        assert_eq!(a.scan, vec![ScanType::IpProto]);
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
        // Combined scan letters, as nmap reads them; anything else stays.
        assert_eq!(
            nmap_style_args(argv(&["feroprobe", "-sCV", "-sSU", "-sn", "-sQZ", "x"])),
            argv(&["feroprobe", "-sC", "-sV", "-sS", "-sU", "-sn", "-sQZ", "x"])
        );
        let a = Args::parse_from(nmap_style_args(argv(&["feroprobe", "-sCV", "x"])));
        assert_eq!(a.scan, [ScanType::Scripts, ScanType::Version]);
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
    fn output_extras_options() {
        let parse = |v: &[&str]| Args::parse_from(nmap_style_args(v.iter().map(|s| s.to_string())));
        let a = parse(&["feroprobe", "-oS", "k.txt", "--append-output", "10.0.0.1"]);
        let o = Outputs::from_args(&a).unwrap();
        assert_eq!(o.skid, vec!["k.txt".to_string()]);
        assert!(o.append);
        assert!(Outputs::from_args(&parse(&["feroprobe", "-oS", "-", "-oX", "-", "x"])).is_err());
        // The last stylesheet option wins, as in nmap.
        let sheet = |v: &[&str]| {
            let a = parse(v);
            xml::stylesheet(a.stylesheet.as_deref(), a.webxml, a.no_stylesheet)
        };
        assert_eq!(
            sheet(&["feroprobe", "--webxml", "--stylesheet", "s.xsl", "x"]).as_deref(),
            Some("s.xsl")
        );
        assert_eq!(
            sheet(&["feroprobe", "--stylesheet", "s.xsl", "--webxml", "x"]).as_deref(),
            Some(xml::WEB_STYLESHEET)
        );
        assert_eq!(
            sheet(&["feroprobe", "--stylesheet", "s.xsl", "--no-stylesheet", "x"]),
            None
        );
        assert_eq!(
            sheet(&[
                "feroprobe",
                "--no-stylesheet",
                "--stylesheet",
                "a",
                "--stylesheet",
                "b",
                "x"
            ])
            .as_deref(),
            Some("b")
        );
    }

    /// A fresh directory private to this user, for tests that write files.
    fn private_dir(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("feroprobe-{tag}-{}-{nanos}", std::process::id()));
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut std::fs::DirBuilder::new(), 0o700)
            .create(&dir)
            .unwrap();
        #[cfg(not(unix))]
        std::fs::DirBuilder::new().create(&dir).unwrap();
        dir
    }

    #[test]
    fn reports_replace_or_append() {
        let dir = private_dir("append");
        let path = dir.join("r.txt");
        let name = path.display().to_string();
        std::fs::write(&path, "a much longer old report\n").unwrap();
        let outputs = |append| Outputs {
            normal: vec![name.clone()],
            append,
            ..Default::default()
        };
        // Opening keeps the old report until the new one is written.
        let mut files = outputs(false).open_files(None).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "a much longer old report\n"
        );
        files.write(&name, "new\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new\n");
        drop(files);
        let mut files = outputs(true).open_files(None).unwrap();
        files.write(&name, "more\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new\nmore\n");
        // The handle opened up front is what gets written, even if the
        // path is replaced in the meantime.
        std::fs::rename(&path, dir.join("moved")).unwrap();
        files.write(&name, "last\n").unwrap();
        assert!(!path.exists());
        assert_eq!(
            std::fs::read_to_string(dir.join("moved")).unwrap(),
            "new\nmore\nlast\n"
        );
        // Not a regular file: written as it is, not emptied first.
        #[cfg(unix)]
        {
            let null = Outputs {
                normal: vec!["/dev/null".into()],
                ..Default::default()
            };
            let mut files = null.open_files(None).unwrap();
            files.write("/dev/null", "report\n").unwrap();
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// As root, a report is not written through someone else's link, nor
    /// through any link in a directory others can write to; a link root
    /// owns in a root-only directory works. A file root creates under sudo
    /// goes to the invoking user.
    #[cfg(unix)]
    #[test]
    fn report_links_are_refused_as_root() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let dir = private_dir("rootlinks");
        let target = dir.join("target");
        std::fs::write(&target, "keep").unwrap();
        let open = |p: &std::path::Path| {
            Outputs {
                normal: vec![p.display().to_string()],
                ..Default::default()
            }
            .open_files(None)
        };
        let lchown = |p: &std::path::Path, uid: u32| {
            let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
            // SAFETY: c is a valid NUL-terminated path.
            assert_eq!(unsafe { libc::lchown(c.as_ptr(), uid, u32::MAX) }, 0);
        };
        // Root's link in root's private directory: allowed.
        let link = dir.join("own.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(open(&link).is_ok());
        // Someone else's link, even there: refused.
        lchown(&link, 65534);
        let err = open(&link).err().unwrap().to_string();
        assert!(err.contains("owned by another user"), "{err}");
        // Root's own link in a shared sticky directory: refused.
        let shared = dir.join("shared");
        std::fs::create_dir(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o1777)).unwrap();
        let link = shared.join("scan.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = open(&link).err().unwrap().to_string();
        assert!(err.contains("other users can write to"), "{err}");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
        // A directory link in the path is held to the same rule: someone
        // else's link to a directory is refused, root's own in a private
        // directory is followed.
        let real = dir.join("realdir");
        std::fs::create_dir(&real).unwrap();
        let sub = shared.join("sub");
        std::os::unix::fs::symlink(&real, &sub).unwrap();
        lchown(&sub, 65534);
        let err = open(&sub.join("r.txt")).err().unwrap().to_string();
        assert!(err.contains("owned by another user"), "{err}");
        assert!(!real.join("r.txt").exists());
        let own = dir.join("ownsub");
        std::os::unix::fs::symlink(&real, &own).unwrap();
        assert!(open(&own.join("r.txt")).is_ok());
        assert!(real.join("r.txt").exists());
        // Root's approved link whose target runs through someone else's
        // link: the nested link is checked too, and refused.
        let victim_dir = dir.join("victimdir");
        std::fs::create_dir(&victim_dir).unwrap();
        let redirect = shared.join("redirect");
        std::os::unix::fs::symlink(&victim_dir, &redirect).unwrap();
        lchown(&redirect, 65534);
        let current = dir.join("current");
        std::os::unix::fs::symlink(&redirect, &current).unwrap();
        let err = open(&current.join("hosts")).err().unwrap().to_string();
        assert!(err.contains("owned by another user"), "{err}");
        assert!(!victim_dir.join("hosts").exists());
        // The same as the report file itself.
        let file_link = shared.join("file-redirect");
        std::os::unix::fs::symlink(&target, &file_link).unwrap();
        lchown(&file_link, 65534);
        let current_file = dir.join("current-file");
        std::os::unix::fs::symlink(&file_link, &current_file).unwrap();
        assert!(open(&current_file).is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
        // A path or link target ending in "/" names a directory, not the
        // regular file before it.
        let important = dir.join("important");
        std::fs::write(&important, "keep").unwrap();
        assert!(open(std::path::Path::new(&format!("{}/", important.display()))).is_err());
        let slash = dir.join("slash");
        std::os::unix::fs::symlink(format!("{}/", important.display()), &slash).unwrap();
        assert!(open(&slash).is_err());
        assert_eq!(std::fs::read_to_string(&important).unwrap(), "keep");
        // A directory link to "/." still resolves from "/", not from the
        // link's own directory.
        let to_root = dir.join("to-root");
        std::os::unix::fs::symlink("/.", &to_root).unwrap();
        let rel = dir.strip_prefix("/").unwrap().join("via-root.txt");
        assert!(open(&to_root.join(&rel)).is_ok());
        assert!(dir.join("via-root.txt").exists());
        assert!(!dir.join(&rel).exists());
        // /dev/stdout is root's link in root's /dev.
        if std::path::Path::new("/dev/stdout").is_symlink() {
            assert!(open(std::path::Path::new("/dev/stdout")).is_ok());
        }
        // A new file is handed to SUDO_UID/SUDO_GID; tests run in threads,
        // so this reads the variables only if the environment has them.
        if let Some((uid, gid)) = privdrop::sudo_ids() {
            let new = dir.join("new.txt");
            open(&new).unwrap();
            let m = std::fs::metadata(&new).unwrap();
            assert_eq!((m.uid(), m.gid()), (uid, gid));
        }
        let _ = std::fs::remove_dir_all(&dir);
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
            assert!(o.open_files(None).is_err());
            let hard = dir.join("hard");
            std::fs::hard_link(&plain, &hard).unwrap();
            assert!(
                out(&hard, std::path::Path::new(&plain))
                    .open_files(None)
                    .is_err()
            );
            assert!(out(&dir.join("a"), &dir.join("b")).open_files(None).is_ok());
        }
        // Windows file systems ignore case: report and REPORT are one file.
        #[cfg(windows)]
        {
            let o = Outputs {
                normal: vec![dir.join("report").display().to_string()],
                xml: vec![dir.join("REPORT").display().to_string()],
                ..Default::default()
            };
            assert!(o.open_files(None).is_err());
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
        assert!(args(&["feroprobe", "-PZ", "x"]).is_err());
        assert!(args(&["feroprobe", "-PS70000", "x"]).is_err());
    }

    #[test]
    fn sctp_protocol_and_arp_pings() {
        let args = |v: &[&str]| Args::try_parse_from(v.iter().copied());
        let a = args(&[
            "feroprobe",
            "-PY",
            "-PY2905,80",
            "-PO",
            "-PO6,17",
            "-PR",
            "x",
        ])
        .unwrap();
        assert_eq!(
            a.ping,
            vec![
                PingArg::Sctp(vec![80]),
                PingArg::Sctp(vec![80, 2905]),
                PingArg::Proto(vec![1, 2, 4]),
                PingArg::Proto(vec![6, 17]),
                PingArg::Arp,
            ]
        );
        let p = ping_probes(&a.ping).unwrap().unwrap();
        assert_eq!(p.sctp, vec![80, 2905]);
        assert_eq!(p.proto, vec![1, 2, 4, 6, 17]);
        assert!(p.needs_raw() && !p.echo && p.syn.is_empty());
        // -PR alone picks no probe, so the defaults stay, as in nmap; it
        // goes with -Pn too.
        assert_eq!(ping_probes(&[PingArg::Arp]).unwrap(), None);
        assert_eq!(ping_probes(&[PingArg::Skip, PingArg::Arp]).unwrap(), None);
        // Protocol 0 is a valid -PO protocol; 256 is not.
        assert_eq!(
            args(&["feroprobe", "-PO0", "x"]).unwrap().ping,
            vec![PingArg::Proto(vec![0])]
        );
        assert!(args(&["feroprobe", "-PO256", "x"]).is_err());
        assert!(args(&["feroprobe", "-PR80", "x"]).is_err());
        assert!(args(&["feroprobe", "-PY0", "x"]).is_err());

        // Without raw sockets, -PY and -PO are refused, never dropped.
        assert!(raw_ping_check(&p, true).is_ok());
        assert!(raw_ping_check(&PingProbes::default(), false).is_ok());
        let e = raw_ping_check(&p, false).unwrap_err().to_string();
        assert!(e.contains("-PY"), "{e}");
        let only_proto = PingProbes {
            proto: vec![1],
            ..PingProbes::none()
        };
        let e = raw_ping_check(&only_proto, false).unwrap_err().to_string();
        assert!(e.contains("-PO"), "{e}");

        // --exclude-ports thins them too: S: ports and P: protocols.
        let ex = parse_port_lists("S:80,P:2", false, true).unwrap();
        let mut probes = PingProbes {
            sctp: vec![80],
            proto: vec![1, 2],
            ..PingProbes::none()
        };
        let w = exclude_ping_ports(&mut probes, &ex);
        assert_eq!((probes.sctp.len(), probes.proto.clone()), (0, vec![1]));
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("SCTP"), "{w:?}");
    }

    #[test]
    fn list_scan() {
        use ScanType::*;
        let pl = plan(&[List], false, true, false).unwrap();
        assert!(pl.list && pl.ping_only && !pl.discovery);
        assert_eq!(pl.tcp, None);
        // -sn may ride along, as in nmap; scan types may not.
        assert!(plan(&[List, PingOnly], false, true, false).unwrap().list);
        for other in [Syn, Connect, Udp, Version, IpProto, SctpInit] {
            let e = plan(&[List, other], false, true, false).unwrap_err();
            assert!(e.to_string().contains(other.flag()), "{e}");
        }
        assert!(plan(&[List], false, true, true).is_err());

        let args = |v: &[&str]| {
            let mut all = vec!["feroprobe", "-sL"];
            all.extend_from_slice(v);
            all.push("10.0.0.1");
            Args::try_parse_from(all).unwrap()
        };
        assert!(list_scan_checks(&args(&[])).unwrap().is_empty());
        assert!(list_scan_checks(&args(&["-Pn", "-n"])).unwrap().is_empty());
        for bad in [
            &["-p", "80"][..],
            &["-F"],
            &["--top-ports", "10"],
            &["-O"],
            &["-A"],
            &["--traceroute"],
            &["--script", "banner"],
        ] {
            assert!(list_scan_checks(&args(bad)).is_err(), "{bad:?}");
        }
        // -P options are ignored, with a warning each.
        let w = list_scan_checks(&args(&["-PE", "-PS22", "-PS80", "-PR"])).unwrap();
        assert_eq!(w.len(), 3, "{w:?}");
        assert!(w[0].contains("-PE is ignored"), "{w:?}");
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

    fn plan_with_tcp(tcp: Option<ScanType>) -> Plan {
        Plan {
            tcp,
            udp: false,
            sctp: None,
            ip_proto: false,
            version: false,
            ping_only: false,
            discovery: true,
            list: false,
        }
    }

    #[test]
    fn packet_options_from_the_command_line() {
        let o = packet_options(&args(&[])).unwrap();
        assert!(!o.is_active());
        let o = packet_options(&args(&["--data", "0xdead", "--ttl", "9", "--badsum"])).unwrap();
        assert_eq!(o.data.as_deref(), Some(&[0xde, 0xad][..]));
        assert_eq!((o.ttl, o.badsum), (Some(9), true));
        let o = packet_options(&args(&["--data-string", "hi"])).unwrap();
        assert_eq!(o.data.as_deref(), Some(&b"hi"[..]));
        let o = packet_options(&args(&["--data-length", "7"])).unwrap();
        assert_eq!(o.data.map(|d| d.len()), Some(7));
        let o = packet_options(&args(&["--ip-options", "R"])).unwrap();
        assert_eq!(o.ip_options.len(), 40);
        // Like nmap: one data option at most, and sane values.
        let bad = |v: &[&str]| {
            let mut all = vec!["feroprobe"];
            all.extend_from_slice(v);
            all.push("10.0.0.1");
            Args::try_parse_from(all).is_err()
        };
        assert!(bad(&["--data", "01", "--data-string", "x"]));
        assert!(bad(&["--data-string", "x", "--data-length", "1"]));
        assert!(bad(&["--data", "xyz"]));
        assert!(bad(&["--data-length", "70000"]));
        assert!(bad(&["--ttl", "256"]));
        assert!(bad(&["--ip-options", "Q"]));
        // The last of --privileged and --unprivileged wins.
        let a = args(&["--privileged", "--unprivileged"]);
        assert!(a.unprivileged && !a.privileged);
    }

    #[test]
    fn relay_password_is_masked_in_reports() {
        let a = |v: &[&str]| redact_args(v.iter().map(|s| s.to_string()), None).join(" ");
        assert_eq!(
            a(&["feroprobe", "-b", "bob:s3cret@ftp.lan:2121", "10.0.0.1"]),
            "feroprobe -b bob:****@ftp.lan:2121 10.0.0.1"
        );
        assert_eq!(a(&["feroprobe", "-bbob:x@ftp"]), "feroprobe -bbob:****@ftp");
        assert_eq!(a(&["feroprobe", "-b", "ftp.lan"]), "feroprobe -b ftp.lan");
        assert_eq!(a(&["feroprobe", "-sS", "a@b"]), "feroprobe -sS a@b");
        // Grouped short options: masked by the relay's own password.
        let g = |v: &[&str]| redact_args(v.iter().map(|s| s.to_string()), Some("s3cret")).join(" ");
        assert_eq!(
            g(&["feroprobe", "-vb", "bob:s3cret@ftp.lan", "10.0.0.1"]),
            "feroprobe -vb bob:****@ftp.lan 10.0.0.1"
        );
        assert_eq!(
            g(&["feroprobe", "-vbbob:s3cret@ftp"]),
            "feroprobe -vbbob:****@ftp"
        );
    }

    #[test]
    fn packet_option_warnings_name_what_is_not_honored() {
        let t = |s: &str| Target {
            addr: s.parse().unwrap(),
            hostname: None,
        };
        let mut o = feroprobe_core::PacketOptions {
            badsum: true,
            data: Some(vec![0; 1500]),
            ip_options: vec![1, 1, 1, 1],
            ..Default::default()
        };
        let w = packet_option_warnings(
            &mut o,
            &plan_with_tcp(Some(ScanType::Connect)),
            &[t("10.0.0.1"), t("fd00::1")],
            false,
        );
        let all = w.join("\n");
        assert!(all.contains("1400 bytes"), "{all}");
        assert!(all.contains("TCP connect scan"), "{all}");
        assert!(all.contains("--badsum needs raw sockets"), "{all}");
        assert!(all.contains("fd00::1"), "{all}");
        // An unhonoured --badsum is dropped, so the dry run does not claim it.
        assert!(!o.badsum);
        let mut o = feroprobe_core::PacketOptions {
            ttl: Some(3),
            ..Default::default()
        };
        assert!(
            packet_option_warnings(
                &mut o,
                &plan_with_tcp(Some(ScanType::Syn)),
                &[t("10.0.0.1")],
                true
            )
            .is_empty()
        );
    }

    #[test]
    fn evasion_parsing() {
        assert!(!evasion_from_args(&args(&[])).unwrap().is_active());
        assert_eq!(
            evasion_from_args(&args(&["-f"])).unwrap().fragment,
            Some(Fragment::Eight)
        );
        assert_eq!(
            evasion_from_args(&args(&["--mtu", "16"])).unwrap().fragment,
            Some(Fragment::Mtu(16))
        );
        assert!(evasion_from_args(&args(&["--mtu", "15"])).is_err());
        assert!(evasion_from_args(&args(&["--mtu", "0"])).is_err());
        let ev = evasion_from_args(&args(&["-D", "10.0.0.5,ME,10.0.0.6"])).unwrap();
        assert_eq!(ev.decoys.len(), 2); // ME is a position marker, not a decoy
        assert!(evasion_from_args(&args(&["-D", "not-an-ip"])).is_err());
        assert_eq!(
            evasion_from_args(&args(&["-S", "10.1.2.3"]))
                .unwrap()
                .spoof_source,
            Some("10.1.2.3".parse().unwrap())
        );
        assert!(evasion_from_args(&args(&["-S", "nope"])).is_err());
    }

    #[test]
    fn evasion_gate_refuses_out_of_scope() {
        let ev = evasion_from_args(&args(&["-f"])).unwrap();
        let syn = plan_with_tcp(Some(ScanType::Syn));

        // A public target is refused by the safeguard without the opt-in,
        // whatever the privileges, and the message points to the flag.
        let public = [Target::new("8.8.8.8".parse().unwrap())];
        let err = gate_evasion(&ev, &public, &syn, false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("public address"), "{err}");
        assert!(err.contains("--allow-public-evasion"), "{err}");

        // A public decoy or spoofed source is refused too, even when the
        // target itself is private: it would make the target answer a
        // public host.
        let private = [Target::new("10.0.0.1".parse().unwrap())];
        let public_decoy = evasion_from_args(&args(&["-D", "8.8.8.8"])).unwrap();
        let err = gate_evasion(&public_decoy, &private, &syn, false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("public address"), "{err}");
        let public_source = evasion_from_args(&args(&["-S", "8.8.8.8"])).unwrap();
        let err = gate_evasion(&public_source, &private, &syn, false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("public address"), "{err}");

        // An IPv6 target is refused as IPv4-only, flag or no flag.
        let v6 = [Target::new("fd00::1".parse().unwrap())];
        let err = gate_evasion(&ev, &v6, &syn, true).unwrap_err().to_string();
        assert!(err.contains("IPv4 only"), "{err}");

        // A connect scan cannot carry evasion, flag or no flag.
        let connect = plan_with_tcp(Some(ScanType::Connect));
        let err = gate_evasion(&ev, &private, &connect, true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("raw TCP scan"), "{err}");

        // No evasion flags: the gate is a no-op even for a public target.
        assert!(gate_evasion(&Evasion::default(), &public, &syn, false).is_ok());
    }

    #[test]
    fn evasion_gate_public_needs_authorization_flag() {
        let ev = evasion_from_args(&args(&["-f"])).unwrap();
        let syn = plan_with_tcp(Some(ScanType::Syn));
        let public = [Target::new("8.8.8.8".parse().unwrap())];

        // With --allow-public-evasion the scope safeguard no longer refuses a
        // public target. (The privilege check is separate, in main, so a dry
        // run can skip it.)
        assert!(gate_evasion(&ev, &public, &syn, true).is_ok());
    }

    #[test]
    fn evasion_gate_allows_private_targets() {
        let ev = evasion_from_args(&args(&["-f"])).unwrap();
        let syn = plan_with_tcp(Some(ScanType::Syn));
        let private = [
            Target::new("10.0.0.1".parse().unwrap()),
            Target::new("192.168.1.5".parse().unwrap()),
        ];
        // A private target clears the safeguard without the opt-in flag.
        assert!(gate_evasion(&ev, &private, &syn, false).is_ok());
    }

    #[test]
    fn version_intensity_last_one_wins() {
        let level = |argv: &[&str]| version_intensity(&args(argv));
        assert_eq!(level(&["-sV"]), 7);
        assert_eq!(level(&["-sV", "--version-light"]), 2);
        assert_eq!(
            level(&["-sV", "--version-all", "--version-intensity", "4"]),
            4
        );
        assert_eq!(
            level(&["-sV", "--version-intensity", "4", "--version-all"]),
            9
        );
        assert_eq!(level(&["-sV", "--version-all", "--version-light"]), 2);
        assert!(Args::try_parse_from(["feroprobe", "--version-intensity", "10", "x"]).is_err());
        assert_eq!(
            version_option(&args(&["--version-trace"])),
            Some("--version-trace")
        );
        assert_eq!(version_option(&args(&["-sV"])), None);
        let to_stderr = |argv: &[&str]| version_scan(&args(argv)).unwrap().trace_to_stderr;
        assert!(!to_stderr(&["-sV", "--version-trace"]));
        assert!(to_stderr(&["-sV", "--version-trace", "-o", "json"]));
        assert!(to_stderr(&["-sV", "--version-trace", "-oX", "-"]));
        assert!(!to_stderr(&["-sV", "--version-trace", "-oN", "-"]));
    }

    fn dry_order() -> DryOrder<'static> {
        static VERSION: std::sync::LazyLock<VersionScan> =
            std::sync::LazyLock::new(|| VersionScan::new(Duration::from_secs(3)));
        DryOrder {
            tcp: &[80],
            udp: &[],
            sctp: &[],
            protocols: &[],
            os: false,
            trace: false,
            trace_fallback: Some(80),
            version: &VERSION,
            bounce: None,
            scripts: None,
        }
    }

    #[test]
    fn traceroute_never_falls_back_outside_the_scan() {
        let root = PingProbes::nmap_default(true);
        let tcp = plan_with_tcp(Some(ScanType::Syn));
        // A TCP scan: its first port, never a port it does not scan.
        let a = args(&["--traceroute", "-p", "502,102"]);
        assert_eq!(trace_fallback_port(&a, &tcp, &[102, 502], &root), Some(102));
        // A UDP-only scan: the discovery SYN port (443 as root), which the
        // command probes anyway.
        let mut udp = plan_with_tcp(None);
        udp.udp = true;
        let a = args(&["-sU", "-p", "53", "--traceroute"]);
        assert_eq!(trace_fallback_port(&a, &udp, &[53], &root), Some(443));
        // ... and with -Pn, no TCP port at all: not traced (was port 80).
        udp.discovery = false;
        assert_eq!(trace_fallback_port(&a, &udp, &[53], &root), None);
        // ICMP-only discovery probes no TCP port either.
        udp.discovery = true;
        let icmp = PingProbes {
            echo: true,
            ..PingProbes::none()
        };
        assert_eq!(trace_fallback_port(&a, &udp, &[53], &icmp), None);
        // -sn: -p names the port, else the discovery ports.
        let mut sn = plan_with_tcp(None);
        sn.ping_only = true;
        let a = args(&["-sn", "--traceroute", "-p", "443"]);
        assert_eq!(trace_fallback_port(&a, &sn, &[443], &root), Some(443));
        let a = args(&["-sn", "--traceroute", "-PA22"]);
        let ack = PingProbes {
            ack: vec![22],
            ..PingProbes::none()
        };
        assert_eq!(trace_fallback_port(&a, &sn, &[1, 2, 3], &ack), Some(22));
        // -sn -Pn without -p: nothing to trace through.
        sn.discovery = false;
        let a = args(&["-sn", "-Pn", "--traceroute"]);
        assert_eq!(trace_fallback_port(&a, &sn, &[80], &root), None);
    }

    #[test]
    fn dry_run_says_where_traceroute_goes() {
        let plan = plan_with_tcp(Some(ScanType::Syn));
        let d = DryOrder {
            trace: true,
            trace_fallback: Some(102),
            ..dry_order()
        };
        let notes = dry_run_notes(&args(&["-n"]), &plan, &d, true).join("\n");
        assert!(notes.contains("TCP port 102"), "{notes}");
        let d = DryOrder {
            trace: true,
            trace_fallback: None,
            ..dry_order()
        };
        let notes = dry_run_notes(&args(&["-n"]), &plan, &d, true).join("\n");
        assert!(notes.contains("not traced"), "{notes}");
    }

    #[test]
    fn dry_run_flag_and_notes() {
        let a = args(&["--dry-run", "-sV", "-n"]);
        assert!(a.dry_run);
        let syn = plan_with_tcp(Some(ScanType::Syn));
        let mut plan = plan_with_tcp(Some(ScanType::Syn));
        plan.version = true;
        let d = DryOrder {
            os: true,
            trace: true,
            ..dry_order()
        };
        let notes = dry_run_notes(&a, &plan, &d, false).join("\n");
        // Steps that need replies are named, not listed probe by probe.
        assert!(notes.contains("service detection (-sV)"), "{notes}");
        // The -sV probes are described, at the intensity in use.
        assert!(notes.contains("-sV (intensity 7"), "{notes}");
        assert!(notes.contains("http on 80"), "{notes}");
        // OS detection is listed probe by probe (with port placeholders).
        assert!(!notes.contains("OS detection (-O)"), "{notes}");
        assert!(notes.contains("traceroute"), "{notes}");
        // -n: no reverse DNS to mention.
        assert!(!notes.contains("reverse DNS"), "{notes}");
        // Unprivileged: the real run of a raw scan needs root.
        assert!(notes.contains("CAP_NET_RAW"), "{notes}");
        // Privileged: no such warning.
        let notes = dry_run_notes(&args(&["--dry-run"]), &syn, &dry_order(), true).join("\n");
        assert!(!notes.contains("CAP_NET_RAW"), "{notes}");
        assert!(notes.contains("reverse DNS"), "{notes}");
        // The unprivileged default is explained.
        let connect = plan_with_tcp(Some(ScanType::Connect));
        let notes = dry_run_notes(&args(&["--dry-run"]), &connect, &dry_order(), false).join("\n");
        assert!(notes.contains("SYN scan (-sS)"), "{notes}");
        let notes =
            dry_run_notes(&args(&["--dry-run", "-sT"]), &connect, &dry_order(), false).join("\n");
        assert!(!notes.contains("SYN scan (-sS)"), "{notes}");
    }

    #[test]
    fn port_selection() {
        let lists = |argv: &[&str]| port_lists(&args(argv), false, true).unwrap();
        let fast = lists(&["-F"]);
        assert_eq!((fast.tcp.len(), fast.udp.len()), (100, 100));
        let default = lists(&[]);
        assert_eq!((default.tcp.len(), default.udp.len()), (1000, 1000));
        let l = lists(&["-p", "22,U:53,161,T:80"]);
        assert_eq!((l.tcp, l.udp), (vec![22, 80], vec![22, 53, 161]));
        let l = lists(&["-p", "20-25,U:50-55", "--exclude-ports", "21-23,U:53"]);
        assert_eq!(l.tcp, vec![20, 24, 25]);
        assert_eq!(l.udp, vec![20, 24, 25, 50, 51, 52, 54, 55]);
        let l = lists(&["--top-ports", "10", "--exclude-ports", "T:80"]);
        assert!(!l.tcp.contains(&80) && l.tcp.len() == 9, "{:?}", l.tcp);
        // S: (SCTP) and P: (IP protocols) are valid now.
        let l = lists(&["-p", "T:22,S:2905,P:1,6"]);
        assert_eq!(l.tcp, vec![22]);
        assert_eq!(l.sctp, vec![2905]);
        assert_eq!(l.protocols, vec![1, 6]);
        assert!(port_lists(&args(&["-p", "P:300"]), false, true).is_err());
        // -sO reads unprefixed -p as IP protocol numbers (0-255): 0 and "-"
        // are valid, 300 is not, and a cast must never wrap it into range.
        let proto = |p: &str| port_lists(&args(&["-sO", "-p", p]), true, false);
        assert_eq!(proto("0").unwrap().protocols, vec![0]);
        assert_eq!(proto("-").unwrap().protocols.len(), 256);
        assert!(proto("300").is_err());
        // --exclude-ports reads protocol numbers (0 included) under -sO,
        // rather than rejecting 0 as an unscannable port.
        let l = port_lists(
            &args(&["-sO", "-p", "1,6", "--exclude-ports", "0,6"]),
            true,
            false,
        )
        .unwrap();
        assert_eq!(l.protocols, vec![1]);
        // --exclude-ports also thins the discovery probes, like nmap.
        let ex = parse_port_lists("80,U:53", false, true).unwrap();
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
        // 1000 probes/s with 1.5 s timeouts needs 1500 in flight (on
        // Windows, whose connect tries wait at least 3 s, 3000).
        let (cfg, w) = tuned(&["--min-rate", "1000", "--timeout", "1500"], None).unwrap();
        assert_eq!(cfg.concurrency, if cfg!(windows) { 3000 } else { 1500 });
        assert_eq!(cfg.max_rate, None);
        assert!(w.is_empty());
        let (cfg, w) = tuned(&["--min-rate", "9000", "--timeout", "100"], Some(1024)).unwrap();
        if cfg!(windows) {
            // 27000 needed: capped by the open-file limit, with a warning.
            assert_eq!((cfg.max_rate, cfg.concurrency), (None, 960));
            assert_eq!(w.len(), 1, "{w:?}");
        } else {
            assert_eq!((cfg.max_rate, cfg.concurrency), (None, 900));
            assert!(w.is_empty());
        }
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
        // An explicit --max-scan-delay below the template's delay then holds.
        let (cfg, _) = tuned(
            &["-T2", "--min-rate", "100", "--max-scan-delay", "10ms"],
            None,
        )
        .unwrap();
        assert_eq!(cfg.max_scan_delay, Duration::from_millis(10));
        assert_eq!(cfg.max_udp_scan_delay, Duration::from_millis(10));
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
            max_rate: Some(max_rate),
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
            sctp: None,
            ip_proto: false,
            version: false,
            ping_only: false,
            list: false,
            discovery: false,
        };
        let job = ScanJob {
            plan: &plan,
            tcp: &[open],
            udp: &[],
            sctp: &[],
            protocols: &[],
            scanflags: None,
            version: VersionScan::new(Duration::from_secs(1)),
            os: false,
            os_opts: OsOptions::default(),
            bounce: None,
        };
        let target = Target {
            addr: "127.0.0.1".parse().unwrap(),
            hostname: None,
        };
        let quiet = Progress {
            quiet: true,
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
            scripts: Vec::new(),
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

    fn ics(on: bool) -> config::Settings {
        config::Settings {
            ics_protection: on,
            ics_protection_source: on.then(|| std::path::PathBuf::from(".feroproberc")),
            ics_built_in: false,
        }
    }

    fn argv(a: &[&str]) -> Args {
        let mut v = vec!["feroprobe"];
        v.extend_from_slice(a);
        Args::try_parse_from(v).unwrap()
    }

    #[test]
    fn ics_protection_off_by_default_runs_everything() {
        let off = config::Settings::default();
        assert!(!off.ics_protection);
        for a in [&["-sV"][..], &["-O"], &["-A"], &["-sS", "-sV", "-O"]] {
            let mut a = a.to_vec();
            a.push("10.0.0.1");
            assert!(gate_ics(&off, &argv(&a)).unwrap().is_empty(), "{a:?}");
        }
    }

    #[test]
    fn ics_protection_blocks_hostile_options() {
        for (opts, named) in [
            (&["-sV"][..], "-sV"),
            (&["-O"], "-O"),
            (&["-A"], "-A"),
            (&["-sS", "-sV", "-O"], "-sV, -O"),
            (&["--script", "banner"], "--script"),
            (&["-sV", "--script=safe"], "-sV, --script"),
            (&["-sC"], "-sC"),
            (&["-sC", "--script", "banner"], "-sC, --script"),
        ] {
            let mut a = opts.to_vec();
            a.push("10.0.0.1");
            let err = gate_ics(&ics(true), &argv(&a)).unwrap_err().to_string();
            assert!(err.contains(&format!("so {named} is refused")), "{err}");
            assert!(err.contains("--override-ics-protection"), "{err}");
            assert!(err.contains(".feroproberc"), "{err}");
        }
    }

    #[test]
    fn ics_protection_allows_plain_scans() {
        for opts in [&["-sS"][..], &["-sT", "-sU"], &["-sn"], &["--traceroute"]] {
            let mut a = opts.to_vec();
            a.push("10.0.0.1");
            assert!(gate_ics(&ics(true), &argv(&a)).unwrap().is_empty(), "{a:?}");
        }
    }

    #[test]
    fn ics_dry_run_with_scripts_warns() {
        let a = argv(&["--script", "banner", "--dry-run", "10.0.0.1"]);
        let lines = gate_ics(&ics(true), &a).unwrap();
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].contains("a real run with --script would be refused"),
            "{}",
            lines[0]
        );
        // --script-help sends nothing and is never refused.
        let a = argv(&["--script-help", "banner"]);
        assert!(gate_ics(&ics(true), &a).unwrap().is_empty());
    }

    #[test]
    fn script_options() {
        // --script adds up; --script-help needs no target.
        let a = argv(&["--script", "banner", "--script=safe,+x", "10.0.0.1"]);
        assert_eq!(a.script, ["banner", "safe,+x"]);
        let a = argv(&["--script-help", "banner"]);
        assert_eq!(a.script_help, ["banner"]);
        assert!(Args::try_parse_from(["feroprobe", "--script", "banner"]).is_err());

        let engine = script_scan(&argv(&["--script", "banner", "10.0.0.1"]))
            .unwrap()
            .unwrap();
        assert_eq!(engine.scripts()[0].id, "banner");
        assert_eq!(engine.timeout, None);
        let t = |extra: &[&str]| {
            let mut a = vec!["--script", "banner"];
            a.extend_from_slice(extra);
            a.push("10.0.0.1");
            script_scan(&argv(&a)).unwrap().unwrap().timeout
        };
        assert_eq!(
            t(&["--script-timeout", "30s"]),
            Some(Duration::from_secs(30))
        );
        assert_eq!(t(&["--script-timeout", "0"]), None);
        // -T5 sets ten minutes, as in nmap; --script-timeout still wins.
        assert_eq!(t(&["-T5"]), Some(INSANE_SCRIPT_TIMEOUT));
        assert_eq!(
            t(&["-T5", "--script-timeout", "1m"]),
            Some(Duration::from_secs(60))
        );
        assert_eq!(t(&["-T4"]), None);

        let e = script_scan(&argv(&["--script", "nosuch", "10.0.0.1"])).unwrap_err();
        assert!(e.to_string().contains("'nosuch' did not match"), "{e}");
        let e = script_scan(&argv(&[
            "--script",
            "banner",
            "--script-args",
            "a={b",
            "10.0.0.1",
        ]))
        .unwrap_err();
        assert!(e.to_string().contains("--script-args did not parse"), "{e}");
        assert!(
            script_scan(&argv(&["--script-args", "a=1", "10.0.0.1"]))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn default_scripts_from_sc_and_aggressive() {
        let ids = |a: &[&str]| -> Vec<String> {
            let mut v = a.to_vec();
            v.push("10.0.0.1");
            script_scan(&argv(&v))
                .unwrap()
                .map(|e| e.scripts().iter().map(|s| s.id.clone()).collect())
                .unwrap_or_default()
        };
        let defaults = ids(&["-sC"]);
        assert!(defaults.contains(&"ssh-hostkey".to_string()), "{defaults:?}");
        assert!(!defaults.contains(&"banner".to_string()), "{defaults:?}");
        // -A includes -sC, as in nmap; --script adds to it.
        assert_eq!(ids(&["-A"]), defaults);
        assert_eq!(ids(&["-sC", "-A"]), defaults);
        let both = ids(&["-sC", "--script", "banner"]);
        assert_eq!(both.len(), defaults.len() + 1);
        assert!(both.contains(&"banner".to_string()));
        assert!(ids(&["-sV"]).is_empty());
        // Script arguments count as used with -sC.
        assert!(
            script_scan(&argv(&["-sC", "--script-args", "a=1", "10.0.0.1"]))
                .unwrap()
                .is_some()
        );
        // -sC is no scan type: it leaves the default scan in place and
        // rides along with -sn, but a list scan refuses it.
        let a = argv(&["-sC", "10.0.0.1"]);
        let pl = plan(&a.scan, false, true, false).unwrap();
        assert_eq!(pl.tcp, Some(ScanType::Syn));
        let a = argv(&["-sn", "-sC", "10.0.0.1"]);
        assert!(plan(&a.scan, false, true, false).unwrap().ping_only);
        let a = argv(&["-sU", "-sC", "10.0.0.1"]);
        let pl = plan(&a.scan, false, true, false).unwrap();
        assert!(pl.udp && pl.tcp.is_none());
        let a = argv(&["-sL", "-sC", "10.0.0.1"]);
        let e = plan(&a.scan, false, true, false).unwrap_err().to_string();
        assert!(e.contains("cannot be combined with -sC"), "{e}");
    }

    #[test]
    fn dry_run_lists_scripts_and_their_scope() {
        let engine = script_scan(&argv(&["--script", "banner", "10.0.0.1"]))
            .unwrap()
            .unwrap();
        let plan = plan_with_tcp(Some(ScanType::Connect));
        let d = DryOrder {
            scripts: Some(&engine),
            ..dry_order()
        };
        let notes = dry_run_notes(&args(&["-n"]), &plan, &d, true).join("\n");
        assert!(notes.contains("would load: banner (portrule)"), "{notes}");
        assert!(
            notes.contains("only to the 1 TCP port(s) this scan probes"),
            "{notes}"
        );
    }

    #[test]
    fn ics_override_runs_with_a_warning() {
        let a = argv(&["-A", "--override-ics-protection", "10.0.0.1"]);
        let lines = gate_ics(&ics(true), &a).unwrap();
        assert!(
            lines
                .iter()
                .any(|l| l.contains("running -A although ICS protection is on"))
        );
        assert!(lines.iter().all(|l| l.starts_with("WARNING:")));
        // Nothing to override: one note, no block.
        let a = argv(&["-sS", "--override-ics-protection", "10.0.0.1"]);
        assert!(gate_ics(&ics(true), &a).unwrap().is_empty());
        let lines = gate_ics(&ics(false), &a).unwrap();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("has no effect"));
    }

    #[test]
    fn ics_dry_run_previews_with_a_warning() {
        let a = argv(&["--dry-run", "-sV", "-O", "10.0.0.1"]);
        let lines = gate_ics(&ics(true), &a).unwrap();
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].starts_with("Warning: ICS protection is on"),
            "{}",
            lines[0]
        );
        assert!(
            lines[0].contains("a real run with -sV, -O would be refused"),
            "{}",
            lines[0]
        );
        assert!(
            lines[0].contains("--override-ics-protection"),
            "{}",
            lines[0]
        );
        // Protection off: a dry run is as quiet as any other run.
        assert!(gate_ics(&ics(false), &a).unwrap().is_empty());
        // The same command without --dry-run is still refused.
        assert!(gate_ics(&ics(true), &argv(&["-sV", "-O", "10.0.0.1"])).is_err());
        // With the override too, the override's warning applies.
        let a = argv(&["--dry-run", "-A", "--override-ics-protection", "10.0.0.1"]);
        let lines = gate_ics(&ics(true), &a).unwrap();
        assert!(lines.iter().any(|l| l.contains("running -A although")));
    }

    #[test]
    fn built_in_ics_protection_names_the_build() {
        let built = config::Settings {
            ics_protection: true,
            ics_protection_source: None,
            ics_built_in: true,
        };
        let err = gate_ics(&built, &argv(&["-sV", "10.0.0.1"]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("(built into this FeroProbe)"), "{err}");
        let a = argv(&["-sV", "--override-ics-protection", "10.0.0.1"]);
        assert!(!gate_ics(&built, &a).unwrap().is_empty());
    }

    #[test]
    fn ot_ports_warn_by_protocol() {
        assert_eq!(ot_port_warning(&[22, 80, 443], &[53]), None);
        let w = ot_port_warning(&[22, 502, 102], &[47808]).unwrap();
        assert!(
            w.contains("102/tcp S7comm, 502/tcp Modbus, 47808/udp BACnet"),
            "{w}"
        );
        // BACnet is UDP: a TCP 47808 is no hit; Modbus is TCP only.
        assert_eq!(ot_port_warning(&[47808], &[502]), None);
        let w = ot_port_warning(&[20000, 44818], &[20000]).unwrap();
        assert!(
            w.contains("20000/tcp DNP3, 20000/udp DNP3, 44818/tcp EtherNet/IP"),
            "{w}"
        );
    }
}
