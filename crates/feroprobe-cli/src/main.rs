//! `feroprobe`: an nmap-style network scanner, written natively in Rust.

mod output;

use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::{Parser, ValueEnum};
use feroprobe_core::{
    HostResult, ScanConfig, Target, connect_scan, discover, parse_ports, raw_sockets_available,
    resolve_targets, syn_scan, top_ports, top_udp_ports, udp_scan,
};

use output::RunInfo;

/// Windows only reports "connection refused" about 2s after the reset, so a
/// shorter timeout would show closed ports as filtered there.
const DEFAULT_TIMEOUT_MS: u64 = if cfg!(windows) { 3000 } else { 1500 };

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ScanType {
    /// -sS: TCP SYN scan (raw sockets, needs root; default when root on Linux)
    #[value(name = "S")]
    Syn,
    /// -sT: TCP connect scan (no privileges needed)
    #[value(name = "T")]
    Connect,
    /// -sU: UDP scan
    #[value(name = "U")]
    Udp,
    /// -sn: host discovery only, no port scan
    #[value(name = "n")]
    PingOnly,
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
}

/// Fast, native network scanner with an nmap-style command line.
///
/// Examples:
///   feroprobe 192.168.1.0/24
///   sudo feroprobe -sS -p 1-65535 10.0.0.5
///   feroprobe -sT -sU -p 53,123,161 scanme.example.org
///   feroprobe -sn 192.168.1.0/24
///   feroprobe -Pn --top-ports 1000 --open -o json 10.0.0.1-50
#[derive(Debug, Parser)]
#[command(version, verbatim_doc_comment)]
struct Args {
    /// Targets: IP addresses, CIDR blocks (10.0.0.0/24), ranges (10.0.0.1-20) or hostnames
    #[arg(required = true)]
    targets: Vec<String>,

    /// Scan technique, nmap style: -sS (SYN), -sT (connect), -sU (UDP), -sn (no port scan).
    /// Can be repeated, e.g. -sS -sU. Default: -sS when run as root on Linux with only IPv4 targets, else -sT
    #[arg(
        short = 's',
        value_name = "TYPE",
        value_enum,
        hide_possible_values = true
    )]
    scan: Vec<ScanType>,

    /// -Pn: skip host discovery and scan every target as if it were up
    #[arg(short = 'P', value_name = "n", value_enum, hide_possible_values = true)]
    ping: Option<PingMode>,

    /// Ports to scan, e.g. "22", "1-1024", "22,80,443", "-" for all
    #[arg(short = 'p', long, conflicts_with = "top_ports")]
    ports: Option<String>,

    /// Scan the N most common ports (default 100 for TCP, 20 for UDP)
    #[arg(long, value_name = "N")]
    top_ports: Option<usize>,

    /// Per-probe timeout in milliseconds [default: 1500, or 3000 on Windows]
    #[arg(long, value_name = "MS", default_value_t = DEFAULT_TIMEOUT_MS, hide_default_value = true)]
    timeout: u64,

    /// Maximum connect/UDP probes in flight at once
    #[arg(short = 'c', long, value_name = "N", default_value_t = 500)]
    concurrency: usize,

    /// Maximum packets per second for raw-socket probes (SYN, ICMP)
    #[arg(long, value_name = "PPS", default_value_t = 5000)]
    max_rate: u32,

    /// Extra attempts for probes that get no answer
    #[arg(long, value_name = "N", default_value_t = 1)]
    retries: u32,

    /// Only show open (and open|filtered) ports
    #[arg(long)]
    open: bool,

    /// Show why each port got its state (syn-ack, reset, port-unreach, ...)
    #[arg(long)]
    reason: bool,

    /// Output format
    #[arg(short = 'o', long, value_enum, default_value_t = Format::Table)]
    output: Format,
}

/// What to run, after applying nmap's defaults to the flags.
#[derive(Debug, PartialEq, Eq)]
struct Plan {
    tcp: Option<ScanType>,
    udp: bool,
    ping_only: bool,
    discovery: bool,
}

/// `syn_ok` says whether a SYN scan can serve as the default: the process is
/// privileged and every target is IPv4 (the SYN scan is IPv4 only for now).
fn plan(scan: &[ScanType], ping: Option<PingMode>, syn_ok: bool) -> Result<Plan> {
    let has = |t| scan.contains(&t);
    if has(ScanType::Syn) && has(ScanType::Connect) {
        bail!("choose one TCP scan type: -sS or -sT");
    }
    let ping_only = has(ScanType::PingOnly);
    if ping_only && scan.len() > 1 {
        bail!("-sn (no port scan) cannot be combined with other scan types");
    }
    if ping_only && ping.is_some() {
        bail!("-sn with -Pn would do nothing");
    }
    let tcp = if has(ScanType::Syn) {
        Some(ScanType::Syn)
    } else if has(ScanType::Connect) {
        Some(ScanType::Connect)
    } else if scan.is_empty() {
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
        ping_only,
        discovery: ping.is_none(),
    })
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
    let targets = resolve_targets(&args.targets)
        .await
        .context("resolving targets")?;
    let all_ipv4 = targets.iter().all(|t| t.addr.is_ipv4());
    let plan = plan(&args.scan, args.ping, all_ipv4 && raw_sockets_available())?;

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

    let cfg = ScanConfig {
        timeout: Duration::from_millis(args.timeout),
        concurrency: args.concurrency,
        retries: args.retries,
        max_rate: args.max_rate,
    };

    let started = Instant::now();
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

        match plan.tcp {
            Some(ScanType::Syn) => {
                scan_types.push("tcp-syn");
                let r = syn_scan(&live, &tcp_ports, &cfg)
                    .await
                    .context("SYN scan failed")?;
                merge(&mut hosts, &scanned, r);
            }
            Some(_) => {
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
    } else {
        scan_types.push("ping");
    }

    let ports_per_host =
        plan.tcp.map_or(0, |_| tcp_ports.len()) + if plan.udp { udp_ports.len() } else { 0 };
    let info = RunInfo {
        scan_types,
        ports_per_host,
        elapsed: started.elapsed(),
        only_open: args.open,
        show_reason: args.reason,
        assume_up: !plan.discovery,
        ping_only: plan.ping_only,
    };
    match args.output {
        Format::Table => output::print_table(&hosts, &info),
        Format::Json => output::print_json(&hosts, &info)?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(scan: &[ScanType], ping: Option<PingMode>, syn_ok: bool) -> Result<Plan> {
        plan(scan, ping, syn_ok)
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
    fn rejects_conflicts() {
        assert!(p(&[ScanType::Syn, ScanType::Connect], None, true).is_err());
        assert!(p(&[ScanType::PingOnly, ScanType::Udp], None, true).is_err());
        assert!(p(&[ScanType::PingOnly], Some(PingMode::Skip), true).is_err());
    }

    #[test]
    fn nmap_style_flags_parse() {
        let a = Args::try_parse_from(["feroprobe", "-sS", "-sU", "-Pn", "-p", "22", "10.0.0.1"])
            .unwrap();
        assert_eq!(a.scan, vec![ScanType::Syn, ScanType::Udp]);
        assert_eq!(a.ping, Some(PingMode::Skip));
        let a = Args::try_parse_from(["feroprobe", "-sn", "10.0.0.0/24"]).unwrap();
        assert_eq!(a.scan, vec![ScanType::PingOnly]);
        assert!(Args::try_parse_from(["feroprobe", "-sX", "10.0.0.1"]).is_err());
    }
}
