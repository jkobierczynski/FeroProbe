//! `feroprobe`: an nmap-style network scanner, written natively in Rust.

mod output;

use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::{Parser, ValueEnum};
use feroprobe_core::{ScanConfig, connect_scan, parse_ports, resolve_targets, top_ports};

/// Windows only reports "connection refused" about 2s after the reset, so a
/// shorter timeout would show closed ports as filtered there.
const DEFAULT_TIMEOUT_MS: u64 = if cfg!(windows) { 3000 } else { 1500 };

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Format {
    /// Human-readable table, like nmap's normal output
    Table,
    /// Machine-readable JSON
    Json,
}

/// Fast, native TCP port scanner.
///
/// Examples:
///   feroprobe 192.168.1.0/24
///   feroprobe -p 22,80,443,8000-8100 scanme.example.org
///   feroprobe --top-ports 1000 --open -o json 10.0.0.1-50
#[derive(Debug, Parser)]
#[command(version, verbatim_doc_comment)]
struct Args {
    /// Targets: IP addresses, CIDR blocks (10.0.0.0/24), ranges (10.0.0.1-20) or hostnames
    #[arg(required = true)]
    targets: Vec<String>,

    /// Ports to scan, e.g. "22", "1-1024", "22,80,443", "-" for all
    #[arg(short = 'p', long, conflicts_with = "top_ports")]
    ports: Option<String>,

    /// Scan the N most common ports (default when -p is not given)
    #[arg(long, value_name = "N", default_value_t = 100)]
    top_ports: usize,

    /// Per-connection timeout in milliseconds [default: 1500, or 3000 on Windows]
    #[arg(long, value_name = "MS", default_value_t = DEFAULT_TIMEOUT_MS, hide_default_value = true)]
    timeout: u64,

    /// Maximum connection attempts in flight at once
    #[arg(short = 'c', long, value_name = "N", default_value_t = 500)]
    concurrency: usize,

    /// Extra attempts for ports that time out
    #[arg(long, value_name = "N", default_value_t = 1)]
    retries: u32,

    /// Only show open ports
    #[arg(long)]
    open: bool,

    /// Output format
    #[arg(short = 'o', long, value_enum, default_value_t = Format::Table)]
    output: Format,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let ports = match &args.ports {
        Some(spec) => parse_ports(spec)?,
        None => top_ports(args.top_ports),
    };
    if ports.is_empty() {
        bail!("no ports to scan");
    }

    let targets = resolve_targets(&args.targets)
        .await
        .context("resolving targets")?;

    let cfg = ScanConfig {
        timeout: Duration::from_millis(args.timeout),
        concurrency: args.concurrency,
        retries: args.retries,
    };

    let started = Instant::now();
    let hosts = connect_scan(&targets, &ports, &cfg, |_, _| {})
        .await
        .context("scan aborted (try a lower --concurrency)")?;
    let elapsed = started.elapsed();

    match args.output {
        Format::Table => output::print_table(&hosts, ports.len(), elapsed, args.open),
        Format::Json => output::print_json(&hosts, elapsed, args.open)?,
    }
    Ok(())
}
