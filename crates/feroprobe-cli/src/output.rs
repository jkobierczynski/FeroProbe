//! Rendering scan results.

use std::time::{Duration, SystemTime};

use anyhow::Result;
use feroprobe_core::{HostResult, PortResult, PortState, service_name};
use serde::Serialize;

/// Everything about the run that the renderers need besides the hosts.
pub struct RunInfo {
    /// The command line, for the XML report.
    pub args: String,
    /// When the scan started.
    pub start: SystemTime,
    pub scan_types: Vec<&'static str>,
    /// TCP and UDP ports scanned on each host (empty if that scan did not run).
    pub tcp_ports: Vec<u16>,
    pub udp_ports: Vec<u16>,
    pub ports_per_host: usize,
    pub elapsed: Duration,
    /// Only show open (and open|filtered) ports, like nmap's `--open`.
    pub only_open: bool,
    /// Show why each port got its state.
    pub show_reason: bool,
    /// `-sV` ran: show the VERSION column.
    pub show_version: bool,
    /// `-O` ran: show each host's OS guess.
    pub show_os: bool,
    /// `-Pn`: discovery was skipped, so report every host.
    pub assume_up: bool,
    /// `-sn`: discovery only, no port table.
    pub ping_only: bool,
    /// `--nmap-label`: the XML report says `scanner="nmap"`.
    pub nmap_label: bool,
}

pub(crate) fn is_openish(state: PortState) -> bool {
    matches!(state, PortState::Open | PortState::OpenFiltered)
}

pub(crate) fn visible(host: &HostResult, only_open: bool) -> impl Iterator<Item = &PortResult> {
    host.ports
        .iter()
        .filter(move |p| !only_open || is_openish(p.state))
}

/// The service name to show: what `-sV` found, else the usual one for the port.
fn service_label(p: &PortResult) -> String {
    match &p.service {
        Some(s) => s.full_name(),
        None => service_name(p.protocol, p.port).to_string(),
    }
}

pub(crate) fn reported(host: &HostResult, info: &RunInfo) -> bool {
    info.assume_up || host.is_up()
}

/// Like nmap, collapse the most common non-open state into one summary
/// instead of listing hundreds of closed ports. Returns that state with its
/// count (none with `--open`) and the ports to list.
pub(crate) fn port_rows<'a>(
    host: &'a HostResult,
    info: &RunInfo,
) -> (Option<(usize, PortState)>, Vec<&'a PortResult>) {
    let hidden = [
        PortState::Closed,
        PortState::Filtered,
        PortState::OpenFiltered,
    ]
    .into_iter()
    .map(|s| (host.count(s), s))
    .filter(|&(n, _)| n > 0)
    .max_by_key(|&(n, _)| n);
    let rows = visible(host, info.only_open)
        .filter(|p| info.only_open || Some(p.state) != hidden.map(|(_, s)| s))
        .collect();
    (hidden, rows)
}

pub fn print_table(hosts: &[HostResult], info: &RunInfo) {
    println!("Starting FeroProbe {}", env!("CARGO_PKG_VERSION"));
    let mut up = 0;
    for host in hosts.iter().filter(|h| reported(h, info)) {
        up += 1;
        match &host.hostname {
            Some(name) => println!("\nScan report for {name} ({})", host.addr),
            None => println!("\nScan report for {}", host.addr),
        }
        match (host.latency_ms, host.up_reason) {
            (Some(ms), Some(why)) => println!("Host is up, {why} ({ms:.2} ms latency)."),
            (None, Some(why)) => println!("Host is up, {why}."),
            _ => {}
        }
        if let Some(mac) = &host.mac {
            match mac.vendor {
                Some(v) => println!("MAC Address: {} ({v})", mac.addr),
                None => println!("MAC Address: {} (Unknown)", mac.addr),
            }
        }
        if !info.ping_only {
            print_ports(host, info);
        }
        if info.show_os {
            print_os(host);
        }
    }
    let what = if info.ping_only {
        String::new()
    } else {
        format!(", {} port(s) each", info.ports_per_host)
    };
    println!(
        "\nFeroProbe done: {} host(s), {} up{what}, in {:.2}s",
        hosts.len(),
        up,
        info.elapsed.as_secs_f64()
    );
}

/// The port table for one host.
fn print_ports(host: &HostResult, info: &RunInfo) {
    let (hidden, rows) = port_rows(host, info);
    if rows.is_empty() {
        match hidden {
            _ if info.only_open => println!("No open ports found"),
            Some((n, state)) => println!("All {n} scanned ports are {state}"),
            None => {}
        }
        return;
    }
    if let (false, Some((n, state))) = (info.only_open, hidden) {
        println!("Not shown: {n} {state} ports");
    }
    let mut header = vec![format!("{:<10} {:<14} {:<14}", "PORT", "STATE", "SERVICE")];
    if info.show_reason {
        header.push(format!("{:<14}", "REASON"));
    }
    if info.show_version {
        header.push("VERSION".into());
    }
    println!("{}", header.join(" ").trim_end());
    let mut unrecognized = Vec::new();
    for p in &rows {
        let port = format!("{}/{}", p.port, p.protocol);
        let mut line = vec![format!(
            "{port:<10} {:<14} {:<14}",
            p.state,
            service_label(p)
        )];
        if info.show_reason {
            line.push(format!("{:<14}", p.reason));
        }
        if let (true, Some(s)) = (info.show_version, &p.service) {
            line.push(s.version_line());
            if let Some(fp) = &s.fingerprint {
                unrecognized.push(format!("{port}: \"{fp}\""));
            }
        }
        println!("{}", line.join(" ").trim_end());
    }
    if !unrecognized.is_empty() {
        println!("Unrecognized service replies:");
        for u in unrecognized {
            println!("  {u}");
        }
    }
}

/// The OS guess for one host, after `-O`.
fn print_os(host: &HostResult) {
    match &host.os {
        Some(os) => {
            println!(
                "OS guess: {} ({}%), from {}/tcp",
                os.name, os.accuracy, os.port
            );
            println!("OS fingerprint: {}", os.traits.fingerprint());
            let hops = if os.distance == 1 { "hop" } else { "hops" };
            println!("Network distance: {} {hops}", os.distance);
        }
        None => println!("OS guess: none (needs an open TCP port that answers a SYN)"),
    }
}

#[derive(Serialize)]
struct JsonReport<'a> {
    scanner: &'static str,
    version: &'static str,
    scan_types: &'a [&'static str],
    elapsed_secs: f64,
    hosts: Vec<JsonHost<'a>>,
}

#[derive(Serialize)]
struct JsonHost<'a> {
    #[serde(flatten)]
    host: JsonHostInfo<'a>,
    up: bool,
    ports: Vec<JsonPort<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    os: Option<&'a feroprobe_core::OsMatch>,
}

#[derive(Serialize)]
struct JsonHostInfo<'a> {
    addr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    hostname: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    up_reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    latency_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mac: Option<&'a feroprobe_core::MacInfo>,
}

#[derive(Serialize)]
struct JsonPort<'a> {
    port: u16,
    protocol: feroprobe_core::Protocol,
    state: PortState,
    reason: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    rtt_ms: Option<f64>,
    service: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    product: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    extra_info: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tunnel: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fingerprint: Option<&'a str>,
}

impl<'a> JsonPort<'a> {
    fn new(p: &'a PortResult) -> Self {
        let s = p.service.as_ref();
        Self {
            port: p.port,
            protocol: p.protocol,
            state: p.state,
            reason: p.reason,
            rtt_ms: p.rtt_ms,
            service: s.map_or_else(
                || service_name(p.protocol, p.port).to_string(),
                |s| s.name.clone(),
            ),
            product: s.and_then(|s| s.product.as_deref()),
            version: s.and_then(|s| s.version.as_deref()),
            extra_info: s.and_then(|s| s.extra_info.as_deref()),
            tunnel: s.and_then(|s| s.tunnel),
            fingerprint: s.and_then(|s| s.fingerprint.as_deref()),
        }
    }
}

pub fn print_json(hosts: &[HostResult], info: &RunInfo) -> Result<()> {
    let report = JsonReport {
        scanner: "feroprobe",
        version: env!("CARGO_PKG_VERSION"),
        scan_types: &info.scan_types,
        elapsed_secs: info.elapsed.as_secs_f64(),
        hosts: hosts
            .iter()
            .map(|h| JsonHost {
                host: JsonHostInfo {
                    addr: h.addr.to_string(),
                    hostname: h.hostname.as_deref(),
                    up_reason: h.up_reason,
                    latency_ms: h.latency_ms,
                    mac: h.mac.as_ref(),
                },
                up: reported(h, info),
                os: h.os.as_ref(),
                ports: visible(h, info.only_open).map(JsonPort::new).collect(),
            })
            .collect(),
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
