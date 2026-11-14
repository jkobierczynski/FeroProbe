//! Rendering scan results.

use std::fmt::Write;
use std::time::{Duration, SystemTime};

/// `writeln!` into a String, which cannot fail.
macro_rules! w {
    ($($t:tt)*) => {{
        let _ = writeln!($($t)*);
    }};
}

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
    /// Only show open (and open|filtered, unfiltered) ports, like nmap's `--open`.
    pub only_open: bool,
    /// Show why each port got its state.
    pub show_reason: bool,
    /// `-sV` ran: show the VERSION column.
    pub show_version: bool,
    /// `-O` ran: show each host's OS guess.
    pub show_os: bool,
    /// `--traceroute` ran: show each host's route.
    pub show_trace: bool,
    /// `-Pn`: discovery was skipped, so report every host.
    pub assume_up: bool,
    /// `-sn`: discovery only, no port table.
    pub ping_only: bool,
    /// `--nmap-label`: the XML report says `scanner="nmap"`.
    pub nmap_label: bool,
    /// How many `-v` were given.
    pub verbosity: u8,
}

pub(crate) fn is_openish(state: PortState) -> bool {
    matches!(
        state,
        PortState::Open | PortState::OpenFiltered | PortState::Unfiltered
    )
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
        PortState::Unfiltered,
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

/// The report in nmap's "normal" layout (stdout, `-oN`).
pub fn render_table(hosts: &[HostResult], info: &RunInfo) -> String {
    let mut s = String::new();
    let out = &mut s;
    w!(out, "Starting FeroProbe {}", env!("CARGO_PKG_VERSION"));
    let mut up = 0;
    for host in hosts.iter().filter(|h| reported(h, info)) {
        up += 1;
        match host.hostname.as_ref().or(host.rdns.as_ref()) {
            Some(name) => w!(out, "\nScan report for {name} ({})", host.addr),
            None => w!(out, "\nScan report for {}", host.addr),
        }
        match (host.latency_ms, host.up_reason) {
            (Some(ms), Some(why)) => w!(out, "Host is up, {why} ({ms:.2} ms latency)."),
            (None, Some(why)) => w!(out, "Host is up, {why}."),
            _ => {}
        }
        // A name given on the command line hides the address's own name.
        if let (Some(given), Some(rdns)) = (&host.hostname, &host.rdns)
            && !given.eq_ignore_ascii_case(rdns)
        {
            w!(out, "rDNS record for {}: {rdns}", host.addr);
        }
        if let Some(mac) = &host.mac {
            match mac.vendor {
                Some(v) => w!(out, "MAC Address: {} ({v})", mac.addr),
                None => w!(out, "MAC Address: {} (Unknown)", mac.addr),
            }
        }
        if !info.ping_only {
            print_ports(out, host, info);
        }
        if info.show_os {
            print_os(out, host);
        }
        if info.show_trace {
            print_trace(out, host);
        }
    }
    let what = if info.ping_only {
        String::new()
    } else {
        format!(", {} port(s) each", info.ports_per_host)
    };
    w!(
        out,
        "\nFeroProbe done: {} host(s), {} up{what}, in {:.2}s",
        hosts.len(),
        up,
        info.elapsed.as_secs_f64()
    );
    s
}

/// The port table for one host.
fn print_ports(out: &mut String, host: &HostResult, info: &RunInfo) {
    let (hidden, rows) = port_rows(host, info);
    if rows.is_empty() {
        match hidden {
            _ if info.only_open => w!(out, "No open ports found"),
            Some((n, state)) => w!(out, "All {n} scanned ports are {state}"),
            None => {}
        }
        return;
    }
    if let (false, Some((n, state))) = (info.only_open, hidden) {
        w!(out, "Not shown: {n} {state} ports");
    }
    let mut header = vec![format!("{:<10} {:<14} {:<14}", "PORT", "STATE", "SERVICE")];
    if info.show_reason {
        header.push(format!("{:<14}", "REASON"));
    }
    if info.show_version {
        header.push("VERSION".into());
    }
    w!(out, "{}", header.join(" ").trim_end());
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
        w!(out, "{}", line.join(" ").trim_end());
    }
    if !unrecognized.is_empty() {
        w!(out, "Unrecognized service replies:");
        for u in unrecognized {
            w!(out, "  {u}");
        }
    }
}

/// The OS guess for one host, after `-O`.
fn print_os(out: &mut String, host: &HostResult) {
    match &host.os {
        Some(os) => {
            w!(
                out,
                "OS guess: {} ({}%), from {}/tcp",
                os.name,
                os.accuracy,
                os.port
            );
            w!(out, "OS fingerprint: {}", os.traits.fingerprint());
            let hops = if os.distance == 1 { "hop" } else { "hops" };
            w!(out, "Network distance: {} {hops}", os.distance);
        }
        None => w!(
            out,
            "OS guess: none (needs an open TCP port that answers a SYN)"
        ),
    }
}

/// The route to one host, after `--traceroute`, in nmap's layout.
fn print_trace(out: &mut String, host: &HostResult) {
    let Some(t) = &host.trace else { return };
    if t.hops.is_empty() {
        w!(out, "TRACEROUTE: no hops answered");
        return;
    }
    w!(out, "TRACEROUTE (using port {}/{})", t.port, t.protocol);
    w!(out, "HOP RTT        ADDRESS");
    for hop in &t.hops {
        let rtt = hop
            .rtt_ms
            .map_or_else(|| "...".to_string(), |ms| format!("{ms:.2} ms"));
        let addr = hop.addr.map_or_else(String::new, |a| a.to_string());
        w!(out, "{:<3} {rtt:<10} {addr}", hop.ttl);
    }
    if !t.reached {
        w!(out, "(the host itself did not answer)");
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
    #[serde(skip_serializing_if = "Option::is_none")]
    trace: Option<&'a feroprobe_core::Trace>,
}

#[derive(Serialize)]
struct JsonHostInfo<'a> {
    addr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    hostname: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rdns: Option<&'a str>,
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

/// The report as JSON (`-o json`, `-oJ`).
pub fn render_json(hosts: &[HostResult], info: &RunInfo) -> Result<String> {
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
                    rdns: h.rdns.as_deref(),
                    up_reason: h.up_reason,
                    latency_ms: h.latency_ms,
                    mac: h.mac.as_ref(),
                },
                up: reported(h, info),
                os: h.os.as_ref(),
                trace: h.trace.as_ref(),
                ports: visible(h, info.only_open).map(JsonPort::new).collect(),
            })
            .collect(),
    };
    Ok(serde_json::to_string_pretty(&report)? + "\n")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    /// A run description for renderer tests.
    pub(crate) fn info() -> RunInfo {
        RunInfo {
            args: "feroprobe -sV <x> & \"y\"".into(),
            start: UNIX_EPOCH + Duration::from_secs(1_794_591_914),
            scan_types: vec!["tcp-connect", "version"],
            tcp_ports: vec![22, 80, 81, 82, 443],
            udp_ports: vec![],
            ports_per_host: 5,
            elapsed: Duration::from_millis(1500),
            only_open: false,
            show_reason: false,
            show_version: true,
            show_os: false,
            show_trace: false,
            assume_up: false,
            ping_only: false,
            nmap_label: false,
            verbosity: 0,
        }
    }

    #[test]
    fn report_names_come_from_the_command_line_or_reverse_dns() {
        let mut named = HostResult::new("10.0.0.5".parse().unwrap(), None);
        named.up_reason = Some("echo-reply");
        named.rdns = Some("web.example".into());
        let mut both = HostResult::new("10.0.0.6".parse().unwrap(), Some("db".into()));
        both.up_reason = Some("echo-reply");
        both.rdns = Some("db7.example".into());
        let mut same = HostResult::new("10.0.0.7".parse().unwrap(), Some("MAIL.example".into()));
        same.up_reason = Some("echo-reply");
        same.rdns = Some("mail.example".into());
        let table = render_table(&[named, both, same], &info());
        assert!(
            table.contains("Scan report for web.example (10.0.0.5)"),
            "{table}"
        );
        assert!(table.contains("Scan report for db (10.0.0.6)"), "{table}");
        assert!(
            table.contains("rDNS record for 10.0.0.6: db7.example"),
            "{table}"
        );
        assert!(!table.contains("rDNS record for 10.0.0.7"), "{table}");
    }
}
