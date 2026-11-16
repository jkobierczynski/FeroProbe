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
use feroprobe_core::{HostResult, OsResult, PortResult, PortState, Protocol, service_name};
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
    pub sctp_ports: Vec<u16>,
    /// IP protocol numbers for `-sO`.
    pub protocols: Vec<u16>,
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
    /// `--osscan-guess`: show near OS matches too.
    pub os_guess: bool,
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
    /// `--defeat-rst-ratelimit` (or `--open`) was in effect for a TCP scan.
    pub defeat_rst: bool,
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

/// The most ports of one non-open state nmap lists before it collapses
/// them into a "Not shown" summary (`max_per_state` in nmap's
/// `PortList::isIgnoredState`); each `-v` raises it by the same amount.
pub(crate) const MAX_LISTED_PER_STATE: usize = 25;

/// Like nmap, collapse each non-open state with more than
/// [`MAX_LISTED_PER_STATE`] ports (times one plus the `-v` count) into a
/// summary instead of listing hundreds of closed ports, and list every port
/// of the other states. So `-p 80` on a closed port shows `80/tcp closed`.
/// Returns the collapsed states with their counts, most ports first (none
/// with `--open`), and the ports to list.
pub(crate) fn port_rows<'a>(
    host: &'a HostResult,
    info: &RunInfo,
) -> (Vec<(usize, PortState)>, Vec<&'a PortResult>) {
    let limit = MAX_LISTED_PER_STATE * (usize::from(info.verbosity) + 1);
    let mut hidden: Vec<(usize, PortState)> = [
        PortState::Closed,
        PortState::Filtered,
        PortState::OpenFiltered,
        PortState::Unfiltered,
        PortState::ClosedFiltered,
    ]
    .into_iter()
    // nmap never folds open|filtered ports above -vv: they may be open.
    .filter(|&s| !(s == PortState::OpenFiltered && info.verbosity > 2))
    .map(|s| (host.count(s), s))
    .filter(|&(n, _)| n > limit)
    .collect();
    if info.only_open {
        hidden.clear();
    }
    // Most ports first, as nmap orders its "Not shown" line (stable, so a
    // tie keeps the order above).
    hidden.sort_by_key(|&(n, _)| std::cmp::Reverse(n));
    let rows = visible(host, info.only_open)
        .filter(|p| !hidden.iter().any(|&(_, s)| s == p.state))
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
            // -Pn without an answer to time it by: nmap's "Host is up".
            (Some(ms), None) => w!(out, "Host is up ({ms:.2} ms latency)."),
            (None, None) => w!(out, "Host is up."),
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
        if host.timed_out {
            w!(out, "Skipping host {} due to host timeout", host.addr);
        } else if !info.ping_only {
            print_ports(out, host, info);
        }
        if info.show_os && !host.timed_out {
            print_os(out, host, info);
        }
        if info.show_version && !host.timed_out {
            print_service_info(out, host);
        }
        if info.show_trace {
            print_trace(out, host);
        }
    }
    if hosts.len() == 1 && up == 0 && !info.assume_up {
        w!(
            out,
            "Note: the host seems down. If it is up but blocks our ping probes, try -Pn"
        );
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

/// nmap's "Not shown" list: `98 filtered ports, 30 closed ports`.
fn not_shown(hidden: &[(usize, PortState)]) -> String {
    let parts: Vec<String> = hidden
        .iter()
        .map(|(n, state)| format!("{n} {state} port{}", if *n == 1 { "" } else { "s" }))
        .collect();
    parts.join(", ")
}

/// nmap's caveat under the port summary when `--defeat-rst-ratelimit`
/// may have turned closed ports into filtered ones.
fn defeat_rst_note(out: &mut String, host: &HostResult, info: &RunInfo) {
    if info.defeat_rst
        && host
            .ports
            .iter()
            .any(|p| p.protocol == feroprobe_core::Protocol::Tcp && p.state == PortState::Filtered)
    {
        w!(
            out,
            "Some closed ports may be reported as filtered due to --defeat-rst-ratelimit"
        );
    }
}

/// The port table for one host.
fn print_ports(out: &mut String, host: &HostResult, info: &RunInfo) {
    let (hidden, rows) = port_rows(host, info);
    if rows.is_empty() {
        match hidden.as_slice() {
            _ if info.only_open => w!(out, "No open ports found"),
            [(n, state)] => w!(out, "All {n} scanned ports are {state}"),
            [] => {}
            more => {
                let n: usize = more.iter().map(|(n, _)| n).sum();
                w!(out, "All {n} scanned ports are in ignored states.");
                w!(out, "Not shown: {}", not_shown(more));
            }
        }
        defeat_rst_note(out, host, info);
        return;
    }
    if !hidden.is_empty() {
        w!(out, "Not shown: {}", not_shown(&hidden));
    }
    defeat_rst_note(out, host, info);
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

/// nmap's "Service Info" line: the host names, operating systems, device
/// types and OS/hardware CPEs that `-sV` learned from this host's services.
/// Application CPEs only go in the XML and JSON reports, as in nmap.
fn print_service_info(out: &mut String, host: &HostResult) {
    let mut hosts: Vec<&str> = Vec::new();
    let mut oses: Vec<&str> = Vec::new();
    let mut devices: Vec<&str> = Vec::new();
    let mut cpes: Vec<&str> = Vec::new();
    for s in host.ports.iter().filter_map(|p| p.service.as_ref()) {
        for (list, value) in [
            (&mut hosts, s.hostname.as_deref()),
            (&mut oses, s.os_type.as_deref()),
            (&mut devices, s.device_type.as_deref()),
        ] {
            if let Some(v) = value
                && !list.contains(&v)
            {
                list.push(v);
            }
        }
        for c in s.cpe.iter().filter(|c| !c.starts_with("cpe:/a:")) {
            if !cpes.contains(&c.as_str()) {
                cpes.push(c);
            }
        }
    }
    let mut parts = Vec::new();
    for (one, many, list) in [
        ("Host", "Hosts", &hosts),
        ("OS", "OSs", &oses),
        ("Device", "Devices", &devices),
        ("CPE", "CPE", &cpes),
    ] {
        if !list.is_empty() {
            let label = if list.len() == 1 { one } else { many };
            parts.push(format!("{label}: {}", list.join(", ")));
        }
    }
    if !parts.is_empty() {
        w!(out, "Service Info: {}", parts.join("; "));
    }
}

/// nmap's "Device type", "Running" and "OS CPE" lines for the matches
/// shown: the perfect ones, or with `guess` the near ones too.
fn print_os_classes(out: &mut String, os: &OsResult, guess: bool) {
    let shown = if os.perfect > 0 {
        &os.matches[..os.perfect]
    } else if guess {
        &os.matches[..]
    } else {
        return;
    };
    if shown.is_empty() {
        return;
    }
    let mut types: Vec<&str> = Vec::new();
    let mut cpes: Vec<&str> = Vec::new();
    // "vendor family", its generations, its best accuracy.
    let mut families: Vec<(String, String, u8)> = Vec::new();
    for m in shown {
        if !types.contains(&m.device_type.as_str()) {
            types.push(&m.device_type);
        }
        for c in &m.cpe {
            if !cpes.contains(&c.as_str()) {
                cpes.push(c);
            }
        }
        let name = if m.vendor == m.family {
            m.family.clone()
        } else {
            format!("{} {}", m.vendor, m.family)
        };
        match families.iter_mut().find(|(n, _, _)| *n == name) {
            Some((_, gens, _)) => {
                if !m.generation.is_empty() && !gens.contains(&m.generation) {
                    if !gens.is_empty() {
                        gens.push('|');
                    }
                    gens.push_str(&m.generation);
                }
            }
            None => families.push((name, m.generation.clone(), m.accuracy)),
        }
    }
    w!(out, "Device type: {}", types.join("|"));
    let running: Vec<String> = families
        .iter()
        .map(|(name, gens, acc)| {
            let mut s = name.clone();
            if !gens.is_empty() {
                s.push(' ');
                s.push_str(gens);
            }
            if os.perfect == 0 {
                s.push_str(&format!(" ({acc}%)"));
            }
            s
        })
        .collect();
    w!(
        out,
        "Running{}: {}",
        if os.perfect == 0 {
            " (JUST GUESSING)"
        } else {
            ""
        },
        running.join(", ")
    );
    if !cpes.is_empty() {
        w!(out, "OS CPE: {}", cpes.join(" "));
    }
}

/// The fingerprint block, for adding the host to the database.
fn print_fingerprint(out: &mut String, os: &OsResult) {
    w!(out, "TCP/IP fingerprint:");
    let fp = feroprobe_core::os::Fingerprint {
        tests: os
            .fingerprint
            .split(' ')
            .filter_map(|t| t.split_once('='))
            .map(|(t, v)| (t.to_string(), v.to_string()))
            .collect(),
    };
    for line in fp.wrapped(72) {
        w!(out, "OS:{line}");
    }
}

/// Where to send a fingerprint FeroProbe could not match.
const OS_SUBMIT: &str = "If you know what OS is running on it, see docs/os-fingerprints.md";

/// The OS detection results for one host, after `-O`, in nmap's layout.
fn print_os(out: &mut String, host: &HostResult, info: &RunInfo) {
    let Some(os) = &host.os else {
        let open = host
            .ports
            .iter()
            .any(|p| p.protocol == Protocol::Tcp && p.state == PortState::Open);
        if open {
            w!(
                out,
                "OS detection skipped: --osscan-limit needs an open and a closed TCP port"
            );
        } else {
            w!(
                out,
                "OS detection skipped: no open TCP port found (OS probes only go to ports the scan found)"
            );
        }
        return;
    };
    if os.closed_port.is_none() {
        w!(
            out,
            "Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port"
        );
    }
    let guess = info.os_guess || os.not_ideal.is_some();
    print_os_classes(out, os, guess);
    let suffix = if os.not_ideal.is_some() {
        "(test conditions non-ideal)".to_string()
    } else {
        format!("({OS_SUBMIT})")
    };
    if os.perfect > 0 {
        let names: Vec<&str> = os.matches[..os.perfect]
            .iter()
            .map(|m| m.name.as_str())
            .collect();
        w!(out, "OS details: {}", names.join(", "));
        if info.verbosity > 1 {
            print_fingerprint(out, os);
        }
    } else if !os.matches.is_empty() {
        if let (true, Some(reason)) = (info.verbosity > 1, &os.not_ideal) {
            w!(out, "OS fingerprint not ideal because: {reason}");
        }
        if guess {
            let list: Vec<String> = os
                .matches
                .iter()
                .map(|m| format!("{} ({}%)", m.name, m.accuracy))
                .collect();
            w!(out, "Aggressive OS guesses: {}", list.join(", "));
        }
        w!(out, "No exact OS matches for host {suffix}.");
        if os.not_ideal.is_none() || info.verbosity > 1 {
            print_fingerprint(out, os);
        }
    } else {
        if let Some(reason) = &os.not_ideal {
            w!(out, "OS fingerprint not ideal because: {reason}");
            w!(out, "No OS matches for host");
        } else {
            w!(out, "No OS matches for host ({OS_SUBMIT}).");
        }
        if os.not_ideal.is_none() || info.verbosity > 1 {
            print_fingerprint(out, os);
        }
    }
    if let Some(d) = os.distance {
        w!(
            out,
            "Network Distance: {d} hop{}",
            if d == 1 { "" } else { "s" }
        );
    }
    if info.verbosity > 0
        && let Some(class) = &os.ipid_class
    {
        w!(
            out,
            "IP ID Sequence Generation: {}",
            feroprobe_core::os::fingerprint::ipid_class_words(class)
        );
    }
}

/// The route to one host, after `--traceroute`, in nmap's layout.
fn print_trace(out: &mut String, host: &HostResult) {
    let Some(t) = &host.trace else { return };
    if t.hops.is_empty() {
        w!(out, "TRACEROUTE: no hops answered");
        return;
    }
    if t.direct {
        // nmap's header when no probe was sent (a directly connected host).
        w!(out, "TRACEROUTE");
    } else {
        w!(out, "TRACEROUTE (using port {}/{})", t.port, t.protocol);
    }
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
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    timed_out: bool,
    ports: Vec<JsonPort<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    os: Option<&'a OsResult>,
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
    hostname: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    os_type: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_type: Option<&'a str>,
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    cpe: &'a [String],
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
            hostname: s.and_then(|s| s.hostname.as_deref()),
            os_type: s.and_then(|s| s.os_type.as_deref()),
            device_type: s.and_then(|s| s.device_type.as_deref()),
            cpe: s.map_or(&[][..], |s| &s.cpe[..]),
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
                timed_out: h.timed_out,
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
            sctp_ports: vec![],
            protocols: vec![],
            ports_per_host: 5,
            elapsed: Duration::from_millis(1500),
            only_open: false,
            show_reason: false,
            show_version: true,
            show_os: false,
            os_guess: false,
            show_trace: false,
            assume_up: false,
            ping_only: false,
            nmap_label: false,
            verbosity: 0,
            defeat_rst: false,
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

    fn tcp(port: u16, state: PortState) -> PortResult {
        PortResult {
            port,
            protocol: feroprobe_core::Protocol::Tcp,
            state,
            reason: "reset",
            rtt_ms: None,
            service: None,
        }
    }

    #[test]
    fn few_closed_ports_are_listed_like_nmap() {
        // `-p 80` on a closed port: nmap lists it rather than summarising.
        let mut host = HostResult::new("127.0.0.1".parse().unwrap(), None);
        host.up_reason = Some("localhost-response");
        host.ports = vec![tcp(80, PortState::Closed)];
        let table = render_table(std::slice::from_ref(&host), &info());
        assert!(table.contains("PORT       STATE"), "{table}");
        assert!(table.contains("80/tcp     closed         http"), "{table}");
        assert!(
            !table.contains("Not shown") && !table.contains("All 1"),
            "{table}"
        );

        // 25 of a state are still listed; 26 collapse.
        host.ports = (1..=25).map(|p| tcp(p, PortState::Closed)).collect();
        let table = render_table(std::slice::from_ref(&host), &info());
        assert!(
            table.contains("25/tcp") && !table.contains("Not shown"),
            "{table}"
        );
        host.ports.push(tcp(26, PortState::Closed));
        let table = render_table(std::slice::from_ref(&host), &info());
        assert!(table.contains("All 26 scanned ports are closed"), "{table}");
        // -v raises the limit, as in nmap.
        let v = RunInfo {
            verbosity: 1,
            ..info()
        };
        let table = render_table(std::slice::from_ref(&host), &v);
        assert!(
            table.contains("26/tcp") && !table.contains("All 26"),
            "{table}"
        );

        // Several large states each collapse, most ports first.
        host.ports = (1..=30).map(|p| tcp(p, PortState::Closed)).collect();
        host.ports
            .extend((100..=139).map(|p| tcp(p, PortState::Filtered)));
        host.ports.push(tcp(22, PortState::Open));
        let table = render_table(std::slice::from_ref(&host), &info());
        assert!(
            table.contains("Not shown: 40 filtered ports, 30 closed ports"),
            "{table}"
        );
        assert!(table.contains("22/tcp"), "{table}");
        host.ports.pop();
        let table = render_table(std::slice::from_ref(&host), &info());
        assert!(
            table.contains("All 70 scanned ports are in ignored states."),
            "{table}"
        );

        // Above -vv, open|filtered ports are always listed, as in nmap.
        host.ports = (1..=200).map(|p| tcp(p, PortState::Closed)).collect();
        host.ports
            .extend((1000..=1100).map(|p| tcp(p, PortState::OpenFiltered)));
        let vvv = RunInfo {
            verbosity: 3,
            ..info()
        };
        let table = render_table(std::slice::from_ref(&host), &vvv);
        assert!(table.contains("Not shown: 200 closed ports"), "{table}");
        assert!(table.contains("1100/tcp   open|filtered"), "{table}");
        // -oG and -oX use the same rows.
        let g = crate::grep::render(std::slice::from_ref(&host), &vvv);
        assert!(g.contains("1100/open|filtered/tcp"), "{g}");
        assert!(g.contains("Ignored State: closed (200)"), "{g}");
        let x = crate::xml::render(std::slice::from_ref(&host), &vvv);
        assert!(
            x.contains("<extraports state=\"closed\" count=\"200\">"),
            "{x}"
        );
        assert!(!x.contains("<extraports state=\"open|filtered\""), "{x}");
        assert!(
            x.contains("portid=\"1100\"><state state=\"open|filtered\""),
            "{x}"
        );
    }

    #[test]
    fn a_lone_down_host_gets_nmaps_hint() {
        let down = HostResult::new("10.0.0.9".parse().unwrap(), None);
        let table = render_table(std::slice::from_ref(&down), &info());
        assert!(
            table.contains("seems down") && table.contains("try -Pn"),
            "{table}"
        );
        // Not with -Pn, and not when more than one host was scanned.
        let pn = RunInfo {
            assume_up: true,
            ..info()
        };
        assert!(!render_table(std::slice::from_ref(&down), &pn).contains("seems down"));
        let two = [down.clone(), down];
        assert!(!render_table(&two, &info()).contains("seems down"));
    }

    #[test]
    fn timed_out_hosts_have_no_port_results() {
        let mut host = HostResult::new("10.0.0.9".parse().unwrap(), None);
        host.up_reason = Some("echo-reply");
        host.timed_out = true;
        let table = render_table(std::slice::from_ref(&host), &info());
        assert!(
            table.contains("Skipping host 10.0.0.9 due to host timeout"),
            "{table}"
        );
        assert!(!table.contains("PORT"), "{table}");
        let json = render_json(std::slice::from_ref(&host), &info()).unwrap();
        assert!(json.contains("\"timed_out\": true"), "{json}");
        host.timed_out = false;
        let json = render_json(&[host], &info()).unwrap();
        assert!(!json.contains("timed_out"), "{json}");
    }
    #[test]
    fn service_info_line_like_nmap() {
        use feroprobe_core::ServiceInfo;
        let mut host = HostResult::new("10.0.0.9".parse().unwrap(), None);
        host.up_reason = Some("echo-reply");
        let svc = |name: &str, host: Option<&str>, os: Option<&str>, cpe: &[&str]| ServiceInfo {
            name: name.into(),
            hostname: host.map(Into::into),
            os_type: os.map(Into::into),
            cpe: cpe.iter().map(|c| c.to_string()).collect(),
            ..Default::default()
        };
        let mut ssh = tcp(22, PortState::Open);
        ssh.service = Some(svc(
            "ssh",
            None,
            Some("Linux"),
            &["cpe:/a:openbsd:openssh:9.6p1", "cpe:/o:linux:linux_kernel"],
        ));
        let mut smtp = tcp(25, PortState::Open);
        smtp.service = Some(svc(
            "smtp",
            Some("mail.example"),
            Some("Linux"),
            &["cpe:/o:linux:linux_kernel"],
        ));
        host.ports = vec![ssh, smtp];
        let table = render_table(std::slice::from_ref(&host), &info());
        // Application CPEs stay out; repeated values are listed once.
        assert!(
            table.contains(
                "Service Info: Host: mail.example; OS: Linux; CPE: cpe:/o:linux:linux_kernel\n"
            ),
            "{table}"
        );
        let json = render_json(std::slice::from_ref(&host), &info()).unwrap();
        assert!(json.contains("\"cpe\": [\n"), "{json}");
        assert!(json.contains("\"hostname\": \"mail.example\""), "{json}");
        // Without -sV there is no Service Info.
        let mut plain = info();
        plain.show_version = false;
        assert!(!render_table(&[host], &plain).contains("Service Info"));
    }
}
