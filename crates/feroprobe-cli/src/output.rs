//! Rendering scan results.

use std::time::Duration;

use anyhow::Result;
use feroprobe_core::{HostResult, PortResult, PortState, Protocol};
use serde::Serialize;

/// Well-known service names for display. Purely a label from the port
/// number; real service detection comes later.
fn service_name(protocol: Protocol, port: u16) -> &'static str {
    match (protocol, port) {
        (Protocol::Tcp, 21) => "ftp",
        (Protocol::Tcp, 22) => "ssh",
        (Protocol::Tcp, 23) => "telnet",
        (Protocol::Tcp, 25) => "smtp",
        (_, 53) => "domain",
        (Protocol::Udp, 67) => "dhcps",
        (Protocol::Udp, 68) => "dhcpc",
        (Protocol::Udp, 69) => "tftp",
        (Protocol::Tcp, 80) => "http",
        (Protocol::Tcp, 110) => "pop3",
        (_, 111) => "rpcbind",
        (Protocol::Udp, 123) => "ntp",
        (Protocol::Tcp, 135) => "msrpc",
        (Protocol::Udp, 137) => "netbios-ns",
        (Protocol::Udp, 138) => "netbios-dgm",
        (Protocol::Tcp, 139) => "netbios-ssn",
        (Protocol::Tcp, 143) => "imap",
        (Protocol::Udp, 161) => "snmp",
        (Protocol::Udp, 162) => "snmptrap",
        (Protocol::Tcp, 389) => "ldap",
        (Protocol::Tcp, 443) => "https",
        (Protocol::Tcp, 445) => "microsoft-ds",
        (Protocol::Tcp, 465) => "smtps",
        (Protocol::Udp, 500) => "isakmp",
        (Protocol::Udp, 514) => "syslog",
        (Protocol::Tcp, 587) => "submission",
        (Protocol::Tcp, 993) => "imaps",
        (Protocol::Tcp, 995) => "pop3s",
        (Protocol::Tcp, 1433) => "ms-sql-s",
        (Protocol::Tcp, 1883) => "mqtt",
        (Protocol::Udp, 1900) => "upnp",
        (_, 2049) => "nfs",
        (Protocol::Tcp, 2375) => "docker",
        (Protocol::Tcp, 3306) => "mysql",
        (Protocol::Tcp, 3389) => "ms-wbt-server",
        (Protocol::Udp, 4500) => "nat-t-ike",
        (Protocol::Tcp, 5432) => "postgresql",
        (Protocol::Udp, 5353) => "mdns",
        (Protocol::Tcp, 5672) => "amqp",
        (Protocol::Tcp, 5900) => "vnc",
        (Protocol::Tcp, 6379) => "redis",
        (Protocol::Tcp, 6443) => "kubernetes",
        (Protocol::Tcp, 8080) => "http-proxy",
        (Protocol::Tcp, 8443) => "https-alt",
        (Protocol::Tcp, 9200) => "elasticsearch",
        (_, 11211) => "memcache",
        (Protocol::Tcp, 27017) => "mongodb",
        _ => "unknown",
    }
}

/// Everything about the run that the renderers need besides the hosts.
pub struct RunInfo {
    pub scan_types: Vec<&'static str>,
    pub ports_per_host: usize,
    pub elapsed: Duration,
    /// Only show open (and open|filtered) ports, like nmap's `--open`.
    pub only_open: bool,
    /// Show why each port got its state.
    pub show_reason: bool,
    /// `-Pn`: discovery was skipped, so report every host.
    pub assume_up: bool,
    /// `-sn`: discovery only, no port table.
    pub ping_only: bool,
}

fn is_openish(state: PortState) -> bool {
    matches!(state, PortState::Open | PortState::OpenFiltered)
}

fn visible(host: &HostResult, only_open: bool) -> impl Iterator<Item = &PortResult> {
    host.ports
        .iter()
        .filter(move |p| !only_open || is_openish(p.state))
}

fn reported(host: &HostResult, info: &RunInfo) -> bool {
    info.assume_up || host.is_up()
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
        if info.ping_only {
            continue;
        }

        // Like nmap, collapse the most common non-open state into one line
        // instead of listing hundreds of closed ports.
        let hidden = [
            PortState::Closed,
            PortState::Filtered,
            PortState::OpenFiltered,
        ]
        .into_iter()
        .map(|s| (host.count(s), s))
        .filter(|&(n, _)| n > 0)
        .max_by_key(|&(n, _)| n);
        let rows: Vec<_> = visible(host, info.only_open)
            .filter(|p| info.only_open || Some(p.state) != hidden.map(|(_, s)| s))
            .collect();
        if rows.is_empty() {
            match hidden {
                _ if info.only_open => println!("No open ports found"),
                Some((n, state)) => println!("All {n} scanned ports are {state}"),
                None => {}
            }
            continue;
        }
        if let (false, Some((n, state))) = (info.only_open, hidden) {
            println!("Not shown: {n} {state} ports");
        }
        if info.show_reason {
            println!("{:<10} {:<14} {:<14} REASON", "PORT", "STATE", "SERVICE");
        } else {
            println!("{:<10} {:<14} SERVICE", "PORT", "STATE");
        }
        for p in rows {
            let port = format!("{}/{}", p.port, p.protocol);
            let service = service_name(p.protocol, p.port);
            if info.show_reason {
                println!("{port:<10} {:<14} {service:<14} {}", p.state, p.reason);
            } else {
                println!("{port:<10} {:<14} {service}", p.state);
            }
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
}

#[derive(Serialize)]
struct JsonPort<'a> {
    #[serde(flatten)]
    result: &'a PortResult,
    service: &'static str,
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
                },
                up: h.is_up(),
                ports: visible(h, info.only_open)
                    .map(|p| JsonPort {
                        result: p,
                        service: service_name(p.protocol, p.port),
                    })
                    .collect(),
            })
            .collect(),
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
