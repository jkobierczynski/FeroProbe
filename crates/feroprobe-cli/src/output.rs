//! Rendering scan results.

use std::time::Duration;

use anyhow::Result;
use feroprobe_core::{HostResult, PortResult, PortState};
use serde::Serialize;

/// Well-known service names for display. Purely a label from the port
/// number; real service detection comes later.
fn service_name(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "domain",
        80 => "http",
        110 => "pop3",
        111 => "rpcbind",
        135 => "msrpc",
        139 => "netbios-ssn",
        143 => "imap",
        389 => "ldap",
        443 => "https",
        445 => "microsoft-ds",
        465 => "smtps",
        587 => "submission",
        993 => "imaps",
        995 => "pop3s",
        1433 => "ms-sql-s",
        1883 => "mqtt",
        2049 => "nfs",
        2375 => "docker",
        3306 => "mysql",
        3389 => "ms-wbt-server",
        5432 => "postgresql",
        5672 => "amqp",
        5900 => "vnc",
        6379 => "redis",
        6443 => "kubernetes",
        8080 => "http-proxy",
        8443 => "https-alt",
        9200 => "elasticsearch",
        11211 => "memcache",
        27017 => "mongodb",
        _ => "unknown",
    }
}

fn visible(host: &HostResult, only_open: bool) -> impl Iterator<Item = &PortResult> {
    host.ports
        .iter()
        .filter(move |p| !only_open || p.state == PortState::Open)
}

pub fn print_table(
    hosts: &[HostResult],
    ports_per_host: usize,
    elapsed: Duration,
    only_open: bool,
) {
    println!("Starting FeroProbe {}", env!("CARGO_PKG_VERSION"));
    let mut up = 0;
    for host in hosts {
        if !host.is_up() {
            continue;
        }
        up += 1;
        match &host.hostname {
            Some(name) => println!("\nScan report for {name} ({})", host.addr),
            None => println!("\nScan report for {}", host.addr),
        }

        // Like nmap, collapse the dominant non-open state into one line
        // instead of listing hundreds of closed ports.
        let closed = host.count(PortState::Closed);
        let filtered = host.count(PortState::Filtered);
        let (hidden_state, hidden) = if closed >= filtered {
            (PortState::Closed, closed)
        } else {
            (PortState::Filtered, filtered)
        };
        if !only_open && hidden > 0 {
            println!("Not shown: {hidden} {hidden_state} tcp ports");
        }

        let rows: Vec<_> = visible(host, only_open)
            .filter(|p| only_open || p.state != hidden_state)
            .collect();
        if rows.is_empty() && only_open {
            println!("No open ports found");
            continue;
        }
        if rows.is_empty() {
            println!(
                "All {} scanned ports are {}",
                host.ports.len(),
                hidden_state
            );
            continue;
        }
        println!("{:<10} {:<9} SERVICE", "PORT", "STATE");
        for p in rows {
            println!(
                "{:<10} {:<9} {}",
                format!("{}/tcp", p.port),
                p.state,
                service_name(p.port)
            );
        }
    }
    println!(
        "\nFeroProbe done: {} host(s) scanned, {} up, {} port(s) each, in {:.2}s",
        hosts.len(),
        up,
        ports_per_host,
        elapsed.as_secs_f64()
    );
}

#[derive(Serialize)]
struct JsonReport<'a> {
    scanner: &'static str,
    version: &'static str,
    scan_type: &'static str,
    elapsed_secs: f64,
    hosts: Vec<JsonHost<'a>>,
}

#[derive(Serialize)]
struct JsonHost<'a> {
    addr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    hostname: Option<&'a str>,
    up: bool,
    ports: Vec<JsonPort<'a>>,
}

#[derive(Serialize)]
struct JsonPort<'a> {
    #[serde(flatten)]
    result: &'a PortResult,
    protocol: &'static str,
    service: &'static str,
}

pub fn print_json(hosts: &[HostResult], elapsed: Duration, only_open: bool) -> Result<()> {
    let report = JsonReport {
        scanner: "feroprobe",
        version: env!("CARGO_PKG_VERSION"),
        scan_type: "tcp-connect",
        elapsed_secs: elapsed.as_secs_f64(),
        hosts: hosts
            .iter()
            .map(|h| JsonHost {
                addr: h.addr.to_string(),
                hostname: h.hostname.as_deref(),
                up: h.is_up(),
                ports: visible(h, only_open)
                    .map(|p| JsonPort {
                        result: p,
                        protocol: "tcp",
                        service: service_name(p.port),
                    })
                    .collect(),
            })
            .collect(),
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
