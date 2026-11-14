//! "Grepable" output in the layout of nmap's `-oG`: one line per host, so
//! `grep`, `awk` and `cut` can pick results apart.
//!
//! Fields are separated by tabs, shown here as `<TAB>`:
//!
//! ```text
//! # FeroProbe 0.3.0 scan initiated Sat Nov 14 05:40:00 2026 UTC as: feroprobe -oG - 10.0.0.1
//! Host: 10.0.0.1 ()<TAB>Status: Up
//! Host: 10.0.0.1 ()<TAB>Ports: 22/open/tcp//ssh//OpenSSH 9.6/, 80/closed/tcp//http///<TAB>Ignored State: filtered (98)
//! # FeroProbe done at Sat Nov 14 05:40:02 2026 UTC -- 1 IP address (1 host up) scanned in 1.50 seconds
//! ```
//!
//! Each port is `port/state/protocol/owner/service/rpc/version/`; fields
//! that would contain `/` or `,` have them replaced (by `|` and `;`), as
//! nmap does, so the separators stay unambiguous.

use std::fmt::Write;

use feroprobe_core::{HostResult, PortResult, service_name};

use crate::output::{RunInfo, port_rows, reported};
use crate::xml::time_str;

/// Make a value safe inside a `/`-separated, `,`-joined port entry.
fn field(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '/' => '|',
            ',' => ';',
            '\t' | '\n' | '\r' => ' ',
            c => c,
        })
        .collect()
}

fn port_entry(p: &PortResult) -> String {
    let (service, version) = match &p.service {
        Some(s) => (s.full_name(), s.version_line()),
        None => (service_name(p.protocol, p.port).to_string(), String::new()),
    };
    format!(
        "{}/{}/{}//{}//{}/",
        p.port,
        field(&p.state.to_string()),
        p.protocol,
        field(&service),
        field(&version)
    )
}

/// The whole report in nmap's grepable layout.
pub fn render(hosts: &[HostResult], info: &RunInfo) -> String {
    let mut x = String::new();
    let _ = writeln!(
        x,
        "# FeroProbe {} scan initiated {} as: {}",
        env!("CARGO_PKG_VERSION"),
        time_str(info.start),
        info.args.replace('\n', " ")
    );
    let mut up = 0;
    for host in hosts.iter().filter(|h| reported(h, info)) {
        up += 1;
        let name = host
            .hostname
            .as_deref()
            .or(host.rdns.as_deref())
            .unwrap_or("");
        let head = format!("Host: {} ({name})", host.addr);
        if host.timed_out {
            let _ = writeln!(x, "{head}\tStatus: Timeout");
            continue;
        }
        let _ = writeln!(x, "{head}\tStatus: Up");
        if info.ping_only {
            continue;
        }
        let (hidden, rows) = port_rows(host, info);
        let mut line = head;
        if !rows.is_empty() {
            let ports: Vec<String> = rows.iter().map(|p| port_entry(p)).collect();
            let _ = write!(line, "\tPorts: {}", ports.join(", "));
        }
        if let (false, Some((n, state))) = (info.only_open, hidden) {
            let _ = write!(line, "\tIgnored State: {state} ({n})");
        }
        if let Some(os) = &host.os {
            let _ = write!(line, "\tOS: {}", field(&os.name));
        }
        let _ = writeln!(x, "{line}");
    }
    let n = hosts.len();
    let _ = writeln!(
        x,
        "# FeroProbe done at {} -- {n} IP address{} ({up} host{} up) scanned in {:.2} seconds",
        time_str(info.start + info.elapsed),
        if n == 1 { "" } else { "es" },
        if up == 1 { "" } else { "s" },
        info.elapsed.as_secs_f64()
    );
    x
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::tests::info;
    use feroprobe_core::{PortState, Protocol, ServiceInfo};

    fn port(port: u16, state: PortState, service: Option<ServiceInfo>) -> PortResult {
        PortResult {
            port,
            protocol: Protocol::Tcp,
            state,
            reason: "syn-ack",
            rtt_ms: None,
            service,
        }
    }

    #[test]
    fn one_line_per_host_with_ports() {
        let mut host = HostResult::new("10.0.0.5".parse().unwrap(), Some("web".into()));
        host.up_reason = Some("echo-reply");
        host.ports = vec![
            port(
                22,
                PortState::Open,
                Some(ServiceInfo {
                    name: "ssh".into(),
                    product: Some("Open/SSH, test".into()),
                    version: Some("9.6".into()),
                    ..Default::default()
                }),
            ),
            port(80, PortState::Closed, None),
            port(81, PortState::Filtered, None),
            port(82, PortState::Filtered, None),
        ];
        let down = HostResult::new("10.0.0.6".parse().unwrap(), None);
        let g = render(&[host, down], &info());
        let lines: Vec<&str> = g.lines().collect();
        assert!(lines[0].starts_with("# FeroProbe "), "{g}");
        assert_eq!(lines[1], "Host: 10.0.0.5 (web)\tStatus: Up");
        assert_eq!(
            lines[2],
            "Host: 10.0.0.5 (web)\tPorts: 22/open/tcp//ssh//Open|SSH; test 9.6/, 80/closed/tcp//http///\tIgnored State: filtered (2)"
        );
        assert!(
            lines[3].contains("-- 2 IP addresses (1 host up) scanned in 1.50 seconds"),
            "{g}"
        );
        assert_eq!(lines.len(), 4);
    }

    #[test]
    fn timed_out_hosts() {
        let mut host = HostResult::new("10.0.0.9".parse().unwrap(), None);
        host.up_reason = Some("echo-reply");
        host.timed_out = true;
        let g = render(&[host], &info());
        let lines: Vec<&str> = g.lines().collect();
        assert_eq!(lines[1], "Host: 10.0.0.9 ()\tStatus: Timeout");
        assert_eq!(lines.len(), 3, "{g}");
    }
}
