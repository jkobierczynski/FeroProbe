//! XML output in the layout of nmap's `-oX`, so tools that already read nmap
//! reports (ndiff-style diffing, report converters, importers) can read ours.

use std::fmt::Write;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use feroprobe_core::{HostResult, PortResult, PortState, Protocol, service_name};

use crate::output::{RunInfo, port_rows, reported};

/// Escape text for an XML attribute value.
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            // XML 1.0 does not allow most control characters at all.
            c if c.is_control() && !matches!(c, '\t' | '\n' | '\r') => {}
            c => out.push(c),
        }
    }
    out
}

fn unix_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// `Fri Nov 13 17:45:14 2026 UTC`, like nmap's `startstr` but in UTC.
fn time_str(t: SystemTime) -> String {
    let secs = unix_secs(t);
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    const WEEKDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    format!(
        "{} {} {:>2} {:02}:{:02}:{:02} {} UTC",
        WEEKDAYS[days.rem_euclid(7) as usize],
        MONTHS[(month - 1) as usize],
        day,
        rem / 3600,
        rem / 60 % 60,
        rem % 60,
        year
    )
}

/// Ports as nmap writes them in `scaninfo`: `1-1024,3306,8080`.
fn port_ranges(ports: &[u16]) -> String {
    let mut sorted = ports.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut out = Vec::new();
    let mut i = 0;
    while i < sorted.len() {
        let start = sorted[i];
        while i + 1 < sorted.len() && sorted[i + 1] == sorted[i] + 1 {
            i += 1;
        }
        let end = sorted[i];
        out.push(if start == end {
            start.to_string()
        } else {
            format!("{start}-{end}")
        });
        i += 1;
    }
    out.join(",")
}

fn state_str(s: PortState) -> &'static str {
    match s {
        PortState::Open => "open",
        PortState::Closed => "closed",
        PortState::Filtered => "filtered",
        PortState::OpenFiltered => "open|filtered",
    }
}

fn write_port(x: &mut String, p: &PortResult) {
    let proto = match p.protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    };
    let _ = write!(
        x,
        "<port protocol=\"{proto}\" portid=\"{}\"><state state=\"{}\" reason=\"{}\" reason_ttl=\"0\"/>",
        p.port,
        state_str(p.state),
        esc(p.reason)
    );
    match &p.service {
        Some(s) => {
            let _ = write!(x, "<service name=\"{}\"", esc(&s.name));
            for (key, value) in [
                ("product", &s.product),
                ("version", &s.version),
                ("extrainfo", &s.extra_info),
            ] {
                if let Some(v) = value {
                    let _ = write!(x, " {key}=\"{}\"", esc(v));
                }
            }
            if let Some(t) = s.tunnel {
                let _ = write!(x, " tunnel=\"{t}\"");
            }
            if let Some(fp) = &s.fingerprint {
                let _ = write!(x, " servicefp=\"{}\"", esc(fp));
            }
            x.push_str(" method=\"probed\" conf=\"10\"/>");
        }
        None => {
            let _ = write!(
                x,
                "<service name=\"{}\" method=\"table\" conf=\"3\"/>",
                service_name(p.protocol, p.port)
            );
        }
    }
    x.push_str("</port>\n");
}

fn write_host(x: &mut String, host: &HostResult, info: &RunInfo, start: u64, end: u64) {
    let up = reported(host, info);
    let _ = writeln!(x, "<host starttime=\"{start}\" endtime=\"{end}\">");
    let reason = host.up_reason.unwrap_or(if info.assume_up {
        "user-set"
    } else {
        "no-response"
    });
    let _ = writeln!(
        x,
        "<status state=\"{}\" reason=\"{}\" reason_ttl=\"0\"/>",
        if up { "up" } else { "down" },
        esc(reason)
    );
    let addrtype = match host.addr {
        IpAddr::V4(_) => "ipv4",
        IpAddr::V6(_) => "ipv6",
    };
    let _ = writeln!(
        x,
        "<address addr=\"{}\" addrtype=\"{addrtype}\"/>",
        host.addr
    );
    match &host.hostname {
        Some(name) => {
            let _ = writeln!(
                x,
                "<hostnames>\n<hostname name=\"{}\" type=\"user\"/>\n</hostnames>",
                esc(name)
            );
        }
        None => x.push_str("<hostnames>\n</hostnames>\n"),
    }
    if !info.ping_only {
        let (hidden, rows) = port_rows(host, info);
        x.push_str("<ports>");
        if let (false, Some((n, state))) = (info.only_open, hidden) {
            let _ = write!(
                x,
                "<extraports state=\"{}\" count=\"{n}\">\n</extraports>",
                state_str(state)
            );
        }
        x.push('\n');
        for p in rows {
            write_port(x, p);
        }
        x.push_str("</ports>\n");
    }
    if let Some(ms) = host.latency_ms {
        // nmap reports times in microseconds.
        let us = (ms * 1000.0).round() as u64;
        let _ = writeln!(x, "<times srtt=\"{us}\" rttvar=\"{us}\" to=\"100000\"/>");
    }
    x.push_str("</host>\n");
}

/// The whole report as an nmap-style XML document.
pub fn render(hosts: &[HostResult], info: &RunInfo) -> String {
    let start = unix_secs(info.start);
    let finish = info.start + info.elapsed;
    let end = unix_secs(finish);
    let mut x = String::new();
    x.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE nmaprun>\n");
    let _ = writeln!(
        x,
        "<nmaprun scanner=\"feroprobe\" args=\"{}\" start=\"{start}\" startstr=\"{}\" version=\"{}\" xmloutputversion=\"1.05\">",
        esc(&info.args),
        time_str(info.start),
        env!("CARGO_PKG_VERSION")
    );
    for scan in &info.scan_types {
        let (kind, protocol, ports) = match *scan {
            "tcp-syn" => ("syn", "tcp", &info.tcp_ports),
            "tcp-connect" => ("connect", "tcp", &info.tcp_ports),
            "udp" => ("udp", "udp", &info.udp_ports),
            _ => continue,
        };
        let _ = writeln!(
            x,
            "<scaninfo type=\"{kind}\" protocol=\"{protocol}\" numservices=\"{}\" services=\"{}\"/>",
            ports.len(),
            port_ranges(ports)
        );
    }
    let mut up = 0;
    for host in hosts.iter().filter(|h| reported(h, info)) {
        up += 1;
        write_host(&mut x, host, info, start, end);
    }
    let elapsed = info.elapsed.as_secs_f64();
    let _ = writeln!(
        x,
        "<runstats><finished time=\"{end}\" timestr=\"{}\" elapsed=\"{elapsed:.2}\" summary=\"FeroProbe done: {} host(s), {up} up, in {elapsed:.2}s\" exit=\"success\"/><hosts up=\"{up}\" down=\"{}\" total=\"{}\"/>\n</runstats>",
        time_str(finish),
        hosts.len(),
        hosts.len() - up,
        hosts.len()
    );
    x.push_str("</nmaprun>\n");
    x
}

#[cfg(test)]
mod tests {
    use super::*;
    use feroprobe_core::ServiceInfo;
    use std::time::Duration;

    fn info() -> RunInfo {
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
            assume_up: false,
            ping_only: false,
        }
    }

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
    fn ranges_and_time() {
        assert_eq!(port_ranges(&[443, 22, 80, 81, 82]), "22,80-82,443");
        assert_eq!(port_ranges(&[]), "");
        assert_eq!(time_str(UNIX_EPOCH), "Thu Jan  1 00:00:00 1970 UTC");
        assert_eq!(
            time_str(UNIX_EPOCH + Duration::from_secs(1_794_591_914)),
            "Fri Nov 13 17:45:14 2026 UTC"
        );
        assert_eq!(
            time_str(UNIX_EPOCH + Duration::from_secs(951_782_400)),
            "Tue Feb 29 00:00:00 2000 UTC"
        );
    }

    #[test]
    fn report_layout() {
        let mut host = HostResult::new("10.0.0.5".parse().unwrap(), Some("box".into()));
        host.up_reason = Some("echo-reply");
        host.latency_ms = Some(0.25);
        let ssh = ServiceInfo {
            name: "ssh".into(),
            product: Some("OpenSSH".into()),
            version: Some("9.6".into()),
            extra_info: Some("a <b> & \"c\"".into()),
            ..Default::default()
        };
        host.ports = vec![
            port(22, PortState::Open, Some(ssh)),
            port(80, PortState::Closed, None),
            port(81, PortState::Closed, None),
            port(443, PortState::Open, None),
        ];
        let xml = render(&[host], &info());
        for want in [
            "args=\"feroprobe -sV &lt;x&gt; &amp; &quot;y&quot;\"",
            "<scaninfo type=\"connect\" protocol=\"tcp\" numservices=\"5\" services=\"22,80-82,443\"/>",
            "<status state=\"up\" reason=\"echo-reply\" reason_ttl=\"0\"/>",
            "<address addr=\"10.0.0.5\" addrtype=\"ipv4\"/>",
            "<hostname name=\"box\" type=\"user\"/>",
            "<extraports state=\"closed\" count=\"2\">",
            "<port protocol=\"tcp\" portid=\"22\"><state state=\"open\" reason=\"syn-ack\" reason_ttl=\"0\"/><service name=\"ssh\" product=\"OpenSSH\" version=\"9.6\" extrainfo=\"a &lt;b&gt; &amp; &quot;c&quot;\" method=\"probed\" conf=\"10\"/></port>",
            "<service name=\"https\" method=\"table\" conf=\"3\"/>",
            "<times srtt=\"250\"",
            "<hosts up=\"1\" down=\"0\" total=\"1\"/>",
        ] {
            assert!(xml.contains(want), "missing {want} in\n{xml}");
        }
        assert!(!xml.contains("portid=\"80\""));
        // Every element that opens is closed.
        for tag in ["nmaprun", "host", "ports", "port", "runstats", "hostnames"] {
            let opened =
                xml.matches(&format!("<{tag}>")).count() + xml.matches(&format!("<{tag} ")).count();
            assert_eq!(opened, xml.matches(&format!("</{tag}>")).count(), "{tag}");
        }
    }
}
