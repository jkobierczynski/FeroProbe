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
            c if is_xml_char(c) => out.push(c),
            // Characters XML 1.0 forbids even escaped: drop them.
            _ => {}
        }
    }
    out
}

/// Whether XML 1.0 allows `c` in a document (its `Char` production).
fn is_xml_char(c: char) -> bool {
    matches!(c,
        '\t' | '\n' | '\r'
        | '\u{20}'..='\u{D7FF}'
        | '\u{E000}'..='\u{FFFD}'
        | '\u{10000}'..)
}

fn unix_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// `Fri Nov 13 17:45:14 2026 UTC`, like nmap's `startstr` but in UTC.
pub(crate) fn time_str(t: SystemTime) -> String {
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
        PortState::Unfiltered => "unfiltered",
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
    let timedout = if host.timed_out {
        " timedout=\"true\""
    } else {
        ""
    };
    let _ = writeln!(
        x,
        "<host starttime=\"{start}\" endtime=\"{end}\"{timedout}>"
    );
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
    if let Some(mac) = &host.mac {
        let _ = write!(x, "<address addr=\"{}\" addrtype=\"mac\"", mac.addr);
        if let Some(v) = mac.vendor {
            let _ = write!(x, " vendor=\"{}\"", esc(v));
        }
        x.push_str("/>\n");
    }
    x.push_str("<hostnames>\n");
    for (name, kind) in [(&host.hostname, "user"), (&host.rdns, "PTR")] {
        if let Some(name) = name {
            let _ = writeln!(x, "<hostname name=\"{}\" type=\"{kind}\"/>", esc(name));
        }
    }
    x.push_str("</hostnames>\n");
    if !info.ping_only && !host.timed_out {
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
    if let Some(os) = &host.os {
        let _ = writeln!(
            x,
            "<os><portused state=\"open\" proto=\"tcp\" portid=\"{}\"/>\n<osmatch name=\"{}\" accuracy=\"{}\" line=\"0\"><osclass type=\"{}\" vendor=\"{}\" osfamily=\"{}\" accuracy=\"{}\"/></osmatch>\n<osfingerprint fingerprint=\"{}\"/>\n</os>",
            os.port,
            esc(&os.name),
            os.accuracy,
            os.device_type,
            esc(os.vendor),
            esc(os.family),
            os.accuracy,
            esc(&os.traits.fingerprint())
        );
        let _ = writeln!(x, "<distance value=\"{}\"/>", os.distance);
    }
    if let Some(t) = &host.trace
        && !t.hops.is_empty()
    {
        let _ = writeln!(x, "<trace port=\"{}\" proto=\"{}\">", t.port, t.protocol);
        // nmap leaves silent hops out of the XML.
        for hop in t.hops.iter().filter(|h| h.addr.is_some()) {
            let _ = write!(x, "<hop ttl=\"{}\"", hop.ttl);
            if let Some(a) = hop.addr {
                let _ = write!(x, " ipaddr=\"{a}\"");
            }
            if let Some(ms) = hop.rtt_ms {
                let _ = write!(x, " rtt=\"{ms:.2}\"");
            }
            x.push_str("/>\n");
        }
        x.push_str("</trace>\n");
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
    // Some importers only accept reports whose scanner is "nmap". The
    // comment keeps the real producer on record; nmap's DTD has no
    // attribute for it.
    let scanner = if info.nmap_label {
        let _ = writeln!(
            x,
            "<!-- Generated by FeroProbe {}, labelled as nmap for compatibility -->",
            env!("CARGO_PKG_VERSION")
        );
        "nmap"
    } else {
        "feroprobe"
    };
    let _ = writeln!(
        x,
        "<nmaprun scanner=\"{scanner}\" args=\"{}\" start=\"{start}\" startstr=\"{}\" version=\"{}\" xmloutputversion=\"1.05\">",
        esc(&info.args),
        time_str(info.start),
        env!("CARGO_PKG_VERSION")
    );
    for scan in &info.scan_types {
        let (kind, protocol, ports) = match *scan {
            "udp" => ("udp", "udp", &info.udp_ports),
            // tcp-syn, tcp-connect, tcp-fin, tcp-ack, ...: nmap's own names.
            s if s.starts_with("tcp-") => (&s[4..], "tcp", &info.tcp_ports),
            _ => continue,
        };
        let _ = writeln!(
            x,
            "<scaninfo type=\"{kind}\" protocol=\"{protocol}\" numservices=\"{}\" services=\"{}\"/>",
            ports.len(),
            port_ranges(ports)
        );
    }
    // nmap's DTD wants these two after scaninfo, before the hosts.
    let _ = writeln!(
        x,
        "<verbose level=\"{}\"/>\n<debugging level=\"0\"/>",
        info.verbosity
    );
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

    use crate::output::tests::info;

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
    fn forbidden_characters_keep_the_report_parseable() {
        assert_eq!(esc("a\u{1}b\u{FFFE}c\u{FFFF}d\te"), "abcd\te");
        let mut host = HostResult::new("10.0.0.5".parse().unwrap(), None);
        host.ports = vec![port(
            22,
            PortState::Open,
            Some(ServiceInfo {
                name: "x".into(),
                product: Some("bad\u{FFFF}\u{0}\u{1b}[0m<&>\u{1F600}".into()),
                ..Default::default()
            }),
        )];
        let xml = render(&[host], &info());
        let doc = roxmltree::Document::parse_with_options(
            &xml,
            roxmltree::ParsingOptions {
                allow_dtd: true,
                ..Default::default()
            },
        )
        .expect("well-formed XML");
        let service = doc
            .descendants()
            .find(|n| n.has_tag_name("service"))
            .unwrap();
        assert_eq!(service.attribute("product"), Some("bad[0m<&>\u{1F600}"));
        // Element order nmap's DTD expects at the top level.
        let top: Vec<_> = doc
            .root_element()
            .children()
            .filter(|n| n.is_element())
            .map(|n| n.tag_name().name())
            .collect();
        assert_eq!(
            top,
            ["scaninfo", "verbose", "debugging", "host", "runstats"]
        );
    }

    #[test]
    fn nmap_label() {
        let plain = render(&[], &info());
        assert!(plain.contains("<nmaprun scanner=\"feroprobe\" "));
        assert!(!plain.contains("<!--"));

        let labelled = render(
            &[],
            &RunInfo {
                nmap_label: true,
                ..info()
            },
        );
        assert!(labelled.contains("<nmaprun scanner=\"nmap\" "));
        assert!(labelled.contains("<!-- Generated by FeroProbe "));
        let opts = roxmltree::ParsingOptions {
            allow_dtd: true,
            ..Default::default()
        };
        let doc = roxmltree::Document::parse_with_options(&labelled, opts).unwrap();
        assert_eq!(doc.root_element().attribute("scanner"), Some("nmap"));
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
        host.rdns = Some("box.example".into());
        host.up_reason = Some("echo-reply");
        host.latency_ms = Some(0.25);
        // Built by hand: MacInfo::new would consult the system's OUI list.
        host.mac = Some(feroprobe_core::MacInfo {
            addr: feroprobe_core::MacAddr([0x00, 0x50, 0x56, 0x01, 0x02, 0x03]),
            vendor: Some("VMware"),
        });
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
            "<address addr=\"10.0.0.5\" addrtype=\"ipv4\"/>\n<address addr=\"00:50:56:01:02:03\" addrtype=\"mac\" vendor=\"VMware\"/>",
            "<hostnames>\n<hostname name=\"box\" type=\"user\"/>\n<hostname name=\"box.example\" type=\"PTR\"/>\n</hostnames>",
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

    #[test]
    fn timed_out_host() {
        let mut host = HostResult::new("10.0.0.9".parse().unwrap(), None);
        host.up_reason = Some("echo-reply");
        host.ports = vec![port(22, PortState::Open, None)];
        host.timed_out = true;
        let xml = render(&[host], &info());
        assert!(xml.contains("timedout=\"true\">"), "{xml}");
        assert!(!xml.contains("<ports>"), "{xml}");
        let opts = roxmltree::ParsingOptions {
            allow_dtd: true,
            ..Default::default()
        };
        roxmltree::Document::parse_with_options(&xml, opts).expect("well-formed XML");
    }

    #[test]
    fn trace_lists_answering_hops() {
        use feroprobe_core::{Hop, Trace};
        let mut host = HostResult::new("203.0.113.5".parse().unwrap(), None);
        host.ports = vec![port(443, PortState::Open, None)];
        let hop = |ttl, addr: Option<&str>, rtt| Hop {
            ttl,
            addr: addr.map(|a| a.parse().unwrap()),
            rtt_ms: rtt,
        };
        host.trace = Some(Trace {
            port: 443,
            protocol: Protocol::Tcp,
            hops: vec![
                hop(1, Some("192.0.2.1"), Some(0.5)),
                hop(2, None, None),
                hop(3, Some("203.0.113.5"), Some(12.345)),
            ],
            reached: true,
        });
        let xml = render(&[host], &info());
        assert!(
            xml.contains(
                "<trace port=\"443\" proto=\"tcp\">\n<hop ttl=\"1\" ipaddr=\"192.0.2.1\" rtt=\"0.50\"/>\n<hop ttl=\"3\" ipaddr=\"203.0.113.5\" rtt=\"12.35\"/>\n</trace>\n"
            ),
            "{xml}"
        );
    }
}
