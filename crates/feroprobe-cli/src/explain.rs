//! `--explain`: before anything is sent, print the plan FeroProbe made from
//! the command line, step by step, with the reason for each choice.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

use feroprobe_core::{PingProbes, ScanConfig, Target};

use crate::{Args, Plan, ScanType};

/// What the plan was built from, beyond the command line.
pub(crate) struct Facts<'a> {
    pub targets: &'a [Target],
    pub excluded: usize,
    pub plan: &'a Plan,
    pub probes: &'a PingProbes,
    /// Raw sockets may be used (root or CAP_NET_RAW on Linux).
    pub privileged: bool,
    /// ICMP echo can be sent (raw, or an unprivileged ping socket).
    pub icmp: bool,
    /// Targets on a directly connected network, by interface name.
    pub local: BTreeMap<String, usize>,
    pub tcp_ports: &'a [u16],
    pub udp_ports: &'a [u16],
    pub cfg: &'a ScanConfig,
    pub os: bool,
    pub trace: bool,
}

fn ports(list: &[u16]) -> String {
    let shown: Vec<String> = list.iter().take(8).map(u16::to_string).collect();
    let more = if list.len() > 8 { ", ..." } else { "" };
    format!("{}{more}", shown.join(","))
}

fn plural(n: usize, one: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {one}s")
    }
}

fn duration(d: Duration) -> String {
    if d.as_millis() < 1000 {
        format!("{} ms", d.as_millis())
    } else {
        format!("{:.1} s", d.as_secs_f64())
    }
}

/// The plan, one line per decision, numbered by phase as nmap runs them.
pub(crate) fn explain(args: &Args, f: &Facts) -> Vec<String> {
    let mut out = vec!["FeroProbe plan (--explain), before anything is sent:".to_string()];
    let mut step = 0;
    let mut head = |out: &mut Vec<String>, title: &str| {
        step += 1;
        out.push(format!("{step}. {title}"));
    };
    // A line starting with two spaces is a sub-item of the line before.
    let say = |out: &mut Vec<String>, line: String| match line.strip_prefix("  ") {
        Some(sub) => out.push(format!("     * {sub}")),
        None => out.push(format!("   - {line}")),
    };

    // 1. Targets.
    head(&mut out, "Targets");
    let v6 = f.targets.iter().filter(|t| t.addr.is_ipv6()).count();
    say(
        &mut out,
        format!(
            "{} to scan ({} IPv4, {v6} IPv6)",
            plural(f.targets.len(), "host"),
            f.targets.len() - v6
        ),
    );
    if f.excluded > 0 {
        say(
            &mut out,
            format!(
                "{} left out by --exclude/--excludefile",
                plural(f.excluded, "host")
            ),
        );
    }
    if f.targets.iter().any(|t| t.hostname.is_some()) {
        let why = if args.ipv6 {
            "IPv6 address, because of -6"
        } else {
            "IPv4 address (nmap's default; -6 picks IPv6)"
        };
        say(&mut out, format!("hostnames are scanned at their {why}"));
    }
    if args.randomize_hosts {
        say(
            &mut out,
            "hosts are scanned in random order (--randomize-hosts)".into(),
        );
    }

    // 2. Host discovery.
    head(&mut out, "Host discovery");
    let p = f.plan;
    if !p.discovery {
        say(
            &mut out,
            "skipped (-Pn): every target is treated as up".into(),
        );
    } else {
        let local: usize = f.local.values().sum();
        if local > 0 {
            let nets: Vec<String> = if f.local.len() == 1 {
                f.local.keys().cloned().collect()
            } else {
                f.local.iter().map(|(i, n)| format!("{n} on {i}")).collect()
            };
            say(
                &mut out,
                format!(
                    "{} on a local network ({}) {} asked with ARP (IPv4) or neighbour discovery (IPv6); only that answer counts, so no other probes go to {}. --disable-arp-ping turns this off",
                    plural(local, "host"),
                    nets.join(", "),
                    if local == 1 { "is" } else { "are" },
                    if local == 1 { "it" } else { "them" }
                ),
            );
        } else if !f.cfg.arp_ping {
            say(
                &mut out,
                "no ARP or neighbour discovery (--disable-arp-ping)".into(),
            );
        } else if !f.privileged {
            say(
                &mut out,
                "no ARP or neighbour discovery: that needs raw sockets (root on Linux)".into(),
            );
        }
        if local > 0 && local == f.targets.len() {
            say(
                &mut out,
                "no other hosts, so no ping probes are sent".into(),
            );
        } else {
            let chosen = !args.ping.is_empty();
            let source = if chosen {
                "the -P options"
            } else {
                "the default probes, as nmap's"
            };
            say(
                &mut out,
                format!("other hosts get {source}; any answer means the host is up:"),
            );
            let pr = f.probes;
            if pr.echo {
                let how = if !f.icmp {
                    "not sent: no raw socket and no unprivileged ping socket here"
                } else if f.privileged {
                    "raw socket"
                } else {
                    "unprivileged ping socket"
                };
                say(&mut out, format!("  ICMP echo request ({how})"));
            }
            if pr.timestamp || pr.mask {
                say(
                    &mut out,
                    "  ICMP timestamp/address mask request (IPv4, raw sockets)".into(),
                );
            }
            if !pr.syn.is_empty() {
                say(
                    &mut out,
                    format!(
                        "  TCP connect to port {} (a handshake or a reset proves the host)",
                        ports(&pr.syn)
                    ),
                );
            }
            if !pr.ack.is_empty() {
                let how = if f.privileged {
                    "bare ACK, answered by a reset"
                } else {
                    "a connect, since a bare ACK needs raw sockets"
                };
                say(
                    &mut out,
                    format!("  TCP ACK to port {} ({how})", ports(&pr.ack)),
                );
            }
            if !pr.udp.is_empty() {
                say(
                    &mut out,
                    format!(
                        "  UDP to port {} (a reply or a port unreachable proves the host)",
                        ports(&pr.udp)
                    ),
                );
            }
        }
        if args.exclude_ports.is_some() {
            say(
                &mut out,
                "--exclude-ports also applies to these probe ports, as in nmap".into(),
            );
        }
        if p.ping_only {
            say(&mut out, "-sn: stop here, no port scan".into());
        }
    }

    // 3. Names.
    head(&mut out, "Reverse DNS");
    let servers = if args.dns_servers.is_empty() {
        "the system resolver".to_string()
    } else {
        let list: Vec<String> = args.dns_servers.iter().map(ToString::to_string).collect();
        list.join(", ")
    };
    if args.no_resolve {
        say(&mut out, "off (-n)".into());
    } else if args.always_resolve {
        say(&mut out, format!("every target (-R), asking {servers}"));
    } else {
        say(
            &mut out,
            format!("hosts that are up, asking {servers} (-n turns it off, -R asks for all)"),
        );
    }

    // 4. Port scan.
    if !p.ping_only {
        head(&mut out, "Port scan");
        if let Some(t) = p.tcp {
            let explicit = args.scan.iter().any(|s| ScanType::TCP.contains(s));
            let why = match (explicit, t) {
                (true, _) => format!("asked for with {}", t.flag()),
                (false, ScanType::Syn) => "the default, because raw sockets may be used".into(),
                (false, _) => {
                    "the default, because raw sockets are not available (not root)".into()
                }
            };
            let name = match t {
                ScanType::Syn => "TCP SYN scan",
                ScanType::Connect => "TCP connect scan",
                ScanType::Fin => "TCP FIN scan",
                ScanType::Null => "TCP NULL scan",
                ScanType::Xmas => "TCP Xmas scan",
                ScanType::Ack => "TCP ACK scan",
                ScanType::Window => "TCP Window scan",
                ScanType::Maimon => "TCP Maimon scan",
                _ => "TCP scan",
            };
            say(&mut out, format!("{name} ({}): {why}", t.flag()));
            if args.scanflags.is_some() {
                say(&mut out, "with the TCP flags from --scanflags".into());
            }
            say(
                &mut out,
                format!("{} TCP ports: {}", f.tcp_ports.len(), ports(f.tcp_ports)),
            );
        }
        if p.udp {
            say(
                &mut out,
                format!(
                    "UDP scan (-sU), {} UDP ports: {}",
                    f.udp_ports.len(),
                    ports(f.udp_ports)
                ),
            );
        }
        let source = if let Some(spec) = &args.ports {
            format!("-p {spec}")
        } else if args.fast {
            "-F (the 100 most common)".into()
        } else if let Some(n) = args.top_ports {
            format!("--top-ports {n}")
        } else {
            "the default: the 100 most common TCP and 20 most common UDP ports".into()
        };
        say(&mut out, format!("ports come from {source}"));
        if let Some(ex) = &args.exclude_ports {
            say(&mut out, format!("minus --exclude-ports {ex}"));
        }
        let order = if args.ordered_ports {
            "in order (-r)"
        } else {
            "in shuffled order, as nmap does (-r keeps them in order)"
        };
        say(&mut out, format!("probed {order}"));
    }

    // 5. Timing.
    head(&mut out, "Timing");
    let c = f.cfg;
    let template = args.timing.map_or_else(
        || "T3 (normal, the default)".to_string(),
        |t| format!("T{} ({})", t.level(), t.name()),
    );
    say(&mut out, format!("template {template}"));
    say(
        &mut out,
        format!(
            "wait {} for each answer and retry {} more time{}; at most {} connect/UDP probes at once and {} packets per second",
            duration(c.timeout),
            c.retries,
            if c.retries == 1 { "" } else { "s" },
            c.concurrency,
            c.max_rate
        ),
    );
    if !c.scan_delay.is_zero() {
        say(
            &mut out,
            format!(
                "at least {} between probes (--scan-delay or the template)",
                duration(c.scan_delay)
            ),
        );
    }
    if let Some(min) = args.min_rate {
        say(
            &mut out,
            format!("--min-rate {min}: limits raised so at least {min} probes go out per second"),
        );
    }
    if let Some(limit) = args.host_timeout.filter(|d| !d.is_zero()) {
        say(
            &mut out,
            format!(
                "each host gets its own clock and is dropped after {} (--host-timeout)",
                duration(limit)
            ),
        );
    }

    // 6. After the scan.
    let mut extras = Vec::new();
    if p.version {
        extras.push("service and version detection on open ports (-sV)".to_string());
    }
    if f.os {
        extras.push("OS detection from SYN-ACK traits (-O)".to_string());
    }
    if f.trace {
        extras.push("traceroute to each host that is up (--traceroute)".to_string());
    }
    if !extras.is_empty() {
        head(&mut out, "After the port scan");
        for e in extras {
            say(&mut out, e);
        }
    }
    out
}

/// Targets on a directly connected network, by interface, the way host
/// discovery groups them for ARP and neighbour discovery.
pub(crate) fn local_targets(targets: &[Target]) -> BTreeMap<String, usize> {
    let nets = feroprobe_core::arp::local_networks().unwrap_or_default();
    let links = feroprobe_core::ndp::local_links().unwrap_or_default();
    let mut by_if: BTreeMap<String, usize> = BTreeMap::new();
    for t in targets {
        let name = match t.addr {
            IpAddr::V4(ip) => {
                feroprobe_core::arp::local_net_for(ip, &nets).map(|n| n.ifname.clone())
            }
            IpAddr::V6(ip) => feroprobe_core::ndp::link_for(ip, &links).map(|l| l.ifname.clone()),
        };
        if let Some(name) = name {
            *by_if.entry(name).or_default() += 1;
        }
    }
    by_if
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn plan_lines_give_reasons() {
        let args = Args::try_parse_from([
            "feroprobe",
            "-F",
            "--exclude-ports",
            "80",
            "-sV",
            "10.0.0.1",
        ])
        .unwrap();
        let plan = crate::plan(&args.scan, false, false, false).unwrap();
        let targets = [Target::new("10.0.0.1".parse().unwrap())];
        let cfg = ScanConfig::default();
        let probes = PingProbes {
            syn: vec![443],
            ..PingProbes::default()
        };
        let facts = Facts {
            targets: &targets,
            excluded: 0,
            plan: &plan,
            probes: &probes,
            privileged: false,
            icmp: true,
            local: BTreeMap::new(),
            tcp_ports: &[22, 443],
            udp_ports: &[],
            cfg: &cfg,
            os: false,
            trace: false,
        };
        let text = explain(&args, &facts).join("\n");
        for want in [
            "1 host to scan",
            "no ARP or neighbour discovery: that needs raw sockets",
            "ICMP echo request (unprivileged ping socket)",
            "TCP connect to port 443",
            "--exclude-ports also applies to these probe ports",
            "TCP connect scan (-sT): the default, because raw sockets are not available",
            "ports come from -F",
            "minus --exclude-ports 80",
            "template T3 (normal, the default)",
            "service and version detection",
        ] {
            assert!(text.contains(want), "missing {want:?} in:\n{text}");
        }
    }
}
