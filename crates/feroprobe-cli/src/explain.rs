//! `--explain`: before anything is sent, print the plan FeroProbe made from
//! the command line, step by step, with the reason for each choice.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use feroprobe_core::script::Script;
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
    /// The TCP ping probes go out as raw SYNs and ACKs, not connects.
    pub raw_pings: bool,
    /// Targets that are this machine, marked up without a probe (only
    /// counted when privileged, as nmap only skips them then).
    pub localhost: usize,
    /// Targets on a directly connected network, by interface name.
    pub local: BTreeMap<String, usize>,
    pub tcp_ports: &'a [u16],
    /// The FTP bounce relay (`-b`), as `server:port (address)`, without
    /// the login.
    pub bounce: Option<String>,
    pub udp_ports: &'a [u16],
    pub sctp_ports: &'a [u16],
    pub protocols: &'a [u8],
    pub cfg: &'a ScanConfig,
    pub os: bool,
    pub trace: bool,
    /// The scripts `--script`, `-sC` or `-A` chose, loaded; empty when
    /// none run.
    pub scripts: &'a [Arc<Script>],
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

/// How long probes wait, for the timing step.
fn wait_text(rtt: &feroprobe_core::RttTimeouts) -> String {
    if rtt.min == rtt.max {
        format!("wait a fixed {} for each answer", duration(rtt.min))
    } else {
        format!(
            "wait {} for each answer at first, then adapt to each host's measured round-trip time (between {} and {})",
            duration(rtt.initial),
            duration(rtt.min),
            duration(rtt.max)
        )
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
    if p.list {
        say(
            &mut out,
            "none: -sL only lists the targets and sends them nothing, not even ARP".into(),
        );
    } else if !p.discovery {
        say(
            &mut out,
            "skipped (-Pn): every target is treated as up".into(),
        );
    } else {
        if f.localhost > 0 {
            say(
                &mut out,
                format!(
                    "{} {} this machine, so {} up without a probe (localhost-response), as nmap does when privileged",
                    plural(f.localhost, "target"),
                    if f.localhost == 1 { "is" } else { "are" },
                    if f.localhost == 1 {
                        "it is"
                    } else {
                        "they are"
                    },
                ),
            );
        }
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
        if local + f.localhost == f.targets.len() {
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
                let line = if f.raw_pings {
                    format!(
                        "  TCP SYN to port {} (raw; a SYN/ACK or a reset proves the host)",
                        ports(&pr.syn)
                    )
                } else {
                    format!(
                        "  TCP connect to port {} (a handshake or a reset proves the host)",
                        ports(&pr.syn)
                    )
                };
                say(&mut out, line);
            }
            if !pr.ack.is_empty() {
                let how = if f.raw_pings {
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
            if !pr.sctp.is_empty() {
                say(
                    &mut out,
                    format!(
                        "  SCTP INIT to port {} (raw; an INIT-ACK, an ABORT or the host's own port or protocol unreachable proves it)",
                        ports(&pr.sctp)
                    ),
                );
            }
            if !pr.proto.is_empty() {
                let names: Vec<String> = pr
                    .proto
                    .iter()
                    .map(|&n| format!("{n} ({})", feroprobe_core::ip_protocol_name(n)))
                    .collect();
                say(
                    &mut out,
                    format!(
                        "  IP protocol ping, protocol {} (raw; an answer in that protocol or the host's own protocol unreachable proves it)",
                        names.join(", ")
                    ),
                );
            }
        }
        if args.ping.contains(&crate::PingArg::Arp) {
            say(
                &mut out,
                "-PR adds nothing: ARP and neighbour discovery already run where they can, as in nmap"
                    .into(),
            );
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
    } else if p.list {
        say(
            &mut out,
            format!("every target, as a list scan does, asking {servers} (-n turns it off)"),
        );
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
        if let Some(relay) = &f.bounce {
            say(
                &mut out,
                format!(
                    "FTP bounce scan (-b) through the relay {relay}, which connects to each port \
                     for us, {} TCP ports: {}",
                    f.tcp_ports.len(),
                    ports(f.tcp_ports)
                ),
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
        if let Some(kind) = p.sctp {
            let (flag, name) = match kind {
                feroprobe_core::SctpScanKind::Init => ("-sY", "SCTP INIT scan"),
                feroprobe_core::SctpScanKind::CookieEcho => ("-sZ", "SCTP COOKIE ECHO scan"),
            };
            say(
                &mut out,
                format!(
                    "{name} ({flag}), {} SCTP ports: {}",
                    f.sctp_ports.len(),
                    ports(f.sctp_ports)
                ),
            );
        }
        if p.ip_proto {
            let protos: Vec<u16> = f.protocols.iter().map(|&n| u16::from(n)).collect();
            say(
                &mut out,
                format!(
                    "IP protocol scan (-sO), {} protocols: {}",
                    protos.len(),
                    ports(&protos)
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
            "the defaults: the 1000 most common TCP and UDP ports, the 50 most common SCTP ports, \
             all 256 IP protocols with -sO"
                .into()
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
            "{} and resend {}; at most {} probes waiting for an answer at once{}",
            wait_text(&c.rtt),
            match c.retries {
                0 => "nothing".to_string(),
                1 => "once".to_string(),
                n => format!("once, or up to {n} times to hosts that lose probes"),
            },
            c.concurrency,
            c.max_rate
                .map_or(String::new(), |r| format!(" and {r} packets per second"))
        ),
    );
    if let Some(min) = args.min_parallelism {
        say(
            &mut out,
            format!("--min-parallelism {min}: at least {min} connect/UDP probes at once"),
        );
    }
    if let Some(name) = &args.interface {
        say(
            &mut out,
            format!("send and receive on interface {name} (-e); only its networks count as local"),
        );
    }
    if let Some(port) = args.source_port {
        say(
            &mut out,
            format!(
                "raw TCP/UDP/SCTP probes and UDP scan probes from source port {port} (-g); \
                 connect scans, -sV, traceroute and DNS keep their own ports"
            ),
        );
    }
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
            format!(
                "--min-rate {min}: aim for at least {min} probes per second, \
                 a target, not a promise: -c and the open-file limit still cap it"
            ),
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
        let intensity = crate::version_intensity(args);
        extras.push(format!(
            "service and version detection on open ports, and UDP ports left open|filtered \
             (-sV, intensity {intensity})"
        ));
    }
    if f.os {
        extras.push(
            "OS detection (-O): up to 9 probes per try to an open and a closed TCP port the \
             scan finds (and an ICMP echo if discovery sends echo requests), matched against \
             FeroProbe's own OS database"
                .to_string(),
        );
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

    // 7. Scripts.
    if !f.scripts.is_empty() {
        head(&mut out, "Script scan");
        for line in script_lines(args, f) {
            say(&mut out, line);
        }
    }
    out
}

/// Where and when the chosen scripts run: the scope every script's
/// connections are held to, then the scripts by phase, with what the
/// built-in scripts' rules key on. A script from a file gets its name
/// only: its rule is its own Lua code, which says nothing about its
/// targets before it runs.
fn script_lines(args: &Args, f: &Facts) -> Vec<String> {
    let mut out = Vec::new();
    let how = match (args.script.is_empty(), crate::default_scripts(args)) {
        (true, _) if args.aggressive => "the default scripts (-sC, part of -A)".to_string(),
        (true, _) => "the default scripts (-sC)".to_string(),
        (false, true) => format!(
            "the scripts chosen by --script {} and the default scripts (-sC{})",
            args.script.join(","),
            if args.aggressive { ", part of -A" } else { "" }
        ),
        (false, false) => format!("the scripts chosen by --script {}", args.script.join(",")),
    };
    out.push(format!("{}: {how}", plural(f.scripts.len(), "script")));

    // The scope envelope: the hard limit on every script connection.
    let hosts = if f.plan.list {
        "no host (-sL scans nothing)".to_string()
    } else {
        match f.targets.len() {
            n if !f.plan.discovery => format!("every target (-Pn), {}", plural(n, "host")),
            1 => "the target, if it is found up".to_string(),
            n => format!("whichever of the {n} targets are found up"),
        }
    };
    let tcp = f.tcp_ports;
    let udp = f.udp_ports;
    let ports = match (tcp.is_empty(), udp.is_empty()) {
        (true, true) => "no ports, since this scan probes none".to_string(),
        (false, true) => format!("{}: {}", plural(tcp.len(), "TCP port"), ports(tcp)),
        (true, false) => format!("{}: {}", plural(udp.len(), "UDP port"), ports(udp)),
        (false, false) => format!(
            "{}: {}, and {}: {}",
            plural(tcp.len(), "TCP port"),
            ports(tcp),
            plural(udp.len(), "UDP port"),
            ports(udp)
        ),
    };
    out.push(format!(
        "scope: a script may connect only to the host it runs against, on the ports this scan \
         probes there; FeroProbe refuses any other connection. Here that is {hosts}, on {ports}"
    ));
    if !f.sctp_ports.is_empty() || !f.protocols.is_empty() {
        out.push("scripts cannot open SCTP or raw IP sockets, whatever the scan probes".into());
    }
    out.extend(forced_out_of_scope(f));

    // The scripts by phase. A script with several rules shows under each.
    let built_in = |s: &Script| s.path.is_none();
    let names = |pick: &dyn Fn(&Script) -> bool| -> Vec<String> {
        f.scripts
            .iter()
            .filter(|s| pick(s))
            .map(|s| s.id.clone())
            .collect()
    };
    let pre = names(&|s| s.rules.prerule);
    if !pre.is_empty() {
        out.push(format!(
            "before the scan (prerule), sending nothing to the targets: {}",
            pre.join(", ")
        ));
    }
    for (phase, title, pick) in [
        (
            "hostrule",
            "once per host that is up (hostrule), when the rule says yes",
            (&|s: &Script| s.rules.hostrule) as &dyn Fn(&Script) -> bool,
        ),
        (
            "portrule",
            "once per port found open, open|filtered or unfiltered (portrule), when the rule \
             says yes",
            &|s: &Script| s.rules.portrule,
        ),
    ] {
        let chosen: Vec<&Arc<Script>> = f.scripts.iter().filter(|s| pick(s)).collect();
        if chosen.is_empty() {
            continue;
        }
        out.push(format!("{title}:"));
        // Built-in scripts that key on the same ports share a line.
        let mut groups: Vec<(&str, Vec<&str>)> = Vec::new();
        let mut own_code = Vec::new();
        for s in &chosen {
            let keys = built_in(s)
                .then(|| feroprobe_core::script::rule_keys(&s.id))
                .flatten();
            match keys {
                Some(k) => match groups.iter_mut().find(|(g, _)| *g == k) {
                    Some((_, ids)) => ids.push(&s.id),
                    None => groups.push((k, vec![&s.id])),
                },
                None => own_code.push(s.id.as_str()),
            }
        }
        for (keys, ids) in groups {
            out.push(format!("  {}: {keys}", ids.join(", ")));
        }
        if !own_code.is_empty() {
            out.push(format!(
                "  {}: the {phase} is the script's own code and names no ports; it is asked \
                 about each {}, inside the scope above",
                own_code.join(", "),
                if phase == "hostrule" { "host" } else { "port" }
            ));
        }
        if chosen.iter().any(|s| s.forced) {
            let forced: Vec<&str> = chosen
                .iter()
                .filter(|s| s.forced)
                .map(|s| s.id.as_str())
                .collect();
            out.push(format!(
                "  {}: forced with + in --script, so {} on every {} whatever {} rule says",
                forced.join(", "),
                if forced.len() == 1 {
                    "it runs"
                } else {
                    "they run"
                },
                if phase == "hostrule" { "host" } else { "port" },
                if forced.len() == 1 { "its" } else { "their" }
            ));
        }
    }
    let post = names(&|s| s.rules.postrule);
    if !post.is_empty() {
        out.push(format!(
            "after the scan (postrule), sending nothing to the targets: {}",
            post.join(", ")
        ));
    }
    out.push(
        "to see the connections scripts actually make: --script-trace, or -d2 for each script \
         run and the host and port it ran against"
            .into(),
    );
    out
}

/// A note for each protocol that forced built-in scripts need and this
/// scan does not probe: forced with +, they run on every host or port
/// anyway, and every connection they try is refused.
fn forced_out_of_scope(f: &Facts) -> Vec<String> {
    use feroprobe_core::script::{Needs, rule_needs};
    let mut out = Vec::new();
    for (proto, need, probed, how) in [
        ("UDP", Needs::Udp, f.udp_ports, "-sU to scan UDP"),
        ("TCP", Needs::Tcp, f.tcp_ports, "-sS or -sT to scan TCP"),
    ] {
        if !probed.is_empty() {
            continue;
        }
        let ids: Vec<&str> = f
            .scripts
            .iter()
            .filter(|s| s.forced && s.path.is_none() && rule_needs(&s.id) == Some(need))
            .map(|s| s.id.as_str())
            .collect();
        if ids.is_empty() {
            continue;
        }
        let one = ids.len() == 1;
        out.push(format!(
            "note: {} {} only over {proto}, and this scan probes no {proto} ports. Forced \
             with +, {} still {}, but FeroProbe refuses every connection {}: expect one \
             warning per script, or add {how}",
            ids.join(", "),
            if one { "connects" } else { "connect" },
            if one { "it" } else { "they" },
            if one { "runs" } else { "run" },
            if one { "it tries" } else { "they try" },
        ));
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
            raw_pings: false,
            localhost: 0,
            local: BTreeMap::new(),
            tcp_ports: &[22, 443],
            bounce: None,
            udp_ports: &[],
            sctp_ports: &[],
            protocols: &[],
            cfg: &cfg,
            os: false,
            trace: false,
            scripts: &[],
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

    #[test]
    fn script_scan_shows_scope_and_phases() {
        let args = Args::try_parse_from([
            "feroprobe",
            "--script",
            "ssh-hostkey,clock-skew,/x/mine.nse",
            "-p",
            "22",
            "10.0.0.1",
            "10.0.0.2",
        ])
        .unwrap();
        let plan = crate::plan(&args.scan, false, false, false).unwrap();
        let targets = [
            Target::new("10.0.0.1".parse().unwrap()),
            Target::new("10.0.0.2".parse().unwrap()),
        ];
        let cfg = ScanConfig::default();
        let probes = PingProbes::default();
        let mut scripts: Vec<Arc<Script>> = Script::built_in()
            .unwrap()
            .into_iter()
            .filter(|s| s.id == "ssh-hostkey" || s.id == "clock-skew")
            .map(Arc::new)
            .collect();
        let mine = Script::load(
            "mine",
            Some("/x/mine.nse".into()),
            "categories = {'safe'}\nportrule = function() return true end\n\
             action = function() end\n",
        )
        .unwrap();
        scripts.push(Arc::new(mine));
        let facts = Facts {
            targets: &targets,
            excluded: 0,
            plan: &plan,
            probes: &probes,
            privileged: false,
            icmp: true,
            raw_pings: false,
            localhost: 0,
            local: BTreeMap::new(),
            tcp_ports: &[22],
            bounce: None,
            udp_ports: &[],
            sctp_ports: &[],
            protocols: &[],
            cfg: &cfg,
            os: false,
            trace: false,
            scripts: &scripts,
        };
        let text = explain(&args, &facts).join("\n");
        for want in [
            "Script scan",
            "3 scripts: the scripts chosen by --script ssh-hostkey,clock-skew,/x/mine.nse",
            "Here that is whichever of the 2 targets are found up, on 1 TCP port: 22",
            "once per host that is up (hostrule), when the rule says yes:\n     * clock-skew: ",
            "* ssh-hostkey: TCP 22, or a TCP port named ssh",
            "* mine: the portrule is the script's own code and names no ports",
            "after the scan (postrule), sending nothing to the targets: clock-skew",
            "--script-trace, or -d2",
        ] {
            assert!(text.contains(want), "missing {want:?} in:\n{text}");
        }
        // An external script never gets a port list of its own.
        assert!(!text.contains("mine: TCP"), "{text}");
        assert!(!text.contains("note:"), "{text}");
    }

    #[test]
    fn forced_scripts_on_a_protocol_not_scanned() {
        let args = Args::try_parse_from(["feroprobe", "-p", "80", "10.0.0.1"]).unwrap();
        let plan = crate::plan(&args.scan, false, false, false).unwrap();
        let targets = [Target::new("10.0.0.1".parse().unwrap())];
        let cfg = ScanConfig::default();
        let probes = PingProbes::default();
        let pick = |ids: &[&str], forced: bool| -> Vec<Arc<Script>> {
            Script::built_in()
                .unwrap()
                .into_iter()
                .filter(|s| ids.contains(&s.id.as_str()))
                .map(|mut s| {
                    s.forced = forced;
                    Arc::new(s)
                })
                .collect()
        };
        let facts = |scripts, tcp, udp| Facts {
            targets: &targets,
            excluded: 0,
            plan: &plan,
            probes: &probes,
            privileged: false,
            icmp: true,
            raw_pings: false,
            localhost: 0,
            local: BTreeMap::new(),
            tcp_ports: tcp,
            bounce: None,
            udp_ports: udp,
            sctp_ports: &[],
            protocols: &[],
            cfg: &cfg,
            os: false,
            trace: false,
            scripts,
        };
        let both = pick(&["ntp-info", "snmp-info", "dns-nsid", "http-title"], true);
        let lines = forced_out_of_scope(&facts(&both, &[80], &[]));
        assert_eq!(
            lines,
            [
                "note: ntp-info, snmp-info connect only over UDP, and this scan probes no UDP \
              ports. Forced with +, they still run, but FeroProbe refuses every connection \
              they try: expect one warning per script, or add -sU to scan UDP"
            ]
        );
        // UDP scanned: nothing to say.
        assert!(forced_out_of_scope(&facts(&both, &[80], &[161])).is_empty());
        // Only -sU: the TCP-only scripts are named.
        let lines = forced_out_of_scope(&facts(&both, &[], &[161]));
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].starts_with("note: http-title connects only over TCP"),
            "{lines:?}"
        );
        // Not forced: the rule keeps them off, so no note.
        let plain = pick(&["ntp-info"], false);
        assert!(forced_out_of_scope(&facts(&plain, &[80], &[])).is_empty());
    }
}
