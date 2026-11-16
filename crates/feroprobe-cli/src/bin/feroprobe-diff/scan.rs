//! A saved scan, read from an nmap-style XML report (FeroProbe's `-oX`, or
//! nmap's). Only what the comparison looks at is kept: the run's banner,
//! and per host its state, addresses, names, ports, services, OS matches
//! and script results.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::net::IpAddr;

use anyhow::{Context, Result, bail};

/// One run of the scanner: one `<nmaprun>` document.
#[derive(Debug, Default, Clone)]
pub struct Scan {
    pub scanner: Option<String>,
    pub version: Option<String>,
    pub args: Option<String>,
    /// Unix seconds, from `<nmaprun start>`.
    pub start: Option<i64>,
    /// Unix seconds, from `<runstats><finished time>`.
    pub end: Option<i64>,
    pub hosts: Vec<Host>,
    pub pre_scripts: Vec<Script>,
    pub post_scripts: Vec<Script>,
}

#[derive(Debug, Default, Clone)]
pub struct Host {
    /// `up`, `down`, ...; `None` when the report gives none.
    pub state: Option<String>,
    pub addresses: Vec<Address>,
    pub hostnames: Vec<String>,
    /// Keyed by (port number, protocol), so ports come out in that order.
    pub ports: BTreeMap<PortSpec, Port>,
    /// The "Not shown" groups: state → count.
    pub extraports: BTreeMap<String, u64>,
    /// OS match names, in the report's order (best first).
    pub os: Vec<String>,
    pub scripts: Vec<Script>,
}

pub type PortSpec = (u32, String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Port {
    pub spec: PortSpec,
    pub state: Option<String>,
    pub service: Service,
    pub scripts: Vec<Script>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Service {
    pub name: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub extrainfo: Option<String>,
    pub tunnel: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Script {
    pub id: String,
    pub output: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Address {
    Ip(IpAddr),
    Mac(String),
}

impl Address {
    pub fn kind(&self) -> &'static str {
        match self {
            Address::Ip(IpAddr::V4(_)) => "ipv4",
            Address::Ip(IpAddr::V6(_)) => "ipv6",
            Address::Mac(_) => "mac",
        }
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Address::Ip(a) => a.fmt(f),
            Address::Mac(m) => f.write_str(m),
        }
    }
}

/// IPv4 first, then IPv6, then MAC addresses, as ndiff lists them; IP
/// addresses in numeric order.
impl Ord for Address {
    fn cmp(&self, other: &Self) -> Ordering {
        fn rank(a: &Address) -> u8 {
            match a {
                Address::Ip(IpAddr::V4(_)) => 0,
                Address::Ip(IpAddr::V6(_)) => 1,
                Address::Mac(_) => 2,
            }
        }
        rank(self)
            .cmp(&rank(other))
            .then_with(|| match (self, other) {
                (Address::Ip(a), Address::Ip(b)) => a.cmp(b),
                (Address::Mac(a), Address::Mac(b)) => {
                    a.to_ascii_lowercase().cmp(&b.to_ascii_lowercase())
                }
                _ => Ordering::Equal,
            })
    }
}

impl PartialOrd for Address {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// What makes two hosts in different scans "the same host": its first
/// address (IPv4 before IPv6 before MAC), or its first name when it has no
/// address.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum HostKey {
    Addr(Address),
    Name(String),
    Nothing,
}

impl Host {
    pub fn key(&self) -> HostKey {
        if let Some(a) = self.addresses.iter().min() {
            HostKey::Addr(a.clone())
        } else if let Some(n) = self.hostnames.iter().min() {
            HostKey::Name(n.clone())
        } else {
            HostKey::Nothing
        }
    }

    /// `name (address)`, `address`, or `name`, as ndiff writes a host.
    pub fn display_name(&self) -> String {
        let mut addrs = self.addresses.clone();
        addrs.sort();
        let addrs: Vec<String> = addrs.iter().map(ToString::to_string).collect();
        let addrs = addrs.join(", ");
        let mut names = self.hostnames.clone();
        names.sort();
        let names = names.join(", ");
        match (names.is_empty(), addrs.is_empty()) {
            (false, false) => format!("{names} ({addrs})"),
            (false, true) => names,
            (true, false) => addrs,
            (true, true) => "<no name>".to_string(),
        }
    }

    /// Whether ports in `state` are folded into "Not shown" for this host
    /// (an unknown state, or a port the host's report does not list, counts
    /// as folded).
    pub fn is_extraports(&self, state: Option<&str>) -> bool {
        state.is_none_or(|s| self.extraports.contains_key(s))
    }

    /// `993 filtered ports, 2 closed ports`: the biggest group first.
    pub fn extraports_string(&self) -> String {
        let mut groups: Vec<(&String, &u64)> = self.extraports.iter().collect();
        groups.sort_by(|a, b| b.1.cmp(a.1).then_with(|| b.0.cmp(a.0)));
        groups
            .iter()
            .map(|(state, n)| format!("{n} {state} ports"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl Port {
    pub fn empty(spec: PortSpec) -> Port {
        Port {
            spec,
            state: None,
            service: Service::default(),
            scripts: Vec::new(),
        }
    }

    pub fn spec_string(&self) -> String {
        format!("{}/{}", self.spec.0, self.spec.1)
    }

    pub fn state_string(&self) -> String {
        self.state.clone().unwrap_or_else(|| "unknown".to_string())
    }
}

impl Service {
    /// The SERVICE column: `ssl/http`, `http`.
    pub fn name_string(&self) -> Option<String> {
        let parts: Vec<&str> = [&self.tunnel, &self.name]
            .into_iter()
            .flatten()
            .map(String::as_str)
            .collect();
        (!parts.is_empty()).then(|| parts.join("/"))
    }

    /// The VERSION column: `OpenSSH 9.6p1 (Ubuntu Linux; protocol 2.0)`.
    pub fn version_string(&self) -> Option<String> {
        let mut parts: Vec<String> = Vec::new();
        parts.extend(self.product.clone());
        parts.extend(self.version.clone());
        if let Some(e) = &self.extrainfo {
            parts.push(format!("({e})"));
        }
        (!parts.is_empty()).then(|| parts.join(" "))
    }

    pub fn is_empty(&self) -> bool {
        *self == Service::default()
    }
}

impl Script {
    /// The script's lines as the normal output shows them:
    /// `|  id: first`, ..., `|_ last`.
    pub fn lines(&self) -> Vec<String> {
        let mut lines: Vec<String> = self.output.lines().map(str::to_string).collect();
        if let Some(first) = lines.first_mut() {
            *first = format!("{}: {first}", self.id);
        }
        let n = lines.len();
        lines
            .into_iter()
            .enumerate()
            .map(|(i, l)| {
                if i + 1 == n {
                    format!("|_ {l}")
                } else {
                    format!("|  {l}")
                }
            })
            .collect()
    }
}

fn attr(node: roxmltree::Node, name: &str) -> Option<String> {
    node.attribute(name).map(str::to_string)
}

fn children<'a, 'i>(
    node: roxmltree::Node<'a, 'i>,
    name: &'static str,
) -> impl Iterator<Item = roxmltree::Node<'a, 'i>> {
    node.children()
        .filter(move |c| c.is_element() && c.tag_name().name() == name)
}

fn scripts(node: roxmltree::Node, warnings: &mut Vec<String>) -> Vec<Script> {
    let mut out: Vec<Script> = children(node, "script")
        .filter_map(|s| match (s.attribute("id"), s.attribute("output")) {
            (Some(id), Some(output)) => Some(Script {
                id: id.to_string(),
                output: output.to_string(),
            }),
            _ => {
                warnings.push("a script element without an id or output; skipped".to_string());
                None
            }
        })
        .collect();
    out.sort();
    out
}

impl Scan {
    /// Reads a report. Warnings are for parts that could not be used and
    /// were skipped, as ndiff does.
    pub fn parse(text: &str) -> Result<(Scan, Vec<String>)> {
        let opts = roxmltree::ParsingOptions {
            allow_dtd: true,
            ..Default::default()
        };
        let doc = match roxmltree::Document::parse_with_options(text, opts) {
            Ok(d) => d,
            Err(e) => {
                // An -oX file written with --append-output holds one document
                // per run; say so rather than only "unexpected data".
                if text.matches("<nmaprun").count() > 1 {
                    bail!(
                        "{e}; the file holds more than one scan (written with --append-output?). \
                         Split it into one file per scan"
                    );
                }
                bail!("{e}");
            }
        };
        let root = doc.root_element();
        if root.tag_name().name() != "nmaprun" {
            bail!(
                "not a scan report: the document is <{}>, not <nmaprun>",
                root.tag_name().name()
            );
        }
        let mut warnings = Vec::new();
        let mut scan = Scan {
            scanner: attr(root, "scanner"),
            version: attr(root, "version"),
            args: attr(root, "args"),
            ..Default::default()
        };
        if let Some(s) = root.attribute("start") {
            scan.start = Some(
                s.parse()
                    .with_context(|| format!("bad start time \"{s}\" in <nmaprun>"))?,
            );
        }
        for stats in children(root, "runstats") {
            for f in children(stats, "finished") {
                if let Some(t) = f.attribute("time") {
                    scan.end = Some(
                        t.parse()
                            .with_context(|| format!("bad finish time \"{t}\""))?,
                    );
                }
            }
        }
        for pre in children(root, "prescript") {
            scan.pre_scripts.extend(scripts(pre, &mut warnings));
        }
        scan.pre_scripts.sort();
        for post in children(root, "postscript") {
            scan.post_scripts.extend(scripts(post, &mut warnings));
        }
        scan.post_scripts.sort();
        // <hosthint> elements (nmap's early notices) are not hosts.
        for h in children(root, "host") {
            scan.hosts.push(parse_host(h, &mut warnings));
        }
        Ok((scan, warnings))
    }
}

fn parse_host(h: roxmltree::Node, warnings: &mut Vec<String>) -> Host {
    let mut host = Host::default();
    for a in children(h, "address") {
        let Some(addr) = a.attribute("addr") else {
            warnings.push("an address element without addr; skipped".to_string());
            continue;
        };
        let parsed = match a.attribute("addrtype").unwrap_or("ipv4") {
            "ipv4" | "ipv6" => addr.parse().ok().map(Address::Ip),
            "mac" => Some(Address::Mac(addr.to_string())),
            _ => None,
        };
        match parsed {
            Some(p) if !host.addresses.contains(&p) => host.addresses.push(p),
            Some(_) => {}
            None => warnings.push(format!("unreadable address \"{addr}\"; skipped")),
        }
    }
    for s in children(h, "status") {
        host.state = attr(s, "state");
    }
    for names in children(h, "hostnames") {
        for n in children(names, "hostname") {
            if let Some(name) = n.attribute("name")
                && !host.hostnames.iter().any(|x| x == name)
            {
                host.hostnames.push(name.to_string());
            }
        }
    }
    let who = host.display_name();
    for ports in children(h, "ports") {
        for e in children(ports, "extraports") {
            let state = e.attribute("state").unwrap_or("unknown").to_string();
            let count = e
                .attribute("count")
                .and_then(|c| c.parse().ok())
                .unwrap_or_else(|| {
                    warnings.push(format!(
                        "extraports of host {who} without a usable count; taken as 0"
                    ));
                    0
                });
            host.extraports.insert(state, count);
        }
        for p in children(ports, "port") {
            let (Some(id), Some(proto)) = (
                p.attribute("portid").and_then(|i| i.parse().ok()),
                p.attribute("protocol"),
            ) else {
                warnings.push(format!(
                    "a port of host {who} without a usable portid or protocol; skipped"
                ));
                continue;
            };
            let mut port = Port::empty((id, proto.to_string()));
            // Like ndiff, a port without a state is not taken.
            let Some(state) = children(p, "state").find_map(|s| attr(s, "state")) else {
                warnings.push(format!(
                    "port {} of host {who} has no state; skipped",
                    port.spec_string()
                ));
                continue;
            };
            port.state = Some(state);
            if let Some(s) = children(p, "service").next() {
                port.service = Service {
                    name: attr(s, "name"),
                    product: attr(s, "product"),
                    version: attr(s, "version"),
                    extrainfo: attr(s, "extrainfo"),
                    tunnel: attr(s, "tunnel"),
                };
            }
            port.scripts = scripts(p, warnings);
            host.ports.insert(port.spec.clone(), port);
        }
    }
    for os in children(h, "os") {
        for m in children(os, "osmatch") {
            if let Some(name) = m.attribute("name") {
                host.os.push(name.to_string());
            }
        }
    }
    for hs in children(h, "hostscript") {
        host.scripts.extend(scripts(hs, warnings));
    }
    host.scripts.sort();
    host
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_feroprobe_report() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="feroprobe.xsl" type="text/xsl"?>
<nmaprun scanner="feroprobe" args="feroprobe -sV 10.0.0.5" start="1700000000" version="0.5.0">
<host><status state="up" reason="echo-reply"/>
<address addr="10.0.0.5" addrtype="ipv4"/>
<address addr="00:11:22:33:44:55" addrtype="mac" vendor="X"/>
<hostnames><hostname name="a.lan" type="user"/><hostname name="a.lan" type="PTR"/></hostnames>
<ports><extraports state="closed" count="997"></extraports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="9.6p1" extrainfo="protocol 2.0" method="probed" conf="10"><cpe>cpe:/a:openbsd:openssh:9.6p1</cpe></service></port>
<port protocol="tcp" portid="443"><state state="open"/><service name="http" tunnel="ssl"/><script id="b" output="two"/><script id="a" output="one&#10;more"/></port>
<port protocol="tcp" portid="80"></port>
</ports>
<os><osmatch name="Linux 5.x" accuracy="100"/><osmatch name="Linux 4.x" accuracy="95"/></os>
</host>
<runstats><finished time="1700000060"/></runstats>
</nmaprun>"#;
        let (scan, warnings) = Scan::parse(xml).unwrap();
        assert_eq!(scan.scanner.as_deref(), Some("feroprobe"));
        assert_eq!(scan.start, Some(1_700_000_000));
        assert_eq!(scan.end, Some(1_700_000_060));
        let h = &scan.hosts[0];
        assert_eq!(h.state.as_deref(), Some("up"));
        assert_eq!(h.hostnames, ["a.lan"]);
        assert_eq!(h.display_name(), "a.lan (10.0.0.5, 00:11:22:33:44:55)");
        assert_eq!(h.extraports_string(), "997 closed ports");
        assert_eq!(h.ports.len(), 2, "the port without a state is skipped");
        assert_eq!(warnings.len(), 1);
        let ssh = &h.ports[&(22, "tcp".to_string())];
        assert_eq!(
            ssh.service.version_string().as_deref(),
            Some("OpenSSH 9.6p1 (protocol 2.0)")
        );
        let https = &h.ports[&(443, "tcp".to_string())];
        assert_eq!(https.service.name_string().as_deref(), Some("ssl/http"));
        assert_eq!(https.scripts[0].id, "a");
        assert_eq!(https.scripts[0].lines(), ["|  a: one", "|_ more"]);
        assert_eq!(h.os, ["Linux 5.x", "Linux 4.x"]);
    }

    #[test]
    fn concatenated_reports_get_a_clear_error() {
        let one = r#"<?xml version="1.0"?><nmaprun scanner="nmap"></nmaprun>"#;
        let err = Scan::parse(&format!("{one}\n{one}"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("more than one scan"), "{err}");
    }

    #[test]
    fn other_documents_are_refused() {
        assert!(Scan::parse("<html/>").is_err());
        assert!(Scan::parse("not xml").is_err());
    }

    #[test]
    fn hosts_sort_numerically_ipv4_first() {
        let ip = |s: &str| Address::Ip(s.parse().unwrap());
        let mut v = vec![
            ip("::1"),
            ip("10.0.0.10"),
            Address::Mac("AA".into()),
            ip("10.0.0.2"),
        ];
        v.sort();
        assert_eq!(
            v,
            [
                ip("10.0.0.2"),
                ip("10.0.0.10"),
                ip("::1"),
                Address::Mac("AA".into())
            ]
        );
    }
}
