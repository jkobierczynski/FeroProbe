//! The service rules file: the probes `-sV` sends and the rules that read
//! the replies.
//!
//! The rules ship inside the binary (`data/service-rules.txt`) and can be
//! replaced with `--service-rules FILE`. The format is FeroProbe's own and
//! is documented in that file and in the manual. nmap's
//! `nmap-service-probes` is not used, and is refused with a clear message
//! if given, because its licence does not allow redistributing it.

use std::fmt;
use std::path::Path;
use std::sync::{Arc, LazyLock};

use regex::bytes::{Captures, Regex, RegexBuilder};

use crate::model::Protocol;

/// The rules built into FeroProbe.
pub const BUILTIN: &str = include_str!("../../data/service-rules.txt");

/// The first directive of every rules file, with the format version.
const MAGIC: &str = "feroprobe-service-rules";
const FORMAT_VERSION: &str = "1";

/// What a probe does once connected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeKind {
    /// Send these bytes (nothing: just listen) and read the reply.
    Send(Vec<u8>),
    /// A TLS handshake; the other probes then run inside it.
    Tls,
}

/// Something sent to a service to make it answer.
#[derive(Debug, Clone)]
pub struct Probe {
    pub name: String,
    /// TCP or UDP.
    pub protocol: Protocol,
    /// 0-9. Sent when the intensity is at least this, and always to
    /// [`ports`](Self::ports). 0 means always.
    pub rarity: u8,
    /// The ports the probe is meant for.
    pub ports: Vec<u16>,
    pub kind: ProbeKind,
    /// TLS probe only: inside TLS, listen first on these ports.
    pub listen_ports: Vec<u16>,
    /// Line in the rules file.
    pub line: usize,
}

impl Probe {
    /// The bytes to send, empty for a listen-only probe or TLS.
    pub fn payload(&self) -> &[u8] {
        match &self.kind {
            ProbeKind::Send(p) => p,
            ProbeKind::Tls => &[],
        }
    }

    /// Whether this probe is meant for `port`.
    pub fn is_for(&self, port: u16) -> bool {
        self.ports.contains(&port)
    }
}

/// One match rule.
#[derive(Debug)]
pub struct Rule {
    pub service: String,
    /// A soft match names the service only.
    pub soft: bool,
    /// Only match replies to this probe.
    pub probe: Option<String>,
    pub regex: Regex,
    pub product: String,
    pub version: String,
    pub info: Vec<String>,
    pub host: String,
    pub os: String,
    pub device: String,
    pub cpe: Vec<String>,
    /// Line in the rules file.
    pub line: usize,
}

/// A rules file, parsed and compiled.
#[derive(Debug)]
pub struct ServiceDb {
    /// Probes in file order.
    pub probes: Vec<Probe>,
    /// Rules in file order: the first one that matches wins.
    pub rules: Vec<Rule>,
    /// Where the rules came from, for messages: "built-in" or a path.
    pub source: String,
    /// TCP ports `-sV` leaves alone unless `--allports` is given (`exclude
    /// tcp`): printers' raw ports print whatever reaches them.
    pub exclude_tcp: Vec<u16>,
    /// UDP ports `-sV` leaves alone unless `--allports` is given.
    pub exclude_udp: Vec<u16>,
}

/// A mistake in a rules file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub line: usize,
    pub message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for ParseError {}

static BUILTIN_DB: LazyLock<Arc<ServiceDb>> = LazyLock::new(|| {
    Arc::new(
        ServiceDb::parse(BUILTIN, "built-in")
            .unwrap_or_else(|e| panic!("built-in service rules: {e}")),
    )
});

impl ServiceDb {
    /// The rules built into FeroProbe.
    pub fn builtin() -> Arc<Self> {
        Arc::clone(&BUILTIN_DB)
    }

    /// Read a rules file.
    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let text = std::fs::read_to_string(path)?;
        Ok(Self::parse(&text, &path.display().to_string())?)
    }

    /// The probe called `name`.
    pub fn probe(&self, name: &str) -> Option<&Probe> {
        self.probes.iter().find(|p| p.name == name)
    }

    /// Whether `-sV` skips `port` unless `--allports` is given.
    pub fn excluded(&self, protocol: Protocol, port: u16) -> bool {
        match protocol {
            Protocol::Tcp => self.exclude_tcp.contains(&port),
            Protocol::Udp => self.exclude_udp.contains(&port),
            _ => false,
        }
    }

    /// The TCP TLS probe, if the rules have one.
    pub fn tls(&self) -> Option<&Probe> {
        self.probes
            .iter()
            .find(|p| p.kind == ProbeKind::Tls && p.protocol == Protocol::Tcp)
    }

    /// Parse the text of a rules file. `source` names it in messages.
    pub fn parse(text: &str, source: &str) -> Result<Self, ParseError> {
        let mut db = Self {
            probes: Vec::new(),
            rules: Vec::new(),
            source: source.to_string(),
            exclude_tcp: Vec::new(),
            exclude_udp: Vec::new(),
        };
        let mut seen_magic = false;
        // What indented attribute lines belong to.
        enum Current {
            None,
            Probe,
            Rule(Box<RuleDraft>),
        }
        let mut current = Current::None;
        let finish = |db: &mut Self, current: Current| -> Result<(), ParseError> {
            if let Current::Rule(draft) = current {
                db.rules.push(draft.compile()?);
            }
            Ok(())
        };
        for (i, raw) in text.lines().enumerate() {
            let line = i + 1;
            let err = |message: String| ParseError { line, message };
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let indented = raw.starts_with([' ', '\t']);
            let (key, rest) = split_word(trimmed);
            if !seen_magic {
                if looks_like_nmap(trimmed) {
                    return Err(err(
                        "this looks like nmap's nmap-service-probes; FeroProbe reads only its \
                         own rules format (see the manual, \"Service rules file\")"
                            .into(),
                    ));
                }
                if key != MAGIC {
                    return Err(err(format!(
                        "a rules file starts with \"{MAGIC} {FORMAT_VERSION}\""
                    )));
                }
                if rest != FORMAT_VERSION {
                    return Err(err(format!(
                        "format version {rest:?} is not supported (this FeroProbe reads \
                         version {FORMAT_VERSION})"
                    )));
                }
                seen_magic = true;
                continue;
            }
            if indented {
                match &mut current {
                    Current::None => {
                        return Err(err(format!("{key:?} must follow a probe or match line")));
                    }
                    Current::Probe => {
                        let probe = db.probes.last_mut().expect("a probe was started");
                        probe_attr(probe, key, rest).map_err(err)?;
                    }
                    Current::Rule(draft) => draft.attr(key, rest).map_err(err)?,
                }
                continue;
            }
            finish(&mut db, std::mem::replace(&mut current, Current::None))?;
            match key {
                "probe" => {
                    let (name, proto) = split_word(rest);
                    let protocol = match proto {
                        "tcp" => Protocol::Tcp,
                        "udp" => Protocol::Udp,
                        _ => return Err(err("a probe line is \"probe NAME tcp|udp\"".into())),
                    };
                    if name.is_empty() {
                        return Err(err("the probe has no name".into()));
                    }
                    if db.probes.iter().any(|p| p.name == name) {
                        return Err(err(format!("probe {name:?} is defined twice")));
                    }
                    db.probes.push(Probe {
                        name: name.to_string(),
                        protocol,
                        rarity: 5,
                        ports: Vec::new(),
                        kind: ProbeKind::Send(Vec::new()),
                        listen_ports: Vec::new(),
                        line,
                    });
                    current = Current::Probe;
                }
                "match" | "softmatch" => {
                    let (service, pattern) = split_word(rest);
                    if service.is_empty() || pattern.is_empty() {
                        return Err(err(format!("a rule line is \"{key} SERVICE REGEX\"")));
                    }
                    current = Current::Rule(Box::new(RuleDraft::new(
                        service,
                        pattern,
                        key == "softmatch",
                        line,
                    )));
                }
                "exclude" => {
                    let (proto, list) = split_word(rest);
                    let ports = parse_ports(list).map_err(err)?;
                    match proto {
                        "tcp" if !ports.is_empty() => db.exclude_tcp.extend(ports),
                        "udp" if !ports.is_empty() => db.exclude_udp.extend(ports),
                        _ => {
                            return Err(err("an exclude line is \"exclude tcp|udp PORTS\"".into()));
                        }
                    }
                }
                _ => return Err(err(format!("unknown directive {key:?}"))),
            }
        }
        finish(&mut db, current)?;
        if !seen_magic {
            return Err(ParseError {
                line: 1,
                message: format!("the file is empty; it starts with \"{MAGIC} {FORMAT_VERSION}\""),
            });
        }
        // Every rule tied to a probe must name one that exists.
        for rule in &db.rules {
            if let Some(p) = &rule.probe
                && db.probe(p).is_none()
            {
                return Err(ParseError {
                    line: rule.line,
                    message: format!("no probe is called {p:?}"),
                });
            }
        }
        Ok(db)
    }
}

/// Whether a line comes from nmap's probe file.
fn looks_like_nmap(line: &str) -> bool {
    line.starts_with("Probe TCP ")
        || line.starts_with("Probe UDP ")
        || line.starts_with("Exclude ")
        || (line.starts_with("match ") && line.contains(" m|"))
}

fn split_word(s: &str) -> (&str, &str) {
    match s.split_once([' ', '\t']) {
        Some((a, b)) => (a, b.trim()),
        None => (s, ""),
    }
}

fn probe_attr(probe: &mut Probe, key: &str, value: &str) -> Result<(), String> {
    match key {
        "rarity" => {
            probe.rarity = value
                .parse()
                .ok()
                .filter(|r| *r <= 9)
                .ok_or_else(|| format!("rarity must be 0-9, not {value:?}"))?;
        }
        "ports" => probe.ports.extend(parse_ports(value)?),
        "listen-ports" => probe.listen_ports.extend(parse_ports(value)?),
        "tls" => {
            if !probe.payload().is_empty() {
                return Err("a tls probe sends no payload".into());
            }
            probe.kind = ProbeKind::Tls;
        }
        "send" | "pad" => {
            let bytes = if key == "send" {
                unescape(value)?
            } else {
                let n: usize = value
                    .parse()
                    .ok()
                    .filter(|n| *n <= 4096)
                    .ok_or_else(|| format!("pad takes a number of bytes, not {value:?}"))?;
                vec![0; n]
            };
            match &mut probe.kind {
                ProbeKind::Send(p) => p.extend(bytes),
                ProbeKind::Tls => return Err("a tls probe sends no payload".into()),
            }
        }
        _ => return Err(format!("unknown probe attribute {key:?}")),
    }
    Ok(())
}

/// A port list such as `80,443,8000-8010`.
fn parse_ports(value: &str) -> Result<Vec<u16>, String> {
    let mut out = Vec::new();
    for part in value.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let bad = || format!("bad port or range {part:?}");
        let (a, b) = part.split_once('-').unwrap_or((part, part));
        let a: u16 = a.trim().parse().map_err(|_| bad())?;
        let b: u16 = b.trim().parse().map_err(|_| bad())?;
        if a > b {
            return Err(bad());
        }
        out.extend(a..=b);
    }
    Ok(out)
}

/// A quoted string with C-like escapes: `\r \n \t \0 \\ \" \xHH`.
fn unescape(value: &str) -> Result<Vec<u8>, String> {
    let inner = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .filter(|_| value.len() >= 2)
        .ok_or_else(|| "send takes a string in double quotes".to_string())?;
    let mut out = Vec::new();
    let mut bytes = inner.bytes();
    while let Some(b) = bytes.next() {
        if b == b'"' {
            return Err("a \" inside the string must be written \\\"".into());
        }
        if b != b'\\' {
            out.push(b);
            continue;
        }
        let e = bytes.next().ok_or("the string ends with a lone \\")?;
        out.push(match e {
            b'r' => b'\r',
            b'n' => b'\n',
            b't' => b'\t',
            b'0' => 0,
            b'\\' => b'\\',
            b'"' => b'"',
            b'x' => {
                let hex: Vec<u8> = bytes.by_ref().take(2).collect();
                std::str::from_utf8(&hex)
                    .ok()
                    .filter(|h| h.len() == 2)
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
                    .ok_or("\\x takes two hex digits")?
            }
            other => return Err(format!("unknown escape \\{}", char::from(other))),
        });
    }
    Ok(out)
}

/// A rule whose attributes are still being read.
struct RuleDraft {
    service: String,
    soft: bool,
    pattern: String,
    probe: Option<String>,
    product: String,
    version: String,
    info: Vec<String>,
    host: String,
    os: String,
    device: String,
    cpe: Vec<String>,
    line: usize,
}

impl RuleDraft {
    fn new(service: &str, pattern: &str, soft: bool, line: usize) -> Self {
        Self {
            service: service.to_string(),
            soft,
            pattern: pattern.to_string(),
            probe: None,
            product: String::new(),
            version: String::new(),
            info: Vec::new(),
            host: String::new(),
            os: String::new(),
            device: String::new(),
            cpe: Vec::new(),
            line,
        }
    }

    fn attr(&mut self, key: &str, value: &str) -> Result<(), String> {
        let one = |slot: &mut String| {
            if slot.is_empty() {
                *slot = value.to_string();
                Ok(())
            } else {
                Err(format!("{key} is given twice"))
            }
        };
        match key {
            "probe" => {
                if self.probe.replace(value.to_string()).is_some() {
                    return Err("probe is given twice".into());
                }
                Ok(())
            }
            _ if self.soft && key != "probe" => Err(format!(
                "a softmatch names the service only; {key:?} needs a match"
            )),
            "product" => one(&mut self.product),
            "version" => one(&mut self.version),
            "host" => one(&mut self.host),
            "os" => one(&mut self.os),
            "device" => one(&mut self.device),
            "info" => {
                self.info.push(value.to_string());
                Ok(())
            }
            "cpe" => {
                if !value.starts_with("cpe:/") {
                    return Err(format!("a CPE starts with cpe:/, not {value:?}"));
                }
                self.cpe.push(value.to_string());
                Ok(())
            }
            _ => Err(format!("unknown rule attribute {key:?}")),
        }
    }

    fn compile(self) -> Result<Rule, ParseError> {
        let regex = RegexBuilder::new(&format!("(?s-u){}", self.pattern))
            .size_limit(1 << 20)
            .build()
            .map_err(|e| ParseError {
                line: self.line,
                message: format!("bad regex: {e}"),
            })?;
        Ok(Rule {
            service: self.service,
            soft: self.soft,
            probe: self.probe,
            regex,
            product: self.product,
            version: self.version,
            info: self.info,
            host: self.host,
            os: self.os,
            device: self.device,
            cpe: self.cpe,
            line: self.line,
        })
    }
}

impl Rule {
    /// Whether this rule may read a reply to `probe`.
    pub fn applies_to(&self, probe: &str) -> bool {
        self.probe.as_deref().is_none_or(|p| p == probe)
    }

    /// Fill a template such as `OpenSSH ${2}` from the regex's groups.
    pub fn fill(caps: &Captures, template: &str) -> Option<String> {
        if template.is_empty() {
            return None;
        }
        let mut out = Vec::new();
        caps.expand(template.as_bytes(), &mut out);
        super::rules::clean(&out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<ServiceDb, ParseError> {
        ServiceDb::parse(text, "test")
    }

    #[test]
    fn builtin_parses() {
        let db = ServiceDb::builtin();
        assert!(db.probes.len() > 30, "{}", db.probes.len());
        assert!(db.rules.len() > 140, "{}", db.rules.len());
        assert_eq!(db.probe("null").unwrap().rarity, 0);
        assert_eq!(db.tls().unwrap().name, "tls");
        // Printers' raw ports are left alone, as in nmap.
        assert!((9100..=9107).all(|p| db.excluded(Protocol::Tcp, p)));
        assert!(!db.excluded(Protocol::Tcp, 9108));
        assert!(!db.excluded(Protocol::Udp, 9100));
        // Every rarity is in range and every probe can be sent.
        for p in &db.probes {
            assert!(p.rarity <= 9);
            assert!(matches!(p.protocol, Protocol::Tcp | Protocol::Udp));
        }
    }

    #[test]
    fn exclude_lines() {
        let db =
            parse("feroprobe-service-rules 1\nexclude tcp 9100-9101,515\nexclude udp 7\n").unwrap();
        assert_eq!(db.exclude_tcp, vec![9100, 9101, 515]);
        assert!(db.excluded(Protocol::Udp, 7));
        for bad in ["exclude sctp 1", "exclude tcp", "exclude tcp 9-1"] {
            let e = parse(&format!("feroprobe-service-rules 1\n{bad}\n")).unwrap_err();
            assert_eq!(e.line, 2, "{bad}");
        }
    }

    #[test]
    fn a_small_file() {
        let db = parse(
            "# comment\nferoprobe-service-rules 1\n\nprobe hello tcp\n  rarity 3\n  ports 7,10-12\n  send \"hi\\r\\n\\x00\"\n  pad 2\n\
             match echo ^hi\n  probe hello\n  product Echo ${0}\n  info a\n  info b\n  cpe cpe:/a:x:y\n\
             softmatch thing ^th\n",
        )
        .unwrap();
        let p = db.probe("hello").unwrap();
        assert_eq!(p.rarity, 3);
        assert_eq!(p.ports, vec![7, 10, 11, 12]);
        assert_eq!(p.payload(), b"hi\r\n\x00\x00\x00");
        assert_eq!(db.rules.len(), 2);
        let r = &db.rules[0];
        assert_eq!((r.service.as_str(), r.soft, r.line), ("echo", false, 9));
        assert_eq!(r.probe.as_deref(), Some("hello"));
        assert_eq!(r.info, vec!["a", "b"]);
        assert!(db.rules[1].soft);
    }

    #[test]
    fn mistakes_are_reported_with_their_line() {
        let head = "feroprobe-service-rules 1\n";
        let cases = [
            ("probe x tcp\n  rarity 10\n", 3, "rarity"),
            ("probe x sctp\n", 2, "tcp|udp"),
            ("probe x tcp\n  send \"\\q\"\n", 3, "escape"),
            ("probe x tcp\n  send hi\n", 3, "double quotes"),
            ("probe x tcp\n  ports 9-1\n", 3, "port"),
            ("match x ^(\n", 2, "regex"),
            ("match x ^a\n  probe nope\n", 2, "no probe"),
            ("softmatch x ^a\n  product P\n", 3, "softmatch"),
            ("  product P\n", 2, "must follow"),
            ("hello\n", 2, "unknown directive"),
            ("probe x tcp\nprobe x udp\n", 3, "twice"),
            ("match x ^a\n  cpe a:b\n", 3, "cpe:/"),
        ];
        for (body, line, needle) in cases {
            let e = parse(&format!("{head}{body}")).unwrap_err();
            assert_eq!(e.line, line, "{body:?}: {e}");
            assert!(e.message.contains(needle), "{body:?}: {e}");
        }
        assert!(parse("").unwrap_err().message.contains("empty"));
        assert!(
            parse("feroprobe-service-rules 2\n")
                .unwrap_err()
                .message
                .contains("version")
        );
        let nmap = "# Nmap service detection probe list\nProbe TCP NULL q||\n";
        assert!(
            parse(nmap)
                .unwrap_err()
                .message
                .contains("nmap-service-probes")
        );
    }

    #[test]
    fn payloads_match_the_protocol_lengths() {
        let db = ServiceDb::builtin();
        let len = |name: &str| db.probe(name).unwrap().payload().len();
        // Each length matches the one written inside the payload.
        assert_eq!(len("rdp"), 0x13);
        assert_eq!(len("mssql"), 0x2f);
        assert_eq!(len("smb"), 4 + 0x6c);
        assert_eq!(len("ldap"), 2 + 0x79);
        assert_eq!(len("mongodb"), 0x38);
        assert_eq!(len("rpc"), 4 + 0x28);
        assert_eq!(len("rpc-udp"), 0x28);
        assert_eq!(len("dns-tcp"), 2 + 0x1e);
        assert_eq!(len("dns-version"), 0x1e);
        assert_eq!(len("pptp"), 0x9c);
        assert_eq!(len("git"), 0x2d);
        assert_eq!(len("snmp"), 2 + 0x26);
        assert_eq!(len("ntp"), 48);
        assert_eq!(len("nbstat"), 50);
        assert_eq!(len("ipmi"), 23);
        assert_eq!(len("x11"), 12);
        let smb = db.probe("smb").unwrap().payload();
        // StructureSize 36 right after the 64-byte SMB2 header.
        assert_eq!(&smb[4 + 64..4 + 66], b"\x24\x00");
        assert_eq!(&smb[smb.len() - 8..], b"\x02\x02\x10\x02\x00\x03\x02\x03");
    }

    #[test]
    fn udp_payloads_match_the_scan() {
        // The UDP scan and -sV send the same NetBIOS, NTP, SNMP and SSDP
        // queries.
        let db = ServiceDb::builtin();
        for (probe, port) in [("nbstat", 137), ("ntp", 123), ("snmp", 161), ("ssdp", 1900)] {
            assert_eq!(
                db.probe(probe).unwrap().payload(),
                crate::udp::payload_for(port),
                "{probe}"
            );
        }
    }
}
