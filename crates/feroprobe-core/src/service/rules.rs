//! Probes and match rules for service detection.
//!
//! These are FeroProbe's own, written from the protocols' public
//! specifications and from banners that real servers send. nmap's
//! `nmap-service-probes` database is deliberately not used: its license does
//! not allow redistributing it here.
//!
//! A rule is a byte regex run against a service's response. `${n}` in the
//! product, version and info templates is replaced by capture group `n`.
//! Rules are tried in order and the first match wins, so specific rules come
//! before generic ones.

use std::sync::LazyLock;

use regex::bytes::{Captures, Regex, RegexBuilder};

use super::{ServiceInfo, printable};

/// Data sent to a service to make it answer.
#[derive(Debug)]
pub(super) struct Probe {
    pub name: &'static str,
    pub payload: &'static [u8],
    /// Ports where this probe is tried first.
    pub ports: &'static [u16],
}

/// Send nothing and wait: services that talk first (SSH, FTP, SMTP, ...).
pub(super) const NULL: Probe = Probe {
    name: "null",
    payload: b"",
    ports: &[],
};

pub(super) const HTTP: Probe = Probe {
    name: "http",
    payload: b"GET / HTTP/1.0\r\n\r\n",
    ports: &[
        80, 81, 591, 2375, 3000, 5000, 5601, 7001, 8000, 8008, 8080, 8081, 8088, 8888, 9000, 9090,
        9200,
    ],
};

/// Probes for services that stay silent until asked in their own protocol.
/// They are only sent to their usual ports, to keep scans quick.
pub(super) const PROBES: &[Probe] = &[
    HTTP,
    Probe {
        name: "redis",
        // RESP array: INFO server
        payload: b"*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n",
        ports: &[6379, 6380],
    },
    Probe {
        name: "memcached",
        payload: b"version\r\n",
        ports: &[11211],
    },
    Probe {
        name: "pgsql",
        // SSLRequest: length 8, code 80877103.
        payload: &[0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f],
        ports: &[5432],
    },
    Probe {
        name: "amqp",
        // AMQP 0-9-1 protocol header.
        payload: b"AMQP\x00\x00\x09\x01",
        ports: &[5671, 5672],
    },
    Probe {
        name: "mqtt",
        // MQTT 3.1.1 CONNECT, clean session, keepalive 60, client id "feroprobe".
        payload: b"\x10\x15\x00\x04MQTT\x04\x02\x00\x3c\x00\x09feroprobe",
        ports: &[1883],
    },
    Probe {
        name: "rdp",
        // TPKT + X.224 Connection Request with an RDP negotiation request
        // offering TLS and CredSSP.
        payload: b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00",
        ports: &[3389],
    },
    Probe {
        name: "mssql",
        // TDS PRELOGIN: VERSION, ENCRYPTION, INSTOPT, THREADID and MARS.
        payload: b"\x12\x01\x00\x2f\x00\x00\x01\x00\
            \x00\x00\x1a\x00\x06\x01\x00\x20\x00\x01\x02\x00\x21\x00\x01\
            \x03\x00\x22\x00\x04\x04\x00\x26\x00\x01\xff\
            \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        ports: &[1433],
    },
    Probe {
        name: "smb",
        // NetBIOS session header + SMB2 NEGOTIATE offering 2.0.2 to 3.0.2.
        payload: b"\x00\x00\x00\x6c\xfeSMB\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\
            \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
            \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
            \x00\x00\x00\x00\x00\x00\x00\x00\x24\x00\x04\x00\x01\x00\x00\x00\x00\x00\x00\x00\
            \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
            \x00\x00\x00\x00\x02\x02\x10\x02\x00\x03\x02\x03",
        ports: &[445],
    },
    Probe {
        name: "ldap",
        // SearchRequest for the rootDSE: base "", scope base,
        // (objectClass=*), asking for the vendor, host and naming context.
        payload: b"\x30\x79\x02\x01\x01\x63\x74\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\
            \x02\x01\x00\x01\x01\x00\x87\x0bobjectClass\x30\x54\x04\x01*\x04\x01+\
            \x04\x0avendorName\x04\x0dvendorVersion\x04\x14defaultNamingContext\
            \x04\x0bdnsHostName\x04\x0enamingContexts",
        ports: &[389, 636, 3268, 3269],
    },
    Probe {
        name: "mongodb",
        // OP_MSG {buildinfo: 1, $db: "admin"}, which needs no login.
        payload: b"\x38\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xdd\x07\x00\x00\
            \x00\x00\x00\x00\x00\x23\x00\x00\x00\x10buildinfo\x00\x01\x00\x00\x00\
            \x02$db\x00\x06\x00\x00\x00admin\x00\x00",
        ports: &[27017, 27018, 27019],
    },
    Probe {
        name: "zookeeper",
        // The "srvr" four-letter command, allowed by default.
        payload: b"srvr\n",
        ports: &[2181],
    },
    Probe {
        name: "rtsp",
        payload: b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        ports: &[554, 8554],
    },
    Probe {
        name: "sip",
        payload: b"OPTIONS sip:feroprobe.invalid SIP/2.0\r\n\
            Via: SIP/2.0/TCP feroprobe.invalid;branch=z9hG4bKferoprobe\r\n\
            From: <sip:feroprobe@feroprobe.invalid>;tag=feroprobe\r\n\
            To: <sip:feroprobe.invalid>\r\n\
            Call-ID: feroprobe@feroprobe.invalid\r\nCSeq: 1 OPTIONS\r\n\
            Max-Forwards: 70\r\nContent-Length: 0\r\n\r\n",
        ports: &[5060, 5061],
    },
];

/// Ports where TLS is tried before anything else.
pub(super) const TLS_PORTS: &[u16] = &[
    443, 465, 636, 853, 990, 992, 993, 994, 995, 2376, 5061, 5671, 6443, 8443, 8883, 9443, 10250,
];

/// TLS ports whose service talks first, so we listen before sending HTTP.
pub(super) const TLS_BANNER_PORTS: &[u16] = &[465, 990, 992, 993, 994, 995];

/// One match rule. Build them with [`r`] and the setters below.
#[derive(Debug)]
pub(super) struct Rule {
    service: &'static str,
    /// Only match responses to this probe (for short, ambiguous replies).
    probe: Option<&'static str>,
    pattern: &'static str,
    product: &'static str,
    version: &'static str,
    info: &'static [&'static str],
}

const fn r(service: &'static str, pattern: &'static str) -> Rule {
    Rule {
        service,
        probe: None,
        pattern,
        product: "",
        version: "",
        info: &[],
    }
}

impl Rule {
    const fn product(mut self, p: &'static str) -> Self {
        self.product = p;
        self
    }
    const fn version(mut self, v: &'static str) -> Self {
        self.version = v;
        self
    }
    const fn info(mut self, i: &'static [&'static str]) -> Self {
        self.info = i;
        self
    }
    const fn probe(mut self, p: &'static str) -> Self {
        self.probe = Some(p);
        self
    }
}

/// Patterns run on raw bytes with `(?s-u)`: `.` matches any byte, including
/// newlines, and `\xNN` matches the byte NN.
static RULES: &[Rule] = &[
    // SSH
    r("ssh", r"^SSH-([\d.]+)-OpenSSH_for_Windows_([\w.]+)")
        .product("OpenSSH for Windows")
        .version("${2}")
        .info(&["protocol ${1}"]),
    r("ssh", r"^SSH-([\d.]+)-OpenSSH_([\w.]+)[ -]([^\r\n]+)")
        .product("OpenSSH")
        .version("${2}")
        .info(&["${3}", "protocol ${1}"]),
    r("ssh", r"^SSH-([\d.]+)-OpenSSH_([\w.]+)")
        .product("OpenSSH")
        .version("${2}")
        .info(&["protocol ${1}"]),
    r("ssh", r"^SSH-([\d.]+)-dropbear_([\w.]+)")
        .product("Dropbear sshd")
        .version("${2}")
        .info(&["protocol ${1}"]),
    r("ssh", r"^SSH-([\d.]+)-libssh[_-]([\d.]+)")
        .product("libssh")
        .version("${2}")
        .info(&["protocol ${1}"]),
    r("ssh", r"^SSH-([\d.]+)-Cisco-([\d.]+)")
        .product("Cisco SSH")
        .version("${2}")
        .info(&["protocol ${1}"]),
    r("ssh", r"^SSH-([\d.]+)-ROSSSH")
        .product("MikroTik RouterOS sshd")
        .info(&["protocol ${1}"]),
    r("ssh", r"^SSH-([\d.]+)-paramiko_([\d.]+)")
        .product("Paramiko")
        .version("${2}")
        .info(&["protocol ${1}"]),
    r("ssh", r"^SSH-([\d.]+)-AsyncSSH_([\d.]+)")
        .product("AsyncSSH")
        .version("${2}")
        .info(&["protocol ${1}"]),
    r("ssh", r"^SSH-([\d.]+)-Erlang/([\d.]+)")
        .product("Erlang sshd")
        .version("${2}")
        .info(&["protocol ${1}"]),
    r("ssh", r"^SSH-([\d.]+)-Go\r?\n")
        .product("Go x/crypto/ssh")
        .info(&["protocol ${1}"]),
    r("ssh", r"^SSH-([\d.]+)-mod_sftp")
        .product("ProFTPD mod_sftp")
        .info(&["protocol ${1}"]),
    r(
        "ssh",
        r"^SSH-([\d.]+)-[\d.]+ FlowSsh: Bitvise SSH Server \(WinSSHD\) ([\d.]+)",
    )
    .product("Bitvise WinSSHD")
    .version("${2}")
    .info(&["protocol ${1}"]),
    r("ssh", r"^SSH-([\d.]+)-([^\r\n]+)")
        .product("${2}")
        .info(&["protocol ${1}"]),
    // SMTP, before FTP: both greet with 220.
    r("smtp", r"^220[ -](\S+) ESMTP Postfix")
        .product("Postfix smtpd")
        .info(&["host: ${1}"]),
    r("smtp", r"^220[ -](\S+) ESMTP Exim ([\d.]+)")
        .product("Exim smtpd")
        .version("${2}")
        .info(&["host: ${1}"]),
    r("smtp", r"^220[ -](\S+) ESMTP Sendmail ([\w.]+)")
        .product("Sendmail")
        .version("${2}")
        .info(&["host: ${1}"]),
    r("smtp", r"^220[ -](\S+) ESMTP OpenSMTPD")
        .product("OpenSMTPD")
        .info(&["host: ${1}"]),
    r("smtp", r"^220[ -](\S+) Microsoft ESMTP MAIL Service")
        .product("Microsoft ESMTP")
        .info(&["host: ${1}"]),
    r("smtp", r"^220[ -](\S+) ESMTP Haraka[/ ]([\d.]+)")
        .product("Haraka smtpd")
        .version("${2}")
        .info(&["host: ${1}"]),
    r("smtp", r"^220[ -](\S+) [^\r\n]*\bE?SMTP\b").info(&["host: ${1}"]),
    // FTP
    r("ftp", r"^220[ -][^\r\n]*\(vsFTPd ([\w.]+)\)")
        .product("vsftpd")
        .version("${1}"),
    r("ftp", r"^220[ -]ProFTPD ([\d.]+\w*) Server")
        .product("ProFTPD")
        .version("${1}"),
    r("ftp", r"^220[ -]ProFTPD").product("ProFTPD"),
    r("ftp", r"^220-+ Welcome to Pure-FTPd").product("Pure-FTPd"),
    r("ftp", r"^220[ -]FileZilla Server(?: version)? ([\w.]+)")
        .product("FileZilla ftpd")
        .version("${1}"),
    r("ftp", r"^220[ -]Microsoft FTP Service").product("Microsoft ftpd"),
    r("ftp", r"^220[ -]Serv-U FTP Server v([\d.]+)")
        .product("Serv-U ftpd")
        .version("${1}"),
    r("ftp", r"^220[ -](\S+) FTP server \(MikroTik ([\d.]+)\)")
        .product("MikroTik RouterOS ftpd")
        .version("${2}")
        .info(&["host: ${1}"]),
    r("ftp", r"^220[ -]bftpd ([\d.]+)")
        .product("bftpd")
        .version("${1}"),
    r("ftp", r"^220[ -][^\r\n]*\bFTP\b"),
    // POP3 and IMAP
    r("pop3", r"^\+OK [^\r\n]*Dovecot").product("Dovecot pop3d"),
    r(
        "pop3",
        r"^\+OK The Microsoft Exchange POP3 service is ready",
    )
    .product("Microsoft Exchange pop3d"),
    r("pop3", r"^\+OK [^\r\n]*Cyrus POP3 v?([\w.\-]+)")
        .product("Cyrus pop3d")
        .version("${1}"),
    r("pop3", r"^\+OK Hello there").product("Courier pop3d"),
    r("pop3", r"^\+OK [^\r\n]*POP3"),
    r("imap", r"^\* OK [^\r\n]*Dovecot").product("Dovecot imapd"),
    r(
        "imap",
        r"^\* OK The Microsoft Exchange IMAP4 service is ready",
    )
    .product("Microsoft Exchange imapd"),
    r("imap", r"^\* OK [^\r\n]*Cyrus IMAP[^\r\n]*? v?(\d[\w.\-]*)")
        .product("Cyrus imapd")
        .version("${1}"),
    r("imap", r"^\* OK [^\r\n]*Courier-IMAP").product("Courier imapd"),
    r("imap", r"^\* OK [^\r\n]*IMAP"),
    // MySQL and MariaDB: a handshake packet, protocol version 10.
    r("mysql", r"^.\x00\x00\x00\x0a5\.5\.5-([\d.]+)-MariaDB")
        .product("MariaDB")
        .version("${1}"),
    r("mysql", r"^.\x00\x00\x00\x0a([\d.]+)-MariaDB")
        .product("MariaDB")
        .version("${1}"),
    r("mysql", r"^.\x00\x00\x00\x0a(\d[\w.\-]*)\x00")
        .product("MySQL")
        .version("${1}"),
    r(
        "mysql",
        r"^.\x00\x00\x00\xff..Host .* is not allowed to connect to this (MySQL|MariaDB) server",
    )
    .product("${1}")
    .info(&["unauthorized"]),
    // Redis
    r("redis", r"redis_version:([\d.]+)")
        .product("Redis key-value store")
        .version("${1}"),
    r("redis", r"^-NOAUTH ")
        .product("Redis key-value store")
        .info(&["authentication required"]),
    // Redis reading our HTTP probe as a GET command.
    r(
        "redis",
        r"^-ERR wrong number of arguments for 'get' command\r\n",
    )
    .product("Redis key-value store"),
    r("redis", r"^-DENIED Redis is running in protected mode")
        .product("Redis key-value store")
        .info(&["protected mode"]),
    // memcached
    r("memcache", r"^VERSION ([\d.]+)\r\n")
        .product("Memcached")
        .version("${1}"),
    // PostgreSQL answers an SSLRequest with a single S (yes) or N (no).
    r("postgresql", r"^[SN]\z")
        .probe("pgsql")
        .product("PostgreSQL DB"),
    // AMQP: Connection.Start lists the broker's product and version.
    r(
        "amqp",
        r"^\x01\x00\x00.*\x07productS....RabbitMQ.*\x07versionS....([\d.]+)",
    )
    .product("RabbitMQ")
    .version("${1}"),
    r("amqp", r"^\x01\x00\x00\x00").probe("amqp"),
    r("amqp", r"^AMQP\x00\x00\x09\x01").probe("amqp"),
    // MQTT: CONNACK.
    r("mqtt", r"^\x20\x02\x00[\x00-\x05]").probe("mqtt"),
    // MongoDB: an OP_MSG reply (opcode 2013) to buildinfo.
    r(
        "mongodb",
        r"^.{12}\xdd\x07\x00\x00.*\x02version\x00....(\d[\w.\-]*)\x00",
    )
    .probe("mongodb")
    .product("MongoDB")
    .version("${1}"),
    r("mongodb", r"^.{12}\xdd\x07\x00\x00")
        .probe("mongodb")
        .product("MongoDB"),
    // ZooKeeper: the version, without the build hash after it.
    r("zookeeper", r"^Zookeeper version: ([\w.]+)")
        .product("Apache ZooKeeper")
        .version("${1}"),
    r(
        "zookeeper",
        r"^srvr is not executed because it is not in the whitelist",
    )
    .product("Apache ZooKeeper")
    .info(&["four-letter commands restricted"]),
    // Talk-first services.
    r("rsync", r"^@RSYNCD: ([\d.]+)").info(&["protocol ${1}"]),
    r("nntp", r"^20[01] [^\r\n]*InterNetNews server INN ([\d.]+)")
        .product("INN")
        .version("${1}"),
    r("nntp", r"^20[01] [^\r\n]*\b(?i:nntp|news)\b"),
    r(
        "irc",
        r"^:\S+ NOTICE (?:AUTH|\*) :\*\*\* (?:Looking up|Checking|Processing)",
    ),
    // Others
    r("vnc", r"^RFB (\d{3})\.(\d{3})\n")
        .product("VNC")
        .info(&["protocol ${1}.${2}"]),
    r("rtsp", r"^RTSP/1\.0 \d{3}"),
    r("telnet", r"^\xff[\xfb-\xfe]"),
];

static COMPILED: LazyLock<Vec<(&'static Rule, Regex)>> = LazyLock::new(|| {
    RULES
        .iter()
        .map(|rule| {
            let re = RegexBuilder::new(&format!("(?s-u){}", rule.pattern))
                .build()
                .unwrap_or_else(|e| panic!("bad service rule {:?}: {e}", rule.pattern));
            (rule, re)
        })
        .collect()
});

/// Identify the service that sent `data` in reply to `probe`.
pub(super) fn match_response(probe: &str, data: &[u8]) -> Option<ServiceInfo> {
    if data.is_empty() {
        return None;
    }
    if let Some(info) = parse_headers(data) {
        return Some(info);
    }
    if let Some(info) = super::parsers::parse(probe, data) {
        return Some(info);
    }
    COMPILED.iter().find_map(|(rule, re)| {
        if rule.probe.is_some_and(|p| p != probe) {
            return None;
        }
        let caps = re.captures(data)?;
        let info = rule
            .info
            .iter()
            .filter_map(|t| fill(&caps, t))
            .collect::<Vec<_>>();
        Some(ServiceInfo {
            name: rule.service.to_string(),
            product: fill(&caps, rule.product),
            version: fill(&caps, rule.version),
            extra_info: (!info.is_empty()).then(|| info.join("; ")),
            ..Default::default()
        })
    })
}

fn fill(caps: &Captures, template: &str) -> Option<String> {
    if template.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    caps.expand(template.as_bytes(), &mut out);
    clean(&out)
}

/// Text from a response, made safe to print: control characters dropped,
/// whitespace trimmed, at most 80 characters.
pub(super) fn clean(bytes: &[u8]) -> Option<String> {
    let text: String = String::from_utf8_lossy(bytes)
        .chars()
        .filter(|c| !c.is_control())
        .take(80)
        .collect();
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_string())
}

static STATUS_LINE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?-u)^(HTTP|RTSP|SIP)/\d(?:\.\d)? \d{3}").expect("valid regex"));
static ES_VERSION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?-u)"number"\s*:\s*"([\w.\-]+)""#).expect("valid regex"));
static COUCHDB_VERSION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?-u)"couchdb"\s*:\s*"Welcome".*?"version"\s*:\s*"([\w.\-]+)""#)
        .expect("valid regex")
});

/// HTTP, RTSP and SIP responses, which share a header format. The product
/// comes from the Server header (or SIP's User-Agent).
fn parse_headers(data: &[u8]) -> Option<ServiceInfo> {
    let caps = STATUS_LINE.captures(data)?;
    let split = data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(data.len());
    let (head, body) = data.split_at(split);
    let mut info = ServiceInfo::named(match &caps[1] {
        b"RTSP" => "rtsp",
        b"SIP" => "sip",
        _ => "http",
    });
    if let Some(server) = header(head, "server").or_else(|| header(head, "user-agent")) {
        let (product, version, extra) = split_server(&server);
        info.product = Some(product);
        info.version = version;
        info.extra_info = extra;
    }
    // Some HTTP APIs describe themselves in a JSON body at /.
    let body_has = |s: &[u8]| body.windows(s.len()).any(|w| w == s);
    if body_has(b"\"cluster_name\"") && body_has(b"\"lucene_version\"") {
        info.product = Some("Elasticsearch REST API".into());
        info.version = ES_VERSION.captures(body).and_then(|c| clean(&c[1]));
    } else if let Some(c) = COUCHDB_VERSION.captures(body) {
        info.product = Some("CouchDB httpd".into());
        info.version = clean(&c[1]);
    }
    Some(info)
}

/// The value of an HTTP header, matched case-insensitively.
fn header(head: &[u8], name: &str) -> Option<String> {
    head.split(|&b| b == b'\n').find_map(|line| {
        let (key, value) = line.split_at(line.iter().position(|&b| b == b':')?);
        key.eq_ignore_ascii_case(name.as_bytes())
            .then(|| clean(&value[1..]))
            .flatten()
    })
}

/// Split a Server header such as `Apache/2.4.58 (Ubuntu)` into product,
/// version and extra info.
fn split_server(server: &str) -> (String, Option<String>, Option<String>) {
    let (first, rest) = server.split_once(' ').unwrap_or((server, ""));
    // Jetty writes `Jetty(9.4.53.v20231009)`.
    let (name, version) = match first.split_once('/') {
        Some((n, v)) => (n, Some(v.to_string()).filter(|v| !v.is_empty())),
        None => match first.strip_suffix(')').and_then(|f| f.split_once('(')) {
            Some((n, v)) => (n, Some(v.to_string()).filter(|v| !v.is_empty())),
            None => (first, None),
        },
    };
    let product = match name {
        "Apache" => "Apache httpd",
        "Apache-Coyote" => "Apache Tomcat/Coyote JSP engine",
        "Microsoft-IIS" => "Microsoft IIS httpd",
        "Microsoft-HTTPAPI" => "Microsoft HTTPAPI httpd",
        "Kestrel" => "Microsoft Kestrel httpd",
        "SimpleHTTP" => "Python SimpleHTTPServer",
        "BaseHTTP" => "Python BaseHTTPServer",
        "Werkzeug" => "Werkzeug httpd",
        "gunicorn" => "Gunicorn",
        "uvicorn" => "Uvicorn",
        "openresty" => "OpenResty web app server",
        "LiteSpeed" => "LiteSpeed httpd",
        "Docker" => "Docker API",
        other => other,
    };
    let extra = rest
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')')
        .trim();
    (
        product.to_string(),
        version,
        (!extra.is_empty()).then(|| extra.to_string()),
    )
}

/// Turn an unrecognized response into an entry that shows what came back.
pub(super) fn unrecognized(data: &[u8], guess: &str) -> ServiceInfo {
    ServiceInfo {
        name: format!("{guess}?"),
        fingerprint: Some(printable(data, 120)),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(data: &[u8]) -> ServiceInfo {
        match_response("null", data).unwrap_or_else(|| panic!("no match for {data:?}"))
    }

    #[test]
    fn all_rules_compile() {
        assert_eq!(COMPILED.len(), RULES.len());
    }

    #[test]
    fn ssh() {
        let i = m(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n");
        assert_eq!(i.name, "ssh");
        assert_eq!(i.product.as_deref(), Some("OpenSSH"));
        assert_eq!(i.version.as_deref(), Some("9.6p1"));
        assert_eq!(
            i.extra_info.as_deref(),
            Some("Ubuntu-3ubuntu13.5; protocol 2.0")
        );
        let i = m(b"SSH-2.0-OpenSSH_8.0\r\n");
        assert_eq!(i.extra_info.as_deref(), Some("protocol 2.0"));
        let i = m(b"SSH-2.0-Cisco-1.25\r\n");
        assert_eq!(
            (i.product.as_deref(), i.version.as_deref()),
            (Some("Cisco SSH"), Some("1.25"))
        );
        let i = m(b"SSH-2.0-SomethingElse_1.0\r\n");
        assert_eq!(i.product.as_deref(), Some("SomethingElse_1.0"));
    }

    #[test]
    fn mail_and_ftp() {
        let i = m(b"220 mail.example.org ESMTP Postfix (Debian/GNU)\r\n");
        assert_eq!(
            (i.name.as_str(), i.product.as_deref()),
            ("smtp", Some("Postfix smtpd"))
        );
        assert_eq!(i.extra_info.as_deref(), Some("host: mail.example.org"));
        let i = m(b"220 (vsFTPd 3.0.5)\r\n");
        assert_eq!(
            (i.name.as_str(), i.version.as_deref()),
            ("ftp", Some("3.0.5"))
        );
        assert_eq!(m(b"220 Welcome to some FTP service\r\n").name, "ftp");
        assert_eq!(m(b"+OK Dovecot (Ubuntu) ready.\r\n").name, "pop3");
        assert_eq!(
            m(b"* OK [CAPABILITY IMAP4rev1] Dovecot ready.\r\n").name,
            "imap"
        );
    }

    #[test]
    fn mysql_handshakes() {
        let mut pkt = vec![0x4a, 0, 0, 0, 0x0a];
        pkt.extend_from_slice(b"8.0.36-0ubuntu0.22.04.1\0\x08\0\0\0");
        let i = m(&pkt);
        assert_eq!(i.product.as_deref(), Some("MySQL"));
        assert_eq!(i.version.as_deref(), Some("8.0.36-0ubuntu0.22.04.1"));
        let mut pkt = vec![0x5b, 0, 0, 0, 0x0a];
        pkt.extend_from_slice(b"5.5.5-10.11.6-MariaDB-0+deb12u1\0");
        let i = m(&pkt);
        assert_eq!(i.product.as_deref(), Some("MariaDB"));
        assert_eq!(i.version.as_deref(), Some("10.11.6"));
    }

    #[test]
    fn http_server_header() {
        let i = m(b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.58 (Ubuntu)\r\n\r\n<html>");
        assert_eq!(i.name, "http");
        assert_eq!(i.product.as_deref(), Some("Apache httpd"));
        assert_eq!(i.version.as_deref(), Some("2.4.58"));
        assert_eq!(i.extra_info.as_deref(), Some("Ubuntu"));
        let i = m(b"HTTP/1.1 404 Not Found\r\nserver: nginx\r\n\r\n");
        assert_eq!((i.product.as_deref(), i.version), (Some("nginx"), None));
        let i = m(b"HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n");
        assert_eq!((i.name.as_str(), i.product), ("http", None));
        let es = b"HTTP/1.1 200 OK\r\n\r\n{\"cluster_name\":\"x\",\"version\":{\"number\":\"8.13.4\",\"lucene_version\":\"9.10.0\"}}";
        let i = m(es);
        assert_eq!(i.product.as_deref(), Some("Elasticsearch REST API"));
        assert_eq!(i.version.as_deref(), Some("8.13.4"));
    }

    #[test]
    fn probe_specific_rules() {
        assert!(match_response("null", b"N").is_none());
        let i = match_response("pgsql", b"N").unwrap();
        assert_eq!(i.name, "postgresql");
        let i = match_response("redis", b"$300\r\n# Server\r\nredis_version:7.2.4\r\n").unwrap();
        assert_eq!(
            (i.name.as_str(), i.version.as_deref()),
            ("redis", Some("7.2.4"))
        );
        let i = match_response("memcached", b"VERSION 1.6.21\r\n").unwrap();
        assert_eq!(i.version.as_deref(), Some("1.6.21"));
    }

    #[test]
    fn rabbitmq_connection_start() {
        // Field table entries: short-string name, type 'S', long string.
        let mut frame = b"\x01\x00\x00\x00\x00\x01\x00\x00\x0a\x00\x0a\x00\x09".to_vec();
        frame.extend_from_slice(b"\x00\x00\x00\x40");
        frame.extend_from_slice(b"\x07productS\x00\x00\x00\x08RabbitMQ");
        frame.extend_from_slice(b"\x07versionS\x00\x00\x00\x0612.0.3");
        let i = match_response("amqp", &frame).unwrap();
        assert_eq!(i.name, "amqp");
        assert_eq!(i.product.as_deref(), Some("RabbitMQ"));
        assert_eq!(i.version.as_deref(), Some("12.0.3"));
    }

    #[test]
    fn probe_payload_lengths() {
        let len = |name: &str| {
            PROBES
                .iter()
                .find(|p| p.name == name)
                .unwrap()
                .payload
                .len()
        };
        // Each length matches the one written inside the payload.
        assert_eq!(len("rdp"), 0x13);
        assert_eq!(len("mssql"), 0x2f);
        assert_eq!(len("smb"), 4 + 0x6c);
        assert_eq!(len("ldap"), 2 + 0x79);
        assert_eq!(len("mongodb"), 0x38);
        let names: Vec<_> = PROBES.iter().map(|p| p.name).collect();
        let mut unique = names.clone();
        unique.dedup();
        assert_eq!(names, unique);
    }

    #[test]
    fn more_ssh_and_mail() {
        let i = m(b"SSH-2.0-OpenSSH_for_Windows_9.5\r\n");
        assert_eq!(
            (i.product.as_deref(), i.version.as_deref()),
            (Some("OpenSSH for Windows"), Some("9.5"))
        );
        let i = m(b"SSH-2.0-libssh_0.10.6\r\n");
        assert_eq!(
            (i.product.as_deref(), i.version.as_deref()),
            (Some("libssh"), Some("0.10.6"))
        );
        assert_eq!(
            m(b"SSH-2.0-ROSSSH\r\n").product.as_deref(),
            Some("MikroTik RouterOS sshd")
        );
        assert_eq!(
            m(b"SSH-2.0-Go\r\n").product.as_deref(),
            Some("Go x/crypto/ssh")
        );
        let i = m(b"220 ftp.example.org FTP server (MikroTik 7.14.2) ready\r\n");
        assert_eq!(
            (i.product.as_deref(), i.version.as_deref()),
            (Some("MikroTik RouterOS ftpd"), Some("7.14.2"))
        );
        let i = m(b"* OK The Microsoft Exchange IMAP4 service is ready.\r\n");
        assert_eq!(i.product.as_deref(), Some("Microsoft Exchange imapd"));
        let i = m(b"* OK mail.example.org Cyrus IMAP v3.8.1-Debian server ready\r\n");
        assert_eq!(
            (i.product.as_deref(), i.version.as_deref()),
            (Some("Cyrus imapd"), Some("3.8.1-Debian"))
        );
        assert_eq!(
            m(b"+OK Hello there.\r\n").product.as_deref(),
            Some("Courier pop3d")
        );
        let i = m(b"@RSYNCD: 31.0\n");
        assert_eq!(
            (i.name.as_str(), i.extra_info.as_deref()),
            ("rsync", Some("protocol 31.0"))
        );
        let i = m(b"200 news.example.org InterNetNews server INN 2.7.1 ready\r\n");
        assert_eq!(
            (i.name.as_str(), i.version.as_deref()),
            ("nntp", Some("2.7.1"))
        );
        let i = m(b":irc.example.org NOTICE * :*** Looking up your hostname...\r\n");
        assert_eq!(i.name, "irc");
    }

    #[test]
    fn databases_and_coordinators() {
        let mut reply = vec![0u8; 12];
        reply.extend_from_slice(b"\xdd\x07\x00\x00\x00\x00\x00\x00\x00");
        reply.extend_from_slice(b"\x40\x00\x00\x00\x02version\x00\x06\x00\x00\x007.0.5\x00");
        let i = match_response("mongodb", &reply).unwrap();
        assert_eq!(
            (i.name.as_str(), i.version.as_deref()),
            ("mongodb", Some("7.0.5"))
        );
        // Without the probe, those bytes mean nothing.
        assert!(match_response("null", &reply).is_none());
        let i = match_response(
            "zookeeper",
            b"Zookeeper version: 3.8.4-9316c2a7a97e1666d8f4593f34dd6fc36ecc436c, built on 2024-02-12\n",
        )
        .unwrap();
        assert_eq!(
            (i.product.as_deref(), i.version.as_deref()),
            (Some("Apache ZooKeeper"), Some("3.8.4"))
        );
    }

    #[test]
    fn rtsp_sip_and_more_http() {
        let i = match_response(
            "rtsp",
            b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: GStreamer RTSP server\r\n\r\n",
        )
        .unwrap();
        assert_eq!(
            (i.name.as_str(), i.product.as_deref()),
            ("rtsp", Some("GStreamer"))
        );
        let i = match_response(
            "sip",
            b"SIP/2.0 200 OK\r\nUser-Agent: Asterisk PBX 20.5.0\r\n\r\n",
        )
        .unwrap();
        assert_eq!(
            (i.name.as_str(), i.product.as_deref()),
            ("sip", Some("Asterisk"))
        );
        let i = m(b"HTTP/1.1 200 OK\r\nServer: Jetty(9.4.53.v20231009)\r\n\r\n");
        assert_eq!(
            (i.product.as_deref(), i.version.as_deref()),
            (Some("Jetty"), Some("9.4.53.v20231009"))
        );
        let i = m(b"HTTP/1.1 200 OK\r\nServer: Werkzeug/3.0.1 Python/3.12.3\r\n\r\n");
        assert_eq!(
            (i.product.as_deref(), i.extra_info.as_deref()),
            (Some("Werkzeug httpd"), Some("Python/3.12.3"))
        );
        let couch = b"HTTP/1.1 200 OK\r\nServer: CouchDB/3.3.3 (Erlang OTP/24)\r\n\r\n{\"couchdb\":\"Welcome\",\"version\":\"3.3.3\"}";
        let i = m(couch);
        assert_eq!(
            (i.product.as_deref(), i.version.as_deref()),
            (Some("CouchDB httpd"), Some("3.3.3"))
        );
    }

    #[test]
    fn unknown_data() {
        assert!(match_response("null", b"hello there\r\n").is_none());
        let i = unrecognized(b"hi\r\n\x01", "foo");
        assert_eq!(i.name, "foo?");
        assert_eq!(i.fingerprint.as_deref(), Some("hi\\r\\n\\x01"));
    }
}
