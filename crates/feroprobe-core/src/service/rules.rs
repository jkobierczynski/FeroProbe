//! Matching service replies against the rules in the rules file
//! ([`super::db`]), plus FeroProbe's built-in readers: the binary parsers in
//! [`super::parsers`] and a generic HTTP/RTSP/SIP header reader used when
//! no rule names the product.

use std::sync::LazyLock;

use regex::bytes::Regex;

use super::db::{Rule, ServiceDb};
use super::{ServiceInfo, printable};

/// What matched a reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Found {
    /// The service is identified; probing stops.
    Hard(Box<ServiceInfo>),
    /// Only the service name; probing goes on with probes that can tell
    /// more.
    Soft(String),
}

/// A match and what made it, for `--version-trace`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Matched {
    pub found: Found,
    /// `rules line 42`, `built-in parser smb`, ...
    pub by: String,
}

/// Identify the service that sent `data` in reply to `probe`. Order: the
/// built-in parser for the probe, the hard rules in file order, the
/// generic header reader, then the soft rules.
pub(super) fn match_response(db: &ServiceDb, probe: &str, data: &[u8]) -> Option<Matched> {
    if data.is_empty() {
        return None;
    }
    if let Some(info) = super::parsers::parse(probe, data) {
        return Some(Matched {
            found: Found::Hard(Box::new(info)),
            by: format!("built-in parser {probe}"),
        });
    }
    let applicable = || db.rules.iter().filter(|r| r.applies_to(probe));
    for rule in applicable().filter(|r| !r.soft) {
        if let Some(caps) = rule.regex.captures(data) {
            return Some(Matched {
                found: Found::Hard(Box::new(fill_info(rule, &caps))),
                by: format!("{} line {}", rules_name(db), rule.line),
            });
        }
    }
    if let Some(info) = parse_headers(data) {
        return Some(Matched {
            found: Found::Hard(Box::new(info)),
            by: "built-in header reader".into(),
        });
    }
    applicable()
        .filter(|r| r.soft)
        .find(|r| r.regex.is_match(data))
        .map(|rule| Matched {
            found: Found::Soft(rule.service.clone()),
            by: format!("{} line {}", rules_name(db), rule.line),
        })
}

fn rules_name(db: &ServiceDb) -> String {
    if db.source == "built-in" {
        "built-in rules".into()
    } else {
        db.source.clone()
    }
}

fn fill_info(rule: &Rule, caps: &regex::bytes::Captures) -> ServiceInfo {
    let info: Vec<String> = rule
        .info
        .iter()
        .filter_map(|t| Rule::fill(caps, t))
        .collect();
    ServiceInfo {
        name: rule.service.clone(),
        product: Rule::fill(caps, &rule.product),
        version: Rule::fill(caps, &rule.version),
        extra_info: (!info.is_empty()).then(|| info.join("; ")),
        hostname: Rule::fill(caps, &rule.host),
        os_type: Rule::fill(caps, &rule.os),
        device_type: Rule::fill(caps, &rule.device),
        cpe: rule
            .cpe
            .iter()
            .filter_map(|t| Rule::fill(caps, t))
            // A version group that matched nothing leaves a trailing colon.
            .map(|c| c.trim_end_matches(':').to_string())
            .collect(),
        ..Default::default()
    }
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
/// HTTP, RTSP and SIP responses, which share a header format. The product
/// comes from the Server header (or SIP's User-Agent).
fn parse_headers(data: &[u8]) -> Option<ServiceInfo> {
    let caps = STATUS_LINE.captures(data)?;
    let split = data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(data.len());
    let head = &data[..split];
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

    use crate::service::db::ServiceDb;

    /// The hard match for a reply to `probe`, with the built-in rules.
    fn mr(probe: &str, data: &[u8]) -> Option<ServiceInfo> {
        match match_response(&ServiceDb::builtin(), probe, data)?.found {
            Found::Hard(info) => Some(*info),
            Found::Soft(_) => None,
        }
    }

    fn m(data: &[u8]) -> ServiceInfo {
        mr("null", data).unwrap_or_else(|| panic!("no match for {data:?}"))
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
        assert_eq!(i.hostname.as_deref(), Some("mail.example.org"));
        assert_eq!(i.extra_info.as_deref(), Some("Debian/GNU"));
        assert_eq!(i.cpe, vec!["cpe:/a:postfix:postfix"]);
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
        assert!(mr("null", b"N").is_none());
        let i = mr("pgsql", b"N").unwrap();
        assert_eq!(i.name, "postgresql");
        let i = mr("redis", b"$300\r\n# Server\r\nredis_version:7.2.4\r\n").unwrap();
        assert_eq!(
            (i.name.as_str(), i.version.as_deref()),
            ("redis", Some("7.2.4"))
        );
        let i = mr("memcached", b"VERSION 1.6.21\r\n").unwrap();
        assert_eq!(i.version.as_deref(), Some("1.6.21"));
    }

    #[test]
    fn rabbitmq_connection_start() {
        // Field table entries: short-string name, type 'S', long string.
        let mut frame = b"\x01\x00\x00\x00\x00\x01\x00\x00\x0a\x00\x0a\x00\x09".to_vec();
        frame.extend_from_slice(b"\x00\x00\x00\x40");
        frame.extend_from_slice(b"\x07productS\x00\x00\x00\x08RabbitMQ");
        frame.extend_from_slice(b"\x07versionS\x00\x00\x00\x0612.0.3");
        let i = mr("amqp", &frame).unwrap();
        assert_eq!(i.name, "amqp");
        assert_eq!(i.product.as_deref(), Some("RabbitMQ"));
        assert_eq!(i.version.as_deref(), Some("12.0.3"));
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
        let i = mr("mongodb", &reply).unwrap();
        assert_eq!(
            (i.name.as_str(), i.version.as_deref()),
            ("mongodb", Some("7.0.5"))
        );
        // Without the probe, those bytes mean nothing.
        assert!(mr("null", &reply).is_none());
        let i = mr(
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
        let i = mr(
            "rtsp",
            b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: GStreamer RTSP server\r\n\r\n",
        )
        .unwrap();
        assert_eq!(
            (i.name.as_str(), i.product.as_deref()),
            ("rtsp", Some("GStreamer"))
        );
        let i = mr(
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
        assert!(mr("null", b"hello there\r\n").is_none());
        let i = unrecognized(b"hi\r\n\x01", "foo");
        assert_eq!(i.name, "foo?");
        assert_eq!(i.fingerprint.as_deref(), Some("hi\\r\\n\\x01"));
    }
    /// (service, product, version) of a hard match.
    fn spv(i: &ServiceInfo) -> (&str, Option<&str>, Option<&str>) {
        (i.name.as_str(), i.product.as_deref(), i.version.as_deref())
    }

    #[test]
    fn host_os_device_and_cpe() {
        let i = m(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n");
        assert_eq!(i.os_type.as_deref(), Some("Linux"));
        assert_eq!(
            i.cpe,
            vec!["cpe:/a:openbsd:openssh:9.6p1", "cpe:/o:linux:linux_kernel"]
        );
        let i = m(b"SSH-2.0-OpenSSH_8.0\r\n");
        assert_eq!((i.os_type, i.cpe.len()), (None, 1));
        let i = m(b"SSH-2.0-ROSSSH\r\n");
        assert_eq!(i.device_type.as_deref(), Some("router"));
        let i =
            m(b"220 mx.example.org Microsoft ESMTP MAIL Service, Version: 10.0.17763.1 ready\r\n");
        assert_eq!(
            spv(&i),
            ("smtp", Some("Microsoft ESMTP"), Some("10.0.17763.1"))
        );
        assert_eq!(i.hostname.as_deref(), Some("mx.example.org"));
        assert_eq!(i.os_type.as_deref(), Some("Windows"));
        // A CPE template whose version group is empty loses its colon.
        let i = m(b"HTTP/1.1 200 OK\r\nServer: openresty\r\n\r\n");
        assert_eq!(i.cpe, vec!["cpe:/a:openresty:openresty"]);
    }

    #[test]
    fn more_ssh() {
        let i = m(b"SSH-2.0-dropbear_2022.83\r\n");
        assert_eq!(spv(&i), ("ssh", Some("Dropbear sshd"), Some("2022.83")));
        let i = m(b"SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\n");
        assert_eq!(
            i.extra_info.as_deref(),
            Some("Debian-10+deb9u7; protocol 2.0")
        );
        let i = m(b"SSH-2.0-HUAWEI-1.5\r\n");
        assert_eq!(spv(&i), ("ssh", Some("Huawei VRP sshd"), Some("1.5")));
        let i = m(b"SSH-2.0-mpSSH_0.2.1\r\n");
        assert_eq!(i.device_type.as_deref(), Some("remote management"));
        let i = m(b"SSH-2.0-Sun_SSH_1.1.4\r\n");
        assert_eq!(i.os_type.as_deref(), Some("Solaris"));
        let i = m(b"SSH-2.0-Twisted\r\n");
        assert_eq!(spv(&i), ("ssh", Some("Twisted Conch sshd"), None));
    }

    #[test]
    fn more_mail_and_ftp() {
        let i = m(b"220 ftp.example.org FTP server (Version wu-2.6.2(1) Mon Jan 1 00:00:00 UTC 2024) ready.\r\n");
        assert_eq!(spv(&i), ("ftp", Some("WU-FTPD"), Some("wu-2.6.2")));
        let i = m(b"220 ProFTPD 1.3.8b Server (Debian) [::ffff:10.0.0.5]\r\n");
        assert_eq!(i.cpe, vec!["cpe:/a:proftpd:proftpd:1.3.8b"]);
        let i = m(b"* OK [CAPABILITY IMAP4REV1 LITERAL+] localhost IMAP4rev1 2007f.404 at Mon, 1 Jan 2024\r\n");
        assert_eq!(spv(&i), ("imap", Some("UW imapd"), Some("2007f.404")));
        let i = m(b"+OK Qpopper (version 4.1.0) at mail starting.\r\n");
        assert_eq!(spv(&i), ("pop3", Some("Qpopper"), Some("4.1.0")));
        let i = m(b"220 mail.example.org ESMTP Exim 4.97 Mon, 01 Jan 2024\r\n");
        assert_eq!(i.cpe, vec!["cpe:/a:exim:exim:4.97"]);
    }

    #[test]
    fn soft_matches() {
        let db = ServiceDb::builtin();
        let soft =
            |probe: &str, data: &[u8]| match match_response(&db, probe, data).map(|m| m.found) {
                Some(Found::Soft(s)) => Some(s),
                _ => None,
            };
        assert_eq!(soft("null", b"+OK ready\r\n").as_deref(), Some("pop3"));
        assert_eq!(soft("null", b"* OK ready\r\n").as_deref(), Some("imap"));
        // Only for replies to the listen probe.
        assert_eq!(soft("http", b"+OK ready\r\n"), None);
        let by = match_response(&db, "null", b"+OK ready\r\n").unwrap().by;
        assert!(by.starts_with("built-in rules line "), "{by}");
    }

    #[test]
    fn http_rules() {
        let i = m(b"HTTP/1.1 200 OK\r\nDate: x\r\nServer: Apache/2.4.58 (Ubuntu)\r\n\r\n");
        assert_eq!(spv(&i), ("http", Some("Apache httpd"), Some("2.4.58")));
        assert_eq!(i.extra_info.as_deref(), Some("Ubuntu"));
        assert_eq!(i.cpe, vec!["cpe:/a:apache:http_server:2.4.58"]);
        let i = m(b"HTTP/1.1 404 Not Found\r\nserver: nginx/1.24.0\r\n\r\n");
        assert_eq!(spv(&i), ("http", Some("nginx"), Some("1.24.0")));
        let i = m(b"HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\n\r\n");
        assert_eq!(i.os_type.as_deref(), Some("Windows"));
        let i = m(b"HTTP/1.1 400 Bad Request\r\nServer: squid/6.6\r\n\r\n");
        assert_eq!(
            spv(&i),
            ("http-proxy", Some("Squid http proxy"), Some("6.6"))
        );
        let i = m(b"HTTP/1.1 403 Forbidden\r\nX-Content-Type-Options: nosniff\r\nX-Jenkins: 2.440.1\r\n\r\n");
        assert_eq!(spv(&i), ("http", Some("Jenkins"), Some("2.440.1")));
        let i = m(b"HTTP/1.1 200 OK\r\nX-Powered-By: Express\r\nContent-Type: text/html\r\n\r\n");
        assert_eq!(i.product.as_deref(), Some("Node.js Express framework"));
        let i = m(b"HTTP/1.1 200 OK\r\nServer: Docker/24.0.7 (linux)\r\n\r\n");
        assert_eq!(spv(&i), ("http", Some("Docker API"), Some("24.0.7")));
        assert_eq!(i.os_type.as_deref(), Some("linux"));
        // A Server line in the body does not count.
        let i = m(b"HTTP/1.1 200 OK\r\nServer: TestServer/1.0\r\n\r\nServer: Apache/2.4.58\r\n");
        assert_eq!(spv(&i), ("http", Some("TestServer"), Some("1.0")));
        // No rule for this server: the generic header reader.
        let i = m(b"HTTP/1.0 200 OK\r\nServer: TestServer/1.2.3 (Test)\r\n\r\n");
        assert_eq!(spv(&i), ("http", Some("TestServer"), Some("1.2.3")));
        assert!(i.cpe.is_empty());
    }

    #[test]
    fn databases_queues_and_more() {
        let i = mr(
            "redis",
            b"$400\r\n# Server\r\nredis_version:7.2.4\r\nredis_mode:standalone\r\nos:Linux 6.8.0 x86_64\r\n",
        )
        .unwrap();
        assert_eq!(
            spv(&i),
            ("redis", Some("Redis key-value store"), Some("7.2.4"))
        );
        assert_eq!(i.os_type.as_deref(), Some("Linux"));
        let i = m(b"INFO {\"server_id\":\"N1\",\"version\":\"2.10.7\",\"go\":\"go1.22\"}\r\n");
        assert_eq!(spv(&i), ("nats", Some("NATS server"), Some("2.10.7")));
        let i = m(b"\x00\x00\x01\x0c\x01ActiveMQ\x00\x00\x00\x0c\x01\x00\x00\x00\x00\x0fProviderVersion\x09\x00\x066.0.1\x00");
        assert_eq!(
            spv(&i),
            (
                "apachemq",
                Some("ActiveMQ OpenWire transport"),
                Some("6.0.1")
            )
        );
        let i = mr(
            "beanstalkd",
            b"OK 120\r\n---\ncurrent-jobs-urgent: 0\nversion: \"1.13\"\n",
        )
        .unwrap();
        assert_eq!(spv(&i), ("beanstalkd", Some("beanstalkd"), Some("1.13")));
        let mut sup = b"\x84\x00\x00\x01\x06\x00\x00\x00\x40\x00\x02".to_vec();
        sup.extend_from_slice(b"\x00\x0bCQL_VERSION\x00\x01\x00\x053.4.7");
        let i = mr("cassandra", &sup).unwrap();
        assert_eq!(i.extra_info.as_deref(), Some("CQL 3.4.7"));
        let i = mr("epmd", b"\x00\x00\x11\x11name rabbit at port 25672\n").unwrap();
        assert_eq!(i.extra_info.as_deref(), Some("node rabbit at port 25672"));
        let i = m(b"( success ( 2 2 ( ) ( edit-pipeline svndiff1 ) ) )");
        assert_eq!(spv(&i), ("svnserve", Some("Subversion svnserve"), None));
        let i = m(
            b"220 dict.example.org dictd 1.12.1/rf on Linux 6.1.0-18-amd64 <auth.mime> <1.2@x>\r\n",
        );
        assert_eq!(spv(&i), ("dict", Some("dictd"), Some("1.12.1/rf")));
        assert_eq!(
            mr("crlf", b"0 , 0 : ERROR : INVALID-PORT\r\n")
                .unwrap()
                .name,
            "auth"
        );
        let i = m(b"RFB 003.889\n");
        assert_eq!(i.os_type.as_deref(), Some("Mac OS X"));
        let i = m(b"\xff\xfb\x01\xff\xfb\x03\r\n\r\nUser Access Verification\r\n\r\nPassword: ");
        assert_eq!(i.product.as_deref(), Some("Cisco telnetd"));
    }

    #[test]
    fn binary_probe_replies() {
        let mut x11 = b"\x01\x00\x0b\x00\x00\x00\x10\x00".to_vec();
        x11.extend_from_slice(&[0; 32]);
        x11.extend_from_slice(b"The X.Org Foundation\x00\x00");
        let i = mr("x11", &x11).unwrap();
        assert_eq!(i.name, "X11");
        assert_eq!(
            i.extra_info.as_deref(),
            Some("vendor: The X.Org Foundation")
        );
        let i = mr(
            "x11",
            b"\x00\x16\x0b\x00\x00\x00\x06\x00No protocol specified\n\x00\x00",
        )
        .unwrap();
        assert_eq!(i.extra_info.as_deref(), Some("access denied"));
        // An accepted, successful reply to the portmapper NULL call.
        let mut rpc = b"\x80\x00\x00\x18FPRO\x00\x00\x00\x01\x00\x00\x00\x00".to_vec();
        rpc.extend_from_slice(&[0; 8]);
        rpc.extend_from_slice(&[0; 4]);
        assert_eq!(mr("rpc", &rpc).unwrap().name, "rpcbind");
        // Program unavailable: an RPC service, not the portmapper.
        let mut other = rpc.clone();
        other[27] = 1;
        assert_eq!(mr("rpc", &other).unwrap().name, "rpc");
        assert_eq!(mr("rpc-udp", &rpc[4..]).unwrap().name, "rpcbind");
        assert!(mr("null", &rpc).is_none());
        assert_eq!(
            mr("socks5", b"\x05\x00").unwrap().extra_info.as_deref(),
            Some("no authentication")
        );
        assert_eq!(mr("ajp", b"AB\x00\x01\x09").unwrap().name, "ajp13");
        assert_eq!(
            mr("java-rmi", b"\x4e\x00\x09127.0.0.1\x00\x00\xc3\x50")
                .unwrap()
                .name,
            "java-rmi"
        );
        let mut pptp = b"\x00\x9c\x00\x01\x1a\x2b\x3c\x4d\x00\x02\x00\x00\x01\x00\x01\x00".to_vec();
        pptp.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1]);
        pptp.extend_from_slice(&{
            let mut h = [0u8; 64];
            h[..3].copy_from_slice(b"vpn");
            h
        });
        pptp.extend_from_slice(&{
            let mut v = [0u8; 64];
            v[..9].copy_from_slice(b"Microsoft");
            v
        });
        let i = mr("pptp", &pptp).unwrap();
        assert_eq!(
            (i.product.as_deref(), i.hostname.as_deref()),
            (Some("Microsoft"), Some("vpn"))
        );
        assert_eq!(
            mr(
                "git",
                b"0046ERR access denied or repository not exported: /\n"
            )
            .unwrap()
            .name,
            "git"
        );
        let i = mr("xmpp", b"<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' id='1' from='example.org' version='1.0'>").unwrap();
        assert_eq!(i.extra_info.as_deref(), Some("client stream"));
    }

    #[test]
    fn udp_replies() {
        let i = mr(
            "openvpn",
            b"\x40FEDCBA98\x01\x00\x00\x00\x00FEROPROB\x00\x00\x00\x00",
        )
        .unwrap();
        assert_eq!(i.name, "openvpn");
        let i = mr(
            "memcached-udp",
            b"\x00\x01\x00\x00\x00\x01\x00\x00VERSION 1.6.21\r\n",
        )
        .unwrap();
        assert_eq!(spv(&i), ("memcache", Some("Memcached"), Some("1.6.21")));
        let mut ipmi = b"\x06\x00\xff\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10".to_vec();
        ipmi.extend_from_slice(b"\x81\x1c\x63\x20\x00\x38\x00\x01\x97\x04\x03\x00\x00\x00\x00\x09");
        let i = mr("ipmi", &ipmi).unwrap();
        assert_eq!(spv(&i), ("asf-rmcp", Some("IPMI"), Some("2.0")));
        ipmi[22] = 0x17;
        assert_eq!(mr("ipmi", &ipmi).unwrap().version.as_deref(), Some("1.5"));
        // DNS over TCP goes through the DNS reader.
        let mut dns = b"\x00\x2c\x13\x38\x84\x00\x00\x01\x00\x01\x00\x00\x00\x00".to_vec();
        dns.extend_from_slice(b"\x07version\x04bind\x00\x00\x10\x00\x03");
        dns.extend_from_slice(b"\xc0\x0c\x00\x10\x00\x03\x00\x00\x00\x00\x00\x0a\x099.18.24-1");
        let i = mr("dns-tcp", &dns).unwrap();
        assert_eq!(
            (i.name.as_str(), i.version.as_deref()),
            ("domain", Some("9.18.24-1"))
        );
    }
}
