//! Service and version detection, like nmap's `-sV`.
//!
//! The probes and match rules live in a rules file ([`db`], built in from
//! `data/service-rules.txt`, replaceable with `--service-rules`). They are
//! FeroProbe's own; nmap's database is not used.
//!
//! For each open TCP port, until a rule matches:
//!
//! 1. On the TLS probe's ports (443, 993, ...), a TLS handshake first; the
//!    probes then run inside the tunnel.
//! 2. The probes meant for this port (HTTP on 80, Redis on 6379, ...).
//! 3. The listen probe (`null`): SSH, FTP, SMTP and others talk first.
//! 4. Every other probe whose rarity is at most the intensity
//!    (`--version-intensity`, default 7), rarest last, as nmap does.
//! 5. A TLS handshake when the port stayed silent or sent a TLS alert.
//!
//! A soft match names the service but keeps probing, only with the probes
//! that can tell more about that service (all of them at intensity 9), as
//! nmap does. Open UDP ports get the UDP probes the same way, without the
//! listen and TLS steps.

pub mod db;
mod parsers;
mod rules;
mod tls;
mod udp_info;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::stream::{self, StreamExt};
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::model::{HostResult, PortState, Protocol, ScanConfig};
use crate::ports::service_name;
use crate::timing::pace;
pub use db::{ParseError, Probe, ProbeKind, ServiceDb};
use rules::{Found, Matched};

/// What version detection learned about a port.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ServiceInfo {
    /// Service name such as `ssh` or `http`. Ends in `?` when the port
    /// answered but no rule recognized the reply.
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra_info: Option<String>,
    /// The host name the service gave away (Service Info: Host).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// The operating system the service gave away (Service Info: OS).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_type: Option<String>,
    /// The kind of device, such as `router` (Service Info: Device).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_type: Option<String>,
    /// CPE names for the product and operating system.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cpe: Vec<String>,
    /// `ssl` when the service runs inside TLS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tunnel: Option<&'static str>,
    /// The start of a reply no rule recognized, escaped for printing. Useful
    /// for writing new rules.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

impl ServiceInfo {
    fn named(name: &str) -> Self {
        Self {
            name: name.to_string(),
            ..Default::default()
        }
    }

    /// The name with its tunnel, such as `ssl/http`.
    pub fn full_name(&self) -> String {
        match self.tunnel {
            Some(t) => format!("{t}/{}", self.name),
            None => self.name.clone(),
        }
    }

    /// Product, version and extra info on one line, like nmap's VERSION
    /// column: `OpenSSH 9.6p1 (protocol 2.0)`.
    pub fn version_line(&self) -> String {
        let mut parts: Vec<String> = [&self.product, &self.version]
            .into_iter()
            .flatten()
            .cloned()
            .collect();
        if let Some(extra) = &self.extra_info {
            parts.push(format!("({extra})"));
        }
        parts.join(" ")
    }

    fn add_extra(&mut self, extra: String) {
        self.extra_info = Some(match self.extra_info.take() {
            Some(e) => format!("{e}; {extra}"),
            None => extra,
        });
    }
}

/// Escape `data` for printing, nmap style: `SSH-2.0-x\r\n`, at most `max`
/// input bytes.
fn printable(data: &[u8], max: usize) -> String {
    let mut out = String::new();
    for &b in data.iter().take(max) {
        match b {
            b'\r' => out.push_str("\\r"),
            b'\n' => out.push_str("\\n"),
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(char::from(b)),
            _ => out.push_str(&format!("\\x{b:02x}")),
        }
    }
    out
}

/// Largest reply we read from one probe.
const MAX_RESPONSE: usize = 16 * 1024;
/// Once data arrives, how long a pause ends the reply.
const IDLE_GAP: Duration = Duration::from_millis(250);

/// Send `payload` (if any) and collect the reply until `wait` passes with no
/// data, a short pause follows some data, the peer closes, or `wait` has
/// passed since the first data.
async fn exchange<S>(stream: &mut S, payload: &[u8], wait: Duration) -> Vec<u8>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if !payload.is_empty() && stream.write_all(payload).await.is_err() {
        return Vec::new();
    }
    let _ = stream.flush().await;
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    let mut limit = wait;
    // Set at the first data: a slow trickle must not hold the scan forever.
    let mut deadline: Option<Instant> = None;
    while out.len() < MAX_RESPONSE {
        match tokio::time::timeout(limit, stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                out.extend_from_slice(&buf[..n]);
                let end = *deadline.get_or_insert_with(|| Instant::now() + wait);
                limit = IDLE_GAP.min(end.saturating_duration_since(Instant::now()));
                if limit.is_zero() {
                    break;
                }
            }
            _ => break,
        }
    }
    out
}

/// How version detection runs: nmap's `--version-intensity`,
/// `--version-trace` and the rules to use.
#[derive(Debug, Clone)]
pub struct VersionScan {
    /// How long to wait for each reply (`--version-timeout`).
    pub wait: Duration,
    /// 0-9: probes rarer than this are not sent, except to their own ports.
    pub intensity: u8,
    /// Print each probe, reply and match to standard output, like nmap.
    pub trace: bool,
    /// Print the trace to standard error instead, so it cannot spoil a
    /// JSON, XML or grepable report written to standard output.
    pub trace_to_stderr: bool,
    pub db: Arc<ServiceDb>,
}

impl VersionScan {
    /// nmap's default intensity.
    pub const DEFAULT_INTENSITY: u8 = 7;
    /// `--version-light`.
    pub const LIGHT: u8 = 2;
    /// `--version-all`.
    pub const ALL: u8 = 9;

    /// The defaults: intensity 7, no trace, the built-in rules.
    pub fn new(wait: Duration) -> Self {
        Self {
            wait,
            intensity: Self::DEFAULT_INTENSITY,
            trace: false,
            trace_to_stderr: false,
            db: ServiceDb::builtin(),
        }
    }

    fn trace(&self, line: impl FnOnce() -> String) {
        if !self.trace {
            return;
        }
        if self.trace_to_stderr {
            eprintln!("{}", line());
        } else {
            println!("{}", line());
        }
    }
}

/// `1.2.3.4:22` or `[::1]:22`.
fn endpoint(addr: SocketAddr) -> String {
    addr.to_string()
}

fn proto_name(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Udp => "udp",
        _ => "tcp",
    }
}

/// Where the listen probes (no payload, like `null`) go in the order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Listen {
    /// After the probes meant for the port (plain TCP).
    AfterHinted,
    /// First (inside TLS on a port whose service talks first).
    First,
    /// Not at all (UDP; inside TLS elsewhere).
    Never,
}

/// Every probe that may be tried on `port`, in order, with whether it is
/// meant for the port. Whether each one is actually sent depends on the
/// intensity and on soft matches; see [`allowed`]. TLS is not listed.
fn probe_order(
    db: &ServiceDb,
    protocol: Protocol,
    port: u16,
    listen: Listen,
) -> Vec<(&Probe, bool)> {
    let usable: Vec<&Probe> = db
        .probes
        .iter()
        .filter(|p| p.protocol == protocol && p.kind != ProbeKind::Tls)
        .collect();
    let is_listen = |p: &Probe| p.payload().is_empty();
    let mut listens: Vec<(&Probe, bool)> = usable
        .iter()
        .filter(|p| is_listen(p) && listen != Listen::Never)
        .map(|p| (*p, p.is_for(port)))
        .collect();
    let hinted = usable
        .iter()
        .filter(|p| !is_listen(p) && p.is_for(port))
        .map(|p| (*p, true));
    let mut rest: Vec<&Probe> = usable
        .iter()
        .copied()
        .filter(|p| !is_listen(p) && !p.is_for(port))
        .collect();
    // Stable: file order within a rarity.
    rest.sort_by_key(|p| p.rarity);
    let rest = rest.into_iter().map(|p| (p, false));
    let mut order = Vec::new();
    if listen == Listen::First {
        order.append(&mut listens);
    }
    order.extend(hinted);
    order.append(&mut listens);
    order.extend(rest);
    order
}

/// Whether `probe` can name `service` beyond a soft match: a rule tied to
/// the probe or its built-in parser names the service.
fn can_identify(db: &ServiceDb, probe: &Probe, service: &str) -> bool {
    parsers::services(&probe.name).contains(&service)
        || db
            .rules
            .iter()
            .any(|r| !r.soft && r.service == service && r.probe.as_deref() == Some(&probe.name))
}

/// Whether to send `probe`, nmap's rules: without a soft match, the probes
/// meant for the port and those no rarer than the intensity; after a soft
/// match, only the probes that can say more about that service (every
/// probe at intensity 9).
fn allowed(db: &ServiceDb, probe: &Probe, hinted: bool, soft: Option<&str>, intensity: u8) -> bool {
    match soft {
        None => hinted || probe.rarity <= intensity,
        Some(service) => intensity >= VersionScan::ALL || can_identify(db, probe, service),
    }
}

/// What a round of probes learned.
#[derive(Debug, Default)]
struct Round {
    hard: Option<ServiceInfo>,
    soft: Option<String>,
    /// The first reply no rule recognized.
    unknown: Option<Vec<u8>>,
    /// A reply looked like TLS.
    saw_tls: bool,
    /// Something answered, even an empty UDP datagram.
    answered: bool,
}

/// Note what a reply to `probe` showed in `round`, tracing it.
fn take_reply(
    vs: &VersionScan,
    round: &mut Round,
    probe: &Probe,
    addr: SocketAddr,
    protocol: Protocol,
    ssl: bool,
    data: Vec<u8>,
) {
    let proto = proto_name(protocol);
    if data.is_empty() {
        vs.trace(|| {
            format!(
                "Service scan no reply to probe {} from {} ({proto})",
                probe.name,
                endpoint(addr)
            )
        });
        return;
    }
    vs.trace(|| {
        format!(
            "Service scan got {} bytes in reply to probe {} from {} ({proto}): \"{}\"",
            data.len(),
            probe.name,
            endpoint(addr),
            printable(&data, 120)
        )
    });
    if let Some(Matched { found, by }) = rules::match_response(&vs.db, &probe.name, &data) {
        let (kind, name, version) = match &found {
            Found::Hard(i) => (
                "hard",
                i.name.as_str(),
                format!(
                    "|{}|{}|{}|",
                    i.product.as_deref().unwrap_or(""),
                    i.version.as_deref().unwrap_or(""),
                    i.extra_info.as_deref().unwrap_or("")
                ),
            ),
            Found::Soft(s) => ("soft", s.as_str(), "|||".to_string()),
        };
        vs.trace(|| {
            format!(
                "Service scan {kind} match (Probe {} matched with {by}): {} is {}{name}.  Version: {version}",
                probe.name,
                endpoint(addr),
                if ssl { "SSL/" } else { "" },
            )
        });
        match found {
            Found::Hard(info) => {
                round.hard = Some(*info);
                return;
            }
            Found::Soft(s) => {
                round.soft.get_or_insert(s);
            }
        }
    }
    if protocol == Protocol::Tcp && !ssl && is_tls_record(&data) {
        round.saw_tls = true;
    }
    round.unknown.get_or_insert(data);
}

/// The result when no rule matched: the soft match, or the reply nobody
/// recognized (with its fingerprint at intensity 7 or more, like nmap).
fn finish(round: Round, protocol: Protocol, port: u16, vs: &VersionScan) -> Option<ServiceInfo> {
    let fingerprint =
        |d: &[u8]| (vs.intensity >= VersionScan::DEFAULT_INTENSITY).then(|| printable(d, 120));
    match (round.soft, round.unknown) {
        (Some(name), data) => Some(ServiceInfo {
            name,
            fingerprint: data.as_deref().and_then(fingerprint),
            ..Default::default()
        }),
        (None, Some(data)) => {
            let mut info = rules::unrecognized(&data, service_name(protocol, port));
            info.fingerprint = fingerprint(&data);
            Some(info)
        }
        // An empty UDP datagram: the port is open, the service unknown.
        (None, None) if round.answered => Some(ServiceInfo::named(&format!(
            "{}?",
            service_name(protocol, port)
        ))),
        (None, None) => None,
    }
}

/// Send `probe` over a new plain TCP connection and read the reply.
/// `None` if the connection failed, which means the port is no longer
/// reachable.
async fn plain_probe(
    addr: SocketAddr,
    probe: &Probe,
    cfg: &ScanConfig,
    wait: Duration,
) -> Option<Vec<u8>> {
    pace(cfg.scan_delay).await;
    let mut stream = tokio::time::timeout(cfg.timeout, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;
    Some(exchange(&mut stream, probe.payload(), wait).await)
}

/// Send `probe` inside a new TLS session (or `first`, the one the
/// handshake test opened).
async fn tls_probe(
    addr: SocketAddr,
    host: Option<&str>,
    probe: &Probe,
    cfg: &ScanConfig,
    wait: Duration,
    first: &mut Option<tls::Stream>,
) -> Option<Vec<u8>> {
    let mut stream = match first.take() {
        Some(s) => s,
        None => {
            pace(cfg.scan_delay).await;
            tls::connect(addr, host, cfg.timeout, wait).await?.0
        }
    };
    Some(exchange(&mut stream, probe.payload(), wait).await)
}

/// Run the probes for `addr`'s port in order until a hard match, plain or
/// inside TLS.
async fn tcp_round(
    addr: SocketAddr,
    host: Option<&str>,
    cfg: &ScanConfig,
    vs: &VersionScan,
    mut tls_session: Option<tls::Stream>,
) -> Round {
    let ssl = tls_session.is_some();
    let port = addr.port();
    let listen = match vs.db.tls() {
        Some(t) if ssl && t.listen_ports.contains(&port) => Listen::First,
        _ if ssl => Listen::Never,
        _ => Listen::AfterHinted,
    };
    let mut round = Round::default();
    for (probe, hinted) in probe_order(&vs.db, Protocol::Tcp, port, listen) {
        if !allowed(&vs.db, probe, hinted, round.soft.as_deref(), vs.intensity) {
            continue;
        }
        vs.trace(|| {
            format!(
                "Service scan sending probe {} to {} (tcp{})",
                probe.name,
                endpoint(addr),
                if ssl { ", inside TLS" } else { "" }
            )
        });
        let data = if ssl {
            tls_probe(addr, host, probe, cfg, vs.wait, &mut tls_session).await
        } else {
            plain_probe(addr, probe, cfg, vs.wait).await
        };
        let Some(data) = data else {
            vs.trace(|| {
                format!(
                    "Service scan could not connect to {} (tcp); stopping",
                    endpoint(addr)
                )
            });
            break;
        };
        take_reply(vs, &mut round, probe, addr, Protocol::Tcp, ssl, data);
        if round.hard.is_some() {
            break;
        }
    }
    round
}

/// Try TLS on `addr`, and if it works, identify the service inside.
async fn detect_tls(
    addr: SocketAddr,
    host: Option<&str>,
    cfg: &ScanConfig,
    vs: &VersionScan,
) -> Option<ServiceInfo> {
    vs.trace(|| {
        format!(
            "Service scan sending probe tls (TLS handshake) to {} (tcp)",
            endpoint(addr)
        )
    });
    pace(cfg.scan_delay).await;
    let Some((stream, cn)) = tls::connect(addr, host, cfg.timeout, vs.wait).await else {
        vs.trace(|| {
            format!(
                "Service scan no TLS handshake with {} (tcp)",
                endpoint(addr)
            )
        });
        return None;
    };
    vs.trace(|| {
        format!(
            "Service scan TLS handshake with {} (tcp) succeeded",
            endpoint(addr)
        )
    });
    let round = tcp_round(addr, host, cfg, vs, Some(stream)).await;
    let mut info = match round.hard {
        Some(info) => info,
        None if round.soft.is_none() && round.unknown.is_none() => ServiceInfo::named("unknown"),
        None => finish(round, Protocol::Tcp, addr.port(), vs)
            .unwrap_or_else(|| ServiceInfo::named("unknown")),
    };
    info.tunnel = Some("ssl");
    if let Some(cn) = cn {
        info.add_extra(format!("cert CN: {cn}"));
    }
    Some(info)
}

/// Whether `data` starts like a TLS record (an alert or a handshake).
fn is_tls_record(data: &[u8]) -> bool {
    matches!(data, [0x15 | 0x16, 0x03, 0x00..=0x04, ..])
}

/// Identify the service on an open TCP port.
pub async fn detect_tcp(
    addr: SocketAddr,
    host: Option<&str>,
    cfg: &ScanConfig,
    vs: &VersionScan,
) -> Option<ServiceInfo> {
    let port = addr.port();
    let tls = vs
        .db
        .tls()
        .filter(|t| t.is_for(port) || t.rarity <= vs.intensity);
    let tls_first = tls.is_some_and(|t| t.is_for(port));
    if tls_first && let Some(info) = detect_tls(addr, host, cfg, vs).await {
        return Some(info);
    }
    let round = tcp_round(addr, host, cfg, vs, None).await;
    if let Some(info) = round.hard {
        return Some(info);
    }
    // A TLS alert in reply to plain text, or silence to everything: maybe
    // a TLS service on an unusual port.
    let silent = round.soft.is_none() && round.unknown.is_none();
    if tls.is_some()
        && !tls_first
        && (round.saw_tls || silent)
        && let Some(info) = detect_tls(addr, host, cfg, vs).await
    {
        return Some(info);
    }
    finish(round, Protocol::Tcp, port, vs)
}

/// Identify the service on an open UDP port with the UDP probes.
pub async fn detect_udp(
    addr: SocketAddr,
    cfg: &ScanConfig,
    vs: &VersionScan,
) -> Option<ServiceInfo> {
    let mut buf = vec![0u8; 8192];
    let mut round = Round::default();
    // Sockets of earlier probes stay open until the round ends, so the OS
    // cannot hand their source port to a later probe.
    let mut used = Vec::new();
    'probes: for (probe, hinted) in probe_order(&vs.db, Protocol::Udp, addr.port(), Listen::Never) {
        if !allowed(&vs.db, probe, hinted, round.soft.as_deref(), vs.intensity) {
            continue;
        }
        // A socket (so a source port) per probe: a late reply to an earlier
        // probe cannot be read as the answer to this one.
        let Ok(sock) = crate::udp::connected_socket(addr).await else {
            break;
        };
        let mut data = Vec::new();
        for _ in 0..=cfg.retries {
            vs.trace(|| {
                format!(
                    "Service scan sending probe {} to {} (udp)",
                    probe.name,
                    endpoint(addr)
                )
            });
            pace(cfg.scan_delay).await;
            if sock.send(probe.payload()).await.is_err() {
                break 'probes;
            }
            match tokio::time::timeout(vs.wait, sock.recv(&mut buf)).await {
                Ok(Ok(n)) => {
                    round.answered = true;
                    data = buf[..n].to_vec();
                    break;
                }
                // ICMP port unreachable: the port has closed.
                Ok(Err(_)) => break 'probes,
                Err(_) => {}
            }
        }
        used.push(sock);
        take_reply(vs, &mut round, probe, addr, Protocol::Udp, false, data);
        if let Some(info) = round.hard {
            return Some(info);
        }
    }
    drop(used);
    finish(round, Protocol::Udp, addr.port(), vs)
}

/// Run version detection on every open TCP and UDP port of every host, and
/// on UDP ports left open|filtered (which become open if they answer),
/// filling in [`PortResult::service`](crate::PortResult::service).
pub async fn detect_services(hosts: &mut [HostResult], cfg: &ScanConfig, vs: &VersionScan) {
    let jobs: Vec<(usize, usize, SocketAddr, Option<String>, Protocol)> = hosts
        .iter()
        .enumerate()
        .flat_map(|(h, host)| {
            host.ports
                .iter()
                .enumerate()
                // No SCTP probes yet, and -sO "ports" are protocols. Like
                // nmap, UDP ports left open|filtered are probed too: an
                // answer shows they are open.
                .filter(|(_, p)| match p.protocol {
                    Protocol::Tcp => p.state == PortState::Open,
                    Protocol::Udp => matches!(p.state, PortState::Open | PortState::OpenFiltered),
                    Protocol::Sctp | Protocol::Ip => false,
                })
                .map(move |(i, p)| {
                    let addr = crate::target::socket_addr(host.addr, p.port);
                    (h, i, addr, host.hostname.clone(), p.protocol)
                })
        })
        .collect();
    let found: Vec<_> = stream::iter(jobs)
        .map(|(h, i, addr, hostname, protocol)| async move {
            let info = match protocol {
                Protocol::Tcp => detect_tcp(addr, hostname.as_deref(), cfg, vs).await,
                Protocol::Udp => detect_udp(addr, cfg, vs).await,
                Protocol::Sctp | Protocol::Ip => None,
            };
            (h, i, info)
        })
        .buffer_unordered(cfg.concurrency.max(1))
        .collect()
        .await;
    for (h, i, info) in found {
        let port = &mut hosts[h].ports[i];
        if info.is_some() && port.state == PortState::OpenFiltered {
            port.state = PortState::Open;
            port.reason = crate::model::reason::UDP_RESPONSE;
        }
        port.service = info;
    }
}

/// What `--dry-run` says about `-sV`: which probes would go to the open
/// ports among `tcp` and `udp`, in which order, at this intensity. The
/// probes themselves depend on which ports turn out open, so they are
/// described, not listed one by one.
pub fn dry_run_lines(vs: &VersionScan, tcp: &[u16], udp: &[u16]) -> Vec<String> {
    let db = &vs.db;
    let mut lines = vec![format!(
        "-sV (intensity {}, rules: {}) would connect to each open port the scan finds and try \
         these probes in order, stopping at the first rule that matches:",
        vs.intensity, db.source
    )];
    // The scan's own order is shuffled; describe the ports sorted.
    let (mut tcp, mut udp) = (tcp.to_vec(), udp.to_vec());
    tcp.sort_unstable();
    udp.sort_unstable();
    let (tcp, udp) = (&tcp[..], &udp[..]);
    // "http on 80, 8080; redis on 6379" for the scanned ports.
    let meant_for = |protocol: Protocol, ports: &[u16]| -> Vec<String> {
        db.probes
            .iter()
            .filter(|p| p.protocol == protocol && p.kind != ProbeKind::Tls)
            .filter_map(|p| {
                let mine: Vec<String> = ports
                    .iter()
                    .filter(|&&port| p.is_for(port))
                    .map(u16::to_string)
                    .collect();
                (!mine.is_empty()).then(|| format!("{} on {}", p.name, mine.join(", ")))
            })
            .collect()
    };
    let by_rarity = |protocol: Protocol| -> Vec<String> {
        let mut probes: Vec<&Probe> = db
            .probes
            .iter()
            .filter(|p| {
                p.protocol == protocol
                    && p.kind != ProbeKind::Tls
                    && !p.payload().is_empty()
                    && p.rarity <= vs.intensity
            })
            .collect();
        probes.sort_by_key(|p| p.rarity);
        probes.iter().map(|p| p.name.clone()).collect()
    };
    if !tcp.is_empty() {
        let mut steps = Vec::new();
        if let Some(t) = db.tls() {
            let first: Vec<String> = tcp
                .iter()
                .filter(|&&p| t.is_for(p))
                .map(u16::to_string)
                .collect();
            if !first.is_empty() {
                steps.push(format!(
                    "a TLS handshake first on {}, then the probes inside it",
                    first.join(", ")
                ));
            }
        }
        let hinted = meant_for(Protocol::Tcp, tcp);
        if !hinted.is_empty() {
            steps.push(format!(
                "the probes meant for the port ({})",
                hinted.join("; ")
            ));
        }
        let listens: Vec<String> = db
            .probes
            .iter()
            .filter(|p| {
                p.protocol == Protocol::Tcp && p.kind != ProbeKind::Tls && p.payload().is_empty()
            })
            .filter(|p| p.rarity <= vs.intensity)
            .map(|p| p.name.clone())
            .collect();
        if !listens.is_empty() {
            steps.push(format!("{} (connect and listen)", listens.join(", ")));
        }
        let rest = by_rarity(Protocol::Tcp);
        if !rest.is_empty() {
            steps.push(format!("then by rarity: {}", rest.join(", ")));
        }
        if db.tls().is_some_and(|t| t.rarity <= vs.intensity) {
            steps.push("a TLS handshake if the port stayed silent or answered with TLS".into());
        }
        lines.push(format!("  TCP: {}", steps.join("; ")));
    }
    if !udp.is_empty() {
        let mut steps = Vec::new();
        let hinted = meant_for(Protocol::Udp, udp);
        if !hinted.is_empty() {
            steps.push(format!(
                "the probes meant for the port ({})",
                hinted.join("; ")
            ));
        }
        let rest = by_rarity(Protocol::Udp);
        if !rest.is_empty() {
            steps.push(format!("then by rarity: {}", rest.join(", ")));
        }
        if steps.is_empty() {
            steps.push("no probes at this intensity".into());
        }
        lines.push(format!("  UDP: {}", steps.join("; ")));
    }
    lines
}

#[cfg(test)]
mod tests;
