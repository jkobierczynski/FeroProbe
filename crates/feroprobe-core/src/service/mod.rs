//! Service and version detection, like nmap's `-sV`.
//!
//! For each open TCP port:
//!
//! 1. On usual TLS ports, try TLS first and probe the service inside.
//! 2. Send the probes meant for this port (HTTP on 80, Redis on 6379, ...).
//! 3. Connect and listen: SSH, FTP, SMTP and others talk first.
//! 4. If the service is still silent, try HTTP, then TLS.
//!
//! Each response is matched against the rules in [`rules`]. These probes and
//! rules are FeroProbe's own; nmap's database is not used.
//!
//! Open UDP ports get a protocol-specific query where we know one (DNS
//! `version.bind`, NTP, SNMP sysDescr, SSDP).

mod parsers;
mod rules;
mod tls;
mod udp_info;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use futures::stream::{self, StreamExt};
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::model::{HostResult, PortState, Protocol, ScanConfig};
use crate::ports::service_name;
use crate::timing::pace;
use rules::Probe;

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

/// Run one probe over a new plain TCP connection. `None` if the connection
/// failed, which means the port is no longer reachable.
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
    Some(exchange(&mut stream, probe.payload, wait).await)
}

/// Try TLS on `addr`, and if it works, identify the service inside.
async fn detect_tls(
    addr: SocketAddr,
    host: Option<&str>,
    cfg: &ScanConfig,
    wait: Duration,
) -> Option<ServiceInfo> {
    // Listen on ports whose service talks first, else send the probe meant
    // for this port (AMQP on 5671, ...), else HTTP.
    let port = addr.port();
    let mut probe = if rules::TLS_BANNER_PORTS.contains(&port) {
        &rules::NULL
    } else {
        rules::PROBES
            .iter()
            .find(|p| p.ports.contains(&port))
            .unwrap_or(&rules::HTTP)
    };
    pace(cfg.scan_delay).await;
    let (mut stream, cn) = tls::connect(addr, host, cfg.timeout, wait).await?;
    let mut data = exchange(&mut stream, probe.payload, wait).await;
    if data.is_empty() && probe.name != rules::HTTP.name {
        // No answer: try HTTP over a fresh session.
        pace(cfg.scan_delay).await;
        if let Some((mut stream, _)) = tls::connect(addr, host, cfg.timeout, wait).await {
            probe = &rules::HTTP;
            data = exchange(&mut stream, probe.payload, wait).await;
        }
    }
    let mut info = match rules::match_response(probe.name, &data) {
        Some(info) => info,
        None if data.is_empty() => ServiceInfo::named("unknown"),
        None => rules::unrecognized(&data, "unknown"),
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
    wait: Duration,
) -> Option<ServiceInfo> {
    let port = addr.port();
    let tls_first = rules::TLS_PORTS.contains(&port);
    if tls_first && let Some(info) = detect_tls(addr, host, cfg, wait).await {
        return Some(info);
    }

    // Probes meant for this port first, then listen, then HTTP.
    let hinted: Vec<&Probe> = rules::PROBES
        .iter()
        .filter(|p| p.ports.contains(&port))
        .collect();
    let mut generic = vec![&rules::NULL];
    if !hinted.iter().any(|p| p.name == rules::HTTP.name) {
        generic.push(&rules::HTTP);
    }

    // The first reply no rule recognized.
    let mut unknown: Option<Vec<u8>> = None;
    for (probe, is_hinted) in hinted
        .into_iter()
        .map(|p| (p, true))
        .chain(generic.into_iter().map(|p| (p, false)))
    {
        // A service that already answered has shown what it is; generic
        // probes would only repeat that.
        if !is_hinted && unknown.is_some() {
            break;
        }
        let data = plain_probe(addr, probe, cfg, wait).await?;
        if let Some(info) = rules::match_response(probe.name, &data) {
            return Some(info);
        }
        // A TLS alert in reply to plain text: the service wants TLS.
        if is_tls_record(&data)
            && !tls_first
            && let Some(info) = detect_tls(addr, host, cfg, wait).await
        {
            return Some(info);
        }
        if !data.is_empty() {
            unknown.get_or_insert(data);
        }
    }

    // Silent to everything: maybe a TLS service on an unusual port.
    if unknown.is_none() && !tls_first {
        return detect_tls(addr, host, cfg, wait).await;
    }
    let guess = service_name(Protocol::Tcp, port);
    unknown.map(|data| rules::unrecognized(&data, guess))
}

/// Identify the service on an open UDP port, for the few UDP services we
/// know how to ask.
pub async fn detect_udp(addr: SocketAddr, cfg: &ScanConfig, wait: Duration) -> Option<ServiceInfo> {
    let payload = udp_info::payload(addr.port())?;
    let sock = crate::udp::connected_socket(addr).await.ok()?;
    let mut buf = [0u8; 4096];
    for _ in 0..=cfg.retries {
        pace(cfg.scan_delay).await;
        sock.send(payload).await.ok()?;
        if let Ok(Ok(n)) = tokio::time::timeout(wait, sock.recv(&mut buf)).await {
            return udp_info::parse(addr.port(), &buf[..n]);
        }
    }
    None
}

/// Run version detection on every open port of every host, filling in
/// [`PortResult::service`](crate::PortResult::service). `wait` is how long
/// to wait for each reply.
pub async fn detect_services(hosts: &mut [HostResult], cfg: &ScanConfig, wait: Duration) {
    let jobs: Vec<(usize, usize, SocketAddr, Option<String>, Protocol)> = hosts
        .iter()
        .enumerate()
        .flat_map(|(h, host)| {
            host.ports
                .iter()
                .enumerate()
                .filter(|(_, p)| p.state == PortState::Open)
                .map(move |(i, p)| {
                    let addr = crate::target::socket_addr(host.addr, p.port);
                    (h, i, addr, host.hostname.clone(), p.protocol)
                })
        })
        .collect();
    let found: Vec<_> = stream::iter(jobs)
        .map(|(h, i, addr, hostname, protocol)| async move {
            let info = match protocol {
                Protocol::Tcp => detect_tcp(addr, hostname.as_deref(), cfg, wait).await,
                Protocol::Udp => detect_udp(addr, cfg, wait).await,
            };
            (h, i, info)
        })
        .buffer_unordered(cfg.concurrency.max(1))
        .collect()
        .await;
    for (h, i, info) in found {
        hosts[h].ports[i].service = info;
    }
}

#[cfg(test)]
mod tests;
