//! TCP connect scanning.
//!
//! A connect scan completes the full TCP handshake using the operating
//! system's `connect()` call, so it needs no special privileges. Results are
//! classified the way nmap does:
//!
//! - **open**: the handshake completed
//! - **closed**: the host answered with a RST (connection refused)
//! - **filtered**: no answer before the timeout, or an ICMP unreachable error

use std::io::{self, ErrorKind};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use futures::stream::{self, StreamExt};
use serde::Serialize;
use tokio::net::TcpStream;

use crate::target::Target;

/// The state of a single scanned port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

impl std::fmt::Display for PortState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(match self {
            PortState::Open => "open",
            PortState::Closed => "closed",
            PortState::Filtered => "filtered",
        })
    }
}

/// Result for one port on one host.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PortResult {
    pub port: u16,
    pub state: PortState,
    /// Time until the port answered (open or closed). `None` when filtered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<f64>,
}

/// All results for one host, ports sorted ascending.
#[derive(Debug, Clone, Serialize)]
pub struct HostResult {
    pub addr: IpAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    pub ports: Vec<PortResult>,
}

impl HostResult {
    /// Whether any port answered, i.e. the host is known to be up.
    pub fn is_up(&self) -> bool {
        self.ports.iter().any(|p| p.state != PortState::Filtered)
    }

    pub fn count(&self, state: PortState) -> usize {
        self.ports.iter().filter(|p| p.state == state).count()
    }
}

/// Tunables for a connect scan.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// How long to wait for each connection attempt.
    pub timeout: Duration,
    /// Maximum number of connection attempts in flight at once.
    pub concurrency: usize,
    /// Extra attempts for ports that time out (a filtered port may just be a
    /// lost SYN).
    pub retries: u32,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(if cfg!(windows) { 3000 } else { 1500 }),
            concurrency: 500,
            retries: 1,
        }
    }
}

/// Whether a connect error means the network gave no usable answer (the port
/// is filtered), as opposed to a local problem such as running out of file
/// descriptors or ephemeral ports, which must not be reported as a port state.
fn is_network_error(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        ErrorKind::HostUnreachable
            | ErrorKind::NetworkUnreachable
            | ErrorKind::TimedOut
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            // A local firewall rule or a broadcast address (EACCES).
            | ErrorKind::PermissionDenied
    )
}

/// Probe a single TCP port.
///
/// Returns an error only for local failures (see [`is_network_error`]); every
/// answer, or lack of one, from the network becomes a [`PortResult`].
pub async fn probe_port(addr: SocketAddr, cfg: &ScanConfig) -> io::Result<PortResult> {
    let result = |state, rtt_ms| PortResult {
        port: addr.port(),
        state,
        rtt_ms,
    };
    for _ in 0..=cfg.retries {
        let start = Instant::now();
        let outcome = tokio::time::timeout(cfg.timeout, TcpStream::connect(addr)).await;
        let rtt = Some((start.elapsed().as_secs_f64() * 1_000_000.0).round() / 1000.0);
        match outcome {
            Ok(Ok(_stream)) => return Ok(result(PortState::Open, rtt)),
            Ok(Err(e)) if e.kind() == ErrorKind::ConnectionRefused => {
                return Ok(result(PortState::Closed, rtt));
            }
            // ICMP unreachable and similar: definitive, retrying won't help.
            Ok(Err(e)) if is_network_error(&e) => return Ok(result(PortState::Filtered, None)),
            Ok(Err(e)) => return Err(io::Error::new(e.kind(), format!("connect to {addr}: {e}"))),
            // Timed out: maybe the packet was dropped, so retry.
            Err(_) => continue,
        }
    }
    Ok(result(PortState::Filtered, None))
}

/// Scan every port on every target with a TCP connect scan.
///
/// Probes for all hosts are interleaved through one bounded pool, so a slow
/// or unresponsive host does not stall the others. `on_result` is called as
/// each probe finishes (for progress reporting).
///
/// Stops at the first local error (for example "too many open files"), since
/// continuing would only produce wrong results; lower the concurrency then.
pub async fn connect_scan(
    targets: &[Target],
    ports: &[u16],
    cfg: &ScanConfig,
    mut on_result: impl FnMut(usize, &PortResult),
) -> io::Result<Vec<HostResult>> {
    let mut hosts: Vec<HostResult> = targets
        .iter()
        .map(|t| HostResult {
            addr: t.addr,
            hostname: t.hostname.clone(),
            ports: Vec::new(),
        })
        .collect();

    // Iterate port-major so consecutive probes hit different hosts, which
    // spreads load instead of hammering one host at a time.
    let jobs = ports
        .iter()
        .flat_map(|&port| (0..targets.len()).map(move |host_idx| (host_idx, port)));

    let mut results = stream::iter(jobs)
        .map(|(host_idx, port)| {
            let addr = SocketAddr::new(targets[host_idx].addr, port);
            async move { (host_idx, probe_port(addr, cfg).await) }
        })
        .buffer_unordered(cfg.concurrency.max(1));

    while let Some((host_idx, result)) = results.next().await {
        let result = result?;
        on_result(host_idx, &result);
        hosts[host_idx].ports.push(result);
    }

    for host in &mut hosts {
        host.ports.sort_by_key(|p| p.port);
    }
    Ok(hosts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn localhost() -> Target {
        Target::new("127.0.0.1".parse().unwrap())
    }

    /// Bind a port, then drop the listener so we know it is now closed.
    async fn closed_port() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().port()
    }

    #[tokio::test]
    async fn detects_open_and_closed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open = listener.local_addr().unwrap().port();
        let closed = closed_port().await;

        // Windows retries a SYN that was answered with RST for about 2s before
        // reporting "connection refused", so the timeout must be longer than
        // that for a closed port to be seen as closed rather than filtered.
        let cfg = ScanConfig {
            timeout: Duration::from_secs(5),
            ..Default::default()
        };
        let mut seen = 0;
        let hosts = connect_scan(&[localhost()], &[open, closed], &cfg, |_, _| seen += 1)
            .await
            .unwrap();

        assert_eq!(seen, 2);
        assert_eq!(hosts.len(), 1);
        let host = &hosts[0];
        assert!(host.is_up());
        let state_of = |p| host.ports.iter().find(|r| r.port == p).unwrap().state;
        assert_eq!(state_of(open), PortState::Open);
        assert_eq!(state_of(closed), PortState::Closed);
        assert_eq!(host.count(PortState::Open), 1);
    }

    #[tokio::test]
    async fn results_are_sorted() {
        let cfg = ScanConfig::default();
        let mut ports = Vec::new();
        for _ in 0..5 {
            ports.push(closed_port().await);
        }
        ports.sort_unstable_by(|a, b| b.cmp(a));
        let hosts = connect_scan(&[localhost()], &ports, &cfg, |_, _| {})
            .await
            .unwrap();
        let got: Vec<u16> = hosts[0].ports.iter().map(|p| p.port).collect();
        let mut want = ports.clone();
        want.sort_unstable();
        assert_eq!(got, want);
    }

    #[test]
    fn json_shape() {
        let r = PortResult {
            port: 22,
            state: PortState::Filtered,
            rtt_ms: None,
        };
        assert_eq!(
            serde_json::to_string(&r).unwrap(),
            r#"{"port":22,"state":"filtered"}"#
        );
    }
}
