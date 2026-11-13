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
use std::net::SocketAddr;
use std::time::Instant;

use futures::stream::{self, StreamExt};
use tokio::net::TcpStream;

use crate::model::{HostResult, PortResult, PortState, Protocol, ScanConfig, elapsed_ms, reason};
use crate::target::Target;
use crate::timing::pace;

/// Whether an error means the network gave no usable answer (the port is
/// filtered), as opposed to a local problem such as running out of file
/// descriptors or ephemeral ports, which must not be reported as a port state.
pub(crate) fn is_network_error(e: &io::Error) -> bool {
    // No support for the target's address family, e.g. IPv6 disabled here:
    // the target is unreachable from this machine, not a local fault.
    #[cfg(unix)]
    if e.raw_os_error() == Some(libc::EAFNOSUPPORT) {
        return true;
    }
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

/// Probe a single TCP port with a full connect.
///
/// Returns an error only for local failures (see [`is_network_error`]); every
/// answer, or lack of one, from the network becomes a [`PortResult`].
pub async fn probe_port(addr: SocketAddr, cfg: &ScanConfig) -> io::Result<PortResult> {
    let result = |state, reason, rtt_ms| PortResult {
        port: addr.port(),
        protocol: Protocol::Tcp,
        state,
        reason,
        rtt_ms,
        service: None,
    };
    for _ in 0..=cfg.retries {
        pace(cfg.scan_delay).await;
        let start = Instant::now();
        let outcome = tokio::time::timeout(cfg.timeout, TcpStream::connect(addr)).await;
        let rtt = Some(elapsed_ms(start));
        match outcome {
            Ok(Ok(_stream)) => return Ok(result(PortState::Open, reason::SYN_ACK, rtt)),
            Ok(Err(e)) if e.kind() == ErrorKind::ConnectionRefused => {
                return Ok(result(PortState::Closed, reason::CONN_REFUSED, rtt));
            }
            // The OS gave up waiting, just like our own timer below: retry.
            Ok(Err(e)) if e.kind() == ErrorKind::TimedOut => continue,
            // ICMP unreachable and similar: definitive, retrying won't help.
            Ok(Err(e)) if is_network_error(&e) => {
                return Ok(result(PortState::Filtered, reason::UNREACHABLE, None));
            }
            Ok(Err(e)) => return Err(io::Error::new(e.kind(), format!("connect to {addr}: {e}"))),
            // Timed out: maybe the packet was dropped, so retry.
            Err(_) => continue,
        }
    }
    Ok(result(PortState::Filtered, reason::NO_RESPONSE, None))
}

/// Scan every port on every target with a TCP connect scan.
///
/// Probes for all hosts are interleaved through one bounded pool, so a slow
/// or unresponsive host does not stall the others.
///
/// Stops at the first local error (for example "too many open files"), since
/// continuing would only produce wrong results; lower the concurrency then.
pub async fn connect_scan(
    targets: &[Target],
    ports: &[u16],
    cfg: &ScanConfig,
) -> io::Result<Vec<HostResult>> {
    let mut hosts: Vec<HostResult> = targets
        .iter()
        .map(|t| HostResult::new(t.addr, t.hostname.clone()))
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
        hosts[host_idx].ports.push(result?);
    }

    for host in &mut hosts {
        host.sort_ports();
    }
    Ok(hosts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
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
        let hosts = connect_scan(&[localhost()], &[open, closed], &cfg)
            .await
            .unwrap();

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
        let hosts = connect_scan(&[localhost()], &ports, &cfg).await.unwrap();
        let got: Vec<u16> = hosts[0].ports.iter().map(|p| p.port).collect();
        let mut want = ports.clone();
        want.sort_unstable();
        assert_eq!(got, want);
    }

    #[test]
    fn json_shape() {
        let r = PortResult {
            port: 22,
            protocol: Protocol::Tcp,
            state: PortState::Filtered,
            reason: reason::NO_RESPONSE,
            rtt_ms: None,
            service: None,
        };
        assert_eq!(
            serde_json::to_string(&r).unwrap(),
            r#"{"port":22,"protocol":"tcp","state":"filtered","reason":"no-response"}"#
        );
    }
}
