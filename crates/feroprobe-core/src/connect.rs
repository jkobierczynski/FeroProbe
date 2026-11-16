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
use std::time::{Duration, Instant};

use futures::stream::{self, StreamExt};

use crate::model::{HostResult, PortResult, PortState, Protocol, ScanConfig, elapsed_ms, reason};
use crate::rtt::{AsyncWindow, Outcome};
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
///
/// Each try waits for the host's current adaptive timeout (see
/// [`crate::rtt`]), and every answer's round-trip time feeds that estimate.
pub async fn probe_port(addr: SocketAddr, cfg: &ScanConfig) -> io::Result<PortResult> {
    probe_port_in(addr, cfg, None).await
}

/// On Windows a refused connection is reported only about two seconds
/// after the reset arrives (the system retries the SYN first), so a connect
/// try never waits less than this there.
pub const WINDOWS_MIN_CONNECT_WAIT: Duration = Duration::from_millis(3000);

/// How long a connect try to `addr` may wait now.
pub(crate) fn connect_wait(addr: SocketAddr, cfg: &ScanConfig) -> Duration {
    let wait = cfg.probe_timeout(addr.ip());
    if cfg!(windows) {
        wait.max(WINDOWS_MIN_CONNECT_WAIT)
    } else {
        wait
    }
}

/// [`probe_port`] as one probe of a scan: each try takes a place in the
/// scan's congestion windows (host `h`) first.
pub(crate) async fn probe_port_in(
    addr: SocketAddr,
    cfg: &ScanConfig,
    window: Option<(&AsyncWindow, usize)>,
) -> io::Result<PortResult> {
    let result = probe_port_tries(addr, cfg, window).await;
    if let Some((w, h)) = window {
        w.settled(h);
    }
    result
}

async fn probe_port_tries(
    addr: SocketAddr,
    cfg: &ScanConfig,
    window: Option<(&AsyncWindow, usize)>,
) -> io::Result<PortResult> {
    let result = |state, reason, rtt_ms| PortResult {
        port: addr.port(),
        protocol: Protocol::Tcp,
        state,
        reason,
        rtt_ms,
        service: None,
    };
    for tryno in 0..=cfg.retries {
        // cfg.retries is a cap: resend only as often as the host's losses
        // call for (see rtt::Congestion::allowed_tryno).
        let allowed = window.map_or(cfg.first_retries(), |(w, h)| w.allowed_tryno(h));
        if tryno > allowed {
            break;
        }
        let slot = match window {
            Some((w, h)) => match w.acquire(h, tryno).await {
                Some(slot) => Some(slot),
                // The host needs no more probes (proven up in discovery).
                None => break,
            },
            None => None,
        };
        pace(cfg.scan_delay).await;
        let start = Instant::now();
        let outcome =
            tokio::time::timeout(connect_wait(addr, cfg), crate::netif::connect_tcp(addr)).await;
        let rtt = Some(elapsed_ms(start));
        // An answer (handshake or reset) times the round trip.
        let answered = match &outcome {
            Ok(Ok(_)) => true,
            Ok(Err(e)) => e.kind() == ErrorKind::ConnectionRefused,
            Err(_) => false,
        };
        if answered {
            cfg.observe_rtt(addr.ip(), start.elapsed());
        }
        if let Some(slot) = slot {
            let how = match &outcome {
                _ if answered => Outcome::Answered,
                Ok(Err(e)) if e.kind() != ErrorKind::TimedOut && is_network_error(e) => {
                    Outcome::FilteredError
                }
                _ => Outcome::TimedOut,
            };
            slot.finish(start, tryno, how);
        }
        crate::packet_trace::conn(
            addr,
            &match &outcome {
                Ok(Ok(_)) => "Connected".to_string(),
                // "Connection refused", without " (os error 111)".
                Ok(Err(e)) => {
                    let text = e.to_string();
                    text.split(" (os error").next().unwrap_or(&text).to_string()
                }
                Err(_) => "No answer within the timeout".to_string(),
            },
        );
        match outcome {
            Ok(Ok(stream)) => {
                // Close with a reset, not a FIN, as nmap's connect scan
                // does: a zero linger time makes the close abort.
                let _ = socket2::SockRef::from(&stream).set_linger(Some(Duration::ZERO));
                drop(stream);
                return Ok(result(PortState::Open, reason::SYN_ACK, rtt));
            }
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

/// How many files (sockets included) this process may have open at once,
/// where the system says: the soft `RLIMIT_NOFILE` on Unix. Connect and UDP
/// probes each hold a socket, so their parallelism must stay below this.
pub fn open_file_limit() -> Option<u64> {
    #[cfg(unix)]
    {
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit only writes to the struct we pass.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } == 0
            && lim.rlim_cur != libc::RLIM_INFINITY
        {
            // rlim_t is u64 on Linux and macOS but not on every Unix.
            #[allow(clippy::unnecessary_cast)]
            return Some(lim.rlim_cur as u64);
        }
        None
    }
    #[cfg(not(unix))]
    {
        None
    }
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

    // Congestion control, as in nmap: how many probes may wait for an
    // answer at once grows with the answers and shrinks on losses.
    let window = AsyncWindow::new(cfg, vec![ports.len(); targets.len()]);
    let window = &window;
    let mut results = stream::iter(jobs)
        .map(|(host_idx, port)| {
            let addr = crate::target::socket_addr(targets[host_idx].addr, port);
            async move {
                (
                    host_idx,
                    probe_port_in(addr, cfg, Some((window, host_idx))).await,
                )
            }
        })
        .buffer_unordered(cfg.concurrency.max(1));

    while let Some((host_idx, result)) = results.next().await {
        hosts[host_idx].ports.push(result?);
        crate::progress::tick(1);
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
            rtt: crate::rtt::RttTimeouts::fixed(Duration::from_secs(5)),
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
