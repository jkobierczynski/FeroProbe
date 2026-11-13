//! Result types and configuration shared by all scan techniques.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::os::OsMatch;
use crate::service::ServiceInfo;

/// Transport protocol of a scanned port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        })
    }
}

/// The state of a single scanned port, using nmap's vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub enum PortState {
    /// Something answered: a SYN-ACK, a completed handshake, or UDP data.
    #[serde(rename = "open")]
    Open,
    /// The host answered that nothing listens (TCP reset, ICMP port unreachable).
    #[serde(rename = "closed")]
    Closed,
    /// No answer, or an ICMP error that says a filter dropped the probe.
    #[serde(rename = "filtered")]
    Filtered,
    /// UDP only: no answer, which can mean open (silent service) or filtered.
    #[serde(rename = "open|filtered")]
    OpenFiltered,
}

impl std::fmt::Display for PortState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(match self {
            PortState::Open => "open",
            PortState::Closed => "closed",
            PortState::Filtered => "filtered",
            PortState::OpenFiltered => "open|filtered",
        })
    }
}

/// Why a port or host was given its state, like nmap's `--reason`.
pub mod reason {
    pub const SYN_ACK: &str = "syn-ack";
    pub const RESET: &str = "reset";
    pub const CONN_REFUSED: &str = "conn-refused";
    pub const NO_RESPONSE: &str = "no-response";
    pub const UNREACHABLE: &str = "unreachable";
    pub const PORT_UNREACH: &str = "port-unreach";
    pub const UDP_RESPONSE: &str = "udp-response";
    pub const ECHO_REPLY: &str = "echo-reply";
    pub const USER_SET: &str = "user-set";
}

/// Result for one port on one host.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PortResult {
    pub port: u16,
    pub protocol: Protocol,
    pub state: PortState,
    pub reason: &'static str,
    /// Time until the port answered. `None` when nothing answered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<f64>,
    /// What version detection (`-sV`) found, if it ran and learned anything.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<ServiceInfo>,
}

/// All results for one host, ports sorted by protocol then port.
#[derive(Debug, Clone, Serialize)]
pub struct HostResult {
    pub addr: IpAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// How host discovery decided the host is up, if discovery ran.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub up_reason: Option<&'static str>,
    /// Round-trip time of the discovery probe that answered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<f64>,
    pub ports: Vec<PortResult>,
    /// What OS detection (`-O`) guessed, if it ran and the host answered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<OsMatch>,
}

impl HostResult {
    pub fn new(addr: IpAddr, hostname: Option<String>) -> Self {
        Self {
            addr,
            hostname,
            up_reason: None,
            latency_ms: None,
            ports: Vec::new(),
            os: None,
        }
    }

    /// Whether the host is known to be up: discovery said so, or some port
    /// gave a definite answer.
    pub fn is_up(&self) -> bool {
        self.up_reason.is_some()
            || self
                .ports
                .iter()
                .any(|p| matches!(p.state, PortState::Open | PortState::Closed))
    }

    pub fn count(&self, state: PortState) -> usize {
        self.ports.iter().filter(|p| p.state == state).count()
    }

    pub fn sort_ports(&mut self) {
        self.ports.sort_by_key(|p| (p.protocol, p.port));
    }
}

/// Tunables shared by the scan techniques.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// How long to wait for an answer to each probe.
    pub timeout: Duration,
    /// Maximum number of connect/UDP probes in flight at once.
    pub concurrency: usize,
    /// Extra attempts for probes that got no answer.
    pub retries: u32,
    /// Maximum packets per second for raw-socket scans (SYN, ICMP).
    pub max_rate: u32,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            // Windows reports "connection refused" only ~2s after the reset.
            timeout: Duration::from_millis(if cfg!(windows) { 3000 } else { 1500 }),
            concurrency: 500,
            retries: 1,
            max_rate: 5000,
        }
    }
}

/// Milliseconds since `start`, rounded to microseconds.
pub(crate) fn elapsed_ms(start: Instant) -> f64 {
    (start.elapsed().as_secs_f64() * 1_000_000.0).round() / 1000.0
}
