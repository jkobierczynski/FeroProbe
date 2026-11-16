//! Result types and configuration shared by all scan techniques.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::arp::MacInfo;
use crate::os::OsMatch;
use crate::service::ServiceInfo;
use crate::trace::Trace;

/// Transport protocol of a scanned port. [`Protocol::Ip`] is the IP
/// protocol scan (`-sO`), whose "ports" are IP protocol numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Sctp,
    Ip,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Sctp => "sctp",
            Protocol::Ip => "ip",
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
    /// No answer where an open port would stay silent too: UDP, and the
    /// FIN, NULL, Xmas and Maimon scans.
    #[serde(rename = "open|filtered")]
    OpenFiltered,
    /// ACK scan: the port answered with a reset, so no filter blocks it,
    /// but whether it is open is unknown.
    #[serde(rename = "unfiltered")]
    Unfiltered,
    /// Idle scan: the zombie's IP ID did not move, so the port is closed
    /// or a filter dropped the probe.
    #[serde(rename = "closed|filtered")]
    ClosedFiltered,
}

impl std::fmt::Display for PortState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(match self {
            PortState::Open => "open",
            PortState::Closed => "closed",
            PortState::Filtered => "filtered",
            PortState::OpenFiltered => "open|filtered",
            PortState::Unfiltered => "unfiltered",
            PortState::ClosedFiltered => "closed|filtered",
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
    /// ICMP errors from a router or the host for raw TCP probes.
    pub const NET_UNREACH: &str = "net-unreach";
    pub const HOST_UNREACH: &str = "host-unreach";
    pub const PROTO_UNREACH: &str = "proto-unreach";
    pub const ADMIN_PROHIBITED: &str = "admin-prohibited";
    pub const UDP_RESPONSE: &str = "udp-response";
    pub const ECHO_REPLY: &str = "echo-reply";
    pub const TIMESTAMP_REPLY: &str = "timestamp-reply";
    pub const MASK_REPLY: &str = "addressmask-reply";
    pub const ARP_RESPONSE: &str = "arp-response";
    /// The host answered an IPv6 neighbour solicitation.
    pub const ND_RESPONSE: &str = "nd-response";
    pub const USER_SET: &str = "user-set";
    /// The target is this machine (its traffic stays on the loopback
    /// interface), so nmap marks it up without probing it.
    pub const LOCALHOST: &str = "localhost-response";
    /// ICMP time exceeded: the probe died on the way.
    pub const TIME_EXCEEDED: &str = "time-exceeded";
    /// SCTP: the port answered an INIT with an INIT-ACK.
    pub const INIT_ACK: &str = "init-ack";
    /// SCTP: the port answered with an ABORT.
    pub const ABORT: &str = "abort";
    /// IP protocol scan: the host answered in the protocol probed.
    pub const PROTO_RESPONSE: &str = "proto-response";
    /// ICMPv6 parameter problem, which -sO reads like an unreachable.
    pub const PARAM_PROBLEM: &str = "param-problem";
    /// Idle scan: the zombie's IP ID moved, or did not.
    pub const IPID_CHANGE: &str = "ipid-change";
    pub const NO_IPID_CHANGE: &str = "no-ipid-change";
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
    /// The name a reverse DNS (PTR) lookup of the address returned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rdns: Option<String>,
    /// How host discovery decided the host is up, if discovery ran.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub up_reason: Option<&'static str>,
    /// Round-trip time of the discovery probe that answered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<f64>,
    /// The host's MAC address, when ARP discovery found it on a local network.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<MacInfo>,
    pub ports: Vec<PortResult>,
    /// What OS detection (`-O`) guessed, if it ran and the host answered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<OsMatch>,
    /// The route to the host, if `--traceroute` ran.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace: Option<Trace>,
    /// The scan of this host was cut short by `--host-timeout`: its port
    /// and OS results were dropped.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub timed_out: bool,
}

impl HostResult {
    pub fn new(addr: IpAddr, hostname: Option<String>) -> Self {
        Self {
            addr,
            hostname,
            rdns: None,
            up_reason: None,
            latency_ms: None,
            mac: None,
            ports: Vec::new(),
            os: None,
            trace: None,
            timed_out: false,
        }
    }

    /// Whether the host is known to be up: discovery said so, or some port
    /// gave a definite answer.
    pub fn is_up(&self) -> bool {
        self.up_reason.is_some()
            || self.ports.iter().any(|p| {
                matches!(
                    p.state,
                    PortState::Open | PortState::Closed | PortState::Unfiltered
                )
            })
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
    /// The limits on how long a probe waits for its answer (nmap's
    /// `--min-rtt-timeout`, `--max-rtt-timeout`, `--initial-rtt-timeout`).
    /// Within them, each host's timeout follows its measured round-trip
    /// times; see [`crate::rtt`].
    pub rtt: crate::rtt::RttTimeouts,
    /// The run's round-trip time estimates, shared by clones.
    pub rtt_state: crate::rtt::RttState,
    /// The timing template's number, 0 to 5, which tunes how fast the
    /// congestion window grows and how far a loss cuts it, as in nmap.
    pub timing_level: u8,
    /// `--min-rate`: probes per second to keep up, even past a full
    /// congestion window. Zero means none.
    pub min_rate: u32,
    /// `--min-parallelism`: the congestion windows never shrink below this
    /// many probes, as in nmap. Zero or one means the usual floor of one.
    pub min_parallelism: usize,
    /// Maximum number of probes waiting for an answer at once; caps the
    /// congestion window.
    pub concurrency: usize,
    /// The most times a probe without an answer is sent again (nmap's
    /// `--max-retries`). Like nmap, a host's probes are resent once until
    /// one of its resent probes draws an answer, which shows packets are
    /// being lost: then they may be resent one time more than the highest
    /// try that was answered, up to this cap. See
    /// [`ScanConfig::first_retries`].
    pub retries: u32,
    /// Maximum packets per second for raw-socket scans (SYN, ICMP).
    pub max_rate: u32,
    /// Minimum time between probes (nmap's `--scan-delay`), whatever the
    /// parallelism. Zero means no extra spacing.
    pub scan_delay: Duration,
    /// How far the scan may raise a host's delay between probes on its
    /// own when many of them are lost (nmap's `--max-scan-delay`, for
    /// TCP, SCTP and IP protocol probes). Never below `scan_delay`.
    pub max_scan_delay: Duration,
    /// The same for UDP probes: the templates leave it at a second, as
    /// nmap does, because UDP answers are so often rate-limited.
    pub max_udp_scan_delay: Duration,
    /// During host discovery, decide targets on a local Ethernet network by
    /// ARP (when privileged on Linux) instead of ICMP and TCP probes.
    pub arp_ping: bool,
    /// When to give up (nmap's `--host-timeout`): the scan techniques stop
    /// sending and return an error of kind [`std::io::ErrorKind::TimedOut`]
    /// once it has passed. `None` means no limit.
    pub deadline: Option<Instant>,
    /// A `max_rate` budget shared with other scans. `None` gives each scan
    /// its own budget.
    pub rate_schedule: Option<crate::timing::RateSchedule>,
    /// Evasion options (fragmentation, decoys, spoofed source) for the raw
    /// IPv4 TCP scans. Only used when every target is private; the
    /// command-line layer enforces that. Inactive by default.
    pub evasion: crate::evasion::Evasion,
    /// nmap's `-g`: the source port of raw TCP, UDP and SCTP probes (port
    /// scan, discovery pings, OS detection) and of UDP scan probes. `None`
    /// picks a random port. Connect scans, version detection, traceroute
    /// and DNS keep their own ports, as in nmap.
    pub source_port: Option<u16>,
}

impl ScanConfig {
    /// How long a probe to `addr` waits for its answer now, from the
    /// host's measured round-trip times (see [`crate::rtt`]).
    pub fn probe_timeout(&self, addr: std::net::IpAddr) -> Duration {
        self.rtt_state.timeout(addr, &self.rtt, self.scan_delay)
    }

    /// How many times a probe is resent before any loss is seen: one, or
    /// none with `--max-retries 0`. This is what nmap's adaptive retries
    /// come to on a network that loses nothing, and what the probes that
    /// do not adapt (DNS, OS detection, traceroute, ARP, ICMP discovery)
    /// use.
    pub fn first_retries(&self) -> u32 {
        self.retries.min(1)
    }

    /// Record a round-trip time measured to `addr`.
    pub fn observe_rtt(&self, addr: std::net::IpAddr, rtt: Duration) {
        self.rtt_state
            .observe(addr, rtt, &self.rtt, self.scan_delay);
    }

    /// Whether the [`deadline`](Self::deadline) has passed.
    pub fn expired(&self) -> bool {
        self.deadline.is_some_and(|d| Instant::now() >= d)
    }

    /// An error for a scan cut short by the deadline.
    // Only the raw-socket scans, which are Linux only, stop at the deadline.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn timed_out() -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::TimedOut, "host timeout")
    }
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            rtt: crate::rtt::RttTimeouts::default(),
            rtt_state: crate::rtt::RttState::new(),
            timing_level: 3,
            min_rate: 0,
            min_parallelism: 0,
            concurrency: 500,
            retries: 10,
            max_rate: 5000,
            scan_delay: Duration::ZERO,
            max_scan_delay: Duration::from_secs(1),
            max_udp_scan_delay: Duration::from_secs(1),
            arp_ping: true,
            deadline: None,
            rate_schedule: None,
            evasion: crate::evasion::Evasion::default(),
            source_port: None,
        }
    }
}

/// Milliseconds since `start`, rounded to microseconds.
pub(crate) fn elapsed_ms(start: Instant) -> f64 {
    (start.elapsed().as_secs_f64() * 1_000_000.0).round() / 1000.0
}
