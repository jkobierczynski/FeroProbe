//! FeroProbe core: a native Rust network scanning engine.
//!
//! The CLI in `feroprobe` is a thin layer over this crate, so the engine can
//! also be embedded in other tools.
//!
//! Scan techniques:
//! - [`connect_scan`]: TCP connect, no privileges needed
//! - [`syn_scan`]: TCP SYN over raw sockets (Linux, root or `CAP_NET_RAW`)
//! - [`udp_scan`]: UDP with service-specific payloads, no privileges needed
//! - [`discover`]: host discovery with ARP (local networks), ICMP echo and TCP probes
//!
//! [`detect_services`] then identifies the software on open ports, and
//! [`os_detect`] guesses each host's operating system.

pub mod arp;
pub mod connect;
pub mod discovery;
pub mod model;
pub mod ndp;
pub mod netif;
pub mod os;
pub mod oui;
pub mod packet;
pub mod ports;
pub mod raw;
pub mod service;
pub mod syn;
pub mod target;
pub mod timing;
pub mod udp;

pub use arp::{MacAddr, MacInfo};
pub use connect::connect_scan;
pub use discovery::{discover, icmp_available};
pub use model::{HostResult, PortResult, PortState, Protocol, ScanConfig};
pub use os::{OsMatch, TcpTraits, os_detect};
pub use ports::{parse_ports, service_name, top_ports, top_udp_ports};
pub use raw::{raw_ipv6_available, raw_sockets_available};
pub use service::{ServiceInfo, detect_services};
pub use syn::syn_scan;
pub use target::{
    IpVersion, Target, TargetSpec, parse_target, resolve_targets, resolve_targets_with, socket_addr,
};
pub use timing::Timing;
pub use udp::udp_scan;

/// Errors produced while preparing a scan.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid port specification: {0}")]
    InvalidPorts(String),
    #[error("invalid target: {0}")]
    InvalidTarget(String),
    #[error("could not resolve '{0}': {1}")]
    Resolve(String, String),
}

#[cfg(test)]
pub(crate) mod testutil {
    /// Whether this machine has IPv6 on its loopback interface. CI sets
    /// FEROPROBE_REQUIRE_IPV6=1 so the IPv6 tests cannot silently pass there.
    pub(crate) fn ipv6_loopback() -> bool {
        let ok = std::net::TcpListener::bind("[::1]:0").is_ok();
        if !ok {
            assert!(
                std::env::var_os("FEROPROBE_REQUIRE_IPV6").is_none(),
                "FEROPROBE_REQUIRE_IPV6 is set but ::1 is unavailable"
            );
            eprintln!("note: no IPv6 loopback, IPv6 test not run");
        }
        ok
    }
}
