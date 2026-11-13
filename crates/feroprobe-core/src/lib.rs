//! FeroProbe core: a native Rust network scanning engine.
//!
//! The CLI in `feroprobe` is a thin layer over this crate, so the engine can
//! also be embedded in other tools.
//!
//! Scan techniques:
//! - [`connect_scan`]: TCP connect, no privileges needed
//! - [`syn_scan`]: TCP SYN over raw sockets (Linux, root or `CAP_NET_RAW`)
//! - [`udp_scan`]: UDP with service-specific payloads, no privileges needed
//! - [`discover`]: host discovery with ICMP echo and TCP probes

pub mod connect;
pub mod discovery;
pub mod model;
pub mod packet;
pub mod ports;
pub mod raw;
pub mod syn;
pub mod target;
pub mod udp;

pub use connect::connect_scan;
pub use discovery::{discover, icmp_available};
pub use model::{HostResult, PortResult, PortState, Protocol, ScanConfig};
pub use ports::{parse_ports, top_ports, top_udp_ports};
pub use raw::raw_sockets_available;
pub use syn::syn_scan;
pub use target::{Target, TargetSpec, parse_target, resolve_targets};
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
