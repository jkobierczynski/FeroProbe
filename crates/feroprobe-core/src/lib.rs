//! FeroProbe core: a native Rust network scanning engine.
//!
//! The CLI in `feroprobe` is a thin layer over this crate, so the engine can
//! also be embedded in other tools.

pub mod ports;
pub mod scan;
pub mod target;

pub use ports::{parse_ports, top_ports};
pub use scan::{HostResult, PortResult, PortState, ScanConfig, connect_scan};
pub use target::{Target, TargetSpec, parse_target, resolve_targets};

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
