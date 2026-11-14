//! A process-wide probe counter, for progress reports such as nmap's
//! `--stats-every`.
//!
//! The caller sets the number of probes a phase will send with [`reset`];
//! the scan techniques count each probe as it is settled with [`tick`]; and
//! [`snapshot`] reads both at any time, from any thread.

use std::sync::atomic::{AtomicU64, Ordering};

static DONE: AtomicU64 = AtomicU64::new(0);
static TOTAL: AtomicU64 = AtomicU64::new(0);

/// Start counting a new phase of `total` probes (0 when unknown).
pub fn reset(total: u64) {
    DONE.store(0, Ordering::Relaxed);
    TOTAL.store(total, Ordering::Relaxed);
}

/// Count `n` more probes as done.
pub(crate) fn tick(n: u64) {
    DONE.fetch_add(n, Ordering::Relaxed);
}

/// Probes done and the phase's total, as set by [`reset`]. `done` never
/// exceeds a non-zero `total`.
pub fn snapshot() -> (u64, u64) {
    let total = TOTAL.load(Ordering::Relaxed);
    let done = DONE.load(Ordering::Relaxed);
    (if total > 0 { done.min(total) } else { done }, total)
}
