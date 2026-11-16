//! The run's verbosity (`-v`) and debugging level (`-d`), as nmap keeps
//! them in `o.verbose` and `o.debugging`: process-wide, and changeable
//! while the scan runs (the `v`/`V` and `d`/`D` keys), so every message
//! checks the level at the moment it would be printed.
//!
//! Messages go to standard error, like FeroProbe's other progress output,
//! so a report written to standard output (`-oX -`) stays clean.

use std::sync::atomic::{AtomicU8, Ordering};

/// The highest level of either, as in nmap.
pub const MAX_LEVEL: u8 = 10;

static VERBOSITY: AtomicU8 = AtomicU8::new(0);
static DEBUGGING: AtomicU8 = AtomicU8::new(0);

/// The current verbosity.
pub fn verbosity() -> u8 {
    VERBOSITY.load(Ordering::Relaxed)
}

/// Set the verbosity, capped at [`MAX_LEVEL`].
pub fn set_verbosity(level: u8) {
    VERBOSITY.store(level.min(MAX_LEVEL), Ordering::Relaxed);
}

/// The current debugging level.
pub fn debugging() -> u8 {
    DEBUGGING.load(Ordering::Relaxed)
}

/// Set the debugging level, capped at [`MAX_LEVEL`].
pub fn set_debugging(level: u8) {
    DEBUGGING.store(level.min(MAX_LEVEL), Ordering::Relaxed);
}

/// Print `msg` when the verbosity is at least `level`. The message is only
/// built when it is printed.
pub fn verbose(level: u8, msg: impl FnOnce() -> String) {
    if verbosity() >= level {
        eprintln!("{}", msg());
    }
}

/// Print `msg` when the debugging level is at least `level`.
pub fn debug(level: u8, msg: impl FnOnce() -> String) {
    if debugging() >= level {
        eprintln!("{}", msg());
    }
}
