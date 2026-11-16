//! nmap's runtime interaction: while a scan runs, keys typed on the
//! terminal change the verbosity (`v`/`V`), the debugging level (`d`/`D`)
//! and the packet trace (`p`/`P`), `?` lists the keys, and any other key
//! prints a status line.
//!
//! As in nmap, the keys are read from the controlling terminal
//! (`/dev/tty`), not from standard input, so `-iL -` still works; only
//! while FeroProbe is the terminal's foreground job, so a scan started
//! with `&` neither reads keys nor gets stopped for trying; and with the
//! terminal's line editing and echo off, which is put back when the scan
//! ends, when FeroProbe exits, and on Ctrl-C (SIGINT), SIGTERM, SIGQUIT and
//! SIGHUP. `--noninteractive` turns all of this off. Unix only for now.

use std::time::Instant;

use feroprobe_core::debug::{self, MAX_LEVEL};

/// The `?` key's text.
// Only read from a terminal on Unix for now.
#[cfg_attr(not(unix), allow(dead_code))]
const HELP: &str = "Interactive keyboard commands:
?               Display this information
v/V             Increase/decrease verbosity
d/D             Increase/decrease debugging
p/P             Enable/disable packet tracing
anything else   Print status
More help: see \"Runtime interaction\" in the FeroProbe manual";

/// What one key does: changes a level or the packet trace, and returns
/// the line to print.
// Only read from a terminal on Unix for now.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn handle_key(key: u8, started: Instant) -> String {
    let up = |l: u8| (l + 1).min(MAX_LEVEL);
    match key {
        b'v' => {
            debug::set_verbosity(up(debug::verbosity()));
            format!("Verbosity Increased to {}.", debug::verbosity())
        }
        b'V' => {
            debug::set_verbosity(debug::verbosity().saturating_sub(1));
            format!("Verbosity Decreased to {}.", debug::verbosity())
        }
        b'd' => {
            debug::set_debugging(up(debug::debugging()));
            format!("Debugging Increased to {}.", debug::debugging())
        }
        b'D' => {
            debug::set_debugging(debug::debugging().saturating_sub(1));
            format!("Debugging Decreased to {}.", debug::debugging())
        }
        b'p' => {
            feroprobe_core::packet_trace::enable();
            "Packet Tracing enabled.".to_string()
        }
        b'P' => {
            feroprobe_core::packet_trace::disable();
            "Packet Tracing disabled.".to_string()
        }
        b'?' => HELP.to_string(),
        _ => crate::stats_line(started.elapsed()),
    }
}

/// Reads keys until dropped, then puts the terminal back.
// Only read from a terminal on Unix for now.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) struct Keys {
    #[cfg(unix)]
    _inner: unix::Reader,
}

impl Keys {
    /// Stop reading keys and put the terminal back.
    pub(crate) fn stop(self) {}
}

/// Start reading keys, if there is a terminal and FeroProbe is its
/// foreground job. `None` otherwise.
pub(crate) fn start(started: Instant) -> Option<Keys> {
    #[cfg(unix)]
    {
        unix::Reader::start(started).map(|r| Keys { _inner: r })
    }
    #[cfg(not(unix))]
    {
        let _ = started;
        None
    }
}

#[cfg(unix)]
mod unix {
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
    use std::time::Instant;

    /// The terminal and its settings before the scan changed them.
    static TTY: AtomicI32 = AtomicI32::new(-1);
    static SAVED: OnceLock<libc::termios> = OnceLock::new();
    static STOP: AtomicBool = AtomicBool::new(false);

    /// Put the terminal's settings back. Async-signal-safe: only
    /// tcsetattr on a saved copy.
    fn restore() {
        let fd = TTY.load(Ordering::SeqCst);
        if let (true, Some(saved)) = (fd >= 0, SAVED.get()) {
            // SAFETY: tcsetattr on our own descriptor with a valid termios.
            unsafe { libc::tcsetattr(fd, libc::TCSANOW, saved) };
        }
    }

    extern "C" fn restore_at_exit() {
        restore();
    }

    /// Put the terminal back, then die of the signal as if unhandled.
    extern "C" fn restore_and_reraise(sig: libc::c_int) {
        restore();
        // SAFETY: signal and raise are async-signal-safe.
        unsafe {
            libc::signal(sig, libc::SIG_DFL);
            libc::raise(sig);
        }
    }

    fn foreground(fd: i32) -> bool {
        // SAFETY: plain queries on our own descriptor.
        unsafe { libc::tcgetpgrp(fd) == libc::getpgrp() }
    }

    pub(super) struct Reader;

    impl Reader {
        pub(super) fn start(started: Instant) -> Option<Self> {
            // SAFETY: open with a NUL-terminated path.
            let fd = unsafe {
                libc::open(
                    c"/dev/tty".as_ptr(),
                    libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return None;
            }
            // SAFETY: termios is plain data; tcgetattr fills it.
            let mut ti: libc::termios = unsafe { std::mem::zeroed() };
            if !foreground(fd) || unsafe { libc::tcgetattr(fd, &mut ti) } != 0 {
                // SAFETY: closes the descriptor opened above.
                unsafe { libc::close(fd) };
                return None;
            }
            if SAVED.set(ti).is_err() {
                // Started once already in this process.
                unsafe { libc::close(fd) };
                return None;
            }
            TTY.store(fd, Ordering::SeqCst);
            // SAFETY: registering plain extern "C" functions.
            unsafe {
                libc::atexit(restore_at_exit);
                for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGQUIT, libc::SIGHUP] {
                    libc::signal(
                        sig,
                        restore_and_reraise as extern "C" fn(libc::c_int) as *const ()
                            as libc::sighandler_t,
                    );
                }
            }
            ti.c_lflag &= !(libc::ICANON | libc::ECHO);
            ti.c_cc[libc::VMIN] = 1;
            ti.c_cc[libc::VTIME] = 0;
            // SAFETY: tcsetattr on our descriptor with a valid termios.
            unsafe { libc::tcsetattr(fd, libc::TCSANOW, &ti) };
            std::thread::Builder::new()
                .name("keys".into())
                .spawn(move || read_keys(fd, started))
                .ok()?;
            Some(Reader)
        }
    }

    impl Drop for Reader {
        fn drop(&mut self) {
            STOP.store(true, Ordering::SeqCst);
            restore();
        }
    }

    fn read_keys(fd: i32, started: Instant) {
        while !STOP.load(Ordering::SeqCst) {
            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: poll on one valid pollfd.
            let ready = unsafe { libc::poll(&mut pfd, 1, 200) };
            // Only the foreground job may read the terminal; anyone else
            // would be stopped by SIGTTIN.
            if ready <= 0 || STOP.load(Ordering::SeqCst) || !foreground(fd) {
                if ready > 0 {
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
                continue;
            }
            let mut key = 0u8;
            // SAFETY: reads one byte into `key`.
            let n = unsafe { libc::read(fd, (&mut key as *mut u8).cast(), 1) };
            if n == 0 {
                // The terminal went away.
                return;
            }
            if n < 0 {
                continue;
            }
            // Like nmap, one key per press: drop whatever else is queued.
            // SAFETY: tcflush on our descriptor.
            unsafe { libc::tcflush(fd, libc::TCIFLUSH) };
            eprintln!("{}", super::handle_key(key, started));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // One test, as the levels are process-wide.
    #[test]
    fn keys_do_what_nmaps_do() {
        let t = Instant::now();
        debug::set_verbosity(0);
        debug::set_debugging(0);
        assert_eq!(handle_key(b'v', t), "Verbosity Increased to 1.");
        assert_eq!(handle_key(b'v', t), "Verbosity Increased to 2.");
        assert_eq!(handle_key(b'V', t), "Verbosity Decreased to 1.");
        assert_eq!(handle_key(b'V', t), "Verbosity Decreased to 0.");
        assert_eq!(handle_key(b'V', t), "Verbosity Decreased to 0.");
        assert_eq!(handle_key(b'd', t), "Debugging Increased to 1.");
        assert_eq!(handle_key(b'D', t), "Debugging Decreased to 0.");
        for _ in 0..12 {
            handle_key(b'd', t);
        }
        assert_eq!(debug::debugging(), MAX_LEVEL);
        debug::set_debugging(0);
        assert_eq!(handle_key(b'p', t), "Packet Tracing enabled.");
        assert!(feroprobe_core::packet_trace::enabled());
        assert_eq!(handle_key(b'P', t), "Packet Tracing disabled.");
        assert!(!feroprobe_core::packet_trace::enabled());
        assert!(handle_key(b'?', t).starts_with("Interactive keyboard commands:"));
        assert!(handle_key(b' ', t).starts_with("Stats: 0:00:0"));
        assert!(handle_key(b'\n', t).starts_with("Stats: "));
    }
}
