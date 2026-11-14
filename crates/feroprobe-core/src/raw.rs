//! Helpers shared by the raw-socket techniques (SYN scan, ICMP discovery).

use std::io;
#[cfg(target_os = "linux")]
use std::net::UdpSocket;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};

/// Whether this process may open raw sockets (root, or `CAP_NET_RAW` on Linux).
pub fn raw_sockets_available() -> bool {
    Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP)).is_ok()
}

/// Open a raw IPv4 socket for `proto`, with a friendly error if not allowed.
#[cfg(target_os = "linux")]
pub(crate) fn raw_socket(proto: Protocol) -> io::Result<Socket> {
    Socket::new(Domain::IPV4, Type::RAW, Some(proto)).map_err(|e| {
        if e.kind() == io::ErrorKind::PermissionDenied {
            io::Error::new(
                e.kind(),
                "raw sockets need root (or CAP_NET_RAW); run with sudo or use a connect scan (-sT)",
            )
        } else {
            e
        }
    })
}

/// The local address the OS would use to reach `dst`, found by "connecting" a
/// UDP socket (which sends nothing).
#[cfg(target_os = "linux")]
pub(crate) fn source_addr_for(dst: Ipv4Addr) -> io::Result<Ipv4Addr> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.connect(SocketAddrV4::new(dst, 53))?;
    match sock.local_addr()?.ip() {
        std::net::IpAddr::V4(a) => Ok(a),
        std::net::IpAddr::V6(_) => Err(io::Error::other("no IPv4 route to target")),
    }
}

/// A small xorshift generator seeded from the clock and process id. Good
/// enough to pick source ports and sequence cookies; not cryptographic.
#[cfg(target_os = "linux")]
pub(crate) struct Rng(u64);

#[cfg(target_os = "linux")]
impl Rng {
    pub(crate) fn new() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        Self((nanos ^ (u64::from(std::process::id()) << 32)) | 1)
    }

    pub(crate) fn next_u32(&mut self) -> u32 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        (x >> 32) as u32
    }
}

/// Spaces out packets so that no more than `rate` are sent per second, and
/// none closer than the scan delay to any other probe of this process (see
/// [`crate::timing::pace_blocking_or_cancel`]).
pub(crate) struct Pacer {
    start: Instant,
    sent: u32,
    interval: Duration,
    delay: Duration,
}

impl Pacer {
    pub(crate) fn new(rate: u32, delay: Duration) -> Self {
        Self {
            start: Instant::now(),
            sent: 0,
            interval: Duration::from_secs_f64(1.0 / f64::from(rate.max(1))),
            delay,
        }
    }

    pub(crate) fn for_config(cfg: &crate::model::ScanConfig) -> Self {
        Self::new(cfg.max_rate, cfg.scan_delay)
    }

    /// Call before each packet; sleeps until it may go. The first packet
    /// goes at once, and nothing waits after the last one.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn wait(&mut self) {
        self.wait_or_cancel(&std::sync::atomic::AtomicBool::new(false));
    }

    /// Like [`wait`](Self::wait), but stops waiting as soon as `cancel` is
    /// set. Returns whether the packet may be sent; `false` means cancelled.
    pub(crate) fn wait_or_cancel(&mut self, cancel: &std::sync::atomic::AtomicBool) -> bool {
        use std::sync::atomic::Ordering;
        let due = self.start + self.interval.saturating_mul(self.sent);
        loop {
            if cancel.load(Ordering::Relaxed) {
                return false;
            }
            let now = Instant::now();
            if due <= now {
                break;
            }
            std::thread::sleep((due - now).min(crate::timing::CANCEL_POLL));
        }
        self.sent = self.sent.saturating_add(1);
        crate::timing::pace_blocking_or_cancel(self.delay, cancel)
    }
}

/// Send on a raw socket, waiting briefly when the kernel's send buffer is
/// full (ENOBUFS) instead of failing the whole scan.
pub(crate) fn send_with_backoff(sock: &Socket, pkt: &[u8], to: Ipv4Addr) -> io::Result<()> {
    let addr = SocketAddrV4::new(to, 0).into();
    let mut attempts = 0;
    loop {
        match sock.send_to(pkt, &addr) {
            Ok(_) => return Ok(()),
            Err(e) if is_no_buffer_space(&e) && attempts < 50 => {
                attempts += 1;
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(e),
        }
    }
}

fn is_no_buffer_space(e: &io::Error) -> bool {
    #[cfg(unix)]
    return e.raw_os_error() == Some(libc::ENOBUFS);
    #[cfg(not(unix))]
    return {
        let _ = e;
        false
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn cancel_cuts_a_wait_short() {
        // One packet a second, so the second one would wait a full second.
        let mut pacer = Pacer::new(1, Duration::ZERO);
        let cancel = AtomicBool::new(false);
        assert!(pacer.wait_or_cancel(&cancel));
        let t = Instant::now();
        std::thread::scope(|s| {
            s.spawn(|| {
                std::thread::sleep(Duration::from_millis(150));
                cancel.store(true, Ordering::Relaxed);
            });
            assert!(!pacer.wait_or_cancel(&cancel));
        });
        assert!(
            t.elapsed() < Duration::from_millis(600),
            "{:?}",
            t.elapsed()
        );
    }
}
