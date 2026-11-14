//! Helpers shared by the raw-socket techniques (SYN scan, ICMP discovery).

use std::io;
use std::net::SocketAddr;
#[cfg(target_os = "linux")]
use std::net::{IpAddr, UdpSocket};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};

/// Whether this process may open raw sockets (root, or `CAP_NET_RAW` on Linux).
pub fn raw_sockets_available() -> bool {
    Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP)).is_ok()
}

/// Whether this process may open raw IPv6 sockets: it has the privileges
/// and the system has IPv6.
pub fn raw_ipv6_available() -> bool {
    Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::TCP)).is_ok()
}

/// Open a raw IPv4 socket for `proto`, with a friendly error if not allowed.
#[cfg(target_os = "linux")]
pub(crate) fn raw_socket(proto: Protocol) -> io::Result<Socket> {
    raw_socket_in(Domain::IPV4, proto)
}

/// Open a raw socket of `domain` (IPv4 or IPv6) for `proto`.
#[cfg(target_os = "linux")]
pub(crate) fn raw_socket_in(domain: Domain, proto: Protocol) -> io::Result<Socket> {
    Socket::new(domain, Type::RAW, Some(proto)).map_err(|e| {
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
pub(crate) fn source_addr_for(dst: IpAddr) -> io::Result<IpAddr> {
    let sock = match dst {
        IpAddr::V4(_) => UdpSocket::bind("0.0.0.0:0")?,
        IpAddr::V6(_) => UdpSocket::bind("[::]:0")?,
    };
    sock.connect(crate::target::socket_addr(dst, 53))?;
    Ok(sock.local_addr()?.ip())
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

/// Ask each of `targets` a question, once per round and paced like every
/// other probe, and collect the answers: the shared loop of ARP and NDP.
///
/// `send` sends one request. `receive` runs on its own thread and returns
/// the next answer it reads, `Ok(None)` when its read timed out or the
/// packet was not an answer, or an error that ends the sweep. Rounds repeat
/// for unanswered targets up to `cfg.retries`; after each round, answers
/// are awaited for `cfg.timeout`. `on_reply` gets each target's first
/// answer and its round-trip time in ms. Stops early when `cancel` is set.
///
/// A receive error is returned even after a full sweep, since silence then
/// proves nothing; answers that came in before it have been passed on.
#[cfg(target_os = "linux")]
pub(crate) fn request_sweep<A, R>(
    targets: &[A],
    cfg: &crate::model::ScanConfig,
    cancel: &std::sync::atomic::AtomicBool,
    mut send: impl FnMut(A) -> io::Result<()>,
    mut receive: impl FnMut() -> io::Result<Option<(A, R)>> + Send + 'static,
    on_reply: &mut dyn FnMut(A, R, f64),
) -> io::Result<()>
where
    A: Copy + Eq + std::hash::Hash + Send + 'static,
    R: Send + 'static,
{
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::{self, RecvTimeoutError};

    if targets.is_empty() || cancel.load(Ordering::Relaxed) {
        return Ok(());
    }
    let wanted: HashSet<A> = targets.iter().copied().collect();
    let stop = Arc::new(AtomicBool::new(false));
    // Bounded, and only answers from targets we ask, so that a flood on the
    // link cannot grow it while the sender waits between probes. When it is
    // full an answer is dropped; the retry round asks that target again.
    let (tx, rx) = mpsc::sync_channel::<(A, R, Instant)>(wanted.len().clamp(64, 4096));
    let receiver = {
        let stop = Arc::clone(&stop);
        let wanted = wanted.clone();
        std::thread::spawn(move || -> io::Result<()> {
            while !stop.load(Ordering::Relaxed) {
                if let Some((a, r)) = receive()?
                    && wanted.contains(&a)
                    && let Err(mpsc::TrySendError::Disconnected(_)) =
                        tx.try_send((a, r, Instant::now()))
                {
                    break;
                }
            }
            Ok(())
        })
    };

    let mut sent_at: HashMap<A, Instant> = HashMap::new();
    let mut answered: HashSet<A> = HashSet::new();
    let mut record =
        |(a, r, at): (A, R, Instant), sent_at: &HashMap<A, Instant>, answered: &mut HashSet<A>| {
            // Only targets we asked, and only their first answer.
            let Some(&sent) = sent_at.get(&a) else {
                return;
            };
            if wanted.contains(&a) && answered.insert(a) {
                let rtt = (at.saturating_duration_since(sent).as_secs_f64() * 1e6).round() / 1000.0;
                on_reply(a, r, rtt);
            }
        };

    let mut pending: Vec<A> = targets.to_vec();
    let outcome = (|| -> io::Result<()> {
        for _ in 0..=cfg.retries {
            let mut pacer = Pacer::for_config(cfg);
            for &a in &pending {
                if !pacer.wait_or_cancel(cancel) {
                    return Ok(());
                }
                sent_at.insert(a, Instant::now());
                send(a)?;
                while let Ok(r) = rx.try_recv() {
                    record(r, &sent_at, &mut answered);
                }
            }
            let deadline = Instant::now() + cfg.timeout;
            while answered.len() < wanted.len()
                && !cancel.load(Ordering::Relaxed)
                && let Some(left) = deadline.checked_duration_since(Instant::now())
            {
                match rx.recv_timeout(left.min(crate::timing::CANCEL_POLL)) {
                    Ok(r) => record(r, &sent_at, &mut answered),
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => break,
                }
            }
            if cancel.load(Ordering::Relaxed) {
                return Ok(());
            }
            pending.retain(|a| !answered.contains(a));
            if pending.is_empty() {
                break;
            }
        }
        Ok(())
    })();

    stop.store(true, Ordering::Relaxed);
    let received = receiver
        .join()
        .unwrap_or_else(|_| Err(io::Error::other("receiver thread panicked")));
    // Answers still queued (e.g. when a send failed mid-round) count too.
    while let Ok(r) = rx.try_recv() {
        record(r, &sent_at, &mut answered);
    }
    outcome.and(received)
}

/// Whether a receive error only means "nothing yet": a read timeout or an
/// interrupted call.
#[cfg(target_os = "linux")]
pub(crate) fn is_idle_read(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

/// Send on a raw socket, waiting briefly when the kernel's send buffer is
/// full (ENOBUFS) instead of failing the whole scan. `to` is the target's
/// address with port 0, from [`crate::target::socket_addr`] so that a
/// link-local IPv6 target keeps its interface.
pub(crate) fn send_with_backoff(sock: &Socket, pkt: &[u8], to: SocketAddr) -> io::Result<()> {
    let addr = to.into();
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
