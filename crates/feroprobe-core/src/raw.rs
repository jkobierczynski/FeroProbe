//! Helpers shared by the raw-socket techniques (SYN scan, ICMP discovery).

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};

/// Whether this process may open raw sockets (root, or `CAP_NET_RAW` on Linux).
pub fn raw_sockets_available() -> bool {
    Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP)).is_ok()
}

/// Open a raw IPv4 socket for `proto`, with a friendly error if not allowed.
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
pub(crate) struct Rng(u64);

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

/// Spaces out packets so that no more than `rate` are sent per second.
pub(crate) struct Pacer {
    start: Instant,
    sent: u64,
    rate: f64,
}

impl Pacer {
    pub(crate) fn new(rate: u32) -> Self {
        Self {
            start: Instant::now(),
            sent: 0,
            rate: f64::from(rate.max(1)),
        }
    }

    /// Call after each packet; sleeps if we are ahead of schedule.
    pub(crate) fn tick(&mut self) {
        self.sent += 1;
        let due = self.start + Duration::from_secs_f64(self.sent as f64 / self.rate);
        let now = Instant::now();
        if due > now {
            std::thread::sleep(due - now);
        }
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
            #[cfg(unix)]
            Err(e) if e.raw_os_error() == Some(libc::ENOBUFS) && attempts < 50 => {
                attempts += 1;
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(e),
        }
    }
}
