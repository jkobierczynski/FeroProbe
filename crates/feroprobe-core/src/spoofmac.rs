//! `--spoof-mac`: send IPv4 probes and ARP requests in Ethernet frames
//! from a made-up hardware address, as nmap does (it implies its
//! `--send-eth`).
//!
//! Sending: [`crate::raw::send_logged_until`] hands every IPv4 probe to
//! [`prepare`], which completes the IP header the kernel would have
//! written, finds the next hop (the target on the same network, else the
//! gateway) and its MAC address (the kernel's neighbour table, else an ARP
//! request from the spoofed address), and sends the frame on an
//! `AF_PACKET` socket.
//!
//! Receiving: answers addressed to the spoofed MAC reach this host as
//! "other host" frames, which the IP stack drops. For each interface used, a
//! relay thread asks the card to accept the spoofed address
//! (`PACKET_MR_UNICAST`, or promiscuous mode where that is refused) and
//! passes them to the IP stack through the loopback interface (completing
//! partial checksums), so every receiving socket sees
//! them as usual. TCP frames go with a checksum one off: raw sockets read
//! them before TCP checks it, and TCP then drops them instead of answering
//! each SYN-ACK with a reset from the real MAC address. Frames of a
//! connection a kernel socket holds (`-sV`'s, say) are left intact. A strict
//! reverse-path filter (`rp_filter=1`) drops the relayed frames, which
//! [`relay_warning`] reports.
//!
//! IPv6 probes, and probes to this host itself, keep the real address.
//! Linux only.

use std::sync::OnceLock;

use crate::arp::MacAddr;

static SPOOF: OnceLock<MacAddr> = OnceLock::new();

/// Send this run's Ethernet frames from `mac`. Call it once, before the
/// scan.
pub fn set(mac: MacAddr) {
    let _ = SPOOF.set(mac);
}

/// The spoofed MAC address, when `--spoof-mac` is given.
pub fn get() -> Option<MacAddr> {
    SPOOF.get().copied()
}

/// Parse a `--spoof-mac` argument as nmap does: `0` for a random address,
/// hex digits (with optional `:`, `-` or `.` separators, at most 12) for
/// an address or its first bytes with the rest random, or a vendor name,
/// whose prefix is used with three random bytes. Returns the address and
/// the vendor its prefix belongs to, if known.
pub fn parse(arg: &str, mut random: impl FnMut() -> u8) -> Result<MacAddr, String> {
    let arg = arg.trim();
    if arg.is_empty() {
        return Err("--spoof-mac needs an address, prefix, vendor name or 0".into());
    }
    let mut mac = [0u8; 6];
    for b in &mut mac {
        *b = random();
    }
    if arg == "0" {
        // nmap takes six random bytes as they come; a multicast source
        // address is not valid, so the group bit is cleared.
        mac[0] &= 0xfe;
        return Ok(MacAddr(mac));
    }
    let digits: String = arg
        .chars()
        .filter(|c| !matches!(c, ':' | '-' | '.'))
        .collect();
    if !digits.is_empty() && digits.chars().all(|c| c.is_ascii_hexdigit()) {
        if digits.len() > 12 || !digits.len().is_multiple_of(2) {
            return Err(format!(
                "--spoof-mac {arg}: give an even number of hex digits, at most 12"
            ));
        }
        for (i, pair) in digits.as_bytes().chunks(2).enumerate() {
            let s = std::str::from_utf8(pair).unwrap_or("00");
            mac[i] = u8::from_str_radix(s, 16).unwrap_or(0);
        }
        return Ok(MacAddr(mac));
    }
    let prefix = vendor_prefix(arg)
        .ok_or_else(|| format!("--spoof-mac {arg}: no vendor of that name is known"))?;
    mac[..3].copy_from_slice(&prefix);
    Ok(MacAddr(mac))
}

/// The prefix of a vendor named `name` (case does not matter): an exact
/// name first, then one containing it; the built-in table before the
/// installed IEEE list, and the lowest prefix of a vendor with several.
fn vendor_prefix(name: &str) -> Option<[u8; 3]> {
    let want = name.to_ascii_lowercase();
    let builtin = crate::arp::builtin_vendors();
    let db = crate::oui::global().prefixes24();
    let exact = |n: &str| n.to_ascii_lowercase() == want;
    let partial = |n: &str| n.to_ascii_lowercase().contains(&want);
    for test in [&exact as &dyn Fn(&str) -> bool, &partial] {
        if let Some((p, _)) = builtin.iter().find(|(_, n)| test(n)) {
            return Some(*p);
        }
        if let Some(p) = db.iter().filter(|(_, n)| test(n)).map(|(p, _)| *p).min() {
            return Some(p);
        }
    }
    None
}

#[cfg(target_os = "linux")]
pub use imp::relay_warning;
#[cfg(target_os = "linux")]
pub(crate) use imp::{listen_on, prepare, remember};

/// Not Linux: `--spoof-mac` is refused before the scan, so nothing is
/// ever sent this way.
#[cfg(not(target_os = "linux"))]
pub(crate) fn prepare(
    _: &socket2::Socket,
    _: &[u8],
    _: std::net::SocketAddr,
    _: Option<std::time::Instant>,
) -> Option<std::io::Result<Framed>> {
    None
}

/// Not Linux: no frame is ever prepared.
#[cfg(not(target_os = "linux"))]
pub(crate) enum Framed {}

#[cfg(not(target_os = "linux"))]
impl Framed {
    pub(crate) fn source(&self) -> MacAddr {
        match *self {}
    }
    pub(crate) fn send(&self) -> std::io::Result<()> {
        match *self {}
    }
}

/// Not Linux: there is nothing to warn about.
#[cfg(not(target_os = "linux"))]
pub fn relay_warning() -> Option<String> {
    None
}

#[cfg(target_os = "linux")]
mod imp {
    use std::collections::{HashMap, HashSet};
    use std::io;
    use std::mem;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};

    use socket2::Socket;

    use super::get;
    use crate::arp::{ETH_P_ARP, MacAddr, arp_request, parse_arp_reply};

    const ETH_P_IP: u16 = 0x0800;
    const ETH_P_IPV6: u16 = 0x86DD;

    #[derive(Default)]
    struct State {
        /// Next hop (interface index and address) to its MAC address.
        neighbours: HashMap<(u32, Ipv4Addr), MacAddr>,
        /// Interfaces with a relay running.
        relays: HashSet<u32>,
        /// Destinations already warned about (no Ethernet on the way).
        warned: HashSet<IpAddr>,
        /// Next hops that did not answer ARP, and when: not asked again
        /// until [`UNANSWERED_FOR`] has passed.
        unanswered: HashMap<(u32, Ipv4Addr), Instant>,
        /// One lock per next hop being resolved: others wait for its result
        /// instead of asking again, and other hops are not held up.
        resolving: HashMap<(u32, Ipv4Addr), std::sync::Arc<Mutex<()>>>,
    }

    /// At most this many next hops are remembered (answered or not); once
    /// full, the answered ones start over, which costs one more ARP request
    /// each, never a wrong address.
    const MAX_NEIGHBOURS: usize = 65_536;

    impl State {
        fn keep_neighbour(&mut self, key: (u32, Ipv4Addr), mac: MacAddr) {
            if self.neighbours.len() >= MAX_NEIGHBOURS && !self.neighbours.contains_key(&key) {
                self.neighbours.clear();
            }
            self.neighbours.insert(key, mac);
        }
    }

    fn state() -> &'static Mutex<State> {
        static STATE: OnceLock<Mutex<State>> = OnceLock::new();
        STATE.get_or_init(Mutex::default)
    }

    /// One socket for every frame sent.
    fn sender() -> io::Result<&'static OwnedFd> {
        static FD: OnceLock<OwnedFd> = OnceLock::new();
        if let Some(fd) = FD.get() {
            return Ok(fd);
        }
        let fd = packet_socket(0)?;
        Ok(FD.get_or_init(|| fd))
    }

    fn packet_socket(proto: u16) -> io::Result<OwnedFd> {
        // SAFETY: plain socket(2) call; the result is checked.
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, i32::from(proto.to_be())) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a fresh descriptor that we now own.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    fn sockaddr_ll(ifindex: u32, proto: u16) -> libc::sockaddr_ll {
        // SAFETY: sockaddr_ll is plain data; all-zero is a valid value.
        let mut sll: libc::sockaddr_ll = unsafe { mem::zeroed() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = proto.to_be();
        sll.sll_ifindex = ifindex as i32;
        sll
    }

    fn send_frame(fd: &OwnedFd, ifindex: u32, frame: &[u8]) -> io::Result<()> {
        let sll = sockaddr_ll(ifindex, 0);
        let mut attempts = 0;
        loop {
            // SAFETY: sends `frame` to a valid sockaddr_ll.
            let n = unsafe {
                libc::sendto(
                    fd.as_raw_fd(),
                    frame.as_ptr().cast(),
                    frame.len(),
                    0,
                    (&raw const sll).cast(),
                    mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
                )
            };
            if n >= 0 {
                return Ok(());
            }
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::ENOBUFS) && attempts < 50 {
                attempts += 1;
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            return Err(e);
        }
    }

    /// A probe ready to go out in an Ethernet frame from the spoofed
    /// address.
    pub(crate) struct Framed {
        ifindex: u32,
        frame: Vec<u8>,
    }

    impl Framed {
        /// The spoofed source address of the frame.
        pub(crate) fn source(&self) -> MacAddr {
            let mut m = [0u8; 6];
            m.copy_from_slice(&self.frame[6..12]);
            MacAddr(m)
        }

        pub(crate) fn send(&self) -> io::Result<()> {
            send_frame(sender()?, self.ifindex, &self.frame)
        }
    }

    /// The frame that sends `pkt`, written for raw socket `sock`, to `to`
    /// from the spoofed address. `None` when it should go the usual way: no
    /// `--spoof-mac`, IPv6, this host itself, or no Ethernet on the way (a
    /// warning is printed once per destination then). An error when it
    /// cannot go either way: the next hop does not answer ARP, the relay
    /// for its answers cannot start, or no Ethernet route leaves through
    /// the `-e` interface (the raw socket is not bound to it then).
    pub(crate) fn prepare(
        sock: &Socket,
        pkt: &[u8],
        to: SocketAddr,
        deadline: Option<Instant>,
    ) -> Option<io::Result<Framed>> {
        let mac = get()?;
        let IpAddr::V4(dst) = to.ip() else {
            return None;
        };
        // A source-routed probe goes to the route's first hop.
        let (opts, first) = wire_options(sock, dst);
        if is_local(first) {
            return None;
        }
        let (ifindex, hop) = match route(first) {
            Some(r) => r,
            None => {
                if let Some(ifc) = crate::netif::interface() {
                    return Some(Err(io::Error::other(format!(
                        "--spoof-mac: no Ethernet route to {first} through {} (-e)",
                        ifc.name
                    ))));
                }
                warn_once(to.ip(), "no Ethernet route to it");
                return None;
            }
        };
        Some((|| {
            let packet = full_packet(sock, pkt, first, &opts)?;
            listen_on(ifindex)?;
            let hop_mac = neighbour(ifindex, hop, mac, deadline)?;
            let mut frame = Vec::with_capacity(14 + packet.len());
            frame.extend_from_slice(&hop_mac.0);
            frame.extend_from_slice(&mac.0);
            frame.extend_from_slice(&ETH_P_IP.to_be_bytes());
            frame.extend_from_slice(&packet);
            Ok(Framed { ifindex, frame })
        })())
    }

    /// The connection an IPv4 TCP packet received belongs to: this host's
    /// address and port, then the sender's.
    type Flow = (Ipv4Addr, u16, Ipv4Addr, u16);

    pub(super) fn tcp_answer(ip: &[u8]) -> Option<Flow> {
        if ip.len() < 20 || ip[0] >> 4 != 4 || ip[9] != 6 {
            return None;
        }
        let ihl = usize::from(ip[0] & 0x0f) * 4;
        let tcp = ip.get(ihl..ihl + 4)?;
        let addr = |a: &[u8]| Ipv4Addr::new(a[0], a[1], a[2], a[3]);
        Some((
            addr(&ip[16..20]),
            u16::from_be_bytes([tcp[2], tcp[3]]),
            addr(&ip[12..16]),
            u16::from_be_bytes([tcp[0], tcp[1]]),
        ))
    }

    /// Whether a kernel TCP socket in `table` (`/proc/net/tcp`) holds the
    /// connection `flow`: a connect scan's or `-sV`'s, not a raw probe's.
    pub(super) fn kernel_holds(table: &str, flow: Flow) -> bool {
        let (local, lport, remote, rport) = flow;
        // Addresses as the kernel prints them: the 32-bit value in host
        // byte order, in hex; ports in hex.
        let hex = |a: Ipv4Addr, p: u16| format!("{:08X}:{p:04X}", u32::from_ne_bytes(a.octets()));
        let (want_local, want_remote) = (hex(local, lport), hex(remote, rport));
        table.lines().skip(1).any(|l| {
            let mut f = l.split_whitespace().skip(1);
            f.next() == Some(want_local.as_str()) && f.next() == Some(want_remote.as_str())
        })
    }

    /// This host's own address (or loopback): no frame needed.
    fn is_local(dst: Ipv4Addr) -> bool {
        dst.is_loopback()
            || crate::netif::route_source(IpAddr::V4(dst)).is_ok_and(|a| a == IpAddr::V4(dst))
    }

    fn warn_once(dst: IpAddr, why: &str) {
        let Ok(mut s) = state().lock() else { return };
        if s.warned.insert(dst) {
            eprintln!(
                "Warning: --spoof-mac is not honored for {dst} ({why}); its probes go from this host's own address"
            );
        }
    }

    /// The IPv4 options a probe from `sock` to `dst` carries on the wire
    /// (a source route rewritten as the kernel would) and the address it
    /// goes to.
    fn wire_options(sock: &Socket, dst: Ipv4Addr) -> (Vec<u8>, Ipv4Addr) {
        if crate::raw::socket_protocol(sock) == libc::IPPROTO_RAW as u8
            || crate::raw::ip_options_of(sock).is_empty()
        {
            return (Vec::new(), dst);
        }
        crate::packet_opts::get().ipv4_header_options(dst)
    }

    /// The whole IPv4 packet `sock` would send: `pkt` itself on an
    /// `IPPROTO_RAW` socket, else `pkt` behind the header the kernel would
    /// write (the socket's TTL and options, "don't fragment" clear, as
    /// [`crate::raw::nmap_ip_header`] asks for).
    fn full_packet(sock: &Socket, pkt: &[u8], dst: Ipv4Addr, opts: &[u8]) -> io::Result<Vec<u8>> {
        let proto = crate::raw::socket_protocol(sock);
        if proto == libc::IPPROTO_RAW as u8 {
            return Ok(pkt.to_vec());
        }
        let src = match sock.local_addr().ok().and_then(|a| a.as_socket()) {
            Some(SocketAddr::V4(a)) if !a.ip().is_unspecified() => *a.ip(),
            _ => match crate::netif::route_source(IpAddr::V4(dst))? {
                IpAddr::V4(a) => a,
                IpAddr::V6(_) => return Err(io::Error::other("no IPv4 source address")),
            },
        };
        let ttl = sock.ttl_v4().map_or(64, |t| t as u8);
        let id = crate::raw::Rng::new().next_u32() as u16;
        let proto = if proto == 0 {
            crate::packet::IPPROTO_ICMP
        } else {
            proto
        };
        Ok(crate::packet::ipv4_packet_with_options(
            src, dst, proto, ttl, id, opts, pkt,
        ))
    }

    /// The interface and next hop for `dst`, from the kernel's main routing
    /// table (the `-e` interface only, when given). `None` for
    /// interfaces without Ethernet.
    fn route(dst: Ipv4Addr) -> Option<(u32, Ipv4Addr)> {
        let table = std::fs::read_to_string("/proc/net/route").ok()?;
        let only = crate::netif::interface().map(|i| i.name.as_str());
        let (name, gw) = best_route(&table, dst, only)?;
        let ifindex = crate::netif::index_of(&name)?;
        if !crate::netif::ethernet_macs().contains_key(&ifindex) {
            return None;
        }
        Some((ifindex, if gw.is_unspecified() { dst } else { gw }))
    }

    /// The most specific usable route to `dst` in `/proc/net/route`
    /// (lowest metric among equals): its interface and gateway.
    pub(super) fn best_route(
        table: &str,
        dst: Ipv4Addr,
        only: Option<&str>,
    ) -> Option<(String, Ipv4Addr)> {
        // The kernel prints each address as the u32 its bytes form in memory.
        let hex = |s: &str| {
            u32::from_str_radix(s, 16)
                .ok()
                .map(|v| u32::from_be_bytes(v.to_ne_bytes()))
        };
        let dst = u32::from(dst);
        table
            .lines()
            .skip(1)
            .filter_map(|l| {
                let f: Vec<&str> = l.split_whitespace().collect();
                if f.len() < 8 {
                    return None;
                }
                let (net, gw, flags, metric, mask) = (
                    hex(f[1])?,
                    hex(f[2])?,
                    u32::from_str_radix(f[3], 16).ok()?,
                    f[6].parse::<u32>().ok()?,
                    hex(f[7])?,
                );
                let up = flags & 1 != 0;
                let reject = flags & 0x0200 != 0;
                (up && !reject && dst & mask == net & mask && only.is_none_or(|o| o == f[0])).then(
                    || {
                        (
                            mask.count_ones(),
                            metric,
                            f[0].to_string(),
                            Ipv4Addr::from(gw),
                        )
                    },
                )
            })
            .max_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)))
            .map(|(_, _, name, gw)| (name, gw))
    }

    /// Keep `mac` as the address of `ip` on `ifindex` (a target that
    /// answered ARP discovery), so probes to it need no ARP request of
    /// their own.
    pub(crate) fn remember(ifindex: u32, ip: Ipv4Addr, mac: MacAddr) {
        if get().is_some()
            && let Ok(mut s) = state().lock()
        {
            s.keep_neighbour((ifindex, ip), mac);
        }
    }

    /// The MAC address of `hop` on `ifindex`: cached, from the kernel's
    /// neighbour table, or asked for with ARP from the spoofed address.
    fn neighbour(
        ifindex: u32,
        hop: Ipv4Addr,
        mac: MacAddr,
        deadline: Option<Instant>,
    ) -> io::Result<MacAddr> {
        let key = (ifindex, hop);
        let unanswered = || {
            io::Error::new(
                io::ErrorKind::HostUnreachable,
                format!("--spoof-mac: no ARP answer from the next hop {hop}"),
            )
        };
        let cached = || -> Option<io::Result<MacAddr>> {
            let s = state().lock().ok()?;
            if let Some(m) = s.neighbours.get(&key) {
                return Some(Ok(*m));
            }
            s.unanswered
                .get(&key)
                .filter(|at| at.elapsed() < UNANSWERED_FOR)
                .map(|_| Err(unanswered()))
        };
        if let Some(r) = cached() {
            return r;
        }
        // Probes sent together from several threads to the same hop ask
        // once: the others wait here and take its result.
        let lock = state()
            .lock()
            .map_err(|_| io::Error::other("--spoof-mac: state lock poisoned"))?
            .resolving
            .entry(key)
            .or_default()
            .clone();
        let _one = lock.lock();
        if let Some(r) = cached() {
            return r;
        }
        let found = std::fs::read_to_string("/proc/net/arp")
            .ok()
            .and_then(|t| {
                kernel_neighbour(&t, hop, |dev| crate::netif::index_of(dev) == Some(ifindex))
            })
            .map_or_else(|| arp(ifindex, hop, mac, deadline), Ok);
        if let Ok(mut s) = state().lock() {
            match found {
                Ok(m) => {
                    s.keep_neighbour(key, m);
                    s.unanswered.remove(&key);
                }
                // No answer (not a local failure): taken as down a while.
                Err(ref e) if e.kind() == io::ErrorKind::HostUnreachable => {
                    if s.unanswered.len() >= MAX_NEIGHBOURS {
                        s.unanswered.retain(|_, at| at.elapsed() < UNANSWERED_FOR);
                    }
                    if s.unanswered.len() < MAX_NEIGHBOURS {
                        s.unanswered.insert(key, Instant::now());
                    }
                }
                Err(_) => {}
            }
            // Its result is cached now; waiters still hold the lock's Arc.
            s.resolving.remove(&key);
        }
        found
    }

    /// How long a next hop that did not answer ARP is taken as down.
    const UNANSWERED_FOR: Duration = Duration::from_secs(10);

    /// A complete entry for `ip` in `/proc/net/arp`, on a device that
    /// `on_device` accepts.
    pub(super) fn kernel_neighbour(
        table: &str,
        ip: Ipv4Addr,
        on_device: impl Fn(&str) -> bool,
    ) -> Option<MacAddr> {
        table.lines().skip(1).find_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 6 || f[0].parse::<Ipv4Addr>().ok()? != ip || !on_device(f[5]) {
                return None;
            }
            let flags = u32::from_str_radix(f[2].trim_start_matches("0x"), 16).ok()?;
            if flags & 0x2 == 0 {
                return None;
            }
            let mut mac = [0u8; 6];
            let mut parts = f[3].split(':');
            for b in &mut mac {
                *b = u8::from_str_radix(parts.next()?, 16).ok()?;
            }
            (mac != [0; 6]).then_some(MacAddr(mac))
        })
    }

    /// Ask for `hop`'s MAC address with ARP requests from the spoofed
    /// address (three tries, a second in all).
    /// Stops at `deadline` (the host timeout) with a `TimedOut` error,
    /// which is not remembered as an unanswered hop.
    fn arp(
        ifindex: u32,
        hop: Ipv4Addr,
        mac: MacAddr,
        deadline: Option<Instant>,
    ) -> io::Result<MacAddr> {
        let src = match crate::netif::route_source(IpAddr::V4(hop))? {
            IpAddr::V4(a) => a,
            IpAddr::V6(_) => return Err(io::Error::other("no IPv4 source address")),
        };
        let fd = packet_socket(ETH_P_ARP)?;
        let sll = sockaddr_ll(ifindex, ETH_P_ARP);
        // SAFETY: binds to a properly sized sockaddr_ll.
        unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&raw const sll).cast(),
                mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            );
        }
        set_timeout(&fd, Duration::from_millis(50));
        let request = arp_request(mac, src, hop);
        let mut buf = [0u8; 2048];
        let past_deadline = || deadline.is_some_and(|d| Instant::now() >= d);
        for _ in 0..3 {
            if past_deadline() {
                return Err(crate::model::ScanConfig::timed_out());
            }
            send_frame(&fd, ifindex, &request)?;
            crate::packet_trace::log("SENT", || {
                format!("ARP who-has {hop} tell {src} (from {mac})")
            });
            let mut until = Instant::now() + Duration::from_millis(333);
            if let Some(d) = deadline {
                until = until.min(d);
            }
            while Instant::now() < until {
                // SAFETY: reads into a buffer we own, of the given size.
                let n =
                    unsafe { libc::recv(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
                if n <= 0 {
                    continue;
                }
                if let Some((ip, m)) = parse_arp_reply(&buf[..n as usize])
                    && ip == hop
                {
                    crate::packet_trace::log("RCVD", || format!("ARP reply {ip} is-at {m}"));
                    return Ok(m);
                }
            }
        }
        if past_deadline() {
            return Err(crate::model::ScanConfig::timed_out());
        }
        Err(io::Error::new(
            io::ErrorKind::HostUnreachable,
            format!("--spoof-mac: no ARP answer from the next hop {hop}"),
        ))
    }

    fn set_timeout(fd: &OwnedFd, t: Duration) {
        let tv = libc::timeval {
            tv_sec: t.as_secs() as libc::time_t,
            tv_usec: t.subsec_micros() as libc::suseconds_t,
        };
        // SAFETY: sets a receive timeout from a valid timeval.
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&raw const tv).cast(),
                mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }
    }

    /// Make sure answers to the spoofed MAC on `ifindex` reach this host:
    /// start that interface's relay once. An error, and another try next
    /// time, when it cannot start. Does nothing without `--spoof-mac`.
    pub(crate) fn listen_on(ifindex: u32) -> io::Result<()> {
        let Some(mac) = get() else { return Ok(()) };
        let running = || state().lock().is_ok_and(|s| s.relays.contains(&ifindex));
        if running() {
            return Ok(());
        }
        // One start at a time: others wait until the relay is listening.
        static STARTING: Mutex<()> = Mutex::new(());
        let _one = STARTING.lock();
        if running() {
            return Ok(());
        }
        let fail = |e: io::Error| {
            io::Error::new(
                e.kind(),
                format!("--spoof-mac: cannot read answers to {mac}: {e}"),
            )
        };
        let fd = relay_socket(ifindex, mac).map_err(fail)?;
        let out = packet_socket(0).map_err(fail)?;
        let lo = crate::netif::index_of("lo").unwrap_or(1);
        std::thread::Builder::new()
            .name("spoof-mac relay".into())
            .spawn(move || relay(&fd, &out, mac, lo))
            .map_err(fail)?;
        // The socket is listening already, so nothing sent from here on is
        // missed.
        if let Ok(mut s) = state().lock() {
            s.relays.insert(ifindex);
        }
        Ok(())
    }

    /// An `AF_PACKET` socket on `ifindex` with the card told to accept
    /// frames to `mac` (or everything, where it refuses that).
    fn relay_socket(ifindex: u32, mac: MacAddr) -> io::Result<OwnedFd> {
        let fd = packet_socket(libc::ETH_P_ALL as u16)?;
        let sll = sockaddr_ll(ifindex, libc::ETH_P_ALL as u16);
        // SAFETY: binds to a properly sized sockaddr_ll.
        if unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&raw const sll).cast(),
                mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let member = |kind: i32| {
            // SAFETY: packet_mreq is plain data; all-zero is valid.
            let mut mr: libc::packet_mreq = unsafe { mem::zeroed() };
            mr.mr_ifindex = ifindex as i32;
            mr.mr_type = kind as u16;
            mr.mr_alen = 6;
            mr.mr_address[..6].copy_from_slice(&mac.0);
            // SAFETY: setsockopt with a correctly sized packet_mreq.
            unsafe {
                libc::setsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_PACKET,
                    libc::PACKET_ADD_MEMBERSHIP,
                    (&raw const mr).cast(),
                    mem::size_of::<libc::packet_mreq>() as libc::socklen_t,
                )
            }
        };
        if member(libc::PACKET_MR_UNICAST) != 0 && member(libc::PACKET_MR_PROMISC) != 0 {
            return Err(io::Error::last_os_error());
        }
        // Ask for each frame's status, to learn which still carry a
        // partial checksum (a veth peer or checksum offload on this host).
        let on: libc::c_int = 1;
        // SAFETY: setsockopt with a correctly sized int.
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_PACKET,
                libc::PACKET_AUXDATA,
                (&raw const on).cast(),
                mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
        set_timeout(&fd, Duration::from_millis(200));
        Ok(fd)
    }

    /// Pass IP frames for `mac` that the stack would drop to it through
    /// the loopback interface. Runs for the rest of the process.
    fn relay(fd: &OwnedFd, out: &OwnedFd, mac: MacAddr, lo: u32) {
        let mut buf = vec![0u8; 65536];
        loop {
            // SAFETY: sockaddr_ll is plain data; all-zero is a valid value.
            let mut from: libc::sockaddr_ll = unsafe { mem::zeroed() };
            let mut control = [0u64; 8];
            let mut iov = libc::iovec {
                iov_base: buf.as_mut_ptr().cast(),
                iov_len: buf.len(),
            };
            // SAFETY: msghdr is plain data; all-zero is a valid value.
            let mut msg: libc::msghdr = unsafe { mem::zeroed() };
            msg.msg_name = (&raw mut from).cast();
            msg.msg_namelen = mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
            msg.msg_iov = &raw mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = mem::size_of_val(&control) as _;
            // SAFETY: every pointer in `msg` points at a live buffer of the
            // size given.
            let n = unsafe { libc::recvmsg(fd.as_raw_fd(), &raw mut msg, 0) };
            if n < 14 {
                continue;
            }
            let frame = &mut buf[..n as usize];
            let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
            if from.sll_pkttype != libc::PACKET_OTHERHOST
                || frame[..6] != mac.0
                || (ethertype != ETH_P_IP && ethertype != ETH_P_IPV6)
            {
                continue;
            }
            if ethertype == ETH_P_IP {
                // A frame from a veth peer (or with checksum offload) may
                // hold only a partial TCP/UDP checksum, which the stack would
                // reject once the frame comes back in through `lo`: complete
                // it.
                if csum_not_ready(&msg) {
                    complete_checksum(&mut frame[14..]);
                }
                // TCP answers to raw probes are for FeroProbe's raw sockets
                // alone, which see them before TCP checks the checksum. Given
                // a valid one, TCP would answer each SYN-ACK with a reset
                // from this host's real MAC address, as nmap's pcap-read
                // answers never draw. Only a connection of the kernel's own
                // (-sV, say, once the target has learnt the spoofed address)
                // gets its packets intact.
                if let Some(flow) = tcp_answer(&frame[14..])
                    && !std::fs::read_to_string("/proc/net/tcp")
                        .is_ok_and(|t| kernel_holds(&t, flow))
                {
                    complete_checksum(&mut frame[14..]);
                    spoil_tcp_checksum(&mut frame[14..]);
                }
            }
            frame[..12].fill(0);
            let _ = send_frame(out, lo, frame);
        }
    }

    /// Whether the kernel marked the received frame's transport checksum
    /// as not yet filled in (`TP_STATUS_CSUMNOTREADY` in its auxdata).
    fn csum_not_ready(msg: &libc::msghdr) -> bool {
        // SAFETY: walks the control messages recvmsg filled into `msg`.
        let mut c = unsafe { libc::CMSG_FIRSTHDR(msg) };
        while !c.is_null() {
            // SAFETY: `c` is a valid control message header from the kernel.
            let h = unsafe { &*c };
            if h.cmsg_level == libc::SOL_PACKET && h.cmsg_type == libc::PACKET_AUXDATA {
                // SAFETY: a PACKET_AUXDATA message carries a tpacket_auxdata.
                let aux: libc::tpacket_auxdata =
                    unsafe { std::ptr::read_unaligned(libc::CMSG_DATA(c).cast()) };
                return aux.tp_status & libc::TP_STATUS_CSUMNOTREADY != 0;
            }
            // SAFETY: as above.
            c = unsafe { libc::CMSG_NXTHDR(msg, c) };
        }
        false
    }

    /// Make the (valid) TCP checksum of an IPv4 packet wrong by one, so the
    /// stack's TCP drops the packet after the raw sockets have read it.
    pub(super) fn spoil_tcp_checksum(ip: &mut [u8]) {
        let ihl = usize::from(ip[0] & 0x0f) * 4;
        if let Some(b) = ip.get_mut(ihl + 17) {
            // One off is never the other zero (0x0000 vs 0xffff).
            *b ^= 1;
        }
    }

    /// Recompute the TCP or UDP checksum of an IPv4 packet in place.
    pub(super) fn complete_checksum(ip: &mut [u8]) {
        let Some(&v) = ip.first() else { return };
        let ihl = usize::from(v & 0x0f) * 4;
        if v >> 4 != 4 || ip.len() < ihl || ihl < 20 {
            return;
        }
        let total = usize::from(u16::from_be_bytes([ip[2], ip[3]])).min(ip.len());
        let (proto, at) = match ip[9] {
            6 => (6u8, 16),
            17 => (17u8, 6),
            _ => return,
        };
        if total < ihl + at + 2 {
            return;
        }
        let src = IpAddr::V4(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]));
        let dst = IpAddr::V4(Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]));
        let seg = &mut ip[ihl..total];
        seg[at..at + 2].fill(0);
        let mut sum = crate::packet::checksum_with(
            crate::packet::pseudo_header_sum(src, dst, proto, seg.len()),
            seg,
        );
        if proto == 17 && sum == 0 {
            sum = 0xffff;
        }
        seg[at..at + 2].copy_from_slice(&sum.to_be_bytes());
    }

    /// Why answers to the spoofed MAC may not be seen, if they may not: a
    /// strict reverse-path filter drops what the relay hands over.
    pub fn relay_warning() -> Option<String> {
        let read = |n: &str| {
            std::fs::read_to_string(format!("/proc/sys/net/ipv4/conf/{n}/rp_filter"))
                .ok()
                .and_then(|s| s.trim().parse::<u8>().ok())
                .unwrap_or(0)
        };
        (read("all").max(read("lo")) == 1).then(|| {
            "--spoof-mac: the strict reverse-path filter (net.ipv4.conf.all/lo.rp_filter=1) \
             drops answers sent to the spoofed address; only answers to this host's own \
             address will be seen (rp_filter=2 or 0 lets them through)"
                .to_string()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counter() -> impl FnMut() -> u8 {
        let mut n = 0u8;
        move || {
            n = n.wrapping_add(0x11);
            n
        }
    }

    #[test]
    fn parses_nmap_forms() {
        assert_eq!(
            parse("00:11:22:33:44:55", counter()).unwrap(),
            MacAddr([0, 0x11, 0x22, 0x33, 0x44, 0x55])
        );
        assert_eq!(
            parse("001122334455", counter()).unwrap(),
            MacAddr([0, 0x11, 0x22, 0x33, 0x44, 0x55])
        );
        // A prefix keeps the random rest.
        assert_eq!(
            parse("0A-0B", counter()).unwrap(),
            MacAddr([0x0a, 0x0b, 0x33, 0x44, 0x55, 0x66])
        );
        // 0: random, but unicast.
        let m = parse("0", || 0xff).unwrap();
        assert_eq!(m.0[0], 0xfe);
        assert_eq!(&m.0[1..], &[0xff; 5]);
        // A vendor name, from the built-in table, any case.
        assert_eq!(
            parse("virtualbox", counter()).unwrap().oui(),
            [0x08, 0x00, 0x27]
        );
        assert_eq!(
            parse("Raspberry Pi", counter()).unwrap().oui(),
            [0x28, 0xCD, 0xC1]
        );
        assert!(parse("0011223", counter()).is_err());
        assert!(parse("00112233445566", counter()).is_err());
        assert!(parse("no such maker zz", counter()).is_err());
        assert!(parse("", counter()).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn picks_the_most_specific_route() {
        let table = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n\
eth1\t0000000A\t00000000\t0001\t0\t0\t0\t000000FF\t0\t0\t0\n";
        let r = |d: &str, only| imp::best_route(table, d.parse().unwrap(), only);
        assert_eq!(
            r("192.168.1.7", None),
            Some(("eth0".into(), Ipv4Addr::UNSPECIFIED))
        );
        assert_eq!(
            r("8.8.8.8", None),
            Some(("eth0".into(), "192.168.1.1".parse().unwrap()))
        );
        assert_eq!(
            r("10.1.2.3", None),
            Some(("eth1".into(), Ipv4Addr::UNSPECIFIED))
        );
        assert_eq!(
            r("10.1.2.3", Some("eth0")),
            Some(("eth0".into(), "192.168.1.1".parse().unwrap()))
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reads_complete_kernel_neighbours() {
        let t = "IP address       HW type     Flags       HW address            Mask     Device\n\
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:01     *        eth0\n\
192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        eth0\n\
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:02     *        eth2\n";
        assert_eq!(
            imp::kernel_neighbour(t, "192.168.1.1".parse().unwrap(), |d| d == "eth0"),
            Some(MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 1]))
        );
        // The same address on another link is another host.
        assert_eq!(
            imp::kernel_neighbour(t, "192.168.1.1".parse().unwrap(), |d| d == "eth2"),
            Some(MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 2]))
        );
        assert_eq!(
            imp::kernel_neighbour(t, "192.168.1.1".parse().unwrap(), |d| d == "eth1"),
            None
        );
        assert_eq!(
            imp::kernel_neighbour(t, "192.168.1.9".parse().unwrap(), |_| true),
            None
        );
    }

    #[cfg(target_os = "linux")]
    use std::net::Ipv4Addr;

    #[cfg(target_os = "linux")]
    #[test]
    fn partial_checksums_are_completed() {
        use std::net::{IpAddr, Ipv4Addr};
        let (a, b) = (Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 1));
        let good = crate::packet::udp_packet(IpAddr::V4(a), IpAddr::V4(b), 53, 4000, b"hi");
        let mut ip = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0];
        ip.extend_from_slice(&a.octets());
        ip.extend_from_slice(&b.octets());
        ip.extend_from_slice(&good);
        let len = ip.len() as u16;
        ip[2..4].copy_from_slice(&len.to_be_bytes());
        let mut partial = ip.clone();
        partial[26..28].copy_from_slice(&[0x12, 0x34]);
        imp::complete_checksum(&mut partial);
        assert_eq!(partial, ip);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_connections_are_told_from_raw_answers() {
        use std::net::IpAddr;
        let (us, them) = (Ipv4Addr::new(10, 66, 1, 1), Ipv4Addr::new(10, 66, 1, 2));
        let tcp = crate::packet::tcp_syn(IpAddr::V4(them), IpAddr::V4(us), 80, 40000, 1);
        let answer = crate::packet::ipv4_packet_with_options(them, us, 6, 64, 1, &[], &tcp);
        let flow = imp::tcp_answer(&answer).unwrap();
        assert_eq!(flow, (us, 40000, them, 80));
        let mut udp = answer.clone();
        udp[9] = 17;
        assert_eq!(imp::tcp_answer(&udp), None);
        // 10.66.1.1:40000 <-> 10.66.1.2:80, as a little-endian kernel prints it.
        let held = "  sl  local_address rem_address   st tx_queue rx_queue\n   \
   0: 0101420A:9C40 0201420A:0050 01 00000000:00000000\n";
        let listening = "  sl  local_address rem_address   st\n   \
   0: 00000000:9C40 00000000:0000 0A 00000000:00000000\n";
        if cfg!(target_endian = "little") {
            assert!(imp::kernel_holds(held, flow));
        }
        assert!(!imp::kernel_holds(listening, flow));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn spoiled_tcp_checksum_is_always_wrong() {
        for sum in [0x0000u16, 0xffff, 0x1234] {
            let mut ip = vec![0u8; 40];
            ip[0] = 0x45;
            ip[36..38].copy_from_slice(&sum.to_be_bytes());
            imp::spoil_tcp_checksum(&mut ip);
            let got = u16::from_be_bytes([ip[36], ip[37]]);
            assert_eq!(got ^ sum, 1);
            assert!(got != 0xffff - sum);
        }
    }
}
