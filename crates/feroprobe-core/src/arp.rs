//! ARP host discovery for targets on a directly connected IPv4 network.
//!
//! Hosts on the local Ethernet segment must answer ARP to be reachable at
//! all, so an ARP request is both faster and more reliable than a ping: a
//! host that drops every ICMP and TCP probe still answers it. The reply also
//! carries the host's MAC address, from which [`vendor`] guesses the maker of
//! its network card. Like nmap, targets on a local network are decided by ARP
//! alone; everything else goes through the usual ICMP and TCP probes.
//!
//! Frames are built by hand and sent on an `AF_PACKET` socket, so this needs
//! Linux and root (or `CAP_NET_RAW`). Without them, discovery silently falls
//! back to the other probes.

use std::fmt;
use std::net::Ipv4Addr;

use serde::{Serialize, Serializer};

/// A 48-bit Ethernet hardware address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const BROADCAST: MacAddr = MacAddr([0xff; 6]);

    /// The first three bytes, which the IEEE assigns to a manufacturer.
    pub fn oui(&self) -> [u8; 3] {
        [self.0[0], self.0[1], self.0[2]]
    }

    /// Set by the device or its software rather than burnt in by the maker:
    /// virtual machines, containers and phones with MAC randomisation.
    pub fn is_locally_administered(&self) -> bool {
        self.0[0] & 0x02 != 0
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        )
    }
}

impl Serialize for MacAddr {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

/// A host's MAC address, learnt from its ARP reply, and the vendor guess.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MacInfo {
    pub addr: MacAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<&'static str>,
}

impl MacInfo {
    pub fn new(addr: MacAddr) -> Self {
        Self {
            addr,
            vendor: vendor(addr),
        }
    }
}

/// Our own small table of well-known OUI prefixes (public IEEE assignments),
/// biased towards what turns up on lab and home networks.
const VENDORS: &[([u8; 3], &str)] = &[
    ([0x00, 0x00, 0x0C], "Cisco Systems"),
    ([0x00, 0x03, 0x93], "Apple"),
    ([0x00, 0x04, 0x4B], "NVIDIA"),
    ([0x00, 0x05, 0x69], "VMware"),
    ([0x00, 0x09, 0x0F], "Fortinet"),
    ([0x00, 0x0C, 0x29], "VMware"),
    ([0x00, 0x0C, 0x42], "MikroTik (Routerboard.com)"),
    ([0x00, 0x0D, 0xB9], "PC Engines"),
    ([0x00, 0x11, 0x32], "Synology"),
    ([0x00, 0x14, 0x22], "Dell"),
    ([0x00, 0x15, 0x5D], "Microsoft (Hyper-V)"),
    ([0x00, 0x16, 0x3E], "Xen"),
    ([0x00, 0x17, 0x88], "Philips Lighting (Hue)"),
    ([0x00, 0x1A, 0x11], "Google"),
    ([0x00, 0x1B, 0x17], "Palo Alto Networks"),
    ([0x00, 0x1B, 0x21], "Intel"),
    ([0x00, 0x1C, 0x14], "VMware"),
    ([0x00, 0x1C, 0x42], "Parallels"),
    ([0x00, 0x25, 0x90], "Super Micro Computer"),
    ([0x00, 0x50, 0x56], "VMware"),
    ([0x00, 0xE0, 0x4C], "Realtek"),
    ([0x08, 0x00, 0x27], "Oracle VirtualBox"),
    ([0x18, 0xFE, 0x34], "Espressif"),
    ([0x24, 0x0A, 0xC4], "Espressif"),
    ([0x24, 0xA4, 0x3C], "Ubiquiti"),
    ([0x28, 0xCD, 0xC1], "Raspberry Pi"),
    ([0x30, 0xAE, 0xA4], "Espressif"),
    ([0x48, 0x8F, 0x5A], "MikroTik (Routerboard.com)"),
    ([0x4C, 0x5E, 0x0C], "MikroTik (Routerboard.com)"),
    ([0x50, 0xC7, 0xBF], "TP-Link"),
    ([0x52, 0x54, 0x00], "QEMU/KVM virtual NIC"),
    ([0x6C, 0x3B, 0x6B], "MikroTik (Routerboard.com)"),
    ([0x78, 0x8A, 0x20], "Ubiquiti"),
    ([0xA4, 0xCF, 0x12], "Espressif"),
    ([0xB8, 0x27, 0xEB], "Raspberry Pi"),
    ([0xCC, 0x2D, 0xE0], "MikroTik (Routerboard.com)"),
    ([0xD4, 0xCA, 0x6D], "MikroTik (Routerboard.com)"),
    ([0xD8, 0x3A, 0xDD], "Raspberry Pi"),
    ([0xDC, 0xA6, 0x32], "Raspberry Pi"),
    ([0xE4, 0x5F, 0x01], "Raspberry Pi"),
    ([0xE4, 0x8D, 0x8C], "MikroTik (Routerboard.com)"),
    ([0xF0, 0x9F, 0xC2], "Ubiquiti"),
    ([0xFC, 0xEC, 0xDA], "Ubiquiti"),
];

/// Guess who made the network card with this address.
pub fn vendor(mac: MacAddr) -> Option<&'static str> {
    let oui = mac.oui();
    VENDORS
        .binary_search_by(|(p, _)| p.cmp(&oui))
        .ok()
        .map(|i| VENDORS[i].1)
        .or_else(|| {
            mac.is_locally_administered()
                .then_some("Locally administered")
        })
}

pub const ETH_P_ARP: u16 = 0x0806;
const ETH_P_IPV4: u16 = 0x0800;
const ARP_REQUEST: u16 = 1;
const ARP_REPLY: u16 = 2;
/// Ethernet header (14) + ARP for IPv4 over Ethernet (28), before padding.
pub const ARP_FRAME_LEN: usize = 42;

/// An Ethernet frame holding a broadcast ARP "who has `target`?" request.
pub fn arp_request(src_mac: MacAddr, src_ip: Ipv4Addr, target: Ipv4Addr) -> [u8; ARP_FRAME_LEN] {
    let mut f = [0u8; ARP_FRAME_LEN];
    f[0..6].copy_from_slice(&MacAddr::BROADCAST.0);
    f[6..12].copy_from_slice(&src_mac.0);
    f[12..14].copy_from_slice(&ETH_P_ARP.to_be_bytes());
    let a = &mut f[14..];
    a[0..2].copy_from_slice(&1u16.to_be_bytes()); // hardware type: Ethernet
    a[2..4].copy_from_slice(&ETH_P_IPV4.to_be_bytes());
    a[4] = 6; // hardware address length
    a[5] = 4; // protocol address length
    a[6..8].copy_from_slice(&ARP_REQUEST.to_be_bytes());
    a[8..14].copy_from_slice(&src_mac.0);
    a[14..18].copy_from_slice(&src_ip.octets());
    // Target hardware address stays zero: that is what we ask for.
    a[24..28].copy_from_slice(&target.octets());
    f
}

/// The sender of an ARP reply in an Ethernet frame: who answered, and the
/// address they asked us to use. `None` for anything else.
pub fn parse_arp_reply(frame: &[u8]) -> Option<(Ipv4Addr, MacAddr)> {
    if frame.len() < ARP_FRAME_LEN || frame[12..14] != ETH_P_ARP.to_be_bytes() {
        return None;
    }
    let a = &frame[14..];
    let ok = a[0..2] == 1u16.to_be_bytes()
        && a[2..4] == ETH_P_IPV4.to_be_bytes()
        && a[4] == 6
        && a[5] == 4
        && a[6..8] == ARP_REPLY.to_be_bytes();
    if !ok {
        return None;
    }
    let mac = MacAddr(a[8..14].try_into().ok()?);
    let ip = Ipv4Addr::new(a[14], a[15], a[16], a[17]);
    Some((ip, mac))
}

/// An IPv4 network attached to an Ethernet interface of this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalNet {
    pub ifname: String,
    pub ifindex: u32,
    pub mac: MacAddr,
    /// Our own address on that network, used as the ARP sender.
    pub addr: Ipv4Addr,
    pub prefix: u8,
}

impl LocalNet {
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let mask = u32::MAX
            .checked_shl(32 - u32::from(self.prefix))
            .unwrap_or(0);
        u32::from(ip) & mask == u32::from(self.addr) & mask
    }
}

/// The local network `ip` sits on, if any (the most specific one wins).
/// Our own addresses are excluded: there is nobody to ask about them.
pub fn local_net_for(ip: Ipv4Addr, nets: &[LocalNet]) -> Option<&LocalNet> {
    if nets.iter().any(|n| n.addr == ip) {
        return None;
    }
    nets.iter()
        .filter(|n| n.contains(ip))
        .max_by_key(|n| n.prefix)
}

#[cfg(target_os = "linux")]
pub use linux::{local_networks, sweep};

/// Without Linux packet sockets there are no local networks to ARP on.
#[cfg(not(target_os = "linux"))]
pub fn local_networks() -> std::io::Result<Vec<LocalNet>> {
    Ok(Vec::new())
}

#[cfg(not(target_os = "linux"))]
pub fn sweep(
    _net: &LocalNet,
    _targets: &[Ipv4Addr],
    _cfg: &crate::model::ScanConfig,
    _cancel: &std::sync::atomic::AtomicBool,
    _on_reply: &mut dyn FnMut(Ipv4Addr, MacAddr, f64),
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "ARP discovery needs Linux",
    ))
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::{HashMap, HashSet};
    use std::ffi::CStr;
    use std::io;
    use std::mem;
    use std::net::Ipv4Addr;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    use super::{ARP_FRAME_LEN, ETH_P_ARP, LocalNet, MacAddr, arp_request, parse_arp_reply};
    use crate::model::ScanConfig;
    use crate::raw::Pacer;

    /// Every IPv4 network on an up, ARP-capable Ethernet interface.
    pub fn local_networks() -> io::Result<Vec<LocalNet>> {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        // SAFETY: getifaddrs fills `ifap` with a list we free below.
        if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut macs: HashMap<String, (u32, MacAddr)> = HashMap::new();
        let mut v4: Vec<(String, Ipv4Addr, u8)> = Vec::new();
        let mut cur = ifap;
        while !cur.is_null() {
            // SAFETY: `cur` is a node of the list getifaddrs returned.
            let ifa = unsafe { &*cur };
            cur = ifa.ifa_next;
            let flags = ifa.ifa_flags;
            let usable = flags & libc::IFF_UP as u32 != 0
                && flags & libc::IFF_LOOPBACK as u32 == 0
                && flags & libc::IFF_NOARP as u32 == 0;
            if !usable || ifa.ifa_addr.is_null() || ifa.ifa_name.is_null() {
                continue;
            }
            // SAFETY: a non-null name is a NUL-terminated string.
            let name = unsafe { CStr::from_ptr(ifa.ifa_name) }
                .to_string_lossy()
                .into_owned();
            // SAFETY: a non-null address starts with its family.
            let family = i32::from(unsafe { (*ifa.ifa_addr).sa_family });
            match family {
                libc::AF_PACKET => {
                    // SAFETY: AF_PACKET entries hold a sockaddr_ll.
                    let ll = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_ll) };
                    if ll.sll_hatype == libc::ARPHRD_ETHER && ll.sll_halen == 6 {
                        let mut mac = [0u8; 6];
                        mac.copy_from_slice(&ll.sll_addr[..6]);
                        macs.insert(name, (ll.sll_ifindex as u32, MacAddr(mac)));
                    }
                }
                libc::AF_INET if !ifa.ifa_netmask.is_null() => {
                    // SAFETY: AF_INET entries hold sockaddr_in address and mask.
                    let (addr, mask) = unsafe {
                        (
                            &*(ifa.ifa_addr as *const libc::sockaddr_in),
                            &*(ifa.ifa_netmask as *const libc::sockaddr_in),
                        )
                    };
                    let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
                    let prefix = u32::from_be(mask.sin_addr.s_addr).count_ones() as u8;
                    // A /32 (or /31 point-to-point) has no neighbours to ask.
                    if prefix <= 30 {
                        v4.push((name, ip, prefix));
                    }
                }
                _ => {}
            }
        }
        // SAFETY: frees the list from getifaddrs exactly once.
        unsafe { libc::freeifaddrs(ifap) };

        Ok(v4
            .into_iter()
            .filter_map(|(ifname, addr, prefix)| {
                let &(ifindex, mac) = macs.get(&ifname)?;
                Some(LocalNet {
                    ifname,
                    ifindex,
                    mac,
                    addr,
                    prefix,
                })
            })
            .collect())
    }

    /// An `AF_PACKET` socket bound to `ifindex` that sees only ARP frames.
    fn open(ifindex: u32) -> io::Result<OwnedFd> {
        let proto = ETH_P_ARP.to_be();
        // SAFETY: plain socket(2) call; the result is checked.
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, i32::from(proto)) };
        if fd < 0 {
            let e = io::Error::last_os_error();
            return Err(if e.kind() == io::ErrorKind::PermissionDenied {
                io::Error::new(e.kind(), "ARP discovery needs root (or CAP_NET_RAW)")
            } else {
                e
            });
        }
        // SAFETY: `fd` is a fresh descriptor that we now own.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let sll = sockaddr_ll(ifindex, MacAddr([0; 6]));
        // SAFETY: binds to a properly sized sockaddr_ll.
        let r = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&raw const sll).cast(),
                mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if r != 0 {
            return Err(io::Error::last_os_error());
        }
        let tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 50_000,
        };
        // SAFETY: sets a receive timeout from a valid timeval.
        let r = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&raw const tv).cast(),
                mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if r != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(fd)
    }

    fn sockaddr_ll(ifindex: u32, dst: MacAddr) -> libc::sockaddr_ll {
        // SAFETY: sockaddr_ll is plain data; all-zero is a valid value.
        let mut sll: libc::sockaddr_ll = unsafe { mem::zeroed() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = ETH_P_ARP.to_be();
        sll.sll_ifindex = ifindex as i32;
        sll.sll_halen = 6;
        sll.sll_addr[..6].copy_from_slice(&dst.0);
        sll
    }

    fn send(fd: &OwnedFd, ifindex: u32, frame: &[u8]) -> io::Result<()> {
        let sll = sockaddr_ll(ifindex, MacAddr::BROADCAST);
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
            // A full send queue is temporary: wait for it to drain.
            if e.raw_os_error() == Some(libc::ENOBUFS) && attempts < 50 {
                attempts += 1;
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            return Err(e);
        }
    }

    /// Ask every address in `targets` (all on `net`) for its MAC address,
    /// calling `on_reply` once per host that answers, with its RTT in ms.
    /// Stops early when `cancel` is set.
    pub fn sweep(
        net: &LocalNet,
        targets: &[Ipv4Addr],
        cfg: &ScanConfig,
        cancel: &AtomicBool,
        on_reply: &mut dyn FnMut(Ipv4Addr, MacAddr, f64),
    ) -> io::Result<()> {
        if targets.is_empty() || cancel.load(Ordering::Relaxed) {
            return Ok(());
        }
        let fd = Arc::new(open(net.ifindex)?);
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = std::sync::mpsc::channel::<(Ipv4Addr, MacAddr, Instant)>();
        let receiver = {
            let (fd, stop) = (Arc::clone(&fd), Arc::clone(&stop));
            std::thread::spawn(move || {
                let mut buf = [0u8; 2048];
                while !stop.load(Ordering::Relaxed) {
                    // SAFETY: reads into a buffer we own, of the given size.
                    let n = unsafe {
                        libc::recv(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0)
                    };
                    if n < 0 {
                        let e = io::Error::last_os_error();
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock
                                | io::ErrorKind::TimedOut
                                | io::ErrorKind::Interrupted
                        ) {
                            continue;
                        }
                        return;
                    }
                    let at = Instant::now();
                    if let Some((ip, mac)) = parse_arp_reply(&buf[..n as usize])
                        && tx.send((ip, mac, at)).is_err()
                    {
                        return;
                    }
                }
            })
        };

        let wanted: HashSet<Ipv4Addr> = targets.iter().copied().collect();
        let mut sent_at: HashMap<Ipv4Addr, Instant> = HashMap::new();
        let mut answered: HashSet<Ipv4Addr> = HashSet::new();
        let mut record = |(ip, mac, at): (Ipv4Addr, MacAddr, Instant),
                          sent_at: &HashMap<Ipv4Addr, Instant>,
                          answered: &mut HashSet<Ipv4Addr>| {
            // Only hosts we asked about, and only their first answer.
            let Some(&sent) = sent_at.get(&ip) else {
                return;
            };
            if wanted.contains(&ip) && answered.insert(ip) {
                let rtt = (at.saturating_duration_since(sent).as_secs_f64() * 1e6).round() / 1000.0;
                on_reply(ip, mac, rtt);
            }
        };

        let mut pending: Vec<Ipv4Addr> = targets.to_vec();
        let outcome = (|| -> io::Result<()> {
            for _ in 0..=cfg.retries {
                let mut pacer = Pacer::new(cfg.max_rate);
                for &ip in &pending {
                    if cancel.load(Ordering::Relaxed) {
                        return Ok(());
                    }
                    let frame: [u8; ARP_FRAME_LEN] = arp_request(net.mac, net.addr, ip);
                    sent_at.insert(ip, Instant::now());
                    send(&fd, net.ifindex, &frame)?;
                    pacer.tick();
                    while let Ok(r) = rx.try_recv() {
                        record(r, &sent_at, &mut answered);
                    }
                }
                let deadline = Instant::now() + cfg.timeout;
                while answered.len() < wanted.len()
                    && !cancel.load(Ordering::Relaxed)
                    && let Some(left) = deadline.checked_duration_since(Instant::now())
                {
                    match rx.recv_timeout(left.min(Duration::from_millis(100))) {
                        Ok(r) => record(r, &sent_at, &mut answered),
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
                if cancel.load(Ordering::Relaxed) {
                    return Ok(());
                }
                pending.retain(|ip| !answered.contains(ip));
                if pending.is_empty() {
                    break;
                }
            }
            Ok(())
        })();

        stop.store(true, Ordering::Relaxed);
        let _ = receiver.join();
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(addr: &str, prefix: u8) -> LocalNet {
        LocalNet {
            ifname: "eth0".into(),
            ifindex: 2,
            mac: MacAddr([2, 0, 0, 0, 0, 1]),
            addr: addr.parse().unwrap(),
            prefix,
        }
    }

    #[test]
    fn request_layout() {
        let mac = MacAddr([0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let f = arp_request(
            mac,
            "192.168.1.10".parse().unwrap(),
            "192.168.1.1".parse().unwrap(),
        );
        assert_eq!(&f[0..6], &[0xff; 6]);
        assert_eq!(&f[6..12], &mac.0);
        assert_eq!(&f[12..14], &[0x08, 0x06]);
        assert_eq!(&f[14..22], &[0, 1, 0x08, 0x00, 6, 4, 0, 1]);
        assert_eq!(&f[22..28], &mac.0);
        assert_eq!(&f[28..32], &[192, 168, 1, 10]);
        assert_eq!(&f[32..38], &[0; 6]);
        assert_eq!(&f[38..42], &[192, 168, 1, 1]);
    }

    #[test]
    fn parses_replies_only() {
        let us = MacAddr([0x02, 0, 0, 0, 0, 1]);
        let them = MacAddr([0xb8, 0x27, 0xeb, 1, 2, 3]);
        let them_ip: Ipv4Addr = "10.0.0.7".parse().unwrap();
        // Turn our request into the reply a host would send back.
        let mut reply = arp_request(them, them_ip, "10.0.0.1".parse().unwrap()).to_vec();
        reply[0..6].copy_from_slice(&us.0);
        reply[20..22].copy_from_slice(&ARP_REPLY.to_be_bytes());
        // Ethernet pads short frames to 60 bytes; padding must not matter.
        reply.resize(60, 0);
        assert_eq!(parse_arp_reply(&reply), Some((them_ip, them)));

        let request = arp_request(them, them_ip, "10.0.0.1".parse().unwrap());
        assert_eq!(parse_arp_reply(&request), None);
        assert_eq!(parse_arp_reply(&reply[..30]), None);
        let mut not_arp = reply.clone();
        not_arp[12..14].copy_from_slice(&[0x08, 0x00]);
        assert_eq!(parse_arp_reply(&not_arp), None);
    }

    #[test]
    fn picks_the_most_specific_local_net() {
        let nets = [net("10.0.0.5", 8), net("10.1.2.5", 24)];
        let ip = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        assert_eq!(local_net_for(ip("10.1.2.9"), &nets).unwrap().prefix, 24);
        assert_eq!(local_net_for(ip("10.9.9.9"), &nets).unwrap().prefix, 8);
        assert!(local_net_for(ip("192.168.1.1"), &nets).is_none());
        // Our own address is not a neighbour.
        assert!(local_net_for(ip("10.1.2.5"), &nets).is_none());
        assert!(net("0.0.0.0", 0).contains(ip("8.8.8.8")));
    }

    #[test]
    fn vendor_lookup() {
        assert!(VENDORS.is_sorted_by_key(|(p, _)| *p), "keep VENDORS sorted");
        let mac = |b: [u8; 6]| MacAddr(b);
        assert_eq!(vendor(mac([0x00, 0x50, 0x56, 1, 2, 3])), Some("VMware"));
        assert_eq!(
            vendor(mac([0xb8, 0x27, 0xeb, 1, 2, 3])),
            Some("Raspberry Pi")
        );
        // QEMU's prefix is locally administered but still named.
        assert_eq!(
            vendor(mac([0x52, 0x54, 0x00, 1, 2, 3])),
            Some("QEMU/KVM virtual NIC")
        );
        assert!(
            vendor(mac([0x02, 0x42, 0xac, 0x11, 0, 2]))
                .unwrap()
                .contains("Locally")
        );
        assert_eq!(vendor(mac([0x00, 0x00, 0x01, 1, 2, 3])), None);
        assert_eq!(
            mac([0x00, 0x0c, 0x29, 0xab, 0xcd, 0xef]).to_string(),
            "00:0C:29:AB:CD:EF"
        );
    }

    /// ARP the default gateway, which every CI runner and most machines
    /// have on a local Ethernet. Needs root; CI sets FEROPROBE_REQUIRE_RAW.
    #[cfg(target_os = "linux")]
    #[test]
    fn gateway_answers_arp() {
        use std::sync::atomic::AtomicBool;

        let Some(gw) = default_gateway() else {
            eprintln!("note: no IPv4 default gateway, ARP test not run");
            return;
        };
        let nets = local_networks().unwrap();
        let Some(net) = local_net_for(gw, &nets) else {
            eprintln!("note: gateway {gw} is not on an Ethernet network, ARP test not run");
            return;
        };
        if !crate::raw::raw_sockets_available() {
            assert!(
                std::env::var_os("FEROPROBE_REQUIRE_RAW").is_none(),
                "FEROPROBE_REQUIRE_RAW is set but raw sockets are unavailable"
            );
            eprintln!("note: no raw-socket privileges, ARP test not run");
            return;
        }
        let cfg = crate::model::ScanConfig {
            timeout: std::time::Duration::from_secs(1),
            retries: 2,
            ..Default::default()
        };
        let mut got = Vec::new();
        sweep(
            net,
            &[gw],
            &cfg,
            &AtomicBool::new(false),
            &mut |ip, mac, _| got.push((ip, mac)),
        )
        .unwrap();
        assert_eq!(
            got.len(),
            1,
            "gateway {gw} did not answer ARP on {}",
            net.ifname
        );
        assert_eq!(got[0].0, gw);
    }

    /// The IPv4 default gateway from the kernel's routing table.
    #[cfg(target_os = "linux")]
    fn default_gateway() -> Option<Ipv4Addr> {
        let table = std::fs::read_to_string("/proc/net/route").ok()?;
        table.lines().skip(1).find_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            let gw = u32::from_str_radix(f.get(2)?, 16).ok()?;
            // The kernel prints the network-order address as a native u32.
            (*f.get(1)? == "00000000" && gw != 0).then(|| Ipv4Addr::from(gw.to_ne_bytes()))
        })
    }
}
