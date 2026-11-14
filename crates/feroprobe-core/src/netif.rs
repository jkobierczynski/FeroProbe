//! Local network interfaces: names, indexes, IPv6 addresses and Ethernet
//! hardware addresses, as the OS reports them.

use std::net::Ipv6Addr;

/// An IPv6 address configured on an up, non-loopback interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6IfAddr {
    pub ifname: String,
    pub index: u32,
    pub addr: Ipv6Addr,
    pub prefix: u8,
    /// Whether the interface resolves neighbours (it is not point-to-point
    /// or otherwise marked as not needing ARP/NDP).
    pub resolves_neighbours: bool,
}

/// Every IPv6 address on an up, non-loopback interface. Empty where the
/// list cannot be read.
#[cfg(unix)]
pub fn ipv6_addrs() -> Vec<Ipv6IfAddr> {
    use std::ffi::CStr;

    let mut out = Vec::new();
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `ifap` with a list we free below.
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
        return out;
    }
    let mut cur = ifap;
    while !cur.is_null() {
        // SAFETY: `cur` is a node of the list getifaddrs returned.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        let flags = ifa.ifa_flags;
        if flags & libc::IFF_UP as u32 == 0
            || flags & libc::IFF_LOOPBACK as u32 != 0
            || ifa.ifa_addr.is_null()
            || ifa.ifa_name.is_null()
        {
            continue;
        }
        // SAFETY: a non-null address starts with its family.
        if i32::from(unsafe { (*ifa.ifa_addr).sa_family }) != libc::AF_INET6 {
            continue;
        }
        // SAFETY: AF_INET6 entries hold a sockaddr_in6.
        let sin6 = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
        let prefix = if ifa.ifa_netmask.is_null() {
            128
        } else {
            // SAFETY: the netmask of an AF_INET6 entry is a sockaddr_in6.
            let mask = unsafe { &*(ifa.ifa_netmask as *const libc::sockaddr_in6) };
            u128::from_be_bytes(mask.sin6_addr.s6_addr).count_ones() as u8
        };
        // SAFETY: a non-null name is a NUL-terminated string.
        let name = unsafe { CStr::from_ptr(ifa.ifa_name) };
        // SAFETY: if_nametoindex reads the NUL-terminated name.
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        if index == 0 {
            continue;
        }
        out.push(Ipv6IfAddr {
            ifname: name.to_string_lossy().into_owned(),
            index,
            addr: Ipv6Addr::from(sin6.sin6_addr.s6_addr),
            prefix,
            resolves_neighbours: flags & libc::IFF_NOARP as u32 == 0
                && flags & libc::IFF_POINTOPOINT as u32 == 0,
        });
    }
    // SAFETY: frees the list from getifaddrs exactly once.
    unsafe { libc::freeifaddrs(ifap) };
    out
}

#[cfg(not(unix))]
pub fn ipv6_addrs() -> Vec<Ipv6IfAddr> {
    Vec::new()
}

/// The index of the interface called `name`.
#[cfg(unix)]
pub fn index_of(name: &str) -> Option<u32> {
    let name = std::ffi::CString::new(name).ok()?;
    // SAFETY: if_nametoindex reads the NUL-terminated name.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    (index != 0).then_some(index)
}

#[cfg(not(unix))]
pub fn index_of(_name: &str) -> Option<u32> {
    None
}

/// The Ethernet hardware address of each interface that has one, by index.
#[cfg(target_os = "linux")]
pub fn ethernet_macs() -> std::collections::HashMap<u32, crate::arp::MacAddr> {
    let mut out = std::collections::HashMap::new();
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `ifap` with a list we free below.
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
        return out;
    }
    let mut cur = ifap;
    while !cur.is_null() {
        // SAFETY: `cur` is a node of the list getifaddrs returned.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_addr.is_null() {
            continue;
        }
        // SAFETY: a non-null address starts with its family.
        if i32::from(unsafe { (*ifa.ifa_addr).sa_family }) != libc::AF_PACKET {
            continue;
        }
        // SAFETY: AF_PACKET entries hold a sockaddr_ll.
        let ll = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_ll) };
        if ll.sll_hatype == libc::ARPHRD_ETHER && ll.sll_halen == 6 {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&ll.sll_addr[..6]);
            out.insert(ll.sll_ifindex as u32, crate::arp::MacAddr(mac));
        }
    }
    // SAFETY: frees the list from getifaddrs exactly once.
    unsafe { libc::freeifaddrs(ifap) };
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_without_panicking() {
        for a in ipv6_addrs() {
            assert!(a.index > 0 && a.prefix <= 128, "{a:?}");
            assert!(!a.addr.is_loopback());
        }
        assert_eq!(index_of("no-such-if0"), None);
    }
}
