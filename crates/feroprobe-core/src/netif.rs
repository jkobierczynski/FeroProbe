//! Local network interfaces: names, indexes, IPv6 addresses and Ethernet
//! hardware addresses, as the OS reports them; and the interface chosen
//! with `-e`, which every socket of the scan is bound to.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::OnceLock;

use socket2::{Domain, Protocol, Socket, Type};

/// The interface the scan sends and receives on (nmap's `-e`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    pub name: String,
    pub index: u32,
}

static INTERFACE: OnceLock<Interface> = OnceLock::new();

/// Send and receive every probe of this run on the interface `name`
/// (nmap's `-e`): raw, capture, ARP/NDP, connect, UDP and DNS sockets are
/// all bound to it, and only its networks count as local. Fails if there is
/// no such interface, if this system cannot bind sockets to one, or if a
/// different interface was already chosen.
pub fn use_interface(name: &str) -> io::Result<&'static Interface> {
    if !cfg!(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple"
    )) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "-e is only supported on Linux and macOS for now",
        ));
    }
    let index = index_of(name).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("no interface called {name:?} (see `ip link` for the names)"),
        )
    })?;
    let chosen = INTERFACE.get_or_init(|| Interface {
        name: name.to_string(),
        index,
    });
    if chosen.name != name {
        return Err(io::Error::other(format!(
            "interface {} was already chosen",
            chosen.name
        )));
    }
    Ok(chosen)
}

/// The interface chosen with [`use_interface`], if any.
pub fn interface() -> Option<&'static Interface> {
    INTERFACE.get()
}

/// Whether the interface with index `index` may be used: always, unless
/// `-e` chose another one.
// ARP and neighbour discovery, its only users, are Linux only.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn allowed(index: u32) -> bool {
    interface().is_none_or(|i| i.index == index)
}

/// Bind `sock` to the `-e` interface, if one was chosen, so that what it
/// sends leaves through that interface and it only receives what arrives
/// there. `ipv6` names the socket's family (macOS binds per family).
pub(crate) fn bind_socket(sock: &Socket, ipv6: bool) -> io::Result<()> {
    let Some(ifc) = interface() else {
        return Ok(());
    };
    let result = bind_to(sock, ifc, ipv6);
    result.map_err(|e| {
        let why = if e.kind() == io::ErrorKind::PermissionDenied {
            "this system only lets root (or CAP_NET_RAW) bind a socket to an interface".to_string()
        } else {
            e.to_string()
        };
        io::Error::new(
            e.kind(),
            format!("binding to interface {} (-e): {why}", ifc.name),
        )
    })
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn bind_to(sock: &Socket, ifc: &Interface, _ipv6: bool) -> io::Result<()> {
    sock.bind_device(Some(ifc.name.as_bytes()))
}

#[cfg(target_vendor = "apple")]
fn bind_to(sock: &Socket, ifc: &Interface, ipv6: bool) -> io::Result<()> {
    let index = std::num::NonZeroU32::new(ifc.index);
    if ipv6 {
        sock.bind_device_by_index_v6(index)
    } else {
        sock.bind_device_by_index_v4(index)
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
fn bind_to(_sock: &Socket, _ifc: &Interface, _ipv6: bool) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "binding to an interface is not supported on this system",
    ))
}

/// A non-blocking UDP socket of `addr`'s family, bound to the `-e`
/// interface (if any), not yet bound to a local address.
pub(crate) fn udp_socket(ipv6: bool) -> io::Result<Socket> {
    let domain = if ipv6 { Domain::IPV6 } else { Domain::IPV4 };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    bind_socket(&sock, ipv6)?;
    sock.set_nonblocking(true)?;
    Ok(sock)
}

/// The unspecified local address of `dst`'s family, with `port`.
pub(crate) fn any_addr(dst: IpAddr, port: u16) -> SocketAddr {
    match dst {
        IpAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, port).into(),
        IpAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, port).into(),
    }
}

/// The local address the OS would use to reach `dst` (through the `-e`
/// interface, if one was chosen), found by "connecting" a UDP socket,
/// which sends nothing.
pub fn route_source(dst: IpAddr) -> io::Result<IpAddr> {
    let sock = udp_socket(dst.is_ipv6())?;
    sock.bind(&any_addr(dst, 0).into())?;
    sock.connect(&crate::target::socket_addr(dst, 53).into())?;
    sock.local_addr()?
        .as_socket()
        .map(|a| a.ip())
        .ok_or_else(|| io::Error::other("no local address"))
}

/// Open a TCP connection to `addr`, from the `-e` interface if one was
/// chosen.
pub(crate) async fn connect_tcp(addr: SocketAddr) -> io::Result<tokio::net::TcpStream> {
    if interface().is_none() {
        return tokio::net::TcpStream::connect(addr).await;
    }
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    bind_socket(&sock, addr.is_ipv6())?;
    sock.set_nonblocking(true)?;
    let std: std::net::TcpStream = sock.into();
    tokio::net::TcpSocket::from_std_stream(std)
        .connect(addr)
        .await
}

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
