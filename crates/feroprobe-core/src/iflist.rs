//! `--iflist`: the host's interfaces and routes, in the layout of nmap's
//! `--iflist` (two tables, INTERFACES and ROUTES).
//!
//! Like nmap, each address of an interface gets its own row, an interface
//! without addresses gets one row with `(none)/0`, and the routes are
//! sorted IPv4 first, then by prefix length (longest first) and metric, and
//! a route whose device is not a known interface is left out.

use std::collections::HashSet;
use std::fmt::Write as _;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::arp::MacAddr;

/// What kind of link an interface is, as nmap names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IfKind {
    Ethernet,
    Loopback,
    PointToPoint,
    Other,
}

impl IfKind {
    pub fn name(self) -> &'static str {
        match self {
            IfKind::Ethernet => "ethernet",
            IfKind::Loopback => "loopback",
            IfKind::PointToPoint => "point2point",
            IfKind::Other => "other",
        }
    }
}

/// One row of the interface table: an interface and one of its addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfEntry {
    pub name: String,
    pub addr: Option<IpAddr>,
    pub prefix: u8,
    pub kind: IfKind,
    pub up: bool,
    pub mtu: u32,
    /// The hardware address, shown for Ethernet interfaces.
    pub mac: Option<MacAddr>,
}

/// One route of the system's routing table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub dst: IpAddr,
    pub prefix: u8,
    pub dev: String,
    pub metric: u32,
    /// The next hop; `None` for a directly connected network.
    pub gateway: Option<IpAddr>,
}

/// The interface rows, from `getifaddrs`.
#[cfg(unix)]
pub fn interfaces() -> io::Result<Vec<IfEntry>> {
    use std::ffi::CStr;

    struct Link {
        name: String,
        flags: u32,
        /// Each address with the name it carries (an alias such as
        /// `eth0:1` names its own addresses).
        addrs: Vec<(String, IpAddr, u8)>,
        mac: Option<MacAddr>,
        mtu: Option<u32>,
    }
    let mut links: Vec<Link> = Vec::new();
    let mut list = std::mem::MaybeUninit::<*mut libc::ifaddrs>::uninit();
    // SAFETY: getifaddrs fills `list` with a list we free below.
    if unsafe { libc::getifaddrs(list.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: getifaddrs succeeded, so it wrote the list's head.
    let ifap = unsafe { list.assume_init() };
    let mut cur = ifap;
    // SAFETY: `cur` is null or a node of the list getifaddrs returned,
    // which stays valid until freeifaddrs below; as_ref checks for null.
    while let Some(ifa) = unsafe { cur.as_ref() } {
        cur = ifa.ifa_next;
        if ifa.ifa_name.is_null() {
            continue;
        }
        // SAFETY: a non-null name is a NUL-terminated string.
        let name = unsafe { CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();
        // A Linux alias (`eth0:1`) shares its interface's flags, hardware
        // address and MTU.
        let base = name.split(':').next().unwrap_or(&name).to_string();
        let i = match links.iter().position(|l| l.name == base) {
            Some(i) => i,
            None => {
                links.push(Link {
                    name: base,
                    flags: ifa.ifa_flags,
                    addrs: Vec::new(),
                    mac: None,
                    mtu: None,
                });
                links.len() - 1
            }
        };
        let link = &mut links[i];
        link.flags |= ifa.ifa_flags;
        if ifa.ifa_addr.is_null() {
            continue;
        }
        // SAFETY: a non-null address starts with its family.
        let family = i32::from(unsafe { (*ifa.ifa_addr).sa_family });
        if family == libc::AF_INET {
            // SAFETY: AF_INET entries hold sockaddr_in, as does their mask.
            let sin = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
            let prefix = if ifa.ifa_netmask.is_null() {
                32
            } else {
                let m = unsafe { &*(ifa.ifa_netmask as *const libc::sockaddr_in) };
                u32::from_be(m.sin_addr.s_addr).count_ones() as u8
            };
            let addr = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            link.addrs.push((name, IpAddr::V4(addr), prefix));
        } else if family == libc::AF_INET6 {
            // SAFETY: AF_INET6 entries hold sockaddr_in6, as does their mask.
            let sin6 = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
            let prefix = if ifa.ifa_netmask.is_null() {
                128
            } else {
                let m = unsafe { &*(ifa.ifa_netmask as *const libc::sockaddr_in6) };
                u128::from_be_bytes(m.sin6_addr.s6_addr).count_ones() as u8
            };
            let addr = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            link.addrs.push((name, IpAddr::V6(addr), prefix));
        } else {
            link_layer(ifa, family, &mut link.mac, &mut link.mtu);
        }
    }
    // SAFETY: frees the list from getifaddrs exactly once.
    unsafe { libc::freeifaddrs(ifap) };

    let mut out = Vec::new();
    for mut link in links {
        let flag = |f: libc::c_int| link.flags & f as u32 != 0;
        let kind = if flag(libc::IFF_LOOPBACK) {
            IfKind::Loopback
        } else if link.mac.is_some() && !flag(libc::IFF_NOARP) {
            IfKind::Ethernet
        } else if flag(libc::IFF_POINTOPOINT) {
            IfKind::PointToPoint
        } else {
            IfKind::Other
        };
        let up = flag(libc::IFF_UP);
        let mtu = link.mtu.or_else(|| mtu_of(&link.name)).unwrap_or(0);
        let mac = (kind == IfKind::Ethernet).then_some(link.mac).flatten();
        // IPv4 first, as nmap lists an interface's primary address first.
        link.addrs.sort_by_key(|(_, a, _)| a.is_ipv6());
        if link.addrs.is_empty() {
            out.push(IfEntry {
                name: link.name.clone(),
                addr: None,
                prefix: 0,
                kind,
                up,
                mtu,
                mac,
            });
        }
        for (name, addr, prefix) in link.addrs {
            out.push(IfEntry {
                name,
                addr: Some(addr),
                prefix,
                kind,
                up,
                mtu,
                mac,
            });
        }
    }
    Ok(out)
}

#[cfg(not(unix))]
pub fn interfaces() -> io::Result<Vec<IfEntry>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "listing interfaces is not supported on this system yet",
    ))
}

/// The hardware address (and, on macOS, the MTU) from a link-layer entry.
#[cfg(target_os = "linux")]
fn link_layer(ifa: &libc::ifaddrs, family: i32, mac: &mut Option<MacAddr>, _mtu: &mut Option<u32>) {
    if family != libc::AF_PACKET {
        return;
    }
    // SAFETY: AF_PACKET entries hold a sockaddr_ll.
    let ll = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_ll) };
    if ll.sll_hatype == libc::ARPHRD_ETHER && ll.sll_halen == 6 {
        let mut m = [0u8; 6];
        m.copy_from_slice(&ll.sll_addr[..6]);
        *mac = Some(MacAddr(m));
    }
}

#[cfg(target_vendor = "apple")]
fn link_layer(ifa: &libc::ifaddrs, family: i32, mac: &mut Option<MacAddr>, mtu: &mut Option<u32>) {
    // IFT_ETHER, from <net/if_types.h>.
    const IFT_ETHER: u8 = 0x6;
    if family != libc::AF_LINK {
        return;
    }
    if !ifa.ifa_data.is_null() {
        // SAFETY: the AF_LINK entry's data is the interface's if_data.
        let data = unsafe { &*(ifa.ifa_data as *const libc::if_data) };
        *mtu = Some(data.ifi_mtu);
    }
    // SAFETY: AF_LINK entries hold a sockaddr_dl.
    let dl = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_dl) };
    if dl.sdl_type == IFT_ETHER && dl.sdl_alen == 6 {
        let start = usize::from(dl.sdl_nlen);
        // The address follows the name, and may run past sdl_data's
        // declared length: read it from the structure's own bytes.
        let base = std::ptr::addr_of!(dl.sdl_data) as *const u8;
        let mut m = [0u8; 6];
        // SAFETY: the kernel sizes the entry to hold name and address.
        unsafe { std::ptr::copy_nonoverlapping(base.add(start), m.as_mut_ptr(), 6) };
        *mac = Some(MacAddr(m));
    }
}

#[cfg(all(unix, not(any(target_os = "linux", target_vendor = "apple"))))]
fn link_layer(_: &libc::ifaddrs, _: i32, _: &mut Option<MacAddr>, _: &mut Option<u32>) {}

/// An interface's MTU where the link-layer entry did not give it.
#[cfg(unix)]
fn mtu_of(name: &str) -> Option<u32> {
    if cfg!(target_os = "linux") {
        std::fs::read_to_string(format!("/sys/class/net/{name}/mtu"))
            .ok()?
            .trim()
            .parse()
            .ok()
    } else {
        None
    }
}

/// The routing table. Linux only for now.
pub fn routes() -> io::Result<Vec<Route>> {
    if !cfg!(target_os = "linux") {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "reading the routing table is only supported on Linux for now",
        ));
    }
    let mut routes = parse_proc_route(&std::fs::read_to_string("/proc/net/route")?);
    // A host without IPv6 has no IPv6 table: that is not an error.
    if let Ok(text) = std::fs::read_to_string("/proc/net/ipv6_route") {
        routes.extend(parse_ipv6_route(&text));
    }
    Ok(routes)
}

/// The kernel's RTF_UP route flag.
const RTF_UP: u32 = 0x1;

/// Routes from Linux's `/proc/net/route` (IPv4): addresses and masks are
/// the in-memory bytes printed as one hexadecimal number.
pub fn parse_proc_route(text: &str) -> Vec<Route> {
    let addr = |s: &str| {
        u32::from_str_radix(s, 16)
            .ok()
            .map(|v| Ipv4Addr::from(v.to_ne_bytes()))
    };
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 11 {
                return None;
            }
            let flags = u32::from_str_radix(f[3], 16).ok()?;
            if flags & RTF_UP == 0 {
                return None;
            }
            let mask = u32::from(addr(f[7])?);
            // Only contiguous masks, as libdnet's addr_mtob.
            if mask.leading_ones() + mask.trailing_zeros() != 32 {
                return None;
            }
            let gw = addr(f[2])?;
            Some(Route {
                dst: IpAddr::V4(addr(f[1])?),
                prefix: mask.leading_ones() as u8,
                dev: f[0].to_string(),
                metric: f[6].parse().ok()?,
                gateway: (!gw.is_unspecified()).then_some(IpAddr::V4(gw)),
            })
        })
        .collect()
}

/// Routes from Linux's `/proc/net/ipv6_route`: destination, its prefix
/// length, source, its prefix length, next hop, metric, reference count,
/// use count, flags and device.
pub fn parse_ipv6_route(text: &str) -> Vec<Route> {
    let addr = |s: &str| u128::from_str_radix(s, 16).ok().map(Ipv6Addr::from);
    text.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 10 {
                return None;
            }
            let flags = u32::from_str_radix(f[8], 16).ok()?;
            if flags & RTF_UP == 0 {
                return None;
            }
            let gw = addr(f[4])?;
            Some(Route {
                dst: IpAddr::V6(addr(f[0])?),
                prefix: u8::from_str_radix(f[1], 16).ok()?,
                dev: f[9].to_string(),
                metric: u32::from_str_radix(f[5], 16).ok()?,
                gateway: (!gw.is_unspecified()).then_some(IpAddr::V6(gw)),
            })
        })
        .collect()
}

/// nmap's table layout: columns padded to their widest cell plus one
/// space, no trailing spaces.
fn table(rows: &[Vec<String>]) -> String {
    let cols = rows.iter().map(Vec::len).max().unwrap_or(0);
    let widths: Vec<usize> = (0..cols)
        .map(|c| {
            rows.iter()
                .filter_map(|r| r.get(c))
                .map(|s| s.chars().count())
                .max()
                .unwrap_or(0)
        })
        .collect();
    let mut out = String::new();
    for row in rows {
        let last = row.iter().rposition(|s| !s.is_empty()).map_or(0, |i| i + 1);
        let mut line = String::new();
        for (c, cell) in row.iter().enumerate().take(last) {
            line.push_str(cell);
            if c + 1 < last {
                let pad = widths[c] + 1 - cell.chars().count();
                line.extend(std::iter::repeat_n(' ', pad));
            }
        }
        out.push_str(&line);
        out.push('\n');
    }
    out
}

/// The `--iflist` report. With `debug`, a table that could not be read
/// says why, as nmap's does at `-d`.
pub fn render(
    interfaces: &io::Result<Vec<IfEntry>>,
    routes: &io::Result<Vec<Route>>,
    debug: bool,
) -> String {
    let mut out = String::new();
    let mut names = HashSet::new();
    match interfaces {
        Ok(ifs) if !ifs.is_empty() => {
            let mut rows = vec![
                ["DEV", "(SHORT)", "IP/MASK", "TYPE", "UP", "MTU", "MAC"]
                    .map(String::from)
                    .to_vec(),
            ];
            for i in ifs {
                names.insert(i.name.as_str());
                let short = i.name.split(':').next().unwrap_or(&i.name);
                let addr = i
                    .addr
                    .map_or_else(|| "(none)".to_string(), |a| a.to_string());
                rows.push(vec![
                    i.name.clone(),
                    format!("({short})"),
                    format!("{addr}/{}", i.prefix),
                    i.kind.name().to_string(),
                    if i.up { "up" } else { "down" }.to_string(),
                    i.mtu.to_string(),
                    i.mac.map(|m| m.to_string()).unwrap_or_default(),
                ]);
            }
            out.push_str("************************INTERFACES************************\n");
            out.push_str(&table(&rows));
            out.push('\n');
        }
        other => {
            out.push_str("INTERFACES: NONE FOUND(!)\n");
            if debug {
                let why = match other {
                    Err(e) => e.to_string(),
                    Ok(_) => "no interfaces".to_string(),
                };
                let _ = writeln!(out, "Reason: {why}");
            }
        }
    }
    let shown: Vec<&Route> = match routes {
        Ok(r) => {
            let mut r: Vec<&Route> = r
                .iter()
                .filter(|r| names.contains(r.dev.as_str()))
                .collect();
            r.sort_by_key(|r| (r.dst.is_ipv6(), std::cmp::Reverse(r.prefix), r.metric));
            r
        }
        Err(_) => Vec::new(),
    };
    if shown.is_empty() {
        out.push_str("ROUTES: NONE FOUND(!)\n");
        if debug {
            let why = match routes {
                Err(e) => e.to_string(),
                Ok(_) => "no routes through a listed interface".to_string(),
            };
            let _ = writeln!(out, "Reason: {why}");
        }
    } else {
        let mut rows = vec![
            ["DST/MASK", "DEV", "METRIC", "GATEWAY"]
                .map(String::from)
                .to_vec(),
        ];
        for r in shown {
            rows.push(vec![
                format!("{}/{}", r.dst, r.prefix),
                r.dev.clone(),
                r.metric.to_string(),
                r.gateway.map(|g| g.to_string()).unwrap_or_default(),
            ]);
        }
        out.push_str("**************************ROUTES**************************\n");
        out.push_str(&table(&rows));
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A /proc/net/route as this machine's kernel would print it: each
    /// address's bytes read as a native-endian number.
    fn route_table() -> String {
        let hex = |a: [u8; 4]| format!("{:08X}", u32::from_ne_bytes(a));
        let (any, gw, net, mask) = (
            hex([0, 0, 0, 0]),
            hex([192, 168, 0, 1]),
            hex([192, 168, 0, 0]),
            hex([255, 255, 255, 0]),
        );
        format!(
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth0\t{any}\t{gw}\t0003\t0\t0\t100\t{any}\t0\t0\t0
eth0\t{net}\t{any}\t0001\t0\t0\t100\t{mask}\t0\t0\t0
eth0\t{net}\t{any}\t0000\t0\t0\t100\t{mask}\t0\t0\t0
"
        )
    }

    const ROUTE6: &str = "\
fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003     eth0
";

    #[test]
    fn reads_linux_ipv4_routes() {
        let r = parse_proc_route(&route_table());
        // The third route is down (no RTF_UP) and left out.
        assert_eq!(r.len(), 2);
        {
            assert_eq!(r[0].dst, "0.0.0.0".parse::<IpAddr>().unwrap());
            assert_eq!(r[0].prefix, 0);
            assert_eq!(r[0].gateway, Some("192.168.0.1".parse().unwrap()));
            assert_eq!(r[1].dst, "192.168.0.0".parse::<IpAddr>().unwrap());
            assert_eq!(r[1].prefix, 24);
            assert_eq!(r[1].gateway, None);
            assert_eq!(r[1].metric, 100);
        }
    }

    #[test]
    fn reads_linux_ipv6_routes() {
        let r = parse_ipv6_route(ROUTE6);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].dst, "fe80::".parse::<IpAddr>().unwrap());
        assert_eq!(r[0].prefix, 64);
        assert_eq!(r[0].metric, 256);
        assert_eq!(r[0].gateway, None);
        assert_eq!(r[1].gateway, Some("fe80::1".parse().unwrap()));
        assert_eq!(r[1].metric, 1024);
    }

    fn eth(addr: &str, prefix: u8) -> IfEntry {
        IfEntry {
            name: "eth0".into(),
            addr: Some(addr.parse().unwrap()),
            prefix,
            kind: IfKind::Ethernet,
            up: true,
            mtu: 1500,
            mac: Some(MacAddr([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e])),
        }
    }

    #[test]
    fn renders_like_nmap() {
        let lo = IfEntry {
            name: "lo".into(),
            addr: Some("127.0.0.1".parse().unwrap()),
            prefix: 8,
            kind: IfKind::Loopback,
            up: true,
            mtu: 65536,
            mac: None,
        };
        let ifs = Ok(vec![lo, eth("192.168.0.5", 24), eth("fe80::5", 64)]);
        let routes = Ok(vec![
            Route {
                dst: "0.0.0.0".parse().unwrap(),
                prefix: 0,
                dev: "eth0".into(),
                metric: 100,
                gateway: Some("192.168.0.1".parse().unwrap()),
            },
            Route {
                dst: "fe80::".parse().unwrap(),
                prefix: 64,
                dev: "eth0".into(),
                metric: 256,
                gateway: None,
            },
            Route {
                dst: "192.168.0.0".parse().unwrap(),
                prefix: 24,
                dev: "eth0".into(),
                metric: 100,
                gateway: None,
            },
            Route {
                dst: "10.0.0.0".parse().unwrap(),
                prefix: 8,
                dev: "tun9".into(),
                metric: 0,
                gateway: None,
            },
        ]);
        let text = render(&ifs, &routes, false);
        assert_eq!(
            text,
            "\
************************INTERFACES************************
DEV  (SHORT) IP/MASK        TYPE     UP MTU   MAC
lo   (lo)    127.0.0.1/8    loopback up 65536
eth0 (eth0)  192.168.0.5/24 ethernet up 1500  00:1A:2B:3C:4D:5E
eth0 (eth0)  fe80::5/64     ethernet up 1500  00:1A:2B:3C:4D:5E

**************************ROUTES**************************
DST/MASK       DEV  METRIC GATEWAY
192.168.0.0/24 eth0 100
0.0.0.0/0      eth0 100    192.168.0.1
fe80::/64      eth0 256

"
        );
    }

    #[test]
    fn says_why_a_table_is_missing_when_debugging() {
        let none: io::Result<Vec<IfEntry>> = Err(io::Error::other("nope"));
        let routes: io::Result<Vec<Route>> = Ok(Vec::new());
        assert_eq!(
            render(&none, &routes, false),
            "INTERFACES: NONE FOUND(!)\nROUTES: NONE FOUND(!)\n"
        );
        let text = render(&none, &routes, true);
        assert!(text.contains("Reason: nope"), "{text}");
    }

    #[test]
    fn lists_this_host() {
        // Every host the tests run on has at least a loopback interface.
        if cfg!(unix) {
            let ifs = interfaces().unwrap();
            assert!(ifs.iter().any(|i| i.kind == IfKind::Loopback), "{ifs:?}");
        }
    }
}
