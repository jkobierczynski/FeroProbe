//! IPv6 neighbour discovery (NDP) for targets on a directly connected link:
//! the IPv6 counterpart of [`crate::arp`].
//!
//! A neighbour solicitation goes to the target's solicited-node multicast
//! group, and the neighbour advertisement that answers it carries the host's
//! MAC address. As with ARP, a host on the local link has to answer this to
//! be reachable at all, so its answer, or its silence, decides the host.
//!
//! Messages go out on a raw ICMPv6 socket, so this needs Linux and root (or
//! `CAP_NET_RAW`). Without them, discovery falls back to the other probes.

use std::net::Ipv6Addr;

use crate::arp::MacAddr;
use crate::target::{is_link_local, scope_of};

/// An IPv6 address of ours on an Ethernet interface, and its prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalLink {
    pub ifname: String,
    pub ifindex: u32,
    pub mac: MacAddr,
    /// Our address on the link, used as the source of solicitations.
    pub addr: Ipv6Addr,
    pub prefix: u8,
}

impl LocalLink {
    /// Whether `ip` is a neighbour on this link: a link-local address used
    /// on this interface, or an address in this (non-link-local) prefix.
    pub fn reaches(&self, ip: Ipv6Addr) -> bool {
        if ip == self.addr || ip.is_multicast() || ip.is_unspecified() {
            return false;
        }
        if is_link_local(ip) {
            return is_link_local(self.addr) && scope_of(ip) == Some(self.ifindex);
        }
        if is_link_local(self.addr) || self.prefix == 0 || self.prefix > 126 {
            return false;
        }
        let mask = u128::MAX << (128 - u32::from(self.prefix));
        u128::from(ip) & mask == u128::from(self.addr) & mask
    }
}

/// The link to reach `ip` on: for a global address, the most specific
/// matching prefix.
pub fn link_for(ip: Ipv6Addr, links: &[LocalLink]) -> Option<&LocalLink> {
    links
        .iter()
        .filter(|l| l.reaches(ip))
        .max_by_key(|l| l.prefix)
}

#[cfg(target_os = "linux")]
pub use linux::{local_links, sweep};

/// Not available on this platform: there are no links to sweep.
#[cfg(not(target_os = "linux"))]
pub fn local_links() -> std::io::Result<Vec<LocalLink>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "neighbour discovery needs Linux",
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn sweep(
    _link: &LocalLink,
    _targets: &[Ipv6Addr],
    _cfg: &crate::model::ScanConfig,
    _cancel: &std::sync::atomic::AtomicBool,
    _on_reply: &mut dyn FnMut(Ipv6Addr, Option<MacAddr>, f64),
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "neighbour discovery needs Linux",
    ))
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io;
    use std::mem::MaybeUninit;
    use std::net::{Ipv6Addr, SocketAddrV6};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use socket2::{Domain, Protocol, Socket};

    use super::LocalLink;
    use crate::arp::MacAddr;
    use crate::model::ScanConfig;
    use crate::packet::{neighbor_solicit, parse_neighbor_advert, solicited_node};
    use crate::raw::{is_idle_read, raw_socket_in, request_sweep, send_with_backoff};
    use crate::target::is_link_local;

    /// Every IPv6 address on an up Ethernet interface that resolves its
    /// neighbours.
    pub fn local_links() -> io::Result<Vec<LocalLink>> {
        let macs = crate::netif::ethernet_macs();
        Ok(crate::netif::ipv6_addrs()
            .into_iter()
            .filter(|a| a.resolves_neighbours)
            .filter_map(|a| {
                Some(LocalLink {
                    mac: *macs.get(&a.index)?,
                    ifname: a.ifname,
                    ifindex: a.index,
                    addr: a.addr,
                    prefix: a.prefix,
                })
            })
            .collect())
    }

    /// A raw ICMPv6 socket that sends from `link.addr` on its interface,
    /// with the hop limit of 255 that neighbour discovery requires.
    fn open(link: &LocalLink) -> io::Result<Socket> {
        let sock = raw_socket_in(Domain::IPV6, Protocol::ICMPV6)?;
        sock.bind_device(Some(link.ifname.as_bytes()))?;
        sock.set_multicast_if_v6(link.ifindex)?;
        sock.set_multicast_hops_v6(255)?;
        sock.set_unicast_hops_v6(255)?;
        sock.set_multicast_loop_v6(false)?;
        let scope = if is_link_local(link.addr) {
            link.ifindex
        } else {
            0
        };
        sock.bind(&SocketAddrV6::new(link.addr, 0, 0, scope).into())?;
        sock.set_read_timeout(Some(Duration::from_millis(50)))?;
        Ok(sock)
    }

    /// Solicit every address in `targets` (all on `link`), calling
    /// `on_reply` once per host that answers, with its MAC address when the
    /// advertisement gives one and its RTT in ms. Stops early when `cancel`
    /// is set.
    pub fn sweep(
        link: &LocalLink,
        targets: &[Ipv6Addr],
        cfg: &ScanConfig,
        cancel: &AtomicBool,
        on_reply: &mut dyn FnMut(Ipv6Addr, Option<MacAddr>, f64),
    ) -> io::Result<()> {
        if targets.is_empty() || cancel.load(Ordering::Relaxed) {
            return Ok(());
        }
        let sock = Arc::new(open(link)?);
        let receive = {
            let sock = Arc::clone(&sock);
            let mut buf = vec![MaybeUninit::<u8>::uninit(); 2048];
            move || -> io::Result<Option<(Ipv6Addr, Option<MacAddr>)>> {
                let n = match sock.recv(&mut buf) {
                    Ok(n) => n,
                    Err(e) if is_idle_read(&e) => return Ok(None),
                    Err(e) => return Err(e),
                };
                // SAFETY: recv initialised the first `n` bytes.
                let data = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), n) };
                Ok(parse_neighbor_advert(data))
            }
        };
        let send_one = |ip: Ipv6Addr| {
            let group = SocketAddrV6::new(solicited_node(ip), 0, 0, link.ifindex);
            send_with_backoff(&sock, &neighbor_solicit(ip, link.mac), group.into())
        };
        request_sweep(targets, cfg, cancel, send_one, receive, on_reply)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(addr: &str, prefix: u8, ifindex: u32) -> LocalLink {
        LocalLink {
            ifname: "eth0".into(),
            ifindex,
            mac: MacAddr([2, 0, 0, 0, 0, 1]),
            addr: addr.parse().unwrap(),
            prefix,
        }
    }

    #[test]
    fn picks_the_link_for_a_target() {
        let ip = |s: &str| s.parse::<Ipv6Addr>().unwrap();
        let links = [
            link("2001:db8::10", 48, 2),
            link("2001:db8:1::10", 64, 2),
            link("fe80::10", 64, 2),
        ];
        assert_eq!(link_for(ip("2001:db8:1::99"), &links).unwrap().prefix, 64);
        assert_eq!(
            link_for(ip("2001:db8:0:7::99"), &links).unwrap().addr,
            ip("2001:db8::10")
        );
        assert!(link_for(ip("2001:db9::1"), &links).is_none());
        // Not our own address, not multicast.
        assert!(link_for(ip("2001:db8:1::10"), &links).is_none());
        assert!(link_for(ip("ff02::1"), &links).is_none());
        // A /128 has no neighbours.
        assert!(!link("2001:db8::10", 128, 2).reaches(ip("2001:db8::11")));
    }

    #[tokio::test]
    async fn link_local_targets_follow_their_scope() {
        // fe80::77 is only used by this test, since scopes are process-wide.
        crate::target::resolve_targets(&["fe80::77%5"])
            .await
            .unwrap();
        let ip: Ipv6Addr = "fe80::77".parse().unwrap();
        let links = [link("fe80::10", 64, 4), link("fe80::20", 64, 5)];
        assert_eq!(link_for(ip, &links).unwrap().ifindex, 5);
        // A global address of ours never reaches link-local targets.
        assert!(!link("2001:db8::10", 64, 5).reaches(ip));
    }
}
