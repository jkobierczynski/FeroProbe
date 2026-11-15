//! Address scope classification for the anti-abuse safeguards.
//!
//! FeroProbe's evasion options (packet fragmentation, decoys and a spoofed
//! source address) are only allowed against private address ranges, where
//! their legitimate use is testing your own firewall or intrusion-detection
//! system. For any public target they are refused. This module decides what
//! counts as private.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Whether `ip` is in a private / local range, so evasion options may be
/// used against it. This covers the ranges whose traffic never crosses the
/// public internet:
///
/// IPv4: RFC 1918 private (`10/8`, `172.16/12`, `192.168/16`), loopback
/// (`127/8`), link-local (`169.254/16`) and carrier-grade NAT (`100.64/10`,
/// RFC 6598).
///
/// IPv6: loopback (`::1`), unique-local (`fc00::/7`, RFC 4193) and
/// link-local (`fe80::/10`). An IPv4-mapped IPv6 address is judged by its
/// embedded IPv4 address.
pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_v4(v4),
        IpAddr::V6(v6) => is_private_v6(v6),
    }
}

fn is_private_v4(ip: Ipv4Addr) -> bool {
    ip.is_private()            // 10/8, 172.16/12, 192.168/16
        || ip.is_loopback()   // 127/8
        || ip.is_link_local() // 169.254/16
        || is_cgnat(ip) // 100.64/10 (RFC 6598)
}

/// Carrier-grade NAT space, `100.64.0.0/10` (RFC 6598). `Ipv4Addr` has no
/// stable method for it, so it is matched by hand.
fn is_cgnat(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    a == 100 && (64..=127).contains(&b)
}

fn is_private_v6(ip: Ipv6Addr) -> bool {
    if ip.is_loopback() {
        return true;
    }
    // An IPv4-mapped address (::ffff:a.b.c.d) is really IPv4 traffic.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_private_v4(v4);
    }
    let first = ip.segments()[0];
    // Unique-local fc00::/7 and link-local fe80::/10.
    (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
}

/// The first target address that is **not** private, if any. Returned so a
/// refusal can name the address that is out of scope.
pub fn first_public<'a, I>(addrs: I) -> Option<IpAddr>
where
    I: IntoIterator<Item = &'a IpAddr>,
{
    addrs.into_iter().copied().find(|ip| !is_private(*ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn private_v4_ranges() {
        for s in [
            "10.0.0.1",
            "10.255.255.255",
            "172.16.5.4",
            "172.31.0.1",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.3.2",
            "100.64.0.1",
            "100.127.255.254",
        ] {
            assert!(is_private(ip(s)), "{s} should be private");
        }
    }

    #[test]
    fn public_v4_ranges() {
        for s in [
            "8.8.8.8",
            "1.1.1.1",
            "172.32.0.1",     // just past 172.16/12
            "100.63.255.255", // just before 100.64/10
            "100.128.0.0",    // just past 100.64/10
            "192.167.0.1",
            "11.0.0.1",
        ] {
            assert!(!is_private(ip(s)), "{s} should be public");
        }
    }

    #[test]
    fn private_v6_ranges() {
        for s in [
            "::1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(is_private(ip(s)), "{s} should be private");
        }
    }

    #[test]
    fn public_v6_ranges() {
        for s in ["2001:db8::1", "2606:4700:4700::1111", "::ffff:8.8.8.8"] {
            assert!(!is_private(ip(s)), "{s} should be public");
        }
    }

    #[test]
    fn first_public_finds_the_outlier() {
        let addrs = [ip("10.0.0.1"), ip("192.168.0.2"), ip("8.8.8.8")];
        assert_eq!(first_public(&addrs), Some(ip("8.8.8.8")));
        let all_private = [ip("10.0.0.1"), ip("fd00::1")];
        assert_eq!(first_public(&all_private), None);
    }
}
