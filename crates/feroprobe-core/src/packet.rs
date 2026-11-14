//! Minimal builders and parsers for the packets the raw-socket scans use:
//! IPv4, TCP (SYN probes), ICMP (echo, unreachable) and ICMPv6 (echo,
//! neighbour discovery).
//!
//! Only what the scanner needs is implemented, with no external packet crate.
//! IPv6 packets never carry their IP header here: raw IPv6 sockets neither
//! take nor return it.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::arp::MacAddr;

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_ACK: u8 = 0x10;

pub const ICMP_ECHO_REPLY: u8 = 0;
pub const ICMP_DEST_UNREACH: u8 = 3;
pub const ICMP_ECHO_REQUEST: u8 = 8;

pub const ICMPV6_ECHO_REQUEST: u8 = 128;
pub const ICMPV6_ECHO_REPLY: u8 = 129;
pub const ICMPV6_NEIGHBOR_SOLICIT: u8 = 135;
pub const ICMPV6_NEIGHBOR_ADVERT: u8 = 136;

/// The Internet checksum (RFC 1071) over `data`, starting from `initial`.
pub fn checksum_with(initial: u32, data: &[u8]) -> u16 {
    let mut sum = initial;
    let (pairs, rest) = data.as_chunks::<2>();
    for pair in pairs {
        sum += u32::from(u16::from_be_bytes(*pair));
    }
    if let [last] = rest {
        sum += u32::from(*last) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn checksum(data: &[u8]) -> u16 {
    checksum_with(0, data)
}

/// Sum of the IPv4 or IPv6 pseudo-header used by TCP, UDP and ICMPv6
/// checksums. Both addresses must be of the same family.
fn pseudo_header_sum(src: IpAddr, dst: IpAddr, proto: u8, len: usize) -> u32 {
    let words = |ip: IpAddr| -> u32 {
        let bytes: Vec<u8> = match ip {
            IpAddr::V4(a) => a.octets().to_vec(),
            IpAddr::V6(a) => a.octets().to_vec(),
        };
        bytes
            .chunks(2)
            .map(|w| u32::from(u16::from_be_bytes([w[0], w[1]])))
            .sum()
    };
    // The length is 16 bits in the IPv4 pseudo-header and 32 in IPv6's;
    // summed as 16-bit words, both come to the same thing.
    words(src) + words(dst) + u32::from(proto) + (len as u32 >> 16) + (len as u32 & 0xffff)
}

/// Length of a SYN probe: 20-byte TCP header plus a 4-byte MSS option.
pub const SYN_LEN: usize = 24;

/// Build a TCP SYN segment (no IP header) with a valid checksum.
pub fn tcp_syn(
    src: impl Into<IpAddr>,
    dst: impl Into<IpAddr>,
    sport: u16,
    dport: u16,
    seq: u32,
) -> [u8; SYN_LEN] {
    let mut p = [0u8; SYN_LEN];
    p[0..2].copy_from_slice(&sport.to_be_bytes());
    p[2..4].copy_from_slice(&dport.to_be_bytes());
    p[4..8].copy_from_slice(&seq.to_be_bytes());
    // ack = 0
    p[12] = ((SYN_LEN / 4) as u8) << 4; // data offset in 32-bit words
    p[13] = TCP_SYN;
    p[14..16].copy_from_slice(&1024u16.to_be_bytes()); // window
    // checksum at 16..18, urgent pointer 18..20 = 0
    p[20..24].copy_from_slice(&[2, 4, 0x05, 0xb4]); // MSS = 1460
    let sum = checksum_with(
        pseudo_header_sum(src.into(), dst.into(), IPPROTO_TCP, SYN_LEN),
        &p,
    );
    p[16..18].copy_from_slice(&sum.to_be_bytes());
    p
}

/// Length of the OS-detection SYN: 20-byte header plus 20 bytes of options.
pub const OS_SYN_LEN: usize = 40;

/// Build a SYN that offers the common TCP options, in the order Linux
/// clients use (MSS, SACK permitted, timestamps, NOP, window scale), so the
/// reply shows which options the target supports and how it orders them.
pub fn tcp_syn_with_options(
    src: impl Into<IpAddr>,
    dst: impl Into<IpAddr>,
    sport: u16,
    dport: u16,
    seq: u32,
    tsval: u32,
) -> [u8; OS_SYN_LEN] {
    let mut p = [0u8; OS_SYN_LEN];
    p[0..2].copy_from_slice(&sport.to_be_bytes());
    p[2..4].copy_from_slice(&dport.to_be_bytes());
    p[4..8].copy_from_slice(&seq.to_be_bytes());
    p[12] = ((OS_SYN_LEN / 4) as u8) << 4;
    p[13] = TCP_SYN;
    p[14..16].copy_from_slice(&64240u16.to_be_bytes());
    p[20..24].copy_from_slice(&[2, 4, 0x05, 0xb4]); // MSS 1460
    p[24..26].copy_from_slice(&[4, 2]); // SACK permitted
    p[26..28].copy_from_slice(&[8, 10]); // timestamps: value, echo 0
    p[28..32].copy_from_slice(&tsval.to_be_bytes());
    p[36] = 1; // NOP
    p[37..40].copy_from_slice(&[3, 3, 7]); // window scale 7
    let sum = checksum_with(
        pseudo_header_sum(src.into(), dst.into(), IPPROTO_TCP, OS_SYN_LEN),
        &p,
    );
    p[16..18].copy_from_slice(&sum.to_be_bytes());
    p
}

/// The options area of a TCP header.
pub fn tcp_options(buf: &[u8]) -> &[u8] {
    let len = buf
        .get(12)
        .map_or(0, |&b| usize::from(b >> 4) * 4)
        .min(buf.len());
    buf.get(20..len).unwrap_or(&[])
}

/// A parsed IPv4 header and its payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4<'a> {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub protocol: u8,
    pub ttl: u8,
    /// The "don't fragment" flag.
    pub df: bool,
    pub payload: &'a [u8],
}

pub fn parse_ipv4(buf: &[u8]) -> Option<Ipv4<'_>> {
    if buf.len() < 20 || buf[0] >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(buf[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([buf[2], buf[3]]));
    if ihl < 20 || buf.len() < ihl {
        return None;
    }
    // Some kernels report total length differently; never read past `buf`.
    let end = if total >= ihl {
        total.min(buf.len())
    } else {
        buf.len()
    };
    Some(Ipv4 {
        src: Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]),
        dst: Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]),
        protocol: buf[9],
        ttl: buf[8],
        df: buf[6] & 0x40 != 0,
        payload: &buf[ihl..end],
    })
}

/// The TCP header fields the scanner looks at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tcp {
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
}

pub fn parse_tcp(buf: &[u8]) -> Option<Tcp> {
    if buf.len() < 20 {
        return None;
    }
    Some(Tcp {
        sport: u16::from_be_bytes([buf[0], buf[1]]),
        dport: u16::from_be_bytes([buf[2], buf[3]]),
        seq: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
        ack: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
        flags: buf[13],
        window: u16::from_be_bytes([buf[14], buf[15]]),
    })
}

/// Build an ICMP echo request with a valid checksum.
pub fn icmp_echo(id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; 8 + payload.len()];
    p[0] = ICMP_ECHO_REQUEST;
    p[4..6].copy_from_slice(&id.to_be_bytes());
    p[6..8].copy_from_slice(&seq.to_be_bytes());
    p[8..].copy_from_slice(payload);
    let sum = checksum(&p);
    p[2..4].copy_from_slice(&sum.to_be_bytes());
    p
}

/// Build an ICMPv6 echo request. The checksum is left at zero: it covers
/// the IPv6 source address, so the kernel fills it in on ICMPv6 sockets.
pub fn icmpv6_echo(id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut p = icmp_echo(id, seq, payload);
    p[0] = ICMPV6_ECHO_REQUEST;
    p[2..4].copy_from_slice(&[0, 0]);
    p
}

/// The solicited-node multicast group of `addr` (`ff02::1:ffXX:XXXX`),
/// where a neighbour solicitation for it is sent.
pub fn solicited_node(addr: Ipv6Addr) -> Ipv6Addr {
    let o = addr.octets();
    Ipv6Addr::from([
        0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, o[13], o[14], o[15],
    ])
}

/// Length of a neighbour solicitation with a source link-layer option.
pub const NEIGHBOR_SOLICIT_LEN: usize = 32;

/// Build a neighbour solicitation asking for `target`'s link-layer address,
/// giving ours (`src_mac`) so the answer can come straight back. As with
/// echo, the kernel fills in the checksum.
pub fn neighbor_solicit(target: Ipv6Addr, src_mac: MacAddr) -> [u8; NEIGHBOR_SOLICIT_LEN] {
    let mut p = [0u8; NEIGHBOR_SOLICIT_LEN];
    p[0] = ICMPV6_NEIGHBOR_SOLICIT;
    // code, checksum and reserved stay zero
    p[8..24].copy_from_slice(&target.octets());
    p[24] = 1; // source link-layer address option
    p[25] = 1; // length in units of 8 bytes
    p[26..32].copy_from_slice(&src_mac.0);
    p
}

/// Parse a neighbour advertisement: the address it is about and, when
/// given, that address's link-layer address.
pub fn parse_neighbor_advert(buf: &[u8]) -> Option<(Ipv6Addr, Option<MacAddr>)> {
    if buf.len() < 24 || buf[0] != ICMPV6_NEIGHBOR_ADVERT || buf[1] != 0 {
        return None;
    }
    let target = Ipv6Addr::from(<[u8; 16]>::try_from(&buf[8..24]).ok()?);
    let mut mac = None;
    let mut opts = &buf[24..];
    while opts.len() >= 8 {
        let len = usize::from(opts[1]) * 8;
        if len == 0 || len > opts.len() {
            break;
        }
        // Target link-layer address, for Ethernet.
        if opts[0] == 2 && len >= 8 {
            mac = Some(MacAddr(<[u8; 6]>::try_from(&opts[2..8]).ok()?));
        }
        opts = &opts[len..];
    }
    Some((target, mac))
}

/// A parsed ICMP message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Icmp<'a> {
    pub kind: u8,
    pub code: u8,
    /// Identifier and sequence for echo messages (bytes 4..8).
    pub id: u16,
    pub seq: u16,
    /// For errors: the start of the original datagram that caused them.
    pub body: &'a [u8],
}

pub fn parse_icmp(buf: &[u8]) -> Option<Icmp<'_>> {
    if buf.len() < 8 {
        return None;
    }
    Some(Icmp {
        kind: buf[0],
        code: buf[1],
        id: u16::from_be_bytes([buf[4], buf[5]]),
        seq: u16::from_be_bytes([buf[6], buf[7]]),
        body: &buf[8..],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_rfc1071_example() {
        // Example from RFC 1071 section 3: sum 0xddf2, checksum is its complement.
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(checksum(&data), !0xddf2);
        // Odd length pads with a zero byte.
        assert_eq!(checksum(&[0xff]), !0xff00);
    }

    #[test]
    fn syn_round_trip_and_checksum() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let seg = tcp_syn(src, dst, 40000, 443, 0xdead_beef);
        let tcp = parse_tcp(&seg).unwrap();
        assert_eq!(
            tcp,
            Tcp {
                sport: 40000,
                dport: 443,
                seq: 0xdead_beef,
                ack: 0,
                flags: TCP_SYN,
                window: 1024,
            }
        );
        // A correct checksum makes the sum over pseudo-header + segment zero.
        assert_eq!(
            checksum_with(
                pseudo_header_sum(src.into(), dst.into(), IPPROTO_TCP, SYN_LEN),
                &seg
            ),
            0
        );
    }

    #[test]
    fn os_syn_options() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let seg = tcp_syn_with_options(src, dst, 40000, 22, 7, 0x0102_0304);
        let opts = tcp_options(&seg);
        assert_eq!(opts.len(), 20);
        assert_eq!(&opts[..8], &[2, 4, 5, 0xb4, 4, 2, 8, 10]);
        assert_eq!(&opts[16..], &[1, 3, 3, 7]);
        assert_eq!(parse_tcp(&seg).unwrap().window, 64240);
        assert_eq!(
            checksum_with(
                pseudo_header_sum(src.into(), dst.into(), IPPROTO_TCP, OS_SYN_LEN),
                &seg
            ),
            0
        );
        assert!(tcp_options(&seg[..10]).is_empty());
    }

    #[test]
    fn parse_ipv4_header() {
        let mut pkt = vec![
            0x45,
            0,
            0,
            28,
            0,
            0,
            0,
            0,
            64,
            IPPROTO_ICMP,
            0,
            0,
            192,
            168,
            1,
            1,
            192,
            168,
            1,
            2,
        ];
        pkt.extend_from_slice(&icmp_echo(7, 9, &[]));
        let ip = parse_ipv4(&pkt).unwrap();
        assert_eq!(ip.src, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(ip.dst, Ipv4Addr::new(192, 168, 1, 2));
        assert_eq!(ip.protocol, IPPROTO_ICMP);
        assert_eq!((ip.ttl, ip.df), (64, false));
        let icmp = parse_icmp(ip.payload).unwrap();
        assert_eq!((icmp.kind, icmp.id, icmp.seq), (ICMP_ECHO_REQUEST, 7, 9));
        assert_eq!(checksum(ip.payload), 0);

        assert!(parse_ipv4(&pkt[..10]).is_none());
        assert!(parse_ipv4(&[0x60; 40]).is_none()); // IPv6
    }

    #[test]
    fn ipv6_syn_checksum() {
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let p = tcp_syn(src, dst, 40000, 443, 7);
        // Summing the pseudo-header and the segment, checksum included,
        // gives all ones (a zero result once inverted).
        let total = checksum_with(
            pseudo_header_sum(src.into(), dst.into(), IPPROTO_TCP, p.len()),
            &p,
        );
        assert_eq!(total, 0);
        assert_eq!(parse_tcp(&p).unwrap().dport, 443);
        // A different address family gives a different checksum.
        let v4 = tcp_syn(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, 40000, 443, 7);
        assert_ne!(v4[16..18], p[16..18]);
    }

    #[test]
    fn icmpv6_echo_layout() {
        let p = icmpv6_echo(0x1234, 5, b"x");
        assert_eq!(&p[..8], &[128, 0, 0, 0, 0x12, 0x34, 0, 5]);
        assert_eq!(&p[8..], b"x");
    }

    #[test]
    fn neighbour_discovery() {
        let target: Ipv6Addr = "fe80::1234:5678:9abc".parse().unwrap();
        assert_eq!(
            solicited_node(target),
            "ff02::1:ff78:9abc".parse::<Ipv6Addr>().unwrap()
        );
        let mac = MacAddr([2, 0, 0, 0, 0, 9]);
        let ns = neighbor_solicit(target, mac);
        assert_eq!(ns[0], 135);
        assert_eq!(&ns[8..24], &target.octets());
        assert_eq!(&ns[24..32], &[1, 1, 2, 0, 0, 0, 0, 9]);

        // An advertisement: solicited + override flags, then a nonce-like
        // unknown option the parser must skip, then the target's MAC.
        let mut na = vec![136, 0, 0, 0, 0x60, 0, 0, 0];
        na.extend_from_slice(&target.octets());
        na.extend_from_slice(&[14, 1, 1, 2, 3, 4, 5, 6]);
        na.extend_from_slice(&[2, 1, 0x00, 0x50, 0x56, 1, 2, 3]);
        assert_eq!(
            parse_neighbor_advert(&na),
            Some((target, Some(MacAddr([0x00, 0x50, 0x56, 1, 2, 3]))))
        );
        // Without the option, the address alone.
        assert_eq!(parse_neighbor_advert(&na[..24]), Some((target, None)));
        // Other messages and broken options.
        assert_eq!(parse_neighbor_advert(&ns), None);
        let mut bad = na.clone();
        bad[25] = 0;
        assert_eq!(parse_neighbor_advert(&bad), Some((target, None)));
    }
}
