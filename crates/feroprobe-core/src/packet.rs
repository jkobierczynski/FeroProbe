//! Minimal builders and parsers for the packets the raw-socket scans use:
//! IPv4, TCP (SYN probes) and ICMP (echo, unreachable).
//!
//! Only what the scanner needs is implemented, with no external packet crate.

use std::net::Ipv4Addr;

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_ACK: u8 = 0x10;

pub const ICMP_ECHO_REPLY: u8 = 0;
pub const ICMP_DEST_UNREACH: u8 = 3;
pub const ICMP_ECHO_REQUEST: u8 = 8;

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

/// Sum of the IPv4 pseudo-header used by TCP and UDP checksums.
fn pseudo_header_sum(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, len: usize) -> u32 {
    let s = src.octets();
    let d = dst.octets();
    u32::from(u16::from_be_bytes([s[0], s[1]]))
        + u32::from(u16::from_be_bytes([s[2], s[3]]))
        + u32::from(u16::from_be_bytes([d[0], d[1]]))
        + u32::from(u16::from_be_bytes([d[2], d[3]]))
        + u32::from(proto)
        + len as u32
}

/// Length of a SYN probe: 20-byte TCP header plus a 4-byte MSS option.
pub const SYN_LEN: usize = 24;

/// Build a TCP SYN segment (no IP header) with a valid checksum.
pub fn tcp_syn(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, seq: u32) -> [u8; SYN_LEN] {
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
    let sum = checksum_with(pseudo_header_sum(src, dst, IPPROTO_TCP, SYN_LEN), &p);
    p[16..18].copy_from_slice(&sum.to_be_bytes());
    p
}

/// A parsed IPv4 header and its payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4<'a> {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub protocol: u8,
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
                flags: TCP_SYN
            }
        );
        // A correct checksum makes the sum over pseudo-header + segment zero.
        assert_eq!(
            checksum_with(pseudo_header_sum(src, dst, IPPROTO_TCP, SYN_LEN), &seg),
            0
        );
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
        let icmp = parse_icmp(ip.payload).unwrap();
        assert_eq!((icmp.kind, icmp.id, icmp.seq), (ICMP_ECHO_REQUEST, 7, 9));
        assert_eq!(checksum(ip.payload), 0);

        assert!(parse_ipv4(&pkt[..10]).is_none());
        assert!(parse_ipv4(&[0x60; 40]).is_none()); // IPv6
    }
}
