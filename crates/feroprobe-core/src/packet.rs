//! Minimal builders and parsers for the packets the raw-socket scans use:
//! IPv4, IPv6, TCP (SYN probes), UDP, SCTP, IGMP, ICMP (echo, unreachable)
//! and ICMPv6 (echo, neighbour discovery).
//!
//! Only what the scanner needs is implemented, with no external packet crate.
//! Raw IPv6 sockets neither take nor return the IPv6 header, so the
//! builders leave it out; [`parse_ipv6`] reads packets captured whole.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::arp::MacAddr;

/// Payload of the ICMP and ICMPv6 echo requests FeroProbe sends for host
/// discovery: part of the probe signature (docs/responsible-use.md). nmap's
/// echo is empty. The IP protocol scan (`-sO`) sends an empty echo, like nmap.
pub const ECHO_MARKER: &[u8] = b"feroprobe";

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;
pub const TCP_URG: u8 = 0x20;
pub const TCP_ECE: u8 = 0x40;
pub const TCP_CWR: u8 = 0x80;

// --- Recognizable probe signature ------------------------------------------
//
// FeroProbe deliberately marks its own scan traffic so the owner of a
// scanned network can tell a FeroProbe scan apart from other traffic. This
// is a deliberate exception to nmap parity. The marks are documented in
// `docs/responsible-use.md`, and the repository ships Suricata and Snort
// rules (`rules/`) that match them.

/// The TCP window value FeroProbe writes on its raw-socket TCP scan probes
/// (SYN, FIN, NULL, Xmas, ACK, Window, Maimon). The window of a scan probe
/// is otherwise meaningless — the scan never completes a handshake — so a
/// fixed, unusual value is a reliable marker that does not change how the
/// probe behaves or how the target answers it.
pub const PROBE_WINDOW: u16 = 0xFE55;

/// The payload FeroProbe puts in UDP probes that have no protocol-specific
/// payload of their own, as a recognizable marker. Protocol probes (DNS,
/// NTP, SNMP, SSDP, …) keep their own payloads, which are already
/// identifiable as the standard probe for that service.
pub const UDP_MARKER: &[u8] = b"FeroProbeScan/1\n";

pub const ICMP_ECHO_REPLY: u8 = 0;
pub const ICMP_DEST_UNREACH: u8 = 3;
pub const ICMP_TIME_EXCEEDED: u8 = 11;
pub const ICMP_ECHO_REQUEST: u8 = 8;
pub const ICMP_TIMESTAMP: u8 = 13;
pub const ICMP_TIMESTAMP_REPLY: u8 = 14;
pub const ICMP_ADDRESS_MASK: u8 = 17;
pub const ICMP_ADDRESS_MASK_REPLY: u8 = 18;

pub const ICMPV6_DEST_UNREACH: u8 = 1;
pub const ICMPV6_TIME_EXCEEDED: u8 = 3;
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
pub(crate) fn pseudo_header_sum(src: IpAddr, dst: IpAddr, proto: u8, len: usize) -> u32 {
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
    p[14..16].copy_from_slice(&PROBE_WINDOW.to_be_bytes()); // window: FeroProbe marker
    // checksum at 16..18, urgent pointer 18..20 = 0
    p[20..24].copy_from_slice(&[2, 4, 0x05, 0xb4]); // MSS = 1460
    let sum = checksum_with(
        pseudo_header_sum(src.into(), dst.into(), IPPROTO_TCP, SYN_LEN),
        &p,
    );
    p[16..18].copy_from_slice(&sum.to_be_bytes());
    p
}

/// Length of a bare TCP probe: a 20-byte header without options.
pub const TCP_PROBE_LEN: usize = 20;

/// Build a TCP segment (no IP header) with any flags, as the FIN, NULL,
/// Xmas, ACK, Window and Maimon scans send, with a valid checksum.
pub fn tcp_probe(
    src: impl Into<IpAddr>,
    dst: impl Into<IpAddr>,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
) -> [u8; TCP_PROBE_LEN] {
    let mut p = [0u8; TCP_PROBE_LEN];
    p[0..2].copy_from_slice(&sport.to_be_bytes());
    p[2..4].copy_from_slice(&dport.to_be_bytes());
    p[4..8].copy_from_slice(&seq.to_be_bytes());
    p[8..12].copy_from_slice(&ack.to_be_bytes());
    p[12] = ((TCP_PROBE_LEN / 4) as u8) << 4;
    p[13] = flags;
    p[14..16].copy_from_slice(&PROBE_WINDOW.to_be_bytes()); // FeroProbe marker
    let sum = checksum_with(
        pseudo_header_sum(src.into(), dst.into(), IPPROTO_TCP, TCP_PROBE_LEN),
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
    /// The identification field, which idle scans read.
    pub id: u16,
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
        id: u16::from_be_bytes([buf[4], buf[5]]),
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

/// Build an ICMP query of type `kind` (timestamp or address mask request)
/// with `body_len` zero bytes after the identifier and sequence number, and
/// a valid checksum.
pub fn icmp_query(kind: u8, id: u16, seq: u16, body_len: usize) -> Vec<u8> {
    let mut p = icmp_echo(id, seq, &vec![0; body_len]);
    p[0] = kind;
    p[2..4].copy_from_slice(&[0, 0]);
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

/// An ICMP or ICMPv6 error about a TCP segment we sent, with the fields
/// of that segment the error quotes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpTcpError {
    /// ICMP type and code (IPv4 or IPv6 numbering).
    pub kind: u8,
    pub code: u8,
    /// Who sent the error, for IPv4 (from the outer IP header). Raw ICMPv6
    /// sockets return the message alone: take the sender from `recv_from`.
    pub src: Option<IpAddr>,
    /// The quoted segment's destination, ports and sequence number.
    pub dst: IpAddr,
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
}

/// Parse an ICMP error quoting a TCP segment. `data` is what a raw ICMP
/// socket returns: the IPv4 header and message, or for ICMPv6 the message
/// alone. Echo replies and other non-errors give `None`.
pub fn parse_icmp_tcp_error(data: &[u8], v6: bool) -> Option<IcmpTcpError> {
    let (src, msg) = if v6 {
        (None, data)
    } else {
        let ip = parse_ipv4(data)?;
        if ip.protocol != IPPROTO_ICMP {
            return None;
        }
        (Some(IpAddr::V4(ip.src)), ip.payload)
    };
    let icmp = parse_icmp(msg)?;
    let error = if v6 {
        matches!(icmp.kind, ICMPV6_DEST_UNREACH | ICMPV6_TIME_EXCEEDED)
    } else {
        matches!(icmp.kind, ICMP_DEST_UNREACH | ICMP_TIME_EXCEEDED)
    };
    if !error {
        return None;
    }
    // The quoted packet: its IP header, then at least 8 bytes of TCP.
    let b = icmp.body;
    let (dst, tcp): (IpAddr, &[u8]) = if v6 {
        if b.len() < 48 || b[0] >> 4 != 6 || b[6] != IPPROTO_TCP {
            return None;
        }
        let dst: [u8; 16] = b[24..40].try_into().ok()?;
        (Ipv6Addr::from(dst).into(), &b[40..])
    } else {
        if b.len() < 20 || b[0] >> 4 != 4 || b[9] != IPPROTO_TCP {
            return None;
        }
        let ihl = usize::from(b[0] & 0x0f) * 4;
        (
            Ipv4Addr::new(b[16], b[17], b[18], b[19]).into(),
            b.get(ihl..)?,
        )
    };
    if tcp.len() < 8 {
        return None;
    }
    Some(IcmpTcpError {
        kind: icmp.kind,
        code: icmp.code,
        src,
        dst,
        sport: u16::from_be_bytes([tcp[0], tcp[1]]),
        dport: u16::from_be_bytes([tcp[2], tcp[3]]),
        seq: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
    })
}

pub const IPPROTO_IGMP: u8 = 2;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_ICMPV6: u8 = 58;
pub const IPPROTO_SCTP: u8 = 132;

/// ICMPv6 "parameter problem", which -sO reads like ICMP's unreachables.
pub const ICMPV6_PARAM_PROBLEM: u8 = 4;

/// SCTP chunk types the SCTP scans send or read (RFC 9260).
pub const SCTP_INIT: u8 = 1;
pub const SCTP_INIT_ACK: u8 = 2;
pub const SCTP_ABORT: u8 = 6;
pub const SCTP_COOKIE_ECHO: u8 = 10;

/// CRC32c (Castagnoli), the checksum of SCTP (RFC 9260 appendix A).
pub fn crc32c(data: &[u8]) -> u32 {
    const TABLE: [u32; 256] = {
        let mut table = [0u32; 256];
        let mut i = 0;
        while i < 256 {
            let mut c = i as u32;
            let mut k = 0;
            while k < 8 {
                c = if c & 1 != 0 {
                    (c >> 1) ^ 0x82f6_3b78
                } else {
                    c >> 1
                };
                k += 1;
            }
            table[i] = c;
            i += 1;
        }
        table
    };
    !data.iter().fold(!0u32, |crc, &b| {
        TABLE[usize::from((crc as u8) ^ b)] ^ (crc >> 8)
    })
}

/// An SCTP packet (no IP header) of one chunk, with its checksum. The
/// CRC32c goes in little-endian byte order, as RFC 9260 appendix A and
/// every real stack have it.
fn sctp_packet(sport: u16, dport: u16, vtag: u32, chunk: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(12 + chunk.len());
    p.extend_from_slice(&sport.to_be_bytes());
    p.extend_from_slice(&dport.to_be_bytes());
    p.extend_from_slice(&vtag.to_be_bytes());
    p.extend_from_slice(&[0; 4]);
    p.extend_from_slice(chunk);
    let crc = crc32c(&p);
    p[8..12].copy_from_slice(&crc.to_le_bytes());
    p
}

/// An SCTP INIT, as `-sY` sends: verification tag 0 (RFC 9260 requires
/// it for INIT), our initiate tag `itag`, a 32 KiB window, 10 outbound and
/// 2048 inbound streams, and initial TSN `tsn`.
pub fn sctp_init(sport: u16, dport: u16, itag: u32, tsn: u32) -> Vec<u8> {
    let mut chunk = [0u8; 20];
    chunk[0] = SCTP_INIT;
    chunk[2..4].copy_from_slice(&20u16.to_be_bytes());
    chunk[4..8].copy_from_slice(&itag.to_be_bytes());
    chunk[8..12].copy_from_slice(&32768u32.to_be_bytes());
    chunk[12..14].copy_from_slice(&10u16.to_be_bytes());
    chunk[14..16].copy_from_slice(&2048u16.to_be_bytes());
    chunk[16..20].copy_from_slice(&tsn.to_be_bytes());
    sctp_packet(sport, dport, 0, &chunk)
}

/// An SCTP COOKIE ECHO with a made-up 4-byte cookie, as `-sZ` sends. No
/// association matches its tag `vtag`, so an open port drops it silently
/// while a closed one answers with an ABORT.
pub fn sctp_cookie_echo(sport: u16, dport: u16, vtag: u32, cookie: u32) -> Vec<u8> {
    let mut chunk = [0u8; 8];
    chunk[0] = SCTP_COOKIE_ECHO;
    chunk[2..4].copy_from_slice(&8u16.to_be_bytes());
    chunk[4..8].copy_from_slice(&cookie.to_be_bytes());
    sctp_packet(sport, dport, vtag, &chunk)
}

/// The SCTP fields the scanner looks at: ports, verification tag and the
/// type of the first chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sctp {
    pub sport: u16,
    pub dport: u16,
    pub vtag: u32,
    pub chunk: u8,
}

pub fn parse_sctp(buf: &[u8]) -> Option<Sctp> {
    if buf.len() < 16 {
        return None;
    }
    Some(Sctp {
        sport: u16::from_be_bytes([buf[0], buf[1]]),
        dport: u16::from_be_bytes([buf[2], buf[3]]),
        vtag: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
        chunk: buf[12],
    })
}

/// A UDP datagram (no IP header) with a valid checksum.
pub fn udp_packet(src: IpAddr, dst: IpAddr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let len = 8 + payload.len();
    let mut p = Vec::with_capacity(len);
    p.extend_from_slice(&sport.to_be_bytes());
    p.extend_from_slice(&dport.to_be_bytes());
    p.extend_from_slice(&(len as u16).to_be_bytes());
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(payload);
    let mut sum = checksum_with(pseudo_header_sum(src, dst, IPPROTO_UDP, len), &p);
    // Zero means "no checksum" in UDP; all ones is the same value.
    if sum == 0 {
        sum = 0xffff;
    }
    p[6..8].copy_from_slice(&sum.to_be_bytes());
    p
}

/// An IGMP membership query (type 0x11) for all groups.
pub fn igmp_query() -> [u8; 8] {
    let mut p = [0x11, 0, 0, 0, 0, 0, 0, 0];
    let sum = checksum(&p);
    p[2..4].copy_from_slice(&sum.to_be_bytes());
    p
}

/// An ICMPv6 echo request with its checksum, which (unlike ICMP's)
/// covers the IPv6 pseudo-header. Raw ICMPv6 sockets fill it in
/// themselves; other sockets need it done.
pub fn icmpv6_echo_with_checksum(src: Ipv6Addr, dst: Ipv6Addr, id: u16, seq: u16) -> Vec<u8> {
    let mut p = icmpv6_echo(id, seq, &[]);
    p[2..4].copy_from_slice(&[0, 0]);
    let sum = checksum_with(
        pseudo_header_sum(src.into(), dst.into(), IPPROTO_ICMPV6, p.len()),
        &p,
    );
    p[2..4].copy_from_slice(&sum.to_be_bytes());
    p
}

/// An IPv4 packet around `payload`, for sockets where we write the IP
/// header ourselves (`IPPROTO_RAW`): no options, "don't fragment" clear.
pub fn ipv4_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: u8,
    ttl: u8,
    id: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut p = Vec::with_capacity(total);
    p.push(0x45);
    p.push(0);
    p.extend_from_slice(&(total as u16).to_be_bytes());
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&[0, 0]);
    p.push(ttl);
    p.push(protocol);
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    let sum = checksum(&p);
    p[10..12].copy_from_slice(&sum.to_be_bytes());
    p.extend_from_slice(payload);
    p
}

/// An IPv6 packet around `payload`, for sockets where we write the IP
/// header ourselves (`IPPROTO_RAW`): no extension headers, flow label 0.
pub fn ipv6_packet(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    next_header: u8,
    hop_limit: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut p = Vec::with_capacity(40 + payload.len());
    p.extend_from_slice(&[0x60, 0, 0, 0]);
    p.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    p.push(next_header);
    p.push(hop_limit);
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    p.extend_from_slice(payload);
    p
}

/// A parsed IPv6 packet: addresses, the protocol of its payload after any
/// extension headers, and that payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6<'a> {
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub protocol: u8,
    pub hop_limit: u8,
    pub payload: &'a [u8],
}

/// Parse an IPv6 packet with its header, skipping the hop-by-hop,
/// routing, fragment and destination options headers.
pub fn parse_ipv6(buf: &[u8]) -> Option<Ipv6<'_>> {
    if buf.len() < 40 || buf[0] >> 4 != 6 {
        return None;
    }
    let len = usize::from(u16::from_be_bytes([buf[4], buf[5]]));
    let end = (40 + len).min(buf.len());
    let mut next = buf[6];
    let mut at = 40;
    loop {
        let skip = match next {
            0 | 43 | 60 => usize::from(*buf.get(at + 1)?) * 8 + 8,
            44 => {
                // A fragment header is a fixed 8 bytes. Only the first
                // fragment (offset 0) holds the start of the transport
                // header; a later fragment's payload is not one, so refuse
                // to hand it on as such rather than misparse it.
                let frag = u16::from_be_bytes([*buf.get(at + 2)?, *buf.get(at + 3)?]);
                if frag & 0xfff8 != 0 {
                    return None;
                }
                8
            }
            _ => break,
        };
        next = *buf.get(at)?;
        at += skip;
        if at > end {
            return None;
        }
    }
    let src: [u8; 16] = buf[8..24].try_into().ok()?;
    let dst: [u8; 16] = buf[24..40].try_into().ok()?;
    Some(Ipv6 {
        src: src.into(),
        dst: dst.into(),
        protocol: next,
        hop_limit: buf[7],
        payload: &buf[at..end],
    })
}

/// An ICMP or ICMPv6 error, with the packet it quotes: that packet's IP
/// protocol and destination, and the start of its payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpError<'a> {
    /// ICMP type and code (IPv4 or IPv6 numbering).
    pub kind: u8,
    pub code: u8,
    pub protocol: u8,
    pub dst: IpAddr,
    /// The quoted IPv4 packet's identification field, by which a probe with
    /// a fixed IP id can be told from other traffic to the same host;
    /// `None` for IPv6, which has no such field in its base header.
    pub id: Option<u16>,
    /// The quoted packet's payload: at least its first 8 bytes when the
    /// sender followed RFC 792; may be empty.
    pub quoted: &'a [u8],
}

/// Parse an ICMP (`v6` false) or ICMPv6 message, without its IP header,
/// as an error about a packet we sent: destination unreachable or time
/// exceeded, and for ICMPv6 also parameter problem.
pub fn parse_icmp_error(msg: &[u8], v6: bool) -> Option<IcmpError<'_>> {
    let icmp = parse_icmp(msg)?;
    let error = if v6 {
        matches!(
            icmp.kind,
            ICMPV6_DEST_UNREACH | ICMPV6_TIME_EXCEEDED | ICMPV6_PARAM_PROBLEM
        )
    } else {
        matches!(icmp.kind, ICMP_DEST_UNREACH | ICMP_TIME_EXCEEDED)
    };
    if !error {
        return None;
    }
    let b = icmp.body;
    let (protocol, dst, id, quoted): (u8, IpAddr, Option<u16>, &[u8]) = if v6 {
        // The quote may be cut short anywhere, so do not insist on a
        // complete packet: only the fixed header.
        if b.len() < 40 || b[0] >> 4 != 6 {
            return None;
        }
        let dst: [u8; 16] = b[24..40].try_into().ok()?;
        (b[6], Ipv6Addr::from(dst).into(), None, &b[40..])
    } else {
        if b.len() < 20 || b[0] >> 4 != 4 {
            return None;
        }
        let ihl = usize::from(b[0] & 0x0f) * 4;
        (
            b[9],
            Ipv4Addr::new(b[16], b[17], b[18], b[19]).into(),
            Some(u16::from_be_bytes([b[4], b[5]])),
            b.get(ihl..).unwrap_or(&[]),
        )
    };
    Some(IcmpError {
        kind: icmp.kind,
        code: icmp.code,
        protocol,
        dst,
        id,
        quoted,
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
                window: PROBE_WINDOW,
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
    fn tcp_probe_any_flags() {
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let flags = TCP_FIN | TCP_PSH | TCP_URG;
        let seg = tcp_probe(src, dst, 40001, 80, 11, 22, flags);
        let tcp = parse_tcp(&seg).unwrap();
        assert_eq!((tcp.seq, tcp.ack, tcp.flags), (11, 22, flags));
        assert_eq!(tcp.window, PROBE_WINDOW);
        assert!(tcp_options(&seg).is_empty());
        assert_eq!(
            checksum_with(
                pseudo_header_sum(src.into(), dst.into(), IPPROTO_TCP, TCP_PROBE_LEN),
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

    #[test]
    fn crc32c_check_value() {
        // The standard check value of CRC-32C.
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
    }

    #[test]
    fn sctp_packets_round_trip() {
        let init = sctp_init(40000, 2905, 7, 9);
        assert_eq!(init.len(), 32);
        let s = parse_sctp(&init).unwrap();
        assert_eq!(
            (s.sport, s.dport, s.vtag, s.chunk),
            (40000, 2905, 0, SCTP_INIT)
        );
        // The checksum covers the packet with the field zeroed.
        let mut zeroed = init.clone();
        zeroed[8..12].copy_from_slice(&[0; 4]);
        assert_eq!(crc32c(&zeroed).to_le_bytes(), init[8..12]);
        let echo = sctp_cookie_echo(40000, 80, 0x1234_5678, 1);
        let s = parse_sctp(&echo).unwrap();
        assert_eq!((s.vtag, s.chunk), (0x1234_5678, SCTP_COOKIE_ECHO));
    }

    #[test]
    fn ipv4_packet_has_a_valid_header() {
        let src = Ipv4Addr::new(192, 168, 1, 5);
        let dst = Ipv4Addr::new(192, 168, 1, 9);
        let pkt = ipv4_packet(src, dst, 47, 64, 0x4242, &[1, 2, 3]);
        assert_eq!(checksum(&pkt[..20]), 0);
        let ip = parse_ipv4(&pkt).unwrap();
        assert_eq!((ip.src, ip.dst, ip.protocol, ip.id), (src, dst, 47, 0x4242));
        assert_eq!(ip.payload, &[1, 2, 3]);
    }

    #[test]
    fn udp_packet_checksum_verifies() {
        let (src, dst): (IpAddr, IpAddr) =
            ("10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap());
        let p = udp_packet(src, dst, 40000, 40125, b"x");
        assert_eq!(
            checksum_with(pseudo_header_sum(src, dst, IPPROTO_UDP, p.len()), &p),
            0
        );
    }

    #[test]
    fn ipv6_extension_headers_are_skipped() {
        // Fixed header Next Header = 44 (fragment); `frag_hi` is the top
        // byte of the fragment header's offset/flags word.
        let pkt = |frag_hi: u8| {
            let mut pkt = vec![0x60, 0, 0, 0, 0, 16, 44, 64];
            pkt.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
            pkt.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
            // Fragment header (next = UDP, M flag set), then 8 bytes of UDP.
            pkt.extend_from_slice(&[IPPROTO_UDP, 0, frag_hi, 1, 0, 0, 0, 7]);
            pkt.extend_from_slice(&[0, 53, 0x9c, 0x40, 0, 8, 0, 0]);
            pkt
        };
        // The first fragment (offset 0) carries the transport header.
        let first = pkt(0);
        let ip = parse_ipv6(&first).unwrap();
        assert_eq!(ip.protocol, IPPROTO_UDP);
        assert_eq!(ip.payload.len(), 8);
        // A later fragment (nonzero offset) does not, so it is refused
        // rather than read as a transport header.
        assert!(parse_ipv6(&pkt(0x08)).is_none());
    }

    #[test]
    fn icmp_errors_quote_any_protocol() {
        let quoted = ipv4_packet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            47,
            64,
            1,
            &[],
        );
        let mut msg = vec![ICMP_DEST_UNREACH, 2, 0, 0, 0, 0, 0, 0];
        msg.extend_from_slice(&quoted);
        let e = parse_icmp_error(&msg, false).unwrap();
        assert_eq!((e.kind, e.code, e.protocol), (ICMP_DEST_UNREACH, 2, 47));
        assert_eq!(e.dst, IpAddr::from(Ipv4Addr::new(10, 0, 0, 2)));
        assert!(e.quoted.is_empty());
        // An echo reply is no error.
        assert!(parse_icmp_error(&icmp_echo(1, 1, &[]), false).is_none());
    }
}
