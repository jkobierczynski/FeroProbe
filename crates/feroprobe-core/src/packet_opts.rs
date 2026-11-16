//! nmap's packet options: `--data`, `--data-string`, `--data-length`
//! (a payload added to raw probes), `--ttl` (a fixed TTL or hop limit),
//! `--ip-options` (IPv4 header options) and `--badsum` (a wrong transport
//! checksum).
//!
//! They are process-wide, like nmap's: the command line sets them once with
//! [`set`] before anything is sent, and every probe builder reads them with
//! [`get`]. The transforms themselves ([`PacketOptions::finish`],
//! [`parse_hex`], [`parse_ip_options`], ...) are pure, so they are tested
//! without the global.
//!
//! Which probes they reach follows nmap: the raw port scans (TCP, SCTP,
//! IP protocol), the UDP scan, the discovery pings and traceroute. OS
//! detection and version detection keep their own packets.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::OnceLock;

use crate::packet::{
    self, IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_IGMP, IPPROTO_SCTP, IPPROTO_TCP, IPPROTO_UDP,
};

/// The largest payload nmap accepts (`MAX_PAYLOAD_ALLOWED`: an IP packet
/// less the largest IP and TCP headers).
pub const MAX_PAYLOAD: usize = 65535 - 60 - 40;

/// Above this, a payload may not fit in one Ethernet frame; nmap warns.
pub const PAYLOAD_WARN: usize = 1400;

/// The packet options in effect. Empty by default.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PacketOptions {
    /// `--ttl`: the IPv4 TTL and IPv6 hop limit of every probe, instead of
    /// a random one from 37 to 59.
    pub ttl: Option<u8>,
    /// `--data`, `--data-string` or `--data-length`: bytes appended to the
    /// probes. For ICMP echo requests and UDP scan probes they replace the
    /// usual payload, as in nmap.
    pub data: Option<Vec<u8>>,
    /// `--badsum`: send TCP, UDP, SCTP, ICMP and IGMP probes with a wrong
    /// checksum (one less than the right one, as nmap does).
    pub badsum: bool,
    /// `--ip-options`: IPv4 header options, already encoded (a multiple of
    /// 4 bytes, at most 40). IPv4 only.
    pub ip_options: Vec<u8>,
}

static OPTIONS: OnceLock<PacketOptions> = OnceLock::new();
static EMPTY: PacketOptions = PacketOptions {
    ttl: None,
    data: None,
    badsum: false,
    ip_options: Vec::new(),
};

/// Set the packet options for the rest of the process. Only the first call
/// counts; returns false for a later one.
pub fn set(opts: PacketOptions) -> bool {
    OPTIONS.set(opts).is_ok()
}

/// The packet options in effect (empty unless [`set`] was called).
pub fn get() -> &'static PacketOptions {
    OPTIONS.get().unwrap_or(&EMPTY)
}

impl PacketOptions {
    /// Whether any option is set.
    pub fn is_active(&self) -> bool {
        self.ttl.is_some() || self.data.is_some() || self.badsum || !self.ip_options.is_empty()
    }

    /// The payload of an ICMP or ICMPv6 echo request: the `--data` bytes
    /// when given, else FeroProbe's `feroprobe` marker.
    pub fn echo_payload(&self) -> &[u8] {
        self.data.as_deref().unwrap_or(packet::ECHO_MARKER)
    }

    /// The payload of a UDP scan probe to `port`: the `--data` bytes when
    /// given (nmap sends them instead of its port-specific payloads), else
    /// the usual one.
    pub fn udp_payload(&self, port: u16) -> &[u8] {
        match &self.data {
            Some(d) => d,
            None => crate::udp::payload_for(port),
        }
    }

    /// Finish a probe built without these options: append the `--data`
    /// bytes when `add_data` is set, then recompute the checksum, then
    /// spoil it with `--badsum`. `seg` is the transport segment or ICMP
    /// message of IP protocol `proto`, without an IP header.
    ///
    /// Only TCP, UDP, SCTP, ICMP, ICMPv6 and IGMP checksums are touched;
    /// any other protocol just gets its data. An ICMPv6 checksum is
    /// computed here but replaced by the kernel on raw ICMPv6 sockets, so
    /// `--badsum` cannot reach it there.
    pub fn finish(
        &self,
        proto: u8,
        src: IpAddr,
        dst: IpAddr,
        mut seg: Vec<u8>,
        add_data: bool,
    ) -> Vec<u8> {
        let data = self.data.as_deref().filter(|d| add_data && !d.is_empty());
        if data.is_none() && !self.badsum {
            return seg;
        }
        if let Some(d) = data {
            seg.extend_from_slice(d);
            if proto == IPPROTO_UDP && seg.len() >= 8 {
                let len = (seg.len() as u16).to_be_bytes();
                seg[4..6].copy_from_slice(&len);
            }
            set_checksum(proto, src, dst, &mut seg);
        }
        if self.badsum {
            spoil_checksum(proto, &mut seg);
        }
        seg
    }

    /// The IPv4 header options to write, and the address the packet is
    /// actually sent to, for a packet to `dst` whose header we write
    /// ourselves (`IPPROTO_RAW`). With loose or strict source routing the
    /// packet goes to the first hop, and `dst` takes the last slot, as the
    /// kernel does for options set with `IP_OPTIONS`.
    pub fn ipv4_header_options(&self, dst: Ipv4Addr) -> (Vec<u8>, Ipv4Addr) {
        route_options(&self.ip_options, dst)
    }
}

/// A whole IPv4 probe packet for a socket where we write the IP header
/// (`IPPROTO_RAW`): the TTL from `--ttl` (or a random one) and the
/// `--ip-options`. Returns the packet and the address to send it to, which
/// is the first hop of a source route.
pub(crate) fn ipv4_probe(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    proto: u8,
    id: u16,
    payload: &[u8],
) -> (Vec<u8>, Ipv4Addr) {
    let (opts, to) = get().ipv4_header_options(dst);
    let ttl = crate::raw::probe_ttl();
    (
        packet::ipv4_packet_with_options(src, to, proto, ttl, id, &opts, payload),
        to,
    )
}

/// Where the checksum of a `proto` segment lives, or `None` if it has none
/// we handle.
fn checksum_offset(proto: u8) -> Option<usize> {
    match proto {
        IPPROTO_TCP => Some(16),
        IPPROTO_UDP => Some(6),
        IPPROTO_ICMP | IPPROTO_ICMPV6 | IPPROTO_IGMP => Some(2),
        IPPROTO_SCTP => Some(8),
        _ => None,
    }
}

/// Recompute the checksum of `seg` after its contents changed.
pub(crate) fn set_checksum(proto: u8, src: IpAddr, dst: IpAddr, seg: &mut [u8]) {
    let Some(at) = checksum_offset(proto) else {
        return;
    };
    if proto == IPPROTO_SCTP {
        if seg.len() < 12 {
            return;
        }
        seg[8..12].copy_from_slice(&[0; 4]);
        let crc = packet::crc32c(seg);
        seg[8..12].copy_from_slice(&crc.to_le_bytes());
        return;
    }
    if seg.len() < at + 2 {
        return;
    }
    seg[at..at + 2].copy_from_slice(&[0, 0]);
    let sum = match proto {
        IPPROTO_ICMP | IPPROTO_IGMP => packet::checksum(seg),
        _ => {
            let mut s =
                packet::checksum_with(packet::pseudo_header_sum(src, dst, proto, seg.len()), seg);
            if proto == IPPROTO_UDP && s == 0 {
                s = 0xffff;
            }
            s
        }
    };
    seg[at..at + 2].copy_from_slice(&sum.to_be_bytes());
}

/// Whether the checksum of `seg` (TCP, UDP, SCTP, ICMP or IGMP, sent
/// from `src` to `dst`) is wrong, as after `--badsum`. False for other
/// protocols and for ICMPv6, whose checksum the kernel writes.
pub(crate) fn checksum_is_bad(proto: u8, src: IpAddr, dst: IpAddr, seg: &[u8]) -> bool {
    if proto == IPPROTO_ICMPV6 || checksum_offset(proto).is_none() || src.is_ipv4() != dst.is_ipv4()
    {
        return false;
    }
    let mut fixed = seg.to_vec();
    set_checksum(proto, src, dst, &mut fixed);
    fixed != seg
}

/// Make the checksum of `seg` wrong, as nmap's `--badsum` does: one less
/// than the right value (and never 0 for UDP, where 0 means "none").
pub(crate) fn spoil_checksum(proto: u8, seg: &mut [u8]) {
    let Some(at) = checksum_offset(proto) else {
        return;
    };
    if proto == IPPROTO_SCTP {
        if seg.len() >= 12 {
            let crc = u32::from_le_bytes([seg[8], seg[9], seg[10], seg[11]]).wrapping_sub(1);
            seg[8..12].copy_from_slice(&crc.to_le_bytes());
        }
        return;
    }
    if seg.len() < at + 2 {
        return;
    }
    let right = u16::from_be_bytes([seg[at], seg[at + 1]]);
    let mut sum = right.wrapping_sub(1);
    if proto == IPPROTO_UDP && sum == 0 {
        sum = 0xffff;
    }
    // 0x0000 and 0xffff are the same one's-complement value, so a right
    // checksum of 0 needs another step down to become wrong (nmap's
    // decrement misses this).
    if proto != IPPROTO_UDP && right == 0 {
        sum = 0xfffe;
    }
    seg[at..at + 2].copy_from_slice(&sum.to_be_bytes());
}

/// Parse `--data`: hex bytes written `0xAABB...`, `\xAA\xBB...` or
/// `AABB...`, as nmap reads them. An even number of hex digits, at least
/// one byte.
pub fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    let digits: String = if let Some(rest) = s.strip_prefix("0x") {
        rest.to_string()
    } else if s.starts_with("\\x") {
        s.chars()
            .filter(|c| !matches!(c, '\\' | 'x' | 'X'))
            .collect()
    } else {
        s.to_string()
    };
    if digits.is_empty()
        || !digits.len().is_multiple_of(2)
        || !digits.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err(format!(
            "'{s}' is not a hex string: write it as 0xAABBCC, \\xAA\\xBB\\xCC or AABBCC"
        ));
    }
    if digits.len() / 2 > 16384 {
        return Err("--data takes at most 16384 bytes".to_string());
    }
    Ok((0..digits.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&digits[i..i + 2], 16).unwrap_or(0))
        .collect())
}

/// `n` random bytes for `--data-length`. nmap draws one payload for the
/// whole scan, and so does FeroProbe.
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut state = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64)
        ^ (u64::from(std::process::id()) << 32)
        | 1;
    (0..n)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

/// IPv4 option numbers.
const OPT_NOP: u8 = 1;
const OPT_RR: u8 = 7;
const OPT_TS: u8 = 68;
const OPT_LSRR: u8 = 131;
const OPT_SSRR: u8 = 137;

/// Parse `--ip-options` the way nmap does:
///
/// - `R` record route (room for 9 addresses),
/// - `T` internet timestamp, `U` timestamp with addresses,
/// - `L <addr> [<addr> ...]` loose source route, `S <addr> ...` strict,
///   with one slot kept for the target,
/// - or raw bytes: `\x01\x07`, decimal `\1\7`, and `*N` to repeat the last
///   byte N times in all (`\x01*4` is four NOPs).
///
/// The result is padded with zeros (end of options) to a multiple of 4,
/// and may be at most 40 bytes.
pub fn parse_ip_options(spec: &str) -> Result<Vec<u8>, String> {
    let spec = spec.trim();
    let mut chars = spec.chars();
    let out = match chars.next() {
        Some(k @ ('R' | 'L' | 'S')) => {
            let rest = chars.as_str();
            let hops: Vec<Ipv4Addr> = rest
                .split([' ', ','])
                .filter(|t| !t.is_empty())
                .map(|t| {
                    t.parse::<Ipv4Addr>()
                        .map_err(|_| format!("not a valid IPv4 address '{t}' in --ip-options"))
                })
                .collect::<Result<_, _>>()?;
            if k == 'R' {
                if !hops.is_empty() {
                    return Err("--ip-options R takes no addresses".to_string());
                }
                // NOP, then record route with room for 9 addresses.
                let mut o = vec![OPT_NOP, OPT_RR, 39, 4];
                o.resize(40, 0);
                o
            } else {
                if hops.is_empty() {
                    return Err(format!("--ip-options {k} needs at least one hop address"));
                }
                // Up to 8 hops plus the slot for the target.
                if hops.len() > 8 {
                    return Err(
                        "with source routing, leave at least one slot for the target: at most 8 hops"
                            .to_string(),
                    );
                }
                let kind = if k == 'L' { OPT_LSRR } else { OPT_SSRR };
                let len = 3 + 4 * (hops.len() + 1);
                let mut o = vec![OPT_NOP, kind, len as u8, 4];
                for h in &hops {
                    o.extend_from_slice(&h.octets());
                }
                o.extend_from_slice(&[0; 4]);
                o
            }
        }
        Some(k @ ('T' | 'U')) => {
            if !chars.as_str().trim().is_empty() {
                return Err(format!("--ip-options {k} takes no arguments"));
            }
            let len = if k == 'U' { 36 } else { 40 };
            let mut o = vec![OPT_TS, len, 5, u8::from(k == 'U')];
            o.resize(usize::from(len), 0);
            o
        }
        Some('\\') => parse_raw_options(spec)?,
        _ => {
            return Err(format!(
                "bad --ip-options '{spec}': use R, T, U, L <hops>, S <hops> or bytes like \\x01\\x07"
            ));
        }
    };
    let mut out = out;
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
    if out.len() > 40 {
        return Err(format!(
            "IP options can't be more than 40 bytes long (these are {})",
            out.len()
        ));
    }
    Ok(out)
}

/// Raw option bytes: `\xHH` hex, `\NNN` decimal, `*N` repeats.
fn parse_raw_options(spec: &str) -> Result<Vec<u8>, String> {
    let mut out: Vec<u8> = Vec::new();
    let b = spec.as_bytes();
    let mut i = 0;
    let number = |i: &mut usize, radix: u32| -> Option<u32> {
        let start = *i;
        while *i < b.len() && (b[*i] as char).is_digit(radix) {
            *i += 1;
        }
        std::str::from_utf8(&b[start..*i])
            .ok()
            .and_then(|s| u32::from_str_radix(s, radix).ok())
    };
    while i < b.len() {
        match b[i] {
            b'\\' => {
                i += 1;
                let radix = if b.get(i) == Some(&b'x') {
                    i += 1;
                    16
                } else {
                    10
                };
                match number(&mut i, radix) {
                    Some(v) if v <= 255 => out.push(v as u8),
                    Some(_) => return Err("an --ip-options byte must be 0-255".to_string()),
                    None => return Err("not a digit after '\\' in --ip-options".to_string()),
                }
            }
            b'*' => {
                i += 1;
                let Some(&last) = out.last() else {
                    return Err("nothing before '*' in --ip-options".to_string());
                };
                match number(&mut i, 10) {
                    Some(n) if n >= 2 => {
                        for _ in 1..n.min(41) {
                            out.push(last);
                        }
                    }
                    _ => return Err("bad number after '*' in --ip-options".to_string()),
                }
            }
            c => {
                return Err(format!("bad character in --ip-options: '{}'", c as char));
            }
        }
        if out.len() > 40 {
            break;
        }
    }
    Ok(out)
}

/// Rewrite source-route options for a packet whose header we write: the
/// packet goes to the first hop, the remaining hops stay in the option and
/// `dst` fills the last slot. Other options are returned unchanged and the
/// packet goes to `dst`.
fn route_options(opts: &[u8], dst: Ipv4Addr) -> (Vec<u8>, Ipv4Addr) {
    let mut i = 0;
    while i < opts.len() {
        match opts[i] {
            0 => break,
            OPT_NOP => i += 1,
            kind => {
                let Some(&len) = opts.get(i + 1) else { break };
                let len = usize::from(len);
                if len < 2 || i + len > opts.len() {
                    break;
                }
                if (kind == OPT_LSRR || kind == OPT_SSRR) && len >= 3 + 8 {
                    // [kind, len, ptr, hop1, ..., last slot]
                    let body = &opts[i + 3..i + len];
                    let first = Ipv4Addr::new(body[0], body[1], body[2], body[3]);
                    let mut o = opts[..i].to_vec();
                    o.extend_from_slice(&[kind, (len - 4) as u8, 4]);
                    o.extend_from_slice(&body[4..body.len() - 4]);
                    o.extend_from_slice(&dst.octets());
                    o.extend_from_slice(&opts[i + len..]);
                    while !o.len().is_multiple_of(4) {
                        o.push(0);
                    }
                    return (o, first);
                }
                i += len;
            }
        }
    }
    (opts.to_vec(), dst)
}

/// `opts` as Linux takes them in `IP_OPTIONS`: a source route without the
/// slot reserved for the target, since the kernel takes the first hop out
/// and writes the destination into the last slot itself.
pub(crate) fn kernel_options(opts: &[u8]) -> Vec<u8> {
    let mut i = 0;
    while i < opts.len() {
        match opts[i] {
            0 => break,
            OPT_NOP => i += 1,
            kind => {
                let len = usize::from(opts.get(i + 1).copied().unwrap_or(0));
                if len < 2 || i + len > opts.len() {
                    break;
                }
                if (kind == OPT_LSRR || kind == OPT_SSRR) && len >= 3 + 8 {
                    let mut o = opts[..i].to_vec();
                    o.extend_from_slice(&[kind, (len - 4) as u8]);
                    o.extend_from_slice(&opts[i + 2..i + len - 4]);
                    o.extend_from_slice(&opts[i + len..]);
                    while !o.len().is_multiple_of(4) {
                        o.push(0);
                    }
                    return o;
                }
                i += len;
            }
        }
    }
    opts.to_vec()
}

/// The final destination of a packet with header `opts` sent to `dst`:
/// the last slot of a loose or strict source route, else `dst`.
pub fn final_destination(opts: &[u8], dst: Ipv4Addr) -> Ipv4Addr {
    let mut i = 0;
    while i < opts.len() {
        match opts[i] {
            0 => break,
            OPT_NOP => i += 1,
            kind => {
                let len = usize::from(opts.get(i + 1).copied().unwrap_or(0));
                if len < 2 || i + len > opts.len() {
                    break;
                }
                if (kind == OPT_LSRR || kind == OPT_SSRR) && len >= 7 {
                    let a = &opts[i + len - 4..i + len];
                    return Ipv4Addr::new(a[0], a[1], a[2], a[3]);
                }
                i += len;
            }
        }
    }
    dst
}

/// IPv4 header options in nmap's packet-trace notation (its
/// `format_ip_options`): ` NOP RR{#0.0.0.0 0.0.0.0}` with `#` before the
/// slot the pointer names, ` LSRR{...}`, ` SSRR{...}`, ` TM{...}` for a
/// timestamp, ` SI{id=N}`, ` EOL`, and ` ??{\xNN...}` for anything else.
/// Like nmap's, the text starts with a space.
pub fn describe_ip_options(opts: &[u8]) -> String {
    let mut out = String::new();
    let mut i = 0;
    while i < opts.len() {
        let kind = opts[i];
        match kind {
            0 => {
                out.push_str(" EOL");
                i += 1;
                continue;
            }
            OPT_NOP => {
                out.push_str(" NOP");
                i += 1;
                continue;
            }
            _ => {}
        }
        let Some(&len) = opts.get(i + 1) else {
            out.push_str(&format!(" ??{{\\x{kind:02x}}}"));
            break;
        };
        let end = (i + usize::from(len)).min(opts.len()).max(i + 2);
        let body = &opts[i + 2..end];
        match kind {
            OPT_RR | OPT_LSRR | OPT_SSRR if !body.is_empty() => {
                let name = match kind {
                    OPT_LSRR => "LSRR",
                    OPT_SSRR => "SSRR",
                    _ => "RR",
                };
                out.push_str(&format!(" {name}{{"));
                route_slots(&mut out, body[0], &body[1..], 4, 4);
                out.push('}');
            }
            OPT_TS if body.len() >= 2 => {
                let (ptr, flags) = (body[0], body[1]);
                out.push_str(" TM{");
                if ptr % 4 != 1 || usize::from(ptr) > end - i + 1 || ptr < 5 {
                    out.push_str(&format!(" [bad ptr={ptr:02}]"));
                }
                if flags & 0x0c != 0 || flags & 0x03 == 2 {
                    out.push_str(&format!(" [bad flags=\\x{:x}]", flags & 0x0f));
                }
                out.push_str(&format!("[{} hosts not recorded]", flags >> 4));
                let step = if flags & 0x03 == 0 { 4 } else { 8 };
                let mut at = 4;
                for entry in body[2..].chunks_exact(step) {
                    out.push(if at + 1 == usize::from(ptr) { '#' } else { ' ' });
                    let stamp = &entry[step - 4..];
                    if step == 8 {
                        out.push_str(&format!(
                            "{}@",
                            Ipv4Addr::new(entry[0], entry[1], entry[2], entry[3])
                        ));
                    }
                    out.push_str(
                        &u32::from_be_bytes([stamp[0], stamp[1], stamp[2], stamp[3]]).to_string(),
                    );
                    at += step;
                }
                if !body[2..].is_empty() {
                    out.push(if usize::from(ptr) == at + 1 { '#' } else { ' ' });
                }
                out.push('}');
            }
            136 if body.len() == 2 => {
                out.push_str(&format!(
                    " SI{{id={}}}",
                    u16::from_be_bytes([body[0], body[1]])
                ));
            }
            _ => {
                out.push_str(&format!(" ??{{\\x{kind:02x}\\x{len:02x}"));
                for b in body {
                    out.push_str(&format!("\\x{b:02x}"));
                }
                out.push('}');
            }
        }
        i = end;
    }
    out
}

/// The addresses of a route option after its pointer, nmap-style: `#`
/// marks the slot the pointer names (the next one to fill), or comes last
/// when the route is full.
fn route_slots(out: &mut String, ptr: u8, addrs: &[u8], first: usize, step: usize) {
    if usize::from(ptr) % 4 != 0 || usize::from(ptr) > addrs.len() + first || ptr < 4 {
        out.push_str(&format!(" [bad ptr={ptr:02}]"));
    }
    let mut at = first;
    for a in addrs.chunks_exact(step) {
        out.push(if at == usize::from(ptr) { '#' } else { ' ' });
        out.push_str(&Ipv4Addr::new(a[0], a[1], a[2], a[3]).to_string());
        at += step;
    }
    if usize::from(ptr) == at {
        out.push('#');
    }
}

/// nmap's `bintohexstr` dump of the options, 16 bytes a line with a space
/// after the eighth: `\x01\x07\x27\x04... \x00...`.
pub fn hex_ip_options(opts: &[u8]) -> String {
    let mut out = String::new();
    for (i, b) in opts.iter().enumerate() {
        out.push_str(&format!("\\x{b:02x}"));
        if i % 16 == 7 {
            out.push(' ');
        }
        if i % 16 == 15 {
            out.push('\n');
        }
    }
    if !opts.len().is_multiple_of(16) {
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn hex_in_nmaps_three_spellings() {
        assert_eq!(
            parse_hex("0xdeadBEEF").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(parse_hex("\\xde\\xad").unwrap(), vec![0xde, 0xad]);
        assert_eq!(parse_hex("0102").unwrap(), vec![1, 2]);
        assert!(parse_hex("").is_err());
        assert!(parse_hex("0x").is_err());
        assert!(parse_hex("abc").is_err());
        assert!(parse_hex("zz").is_err());
    }

    #[test]
    fn random_payload_has_the_length() {
        assert_eq!(random_bytes(0).len(), 0);
        assert_eq!(random_bytes(25).len(), 25);
    }

    #[test]
    fn data_is_appended_with_a_valid_checksum() {
        let (s, d) = (v4("10.0.0.1"), v4("10.0.0.2"));
        let opts = PacketOptions {
            data: Some(b"hello".to_vec()),
            ..Default::default()
        };
        let syn = packet::tcp_syn(s, d, 40000, 80, 1).to_vec();
        let out = opts.finish(IPPROTO_TCP, s, d, syn, true);
        assert_eq!(out.len(), packet::SYN_LEN + 5);
        assert!(out.ends_with(b"hello"));
        // A valid checksum sums to zero over the pseudo-header and segment.
        let sum = packet::checksum_with(
            packet::pseudo_header_sum(s, d, IPPROTO_TCP, out.len()),
            &out,
        );
        assert_eq!(sum, 0);

        let udp = packet::udp_packet(s, d, 40000, 53, &[]);
        let out = opts.finish(IPPROTO_UDP, s, d, udp, true);
        assert_eq!(u16::from_be_bytes([out[4], out[5]]), 13);
        let sum = packet::checksum_with(
            packet::pseudo_header_sum(s, d, IPPROTO_UDP, out.len()),
            &out,
        );
        assert_eq!(sum, 0);

        let ts = packet::icmp_query(packet::ICMP_TIMESTAMP, 1, 1, 12);
        let out = opts.finish(IPPROTO_ICMP, s, d, ts, true);
        assert_eq!(out.len(), 20 + 5);
        assert_eq!(packet::checksum(&out), 0);

        // A right checksum of 0: 0xffff would still be right.
        let mut echo = packet::icmp_echo(0xf7ff, 0, &[]);
        assert_eq!(&echo[2..4], &[0, 0]);
        spoil_checksum(packet::IPPROTO_ICMP, &mut echo);
        assert_ne!(packet::checksum(&echo), 0);

        let init = packet::sctp_init(40000, 2905, 7, 9);
        let out = opts.finish(IPPROTO_SCTP, s, d, init, true);
        let mut zeroed = out.clone();
        zeroed[8..12].copy_from_slice(&[0; 4]);
        assert_eq!(
            packet::crc32c(&zeroed).to_le_bytes(),
            [out[8], out[9], out[10], out[11]]
        );
    }

    #[test]
    fn no_data_when_not_asked() {
        let (s, d) = (v4("10.0.0.1"), v4("10.0.0.2"));
        let opts = PacketOptions {
            data: Some(b"x".to_vec()),
            ..Default::default()
        };
        let syn = packet::tcp_syn(s, d, 40000, 80, 1).to_vec();
        assert_eq!(opts.finish(IPPROTO_TCP, s, d, syn.clone(), false), syn);
    }

    #[test]
    fn badsum_is_one_less() {
        let (s, d) = (v4("10.0.0.1"), v4("10.0.0.2"));
        let opts = PacketOptions {
            badsum: true,
            ..Default::default()
        };
        let syn = packet::tcp_syn(s, d, 40000, 80, 1).to_vec();
        let good = u16::from_be_bytes([syn[16], syn[17]]);
        let out = opts.finish(IPPROTO_TCP, s, d, syn, true);
        assert_eq!(u16::from_be_bytes([out[16], out[17]]), good.wrapping_sub(1));
        let sum = packet::checksum_with(
            packet::pseudo_header_sum(s, d, IPPROTO_TCP, out.len()),
            &out,
        );
        assert_ne!(sum, 0);

        let init = packet::sctp_init(40000, 2905, 7, 9);
        let out = opts.finish(IPPROTO_SCTP, s, d, init.clone(), true);
        assert_ne!(out[8..12], init[8..12]);
    }

    #[test]
    fn echo_and_udp_payloads() {
        let none = PacketOptions::default();
        assert_eq!(none.echo_payload(), packet::ECHO_MARKER);
        assert_eq!(none.udp_payload(9999), packet::UDP_MARKER);
        let some = PacketOptions {
            data: Some(vec![1, 2]),
            ..Default::default()
        };
        assert_eq!(some.echo_payload(), &[1, 2]);
        assert_eq!(some.udp_payload(53), &[1, 2]);
    }

    #[test]
    fn kernel_options_drop_the_target_slot() {
        let l = parse_ip_options("L 10.0.0.1 10.0.0.2").unwrap();
        let k = kernel_options(&l);
        // [NOP, LSRR, len 11, ptr 4, 10.0.0.1, 10.0.0.2], padded.
        assert_eq!(&k[..12], &[1, 131, 11, 4, 10, 0, 0, 1, 10, 0, 0, 2]);
        assert_eq!(k.len() % 4, 0);
        assert_eq!(
            kernel_options(&parse_ip_options("R").unwrap()),
            parse_ip_options("R").unwrap()
        );
    }

    #[test]
    fn ip_options_like_nmap() {
        let rr = parse_ip_options("R").unwrap();
        assert_eq!(rr.len(), 40);
        assert_eq!(&rr[..4], &[1, 7, 39, 4]);

        let ts = parse_ip_options("T").unwrap();
        assert_eq!(&ts[..4], &[68, 40, 5, 0]);
        let u = parse_ip_options("U").unwrap();
        assert_eq!(&u[..4], &[68, 36, 5, 1]);
        assert_eq!(u.len(), 36);

        let l = parse_ip_options("L 10.0.0.1 10.0.0.2").unwrap();
        assert_eq!(l, vec![1, 131, 15, 4, 10, 0, 0, 1, 10, 0, 0, 2, 0, 0, 0, 0]);
        let s = parse_ip_options("S 192.168.1.1").unwrap();
        assert_eq!(&s[..4], &[1, 137, 11, 4]);

        assert_eq!(
            parse_ip_options("\\x01\\x01\\x01\\x01").unwrap(),
            vec![1; 4]
        );
        assert_eq!(parse_ip_options("\\x01*4").unwrap(), vec![1; 4]);
        // Padded to a multiple of 4.
        assert_eq!(parse_ip_options("\\1").unwrap(), vec![1, 0, 0, 0]);

        assert!(parse_ip_options("Q").is_err());
        assert!(parse_ip_options("L").is_err());
        assert!(parse_ip_options("L 1.2.3").is_err());
        assert!(parse_ip_options("\\x01*41").is_err());
        assert!(
            parse_ip_options(
                "L 1.1.1.1 1.1.1.2 1.1.1.3 1.1.1.4 1.1.1.5 1.1.1.6 1.1.1.7 1.1.1.8 1.1.1.9"
            )
            .is_err()
        );
    }

    #[test]
    fn source_route_goes_to_the_first_hop() {
        let l = parse_ip_options("L 10.0.0.1 10.0.0.2").unwrap();
        let (o, to) = route_options(&l, Ipv4Addr::new(10, 9, 9, 9));
        assert_eq!(to, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(o, vec![1, 131, 11, 4, 10, 0, 0, 2, 10, 9, 9, 9]);
        let rr = parse_ip_options("R").unwrap();
        let (o, to) = route_options(&rr, Ipv4Addr::new(10, 9, 9, 9));
        assert_eq!((o, to), (rr, Ipv4Addr::new(10, 9, 9, 9)));
    }

    #[test]
    fn options_are_described_like_nmap() {
        let l = parse_ip_options("L 10.0.0.1").unwrap();
        assert_eq!(describe_ip_options(&l), " NOP LSRR{#10.0.0.1 0.0.0.0}");
        // The SENT and RCVD options of nmap's own trace, from a TP-Link router.
        let zeros = " 0.0.0.0".repeat(8);
        assert_eq!(
            describe_ip_options(&parse_ip_options("R").unwrap()),
            format!(" NOP RR{{#0.0.0.0{zeros}}}")
        );
        let mut got = vec![7, 39, 12, 192, 168, 1, 1, 192, 168, 1, 1];
        got.resize(39, 0);
        got.push(0);
        assert_eq!(
            describe_ip_options(&got),
            format!(
                " RR{{ 192.168.1.1 192.168.1.1#0.0.0.0{}}} EOL",
                " 0.0.0.0".repeat(6)
            )
        );
        // A full route puts the pointer mark last.
        assert_eq!(
            describe_ip_options(&[7, 7, 8, 10, 0, 0, 1]),
            " RR{ 10.0.0.1#}"
        );
        // Timestamps only, one recorded; then an unknown option.
        assert_eq!(
            describe_ip_options(&[68, 12, 9, 0, 0, 0, 0, 5, 0, 0, 0, 0]),
            " TM{[0 hosts not recorded] 5#0 }"
        );
        assert_eq!(describe_ip_options(&[136, 4, 0, 7]), " SI{id=7}");
        assert_eq!(describe_ip_options(&[99, 3, 0xab]), " ??{\\x63\\x03\\xab}");
    }

    #[test]
    fn options_hex_dump_like_nmap() {
        let rr = parse_ip_options("R").unwrap();
        let dump = hex_ip_options(&rr);
        assert!(dump.starts_with("\\x01\\x07\\x27\\x04\\x00\\x00\\x00\\x00 \\x00"));
        assert_eq!(dump.lines().count(), 3);
        assert!(dump.ends_with("\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00 \n"));
    }
}
