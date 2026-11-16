//! `--packet-trace`: one line per probe sent and per answer received, in
//! the layout of nmap's packet trace (`SENT (0.0412s) TCP ...`). Lines go to
//! standard output, as nmap's do.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use crate::packet;

static ENABLED: AtomicBool = AtomicBool::new(false);
static START: OnceLock<Instant> = OnceLock::new();

/// Turn the trace on for the rest of the process.
pub fn enable() {
    START.get_or_init(Instant::now);
    ENABLED.store(true, Ordering::Relaxed);
}

/// Turn the trace off again (the `P` key while a scan runs). The trace
/// clock keeps running, so later lines still count from the first start.
pub fn disable() {
    ENABLED.store(false, Ordering::Relaxed);
}

/// Whether `--packet-trace` is on.
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Print one trace line: `kind` is SENT, RCVD or CONN. `line` is only built
/// when the trace is on.
pub(crate) fn log(kind: &str, line: impl FnOnce() -> String) {
    if !enabled() {
        return;
    }
    let at = START.get_or_init(Instant::now).elapsed().as_secs_f64();
    println!("{kind} ({at:.4}s) {}", line());
}

/// The TCP flags as nmap writes them: S, A, F, R, P, U, E, C.
pub(crate) fn tcp_flags(flags: u8) -> String {
    [
        (packet::TCP_SYN, 'S'),
        (packet::TCP_ACK, 'A'),
        (packet::TCP_FIN, 'F'),
        (packet::TCP_RST, 'R'),
        (packet::TCP_PSH, 'P'),
        (packet::TCP_URG, 'U'),
        (packet::TCP_ECE, 'E'),
        (packet::TCP_CWR, 'C'),
    ]
    .iter()
    .filter(|(bit, _)| flags & bit != 0)
    .map(|(_, c)| *c)
    .collect()
}

fn host_port(ip: Option<IpAddr>, port: u16) -> String {
    match ip {
        Some(IpAddr::V6(v6)) => format!("[{v6}]:{port}"),
        Some(ip) => format!("{ip}:{port}"),
        None => format!("*:{port}"),
    }
}

/// Describe a transport segment or ICMP message (no IP header) of IP
/// protocol `proto` between `src` and `dst`; an unknown end shows as `*`.
pub(crate) fn describe(proto: u8, data: &[u8], src: Option<IpAddr>, dst: Option<IpAddr>) -> String {
    let to = dst.map_or_else(|| "*".to_string(), |d| d.to_string());
    match proto {
        packet::IPPROTO_TCP => match packet::parse_tcp(data) {
            Some(t) => {
                // Data after the header (--data and friends) shows as len=.
                let hlen = usize::from(data[12] >> 4) * 4;
                let extra = data.len().saturating_sub(hlen);
                let len = if extra > 0 {
                    format!(" len={extra}")
                } else {
                    String::new()
                };
                format!(
                    "TCP {} > {} {} seq={} win={}{len}",
                    host_port(src, t.sport),
                    host_port(dst, t.dport),
                    tcp_flags(t.flags),
                    t.seq,
                    t.window
                )
            }
            None => format!("TCP {} bytes to {to}", data.len()),
        },
        packet::IPPROTO_UDP if data.len() >= 8 => format!(
            "UDP {} > {} len={}",
            host_port(src, u16::from_be_bytes([data[0], data[1]])),
            host_port(dst, u16::from_be_bytes([data[2], data[3]])),
            data.len() - 8
        ),
        packet::IPPROTO_ICMP | packet::IPPROTO_ICMPV6 => {
            let v = if proto == packet::IPPROTO_ICMPV6 {
                "ICMPv6"
            } else {
                "ICMP"
            };
            let from = src.map_or_else(|| "*".to_string(), |s| s.to_string());
            match packet::parse_icmp(data) {
                Some(m) => format!(
                    "{v} [{from} > {to} {} (type={}/code={}) id={} seq={}]",
                    icmp_name(proto == packet::IPPROTO_ICMPV6, m.kind),
                    m.kind,
                    m.code,
                    m.id,
                    m.seq
                ),
                None => format!("{v} {} bytes {from} > {to}", data.len()),
            }
        }
        packet::IPPROTO_SCTP => match packet::parse_sctp(data) {
            Some(c) => format!(
                "SCTP {} > {} {} vtag={}",
                host_port(src, c.sport),
                host_port(dst, c.dport),
                sctp_chunk_name(c.chunk),
                c.vtag
            ),
            None => format!("SCTP {} bytes to {to}", data.len()),
        },
        other => format!(
            "{} {} > {to} ({} bytes)",
            crate::ports::ip_protocol_name(other).to_uppercase(),
            src.map_or_else(|| "*".to_string(), |s| s.to_string()),
            data.len()
        ),
    }
}

/// Describe a packet read from a raw socket for `proto`: IPv4 packets come
/// with their header, IPv6 ones (and Linux ping sockets) without.
pub(crate) fn describe_received(proto: u8, data: &[u8], from: IpAddr) -> String {
    match packet::parse_ipv4(data) {
        Some(ip) if from.is_ipv4() && ip.src == from => format!(
            "{} ttl={}",
            describe(
                ip.protocol,
                ip.payload,
                Some(IpAddr::V4(ip.src)),
                Some(IpAddr::V4(ip.dst))
            ),
            ip.ttl
        ),
        // No header: the local address is not in the packet, and shows
        // as `*` when the routing table cannot tell it either.
        _ => describe(proto, data, Some(from), local_for(from)),
    }
}

/// The local address that talks to `dst`, for trace lines only.
fn local_for(dst: IpAddr) -> Option<IpAddr> {
    #[cfg(target_os = "linux")]
    {
        crate::raw::source_addr_for(dst).ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = dst;
        None
    }
}

/// `IPPROTO_RAW` (255): the socket carries whole IP packets we built
/// ourselves, so the trace must read the IP header, not the socket.
const IPPROTO_RAW: u8 = 255;

/// A TCP segment's options in nmap's packet-trace style, such as
/// `<mss 1460,sackOK,timestamp 123 0,nop,wscale 7>`; empty without options.
pub(crate) fn tcp_options_text(seg: &[u8]) -> String {
    let opts = packet::tcp_options(seg);
    let mut parts = Vec::new();
    let mut i = 0;
    while i < opts.len() {
        let kind = opts[i];
        if kind == 0 {
            parts.push("eol".to_string());
            break;
        }
        if kind == 1 {
            parts.push("nop".to_string());
            i += 1;
            continue;
        }
        let Some(&len) = opts.get(i + 1) else { break };
        let len = usize::from(len);
        let Some(body) = opts.get(i + 2..i + len.max(2)) else {
            break;
        };
        let be16 = |b: &[u8]| u16::from_be_bytes([b[0], b[1]]);
        let be32 = |b: &[u8]| u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        parts.push(match (kind, body.len()) {
            (2, 2) => format!("mss {}", be16(body)),
            (3, 1) => format!("wscale {}", body[0]),
            (4, 0) => "sackOK".to_string(),
            (8, 8) => format!("timestamp {} {}", be32(body), be32(&body[4..])),
            (k, _) => format!("opt {k}"),
        });
        i += len.max(2);
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!("<{}>", parts.join(","))
    }
}

/// A sent raw packet: `to` is where it went, and `ip_options` the IPv4
/// options the socket adds (`--ip-options`).
pub(crate) fn sent(proto: u8, pkt: &[u8], to: SocketAddr, ip_options: &[u8], ttl: Option<u8>) {
    log("SENT", || {
        if proto == IPPROTO_RAW {
            // Evasion probes (-f/--mtu/-D/-S) are complete IPv4 packets, so
            // the real (possibly spoofed or decoy) source and the inner
            // protocol come from the header, not from the socket or `to`.
            describe_raw_ipv4(pkt, to)
        } else {
            let src = local_for(to.ip());
            let bad =
                src.is_some_and(|s| crate::packet_opts::checksum_is_bad(proto, s, to.ip(), pkt));
            format!(
                "{}{}",
                describe(proto, pkt, src, Some(to.ip())),
                kernel_header_note(ttl, ip_options, to.ip(), bad)
            )
        }
    });
}

/// [`header_note`] for a probe whose IPv4 header the kernel writes from
/// the `--ip-options` set on its socket: shown as they leave, so a source
/// route names the hops still to come and the target, plus ` via` the
/// first hop the packet is really sent to.
pub(crate) fn kernel_header_note(
    ttl: Option<u8>,
    ip_options: &[u8],
    dst: IpAddr,
    badsum: bool,
) -> String {
    let IpAddr::V4(dst4) = dst else {
        return header_note(ttl, &[], badsum);
    };
    let (opts, hop) = crate::packet_opts::get().ipv4_header_options(dst4);
    let opts = if ip_options.is_empty() {
        Vec::new()
    } else {
        opts
    };
    let mut s = header_note(ttl, &opts, badsum);
    if !ip_options.is_empty() && hop != dst4 {
        s.push_str(&format!(" via {hop}"));
    }
    s
}

/// What the packet options put in a probe, for its trace line: ` ttl=N`
/// (given only with `--ttl`, so the usual lines stay as they were),
/// ` ipopts={...}` for IPv4 header options and ` badsum` for a wrong
/// transport checksum, each only when present.
pub(crate) fn header_note(ttl: Option<u8>, ip_options: &[u8], badsum: bool) -> String {
    let mut s = String::new();
    if let Some(ttl) = ttl {
        s.push_str(&format!(" ttl={ttl}"));
    }
    if !ip_options.is_empty() {
        s.push_str(&format!(
            " ipopts={{{}}}",
            crate::packet_opts::describe_ip_options(ip_options)
        ));
    }
    if badsum {
        s.push_str(" badsum");
    }
    s
}

/// Trace line for a complete IPv4 packet sent on an `IPPROTO_RAW` socket.
pub(crate) fn describe_raw_ipv4(pkt: &[u8], to: SocketAddr) -> String {
    if pkt.len() < 20 || (pkt[0] >> 4) != 4 {
        return describe(IPPROTO_RAW, pkt, local_for(to.ip()), Some(to.ip()));
    }
    let ihl = usize::from(pkt[0] & 0x0f) * 4;
    let proto = pkt[9];
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    let options = pkt.get(20..ihl).unwrap_or(&[]);
    let ttl = crate::packet_opts::get().ttl.map(|_| pkt[8]);
    let frag = u16::from_be_bytes([pkt[6], pkt[7]]);
    let offset = usize::from(frag & 0x1fff) * 8;
    let more = frag & 0x2000 != 0;
    // A fragment past the first carries no transport header to read.
    if offset > 0 {
        let tail = if more { " +" } else { "" };
        return format!(
            "IP {src} > {dst} proto {proto} frag offset={offset}{tail}{}",
            header_note(ttl, options, false)
        );
    }
    let payload = pkt.get(ihl..).unwrap_or(&[]);
    // The first fragment (offset 0, more set) with `-f` carries only 8 bytes
    // of the TCP header, too few for parse_tcp. Show the addresses and ports
    // from what is there rather than falling back to a byte count.
    if more && proto == packet::IPPROTO_TCP && (4..20).contains(&payload.len()) {
        let sport = u16::from_be_bytes([payload[0], payload[1]]);
        let dport = u16::from_be_bytes([payload[2], payload[3]]);
        return format!(
            "TCP {src}:{sport} > {dst}:{dport} (frag){}",
            header_note(ttl, options, false)
        );
    }
    let mut line = describe(proto, payload, Some(IpAddr::V4(src)), Some(IpAddr::V4(dst)));
    if more {
        line.push_str(" (frag)");
    }
    // A source-routed packet's checksum covers its final destination.
    let last = crate::packet_opts::final_destination(options, dst);
    let bad = !more
        && crate::packet_opts::checksum_is_bad(proto, IpAddr::V4(src), IpAddr::V4(last), payload);
    line.push_str(&header_note(ttl, options, bad));
    line
}

/// A connect() attempt and how it ended, like nmap's CONN lines.
pub(crate) fn conn(to: SocketAddr, outcome: &str) {
    log("CONN", || {
        format!(
            "TCP localhost > {} => {outcome}",
            host_port(Some(to.ip()), to.port())
        )
    });
}

fn sctp_chunk_name(chunk: u8) -> &'static str {
    match chunk {
        packet::SCTP_INIT => "INIT",
        packet::SCTP_INIT_ACK => "INIT-ACK",
        packet::SCTP_ABORT => "ABORT",
        packet::SCTP_COOKIE_ECHO => "COOKIE-ECHO",
        _ => "chunk",
    }
}

fn icmp_name(v6: bool, kind: u8) -> &'static str {
    match (v6, kind) {
        (false, 0) | (true, 129) => "Echo reply",
        (false, 3) | (true, 1) => "Destination unreachable",
        (false, 8) | (true, 128) => "Echo request",
        (false, 11) | (true, 3) => "Time exceeded",
        (false, 13) => "Timestamp request",
        (false, 14) => "Timestamp reply",
        (false, 17) => "Address mask request",
        (false, 18) => "Address mask reply",
        (true, 135) => "Neighbor solicitation",
        (true, 136) => "Neighbor advertisement",
        _ => "ICMP",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_look_like_nmaps() {
        assert_eq!(tcp_flags(packet::TCP_SYN | packet::TCP_ACK), "SA");
        let syn = packet::tcp_syn(
            "192.0.2.1".parse::<IpAddr>().unwrap(),
            "192.0.2.9".parse::<IpAddr>().unwrap(),
            40000,
            80,
            7,
        );
        let line = describe(
            packet::IPPROTO_TCP,
            &syn,
            Some("192.0.2.1".parse().unwrap()),
            Some("192.0.2.9".parse().unwrap()),
        );
        assert_eq!(line, "TCP 192.0.2.1:40000 > 192.0.2.9:80 S seq=7 win=65109");
        // An evasion probe is a whole IPv4 packet on an IPPROTO_RAW socket:
        // the trace reads the header, showing the (here spoofed) source.
        let seg = packet::tcp_syn(
            "10.0.0.9".parse::<IpAddr>().unwrap(),
            "10.0.0.2".parse::<IpAddr>().unwrap(),
            40000,
            80,
            7,
        );
        let ip = packet::ipv4_packet(
            "10.0.0.9".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            packet::IPPROTO_TCP,
            64,
            1,
            &seg,
        );
        let to: SocketAddr = "10.0.0.2:0".parse().unwrap();
        assert_eq!(
            describe_raw_ipv4(&ip, to),
            "TCP 10.0.0.9:40000 > 10.0.0.2:80 S seq=7 win=65109"
        );
        // Fragmenting the same probe (24-byte SYN) into 8-byte pieces.
        let frags = crate::evasion::fragment_ipv4(&ip, crate::evasion::Fragment::Eight);
        assert_eq!(frags.len(), 3);
        // The first fragment holds only 8 bytes of TCP (too few to parse as a
        // full header): show the addresses and ports, not a bare byte count.
        assert_eq!(
            describe_raw_ipv4(&frags[0], to),
            "TCP 10.0.0.9:40000 > 10.0.0.2:80 (frag)"
        );
        // A later fragment is shown as a fragment, not parsed as TCP.
        let line = describe_raw_ipv4(&frags[1], to);
        assert!(line.contains("frag offset=8"), "{line}");
        let echo = packet::icmp_echo(5, 1, &[]);
        let line = describe(
            packet::IPPROTO_ICMP,
            &echo,
            None,
            Some("192.0.2.9".parse().unwrap()),
        );
        assert_eq!(
            line,
            "ICMP [* > 192.0.2.9 Echo request (type=8/code=0) id=5 seq=1]"
        );
        let init = packet::sctp_init(40000, 2905, 7, 1);
        let dst = Some("192.0.2.9".parse().unwrap());
        assert_eq!(
            describe(packet::IPPROTO_SCTP, &init, None, dst),
            "SCTP *:40000 > 192.0.2.9:2905 INIT vtag=0"
        );
        assert_eq!(describe(47, &[], None, dst), "GRE * > 192.0.2.9 (0 bytes)");
    }
}
