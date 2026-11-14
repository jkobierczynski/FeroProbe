//! `--packet-trace`: one line per probe sent and per answer received, in
//! the layout of nmap's packet trace (`SENT (0.0412s) TCP ...`). Lines go to
//! standard output, as nmap's do.

use std::net::{IpAddr, SocketAddr};
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
/// protocol `proto` between `src` (if known) and `dst`.
pub(crate) fn describe(proto: u8, data: &[u8], src: Option<IpAddr>, dst: IpAddr) -> String {
    const IPPROTO_UDP: u8 = 17;
    const IPPROTO_ICMPV6: u8 = 58;
    match proto {
        packet::IPPROTO_TCP => match packet::parse_tcp(data) {
            Some(t) => format!(
                "TCP {} > {} {} seq={} win={}",
                host_port(src, t.sport),
                host_port(Some(dst), t.dport),
                tcp_flags(t.flags),
                t.seq,
                t.window
            ),
            None => format!("TCP {} bytes to {dst}", data.len()),
        },
        IPPROTO_UDP if data.len() >= 8 => format!(
            "UDP {} > {} len={}",
            host_port(src, u16::from_be_bytes([data[0], data[1]])),
            host_port(Some(dst), u16::from_be_bytes([data[2], data[3]])),
            data.len() - 8
        ),
        packet::IPPROTO_ICMP | IPPROTO_ICMPV6 => {
            let v = if proto == IPPROTO_ICMPV6 {
                "ICMPv6"
            } else {
                "ICMP"
            };
            let from = src.map_or_else(|| "*".to_string(), |s| s.to_string());
            match packet::parse_icmp(data) {
                Some(m) => format!(
                    "{v} [{from} > {dst} {} (type={}/code={}) id={} seq={}]",
                    icmp_name(proto == IPPROTO_ICMPV6, m.kind),
                    m.kind,
                    m.code,
                    m.id,
                    m.seq
                ),
                None => format!("{v} {} bytes {from} > {dst}", data.len()),
            }
        }
        other => format!("proto {other}, {} bytes to {dst}", data.len()),
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
                IpAddr::V4(ip.dst)
            ),
            ip.ttl
        ),
        // No header: the local address is not in the packet.
        _ => describe(proto, data, Some(from), local_for(from).unwrap_or(from)),
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

/// A sent raw packet: `to` is where it went.
pub(crate) fn sent(proto: u8, pkt: &[u8], to: SocketAddr) {
    log("SENT", || describe(proto, pkt, local_for(to.ip()), to.ip()));
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
            "192.0.2.9".parse().unwrap(),
        );
        assert_eq!(line, "TCP 192.0.2.1:40000 > 192.0.2.9:80 S seq=7 win=1024");
        let echo = packet::icmp_echo(5, 1, &[]);
        let line = describe(
            packet::IPPROTO_ICMP,
            &echo,
            None,
            "192.0.2.9".parse().unwrap(),
        );
        assert_eq!(
            line,
            "ICMP [* > 192.0.2.9 Echo request (type=8/code=0) id=5 seq=1]"
        );
    }
}
