//! The IP protocol scan, like nmap's `-sO`: which IP protocols (ICMP,
//! IGMP, TCP, UDP, GRE, ESP, SCTP, ...) a host supports. Its "ports" are
//! protocol numbers, 0 to 255.
//!
//! Each probe is an IP packet of that protocol. Those nmap gives a body
//! get one (an ICMP echo request, an IGMP query, a TCP ACK to port 80, a
//! UDP datagram to port 40125, an SCTP INIT to port 80); the rest are a
//! bare IP header. Answers are read as nmap reads them:
//!
//! - **open**: the host answered in that protocol, or (for UDP and
//!   other protocols with ports) with an ICMP port unreachable
//! - **closed**: the host answered with an ICMP protocol unreachable
//! - **filtered**: another ICMP unreachable error, from the host or a router
//! - **open|filtered**: no answer at all
//!
//! Needs root (or `CAP_NET_RAW`) and is Linux only. IPv4 and IPv6 targets
//! can be mixed.

use std::io;

use crate::model::{HostResult, ScanConfig};
use crate::target::Target;

/// Run an IP protocol scan of every protocol number in `protocols` (each
/// at most 255) on every target. Target addresses must be distinct (the
/// CLI resolver guarantees this); a repeated address would leave every
/// copy but one reporting no response.
pub async fn ip_protocol_scan(
    targets: &[Target],
    protocols: &[u8],
    cfg: &ScanConfig,
) -> io::Result<Vec<HostResult>> {
    let (targets, protocols, cfg) = (targets.to_vec(), protocols.to_vec(), cfg.clone());
    tokio::task::spawn_blocking(move || imp::scan_blocking(&targets, &protocols, &cfg))
        .await
        .map_err(io::Error::other)?
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::*;

    pub(super) fn scan_blocking(
        _: &[Target],
        _: &[u8],
        _: &ScanConfig,
    ) -> io::Result<Vec<HostResult>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the IP protocol scan (-sO) is only supported on Linux for now",
        ))
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;

    use std::net::IpAddr;

    use socket2::{Domain, Protocol as SockProto, Socket};

    use crate::capture::Packet;
    use crate::model::{PortState, Protocol, reason};
    use crate::packet::{
        self, ICMP_DEST_UNREACH, ICMP_ECHO_REPLY, ICMPV6_DEST_UNREACH, ICMPV6_PARAM_PROBLEM,
        IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_IGMP, IPPROTO_SCTP, IPPROTO_TCP, IPPROTO_UDP,
    };
    use crate::raw::{Rng, raw_socket_in, send_logged_until};
    use crate::rawscan::{self, Answer, Index};
    use crate::target::socket_addr;

    /// The ports nmap's protocol probes go to: TCP and SCTP to port 80,
    /// UDP to a port that is very likely closed.
    const TCP_PORT: u16 = 80;
    const UDP_PORT: u16 = 40125;
    const SCTP_PORT: u16 = 80;

    /// The fixed parts of this scan's probes.
    #[derive(Debug, Clone, Copy)]
    pub(super) struct Probe {
        pub sport: u16,
        pub seq: u32,
        pub ipid: u16,
        pub icmp_id: u16,
    }

    impl Probe {
        /// The body of the probe for protocol `proto`, after the IP header.
        pub(super) fn body(&self, proto: u8, src: IpAddr, dst: IpAddr) -> Vec<u8> {
            match (proto, src, dst) {
                (IPPROTO_ICMP, IpAddr::V4(_), _) => packet::icmp_echo(self.icmp_id, 0, &[]),
                (IPPROTO_ICMPV6, IpAddr::V6(s), IpAddr::V6(d)) => {
                    packet::icmpv6_echo_with_checksum(s, d, self.icmp_id, 0)
                }
                (IPPROTO_IGMP, IpAddr::V4(_), _) => packet::igmp_query().to_vec(),
                (IPPROTO_TCP, ..) => packet::tcp_probe(
                    src,
                    dst,
                    self.sport,
                    TCP_PORT,
                    self.seq,
                    self.seq,
                    packet::TCP_ACK,
                )
                .to_vec(),
                (IPPROTO_UDP, ..) => packet::udp_packet(src, dst, self.sport, UDP_PORT, &[]),
                (IPPROTO_SCTP, ..) => packet::sctp_init(self.sport, SCTP_PORT, self.seq, self.seq),
                _ => Vec::new(),
            }
        }

        /// The whole packet, IP header included.
        pub(super) fn packet(&self, proto: u8, src: IpAddr, dst: IpAddr) -> Vec<u8> {
            let body = self.body(proto, src, dst);
            match (src, dst) {
                (IpAddr::V4(s), IpAddr::V4(d)) => {
                    packet::ipv4_packet(s, d, proto, 64, self.ipid, &body)
                }
                (IpAddr::V6(s), IpAddr::V6(d)) => packet::ipv6_packet(s, d, proto, 64, &body),
                _ => Vec::new(),
            }
        }
    }

    pub(super) fn scan_blocking(
        targets: &[Target],
        protocols: &[u8],
        cfg: &ScanConfig,
    ) -> io::Result<Vec<HostResult>> {
        // IPPROTO_RAW sockets take the IP header from us, so one socket
        // per family can send any protocol.
        let open = |domain| raw_socket_in(domain, SockProto::from(libc::IPPROTO_RAW));
        let v4 = if targets.iter().any(|t| t.addr.is_ipv4()) {
            Some(open(Domain::IPV4)?)
        } else {
            None
        };
        let v6: Option<Socket> = if targets.iter().any(|t| t.addr.is_ipv6()) {
            match open(Domain::IPV6) {
                Ok(s) => Some(s),
                Err(e) if e.raw_os_error() == Some(libc::EAFNOSUPPORT) => None,
                Err(e) => return Err(e),
            }
        } else {
            None
        };
        let mut rng = Rng::new();
        let probe = Probe {
            sport: 40000 + (rng.next_u32() % 20000) as u16,
            seq: rng.next_u32(),
            ipid: (rng.next_u32() as u16) | 1,
            icmp_id: (rng.next_u32() as u16) | 1,
        };
        let keys: Vec<u16> = protocols.iter().map(|&p| u16::from(p)).collect();
        let send = |_: usize, proto: u16, src: IpAddr, dst: IpAddr| -> io::Result<()> {
            let sock = if dst.is_ipv6() {
                v6.as_ref()
            } else {
                v4.as_ref()
            };
            let Some(sock) = sock else {
                return Err(io::Error::from_raw_os_error(libc::ENETUNREACH));
            };
            let proto = proto as u8;
            let pkt = probe.packet(proto, src, dst);
            // Our own trace line: the socket's protocol is IPPROTO_RAW.
            send_logged_until(sock, &pkt, socket_addr(dst, 0), cfg.deadline, || {
                crate::packet_trace::log("SENT", || {
                    let body = probe.body(proto, src, dst);
                    crate::packet_trace::describe(proto, &body, Some(src), Some(dst))
                });
            })
        };
        let classify = move |pkt: &Packet<'_>, index: &Index| answers(pkt, index, &probe);
        rawscan::run(
            targets,
            &keys,
            cfg,
            Protocol::Ip,
            PortState::OpenFiltered,
            send,
            classify,
        )
    }

    /// Everything a captured packet says about our probes, as nmap reads
    /// it: an ICMP error about a probe first, then, for a packet from a
    /// target, that the target speaks the packet's protocol.
    pub(super) fn answers(pkt: &Packet<'_>, index: &Index, probe: &Probe) -> Vec<Answer> {
        let mut out = Vec::new();
        let v6 = pkt.src.is_ipv6();
        // One of our own probes, seen coming back in: on the loopback
        // interface a probe is delivered to us as well as sent, even when
        // its source and destination differ (127.0.0.1 -> 127.0.0.2). Our
        // IPv4 probes carry a fixed IP id that a target's reply never
        // echoes, so that alone identifies them; IPv6 has no such field, so
        // there we can only catch the same-address loopback echo.
        let ours = match pkt.ipid {
            Some(id) => id == probe.ipid,
            None => {
                pkt.src == pkt.dst
                    && pkt.payload == probe.body(pkt.protocol, pkt.src, pkt.dst).as_slice()
            }
        };
        if ours {
            return out;
        }
        let icmp = if v6 { IPPROTO_ICMPV6 } else { IPPROTO_ICMP };
        if pkt.protocol == icmp
            && let Some(e) = packet::parse_icmp_error(pkt.payload, v6)
            // Only an error quoting our own probe (same fixed IP id) counts;
            // another application's traffic to the same host must not.
            && e.id.is_none_or(|id| id == probe.ipid)
            && let Some(&host) = index.get(&e.dst)
            && let Some((state, why)) = error_state(v6, e.kind, e.code, pkt.src == e.dst)
        {
            out.push(Answer {
                host,
                key: u16::from(e.protocol),
                state,
                reason: why,
            });
        }
        if let Some(&host) = index.get(&pkt.src) {
            let why = match packet::parse_icmp(pkt.payload) {
                Some(m)
                    if pkt.protocol == IPPROTO_ICMP && (m.kind, m.code) == (ICMP_ECHO_REPLY, 0) =>
                {
                    reason::ECHO_REPLY
                }
                Some(m) if pkt.protocol == icmp => {
                    rawscan::icmp_reason(v6, m.kind, m.code).unwrap_or(reason::PROTO_RESPONSE)
                }
                _ => reason::PROTO_RESPONSE,
            };
            out.push(Answer {
                host,
                key: u16::from(pkt.protocol),
                state: PortState::Open,
                reason: why,
            });
        }
        out
    }

    /// The state an ICMP error gives the protocol it quotes, as nmap
    /// decides it: `from_target` says the target itself sent the error.
    pub(super) fn error_state(
        v6: bool,
        kind: u8,
        code: u8,
        from_target: bool,
    ) -> Option<(PortState, &'static str)> {
        let why = rawscan::icmp_reason(v6, kind, code)?;
        let state = match (v6, kind, code) {
            (false, ICMP_DEST_UNREACH, 2) if from_target => PortState::Closed,
            (false, ICMP_DEST_UNREACH, 3) | (true, ICMPV6_DEST_UNREACH, 4) if from_target => {
                PortState::Open
            }
            (true, ICMPV6_PARAM_PROBLEM, 0) => PortState::Open,
            (true, ICMPV6_PARAM_PROBLEM, 1) if from_target => PortState::Closed,
            // nmap leaves ICMPv6 time exceeded alone in this scan.
            (true, kind, _) if kind != ICMPV6_DEST_UNREACH && kind != ICMPV6_PARAM_PROBLEM => {
                return None;
            }
            _ => PortState::Filtered,
        };
        Some((state, why))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::raw::raw_sockets_available;
        use std::net::Ipv4Addr;
        use std::time::Duration;

        const PROBE: Probe = Probe {
            sport: 40000,
            seq: 5,
            ipid: 0x1234,
            icmp_id: 9,
        };

        fn target() -> IpAddr {
            Ipv4Addr::new(10, 0, 0, 9).into()
        }

        fn index() -> Index {
            [(target(), 0)].into()
        }

        fn packet_from(src: IpAddr, protocol: u8, payload: &[u8]) -> Packet<'_> {
            Packet {
                src,
                dst: Ipv4Addr::new(10, 0, 0, 1).into(),
                protocol,
                ttl: 64,
                ipid: Some(7),
                payload,
            }
        }

        fn unreachable(code: u8, quoted_proto: u8) -> Vec<u8> {
            let quoted = packet::ipv4_packet(
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 0, 0, 9),
                quoted_proto,
                64,
                PROBE.ipid,
                &[],
            );
            let mut msg = vec![ICMP_DEST_UNREACH, code, 0, 0, 0, 0, 0, 0];
            msg.extend_from_slice(&quoted);
            msg
        }

        fn got(answers: Vec<Answer>) -> Vec<(u16, PortState, &'static str)> {
            answers.iter().map(|a| (a.key, a.state, a.reason)).collect()
        }

        #[test]
        fn reads_answers_like_nmap() {
            let idx = index();
            // Protocol unreachable from the target: 47 closed, and the
            // target speaks ICMP.
            let msg = unreachable(2, 47);
            assert_eq!(
                got(answers(
                    &packet_from(target(), IPPROTO_ICMP, &msg),
                    &idx,
                    &PROBE
                )),
                [
                    (47, PortState::Closed, reason::PROTO_UNREACH),
                    (1, PortState::Open, reason::PROTO_UNREACH)
                ]
            );
            // Port unreachable: the UDP probe reached a UDP stack.
            let msg = unreachable(3, IPPROTO_UDP);
            assert_eq!(
                got(answers(
                    &packet_from(target(), IPPROTO_ICMP, &msg),
                    &idx,
                    &PROBE
                ))[0],
                (17, PortState::Open, reason::PORT_UNREACH)
            );
            // The same error from a router only says filtered.
            let router: IpAddr = Ipv4Addr::new(10, 0, 0, 254).into();
            let msg = unreachable(2, 47);
            assert_eq!(
                got(answers(
                    &packet_from(router, IPPROTO_ICMP, &msg),
                    &idx,
                    &PROBE
                )),
                [(47, PortState::Filtered, reason::PROTO_UNREACH)]
            );
            // A TCP reset from the target: TCP is open.
            let rst = packet::tcp_probe(
                target(),
                Ipv4Addr::new(10, 0, 0, 1),
                80,
                40000,
                0,
                0,
                packet::TCP_RST,
            );
            assert_eq!(
                got(answers(
                    &packet_from(target(), IPPROTO_TCP, &rst),
                    &idx,
                    &PROBE
                )),
                [(6, PortState::Open, reason::PROTO_RESPONSE)]
            );
            // An echo reply.
            let reply = {
                let mut r = packet::icmp_echo(9, 0, &[]);
                r[0] = ICMP_ECHO_REPLY;
                r
            };
            assert_eq!(
                got(answers(
                    &packet_from(target(), IPPROTO_ICMP, &reply),
                    &idx,
                    &PROBE
                )),
                [(1, PortState::Open, reason::ECHO_REPLY)]
            );
        }

        #[test]
        fn own_probes_on_loopback_are_not_answers() {
            let lo: IpAddr = Ipv4Addr::LOCALHOST.into();
            let idx: Index = [(lo, 0)].into();
            let mine = Packet {
                src: lo,
                dst: lo,
                protocol: 47,
                ttl: 64,
                ipid: Some(PROBE.ipid),
                payload: &[],
            };
            assert!(answers(&mine, &idx, &PROBE).is_empty());
            let theirs = Packet {
                ipid: Some(PROBE.ipid + 1),
                ..mine
            };
            assert_eq!(answers(&theirs, &idx, &PROBE).len(), 1);
        }

        #[test]
        fn icmpv6_errors_follow_nmap() {
            let open = (PortState::Open, reason::PARAM_PROBLEM);
            assert_eq!(
                error_state(true, ICMPV6_PARAM_PROBLEM, 0, false),
                Some(open)
            );
            assert_eq!(
                error_state(true, ICMPV6_PARAM_PROBLEM, 1, true),
                Some((PortState::Closed, reason::PARAM_PROBLEM))
            );
            assert_eq!(
                error_state(true, ICMPV6_DEST_UNREACH, 4, true),
                Some((PortState::Open, reason::PORT_UNREACH))
            );
            assert_eq!(
                error_state(true, packet::ICMPV6_TIME_EXCEEDED, 0, true),
                None
            );
            assert_eq!(
                error_state(false, packet::ICMP_TIME_EXCEEDED, 0, false),
                Some((PortState::Filtered, reason::TIME_EXCEEDED))
            );
        }

        #[test]
        fn scans_localhost() {
            if !raw_sockets_available() {
                assert!(
                    std::env::var_os("FEROPROBE_REQUIRE_RAW").is_none(),
                    "FEROPROBE_REQUIRE_RAW is set but raw sockets are unavailable"
                );
                eprintln!("note: no raw-socket privileges, -sO test not run");
                return;
            }
            let cfg = ScanConfig {
                timeout: Duration::from_millis(400),
                retries: 0,
                ..Default::default()
            };
            let target = Target::new("127.0.0.1".parse().unwrap());
            // 253 is reserved for experiments: Linux has no handler.
            let hosts = scan_blocking(&[target], &[1, 6, 17, 253], &cfg).unwrap();
            let state = |p: u16| {
                let r = hosts[0].ports.iter().find(|r| r.port == p).unwrap();
                (r.protocol, r.state)
            };
            assert_eq!(state(1), (Protocol::Ip, PortState::Open));
            assert_eq!(state(6), (Protocol::Ip, PortState::Open));
            assert_eq!(state(17), (Protocol::Ip, PortState::Open));
            assert_eq!(state(253), (Protocol::Ip, PortState::Closed));
        }
    }
}
