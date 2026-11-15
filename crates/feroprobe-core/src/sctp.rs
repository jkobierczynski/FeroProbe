//! SCTP port scans, like nmap's `-sY` and `-sZ`.
//!
//! The INIT scan (`-sY`) is SCTP's half-open scan: it sends the first
//! chunk of the four-way handshake and never finishes it.
//!
//! - **open**: the host answered with an INIT-ACK
//! - **closed**: it answered with an ABORT
//! - **filtered**: no answer after all retries, or an ICMP unreachable error
//!
//! The COOKIE ECHO scan (`-sZ`) sends the handshake's third chunk out of
//! the blue. An open port silently drops it and a closed one aborts, so it
//! reports **closed** on an ABORT and **open|filtered** on silence, and it
//! cannot tell an open port from a filtered one. Some firewalls that block
//! INIT chunks let it through.
//!
//! Both need root (or `CAP_NET_RAW`) and are Linux only. IPv4 and IPv6
//! targets can be mixed.

use std::io;

use crate::model::{HostResult, PortState, ScanConfig};
use crate::target::Target;

/// Which SCTP scan to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SctpScanKind {
    /// `-sY`: INIT.
    Init,
    /// `-sZ`: COOKIE ECHO.
    CookieEcho,
}

impl SctpScanKind {
    /// nmap's name for the scan, as in the XML `scaninfo` element.
    pub fn name(self) -> &'static str {
        match self {
            SctpScanKind::Init => "sctpinit",
            SctpScanKind::CookieEcho => "sctpcookieecho",
        }
    }

    /// The state of a port that never answered.
    pub fn no_response(self) -> PortState {
        match self {
            SctpScanKind::Init => PortState::Filtered,
            SctpScanKind::CookieEcho => PortState::OpenFiltered,
        }
    }

    /// What an SCTP answer with first chunk `chunk` says about the port,
    /// or `None` if this scan ignores it.
    pub fn classify(self, chunk: u8) -> Option<(PortState, &'static str)> {
        use crate::model::reason;
        use crate::packet::{SCTP_ABORT, SCTP_INIT_ACK};
        match (self, chunk) {
            (SctpScanKind::Init, SCTP_INIT_ACK) => Some((PortState::Open, reason::INIT_ACK)),
            (_, SCTP_ABORT) => Some((PortState::Closed, reason::ABORT)),
            _ => None,
        }
    }
}

/// Run an SCTP scan of every port on every target. Target addresses must
/// be distinct (the CLI resolver guarantees this); a repeated address
/// would leave every copy but one reporting no response.
pub async fn sctp_scan(
    targets: &[Target],
    ports: &[u16],
    cfg: &ScanConfig,
    kind: SctpScanKind,
) -> io::Result<Vec<HostResult>> {
    let (targets, ports, cfg) = (targets.to_vec(), ports.to_vec(), cfg.clone());
    tokio::task::spawn_blocking(move || imp::scan_blocking(&targets, &ports, &cfg, kind))
        .await
        .map_err(io::Error::other)?
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::*;

    pub(super) fn scan_blocking(
        _: &[Target],
        _: &[u16],
        _: &ScanConfig,
        _: SctpScanKind,
    ) -> io::Result<Vec<HostResult>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "SCTP scans (-sY, -sZ) are only supported on Linux for now",
        ))
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;

    use std::net::IpAddr;

    use socket2::{Domain, Protocol as SockProto, Socket};

    use crate::capture::Packet;
    use crate::model::{PortState, Protocol};
    use crate::packet::{self, IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_SCTP};
    use crate::raw::{Rng, nmap_ip_header, raw_socket_in, send_with_backoff_until};
    use crate::rawscan::{self, Answer, Index};
    use crate::target::socket_addr;

    pub(super) fn scan_blocking(
        targets: &[Target],
        ports: &[u16],
        cfg: &ScanConfig,
        kind: SctpScanKind,
    ) -> io::Result<Vec<HostResult>> {
        let open = |domain| raw_socket_in(domain, SockProto::from(i32::from(IPPROTO_SCTP)));
        let v4 = if targets.iter().any(|t| t.addr.is_ipv4()) {
            Some(open(Domain::IPV4)?)
        } else {
            None
        };
        let v6: Option<Socket> = if targets.iter().any(|t| t.addr.is_ipv6()) {
            match open(Domain::IPV6) {
                Ok(s) => Some(s),
                // No IPv6 here: those targets are unreachable.
                Err(e) if e.raw_os_error() == Some(libc::EAFNOSUPPORT) => None,
                Err(e) => return Err(e),
            }
        } else {
            None
        };

        let mut rng = Rng::new();
        let sport = crate::raw::probe_sport(cfg, &mut rng);
        // Our INIT's initiate tag, and the tag of our COOKIE ECHO: answers
        // carry it as their verification tag.
        let tag = rng.next_u32() | 1;
        let tsn = rng.next_u32();
        // The tag an ICMP error quotes from our probe.
        let sent_vtag = match kind {
            SctpScanKind::Init => 0,
            SctpScanKind::CookieEcho => tag,
        };

        let send = |_: usize, port: u16, _: IpAddr, dst: IpAddr| -> io::Result<()> {
            let pkt = match kind {
                SctpScanKind::Init => packet::sctp_init(sport, port, tag, tsn),
                SctpScanKind::CookieEcho => packet::sctp_cookie_echo(sport, port, tag, tsn),
            };
            let sock = if dst.is_ipv6() {
                v6.as_ref()
            } else {
                v4.as_ref()
            };
            let Some(sock) = sock else {
                return Err(io::Error::from_raw_os_error(libc::ENETUNREACH));
            };
            nmap_ip_header(sock, dst.is_ipv6());
            send_with_backoff_until(sock, &pkt, socket_addr(dst, 0), cfg.deadline)
        };
        let classify = move |pkt: &Packet<'_>, index: &Index| -> Vec<Answer> {
            answer(pkt, index, kind, sport, tag, sent_vtag)
                .into_iter()
                .collect()
        };
        rawscan::run(
            targets,
            ports,
            cfg,
            Protocol::Sctp,
            kind.no_response(),
            send,
            classify,
        )
    }

    /// What a captured packet says about one of our probes: an SCTP
    /// answer from a target to our port with our tag, or an ICMP error
    /// quoting one of our probes.
    pub(super) fn answer(
        pkt: &Packet<'_>,
        index: &Index,
        kind: SctpScanKind,
        sport: u16,
        tag: u32,
        sent_vtag: u32,
    ) -> Option<Answer> {
        match pkt.protocol {
            IPPROTO_SCTP => {
                let s = packet::parse_sctp(pkt.payload)?;
                if s.dport != sport || s.vtag != tag {
                    return None;
                }
                let (state, reason) = kind.classify(s.chunk)?;
                Some(Answer {
                    host: *index.get(&pkt.src)?,
                    key: s.sport,
                    state,
                    reason,
                })
            }
            IPPROTO_ICMP | IPPROTO_ICMPV6 => {
                let v6 = pkt.protocol == IPPROTO_ICMPV6;
                let e = packet::parse_icmp_error(pkt.payload, v6)?;
                let q = e.quoted;
                if e.protocol != IPPROTO_SCTP || q.len() < 8 {
                    return None;
                }
                let qsport = u16::from_be_bytes([q[0], q[1]]);
                let qvtag = u32::from_be_bytes([q[4], q[5], q[6], q[7]]);
                if qsport != sport || qvtag != sent_vtag {
                    return None;
                }
                Some(Answer {
                    host: *index.get(&e.dst)?,
                    key: u16::from_be_bytes([q[2], q[3]]),
                    state: PortState::Filtered,
                    reason: rawscan::icmp_reason(v6, e.kind, e.code)?,
                })
            }
            _ => None,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::model::reason;
        use crate::raw::raw_sockets_available;
        use std::net::Ipv4Addr;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::Duration;

        fn index() -> Index {
            [(IpAddr::from(Ipv4Addr::new(10, 0, 0, 9)), 0)].into()
        }

        fn from_target(protocol: u8, payload: &[u8]) -> Packet<'_> {
            Packet {
                src: Ipv4Addr::new(10, 0, 0, 9).into(),
                dst: Ipv4Addr::new(10, 0, 0, 1).into(),
                protocol,
                ttl: 64,
                ipid: Some(1),
                payload,
            }
        }

        /// An SCTP packet with one bare chunk of type `chunk`.
        fn sctp(sport: u16, dport: u16, vtag: u32, chunk: u8) -> Vec<u8> {
            let mut p = Vec::new();
            p.extend_from_slice(&sport.to_be_bytes());
            p.extend_from_slice(&dport.to_be_bytes());
            p.extend_from_slice(&vtag.to_be_bytes());
            p.extend_from_slice(&[0; 4]);
            p.extend_from_slice(&[chunk, 0, 0, 4]);
            p
        }

        #[test]
        fn answers_by_chunk_and_tag() {
            let idx = index();
            let init = SctpScanKind::Init;
            let a = |p: &[u8], kind| answer(&from_target(IPPROTO_SCTP, p), &idx, kind, 40000, 7, 0);
            let ack = sctp(2905, 40000, 7, packet::SCTP_INIT_ACK);
            assert_eq!(
                a(&ack, init).map(|a| (a.key, a.state, a.reason)),
                Some((2905, PortState::Open, reason::INIT_ACK))
            );
            let abort = sctp(80, 40000, 7, packet::SCTP_ABORT);
            assert_eq!(a(&abort, init).unwrap().state, PortState::Closed);
            assert_eq!(
                a(&abort, SctpScanKind::CookieEcho).unwrap().state,
                PortState::Closed
            );
            // An INIT-ACK means nothing to the COOKIE ECHO scan.
            assert!(a(&ack, SctpScanKind::CookieEcho).is_none());
            // Wrong tag, wrong port, or our own INIT seen on loopback.
            assert!(a(&sctp(2905, 40000, 8, packet::SCTP_INIT_ACK), init).is_none());
            assert!(a(&sctp(2905, 40001, 7, packet::SCTP_INIT_ACK), init).is_none());
            assert!(a(&packet::sctp_init(40000, 2905, 7, 1), init).is_none());
        }

        #[test]
        fn icmp_errors_quote_our_probe() {
            let idx = index();
            let probe = packet::sctp_init(40000, 2905, 7, 1);
            let quoted = packet::ipv4_packet(
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 0, 0, 9),
                IPPROTO_SCTP,
                64,
                1,
                &probe,
            );
            let mut msg = vec![3, 2, 0, 0, 0, 0, 0, 0];
            msg.extend_from_slice(&quoted);
            let pkt = from_target(IPPROTO_ICMP, &msg);
            let got = answer(&pkt, &idx, SctpScanKind::Init, 40000, 7, 0).unwrap();
            assert_eq!(
                (got.key, got.state, got.reason),
                (2905, PortState::Filtered, reason::PROTO_UNREACH)
            );
            // A quote of someone else's probe (other tag) is not ours.
            assert!(answer(&pkt, &idx, SctpScanKind::CookieEcho, 40000, 7, 7).is_none());
        }

        /// Raw sockets need root. CI runs the tests with sudo and sets
        /// FEROPROBE_REQUIRE_RAW=1 so these cannot silently pass there.
        fn privileged() -> bool {
            let ok = raw_sockets_available();
            if !ok {
                assert!(
                    std::env::var_os("FEROPROBE_REQUIRE_RAW").is_none(),
                    "FEROPROBE_REQUIRE_RAW is set but raw sockets are unavailable"
                );
                eprintln!("note: no raw-socket privileges, SCTP scan test not run");
            }
            ok
        }

        /// A stand-in SCTP stack on 127.0.0.1: answers INITs to `open`
        /// with an INIT-ACK and everything else with an ABORT. Raw sockets
        /// see SCTP whether or not the kernel has an SCTP module; without
        /// one, the kernel stays quiet while a raw socket is listening.
        fn fake_stack(open: u16, stop: Arc<AtomicBool>) -> std::thread::JoinHandle<()> {
            let sock = raw_socket_in(Domain::IPV4, SockProto::from(132)).unwrap();
            sock.set_read_timeout(Some(Duration::from_millis(50)))
                .unwrap();
            std::thread::spawn(move || {
                let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 2048];
                while !stop.load(Ordering::Relaxed) {
                    let Ok((n, _)) = sock.recv_from(&mut buf) else {
                        continue;
                    };
                    // SAFETY: recv_from initialised the first `n` bytes.
                    let data = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), n) };
                    let Some(ip) = packet::parse_ipv4(data) else {
                        continue;
                    };
                    let Some(s) = packet::parse_sctp(ip.payload) else {
                        continue;
                    };
                    if s.chunk != packet::SCTP_INIT && s.chunk != packet::SCTP_COOKIE_ECHO {
                        continue;
                    }
                    let tag = if s.chunk == packet::SCTP_INIT {
                        u32::from_be_bytes(ip.payload[16..20].try_into().unwrap())
                    } else {
                        s.vtag
                    };
                    let chunk = if s.chunk == packet::SCTP_INIT && s.dport == open {
                        packet::SCTP_INIT_ACK
                    } else {
                        packet::SCTP_ABORT
                    };
                    let mut reply = sctp(s.dport, s.sport, tag, chunk);
                    let crc = packet::crc32c(&reply);
                    reply[8..12].copy_from_slice(&crc.to_le_bytes());
                    let to = socket_addr(IpAddr::from(ip.src), 0);
                    let _ = sock.send_to(&reply, &to.into());
                }
            })
        }

        #[test]
        fn scans_a_fake_stack_on_localhost() {
            if !privileged() {
                return;
            }
            // With the kernel SCTP module loaded, the kernel answers our
            // probe to the unbound port itself (an ABORT) and can beat the
            // fake stack's INIT-ACK; a raw socket does not displace that
            // handler, so the open-port assertion would be flaky. Skip it
            // there rather than racing the kernel.
            if std::path::Path::new("/proc/net/sctp").exists() {
                eprintln!("note: kernel SCTP active, fake-stack test not run");
                return;
            }
            let stop = Arc::new(AtomicBool::new(false));
            let stack = fake_stack(2905, Arc::clone(&stop));
            let cfg = ScanConfig {
                rtt: crate::rtt::RttTimeouts::fixed(Duration::from_millis(400)),
                retries: 0,
                ..Default::default()
            };
            let target = Target::new("127.0.0.1".parse().unwrap());
            let init = scan_blocking(
                std::slice::from_ref(&target),
                &[2905, 3868],
                &cfg,
                SctpScanKind::Init,
            )
            .unwrap();
            let echo =
                scan_blocking(&[target], &[2905, 3868], &cfg, SctpScanKind::CookieEcho).unwrap();
            stop.store(true, Ordering::Relaxed);
            stack.join().unwrap();
            let state = |hosts: &[HostResult], p: u16| {
                let r = hosts[0].ports.iter().find(|r| r.port == p).unwrap();
                (r.protocol, r.state, r.reason)
            };
            assert_eq!(
                state(&init, 2905),
                (Protocol::Sctp, PortState::Open, reason::INIT_ACK)
            );
            assert_eq!(
                state(&init, 3868),
                (Protocol::Sctp, PortState::Closed, reason::ABORT)
            );
            // The fake stack aborts every COOKIE ECHO, like a closed port.
            assert_eq!(state(&echo, 3868).1, PortState::Closed);
        }
    }
}
