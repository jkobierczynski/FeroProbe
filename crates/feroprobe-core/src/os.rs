//! OS detection (`-O`) from how a host answers one SYN.
//!
//! We send a SYN that offers every common TCP option to an open port and
//! read the SYN-ACK off a raw socket. Operating systems differ in:
//!
//! - the initial IP TTL (64 for Linux, BSD and macOS, 128 for Windows, 255
//!   for many network devices), seen after a few hops as a lower value;
//! - which TCP options they echo and in what order;
//! - their window size and window scale, and the "don't fragment" bit.
//!
//! These traits are matched against FeroProbe's own signature list below.
//! nmap's OS database is not used (its license does not allow
//! redistribution), so this is a coarser, family-level guess, like p0f's.
//! It needs raw sockets: Linux, IPv4, root or `CAP_NET_RAW`.

use std::io;
use std::net::{IpAddr, Ipv4Addr};

use serde::Serialize;

use crate::model::{HostResult, PortState, Protocol, ScanConfig};
use crate::packet;

/// What one SYN-ACK told us.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TcpTraits {
    pub ttl: u8,
    pub df: bool,
    pub window: u16,
    /// Option kinds in order: M (MSS), S (SACK permitted), T (timestamps),
    /// N (no-op), W (window scale), E (end of list), or a number.
    pub options: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mss: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wscale: Option<u8>,
}

impl TcpTraits {
    /// Read the traits from a SYN-ACK's IP header fields and TCP header.
    pub fn from_reply(ttl: u8, df: bool, tcp: &[u8]) -> Option<Self> {
        let window = packet::parse_tcp(tcp)?.window;
        let opts = packet::tcp_options(tcp);
        let (mut kinds, mut mss, mut wscale) = (Vec::new(), None, None);
        let mut i = 0;
        while i < opts.len() {
            let kind = opts[i];
            match kind {
                0 => {
                    kinds.push("E".to_string());
                    break;
                }
                1 => {
                    kinds.push("N".to_string());
                    i += 1;
                    continue;
                }
                _ => {}
            }
            let len = usize::from(*opts.get(i + 1)?);
            // A malformed option makes the whole reply unusable.
            if len < 2 || i + len > opts.len() {
                return None;
            }
            let body = &opts[i + 2..i + len];
            kinds.push(match kind {
                2 => {
                    mss = (body.len() == 2).then(|| u16::from_be_bytes([body[0], body[1]]));
                    "M".to_string()
                }
                3 => {
                    wscale = body.first().copied();
                    "W".to_string()
                }
                4 => "S".to_string(),
                8 => "T".to_string(),
                k => k.to_string(),
            });
            i += len;
        }
        Some(Self {
            ttl,
            df,
            window,
            options: kinds.join(","),
            mss,
            wscale,
        })
    }

    /// The likely initial TTL: the next common starting value.
    pub fn initial_ttl(&self) -> u8 {
        match self.ttl {
            0..=32 => 32,
            33..=64 => 64,
            65..=128 => 128,
            _ => 255,
        }
    }

    /// Compact form for reports: `ttl=64 df=1 win=65483 opts=M,S,T,N,W mss=65495 ws=7`.
    pub fn fingerprint(&self) -> String {
        let mut s = format!(
            "ttl={} df={} win={} opts={}",
            self.ttl,
            u8::from(self.df),
            self.window,
            if self.options.is_empty() {
                "-"
            } else {
                &self.options
            }
        );
        if let Some(m) = self.mss {
            s.push_str(&format!(" mss={m}"));
        }
        if let Some(w) = self.wscale {
            s.push_str(&format!(" ws={w}"));
        }
        s
    }
}

/// The OS guess for one host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OsMatch {
    /// What we think runs there, such as `Linux 3.x - 6.x`.
    pub name: String,
    pub vendor: &'static str,
    pub family: &'static str,
    /// `general purpose` or `network device`, like nmap's device type.
    pub device_type: &'static str,
    /// How sure we are, in percent.
    pub accuracy: u8,
    /// Routers between us and the host, from the TTL. 0 for this machine.
    pub distance: u8,
    /// The open port that answered.
    pub port: u16,
    pub traits: TcpTraits,
}

struct Signature {
    name: &'static str,
    vendor: &'static str,
    family: &'static str,
    device_type: &'static str,
    initial_ttl: u8,
    /// Exact option layout, or `None` to match on TTL alone.
    options: Option<&'static str>,
}

const GP: &str = "general purpose";

/// Most specific first. A layout match scores higher than a TTL-only match.
const SIGNATURES: &[Signature] = &[
    Signature {
        name: "Linux 3.x - 6.x",
        vendor: "Linux",
        family: "Linux",
        device_type: GP,
        initial_ttl: 64,
        options: Some("M,S,T,N,W"),
    },
    Signature {
        name: "Linux (TCP timestamps disabled)",
        vendor: "Linux",
        family: "Linux",
        device_type: GP,
        initial_ttl: 64,
        options: Some("M,N,N,S,N,W"),
    },
    // Linux writes its options in a fixed order (MSS, SACK with timestamps,
    // window scale) and pads with NOPs when one is turned off by sysctl.
    Signature {
        name: "Linux (TCP SACK disabled)",
        vendor: "Linux",
        family: "Linux",
        device_type: GP,
        initial_ttl: 64,
        options: Some("M,N,N,T,N,W"),
    },
    Signature {
        name: "Linux (TCP window scaling disabled)",
        vendor: "Linux",
        family: "Linux",
        device_type: GP,
        initial_ttl: 64,
        options: Some("M,S,T"),
    },
    Signature {
        name: "Linux (TCP timestamps and window scaling disabled)",
        vendor: "Linux",
        family: "Linux",
        device_type: GP,
        initial_ttl: 64,
        options: Some("M,N,N,S"),
    },
    Signature {
        name: "Linux (TCP SACK and timestamps disabled)",
        vendor: "Linux",
        family: "Linux",
        device_type: GP,
        initial_ttl: 64,
        options: Some("M,N,W"),
    },
    Signature {
        name: "Linux (TCP SACK and window scaling disabled)",
        vendor: "Linux",
        family: "Linux",
        device_type: GP,
        initial_ttl: 64,
        options: Some("M,N,N,T"),
    },
    Signature {
        name: "Apple macOS or iOS",
        vendor: "Apple",
        family: "macOS",
        device_type: GP,
        initial_ttl: 64,
        options: Some("M,N,W,N,N,T,S,E"),
    },
    Signature {
        name: "FreeBSD",
        vendor: "FreeBSD",
        family: "FreeBSD",
        device_type: GP,
        initial_ttl: 64,
        options: Some("M,N,W,S,T"),
    },
    Signature {
        name: "OpenBSD",
        vendor: "OpenBSD",
        family: "OpenBSD",
        device_type: GP,
        initial_ttl: 64,
        options: Some("M,N,N,S,N,W,N,N,T"),
    },
    Signature {
        name: "Microsoft Windows 10, 11 or Server 2016+",
        vendor: "Microsoft",
        family: "Windows",
        device_type: GP,
        initial_ttl: 128,
        options: Some("M,N,W,N,N,S"),
    },
    Signature {
        name: "Microsoft Windows (TCP timestamps enabled)",
        vendor: "Microsoft",
        family: "Windows",
        device_type: GP,
        initial_ttl: 128,
        options: Some("M,N,W,S,T"),
    },
    Signature {
        name: "Microsoft Windows XP or Server 2003, or newer with window scaling off",
        vendor: "Microsoft",
        family: "Windows",
        device_type: GP,
        initial_ttl: 128,
        options: Some("M,N,N,S"),
    },
    Signature {
        name: "Cisco IOS or similar network device",
        vendor: "Cisco",
        family: "IOS",
        device_type: "network device",
        initial_ttl: 255,
        options: Some("M"),
    },
    // TTL alone.
    Signature {
        name: "Microsoft Windows",
        vendor: "Microsoft",
        family: "Windows",
        device_type: GP,
        initial_ttl: 128,
        options: None,
    },
    Signature {
        name: "Unix-like (Linux, BSD or macOS)",
        vendor: "unknown",
        family: "Unix",
        device_type: GP,
        initial_ttl: 64,
        options: None,
    },
    Signature {
        name: "Network device, Solaris or AIX",
        vendor: "unknown",
        family: "unknown",
        device_type: "network device",
        initial_ttl: 255,
        options: None,
    },
];

/// Match traits against the signatures. `loopback` sets the distance to 0.
pub fn classify(traits: TcpTraits, port: u16, loopback: bool) -> Option<OsMatch> {
    let initial = traits.initial_ttl();
    let sig = SIGNATURES
        .iter()
        .find(|s| s.initial_ttl == initial && s.options.is_none_or(|o| o == traits.options))?;
    let mut accuracy: u8 = if sig.options.is_some() { 90 } else { 60 };
    // Linux, BSD, macOS and Windows set DF on SYN-ACKs.
    if sig.device_type == GP && !traits.df {
        accuracy -= 10;
    }
    let distance = if loopback {
        0
    } else {
        initial.saturating_sub(traits.ttl).saturating_add(1)
    };
    Some(OsMatch {
        name: sig.name.to_string(),
        vendor: sig.vendor,
        family: sig.family,
        device_type: sig.device_type,
        accuracy,
        distance,
        port,
        traits,
    })
}

/// Guess the OS of every host with an open TCP port, filling in
/// [`HostResult::os`]. Hosts without one, IPv6 hosts and hosts that did not
/// answer are left alone.
pub async fn os_detect(hosts: &mut [HostResult], cfg: &ScanConfig) -> io::Result<()> {
    let jobs: Vec<(usize, Ipv4Addr, u16)> = hosts
        .iter()
        .enumerate()
        .filter_map(|(h, host)| {
            let IpAddr::V4(addr) = host.addr else {
                return None;
            };
            let port = host
                .ports
                .iter()
                .find(|p| p.protocol == Protocol::Tcp && p.state == PortState::Open)?
                .port;
            Some((h, addr, port))
        })
        .collect();
    if jobs.is_empty() {
        return Ok(());
    }
    let cfg = cfg.clone();
    let probe_jobs = jobs.clone();
    let replies = tokio::task::spawn_blocking(move || imp::probe_blocking(&probe_jobs, &cfg))
        .await
        .map_err(io::Error::other)??;
    for (job, traits) in jobs.iter().zip(replies) {
        let (h, addr, port) = *job;
        if let Some(traits) = traits {
            hosts[h].os = classify(traits, port, addr.is_loopback());
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::*;

    pub(super) fn probe_blocking(
        _: &[(usize, Ipv4Addr, u16)],
        _: &ScanConfig,
    ) -> io::Result<Vec<Option<TcpTraits>>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "OS detection is only supported on Linux for now",
        ))
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;

    use std::io::Read;
    use std::time::{Duration, Instant};

    use socket2::Protocol as SockProto;

    use crate::raw::{Pacer, Rng, raw_socket, send_with_backoff_until, source_addr_for};

    /// Send one option-rich SYN to each job's port and collect the SYN-ACKs,
    /// in job order. Unanswered probes are retried `cfg.retries` times.
    pub(super) fn probe_blocking(
        jobs: &[(usize, Ipv4Addr, u16)],
        cfg: &ScanConfig,
    ) -> io::Result<Vec<Option<TcpTraits>>> {
        let send_sock = raw_socket(SockProto::TCP)?;
        let mut recv_sock = raw_socket(SockProto::TCP)?;
        recv_sock.set_read_timeout(Some(Duration::from_millis(50)))?;

        let mut rng = Rng::new();
        let sport = 40000 + (rng.next_u32() % 20000) as u16;
        let seq = rng.next_u32();
        let tsval = rng.next_u32();
        let mut found: Vec<Option<TcpTraits>> = vec![None; jobs.len()];
        let sources: Vec<Option<Ipv4Addr>> = jobs
            .iter()
            .map(|&(_, addr, _)| match source_addr_for(addr.into()) {
                Ok(std::net::IpAddr::V4(src)) => Some(src),
                _ => None,
            })
            .collect();
        let mut pacer = Pacer::for_config(cfg);
        let mut buf = vec![0u8; 65536];

        let syn_ack = packet::TCP_SYN | packet::TCP_ACK;
        // Record one reply. Returns true when it completed a job.
        let take = |reply: &[u8], found: &mut [Option<TcpTraits>]| -> bool {
            let Some(ip) = packet::parse_ipv4(reply) else {
                return false;
            };
            let Some(tcp) = packet::parse_tcp(ip.payload) else {
                return false;
            };
            if ip.protocol != packet::IPPROTO_TCP
                || tcp.dport != sport
                || tcp.flags & syn_ack != syn_ack
                || tcp.ack != seq.wrapping_add(1)
            {
                return false;
            }
            let Some(j) = jobs
                .iter()
                .position(|&(_, addr, port)| addr == ip.src && port == tcp.sport)
            else {
                return false;
            };
            if found[j].is_some() {
                return false;
            }
            // A malformed reply leaves the job open for a valid one.
            found[j] = TcpTraits::from_reply(ip.ttl, ip.df, ip.payload);
            found[j].is_some()
        };
        let quiet = |e: &io::Error| {
            matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
            )
        };

        for _ in 0..=cfg.retries {
            if cfg.expired() {
                return Err(ScanConfig::timed_out());
            }
            let mut waiting = (0..jobs.len())
                .filter(|&j| found[j].is_none() && sources[j].is_some())
                .count();
            if waiting == 0 {
                break;
            }
            // Drain replies between sends so a large batch of fast
            // responders cannot overflow the receive buffer.
            recv_sock.set_nonblocking(true)?;
            for (j, &(_, addr, port)) in jobs.iter().enumerate() {
                let (None, Some(src)) = (&found[j], sources[j]) else {
                    continue;
                };
                let pkt = packet::tcp_syn_with_options(src, addr, sport, port, seq, tsval);
                // The wait gives up at the host deadline (--host-timeout).
                if !pacer.wait_until(cfg.deadline) {
                    return Err(ScanConfig::timed_out());
                }
                send_with_backoff_until(&send_sock, &pkt, (addr, 0).into(), cfg.deadline)?;
                // Bounded, so constant inbound traffic can't stall sending.
                // Whatever is left is read by the next drain or the wait.
                let drain_until = Instant::now() + Duration::from_millis(10);
                while Instant::now() < drain_until {
                    match recv_sock.read(&mut buf) {
                        // Late replies do not count, as in the wait below.
                        Ok(_) if cfg.expired() => break,
                        Ok(n) => {
                            if take(&buf[..n], &mut found) {
                                trace_reply(&buf[..n]);
                                waiting -= 1;
                            }
                        }
                        Err(e) if quiet(&e) => break,
                        Err(e) => return Err(e),
                    }
                }
            }
            recv_sock.set_nonblocking(false)?;
            let mut deadline = Instant::now() + cfg.timeout;
            if let Some(limit) = cfg.deadline {
                deadline = deadline.min(limit);
            }
            while waiting > 0 && Instant::now() < deadline {
                match recv_sock.read(&mut buf) {
                    // A read can block past the host deadline: a reply
                    // that arrives after it does not count.
                    Ok(_) if cfg.expired() => break,
                    Ok(n) => {
                        if take(&buf[..n], &mut found) {
                            trace_reply(&buf[..n]);
                            waiting -= 1;
                        }
                    }
                    Err(e) if quiet(&e) => {}
                    Err(e) => return Err(e),
                }
            }
            // The wait ended at the host deadline with probes unanswered.
            if waiting > 0 && cfg.expired() {
                return Err(ScanConfig::timed_out());
            }
        }
        Ok(found)
    }

    /// `--packet-trace` line for an answer OS detection kept.
    fn trace_reply(data: &[u8]) {
        crate::packet_trace::log("RCVD", || match packet::parse_ipv4(data) {
            Some(ip) => crate::packet_trace::describe_received(
                packet::IPPROTO_TCP,
                data,
                IpAddr::V4(ip.src),
            ),
            None => format!("{} bytes", data.len()),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A SYN-ACK TCP header with the given window and options.
    fn syn_ack(window: u16, opts: &[u8]) -> Vec<u8> {
        let mut t = vec![0u8; 20];
        t[12] = (((20 + opts.len()) / 4) as u8) << 4;
        t[13] = packet::TCP_SYN | packet::TCP_ACK;
        t[14..16].copy_from_slice(&window.to_be_bytes());
        t.extend_from_slice(opts);
        t
    }

    const LINUX_OPTS: &[u8] = &[
        2, 4, 0xff, 0xd7, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2, 1, 3, 3, 7,
    ];

    #[test]
    fn reads_options() {
        let t = TcpTraits::from_reply(64, true, &syn_ack(65483, LINUX_OPTS)).unwrap();
        assert_eq!(t.options, "M,S,T,N,W");
        assert_eq!((t.mss, t.wscale, t.window), (Some(65495), Some(7), 65483));
        assert_eq!(
            t.fingerprint(),
            "ttl=64 df=1 win=65483 opts=M,S,T,N,W mss=65495 ws=7"
        );
        // Truncated or bad-length options reject the reply, without panicking.
        assert_eq!(
            TcpTraits::from_reply(64, true, &syn_ack(1, &[2, 4, 5, 0xb4, 3, 9, 0, 0])),
            None
        );
        assert_eq!(
            TcpTraits::from_reply(64, true, &syn_ack(1, &[1, 1, 1, 2])),
            None
        );
    }

    #[test]
    fn classifies_families() {
        let linux = TcpTraits::from_reply(61, true, &syn_ack(65160, LINUX_OPTS)).unwrap();
        let m = classify(linux, 22, false).unwrap();
        assert_eq!((m.family, m.accuracy, m.distance), ("Linux", 90, 4));

        let win_opts = [2, 4, 5, 0xb4, 1, 3, 3, 8, 1, 1, 4, 2];
        let win = TcpTraits::from_reply(127, true, &syn_ack(65535, &win_opts)).unwrap();
        let m = classify(win, 445, false).unwrap();
        assert_eq!((m.family, m.accuracy, m.distance), ("Windows", 90, 2));

        let mac_opts = [
            2, 4, 5, 0xb4, 1, 3, 3, 6, 1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2, 4, 2, 0, 0,
        ];
        let mac = TcpTraits::from_reply(64, true, &syn_ack(65535, &mac_opts)).unwrap();
        assert_eq!(mac.options, "M,N,W,N,N,T,S,E");
        assert_eq!(classify(mac, 22, false).unwrap().family, "macOS");

        let cisco = TcpTraits::from_reply(250, false, &syn_ack(4128, &[2, 4, 2, 0x18])).unwrap();
        let m = classify(cisco, 23, false).unwrap();
        assert_eq!((m.device_type, m.accuracy), ("network device", 90));

        // Linux with sysctls turned off pads with NOPs in its own order.
        let no_sack = [
            2, 4, 5, 0xb4, 1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 7,
        ];
        let t = TcpTraits::from_reply(64, true, &syn_ack(65160, &no_sack)).unwrap();
        assert_eq!(t.options, "M,N,N,T,N,W");
        let m = classify(t, 22, false).unwrap();
        assert_eq!(
            (m.family, m.name.as_str()),
            ("Linux", "Linux (TCP SACK disabled)")
        );
        let sack_only = [2, 4, 5, 0xb4, 1, 1, 4, 2];
        let t = TcpTraits::from_reply(64, true, &syn_ack(64240, &sack_only)).unwrap();
        assert_eq!(classify(t, 22, false).unwrap().family, "Linux");
        // The same layout from TTL 128 is Windows.
        let t = TcpTraits::from_reply(128, true, &syn_ack(64240, &sack_only)).unwrap();
        assert_eq!(classify(t, 445, false).unwrap().family, "Windows");

        // Unknown layout: TTL-only guess, and no DF lowers it further.
        let odd = TcpTraits::from_reply(64, false, &syn_ack(512, &[2, 4, 5, 0xb4])).unwrap();
        let m = classify(odd, 80, true).unwrap();
        assert_eq!((m.family, m.accuracy, m.distance), ("Unix", 50, 0));
    }

    /// Runs only with raw sockets (root on Linux); the CI root job sets
    /// FEROPROBE_REQUIRE_RAW so it cannot silently skip there.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn detects_this_linux_host() {
        if !crate::raw_sockets_available() {
            assert!(
                std::env::var_os("FEROPROBE_REQUIRE_RAW").is_none(),
                "raw sockets required but unavailable"
            );
            return;
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut host = HostResult::new("127.0.0.1".parse().unwrap(), None);
        host.ports.push(crate::model::PortResult {
            port,
            protocol: Protocol::Tcp,
            state: PortState::Open,
            reason: crate::model::reason::SYN_ACK,
            rtt_ms: None,
            service: None,
        });
        let mut hosts = vec![host];
        os_detect(&mut hosts, &ScanConfig::default()).await.unwrap();
        let os = hosts[0].os.as_ref().expect("an OS guess");
        assert_eq!(os.family, "Linux", "{:?}", os.traits);
        assert_eq!(os.distance, 0);
    }

    /// A host deadline that has passed stops OS detection with TimedOut.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn stops_at_the_host_deadline() {
        if !crate::raw_sockets_available() {
            assert!(
                std::env::var_os("FEROPROBE_REQUIRE_RAW").is_none(),
                "raw sockets required but unavailable"
            );
            return;
        }
        let mut host = HostResult::new("127.0.0.1".parse().unwrap(), None);
        host.ports.push(crate::model::PortResult {
            port: 9,
            protocol: Protocol::Tcp,
            state: PortState::Open,
            reason: crate::model::reason::SYN_ACK,
            rtt_ms: None,
            service: None,
        });
        let cfg = ScanConfig {
            deadline: Some(std::time::Instant::now()),
            ..Default::default()
        };
        let err = os_detect(&mut [host], &cfg).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }
}
