use std::time::{Duration, Instant};

use super::fingerprint::{Reply, TcpFields, Try, fingerprint};
use super::probes::{self, Keys};
use super::*;
use crate::packet;

/// A SYN-ACK or reset TCP header with the given fields and options.
fn segment(
    sport: u16,
    dport: u16,
    flags: u8,
    seq: u32,
    ack: u32,
    window: u16,
    opts: &[u8],
) -> Vec<u8> {
    let mut t = vec![0u8; 20];
    t[0..2].copy_from_slice(&sport.to_be_bytes());
    t[2..4].copy_from_slice(&dport.to_be_bytes());
    t[4..8].copy_from_slice(&seq.to_be_bytes());
    t[8..12].copy_from_slice(&ack.to_be_bytes());
    t[12] = (((20 + opts.len()) / 4) as u8) << 4;
    t[13] = flags;
    t[14..16].copy_from_slice(&window.to_be_bytes());
    t.extend_from_slice(opts);
    t
}

const SA: u8 = packet::TCP_SYN | packet::TCP_ACK;
const RA: u8 = packet::TCP_RST | packet::TCP_ACK;

fn ts(v: u32) -> Vec<u8> {
    let mut o = vec![8, 10];
    o.extend_from_slice(&v.to_be_bytes());
    o.extend_from_slice(&[0, 0, 0, 0]);
    o
}

/// The answers a Linux 6.x host on Ethernet (MSS 1460) gives to one try.
fn linux_try(v6: bool, closed: bool) -> Try {
    let keys = Keys::new(|| 1000);
    let mut t = Try::new(v6, keys);
    let t0 = Instant::now();
    let df = (!v6).then_some(true);
    let ipid = (!v6).then_some(0);
    let mss = [2, 4, 5, 0xb4];
    let syn_ack = |i: usize, opts: Vec<u8>, window: u16, at: Instant| Reply {
        ttl: 61,
        df,
        ipid,
        tcp: Some(TcpFields {
            flags: if i == probes::E {
                SA | packet::TCP_ECE
            } else {
                SA
            },
            window,
            seq: 777,
            ack: keys.seq_of(i).wrapping_add(1),
            options: fingerprint::Options::parse(&segment(0, 0, SA, 0, 0, 0, &opts)).unwrap(),
        }),
        at,
    };
    let opts = |parts: &[&[u8]]| parts.concat();
    let ws = [1, 3, 3, 7];
    let s = [4, 2];
    let nn = [1, 1];
    let at = |n: u64| t0 + Duration::from_millis(100 * n);
    t.replies[0] = Some(syn_ack(0, opts(&[&mss, &s, &ts(5000), &ws]), 65160, at(0)));
    t.replies[1] = Some(syn_ack(1, opts(&[&mss]), 64240, at(1)));
    t.replies[2] = Some(syn_ack(2, opts(&[&mss, &nn, &s]), 64240, at(2)));
    t.replies[3] = Some(syn_ack(3, opts(&[&mss, &nn, &ts(5300), &ws]), 65160, at(3)));
    t.replies[4] = Some(syn_ack(4, opts(&[&mss, &nn, &s, &ws]), 64240, at(4)));
    let rst = |flags: u8, seq: u32, ack: u32| Reply {
        ttl: 61,
        df,
        ipid,
        tcp: Some(TcpFields {
            flags,
            window: 0,
            seq,
            ack,
            options: fingerprint::Options::default_layout(),
        }),
        at: at(4),
    };
    t.replies[probes::A] = Some(rst(packet::TCP_RST, keys.ack, 0));
    if closed {
        t.replies[probes::C1] = Some(rst(RA, 0, keys.seq_of(probes::C1).wrapping_add(1)));
        t.replies[probes::C2] = Some(rst(packet::TCP_RST, keys.ack, 0));
    }
    for i in probes::plan(closed, false) {
        t.sent[i] = true;
    }
    t
}

impl fingerprint::Options {
    fn default_layout() -> Self {
        Self {
            layout: "-".into(),
            ..Self::default()
        }
    }
}

fn job(closed: Option<u16>) -> Job {
    Job {
        host: 0,
        addr: "192.0.2.10".parse().unwrap(),
        open: 22,
        closed,
        known_distance: None,
    }
}

#[test]
fn linux_fingerprint_names_the_kernel_series() {
    let t = linux_try(false, true);
    let fp = fingerprint(&t);
    assert_eq!(fp.get("ttl"), Some("64"));
    assert_eq!(fp.get("s1.o"), Some("M,S,T,N,W"));
    assert_eq!(fp.get("s4.o"), Some("M,N,N,T,N,W"));
    assert_eq!(fp.get("e.f"), Some("SAE"));
    assert_eq!(fp.get("ws"), Some("7"));
    assert_eq!(fp.get("ipid"), Some("Z"));
    assert_eq!(fp.get("ts"), Some("1000"));
    assert_eq!(fp.get("c1.ack"), Some("S+"));
    assert_eq!(fp.get("a.seq"), Some("A"));
    let r = result_for(&job(Some(1)), &[t], &ScanConfig::default());
    assert_eq!(r.perfect, 1, "{r:?}");
    assert_eq!(r.matches[0].name, "Linux 4.19 - 6.x");
    assert_eq!(r.matches[0].accuracy, 100);
    assert_eq!(r.distance, Some(4));
    assert_eq!(r.ipid_class.as_deref(), Some("Z"));
    assert_eq!(r.not_ideal, None);
}

#[test]
fn older_linux_and_near_misses() {
    // A 4.x kernel: 20 x MSS windows.
    let mut t = linux_try(false, true);
    for i in [0, 1, 2, 4] {
        let tcp = t.replies[i].as_mut().unwrap().tcp.as_mut().unwrap();
        tcp.window = 20 * if i == 0 { 1448 } else { 1460 };
    }
    let r = result_for(&job(Some(1)), &[t.clone()], &ScanConfig::default());
    assert_eq!(r.matches[0].name, "Linux 3.x - 4.18", "{r:?}");
    assert_eq!(r.perfect, 1);

    // An unusual window: no perfect match, but near ones for --osscan-guess.
    for i in [0, 1, 2, 4] {
        t.replies[i].as_mut().unwrap().tcp.as_mut().unwrap().window = 1234;
    }
    let r = result_for(&job(Some(1)), &[t], &ScanConfig::default());
    assert_eq!(r.perfect, 0);
    assert!(!r.matches.is_empty());
    assert!(
        r.matches
            .iter()
            .all(|m| m.accuracy >= db::GUESS_THRESHOLD && m.accuracy < 100)
    );
    assert!(r.matches[0].family == "Linux", "{r:?}");
}

#[test]
fn ipv6_has_no_df_or_ipid_tests() {
    let t = linux_try(true, false);
    let fp = fingerprint(&t);
    assert_eq!(fp.get("s1.df"), None);
    assert_eq!(fp.get("ipid"), None);
    assert_eq!(fp.get("c1"), None, "no closed port, no c1 test");
    let r = result_for(&job(None), &[t], &ScanConfig::default());
    assert_eq!(r.matches[0].name, "Linux 4.19 - 6.x");
    assert_eq!(r.perfect, 1);
    assert!(r.not_ideal.as_deref().unwrap().contains("closed TCP port"));
}

#[test]
fn windows_and_unanswered() {
    let keys = Keys::new(|| 9);
    let mut t = Try::new(false, keys);
    let mss = [2u8, 4, 5, 0xb4];
    let t0 = Instant::now();
    let mut id = 4000u16;
    let mut reply = |i: usize, opts: &[u8], flags: u8, window: u16, df: bool| {
        id += 1;
        Some(Reply {
            ttl: 125,
            df: Some(df),
            ipid: Some(id),
            tcp: Some(TcpFields {
                flags,
                window,
                seq: if probes::is_ack(i) { keys.ack } else { 5 },
                ack: keys.seq_of(i).wrapping_add(1),
                options: fingerprint::Options::parse(&segment(0, 0, flags, 0, 0, 0, opts)).unwrap(),
            }),
            at: t0 + Duration::from_millis(100 * i as u64),
        })
    };
    let full = [&mss[..], &[1, 3, 3, 8, 1, 1, 4, 2]].concat();
    t.replies[0] = reply(0, &full, SA, 64240, true);
    t.replies[1] = reply(1, &mss, SA, 64240, true);
    t.replies[2] = reply(2, &[&mss[..], &[1, 1, 4, 2]].concat(), SA, 64240, true);
    t.replies[3] = reply(3, &[&mss[..], &[1, 3, 3, 8]].concat(), SA, 64240, true);
    t.replies[4] = reply(4, &full, SA, 64240, true);
    t.replies[5] = reply(5, &[], packet::TCP_RST, 0, true);
    t.replies[6] = reply(6, &[], RA, 0, false);
    t.replies[7] = reply(7, &[], packet::TCP_RST, 0, false);
    t.sent[..=probes::C2].fill(true);
    let fp = fingerprint(&t);
    assert_eq!(fp.get("ts"), Some("U"));
    assert_eq!(fp.get("ipid"), Some("I"));
    assert_eq!(fp.get("ipid.shared"), Some("Y"));
    let r = result_for(&job(Some(1)), &[t], &ScanConfig::default());
    assert_eq!(r.perfect, 1, "{r:?}");
    assert_eq!(r.matches[0].family, "Windows");
    assert!(r.matches[0].name.contains("Windows 10"));

    // Nothing answered: a result without matches.
    let mut quiet = Try::new(false, keys);
    quiet.sent[0] = true;
    let r = result_for(&job(None), &[quiet], &ScanConfig::default());
    assert!(r.matches.is_empty());
    assert_eq!(r.fingerprint, "s1=N");
}

#[test]
fn osscan_limit_and_tries() {
    let mut host = HostResult::new("192.0.2.1".parse().unwrap(), None);
    let port = |port, state| crate::model::PortResult {
        port,
        protocol: Protocol::Tcp,
        state,
        reason: crate::model::reason::SYN_ACK,
        rtt_ms: None,
        service: None,
    };
    let opts = OsOptions::default();
    let limit = OsOptions {
        limit: true,
        ..opts
    };
    // No open port: never probed.
    host.ports.push(port(81, PortState::Closed));
    assert_eq!(job_for(0, &host, &opts), None);
    host.ports.push(port(22, PortState::Open));
    let j = job_for(0, &host, &limit).unwrap();
    assert_eq!((j.open, j.closed), (22, Some(81)));
    assert_eq!(tries_for(&j, &opts, &ScanConfig::default()), DEFAULT_TRIES);
    // Open only: probed without --osscan-limit, with two tries at most.
    host.ports.remove(0);
    assert!(job_for(0, &host, &limit).is_none());
    let j = job_for(0, &host, &opts).unwrap();
    assert_eq!(tries_for(&j, &opts, &ScanConfig::default()), UNIDEAL_TRIES);
    let one = OsOptions {
        max_tries: 1,
        ..opts
    };
    assert_eq!(tries_for(&j, &one, &ScanConfig::default()), 1);
    // An unfiltered port is enough for --osscan-limit, as in nmap.
    host.ports.push(port(443, PortState::Unfiltered));
    assert!(job_for(0, &host, &limit).is_some());
}

#[cfg(target_os = "linux")]
#[test]
fn matches_captured_answers() {
    use std::collections::HashMap;
    let keys = Keys::new(|| 4242);
    let target: IpAddr = "2001:db8::2".parse().unwrap();
    let mut slots: imp::Slots = HashMap::new();
    slots.insert(target, (0, 22, Some(23)));
    let now = Instant::now();
    fn packet_from(src: IpAddr, payload: &[u8], protocol: u8) -> crate::capture::Packet<'_> {
        crate::capture::Packet {
            src,
            dst: "2001:db8::1".parse().unwrap(),
            protocol,
            ttl: 64,
            ipid: None,
            df: false,
            payload,
        }
    }
    // The SYN-ACK to s2.
    let seg = segment(
        22,
        keys.sport_of(1),
        SA,
        1,
        keys.seq_of(1).wrapping_add(1),
        1000,
        &[2, 4, 5, 0xa0],
    );
    let (slot, i, r) = imp::match_reply(
        &packet_from(target, &seg, packet::IPPROTO_TCP),
        now,
        &slots,
        &keys,
    )
    .unwrap();
    assert_eq!((slot, probes::NAMES[i]), (0, "s2"));
    assert_eq!(r.df, None);
    // A wrong acknowledgment, or from the wrong port: not ours.
    let bad = segment(22, keys.sport_of(1), SA, 1, 5, 1000, &[]);
    assert!(
        imp::match_reply(
            &packet_from(target, &bad, packet::IPPROTO_TCP),
            now,
            &slots,
            &keys
        )
        .is_none()
    );
    let bad = segment(
        23,
        keys.sport_of(1),
        SA,
        1,
        keys.seq_of(1).wrapping_add(1),
        1000,
        &[],
    );
    assert!(
        imp::match_reply(
            &packet_from(target, &bad, packet::IPPROTO_TCP),
            now,
            &slots,
            &keys
        )
        .is_none()
    );
    // A reset from the closed port to c2.
    let rst = segment(
        23,
        keys.sport_of(probes::C2),
        packet::TCP_RST,
        keys.ack,
        0,
        0,
        &[],
    );
    let (_, i, _) = imp::match_reply(
        &packet_from(target, &rst, packet::IPPROTO_TCP),
        now,
        &slots,
        &keys,
    )
    .unwrap();
    assert_eq!(probes::NAMES[i], "c2");
    // The echo reply, and our own echo request (seen on loopback): only
    // the reply counts.
    let mut echo = packet::icmpv6_echo(keys.icmp_id, 0, packet::ECHO_MARKER);
    assert!(
        imp::match_reply(
            &packet_from(target, &echo, packet::IPPROTO_ICMPV6),
            now,
            &slots,
            &keys
        )
        .is_none()
    );
    echo[0] = packet::ICMPV6_ECHO_REPLY;
    let (_, i, _) = imp::match_reply(
        &packet_from(target, &echo, packet::IPPROTO_ICMPV6),
        now,
        &slots,
        &keys,
    )
    .unwrap();
    assert_eq!(i, probes::IE);
}

/// Live, against this machine: runs only with raw sockets (root on
/// Linux); the CI root job sets FEROPROBE_REQUIRE_RAW so it cannot
/// silently skip there.
#[cfg(target_os = "linux")]
async fn detect_local(addr: &str) -> Option<OsResult> {
    if !crate::raw_sockets_available() {
        assert!(
            std::env::var_os("FEROPROBE_REQUIRE_RAW").is_none(),
            "raw sockets required but unavailable"
        );
        return None;
    }
    let listener = std::net::TcpListener::bind(format!("{addr}:0")).ok()?;
    let open = listener.local_addr().unwrap().port();
    // A port nothing listens on.
    let closed = {
        let l = std::net::TcpListener::bind(format!("{addr}:0")).unwrap();
        l.local_addr().unwrap().port()
    };
    let ip: IpAddr = addr.trim_matches(|c| c == '[' || c == ']').parse().unwrap();
    let mut host = HostResult::new(ip, None);
    for (port, state) in [(open, PortState::Open), (closed, PortState::Closed)] {
        host.ports.push(crate::model::PortResult {
            port,
            protocol: Protocol::Tcp,
            state,
            reason: crate::model::reason::SYN_ACK,
            rtt_ms: None,
            service: None,
        });
    }
    let mut hosts = vec![host];
    let opts = OsOptions {
        icmp_echo: true,
        ..OsOptions::default()
    };
    os_detect(&mut hosts, &ScanConfig::default(), &opts)
        .await
        .unwrap();
    let os = hosts.pop().unwrap().os;
    assert!(os.is_some(), "no OS result for {addr}");
    os
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn detects_this_linux_host() {
    let Some(os) = detect_local("127.0.0.1").await else {
        return;
    };
    assert_eq!(os.perfect, 1, "{os:?}");
    assert_eq!(os.matches[0].family, "Linux", "{os:?}");
    assert_eq!(os.distance, Some(0));
    assert_eq!(os.tries, 1);
    assert!(os.fingerprint.contains("c1=Y"), "{}", os.fingerprint);
    assert!(os.fingerprint.contains("ie=Y"), "{}", os.fingerprint);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn detects_this_linux_host_over_ipv6() {
    // IPv6 may be absent (many containers have no IPv6 stack at all).
    if !crate::raw_ipv6_available() {
        return;
    }
    let Some(os) = detect_local("[::1]").await else {
        return;
    };
    assert_eq!(os.matches[0].family, "Linux", "{os:?}");
    assert_eq!(os.perfect, 1, "{os:?}");
    assert_eq!(os.distance, Some(0));
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
        deadline: Some(Instant::now()),
        ..Default::default()
    };
    let err = os_detect(&mut [host], &cfg, &OsOptions::default())
        .await
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
}

#[test]
fn a_far_host_found_by_a_try_gets_two_tries() {
    let cfg = ScanConfig::default();
    let j = job(Some(81));
    let near = linux_try(false, true);
    let fp = fingerprint(&near);
    // TTL 61 from 64: four hops, the limit stands.
    assert_eq!(
        tries_after(&j, DEFAULT_TRIES, &near, &fp, &cfg),
        DEFAULT_TRIES
    );
    let mut far = linux_try(false, true);
    for r in far.replies.iter_mut().flatten() {
        r.ttl = 50;
    }
    let fp = fingerprint(&far);
    // Fifteen hops: cut to two, as nmap does for a distant host.
    assert_eq!(
        tries_after(&j, DEFAULT_TRIES, &far, &fp, &cfg),
        UNIDEAL_TRIES
    );
    assert_eq!(tries_after(&j, 1, &far, &fp, &cfg), 1);
}

/// A real device: a TP-Link home router (Linux 3.x kernel; nmap 7.95 says
/// Linux 2.6.32 - 3.10), fingerprinted over the LAN with `-O -vv`.
#[test]
fn matches_a_tp_link_router() {
    let line = "ttl=64 s1=Y s1.f=SA s1.w=14480 s1.m=1460 s1.o=M,S,T,N,W s1.df=Y s2=Y \
        s2.f=SA s2.w=14600 s2.m=1460 s2.o=M s2.df=Y s3=Y s3.f=SA s3.w=14600 \
        s3.m=1460 s3.o=M,N,N,S s3.df=Y s4=Y s4.f=SA s4.m=1460 s4.o=M,N,N,T,N,W \
        s4.df=Y e=Y e.f=SA e.w=14600 e.m=1460 e.o=M,N,N,S,N,W e.df=Y a=Y a.f=R \
        a.w=0 a.df=Y a.seq=A c1=Y c1.f=AR c1.w=0 c1.df=Y c1.ack=S+ c2=Y c2.f=R \
        c2.w=0 c2.df=Y c2.seq=A ie=Y ie.df=N ws=6 ipid=Z ipid.rst=Z ts=100";
    let fp = Fingerprint {
        tests: line
            .split_whitespace()
            .map(|t| {
                let (k, v) = t.split_once('=').unwrap();
                (k.to_string(), v.to_string())
            })
            .collect(),
    };
    let (m, perfect) = classify(db::built_in(), &fp);
    assert_eq!(perfect, 1, "{m:?}");
    assert_eq!(m[0].name, "Linux 3.x - 4.18");
}

/// A real device: a Windows 11 PC with TCP timestamps on (nmap guesses
/// Windows 11 at 99%), fingerprinted over the LAN with `-O -vv`.
#[test]
fn matches_a_windows_11_pc() {
    let line = "ttl=128 s1=Y s1.f=SA s1.w=65535 s1.m=1460 s1.o=M,N,W,S,T s1.df=Y s2=Y \
        s2.f=SA s2.w=65535 s2.m=1460 s2.o=M s2.df=Y s3=Y s3.f=SA s3.w=65535 \
        s3.m=1460 s3.o=M,N,N,S s3.df=Y s4=Y s4.f=SA s4.m=1460 s4.o=M,N,W,N,N,T \
        s4.df=Y e=Y e.f=SA e.w=65535 e.m=1460 e.o=M,N,W,N,N,S e.df=Y a=N ie=Y \
        ie.df=N ws=8 ipid=I ts=1000";
    let fp = Fingerprint {
        tests: line
            .split_whitespace()
            .map(|t| {
                let (k, v) = t.split_once('=').unwrap();
                (k.to_string(), v.to_string())
            })
            .collect(),
    };
    let (m, perfect) = classify(db::built_in(), &fp);
    assert_eq!(perfect, 1, "{m:?}");
    assert_eq!(m[0].name, "Microsoft Windows 10 - 11 or Server 2016 - 2025");
}
