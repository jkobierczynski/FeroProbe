//! Sending the OS-detection probes and reading the answers (Linux).

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol as SockProto, Socket};

use super::fingerprint::{Reply, Try};
use super::probes::{self, Keys, PROBES, Target};
use super::{Job, OsOptions, ScanConfig, classify, db, tries_for};
use crate::capture;
use crate::packet;
use crate::raw::{Pacer, Rng, raw_socket, raw_socket_in, send_logged_until};

/// Where answers are matched: target address to (slot, open port, closed port).
pub(super) type Slots = HashMap<IpAddr, (usize, u16, Option<u16>)>;

/// Match one captured packet to a probe of the current try: returns the
/// slot, the probe index and the answer. Only answers from a target, to
/// the ports or ICMP identifier of this try's probes, count.
pub(super) fn match_reply(
    pkt: &capture::Packet<'_>,
    at: Instant,
    slots: &Slots,
    keys: &Keys,
) -> Option<(usize, usize, Reply)> {
    let &(slot, open, closed) = slots.get(&pkt.src)?;
    let v6 = pkt.src.is_ipv6();
    let df = (!v6).then_some(pkt.df);
    match pkt.protocol {
        packet::IPPROTO_TCP => {
            let tcp = packet::parse_tcp(pkt.payload)?;
            let rst = tcp.flags & packet::TCP_RST != 0;
            let i = keys.probe_for(tcp.dport, tcp.sport, tcp.ack, rst, open, closed)?;
            let from = match probes::target_of(i) {
                Target::Closed => closed?,
                _ => open,
            };
            if tcp.sport != from {
                return None;
            }
            let syn_ack = tcp.flags & (packet::TCP_SYN | packet::TCP_ACK)
                == packet::TCP_SYN | packet::TCP_ACK;
            let fits = if probes::is_ack(i) {
                rst
            } else {
                rst || (syn_ack && tcp.ack == keys.seq_of(i).wrapping_add(1))
            };
            if !fits {
                return None;
            }
            Some((slot, i, Reply::tcp(pkt.ttl, df, pkt.ipid, pkt.payload, at)?))
        }
        packet::IPPROTO_ICMP | packet::IPPROTO_ICMPV6 => {
            let icmp = packet::parse_icmp(pkt.payload)?;
            let reply = if v6 {
                packet::ICMPV6_ECHO_REPLY
            } else {
                packet::ICMP_ECHO_REPLY
            };
            if (pkt.protocol == packet::IPPROTO_ICMPV6) != v6
                || icmp.kind != reply
                || icmp.id != keys.icmp_id
            {
                return None;
            }
            Some((
                slot,
                probes::IE,
                Reply {
                    ttl: pkt.ttl,
                    df,
                    ipid: pkt.ipid,
                    tcp: None,
                    at,
                },
            ))
        }
        _ => None,
    }
}

/// The raw sockets the probes go out on.
struct Sockets {
    tcp4: Option<Socket>,
    tcp6: Option<Socket>,
    icmp4: Option<Socket>,
    icmp6: Option<Socket>,
}

impl Sockets {
    fn tcp(&self, v6: bool) -> Option<&Socket> {
        if v6 {
            self.tcp6.as_ref()
        } else {
            self.tcp4.as_ref()
        }
    }

    fn icmp(&self, v6: bool) -> Option<&Socket> {
        if v6 {
            self.icmp6.as_ref()
        } else {
            self.icmp4.as_ref()
        }
    }
}

/// A socket, or `None` when the system has no such address family (no
/// IPv6 stack); any other error, such as missing privileges, stays one.
fn unless_unsupported(r: io::Result<Socket>) -> io::Result<Option<Socket>> {
    match r {
        Ok(s) => Ok(Some(s)),
        Err(e)
            if e.raw_os_error() == Some(libc::EAFNOSUPPORT)
                || e.kind() == io::ErrorKind::Unsupported =>
        {
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

/// One host in one try.
struct Slot {
    job: usize,
    src: IpAddr,
    dst: IpAddr,
    open: u16,
    closed: Option<u16>,
    icmp: bool,
    t: Try,
}

/// Probe every job, try after try, until each has a perfect match or has
/// used its tries. Returns each job's tries, in job order; a job whose
/// family cannot be probed (no IPv6 raw socket, no route) gets none.
pub(super) fn probe_blocking(
    jobs: &[Job],
    cfg: &ScanConfig,
    opts: &OsOptions,
) -> io::Result<Vec<Vec<Try>>> {
    let any = |v6: bool| jobs.iter().any(|j| j.addr.is_ipv6() == v6);
    // Raw sockets are needed, and failing to open one is an error, as for
    // the other raw scans. Only a missing IPv6 stack is let through: its
    // hosts then get no result rather than sinking the IPv4 ones.
    let socks = Sockets {
        tcp4: any(false).then(|| raw_socket(SockProto::TCP)).transpose()?,
        tcp6: any(true)
            .then(|| unless_unsupported(raw_socket_in(Domain::IPV6, SockProto::TCP)))
            .transpose()?
            .flatten(),
        icmp4: (opts.icmp_echo && any(false))
            .then(|| raw_socket(SockProto::ICMPV4))
            .transpose()?,
        icmp6: (opts.icmp_echo && any(true))
            .then(|| unless_unsupported(raw_socket_in(Domain::IPV6, SockProto::ICMPV6)))
            .transpose()?
            .flatten(),
    };
    let sources: Vec<Option<IpAddr>> = jobs
        .iter()
        .map(|j| {
            let src = crate::netif::route_source(j.addr).ok()?;
            (src.is_ipv6() == j.addr.is_ipv6() && socks.tcp(j.addr.is_ipv6()).is_some())
                .then_some(src)
        })
        .collect();
    let mut limits: Vec<u32> = jobs.iter().map(|j| tries_for(j, opts, cfg)).collect();
    let mut tries: Vec<Vec<Try>> = vec![Vec::new(); jobs.len()];
    let mut done = vec![false; jobs.len()];
    let mut rng = Rng::new();
    let mut pacer = Pacer::for_config(cfg);
    let db = db::built_in();
    loop {
        let mut slots: Vec<Slot> = Vec::new();
        let keys = Keys::new(|| rng.next_u32()).with_source_port(cfg.source_port);
        for (j, job) in jobs.iter().enumerate() {
            let Some(src) = sources[j] else { continue };
            if done[j] || tries[j].len() as u32 >= limits[j] {
                continue;
            }
            let v6 = job.addr.is_ipv6();
            slots.push(Slot {
                job: j,
                src,
                dst: job.addr,
                open: job.open,
                closed: job.closed,
                icmp: socks.icmp(v6).is_some(),
                t: Try::new(v6, keys),
            });
        }
        if slots.is_empty() {
            break;
        }
        if cfg.expired() {
            return Err(ScanConfig::timed_out());
        }
        run_try(&mut slots, &keys, &socks, &mut pacer, cfg)?;
        for s in slots {
            let fp = super::fingerprint::fingerprint(&s.t);
            if classify(db, &fp).1 > 0 {
                done[s.job] = true;
            }
            limits[s.job] = super::tries_after(&jobs[s.job], limits[s.job], &s.t, &fp, cfg);
            tries[s.job].push(s.t);
        }
    }
    Ok(tries)
}

/// Send one try to every slot and collect the answers into the slots.
fn run_try(
    slots: &mut [Slot],
    keys: &Keys,
    socks: &Sockets,
    pacer: &mut Pacer,
    cfg: &ScanConfig,
) -> io::Result<()> {
    let fd = capture::open()?;
    let map: Slots = slots
        .iter()
        .enumerate()
        .map(|(n, s)| (s.dst, (n, s.open, s.closed)))
        .collect();
    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::sync_channel::<(usize, usize, Reply)>(8192);
    let receiver = {
        let stop = Arc::clone(&stop);
        let keys = *keys;
        std::thread::spawn(move || {
            capture::receive_loop(fd, &stop, &tx, |pkt, at| match_reply(pkt, at, &map, &keys));
        })
    };
    let take = |slots: &mut [Slot], (n, i, r): (usize, usize, Reply)| {
        if let Some(s) = slots.get_mut(n)
            && s.t.sent[i]
            && s.t.replies[i].is_none()
        {
            s.t.replies[i] = Some(r);
        }
    };
    // Move what has arrived out of the channel, so a large host group
    // cannot fill it while probes are still going out.
    let drain = |slots: &mut [Slot]| {
        while let Ok(a) = rx.try_recv() {
            take(slots, a);
        }
    };
    // Read answers until `until` (or the host deadline), or until every
    // probe sent so far is answered when `early` is set.
    let wait = |slots: &mut [Slot], until: Instant, early: bool| {
        let until = cfg.deadline.map_or(until, |d| until.min(d));
        loop {
            while let Ok(a) = rx.try_recv() {
                take(slots, a);
            }
            if early
                && slots
                    .iter()
                    .all(|s| (0..PROBES).all(|i| !s.t.sent[i] || s.t.replies[i].is_some()))
            {
                return;
            }
            let Some(left) = until.checked_duration_since(Instant::now()) else {
                return;
            };
            match rx.recv_timeout(left.min(Duration::from_millis(20))) {
                Ok(a) => take(slots, a),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => return,
            }
        }
    };

    let outcome = (|| -> io::Result<()> {
        // The sequence SYNs, one round per probe, 100 ms apart.
        for i in 0..probes::SEQ_PROBES {
            let start = Instant::now();
            for n in 0..slots.len() {
                send(&mut slots[n], i, keys, socks, pacer, cfg)?;
                drain(slots);
            }
            wait(slots, start + probes::SEQ_GAP, false);
        }
        for i in probes::E..PROBES {
            for n in 0..slots.len() {
                send(&mut slots[n], i, keys, socks, pacer, cfg)?;
                drain(slots);
            }
        }
        // Up to the longest adaptive timeout among the hosts of this try.
        let longest = slots
            .iter()
            .map(|s| cfg.probe_timeout(s.dst))
            .max()
            .unwrap_or(cfg.rtt.initial);
        wait(slots, Instant::now() + longest, true);
        if cfg.expired() {
            return Err(ScanConfig::timed_out());
        }
        Ok(())
    })();
    stop.store(true, Ordering::Relaxed);
    let _ = receiver.join();
    drain(slots);
    outcome
}

/// Send probe `i` to one slot, if its plan includes it.
fn send(
    s: &mut Slot,
    i: usize,
    keys: &Keys,
    socks: &Sockets,
    pacer: &mut Pacer,
    cfg: &ScanConfig,
) -> io::Result<()> {
    let v6 = s.t.v6;
    let (sock, pkt) = match probes::target_of(i) {
        Target::Open => (
            socks.tcp(v6),
            probes::tcp_segment(i, s.src, s.dst, s.open, keys),
        ),
        Target::Closed => {
            let Some(port) = s.closed else { return Ok(()) };
            (
                socks.tcp(v6),
                probes::tcp_segment(i, s.src, s.dst, port, keys),
            )
        }
        Target::Icmp => {
            if !s.icmp {
                return Ok(());
            }
            (socks.icmp(v6), probes::echo(v6, keys))
        }
    };
    let Some(sock) = sock else { return Ok(()) };
    if !pacer.wait_until(cfg.deadline) {
        return Err(ScanConfig::timed_out());
    }
    // nmap's OS probes carry no --ip-options.
    crate::raw::nmap_ip_header_bare(sock, v6);
    // `socket_addr` keeps a link-local target's interface scope.
    let to = crate::target::socket_addr(s.dst, 0);
    let proto = match (probes::target_of(i), v6) {
        (Target::Icmp, true) => packet::IPPROTO_ICMPV6,
        (Target::Icmp, false) => packet::IPPROTO_ICMP,
        _ => packet::IPPROTO_TCP,
    };
    send_logged_until(sock, &pkt, to, cfg.deadline, || {
        crate::packet_trace::log("SENT", || probes::describe(proto, &pkt, Some(s.src), s.dst));
    })?;
    s.t.sent[i] = true;
    Ok(())
}
