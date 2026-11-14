//! The send-and-wait loop of the raw scans that read their answers off a
//! packet capture ([`crate::capture`]): the SCTP scans and the IP protocol
//! scan. Each probe is a (host, key) pair, the key being a port or an IP
//! protocol number. Probes go out paced like every other raw probe, in
//! rounds: a probe without an answer is sent again, up to `cfg.retries`
//! times. Linux only.

#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Instant;

use crate::capture::{self, Packet};
use crate::connect::is_network_error;
use crate::model::{HostResult, PortResult, PortState, Protocol, ScanConfig, reason};
use crate::raw::{Pacer, source_addr_for};
use crate::target::Target;

/// What a received packet says about one probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Answer {
    pub host: usize,
    pub key: u16,
    pub state: PortState,
    pub reason: &'static str,
}

/// Where each target is in the list, to match answers to probes.
pub(crate) type Index = HashMap<IpAddr, usize>;

/// Scan every key on every target. `send` sends one probe, given the
/// host's index, the key, and our source and the target's address.
/// `classify` reads each captured packet, on its own thread, and returns
/// the answers it gives (the IP protocol scan can learn about two probes
/// from one packet). Probes that never got an answer get `no_answer`.
pub(crate) fn run(
    targets: &[Target],
    keys: &[u16],
    cfg: &ScanConfig,
    protocol: Protocol,
    no_answer: PortState,
    mut send: impl FnMut(usize, u16, IpAddr, IpAddr) -> io::Result<()>,
    classify: impl Fn(&Packet<'_>, &Index) -> Vec<Answer> + Send + 'static,
) -> io::Result<Vec<HostResult>> {
    let addrs: Vec<IpAddr> = targets.iter().map(|t| t.addr).collect();
    let index: Arc<Index> = Arc::new(addrs.iter().enumerate().map(|(i, a)| (*a, i)).collect());
    let result = |key: u16, state, why, rtt_ms| PortResult {
        port: key,
        protocol,
        state,
        reason: why,
        rtt_ms,
        service: None,
    };
    let mut results: HashMap<(usize, u16), PortResult> = HashMap::new();

    // Hosts we cannot route to get every probe marked filtered up front.
    let mut sources: Vec<Option<IpAddr>> = Vec::with_capacity(addrs.len());
    for (h, addr) in addrs.iter().enumerate() {
        match source_addr_for(*addr) {
            Ok(src) => sources.push(Some(src)),
            Err(e) if is_network_error(&e) => {
                sources.push(None);
                for &k in keys {
                    results.insert(
                        (h, k),
                        result(k, PortState::Filtered, reason::UNREACHABLE, None),
                    );
                }
            }
            Err(e) => return Err(e),
        }
    }

    let fd = capture::open()?;
    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel::<(Answer, Instant)>();
    let receiver = {
        let (stop, index) = (Arc::clone(&stop), Arc::clone(&index));
        std::thread::spawn(move || {
            capture::receive_loop(fd, &stop, &tx, |pkt, at| {
                let answers = classify(pkt, &index);
                // One packet, several answers: send all but the last here.
                let (last, rest) = answers.split_last()?;
                for a in rest {
                    if tx.send((*a, at)).is_err() {
                        return None;
                    }
                }
                Some((*last, at))
            });
        })
    };

    let mut sent_at: HashMap<(usize, u16), Instant> = HashMap::new();
    let record = |results: &mut HashMap<(usize, u16), PortResult>,
                  sent_at: &HashMap<(usize, u16), Instant>,
                  (a, at): (Answer, Instant)|
     -> bool {
        // Only probes we sent, and only their first answer.
        let Some(sent) = sent_at.get(&(a.host, a.key)) else {
            return false;
        };
        if results.contains_key(&(a.host, a.key)) {
            return false;
        }
        let rtt = (at.saturating_duration_since(*sent).as_secs_f64() * 1e6).round() / 1000.0;
        results.insert((a.host, a.key), result(a.key, a.state, a.reason, Some(rtt)));
        true
    };

    // Key-major order spreads the probes across hosts.
    let mut pending: Vec<(usize, u16)> = keys
        .iter()
        .flat_map(|&k| (0..addrs.len()).map(move |h| (h, k)))
        .filter(|p| !results.contains_key(p))
        .collect();
    crate::progress::tick((addrs.len() * keys.len() - pending.len()) as u64);

    let outcome = (|| -> io::Result<()> {
        for round in 0..=cfg.retries {
            let mut pacer = Pacer::for_config(cfg);
            for &(h, k) in &pending {
                if round == 0 {
                    crate::progress::tick(1);
                }
                if cfg.expired() {
                    return Err(ScanConfig::timed_out());
                }
                let Some(src) = sources[h] else { continue };
                if results.contains_key(&(h, k)) {
                    continue;
                }
                if !pacer.wait_until(cfg.deadline) {
                    return Err(ScanConfig::timed_out());
                }
                while let Ok(a) = rx.try_recv() {
                    record(&mut results, &sent_at, a);
                }
                if results.contains_key(&(h, k)) {
                    continue;
                }
                sent_at.insert((h, k), Instant::now());
                match send(h, k, src, addrs[h]) {
                    Ok(()) => {}
                    Err(_) if cfg.expired() => return Err(ScanConfig::timed_out()),
                    Err(e) if is_network_error(&e) => {
                        results.entry((h, k)).or_insert(result(
                            k,
                            PortState::Filtered,
                            reason::UNREACHABLE,
                            None,
                        ));
                    }
                    Err(e) => return Err(e),
                }
            }
            // Wait for stragglers, but stop once every probe is answered.
            let mut unanswered = pending.iter().filter(|p| !results.contains_key(p)).count();
            let mut deadline = Instant::now() + cfg.timeout;
            if let Some(limit) = cfg.deadline {
                deadline = deadline.min(limit);
            }
            while unanswered > 0
                && let Some(left) = deadline.checked_duration_since(Instant::now())
            {
                match rx.recv_timeout(left) {
                    Ok(a) => {
                        if record(&mut results, &sent_at, a) {
                            unanswered -= 1;
                        }
                    }
                    Err(_) => break,
                }
            }
            pending.retain(|p| !results.contains_key(p));
            if pending.is_empty() {
                break;
            }
            if cfg.expired() {
                return Err(ScanConfig::timed_out());
            }
        }
        Ok(())
    })();

    stop.store(true, Ordering::Relaxed);
    let _ = receiver.join();
    // Answers that came in after the last wait still count.
    while let Ok(a) = rx.try_recv() {
        record(&mut results, &sent_at, a);
    }
    outcome?;

    Ok(targets
        .iter()
        .enumerate()
        .map(|(h, t)| {
            let mut host = HostResult::new(t.addr, t.hostname.clone());
            host.ports = keys
                .iter()
                .map(|&k| {
                    results
                        .remove(&(h, k))
                        .unwrap_or_else(|| result(k, no_answer, reason::NO_RESPONSE, None))
                })
                .collect();
            host.sort_ports();
            host
        })
        .collect())
}

/// The state an ICMP or ICMPv6 destination-unreachable (or time-exceeded)
/// error gives a probe, the way nmap reads them for port scans: always
/// filtered, except where `from_target` and the scan say otherwise (see
/// the callers). Returns `None` for codes nmap ignores.
pub(crate) fn icmp_reason(v6: bool, kind: u8, code: u8) -> Option<&'static str> {
    use crate::packet::{
        ICMP_DEST_UNREACH, ICMP_TIME_EXCEEDED, ICMPV6_DEST_UNREACH, ICMPV6_PARAM_PROBLEM,
        ICMPV6_TIME_EXCEEDED,
    };
    Some(match (v6, kind, code) {
        (false, ICMP_TIME_EXCEEDED, _) | (true, ICMPV6_TIME_EXCEEDED, _) => reason::TIME_EXCEEDED,
        (false, ICMP_DEST_UNREACH, 0) | (true, ICMPV6_DEST_UNREACH, 0) => reason::NET_UNREACH,
        (false, ICMP_DEST_UNREACH, 1) | (true, ICMPV6_DEST_UNREACH, 3) => reason::HOST_UNREACH,
        (false, ICMP_DEST_UNREACH, 2) => reason::PROTO_UNREACH,
        (false, ICMP_DEST_UNREACH, 3) | (true, ICMPV6_DEST_UNREACH, 4) => reason::PORT_UNREACH,
        (false, ICMP_DEST_UNREACH, 9 | 10 | 13) | (true, ICMPV6_DEST_UNREACH, 1 | 2 | 5 | 6) => {
            reason::ADMIN_PROHIBITED
        }
        (true, ICMPV6_PARAM_PROBLEM, 0 | 1) => reason::PARAM_PROBLEM,
        _ => return None,
    })
}
