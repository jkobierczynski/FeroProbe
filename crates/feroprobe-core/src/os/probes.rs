//! The OS-detection probe set and the packets it sends.
//!
//! One *try* sends at most [`PROBES`] probes to a host, all to ports and
//! protocols the scan already probed:
//!
//! | Probe | Sent to | Packet |
//! | --- | --- | --- |
//! | `s1`..`s4` | the open TCP port | SYNs with four different option sets, 100 ms apart |
//! | `e` | the open TCP port | a SYN with ECE and CWR (an ECN setup request) |
//! | `a` | the open TCP port | an ACK outside any connection |
//! | `c1` | a closed TCP port, if the scan found one | a SYN |
//! | `c2` | a closed TCP port, if the scan found one | an ACK |
//! | `ie` | the host, only if the command sends ICMP echo requests | an ICMP (or ICMPv6) echo request with the `feroprobe` payload |
//!
//! The SYNs look like an ordinary client's (window 64240, common option
//! layouts), as the OS-detection probes always have: the target's answer to
//! a realistic SYN is what tells stacks apart. They carry no window marker
//! (see `docs/responsible-use.md`); the echo request carries the usual
//! `feroprobe` payload.

use std::net::IpAddr;
use std::time::Duration;

use crate::packet;

/// The number of probes in one try.
pub const PROBES: usize = 9;

/// The probes' names, which the fingerprint's test names start with.
pub const NAMES: [&str; PROBES] = ["s1", "s2", "s3", "s4", "e", "a", "c1", "c2", "ie"];

/// The SYNs to the open port whose answers give the IP ID and timestamp
/// sequences.
pub const SEQ_PROBES: usize = 4;

/// Time between the sequence SYNs, so the timestamp clock can be read.
pub const SEQ_GAP: Duration = Duration::from_millis(100);

/// Index of each probe in [`NAMES`].
pub const S1: usize = 0;
pub const S4: usize = 3;
pub const E: usize = 4;
pub const A: usize = 5;
pub const C1: usize = 6;
pub const C2: usize = 7;
pub const IE: usize = 8;

/// Window of every OS-detection segment: a common client value.
pub const WINDOW: u16 = 64240;

/// Where a probe goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Open,
    Closed,
    Icmp,
}

/// Which port (or ICMP) probe `i` goes to.
pub fn target_of(i: usize) -> Target {
    match i {
        C1 | C2 => Target::Closed,
        IE => Target::Icmp,
        _ => Target::Open,
    }
}

/// Whether probe `i` is an ACK, answered by a reset whose sequence number
/// is our acknowledgment number.
pub fn is_ack(i: usize) -> bool {
    i == A || i == C2
}

const MSS: [u8; 4] = [2, 4, 0x05, 0xb4]; // MSS 1460
const SACK: [u8; 2] = [4, 2];
const NOP: u8 = 1;
const WSCALE: [u8; 3] = [3, 3, 7];

/// The TCP options of probe `i`, with `tsval` in any timestamp option.
pub fn options(i: usize, tsval: u32) -> Vec<u8> {
    let ts = |o: &mut Vec<u8>| {
        o.extend_from_slice(&[8, 10]);
        o.extend_from_slice(&tsval.to_be_bytes());
        o.extend_from_slice(&[0, 0, 0, 0]);
    };
    let mut o = Vec::with_capacity(20);
    match i {
        // Everything, in Linux's client order: MSS, SACK, timestamps, window scale.
        0 | C1 => {
            o.extend_from_slice(&MSS);
            o.extend_from_slice(&SACK);
            ts(&mut o);
            o.push(NOP);
            o.extend_from_slice(&WSCALE);
        }
        // No options at all.
        1 => {}
        // MSS and SACK only, like an old Windows client.
        2 => {
            o.extend_from_slice(&MSS);
            o.extend_from_slice(&[NOP, NOP]);
            o.extend_from_slice(&SACK);
        }
        // MSS, window scale and timestamps, without SACK.
        3 => {
            o.extend_from_slice(&MSS);
            o.push(NOP);
            o.extend_from_slice(&WSCALE);
            o.extend_from_slice(&[NOP, NOP]);
            ts(&mut o);
        }
        // ECN request: MSS, SACK and window scale.
        E => {
            o.extend_from_slice(&MSS);
            o.extend_from_slice(&[NOP, NOP]);
            o.extend_from_slice(&SACK);
            o.push(NOP);
            o.extend_from_slice(&WSCALE);
        }
        _ => {}
    }
    o
}

/// The TCP flags of probe `i`.
pub fn flags(i: usize) -> u8 {
    match i {
        E => packet::TCP_SYN | packet::TCP_ECE | packet::TCP_CWR,
        A | C2 => packet::TCP_ACK,
        _ => packet::TCP_SYN,
    }
}

/// Per-try values that tie answers to probes: probe `i` leaves from
/// `sport + i` (from `sport` itself with `-g`, see [`Keys::fixed`]) with
/// sequence number `seq + i`; the ACK probes acknowledge `ack`; the echo
/// request has identifier `icmp_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Keys {
    pub sport: u16,
    /// Every probe leaves from `sport` (`-g`): answers are then told apart
    /// by the port they come from and the sequence number they acknowledge.
    pub fixed: bool,
    pub seq: u32,
    pub ack: u32,
    pub tsval: u32,
    pub icmp_id: u16,
}

impl Keys {
    /// Fresh values from `next` (a random source).
    pub fn new(mut next: impl FnMut() -> u32) -> Self {
        Self {
            // Room for PROBES consecutive ports below 65536.
            sport: 40000 + (next() % 20000) as u16,
            fixed: false,
            seq: next(),
            ack: next(),
            tsval: next(),
            icmp_id: (next() as u16) | 1,
        }
    }

    /// The same keys with every probe leaving from `port` (`-g`), if given.
    pub fn with_source_port(self, port: Option<u16>) -> Self {
        match port {
            Some(sport) => Self {
                sport,
                fixed: true,
                ..self
            },
            None => self,
        }
    }

    /// The source port of probe `i`.
    pub fn sport_of(&self, i: usize) -> u16 {
        if self.fixed {
            self.sport
        } else {
            self.sport + i as u16
        }
    }

    /// The sequence number of probe `i`.
    pub fn seq_of(&self, i: usize) -> u32 {
        self.seq.wrapping_add(i as u32)
    }

    /// Which TCP probe a segment to our port `dport` answers, if any. With
    /// a fixed source port see [`Keys::probe_for`].
    pub fn probe_for_port(&self, dport: u16) -> Option<usize> {
        if self.fixed {
            return None;
        }
        let i = usize::from(dport.checked_sub(self.sport)?);
        (i < IE).then_some(i)
    }

    /// Which TCP probe a segment answers: one to our port `dport`, from the
    /// target's port `from` (the `open` or the `closed` one), acknowledging
    /// `ack`, a reset when `rst`.
    pub fn probe_for(
        &self,
        dport: u16,
        from: u16,
        ack: u32,
        rst: bool,
        open: u16,
        closed: Option<u16>,
    ) -> Option<usize> {
        if !self.fixed {
            return self.probe_for_port(dport);
        }
        if dport != self.sport {
            return None;
        }
        let (syns, ack_probe) = if from == open {
            (S1..=E, A)
        } else if Some(from) == closed {
            (C1..=C1, C2)
        } else {
            return None;
        };
        // A SYN's answer acknowledges its sequence number plus one; a reset
        // that does not is the answer to the ACK probe.
        syns.into_iter()
            .find(|&i| ack == self.seq_of(i).wrapping_add(1))
            .or(rst.then_some(ack_probe))
    }
}

/// The TCP segment of probe `i` (not `ie`) from `src` to `dst:dport`, with
/// its checksum.
pub fn tcp_segment(i: usize, src: IpAddr, dst: IpAddr, dport: u16, k: &Keys) -> Vec<u8> {
    let opts = options(i, k.tsval);
    let len = 20 + opts.len();
    let mut p = vec![0u8; len];
    p[0..2].copy_from_slice(&k.sport_of(i).to_be_bytes());
    p[2..4].copy_from_slice(&dport.to_be_bytes());
    p[4..8].copy_from_slice(&k.seq_of(i).to_be_bytes());
    if is_ack(i) {
        p[8..12].copy_from_slice(&k.ack.to_be_bytes());
    }
    p[12] = ((len / 4) as u8) << 4;
    p[13] = flags(i);
    p[14..16].copy_from_slice(&WINDOW.to_be_bytes());
    p[20..].copy_from_slice(&opts);
    let sum = packet::checksum_with(
        packet::pseudo_header_sum(src, dst, packet::IPPROTO_TCP, len),
        &p,
    );
    p[16..18].copy_from_slice(&sum.to_be_bytes());
    p
}

/// The echo request of probe `ie`. Over IPv6 the kernel fills in the
/// checksum.
pub fn echo(v6: bool, k: &Keys) -> Vec<u8> {
    if v6 {
        packet::icmpv6_echo(k.icmp_id, 0, packet::ECHO_MARKER)
    } else {
        packet::icmp_echo(k.icmp_id, 0, packet::ECHO_MARKER)
    }
}

/// A probe's `--packet-trace` (and `--dry-run`) line: the usual line, with
/// the TCP options, which are what tell the probes apart.
pub fn describe(proto: u8, pkt: &[u8], src: Option<IpAddr>, dst: IpAddr) -> String {
    let line = crate::packet_trace::describe(proto, pkt, src, Some(dst));
    if proto != packet::IPPROTO_TCP {
        return line;
    }
    let opts = crate::packet_trace::tcp_options_text(pkt);
    if opts.is_empty() {
        line
    } else {
        format!("{line} {opts}")
    }
}

/// What a try sends to one host: probe indexes, in sending order.
/// `closed` and `icmp` say whether the closed-port and echo probes go.
pub fn plan(closed: bool, icmp: bool) -> Vec<usize> {
    (0..PROBES)
        .filter(|&i| match target_of(i) {
            Target::Open => true,
            Target::Closed => closed,
            Target::Icmp => icmp,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn option_layouts_are_word_aligned() {
        for (i, name) in NAMES.iter().enumerate().take(IE) {
            let k = Keys::new(|| 5);
            let o = options(i, k.tsval);
            assert_eq!(o.len() % 4, 0, "probe {name}");
            let seg = tcp_segment(
                i,
                "10.0.0.1".parse().unwrap(),
                "10.0.0.2".parse().unwrap(),
                22,
                &k,
            );
            let tcp = packet::parse_tcp(&seg).unwrap();
            assert_eq!(tcp.flags, flags(i));
            assert_eq!(tcp.window, WINDOW);
            assert_eq!(packet::tcp_options(&seg), &o[..]);
            if i == 0 {
                let line = describe(packet::IPPROTO_TCP, &seg, None, "10.0.0.2".parse().unwrap());
                assert!(
                    line.ends_with(&format!(
                        "<mss 1460,sackOK,timestamp {} 0,nop,wscale 7>",
                        k.tsval
                    )),
                    "{line}"
                );
            }
        }
    }

    #[test]
    fn plan_and_keys() {
        assert_eq!(plan(false, false), vec![0, 1, 2, 3, 4, 5]);
        assert_eq!(plan(true, true).len(), PROBES);
        let k = Keys::new(|| 1000);
        assert_eq!(k.probe_for_port(k.sport + 7), Some(C2));
        assert_eq!(k.probe_for_port(k.sport + 8), None);
        assert_eq!(k.probe_for_port(k.sport - 1), None);

        // -g: every probe from one port, told apart by what they acknowledge.
        let k = k.with_source_port(Some(53));
        assert_eq!((k.sport_of(0), k.sport_of(C2)), (53, 53));
        assert_eq!(
            k.probe_for(53, 22, k.seq_of(2) + 1, false, 22, Some(81)),
            Some(2)
        );
        assert_eq!(k.probe_for(53, 22, 0, true, 22, Some(81)), Some(A));
        assert_eq!(
            k.probe_for(53, 81, k.seq_of(C1) + 1, true, 22, Some(81)),
            Some(C1)
        );
        assert_eq!(k.probe_for(53, 81, 0, true, 22, Some(81)), Some(C2));
        assert_eq!(
            k.probe_for(54, 22, k.seq_of(0) + 1, false, 22, Some(81)),
            None
        );
        assert_eq!(
            k.probe_for(53, 23, k.seq_of(0) + 1, false, 22, Some(81)),
            None
        );
    }
}
