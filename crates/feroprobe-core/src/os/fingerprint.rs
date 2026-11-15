//! Turning the answers to one try into a fingerprint: a list of named
//! tests and their values, which [`super::db`] matches against the
//! signature database. Pure functions, so every test can be exercised
//! with made-up answers.
//!
//! The tests (`<p>` is a probe name from [`super::probes::NAMES`]):
//!
//! | Test | Value |
//! | --- | --- |
//! | `ttl` | the initial TTL or hop limit the answers suggest: 32, 64, 128 or 255 |
//! | `<p>` | `Y` if the probe was answered, `N` if not (only for probes sent) |
//! | `<p>.f` | the answer's TCP flags, in the order `S A F R P U E C` |
//! | `<p>.w` | its TCP window (`s1`, `s2`, `s3`, `e` and the resets) |
//! | `<p>.m` | its MSS option, which `m*N` windows are measured in (not matched by itself) |
//! | `<p>.o` | its TCP option layout: `M` MSS, `S` SACK permitted, `T` timestamps, `N` no-op, `W` window scale, `E` end of list, else the kind number; `-` for none |
//! | `<p>.df` | `Y` if the "don't fragment" bit was set (IPv4 only) |
//! | `<p>.ack` | for a reset answering a SYN: `S+` if it acknowledges our sequence number + 1, `Z` if zero, `O` otherwise |
//! | `<p>.seq` | for a reset answering an ACK: `A` if its sequence number is our acknowledgment number, `Z` if zero, `O` otherwise |
//! | `ws` | the window scale in the answer to `s1`, `-` for none |
//! | `ipid` | the IP ID sequence of the answers to `s1`..`s4` (IPv4): `Z` all zero, `C` constant, `I` incremental, `BI` incremental in steps of 256 (byte-swapped), `RI` random increments, `RD` random |
//! | `ipid.rst` | the same for the resets (`a`, `c1`, `c2`) |
//! | `ipid.shared` | `Y` if the SYN-ACKs and resets take their IP IDs from one counter |
//! | `ts` | the TCP timestamp clock from `s1` and `s4`: `U` no timestamps, `Z` zero, `R` a random offset per connection (the values jump), else the rate in Hz rounded to 2, 100, 250 or 1000, or `O` for another rate |

use std::fmt::Write as _;
use std::time::Instant;

use super::probes::{self, NAMES, PROBES};
use crate::packet;

/// One answer to an OS-detection probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// TTL or hop limit.
    pub ttl: u8,
    /// "Don't fragment" (IPv4); `None` over IPv6.
    pub df: Option<bool>,
    /// The IP identification field (IPv4).
    pub ipid: Option<u16>,
    /// The TCP header's fields, `None` for the echo reply.
    pub tcp: Option<TcpFields>,
    pub at: Instant,
}

/// What a TCP answer said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpFields {
    pub flags: u8,
    pub window: u16,
    pub seq: u32,
    pub ack: u32,
    pub options: Options,
}

/// A TCP option layout, as the `<p>.o` tests write it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Options {
    pub layout: String,
    pub mss: Option<u16>,
    pub wscale: Option<u8>,
    pub tsval: Option<u32>,
}

impl Options {
    /// Read the options of a TCP header. `None` for a malformed option.
    pub fn parse(tcp: &[u8]) -> Option<Self> {
        let opts = packet::tcp_options(tcp);
        let mut o = Options::default();
        let mut kinds: Vec<String> = Vec::new();
        let mut i = 0;
        while i < opts.len() {
            match opts[i] {
                0 => {
                    kinds.push("E".into());
                    break;
                }
                1 => {
                    kinds.push("N".into());
                    i += 1;
                    continue;
                }
                _ => {}
            }
            let kind = opts[i];
            let len = usize::from(*opts.get(i + 1)?);
            if len < 2 || i + len > opts.len() {
                return None;
            }
            let body = &opts[i + 2..i + len];
            kinds.push(match kind {
                2 => {
                    o.mss = (body.len() == 2).then(|| u16::from_be_bytes([body[0], body[1]]));
                    "M".into()
                }
                3 => {
                    o.wscale = body.first().copied();
                    "W".into()
                }
                4 => "S".into(),
                8 => {
                    o.tsval = (body.len() == 8)
                        .then(|| u32::from_be_bytes([body[0], body[1], body[2], body[3]]));
                    "T".into()
                }
                k => k.to_string(),
            });
            i += len;
        }
        o.layout = if kinds.is_empty() {
            "-".into()
        } else {
            kinds.join(",")
        };
        Some(o)
    }
}

impl Reply {
    /// An answer read from a TCP header (`tcp` is the whole segment).
    pub fn tcp(
        ttl: u8,
        df: Option<bool>,
        ipid: Option<u16>,
        tcp: &[u8],
        at: Instant,
    ) -> Option<Self> {
        let h = packet::parse_tcp(tcp)?;
        Some(Self {
            ttl,
            df,
            ipid,
            tcp: Some(TcpFields {
                flags: h.flags,
                window: h.window,
                seq: h.seq,
                ack: h.ack,
                options: Options::parse(tcp)?,
            }),
            at,
        })
    }
}

/// What one try sent and got back from one host.
#[derive(Debug, Clone)]
pub struct Try {
    /// Over IPv6 (no DF bit, no IP ID).
    pub v6: bool,
    /// Which probes were sent.
    pub sent: [bool; PROBES],
    /// The answers, by probe.
    pub replies: [Option<Reply>; PROBES],
    pub keys: probes::Keys,
}

impl Try {
    pub fn new(v6: bool, keys: probes::Keys) -> Self {
        Self {
            v6,
            sent: [false; PROBES],
            replies: Default::default(),
            keys,
        }
    }

    /// How many probes were answered.
    pub fn answered(&self) -> usize {
        self.replies.iter().flatten().count()
    }
}

/// A fingerprint: tests and values, in a fixed order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fingerprint {
    pub tests: Vec<(String, String)>,
}

impl Fingerprint {
    pub fn get(&self, test: &str) -> Option<&str> {
        self.tests
            .iter()
            .find(|(t, _)| t == test)
            .map(|(_, v)| v.as_str())
    }

    fn set(&mut self, test: impl Into<String>, value: impl Into<String>) {
        self.tests.push((test.into(), value.into()));
    }

    /// One line, `test=value` pairs separated by spaces.
    pub fn line(&self) -> String {
        let mut s = String::new();
        for (t, v) in &self.tests {
            if !s.is_empty() {
                s.push(' ');
            }
            let _ = write!(s, "{t}={v}");
        }
        s
    }

    /// Lines of about `width` characters, for the report.
    pub fn wrapped(&self, width: usize) -> Vec<String> {
        let mut lines = vec![String::new()];
        for (t, v) in &self.tests {
            let item = format!("{t}={v}");
            let cur = lines.last_mut().expect("never empty");
            if !cur.is_empty() && cur.len() + 1 + item.len() > width {
                lines.push(item);
            } else {
                if !cur.is_empty() {
                    cur.push(' ');
                }
                cur.push_str(&item);
            }
        }
        lines
    }
}

/// The initial TTL a received TTL most likely started from.
pub fn initial_ttl(ttl: u8) -> u8 {
    match ttl {
        0..=32 => 32,
        33..=64 => 64,
        65..=128 => 128,
        _ => 255,
    }
}

/// The IP ID sequence class of `ids` (in sending order). `None` with fewer
/// than two values.
pub fn ipid_class(ids: &[u16]) -> Option<&'static str> {
    if ids.len() < 2 {
        return None;
    }
    if ids.iter().all(|&i| i == 0) {
        return Some("Z");
    }
    if ids.windows(2).all(|w| w[0] == w[1]) {
        return Some("C");
    }
    // A stack that writes its counter in host order on a little-endian CPU
    // counts in the high byte: its IDs, byte-swapped back, go up by small
    // steps, also when the low byte carries over.
    if ids
        .windows(2)
        .all(|w| (1..=20).contains(&w[1].swap_bytes().wrapping_sub(w[0].swap_bytes())))
    {
        return Some("BI");
    }
    let diffs: Vec<u16> = ids.windows(2).map(|w| w[1].wrapping_sub(w[0])).collect();
    if diffs.iter().all(|&d| (1..=1000).contains(&d)) {
        return Some("I");
    }
    if diffs.iter().all(|&d| (1..20000).contains(&d)) {
        return Some("RI");
    }
    Some("RD")
}

/// nmap's words for an IP ID class, for the verbose report line.
pub fn ipid_class_words(class: &str) -> &'static str {
    match class {
        "Z" => "All zeros",
        "C" => "Constant",
        "I" => "Incremental",
        "BI" => "Broken little-endian incremental",
        "RI" => "Randomized increments",
        "RD" => "Randomized",
        _ => "Busy server or unknown class",
    }
}

/// The timestamp clock class from two answers' timestamp values and
/// arrival times.
pub fn ts_class(first: Option<(u32, Instant)>, last: Option<(u32, Instant)>) -> Option<String> {
    let (Some((v1, t1)), Some((v2, t2))) = (first, last) else {
        return None;
    };
    if v1 == 0 && v2 == 0 {
        return Some("Z".into());
    }
    let secs = t2.saturating_duration_since(t1).as_secs_f64();
    if secs < 0.05 {
        return None;
    }
    let step = v2.wrapping_sub(v1);
    // A clock that went backwards, or ran faster than any real one: each
    // connection gets its own random offset, so no rate can be read.
    if step > u32::MAX / 2 {
        return Some("R".into());
    }
    let hz = f64::from(step) / secs;
    Some(
        match hz {
            h if (0.5..=5.0).contains(&h) => "2",
            h if (70.0..=150.0).contains(&h) => "100",
            h if (170.0..=350.0).contains(&h) => "250",
            h if (700.0..=1500.0).contains(&h) => "1000",
            h if h > 100_000.0 => "R",
            _ => "O",
        }
        .into(),
    )
}

fn yn(b: bool) -> &'static str {
    if b { "Y" } else { "N" }
}

/// The fingerprint of one try.
pub fn fingerprint(t: &Try) -> Fingerprint {
    let mut fp = Fingerprint::default();
    let best_ttl = t.replies.iter().flatten().map(|r| r.ttl).max();
    if let Some(ttl) = best_ttl {
        fp.set("ttl", initial_ttl(ttl).to_string());
    }
    for (i, &name) in NAMES.iter().enumerate() {
        if !t.sent[i] {
            continue;
        }
        fp.set(name, yn(t.replies[i].is_some()));
        let Some(r) = &t.replies[i] else { continue };
        if let Some(tcp) = &r.tcp {
            fp.set(
                format!("{name}.f"),
                crate::packet_trace::tcp_flags(tcp.flags),
            );
            let syn_ack = tcp.flags & packet::TCP_SYN != 0;
            // The windows of s4 repeat what s1 and s3 show; leave them out.
            if i != probes::S4 {
                fp.set(format!("{name}.w"), tcp.window.to_string());
            }
            if syn_ack {
                if let Some(m) = tcp.options.mss {
                    fp.set(format!("{name}.m"), m.to_string());
                }
                fp.set(format!("{name}.o"), tcp.options.layout.clone());
            }
            if let Some(df) = r.df {
                fp.set(format!("{name}.df"), yn(df));
            }
            if !syn_ack && tcp.flags & packet::TCP_RST != 0 {
                if probes::is_ack(i) {
                    let v = match tcp.seq {
                        s if s == t.keys.ack => "A",
                        0 => "Z",
                        _ => "O",
                    };
                    fp.set(format!("{name}.seq"), v);
                } else {
                    let v = match tcp.ack {
                        a if a == t.keys.seq_of(i).wrapping_add(1) => "S+",
                        0 => "Z",
                        _ => "O",
                    };
                    fp.set(format!("{name}.ack"), v);
                }
            }
        } else if let Some(df) = r.df {
            fp.set(format!("{name}.df"), yn(df));
        }
    }
    if let Some(r) = &t.replies[probes::S1]
        && let Some(tcp) = &r.tcp
        && tcp.flags & packet::TCP_SYN != 0
    {
        fp.set(
            "ws",
            tcp.options
                .wscale
                .map_or_else(|| "-".to_string(), |w| w.to_string()),
        );
    }
    if !t.v6 {
        let ids = |probes: &[usize]| -> Vec<u16> {
            probes
                .iter()
                .filter_map(|&i| t.replies[i].as_ref())
                .filter_map(|r| r.ipid)
                .collect()
        };
        let syn = ids(&[0, 1, 2, 3]);
        let rst = ids(&[probes::A, probes::C1, probes::C2]);
        let syn_class = if syn.len() >= 3 {
            ipid_class(&syn)
        } else {
            None
        };
        let rst_class = ipid_class(&rst);
        if let Some(c) = syn_class {
            fp.set("ipid", c);
        }
        if let Some(c) = rst_class {
            fp.set("ipid.rst", c);
        }
        if let (Some(s), Some(r)) = (syn_class, rst_class)
            && matches!(s, "I" | "BI" | "RI")
            && matches!(r, "I" | "BI" | "RI")
        {
            // One counter: every ID, in sending order, keeps counting up.
            let all = ids(&[0, 1, 2, 3, probes::E, probes::A, probes::C1, probes::C2]);
            fp.set("ipid.shared", yn(ipid_class(&all) == Some(s)));
        }
    }
    let ts_of = |i: usize| -> Option<Option<(u32, Instant)>> {
        let r = t.replies[i].as_ref()?;
        let tcp = r.tcp.as_ref()?;
        Some(tcp.options.tsval.map(|v| (v, r.at)))
    };
    match (ts_of(probes::S1), ts_of(probes::S4)) {
        // Both answered without a timestamp: the host does not use them.
        (Some(None), Some(None)) => fp.set("ts", "U"),
        (Some(a), Some(b)) => {
            if let Some(c) = ts_class(a, b) {
                fp.set("ts", c);
            }
        }
        _ => {}
    }
    fp
}

/// The IP IDs of the sequence answers, for the report.
pub fn seq_ipids(t: &Try) -> Vec<u16> {
    t.replies[..probes::SEQ_PROBES]
        .iter()
        .flatten()
        .filter_map(|r| r.ipid)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn ipid_classes() {
        assert_eq!(ipid_class(&[0, 0, 0]), Some("Z"));
        assert_eq!(ipid_class(&[7, 7, 7]), Some("C"));
        assert_eq!(ipid_class(&[100, 101, 105, 110]), Some("I"));
        assert_eq!(ipid_class(&[65534, 2, 9]), Some("I"));
        assert_eq!(ipid_class(&[0x0100, 0x0200, 0x0400]), Some("BI"));
        // The low byte carries over between the second and third ID.
        assert_eq!(ipid_class(&[0xfe00, 0xff00, 0x0001, 0x0101]), Some("BI"));
        assert_eq!(ipid_class(&[100, 5000, 9000]), Some("RI"));
        assert_eq!(ipid_class(&[40000, 1000, 30000]), Some("RD"));
        assert_eq!(ipid_class(&[1]), None);
    }

    #[test]
    fn timestamp_rates() {
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_millis(300);
        assert_eq!(
            ts_class(Some((1000, t0)), Some((1300, t1))).as_deref(),
            Some("1000")
        );
        assert_eq!(
            ts_class(Some((1000, t0)), Some((1030, t1))).as_deref(),
            Some("100")
        );
        assert_eq!(
            ts_class(Some((1000, t0)), Some((1075, t1))).as_deref(),
            Some("250")
        );
        assert_eq!(ts_class(Some((0, t0)), Some((0, t1))).as_deref(), Some("Z"));
        assert_eq!(
            ts_class(Some((1000, t0)), Some((5000, t1))).as_deref(),
            Some("O")
        );
        assert_eq!(
            ts_class(Some((1000, t0)), Some((900_000_000, t1))).as_deref(),
            Some("R")
        );
        assert_eq!(
            ts_class(Some((900_000_000, t0)), Some((1000, t1))).as_deref(),
            Some("R")
        );
        // Wraps around.
        assert_eq!(
            ts_class(Some((u32::MAX - 100, t0)), Some((199, t1))).as_deref(),
            Some("1000")
        );
        assert_eq!(ts_class(None, Some((1, t1))), None);
    }

    #[test]
    fn options_and_wrapping() {
        let mut seg = vec![0u8; 20];
        let opts = [
            2, 4, 5, 0xb4, 4, 2, 8, 10, 0, 0, 1, 0, 0, 0, 0, 0, 1, 3, 3, 7,
        ];
        seg[12] = (((20 + opts.len()) / 4) as u8) << 4;
        seg.extend_from_slice(&opts);
        let o = Options::parse(&seg).unwrap();
        assert_eq!(o.layout, "M,S,T,N,W");
        assert_eq!((o.mss, o.wscale, o.tsval), (Some(1460), Some(7), Some(256)));
        // A bad option length rejects the answer.
        let mut bad = vec![0u8; 20];
        bad[12] = 6 << 4;
        bad.extend_from_slice(&[2, 9, 0, 0]);
        assert_eq!(Options::parse(&bad), None);

        let fp = Fingerprint {
            tests: vec![("a".into(), "1".into()), ("bb".into(), "22".into())],
        };
        assert_eq!(fp.line(), "a=1 bb=22");
        assert_eq!(fp.wrapped(5), vec!["a=1", "bb=22"]);
        assert_eq!(fp.get("bb"), Some("22"));
    }
}
