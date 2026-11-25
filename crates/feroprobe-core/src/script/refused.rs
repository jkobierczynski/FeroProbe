//! Connections a script's scope refused, gathered so the user sees one
//! line per script instead of one per attempt.
//!
//! The scope guard (see [`super::socket::Scope`]) is unchanged: every
//! connection outside the scope is refused. Only the telling changes. A
//! forced script (`+name`) run on every port can try a connection the scan
//! never allowed on each of them, and nmap-style scripts often retry, so a
//! warning per attempt floods the output. Each refusal is counted here.
//! Without `-v` nothing is printed (Jurgen, 2026-11-24): the refusal is the
//! guard working as meant, and the script's own output shows what it got.
//! With `-v`, when the scripts of a phase are done, [`Refusals::warnings`]
//! gives one summary line per script and reason; with `-vv` or `-d` each
//! refusal is also printed as it happens.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Mutex;

use crate::model::Protocol;

/// Why a connection was refused, as far as the summary tells it apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Reason {
    /// A prerule or postrule script, which has no network access.
    NoNetwork,
    /// A host other than the one the script runs against.
    OtherHost,
    /// A port of this protocol the scan did not probe on the host.
    Port(Protocol),
    /// A protocol scripts cannot open sockets for.
    Unsupported(Protocol),
}

/// One refused connection.
#[derive(Debug, Clone)]
pub(crate) struct Refusal {
    pub reason: Reason,
    /// The host the script asked for, as it gave it.
    pub host: String,
    pub port: u16,
    /// The host the script ran against, if any.
    pub against: Option<IpAddr>,
    /// Whether the scan probed no port at all of the refused port's
    /// protocol on that host.
    pub none_probed: bool,
    /// The full message, as `-v` prints it.
    pub message: String,
}

#[derive(Debug, Default)]
struct Tally {
    attempts: usize,
    /// Hosts the script ran against.
    against: BTreeSet<IpAddr>,
    /// Hosts it asked for, for [`Reason::OtherHost`].
    asked: BTreeSet<String>,
    ports: BTreeSet<u16>,
    /// Whether every refusal was for a protocol the scan did not probe.
    none_probed: bool,
}

/// The refusals of a run, by script and reason.
#[derive(Debug, Default)]
pub(crate) struct Refusals {
    seen: Mutex<BTreeMap<(String, Reason), Tally>>,
}

/// Whether each refusal is printed as it happens: `-vv` or `-d`.
fn each_shown() -> bool {
    crate::debug::verbosity() >= 2 || crate::debug::debugging() >= 1
}

/// How many items a summary names before it says how many more.
const SHOWN: usize = 8;

impl Refusals {
    /// Count `r`, refused for `script`. With `-vv` or `-d` it is also
    /// printed at once.
    pub(crate) fn record(&self, script: &str, r: Refusal) {
        if each_shown() {
            eprintln!(
                "Warning: script {script}: connection refused: {}",
                r.message
            );
        }
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        let t = seen.entry((script.to_string(), r.reason)).or_insert(Tally {
            none_probed: true,
            ..Tally::default()
        });
        t.attempts += 1;
        t.against.extend(r.against);
        t.asked.insert(r.host);
        t.ports.insert(r.port);
        t.none_probed &= r.none_probed;
    }

    /// One summary line for each script and reason seen since the last
    /// call, and forget them. None without `-v` (or `-d`).
    pub(crate) fn warnings(&self) -> Vec<String> {
        let lines = self.take(each_shown());
        if crate::debug::verbosity() >= 1 || crate::debug::debugging() >= 1 {
            lines
        } else {
            Vec::new()
        }
    }

    /// [`Refusals::warnings`], `detailed` when each refusal was already
    /// printed.
    fn take(&self, detailed: bool) -> Vec<String> {
        let seen = std::mem::take(&mut *self.seen.lock().unwrap_or_else(|e| e.into_inner()));
        seen.into_iter()
            .map(|((script, reason), t)| summary(&script, reason, &t, detailed))
            .collect()
    }
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// `items` joined with commas, the first [`SHOWN`] of them.
fn some<T: ToString>(items: impl ExactSizeIterator<Item = T>) -> String {
    let n = items.len();
    let mut s: Vec<String> = items.take(SHOWN).map(|i| i.to_string()).collect();
    if n > SHOWN {
        s.push(format!("{} more", n - SHOWN));
    }
    s.join(", ")
}

fn summary(script: &str, reason: Reason, t: &Tally, detailed: bool) -> String {
    let count = plural(t.attempts, "connection", "connections");
    let on = match t.against.len() {
        0 => String::new(),
        1 => format!(" on {}", t.against.iter().next().expect("one host")),
        n => format!(" on {n} hosts"),
    };
    let what = match reason {
        Reason::NoNetwork => {
            "scripts that run before or after the scan may only reach the run's DNS servers"
                .to_string()
        }
        Reason::OtherHost => format!(
            "only the host it runs against is in scope (it tried {})",
            some(t.asked.iter())
        ),
        Reason::Port(proto) => {
            let tried = format!(
                "it tried {}: {}",
                plural(
                    t.ports.len(),
                    &format!("{proto} port"),
                    &format!("{proto} ports")
                ),
                some(t.ports.iter())
            );
            if t.none_probed {
                let up = proto.to_string().to_uppercase();
                format!("{up} not scanned ({tried})")
            } else {
                format!("outside the {proto} ports the scan probed ({tried})")
            }
        }
        Reason::Unsupported(proto) => format!("scripts cannot open {proto} sockets"),
    };
    let hint = if detailed { "" } else { "; -vv shows each" };
    format!("Warning: script {script}: {count} refused{on}, {what}{hint}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn port(port: u16, none_probed: bool) -> Refusal {
        Refusal {
            reason: Reason::Port(Protocol::Udp),
            host: "192.0.2.7".into(),
            port,
            against: Some("192.0.2.7".parse().unwrap()),
            none_probed,
            message: String::new(),
        }
    }

    #[test]
    fn one_line_per_script_and_reason() {
        let r = Refusals::default();
        for p in [21, 22, 110, 21, 22, 110] {
            r.record("ntp-info", port(p, true));
        }
        r.record("snmp-info", port(21, true));
        let w = r.take(false);
        assert_eq!(
            w,
            [
                "Warning: script ntp-info: 6 connections refused on 192.0.2.7, UDP not \
                 scanned (it tried 3 udp ports: 21, 22, 110); -vv shows each",
                "Warning: script snmp-info: 1 connection refused on 192.0.2.7, UDP not \
                 scanned (it tried 1 udp port: 21); -vv shows each",
            ]
        );
        // Told once: the next phase starts afresh.
        assert!(r.take(false).is_empty());
    }

    #[test]
    fn some_ports_probed_and_long_lists() {
        let r = Refusals::default();
        for p in 1..=10 {
            r.record("x", port(p, p != 3));
        }
        let w = r.take(false);
        assert_eq!(
            w,
            [
                "Warning: script x: 10 connections refused on 192.0.2.7, outside the udp \
                 ports the scan probed (it tried 10 udp ports: 1, 2, 3, 4, 5, 6, 7, 8, 2 \
                 more); -vv shows each"
            ]
        );
    }

    #[test]
    fn other_hosts_and_no_network() {
        let r = Refusals::default();
        r.record(
            "x",
            Refusal {
                reason: Reason::OtherHost,
                host: "other.example".into(),
                port: 80,
                against: Some("192.0.2.7".parse().unwrap()),
                none_probed: false,
                message: String::new(),
            },
        );
        r.record(
            "y",
            Refusal {
                reason: Reason::NoNetwork,
                host: "192.0.2.7".into(),
                port: 80,
                against: None,
                none_probed: false,
                message: String::new(),
            },
        );
        assert_eq!(
            r.take(false),
            [
                "Warning: script x: 1 connection refused on 192.0.2.7, only the host it \
                 runs against is in scope (it tried other.example); -vv shows each",
                "Warning: script y: 1 connection refused, scripts that run before or after \
                 the scan may only reach the run's DNS servers; -vv shows each",
            ]
        );
    }
}
