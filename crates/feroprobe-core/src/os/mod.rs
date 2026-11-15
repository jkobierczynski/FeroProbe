//! OS detection (`-O`): a multi-probe TCP/IP fingerprint matched against
//! FeroProbe's own signature database.
//!
//! Each *try* sends a host at most nine probes ([`probes`]): four SYNs with
//! different TCP options 100 ms apart, a SYN asking for ECN and an ACK to
//! an open TCP port the scan found; a SYN and an ACK to a closed TCP port,
//! when the scan found one; and an ICMP echo request, only when the command
//! sends echo requests anyway (default host discovery as root, or `-PE`).
//! Nothing goes to a port or protocol the command did not already probe.
//! The answers become a fingerprint ([`fingerprint`]): option layouts,
//! windows, flags, the "don't fragment" bit, the IP ID and TCP timestamp
//! sequences and the initial TTL. The fingerprint is scored against every
//! signature in [`db`]; a signature whose every test matches is a perfect
//! match and is reported as the OS, one at 85% or better is a guess.
//!
//! As in nmap, a host without a perfect match is tried again, up to
//! `--max-os-tries` times (5), or twice when the conditions make a match
//! unlikely (no closed port, a distant host); `--osscan-limit` skips hosts
//! without both an open and a closed TCP port; `--osscan-guess` prints the
//! near matches nmap calls "aggressive guesses".
//!
//! It works over IPv4 and IPv6. Answers are read off a packet capture,
//! which gives the IP header (TTL or hop limit, DF, IP ID) for both. Needs
//! raw sockets: Linux, root or `CAP_NET_RAW`.

pub mod db;
pub mod fingerprint;
pub mod probes;

use std::io;
use std::net::IpAddr;

use serde::Serialize;

use crate::model::{HostResult, PortState, Protocol, ScanConfig};

pub use fingerprint::Fingerprint;

/// The `-O` options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OsOptions {
    /// `--osscan-limit`: only hosts with an open and a closed TCP port.
    pub limit: bool,
    /// `--osscan-guess` (or `--fuzzy`): report near matches too.
    pub guess: bool,
    /// `--max-os-tries`: tries for a host without a perfect match.
    pub max_tries: u32,
    /// The command sends ICMP echo requests (host discovery), so the echo
    /// probe stays in scope.
    pub icmp_echo: bool,
}

impl Default for OsOptions {
    fn default() -> Self {
        Self {
            limit: false,
            guess: false,
            max_tries: DEFAULT_TRIES,
            icmp_echo: false,
        }
    }
}

/// nmap's default `--max-os-tries`.
pub const DEFAULT_TRIES: u32 = 5;

/// Tries for a host whose conditions make a match unlikely (nmap's
/// `STANDARD_OS2_TRIES`).
pub const UNIDEAL_TRIES: u32 = 2;

/// One signature that matched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OsMatch {
    /// The signature's name, such as `Linux 4.19 - 6.x`.
    pub name: String,
    /// Percent of the signature's tests (by weight) that matched.
    pub accuracy: u8,
    pub vendor: String,
    pub family: String,
    /// Such as `5.X|6.X`; empty when the signature names none.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub generation: String,
    /// `general purpose`, `router`, `specialized`, ...
    pub device_type: String,
    pub cpe: Vec<String>,
    /// The signature's line in the database.
    pub line: usize,
}

/// What OS detection found for one host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OsResult {
    /// The matches, best first: the perfect ones (100%), or else the
    /// guesses within 10 points of the best (at most 10).
    pub matches: Vec<OsMatch>,
    /// How many of [`matches`](Self::matches) are perfect.
    pub perfect: usize,
    /// The fingerprint of the best try, as `test=value` pairs.
    pub fingerprint: String,
    /// The open TCP port the probes went to.
    pub open_port: u16,
    /// The closed TCP port, if the scan found one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub closed_port: Option<u16>,
    /// Routers between us and the host: 0 for this machine, 1 for a
    /// neighbour (MAC address known), else from the TTL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub distance: Option<u8>,
    /// The IP ID sequence class of the SYN-ACKs (IPv4).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipid_class: Option<String>,
    /// The IP IDs it was read from.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ipids: Vec<u16>,
    /// Tries made.
    pub tries: u32,
    /// Why the result is less reliable than it could be, as nmap's "OS
    /// fingerprint not ideal because ..." (such as a missing closed port).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_ideal: Option<String>,
}

impl OsResult {
    /// The best match, if any.
    pub fn best(&self) -> Option<&OsMatch> {
        self.matches.first()
    }
}

/// One host to fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    /// Index into the host list.
    pub host: usize,
    pub addr: IpAddr,
    pub open: u16,
    pub closed: Option<u16>,
    /// 0 for this machine, 1 for a neighbour, else unknown.
    pub known_distance: Option<u8>,
}

/// The host to fingerprint at `index`, if it qualifies: it needs an open
/// TCP port (the probes are only sent to ports the scan found), and with
/// `--osscan-limit` also a closed or unfiltered one, as in nmap.
pub fn job_for(index: usize, host: &HostResult, opts: &OsOptions) -> Option<Job> {
    let tcp = |state: PortState| {
        host.ports
            .iter()
            .find(|p| p.protocol == Protocol::Tcp && p.state == state)
            .map(|p| p.port)
    };
    let open = tcp(PortState::Open)?;
    let closed = tcp(PortState::Closed);
    if opts.limit && closed.is_none() && tcp(PortState::Unfiltered).is_none() {
        return None;
    }
    let known_distance = if crate::discovery::is_localhost(host.addr) {
        Some(0)
    } else if host.mac.is_some() {
        Some(1)
    } else {
        None
    };
    Some(Job {
        host: index,
        addr: host.addr,
        open,
        closed,
        known_distance,
    })
}

/// Why a fingerprint is not ideal, like nmap's `OmitSubmissionFP`.
fn not_ideal(job: &Job, distance: Option<u8>, cfg: &ScanConfig) -> Option<String> {
    if cfg.scan_delay > std::time::Duration::from_millis(500) {
        return Some(format!(
            "Scan delay ({} ms) is greater than 500",
            cfg.scan_delay.as_millis()
        ));
    }
    if job.closed.is_none() {
        return Some("Missing a closed TCP port so results incomplete".into());
    }
    if let Some(d) = distance
        && d > 5
    {
        return Some(format!(
            "Host distance ({d} network hops) is greater than five"
        ));
    }
    None
}

/// The routers between us and the host, from the answers' TTL when the
/// distance is not known otherwise.
fn distance_of(job: &Job, fp: &Fingerprint, ttl: Option<u8>) -> Option<u8> {
    job.known_distance.or_else(|| {
        let initial: u8 = fp.get("ttl")?.parse().ok()?;
        Some(initial.saturating_sub(ttl?).saturating_add(1))
    })
}

/// Score one fingerprint: the matches to report and how many are perfect.
pub fn classify(db: &[db::Signature], fp: &Fingerprint) -> (Vec<OsMatch>, usize) {
    let found = db::matches(db, fp);
    let perfect = found.iter().take_while(|(_, a)| *a == 100).count();
    let best = found.first().map_or(0, |(_, a)| *a);
    let keep: Vec<OsMatch> = found
        .into_iter()
        .enumerate()
        .take_while(|(i, (_, a))| {
            if perfect > 0 {
                *i < perfect
            } else {
                *i < 10 && *a + 10 > best
            }
        })
        .map(|(_, (s, a))| OsMatch {
            name: s.name.clone(),
            accuracy: a,
            vendor: s.class.vendor.clone(),
            family: s.class.family.clone(),
            generation: s.class.generation.clone(),
            device_type: s.class.device_type.clone(),
            cpe: s.cpe.clone(),
            line: s.line,
        })
        .collect();
    (keep, perfect)
}

/// The result for one host from its tries: the try with the best match
/// (the first perfect one), as nmap's `findBestFPs`.
pub fn result_for(job: &Job, tries: &[fingerprint::Try], cfg: &ScanConfig) -> OsResult {
    let db = db::built_in();
    let mut best: Option<(usize, Vec<OsMatch>, usize, Fingerprint)> = None;
    for (n, t) in tries.iter().enumerate() {
        let fp = fingerprint::fingerprint(t);
        let (m, perfect) = classify(db, &fp);
        let score = |m: &[OsMatch]| m.first().map_or(0, |x| x.accuracy);
        let better = match &best {
            None => true,
            Some((_, bm, _, bfp)) => {
                score(&m) > score(bm)
                    || (score(&m) == score(bm) && fp.tests.len() > bfp.tests.len())
            }
        };
        if better {
            best = Some((n, m, perfect, fp));
        }
        if perfect > 0 {
            break;
        }
    }
    let (n, matches, perfect, fp) = best.unwrap_or_default();
    let t = tries.get(n);
    let ttl = t.and_then(|t| t.replies.iter().flatten().map(|r| r.ttl).max());
    let distance = distance_of(job, &fp, ttl);
    let ipids = t.map(fingerprint::seq_ipids).unwrap_or_default();
    OsResult {
        matches,
        perfect,
        open_port: job.open,
        closed_port: job.closed,
        distance,
        ipid_class: fp.get("ipid").map(str::to_string),
        ipids,
        tries: tries.len() as u32,
        not_ideal: not_ideal(job, distance, cfg),
        fingerprint: fp.line(),
    }
}

/// How many tries a host gets: `--max-os-tries`, at most two when the
/// conditions are not ideal.
pub fn tries_for(job: &Job, opts: &OsOptions, cfg: &ScanConfig) -> u32 {
    let max = opts.max_tries.max(1);
    if not_ideal(job, job.known_distance, cfg).is_some() {
        max.min(UNIDEAL_TRIES)
    } else {
        max
    }
}

/// Fingerprint every host with an open TCP port (and with `--osscan-limit`
/// a closed or unfiltered one too), filling in [`HostResult::os`], over
/// IPv4 and IPv6. Hosts that did not qualify are left alone.
pub async fn os_detect(
    hosts: &mut [HostResult],
    cfg: &ScanConfig,
    opts: &OsOptions,
) -> io::Result<()> {
    let jobs: Vec<Job> = hosts
        .iter()
        .enumerate()
        .filter_map(|(h, host)| job_for(h, host, opts))
        .collect();
    if jobs.is_empty() {
        return Ok(());
    }
    let cfg2 = cfg.clone();
    let opts2 = *opts;
    let probe_jobs = jobs.clone();
    let tries =
        tokio::task::spawn_blocking(move || imp::probe_blocking(&probe_jobs, &cfg2, &opts2))
            .await
            .map_err(io::Error::other)??;
    for (job, tries) in jobs.iter().zip(tries) {
        if !tries.is_empty() {
            hosts[job.host].os = Some(result_for(job, &tries, cfg));
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::*;

    pub(super) fn probe_blocking(
        _: &[Job],
        _: &ScanConfig,
        _: &OsOptions,
    ) -> io::Result<Vec<Vec<fingerprint::Try>>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "OS detection is only supported on Linux for now",
        ))
    }
}

#[cfg(target_os = "linux")]
mod imp;

#[cfg(test)]
mod tests;
