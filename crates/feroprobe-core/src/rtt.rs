//! Adaptive probe timeouts and congestion control, after nmap's.
//!
//! **Timeouts.** Every answer gives a round-trip time. As in nmap (and TCP,
//! RFC 6298), each host keeps a smoothed RTT and its variance, and a probe
//! to it waits `srtt + 4 × rttvar`, clamped to `--min-rtt-timeout` and
//! `--max-rtt-timeout` and never shorter than the scan delay. A host that
//! has not answered yet borrows the estimate of the scan as a whole (all
//! hosts together), and before any answer at all a probe waits
//! `--initial-rtt-timeout`. The estimates live in [`RttState`], shared by
//! every scan of the run, so the port scan starts from what host discovery
//! learned, as nmap's per-target timing does.
//!
//! **Congestion control.** Each scan keeps a congestion window per host and
//! one for all hosts together, like TCP's: the number of probes that may be
//! waiting for an answer at once. It starts at 10, grows with every answer
//! (quickly up to the slow-start threshold, slowly after it) and is cut
//! back when an answer shows that an earlier probe was lost (an answer to a
//! retransmission). `-c` caps it. The window only ever holds probes back:
//! `--max-rate` and `--scan-delay` still apply on top of it, and only
//! `--min-rate` lets a probe through a full window, as in nmap.
//!
//! The constants and update rules follow nmap's `timing.cc` and
//! `scan_engine.cc` (nmap 7.99); the code is our own.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::model::ScanConfig;

/// The three limits on a probe's timeout, nmap's `--min-rtt-timeout`,
/// `--max-rtt-timeout` and `--initial-rtt-timeout`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RttTimeouts {
    /// The shortest a measured timeout may get.
    pub min: Duration,
    /// The longest a measured timeout may get.
    pub max: Duration,
    /// The timeout before anything has been measured.
    pub initial: Duration,
}

impl Default for RttTimeouts {
    /// nmap's defaults (and `-T3`): 100 ms, 10 s, 1 s.
    fn default() -> Self {
        Self {
            min: Duration::from_millis(100),
            max: Duration::from_secs(10),
            initial: Duration::from_secs(1),
        }
    }
}

impl RttTimeouts {
    /// A fixed timeout: all three set to `timeout` (FeroProbe's
    /// `--timeout`), so no measurement can move it.
    pub fn fixed(timeout: Duration) -> Self {
        Self {
            min: timeout,
            max: timeout,
            initial: timeout,
        }
    }

    /// Set the minimum, raising the maximum and the initial timeout to it
    /// where they are lower, as nmap does.
    pub fn set_min(&mut self, min: Duration) {
        self.min = min;
        self.max = self.max.max(min);
        self.initial = self.initial.max(min);
    }

    /// Set the maximum, lowering the minimum and the initial timeout to it
    /// where they are higher, as nmap does.
    pub fn set_max(&mut self, max: Duration) {
        self.max = max;
        self.min = self.min.min(max);
        self.initial = self.initial.min(max);
    }

    /// Set the initial timeout, moving the maximum or the minimum to it
    /// where it falls outside them, as nmap does.
    pub fn set_initial(&mut self, initial: Duration) {
        self.initial = initial;
        self.max = self.max.max(initial);
        self.min = self.min.min(initial);
    }
}

/// Microseconds, as nmap keeps them.
fn us(d: Duration) -> i64 {
    i64::try_from(d.as_micros()).unwrap_or(i64::MAX)
}

/// One RTT estimate: nmap's `struct timeout_info`, in microseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TimeoutInfo {
    /// Smoothed RTT; -1 until the first measurement.
    srtt: i64,
    /// RTT variance; -1 until the first measurement.
    rttvar: i64,
    /// The current timeout.
    timeout: i64,
}

impl TimeoutInfo {
    fn new(limits: &RttTimeouts) -> Self {
        Self {
            srtt: -1,
            rttvar: -1,
            timeout: us(limits.initial),
        }
    }

    /// Whether anything has been measured (nmap checks `srtt > 0`).
    fn measured(&self) -> bool {
        self.srtt > 0
    }

    fn timeout(&self) -> Duration {
        Duration::from_micros(self.timeout.max(0).unsigned_abs())
    }

    /// Fold in one round-trip time of `delta` microseconds: nmap's
    /// `adjust_timeouts2`.
    fn update(&mut self, mut delta: i64, limits: &RttTimeouts, scan_delay: Duration) {
        // Capture timestamps can come a hair before the send time.
        if (-50_000..0).contains(&delta) {
            delta = 10_000;
        }
        if self.srtt == -1 && self.rttvar == -1 {
            self.srtt = delta;
            self.rttvar = delta.clamp(5_000, 2_000_000);
            self.timeout = self.srtt + (self.rttvar << 2);
        } else {
            // Nonsense (over 8 s or negative): ignore it.
            if !(0..8_000_000).contains(&delta) {
                return;
            }
            let rttdelta = delta - self.srtt;
            // A sudden jump far outside the estimate: ignore it too.
            if rttdelta > 1_500_000 && rttdelta > 3 * self.srtt + 2 * self.rttvar {
                return;
            }
            self.srtt += rttdelta >> 3;
            self.rttvar += (rttdelta.abs() - self.rttvar) >> 2;
            self.timeout = self.srtt + (self.rttvar << 2);
        }
        if self.rttvar > 2_300_000 {
            self.rttvar = 2_000_000;
        }
        // nmap's box(): the minimum wins over the maximum if they cross.
        self.timeout = self.timeout.min(us(limits.max)).max(us(limits.min));
        if !scan_delay.is_zero() {
            self.timeout = self.timeout.max(us(scan_delay));
        }
    }
}

/// The RTT estimates of a run: one per host, and one for all hosts
/// together. Clones share the estimates, so every scan and host job that
/// gets a clone of the run's [`ScanConfig`] learns from the others.
#[derive(Debug, Clone, Default)]
pub struct RttState(Arc<Mutex<Estimates>>);

#[derive(Debug, Default)]
struct Estimates {
    hosts: HashMap<IpAddr, TimeoutInfo>,
    group: Option<TimeoutInfo>,
}

impl RttState {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Estimates> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// How long a probe to `addr` waits for its answer now: the host's own
    /// timeout once it has answered, else the group's once any host has,
    /// else the initial timeout. nmap's `probeTimeout()`.
    pub fn timeout(&self, addr: IpAddr, limits: &RttTimeouts) -> Duration {
        Self::timeout_in(&self.lock(), addr, limits)
    }

    fn timeout_in(est: &Estimates, addr: IpAddr, limits: &RttTimeouts) -> Duration {
        if let Some(host) = est.hosts.get(&addr).filter(|t| t.measured()) {
            host.timeout()
        } else if let Some(group) = est.group.filter(|t| t.measured()) {
            group.timeout()
        } else {
            limits.initial
        }
    }

    /// The timeout for a host that has not answered yet: the group's once
    /// any host has, else the initial timeout.
    pub fn group_timeout(&self, limits: &RttTimeouts) -> Duration {
        match self.lock().group.filter(|t| t.measured()) {
            Some(group) => group.timeout(),
            None => limits.initial,
        }
    }

    /// Record a round-trip time measured to `addr`.
    pub fn observe(&self, addr: IpAddr, rtt: Duration, limits: &RttTimeouts, scan_delay: Duration) {
        let delta = us(rtt);
        let mut est = self.lock();
        est.hosts
            .entry(addr)
            .or_insert_with(|| TimeoutInfo::new(limits))
            .update(delta, limits, scan_delay);
        est.group
            .get_or_insert_with(|| TimeoutInfo::new(limits))
            .update(delta, limits, scan_delay);
    }

    /// The smoothed RTT of `addr`, once it has answered.
    pub fn srtt(&self, addr: IpAddr) -> Option<Duration> {
        self.lock()
            .hosts
            .get(&addr)
            .filter(|t| t.measured())
            .map(|t| Duration::from_micros(t.srtt.unsigned_abs()))
    }
}

/// Congestion control settings for one scan: nmap's
/// `scan_performance_vars`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Perf {
    low_cwnd: f64,
    max_cwnd: f64,
    initial_cwnd: f64,
    slow_incr: f64,
    ca_incr: f64,
    cc_scale_max: f64,
    initial_ssthresh: f64,
    group_drop_cwnd_divisor: f64,
    drop_ssthresh_divisor: f64,
}

impl Perf {
    pub(crate) fn for_config(cfg: &ScanConfig) -> Self {
        // nmap's low_cwnd is --min-parallelism, at least one probe.
        let low_cwnd = cfg.min_parallelism.max(1) as f64;
        // -c is FeroProbe's (and, as an alias, nmap's --max-parallelism).
        let max_cwnd = (cfg.concurrency.max(1) as f64).max(low_cwnd);
        Self {
            low_cwnd,
            max_cwnd,
            initial_cwnd: 10f64.clamp(low_cwnd, max_cwnd),
            slow_incr: 1.0,
            // The window grows faster with the more aggressive templates.
            ca_incr: if cfg.timing_level < 4 { 1.0 } else { 2.0 },
            cc_scale_max: 50.0,
            initial_ssthresh: 75.0,
            group_drop_cwnd_divisor: 2.0,
            drop_ssthresh_divisor: match cfg.timing_level {
                0..=3 => 3.0 / 2.0,
                4 => 4.0 / 3.0,
                _ => 5.0 / 4.0,
            },
        }
    }
}

/// One congestion window: nmap's `ultra_timing_vals`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Window {
    cwnd: f64,
    ssthresh: f64,
    expected: u64,
    received: u64,
    last_drop: Option<Instant>,
}

impl Window {
    fn new(perf: &Perf) -> Self {
        Self {
            cwnd: perf.initial_cwnd,
            ssthresh: perf.initial_ssthresh,
            expected: 0,
            received: 0,
            last_drop: None,
        }
    }

    /// Whether one more probe fits beside `active` ones.
    fn has_room(&self, active: usize) -> bool {
        self.cwnd >= active as f64 + 0.5
    }

    /// The answer rate's correction: grow faster when many probes go
    /// unanswered (filtered ports), since then few answers come back to
    /// grow the window with.
    fn cc_scale(&self, perf: &Perf) -> f64 {
        (self.expected as f64 / self.received.max(1) as f64).min(perf.cc_scale_max)
    }

    /// An answer came in.
    fn ack(&mut self, perf: &Perf) {
        self.received += 1;
        if self.cwnd < self.ssthresh {
            self.cwnd = (self.cwnd + perf.slow_incr * self.cc_scale(perf)).min(self.ssthresh);
        } else {
            self.cwnd += perf.ca_incr / self.cwnd * self.cc_scale(perf);
        }
        self.cwnd = self.cwnd.min(perf.max_cwnd);
    }

    /// A probe was lost: back to the lowest window (one host) ...
    fn drop_host(&mut self, active: usize, perf: &Perf, now: Instant) {
        self.cwnd = perf.low_cwnd;
        self.ssthresh = (active as f64 / perf.drop_ssthresh_divisor)
            .max(2.0)
            .trunc();
        self.last_drop = Some(now);
    }

    /// ... or, for all hosts together, half the window.
    fn drop_group(&mut self, active: usize, perf: &Perf, now: Instant) {
        self.cwnd = (self.cwnd / perf.group_drop_cwnd_divisor).max(perf.low_cwnd);
        self.ssthresh = (active as f64 / perf.drop_ssthresh_divisor)
            .max(2.0)
            .trunc();
        self.last_drop = Some(now);
    }

    /// Whether a probe sent at `sent` comes after the last cut, so a batch
    /// of losses cuts the window only once.
    fn after_last_drop(&self, sent: Instant) -> bool {
        self.last_drop.is_none_or(|d| sent > d)
    }

    #[cfg(test)]
    pub(crate) fn cwnd(&self) -> f64 {
        self.cwnd
    }
}

/// What became of a probe, for the congestion windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// It drew an answer.
    Answered,
    /// It drew an ICMP error in a scan where silence means filtered. Such
    /// errors are often rate-limited or sent by a router, so like nmap a
    /// retransmission's error does not count as a loss, and moves no window.
    FilteredError,
    /// It waited out its timeout.
    TimedOut,
}

/// The congestion state of one scan: a window per host and one for the
/// group, and how many probes each has waiting. Also lets `--min-rate`
/// through a full window.
#[derive(Debug)]
pub(crate) struct Congestion {
    perf: Perf,
    group: Window,
    hosts: Vec<Window>,
    active: Vec<usize>,
    active_total: usize,
    /// Hosts with work left, for the group check: like nmap, the group
    /// window only matters while two or more hosts are left.
    incomplete: usize,
    work: Vec<usize>,
    min_rate: u32,
    start: Instant,
    sent: u64,
}

impl Congestion {
    /// `work[h]` is how many probes host `h` has to go (first tries).
    pub(crate) fn new(cfg: &ScanConfig, work: Vec<usize>) -> Self {
        let perf = Perf::for_config(cfg);
        let hosts = work.len();
        Self {
            perf,
            group: Window::new(&perf),
            hosts: vec![Window::new(&perf); hosts],
            active: vec![0; hosts],
            active_total: 0,
            incomplete: work.iter().filter(|&&w| w > 0).count(),
            work,
            min_rate: cfg.min_rate,
            start: Instant::now(),
            sent: 0,
        }
    }

    /// Whether `--min-rate` needs a probe to go now, window or not.
    fn behind_min_rate(&self, now: Instant) -> bool {
        self.min_rate > 0
            && (self.sent as f64)
                < now.duration_since(self.start).as_secs_f64() * f64::from(self.min_rate)
    }

    /// When `--min-rate` next needs a probe sent, if it is set.
    fn min_rate_due(&self) -> Option<Instant> {
        (self.min_rate > 0).then(|| {
            self.start + Duration::from_secs_f64(self.sent as f64 / f64::from(self.min_rate))
        })
    }

    fn host_has_room(&self, h: usize) -> bool {
        self.hosts[h].has_room(self.active[h])
    }

    fn group_has_room(&self) -> bool {
        self.incomplete < 2 || self.group.has_room(self.active_total)
    }

    /// Whether a probe to host `h` may go now.
    pub(crate) fn may_send(&self, h: usize, now: Instant) -> bool {
        (self.host_has_room(h) && self.group_has_room()) || self.behind_min_rate(now)
    }

    /// A probe to host `h` went out.
    pub(crate) fn sent(&mut self, h: usize) {
        self.active[h] += 1;
        self.active_total += 1;
        self.sent += 1;
    }

    /// A probe to host `h` stopped waiting (answered or timed out).
    pub(crate) fn finished_waiting(&mut self, h: usize) {
        self.active[h] = self.active[h].saturating_sub(1);
        self.active_total = self.active_total.saturating_sub(1);
    }

    /// A probe for host `h` was given up for good (answered, or out of
    /// tries), or never needed sending.
    pub(crate) fn settled(&mut self, h: usize) {
        if self.work[h] > 0 {
            self.work[h] -= 1;
            if self.work[h] == 0 {
                self.incomplete = self.incomplete.saturating_sub(1);
            }
        }
    }

    /// Move the windows for a probe to `h` sent at `sent` on try `tryno`
    /// (0 for the first): nmap's `ultrascan_adjust_timing`.
    pub(crate) fn adjust(
        &mut self,
        h: usize,
        sent: Instant,
        tryno: u32,
        outcome: Outcome,
        now: Instant,
    ) {
        if outcome == Outcome::FilteredError && tryno > 0 {
            return;
        }
        self.group.expected += 1;
        self.hosts[h].expected += 1;
        // An answer to a retransmission means an earlier probe was lost.
        if tryno > 0 && outcome != Outcome::TimedOut {
            if self.hosts[h].after_last_drop(sent) {
                self.hosts[h].drop_host(self.active[h], &self.perf, now);
            }
            if self.group.after_last_drop(sent) {
                self.group.drop_group(self.active_total, &self.perf, now);
            }
        }
        if outcome != Outcome::TimedOut {
            self.group.ack(&self.perf);
            self.hosts[h].ack(&self.perf);
        }
    }

    #[cfg(test)]
    pub(crate) fn host_window(&self, h: usize) -> Window {
        self.hosts[h]
    }
}

// Used by the raw scans, which are Linux only.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
/// What a [`Flight`] says to do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Next<K> {
    /// Send this probe now (after the usual rate pacing).
    Send(usize, K),
    /// Every window with work is full: wait for an answer, but no longer
    /// than this, then ask again.
    Wait(Instant),
    /// Nothing left to send this round.
    Idle,
}

// Used by the raw scans, which are Linux only.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
/// One probe in a [`Flight`].
#[derive(Debug, Clone, Copy)]
struct Sent {
    at: Instant,
    tryno: u32,
    waiting: bool,
}

// Used by the raw scans, which are Linux only.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
/// The send loop of a raw scan, keyed by (host index, port or protocol):
/// which probe goes next given the congestion windows, when each waiting
/// probe times out given the hosts' RTT estimates, and the bookkeeping
/// for both. The scan still does the sending and the receiving.
///
/// Probes go out in the order given to [`start_round`](Self::start_round);
/// a probe whose host's window is full is held back, and goes as soon as
/// that host has room, so one slow host does not hold up the others.
pub(crate) struct Flight<K> {
    addrs: Vec<IpAddr>,
    limits: RttTimeouts,
    scan_delay: Duration,
    state: RttState,
    cc: Congestion,
    tryno: u32,
    queue: VecDeque<(usize, K)>,
    held: HashMap<usize, VecDeque<K>>,
    probes: HashMap<(usize, K), Sent>,
    settled: std::collections::HashSet<(usize, K)>,
    /// Probes still waiting for an answer, per host.
    waiting: Vec<Vec<K>>,
}

// Used by the raw scans, which are Linux only.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl<K: Copy + Eq + Hash> Flight<K> {
    /// A flight over `addrs`, with `per_host[h]` first-try probes to send
    /// to host `h`.
    pub(crate) fn new(cfg: &ScanConfig, addrs: &[IpAddr], per_host: Vec<usize>) -> Self {
        Self {
            addrs: addrs.to_vec(),
            limits: cfg.rtt,
            scan_delay: cfg.scan_delay,
            state: cfg.rtt_state.clone(),
            cc: Congestion::new(cfg, per_host),
            tryno: 0,
            queue: VecDeque::new(),
            held: HashMap::new(),
            probes: HashMap::new(),
            settled: std::collections::HashSet::new(),
            waiting: vec![Vec::new(); addrs.len()],
        }
    }

    /// Queue the probes of try `tryno` (0 for the first), in sending order.
    pub(crate) fn start_round(&mut self, probes: impl IntoIterator<Item = (usize, K)>, tryno: u32) {
        self.tryno = tryno;
        self.queue = probes.into_iter().collect();
        self.held.clear();
    }

    /// The timeout for a probe to host `h` now.
    pub(crate) fn timeout(&self, h: usize) -> Duration {
        self.state.timeout(self.addrs[h], &self.limits)
    }

    /// Time out the waiting probes whose time is up.
    pub(crate) fn expire(&mut self, now: Instant) {
        for h in 0..self.waiting.len() {
            if self.waiting[h].is_empty() {
                continue;
            }
            let timeout = self.timeout(h);
            let mut i = 0;
            while i < self.waiting[h].len() {
                let k = self.waiting[h][i];
                let p = self
                    .probes
                    .get_mut(&(h, k))
                    .expect("waiting probe is known");
                if now >= p.at + timeout {
                    p.waiting = false;
                    let (at, tryno) = (p.at, p.tryno);
                    self.waiting[h].swap_remove(i);
                    self.cc.finished_waiting(h);
                    self.cc.adjust(h, at, tryno, Outcome::TimedOut, now);
                } else {
                    i += 1;
                }
            }
        }
    }

    /// When the next waiting probe times out.
    pub(crate) fn next_expiry(&self) -> Option<Instant> {
        self.waiting
            .iter()
            .enumerate()
            .filter(|(_, w)| !w.is_empty())
            .filter_map(|(h, w)| {
                let timeout = self.timeout(h);
                w.iter().map(|k| self.probes[&(h, *k)].at + timeout).min()
            })
            .min()
    }

    /// Whether any probe is still waiting for its answer.
    pub(crate) fn any_waiting(&self) -> bool {
        self.waiting.iter().any(|w| !w.is_empty())
    }

    /// The next probe to send, after timing out the probes whose time is
    /// up. `Wait` gives the moment something can change on its own (a
    /// timeout or `--min-rate`); an answer can change it sooner.
    pub(crate) fn next(&mut self, now: Instant) -> Next<K> {
        self.expire(now);
        // Held probes first: they have waited longest.
        if self.cc.group_has_room() || self.cc.behind_min_rate(now) {
            let ready = self
                .held
                .iter()
                .find(|(h, q)| !q.is_empty() && self.cc.may_send(**h, now))
                .map(|(h, _)| *h);
            if let Some(h) = ready {
                let q = self.held.get_mut(&h).expect("ready host is held");
                let k = q.pop_front().expect("ready queue is not empty");
                if q.is_empty() {
                    self.held.remove(&h);
                }
                return Next::Send(h, k);
            }
        }
        while let Some(&(h, k)) = self.queue.front() {
            if self.cc.may_send(h, now) {
                self.queue.pop_front();
                return Next::Send(h, k);
            }
            if !self.cc.group_has_room() && !self.cc.behind_min_rate(now) {
                break;
            }
            // Only this host is full: hold its probe, try the next one.
            self.queue.pop_front();
            self.held.entry(h).or_default().push_back(k);
        }
        if self.queue.is_empty() && self.held.is_empty() {
            return Next::Idle;
        }
        let soon = now + crate::timing::CANCEL_POLL;
        let due = [self.next_expiry(), self.cc.min_rate_due()]
            .into_iter()
            .flatten()
            .min()
            .unwrap_or(soon);
        Next::Wait(due.max(now))
    }

    /// Probe `(h, k)` went out at `at`.
    pub(crate) fn sent(&mut self, h: usize, k: K, at: Instant) {
        if let Some(old) = self.probes.get(&(h, k))
            && old.waiting
        {
            // Sent again while the earlier copy still waits: one entry.
            self.waiting[h].retain(|x| *x != k);
            self.cc.finished_waiting(h);
        }
        self.probes.insert(
            (h, k),
            Sent {
                at,
                tryno: self.tryno,
                waiting: true,
            },
        );
        self.waiting[h].push(k);
        self.cc.sent(h);
    }

    /// Probe `(h, k)` will not be sent again (answered, unreachable, or
    /// its host is done): it no longer counts as work left.
    pub(crate) fn settle(&mut self, h: usize, k: K) {
        if let Some(p) = self.probes.get_mut(&(h, k))
            && p.waiting
        {
            p.waiting = false;
            self.waiting[h].retain(|x| *x != k);
            self.cc.finished_waiting(h);
        }
        if self.settled.insert((h, k)) {
            self.cc.settled(h);
        }
    }

    /// The first answer to probe `(h, k)` came in at `at`: measure its
    /// round trip, move the windows and settle the probe. `filtered_error`
    /// marks an ICMP error in a scan where silence means filtered. Returns
    /// the round-trip time, if the probe was sent.
    pub(crate) fn answered(
        &mut self,
        h: usize,
        k: K,
        at: Instant,
        filtered_error: bool,
    ) -> Option<Duration> {
        let p = *self.probes.get(&(h, k))?;
        let rtt = at.saturating_duration_since(p.at);
        self.state
            .observe(self.addrs[h], rtt, &self.limits, self.scan_delay);
        if p.waiting {
            self.probes
                .get_mut(&(h, k))
                .expect("probe is known")
                .waiting = false;
            self.waiting[h].retain(|x| *x != k);
            self.cc.finished_waiting(h);
        }
        let outcome = if filtered_error {
            Outcome::FilteredError
        } else {
            Outcome::Answered
        };
        self.cc.adjust(h, p.at, p.tryno, outcome, at);
        if self.settled.insert((h, k)) {
            self.cc.settled(h);
        }
        Some(rtt)
    }

    /// Stop waiting for host `h`'s probes: it needs nothing more (proven
    /// up during discovery). Its probes still queued come out of
    /// [`next`](Self::next) as usual, for the scan to skip and settle.
    pub(crate) fn retire_host(&mut self, h: usize) {
        for k in std::mem::take(&mut self.waiting[h]) {
            if let Some(p) = self.probes.get_mut(&(h, k)) {
                p.waiting = false;
            }
            self.cc.finished_waiting(h);
        }
    }

    #[cfg(test)]
    pub(crate) fn congestion(&self) -> &Congestion {
        &self.cc
    }
}

/// The congestion windows of a scan whose probes are futures (connect and
/// UDP scans): each try of a probe holds a [`Slot`] while it waits for
/// its answer.
pub(crate) struct AsyncWindow {
    cc: Mutex<Congestion>,
    changed: tokio::sync::Notify,
}

impl AsyncWindow {
    /// `per_host[h]` is how many probes host `h` has.
    pub(crate) fn new(cfg: &ScanConfig, per_host: Vec<usize>) -> Self {
        Self {
            cc: Mutex::new(Congestion::new(cfg, per_host)),
            changed: tokio::sync::Notify::new(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Congestion> {
        self.cc.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Wait until a probe to host `h` may go, and count it as sent.
    pub(crate) async fn acquire(&self, h: usize) -> Slot<'_> {
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let due = {
                let mut cc = self.lock();
                let now = Instant::now();
                if cc.may_send(h, now) {
                    cc.sent(h);
                    return Slot {
                        window: self,
                        h,
                        done: false,
                    };
                }
                cc.min_rate_due()
            };
            match due {
                Some(due) => {
                    let _ = tokio::time::timeout_at(due.into(), notified).await;
                }
                None => notified.await,
            }
        }
    }

    /// Host `h`'s probe will not be tried again.
    pub(crate) fn settled(&self, h: usize) {
        self.lock().settled(h);
        self.changed.notify_waiters();
    }
}

/// One try of a probe, waiting for its answer: holds its place in the
/// congestion windows until it is finished or dropped.
pub(crate) struct Slot<'a> {
    window: &'a AsyncWindow,
    h: usize,
    done: bool,
}

impl Slot<'_> {
    /// The try ended (sent at `sent`, try `tryno`), with `outcome`.
    pub(crate) fn finish(mut self, sent: Instant, tryno: u32, outcome: Outcome) {
        let mut cc = self.window.lock();
        cc.finished_waiting(self.h);
        cc.adjust(self.h, sent, tryno, outcome, Instant::now());
        drop(cc);
        self.done = true;
        self.window.changed.notify_waiters();
    }
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.window.lock().finished_waiting(self.h);
            self.window.changed.notify_waiters();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn setters_keep_the_limits_in_order_like_nmap() {
        let mut t = RttTimeouts::default();
        t.set_initial(ms(300_000));
        assert_eq!(
            (t.min, t.max, t.initial),
            (ms(100), ms(300_000), ms(300_000))
        );
        let mut t = RttTimeouts::default();
        t.set_max(ms(50));
        assert_eq!((t.min, t.max, t.initial), (ms(50), ms(50), ms(50)));
        let mut t = RttTimeouts::default();
        t.set_min(ms(2000));
        assert_eq!((t.min, t.max, t.initial), (ms(2000), ms(10_000), ms(2000)));
        assert_eq!(RttTimeouts::fixed(ms(800)).max, ms(800));
    }

    #[test]
    fn first_measurement_sets_srtt_and_variance() {
        let limits = RttTimeouts::default();
        let mut t = TimeoutInfo::new(&limits);
        assert_eq!(t.timeout(), ms(1000));
        // 20 ms: rttvar 20 ms, timeout 20 + 80 = 100 ms.
        t.update(20_000, &limits, Duration::ZERO);
        assert_eq!((t.srtt, t.rttvar, t.timeout), (20_000, 20_000, 100_000));
        // A fast LAN host: the timeout stops at the 100 ms minimum.
        let mut t = TimeoutInfo::new(&limits);
        t.update(300, &limits, Duration::ZERO);
        assert_eq!(t.rttvar, 5_000);
        assert_eq!(t.timeout(), ms(100));
    }

    #[test]
    fn later_measurements_smooth_like_rfc_6298() {
        let limits = RttTimeouts::default();
        let mut t = TimeoutInfo::new(&limits);
        t.update(200_000, &limits, Duration::ZERO);
        // srtt += (100 - 200) / 8; rttvar += (100 - 200) / 4.
        t.update(100_000, &limits, Duration::ZERO);
        assert_eq!(t.srtt, 200_000 - 12_500);
        assert_eq!(t.rttvar, 200_000 - 25_000);
        assert_eq!(t.timeout, t.srtt + 4 * t.rttvar);
        // Nonsense values are ignored.
        let before = t;
        t.update(9_000_000, &limits, Duration::ZERO);
        t.update(-100_000, &limits, Duration::ZERO);
        assert_eq!(t, before);
    }

    #[test]
    fn timeout_stays_within_limits_and_scan_delay() {
        let limits = RttTimeouts {
            min: ms(50),
            max: ms(300),
            initial: ms(250),
        };
        let mut t = TimeoutInfo::new(&limits);
        t.update(1_000_000, &limits, Duration::ZERO);
        assert_eq!(t.timeout(), ms(300));
        let mut t = TimeoutInfo::new(&limits);
        t.update(1_000, &limits, ms(400));
        assert_eq!(t.timeout(), ms(400));
    }

    #[test]
    fn hosts_borrow_the_group_estimate() {
        let limits = RttTimeouts::default();
        let state = RttState::new();
        let (a, b): (IpAddr, IpAddr) = ("10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap());
        assert_eq!(state.timeout(a, &limits), ms(1000));
        assert_eq!(state.group_timeout(&limits), ms(1000));
        state.observe(a, ms(40), &limits, Duration::ZERO);
        assert_eq!(state.timeout(a, &limits), ms(200));
        // b has not answered: it gets the group's timeout.
        assert_eq!(state.timeout(b, &limits), ms(200));
        assert_eq!(state.group_timeout(&limits), ms(200));
        assert_eq!(state.srtt(a), Some(ms(40)));
        assert_eq!(state.srtt(b), None);
        // Clones share the estimates.
        let other = state.clone();
        other.observe(b, ms(1), &limits, Duration::ZERO);
        assert_eq!(state.timeout(b, &limits), ms(100));
    }

    fn cfg(concurrency: usize, level: u8) -> ScanConfig {
        ScanConfig {
            concurrency,
            timing_level: level,
            ..ScanConfig::default()
        }
    }

    #[test]
    fn min_parallelism_is_the_window_floor() {
        let perf = Perf::for_config(&cfg(500, 3));
        assert_eq!(perf.low_cwnd, 1.0);
        let perf = Perf::for_config(&ScanConfig {
            min_parallelism: 20,
            ..cfg(500, 3)
        });
        assert_eq!(perf.low_cwnd, 20.0);
        // Like nmap's box(low, max, 10), the start is raised to the floor.
        assert_eq!(perf.initial_cwnd, 20.0);
        let mut w = Window::new(&perf);
        w.drop_host(10, &perf, Instant::now());
        assert_eq!(w.cwnd(), 20.0);
    }

    #[test]
    fn window_grows_and_shrinks_like_nmap() {
        let cfg = cfg(500, 3);
        let mut cc = Congestion::new(&cfg, vec![100, 100]);
        let now = Instant::now();
        assert_eq!(cc.host_window(0).cwnd(), 10.0);
        // Slow start: one more per answer.
        for _ in 0..5 {
            cc.sent(0);
            cc.finished_waiting(0);
            cc.adjust(0, now, 0, Outcome::Answered, now);
        }
        assert_eq!(cc.host_window(0).cwnd(), 15.0);
        // Timeouts alone do not move the window ...
        cc.adjust(0, now, 0, Outcome::TimedOut, now);
        assert_eq!(cc.host_window(0).cwnd(), 15.0);
        // ... but make each later answer count for more (cc_scale).
        cc.adjust(0, now, 0, Outcome::Answered, now);
        assert!(cc.host_window(0).cwnd() > 16.0);
        // An answer to a retransmission: the host window falls to one.
        let later = now + ms(10);
        cc.adjust(0, later, 1, Outcome::Answered, later);
        assert!(cc.host_window(0).cwnd() <= 2.0);
        // The rest of that batch does not cut it again.
        let w = cc.host_window(0).cwnd();
        cc.adjust(0, now, 1, Outcome::Answered, later);
        assert!(cc.host_window(0).cwnd() >= w);
        // An ICMP error to a retransmission moves nothing.
        let before = cc.host_window(0);
        cc.adjust(0, later + ms(1), 1, Outcome::FilteredError, later + ms(2));
        assert_eq!(cc.host_window(0), before);
    }

    #[test]
    fn concurrency_caps_the_window() {
        let cfg = cfg(1, 0);
        let mut cc = Congestion::new(&cfg, vec![10]);
        let now = Instant::now();
        assert!(cc.may_send(0, now));
        cc.sent(0);
        assert!(!cc.may_send(0, now));
        cc.finished_waiting(0);
        cc.adjust(0, now, 0, Outcome::Answered, now);
        assert_eq!(cc.host_window(0).cwnd(), 1.0);
    }

    #[test]
    fn min_rate_opens_a_full_window() {
        let mut cfg = cfg(1, 3);
        cfg.min_rate = 1000;
        let mut cc = Congestion::new(&cfg, vec![10]);
        cc.start -= ms(100);
        cc.sent(0);
        // 100 ms at 1000/s wants 100 sent; only 1 was.
        assert!(cc.may_send(0, Instant::now()));
    }

    #[test]
    fn flight_holds_back_a_full_host_and_sends_the_others() {
        let cfg = cfg(500, 3);
        let addrs: Vec<IpAddr> = vec!["10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap()];
        let mut f: Flight<u16> = Flight::new(&cfg, &addrs, vec![20, 6]);
        let now = Instant::now();
        // Host 1 answers five probes: its window and the group's grow to
        // 15, host 0's stays at 10.
        f.start_round(
            (1..=5)
                .map(|p| (1, p))
                .chain((1..=20).map(|p| (0, p)))
                .chain([(1, 6)]),
            0,
        );
        for p in 1..=5 {
            assert_eq!(f.next(now), Next::Send(1, p));
            f.sent(1, p, now);
            f.answered(1, p, now + ms(5), false);
        }
        let mut order = Vec::new();
        while let Next::Send(h, k) = f.next(now) {
            f.sent(h, k, now);
            order.push((h, k));
        }
        // Host 0's window of ten fills; its other probes are held back and
        // host 1 still gets its last one.
        assert_eq!(order.len(), 11);
        assert_eq!(order.last(), Some(&(1, 6)));
        assert!(matches!(f.next(now), Next::Wait(_)));
        // An answer frees a place and grows the window by one more.
        let t = now + ms(5);
        f.answered(0, 1, t, false);
        assert_eq!(f.next(t), Next::Send(0, 11));
        f.sent(0, 11, t);
        assert_eq!(f.next(t), Next::Send(0, 12));
        f.sent(0, 12, t);
        assert!(matches!(f.next(t), Next::Wait(_)));
        // Once the waiting probes time out (the 100 ms minimum, from the
        // 5 ms round trips), the rest can go.
        let later = now + ms(200);
        let mut sent = 0;
        while let Next::Send(h, k) = f.next(later) {
            f.sent(h, k, later);
            sent += 1;
        }
        assert_eq!(sent, 8);
        assert_eq!(f.next(later + ms(500)), Next::Idle);
        assert!(!f.any_waiting());
    }

    #[test]
    fn flight_retires_a_done_host() {
        let cfg = cfg(500, 3);
        let addrs: Vec<IpAddr> = vec!["10.0.0.1".parse().unwrap()];
        let mut f: Flight<u16> = Flight::new(&cfg, &addrs, vec![30]);
        f.start_round((1..=30).map(|p| (0, p)), 0);
        let now = Instant::now();
        while let Next::Send(h, k) = f.next(now) {
            f.sent(h, k, now);
        }
        assert!(f.any_waiting());
        f.retire_host(0);
        assert!(!f.any_waiting());
        assert_eq!(f.congestion().active_total, 0);
        // Its queued probes still come out, for the scan to skip.
        let mut rest = 0;
        while let Next::Send(h, k) = f.next(now) {
            f.settle(h, k);
            rest += 1;
        }
        assert_eq!(rest, 20);
        assert_eq!(f.next(now), Next::Idle);
    }

    #[tokio::test]
    async fn async_window_waits_for_a_free_place() {
        let cfg = cfg(2, 3);
        let w = AsyncWindow::new(&cfg, vec![3]);
        let a = w.acquire(0).await;
        let _b = w.acquire(0).await;
        // The third waits until one finishes.
        let third = w.acquire(0);
        tokio::pin!(third);
        assert!(
            tokio::time::timeout(ms(50), third.as_mut()).await.is_err(),
            "a full window let a probe through"
        );
        a.finish(Instant::now(), 0, Outcome::Answered);
        tokio::time::timeout(ms(500), third)
            .await
            .expect("a finished probe frees its place");
    }
}
