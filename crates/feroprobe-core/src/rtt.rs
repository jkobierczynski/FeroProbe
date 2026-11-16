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

    /// `timeout` kept between the minimum and the maximum, for estimates
    /// made under other limits (a clone of the config with new ones).
    fn clamp(&self, timeout: Duration) -> Duration {
        timeout.min(self.max).max(self.min)
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
    /// else the initial timeout. nmap's `probeTimeout()`. A measured
    /// timeout is boxed into the current limits, then raised to the scan
    /// delay, as nmap's `adjust_timeouts2` does.
    pub fn timeout(&self, addr: IpAddr, limits: &RttTimeouts, scan_delay: Duration) -> Duration {
        let est = self.lock();
        let measured = est
            .hosts
            .get(&addr)
            .filter(|t| t.measured())
            .or(est.group.as_ref().filter(|t| t.measured()));
        Self::limited(measured, limits, scan_delay)
    }

    /// The timeout for a host that has not answered yet: the group's once
    /// any host has, else the initial timeout.
    pub fn group_timeout(&self, limits: &RttTimeouts, scan_delay: Duration) -> Duration {
        let est = self.lock();
        Self::limited(
            est.group.as_ref().filter(|t| t.measured()),
            limits,
            scan_delay,
        )
    }

    fn limited(
        measured: Option<&TimeoutInfo>,
        limits: &RttTimeouts,
        scan_delay: Duration,
    ) -> Duration {
        match measured {
            Some(t) => limits.clamp(t.timeout()).max(scan_delay),
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
        // -c is FeroProbe's (and, as an alias, nmap's --max-parallelism).
        let max_cwnd = cfg.concurrency.max(1);
        // nmap's low_cwnd is --min-parallelism, at least one probe, and
        // never above the maximum.
        let low_cwnd = cfg.min_parallelism.clamp(1, max_cwnd) as f64;
        let max_cwnd = max_cwnd as f64;
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
    /// Each host's resends and delay between probes, adapted to its
    /// losses as in nmap.
    pace: Vec<HostPace>,
    /// `--max-retries`: the highest try number a probe may reach.
    retry_cap: u32,
    /// How far a host's delay may be raised: `--max-scan-delay`.
    max_delay: Duration,
    /// Whether the scan has more than one probe; nmap pauses for rate
    /// limiting only then.
    several: bool,
    /// The first raise of a delay that was zero: 5 ms, or 50 ms for UDP.
    first_boost: Duration,
    /// A host whose answers come only after this many resends gets a
    /// longer delay: 3, or 4 with `-T4` and `-T5`.
    boost_after_tryno: u32,
    /// The share of answers that came only after a resend above which a
    /// host's delay is raised: 30 %, or 40 % with `-T4` and `-T5`.
    drop_ratio: f64,
}

/// nmap's per-host retransmission and send-delay state
/// (`max_successful_tryno` and `sdn`).
#[derive(Debug, Clone, Copy)]
struct HostPace {
    /// The highest try number that drew an answer.
    max_successful_tryno: u32,
    /// The least time between two probes to this host.
    delay: Duration,
    /// When the delay was last raised.
    last_boost: Instant,
    /// Answers to resent probes sent after that, and other answers.
    dropped: u32,
    good: u32,
    /// When the last probe went to this host.
    last_sent: Option<Instant>,
    /// The highest try number sent to this host so far, and until when
    /// the host is paused because a higher one was due: nmap's rate
    /// limit detection (`rld`).
    max_tryno_sent: u32,
    paused_until: Option<Instant>,
}

/// How long a host is paused the first time one of its probes is due for
/// a higher try than any sent before (nmap's `RLD_TIME_MS`): a host that
/// limits its answers' rate gets time to recover before the resends.
const RATE_LIMIT_PAUSE: Duration = Duration::from_secs(1);

impl Congestion {
    /// `work[h]` is how many probes host `h` has to go (first tries).
    pub(crate) fn new(cfg: &ScanConfig, work: Vec<usize>) -> Self {
        let perf = Perf::for_config(cfg);
        let hosts = work.len();
        let now = Instant::now();
        let pace = HostPace {
            max_successful_tryno: 0,
            delay: cfg.scan_delay,
            last_boost: now,
            dropped: 0,
            good: 0,
            last_sent: None,
            max_tryno_sent: 0,
            paused_until: None,
        };
        let fast = cfg.timing_level >= 4;
        Self {
            perf,
            group: Window::new(&perf),
            hosts: vec![Window::new(&perf); hosts],
            active: vec![0; hosts],
            active_total: 0,
            incomplete: work.iter().filter(|&&w| w > 0).count(),
            several: work.iter().sum::<usize>() > 1,
            work,
            min_rate: cfg.min_rate,
            start: now,
            sent: 0,
            pace: vec![pace; hosts],
            retry_cap: cfg.retries,
            max_delay: cfg.max_scan_delay.max(cfg.scan_delay),
            first_boost: Duration::from_millis(5),
            boost_after_tryno: if fast { 4 } else { 3 },
            drop_ratio: if fast { 0.40 } else { 0.30 },
        }
    }

    /// For a UDP scan: its delay starts higher when raised (50 ms) and may
    /// go up to `--max-scan-delay` even with `-T4` and `-T5`, as in nmap.
    pub(crate) fn for_udp(mut self, cfg: &ScanConfig) -> Self {
        self.first_boost = Duration::from_millis(50);
        self.max_delay = cfg.max_udp_scan_delay.max(cfg.scan_delay);
        self
    }

    /// The highest try number (0 for the first send) a probe to host `h`
    /// may reach now: nmap's `allowedTryno`. One resend until a resent
    /// probe draws an answer, then one more than the highest try that
    /// did, up to `--max-retries`.
    pub(crate) fn allowed_tryno(&self, h: usize) -> u32 {
        (self.pace[h].max_successful_tryno + 1).min(self.retry_cap)
    }

    /// When host `h`'s delay between probes, or its pause (see
    /// [`pause_for_try`](Self::pause_for_try)), lets the next probe go, if
    /// it has either.
    pub(crate) fn delay_due(&self, h: usize) -> Option<Instant> {
        let p = &self.pace[h];
        let delay = if p.delay.is_zero() {
            None
        } else {
            p.last_sent.map(|t| t + p.delay)
        };
        delay.max(p.paused_until)
    }

    /// A probe to host `h` is about to go as try `tryno`. The first time
    /// a try that high is due, the host is paused for a second instead,
    /// and this returns true: the probe has to wait. nmap's rate limit
    /// detection, which lets a host that limits its answers' rate (as
    /// many do with RSTs and ICMP errors) recover before the resends,
    /// so their answers do not look like more losses.
    pub(crate) fn pause_for_try(&mut self, h: usize, tryno: u32, now: Instant) -> bool {
        let p = &mut self.pace[h];
        if tryno <= p.max_tryno_sent || !self.several {
            return false;
        }
        p.max_tryno_sent = tryno;
        p.paused_until = Some(now + RATE_LIMIT_PAUSE);
        true
    }

    /// Host `h`'s current delay between probes.
    #[cfg(test)]
    pub(crate) fn host_delay(&self, h: usize) -> Duration {
        self.pace[h].delay
    }

    /// Raise host `h`'s delay: nmap's `boostScanDelay`.
    fn boost(&mut self, h: usize, now: Instant) {
        let second = Duration::from_secs(1);
        let p = &mut self.pace[h];
        if p.delay < second {
            p.delay = if p.delay.is_zero() {
                self.first_boost
            } else {
                (p.delay * 2).min(second)
            };
        }
        p.delay = p.delay.min(self.max_delay);
        p.last_boost = now;
        p.dropped = 0;
        p.good = 0;
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

    /// Whether host `h`'s delay between probes has passed.
    fn delay_passed(&self, h: usize, now: Instant) -> bool {
        self.delay_due(h).is_none_or(|due| now >= due)
    }

    /// Whether a probe to host `h` may go now. A host's delay between
    /// probes holds even `--min-rate` back, to stay gentle with a host
    /// that is losing probes.
    pub(crate) fn may_send(&self, h: usize, now: Instant) -> bool {
        self.delay_passed(h, now)
            && ((self.host_has_room(h) && self.group_has_room()) || self.behind_min_rate(now))
    }

    /// A probe to host `h` went out at `now`.
    pub(crate) fn sent(&mut self, h: usize, now: Instant) {
        self.pace[h].last_sent = Some(now);
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
        self.adjust_pace(h, sent, tryno, outcome != Outcome::TimedOut, now);
    }

    /// nmap's send-delay and retry bookkeeping for one probe. An answer
    /// that came only after a resend means the first copy (or its answer)
    /// was lost. When over 10 such answers make up more than 30 % (40 %
    /// with `-T4` and `-T5`) of the host's answers since its delay last
    /// changed, the delay goes up; it also goes up when the host answers
    /// only after more than 3 (4) resends. Answers to resends also let the
    /// host's probes be resent more times.
    /// Only answers to resends sent since the delay last changed count
    /// against it.
    fn adjust_pace(&mut self, h: usize, sent: Instant, tryno: u32, answered: bool, now: Instant) {
        let p = &mut self.pace[h];
        let dropped = tryno > 0 && answered;
        if dropped && sent > p.last_boost {
            p.dropped += 1;
        } else if answered {
            p.good += 1;
        }
        if p.dropped > 10 && f64::from(p.dropped) / f64::from(p.dropped + p.good) > self.drop_ratio
        {
            self.boost(h, now);
        }
        if answered && tryno > self.pace[h].max_successful_tryno {
            self.pace[h].max_successful_tryno = tryno;
            if tryno > self.boost_after_tryno {
                self.boost(h, now);
            }
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
/// probe times out given the hosts' RTT estimates, which probes to send
/// again, and the bookkeeping for all of it. The scan still does the
/// sending and the receiving.
///
/// First tries go out in the order given to [`start`](Self::start). Like
/// nmap's scan engine, a probe that times out is sent again as soon as
/// its host may send, ahead of first tries, while its host allows another
/// try ([`Congestion::allowed_tryno`]); otherwise it waits on a bench in
/// case the host's allowance grows, and gives up once nothing for that
/// host could make it grow. A probe whose host's window is full is held
/// back, and goes as soon as that host has room, so one slow host does
/// not hold up the others.
pub(crate) struct Flight<K> {
    addrs: Vec<IpAddr>,
    limits: RttTimeouts,
    scan_delay: Duration,
    state: RttState,
    cc: Congestion,
    /// First tries not yet handed out.
    queue: VecDeque<(usize, K)>,
    /// Probes due to be sent again.
    retry: VecDeque<(usize, K)>,
    /// Probes held back by their host's window or delay.
    held: std::collections::BTreeMap<usize, VecDeque<K>>,
    /// Probes not yet handed out (queued, due again or held), per host.
    unsent: Vec<usize>,
    /// Probes out of tries for now, per host, and how many in all.
    bench: Vec<Vec<K>>,
    benched: usize,
    probes: HashMap<(usize, K), Sent>,
    /// When each earlier try of a resent probe went out, to time answers
    /// that name their try.
    earlier: HashMap<(usize, K), Vec<Instant>>,
    settled: std::collections::HashSet<(usize, K)>,
    /// Probes still waiting for an answer, per host.
    waiting: Vec<Vec<K>>,
    /// The hosts with probes waiting, so timing out costs no more than
    /// the probes in flight, however many hosts the scan has.
    busy: std::collections::BTreeSet<usize>,
    /// Hosts that need nothing more (proven up during discovery).
    retired: Vec<bool>,
}

// Used by the raw scans, which are Linux only.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl<K: Copy + Eq + Hash> Flight<K> {
    /// A flight over `addrs`, with `per_host[h]` first-try probes to send
    /// to host `h`.
    pub(crate) fn new(cfg: &ScanConfig, addrs: &[IpAddr], per_host: Vec<usize>) -> Self {
        let hosts = addrs.len();
        Self {
            addrs: addrs.to_vec(),
            limits: cfg.rtt,
            scan_delay: cfg.scan_delay,
            state: cfg.rtt_state.clone(),
            cc: Congestion::new(cfg, per_host),
            queue: VecDeque::new(),
            retry: VecDeque::new(),
            held: std::collections::BTreeMap::new(),
            unsent: vec![0; hosts],
            bench: vec![Vec::new(); hosts],
            benched: 0,
            probes: HashMap::new(),
            earlier: HashMap::new(),
            settled: std::collections::HashSet::new(),
            waiting: vec![Vec::new(); hosts],
            busy: std::collections::BTreeSet::new(),
            retired: vec![false; hosts],
        }
    }

    /// Queue the first tries, in sending order.
    pub(crate) fn start(&mut self, probes: impl IntoIterator<Item = (usize, K)>) {
        for (h, k) in probes {
            self.unsent[h] += 1;
            self.queue.push_back((h, k));
        }
    }

    /// Whether probe `(h, k)` has been sent before, so sending it now is
    /// a resend.
    pub(crate) fn is_resend(&self, h: usize, k: K) -> bool {
        self.probes.contains_key(&(h, k))
    }

    /// The timeout for a probe to host `h` now.
    pub(crate) fn timeout(&self, h: usize) -> Duration {
        self.state
            .timeout(self.addrs[h], &self.limits, self.scan_delay)
    }

    /// Time out the waiting probes whose time is up, and line up their
    /// resends.
    pub(crate) fn expire(&mut self, now: Instant) {
        let busy: Vec<usize> = self.busy.iter().copied().collect();
        for h in busy {
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
                    self.timed_out(h, k, tryno);
                } else {
                    i += 1;
                }
            }
            self.sync_busy(h);
            self.tidy(h);
        }
    }

    /// Probe `(h, k)`, sent as try `tryno`, timed out: send it again if
    /// its host allows another try, else bench it.
    fn timed_out(&mut self, h: usize, k: K, tryno: u32) {
        if self.retired[h] || self.settled.contains(&(h, k)) {
            return;
        }
        if tryno < self.cc.allowed_tryno(h) {
            self.unsent[h] += 1;
            self.retry.push_back((h, k));
        } else {
            self.bench[h].push(k);
            self.benched += 1;
        }
    }

    /// Host `h`'s bench: back in line once its allowance has grown past
    /// a benched probe's try, given up once nothing could make it grow
    /// (no probe of the host is waiting or unsent). nmap's
    /// `retransmitBench` and `dismissBench`.
    fn tidy(&mut self, h: usize) {
        if self.bench[h].is_empty() {
            return;
        }
        let allowed = self.cc.allowed_tryno(h);
        let bench = std::mem::take(&mut self.bench[h]);
        self.benched -= bench.len();
        for k in bench {
            let tryno = self.probes[&(h, k)].tryno;
            if self.settled.contains(&(h, k)) {
                continue;
            }
            if tryno < allowed {
                self.unsent[h] += 1;
                self.retry.push_back((h, k));
            } else {
                self.bench[h].push(k);
                self.benched += 1;
            }
        }
        if self.waiting[h].is_empty() && self.unsent[h] == 0 {
            let bench = std::mem::take(&mut self.bench[h]);
            self.benched -= bench.len();
            for k in bench {
                self.settle(h, k);
            }
        }
    }

    /// Keep [`busy`](Self::busy) in step with host `h`'s waiting list.
    fn sync_busy(&mut self, h: usize) {
        if self.waiting[h].is_empty() {
            self.busy.remove(&h);
        } else {
            self.busy.insert(h);
        }
    }

    /// When the next waiting probe times out.
    pub(crate) fn next_expiry(&self) -> Option<Instant> {
        self.busy
            .iter()
            .filter_map(|&h| {
                let timeout = self.timeout(h);
                self.waiting[h]
                    .iter()
                    .map(|k| self.probes[&(h, *k)].at + timeout)
                    .min()
            })
            .min()
    }

    /// Whether any probe is still waiting for its answer.
    #[cfg(test)]
    pub(crate) fn any_waiting(&self) -> bool {
        !self.busy.is_empty()
    }

    /// Whether resending probe `(h, k)` has to wait for its host's pause
    /// first (see [`Congestion::pause_for_try`]).
    fn pauses(&mut self, h: usize, k: K, now: Instant) -> bool {
        match self.probes.get(&(h, k)) {
            Some(p) => self.cc.pause_for_try(h, p.tryno + 1, now),
            None => false,
        }
    }

    /// Hold back resend `(h, k)` while its host may not send: behind the
    /// host's other held resends, ahead of its held first tries.
    fn hold_resend(&mut self, h: usize, k: K) {
        let q = self.held.entry(h).or_default();
        let probes = &self.probes;
        let at = q
            .iter()
            .position(|x| !probes.contains_key(&(h, *x)))
            .unwrap_or(q.len());
        q.insert(at, k);
    }

    /// Hand out probe `(h, k)`: it is no longer unsent.
    fn hand_out(&mut self, h: usize, k: K) -> Next<K> {
        self.unsent[h] -= 1;
        Next::Send(h, k)
    }

    /// The next probe to send, after timing out the probes whose time is
    /// up: resends first, as in nmap, then held probes, then first tries.
    /// `Wait` gives the moment something can change on its own (a
    /// timeout, a host's delay or pause, or `--min-rate`); an answer can
    /// change it sooner. `Idle` means every probe is settled.
    pub(crate) fn next(&mut self, now: Instant) -> Next<K> {
        self.expire(now);
        // Resends first: a host that loses probes gets its losses made up
        // before it is sent more.
        while let Some(&(h, k)) = self.retry.front() {
            self.retry.pop_front();
            if self.settled.contains(&(h, k)) {
                self.unsent[h] -= 1;
                self.tidy(h);
                continue;
            }
            if self.cc.may_send(h, now) && !self.pauses(h, k, now) {
                return self.hand_out(h, k);
            }
            self.hold_resend(h, k);
            if !self.cc.group_has_room() && !self.cc.behind_min_rate(now) {
                break;
            }
        }
        // Then held probes: they have waited longest.
        if self.cc.group_has_room() || self.cc.behind_min_rate(now) {
            loop {
                let ready = self
                    .held
                    .iter()
                    .find(|(h, q)| !q.is_empty() && self.cc.may_send(**h, now))
                    .map(|(h, _)| *h);
                let Some(h) = ready else { break };
                let q = self.held.get_mut(&h).expect("ready host is held");
                let k = q.pop_front().expect("ready queue is not empty");
                if q.is_empty() {
                    self.held.remove(&h);
                }
                if self.settled.contains(&(h, k)) {
                    self.unsent[h] -= 1;
                    self.tidy(h);
                    continue;
                }
                if self.pauses(h, k, now) {
                    self.held.entry(h).or_default().push_front(k);
                    continue;
                }
                return self.hand_out(h, k);
            }
        }
        // Then first tries.
        while let Some(&(h, k)) = self.queue.front() {
            if self.cc.may_send(h, now) {
                self.queue.pop_front();
                return self.hand_out(h, k);
            }
            if !self.cc.group_has_room() && !self.cc.behind_min_rate(now) {
                break;
            }
            // Only this host is held back: hold its probe, try the next.
            self.queue.pop_front();
            self.held.entry(h).or_default().push_back(k);
        }
        if self.queue.is_empty()
            && self.retry.is_empty()
            && self.held.is_empty()
            && self.busy.is_empty()
            && self.benched == 0
        {
            return Next::Idle;
        }
        let soon = now + crate::timing::CANCEL_POLL;
        // A host held back only by its delay between probes is free again
        // when the delay has passed.
        let delays = self
            .held
            .keys()
            .copied()
            .chain(self.queue.front().map(|&(h, _)| h))
            .chain(self.retry.front().map(|&(h, _)| h))
            .filter_map(|h| self.cc.delay_due(h))
            .min();
        let due = [self.next_expiry(), self.cc.min_rate_due(), delays]
            .into_iter()
            .flatten()
            .min()
            .unwrap_or(soon);
        Next::Wait(due.max(now))
    }

    /// The highest try number a probe to host `h` may reach now (see
    /// [`Congestion::allowed_tryno`]).
    #[cfg(test)]
    pub(crate) fn allowed_tryno(&self, h: usize) -> u32 {
        self.cc.allowed_tryno(h)
    }

    /// The try number of probe `(h, k)`'s latest send (0 for the first).
    pub(crate) fn tryno(&self, h: usize, k: K) -> u32 {
        self.probes.get(&(h, k)).map_or(0, |p| p.tryno)
    }

    /// Probe `(h, k)` went out at `at`: its first try, or one more.
    pub(crate) fn sent(&mut self, h: usize, k: K, at: Instant) {
        let tryno = match self.probes.get(&(h, k)) {
            Some(old) => {
                if old.waiting {
                    // Sent again while the earlier copy still waits: one entry.
                    self.waiting[h].retain(|x| *x != k);
                    self.cc.finished_waiting(h);
                }
                let (prev, tryno) = (old.at, old.tryno + 1);
                self.earlier.entry((h, k)).or_default().push(prev);
                tryno
            }
            None => 0,
        };
        self.probes.insert(
            (h, k),
            Sent {
                at,
                tryno,
                waiting: true,
            },
        );
        self.waiting[h].push(k);
        self.busy.insert(h);
        self.cc.sent(h, at);
    }

    /// Probe `(h, k)` will not be sent again (answered, unreachable, or
    /// its host is done): it no longer counts as work left.
    pub(crate) fn settle(&mut self, h: usize, k: K) {
        if let Some(p) = self.probes.get_mut(&(h, k))
            && p.waiting
        {
            p.waiting = false;
            self.waiting[h].retain(|x| *x != k);
            self.sync_busy(h);
            self.cc.finished_waiting(h);
        }
        if self.settled.insert((h, k)) {
            self.cc.settled(h);
        }
        self.tidy(h);
    }

    /// The first answer to probe `(h, k)` came in at `at`: measure its
    /// round trip, move the windows and settle the probe. `filtered_error`
    /// marks an ICMP error in a scan where silence means filtered.
    /// `answers_try` is the try the answer names, when the probes carry
    /// their try number (the raw TCP scans); else the latest is assumed.
    /// Returns the round-trip time, if that try was sent.
    pub(crate) fn answered(
        &mut self,
        h: usize,
        k: K,
        at: Instant,
        filtered_error: bool,
        answers_try: Option<u32>,
    ) -> Option<Duration> {
        let p = *self.probes.get(&(h, k))?;
        let (tryno, sent_at) = match answers_try {
            None => (p.tryno, p.at),
            Some(t) if t == p.tryno => (t, p.at),
            Some(t) if t < p.tryno => (t, *self.earlier.get(&(h, k))?.get(t as usize)?),
            Some(_) => return None,
        };
        let rtt = at.saturating_duration_since(sent_at);
        // Without try numbers, an answer to a resent probe may belong to an
        // earlier copy: only first tries are timed then (Karn's rule). With
        // them every answer is timed, as in nmap.
        if answers_try.is_some() || tryno == 0 {
            self.state
                .observe(self.addrs[h], rtt, &self.limits, self.scan_delay);
        }
        if p.waiting {
            self.probes
                .get_mut(&(h, k))
                .expect("probe is known")
                .waiting = false;
            self.waiting[h].retain(|x| *x != k);
            self.sync_busy(h);
            self.cc.finished_waiting(h);
        }
        let outcome = if filtered_error {
            Outcome::FilteredError
        } else {
            Outcome::Answered
        };
        self.cc.adjust(h, sent_at, tryno, outcome, at);
        if self.settled.insert((h, k)) {
            self.cc.settled(h);
        }
        // The answer may have let the host's benched probes try again.
        self.tidy(h);
        Some(rtt)
    }

    /// Stop waiting for host `h`'s probes and resending them: it needs
    /// nothing more (proven up during discovery). Its first tries still
    /// queued come out of [`next`](Self::next) as usual, for the scan to
    /// skip and settle.
    pub(crate) fn retire_host(&mut self, h: usize) {
        self.retired[h] = true;
        for k in std::mem::take(&mut self.waiting[h]) {
            if let Some(p) = self.probes.get_mut(&(h, k)) {
                p.waiting = false;
            }
            self.cc.finished_waiting(h);
        }
        self.busy.remove(&h);
        let mut give_up: Vec<K> = std::mem::take(&mut self.bench[h]);
        self.benched -= give_up.len();
        let before = self.retry.len();
        self.retry.retain(|&(x, k)| {
            if x == h {
                give_up.push(k);
            }
            x != h
        });
        self.unsent[h] -= before - self.retry.len();
        if let Some(q) = self.held.get_mut(&h) {
            let probes = &self.probes;
            let held_before = q.len();
            q.retain(|k| {
                let resend = probes.contains_key(&(h, *k));
                if resend {
                    give_up.push(*k);
                }
                !resend
            });
            self.unsent[h] -= held_before - q.len();
            if q.is_empty() {
                self.held.remove(&h);
            }
        }
        for k in give_up {
            self.settle(h, k);
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
    /// Hosts whose probes need not go any more (proven up during host
    /// discovery): checked whenever a probe gets its turn.
    skip: Option<SkipHost>,
}

type SkipHost = Box<dyn Fn(usize) -> bool + Send + Sync>;

impl AsyncWindow {
    /// `per_host[h]` is how many probes host `h` has.
    pub(crate) fn new(cfg: &ScanConfig, per_host: Vec<usize>) -> Self {
        Self {
            cc: Mutex::new(Congestion::new(cfg, per_host)),
            changed: tokio::sync::Notify::new(),
            skip: None,
        }
    }

    /// Skip the probes of every host `h` for which `skip(h)` holds by the
    /// time they get their turn: [`acquire`](Self::acquire) then returns
    /// `None` and nothing is sent.
    pub(crate) fn with_skip(
        mut self,
        skip: impl Fn(usize) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.skip = Some(Box::new(skip));
        self
    }

    /// For a UDP scan (see [`Congestion::for_udp`]).
    pub(crate) fn for_udp(self, cfg: &ScanConfig) -> Self {
        let cc = self.cc.into_inner().unwrap_or_else(|e| e.into_inner());
        Self {
            cc: Mutex::new(cc.for_udp(cfg)),
            ..self
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Congestion> {
        self.cc.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The highest try number a probe to host `h` may reach now (see
    /// [`Congestion::allowed_tryno`]).
    pub(crate) fn allowed_tryno(&self, h: usize) -> u32 {
        self.lock().allowed_tryno(h)
    }

    /// Wait until try `tryno` (0 for the first) of a probe to host `h` may
    /// go, and count it as sent. `None` when the host's probes are to be
    /// skipped (see [`with_skip`](Self::with_skip)).
    pub(crate) async fn acquire(&self, h: usize, tryno: u32) -> Option<Slot<'_>> {
        loop {
            if self.skip.as_ref().is_some_and(|skip| skip(h)) {
                return None;
            }
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let due = {
                let mut cc = self.lock();
                let now = Instant::now();
                // A first resend this high pauses the host first.
                let paused = cc.pause_for_try(h, tryno, now);
                if !paused && cc.may_send(h, now) {
                    cc.sent(h, now);
                    return Some(Slot {
                        window: self,
                        h,
                        done: false,
                    });
                }
                // Wake for --min-rate or the host's delay between probes,
                // whichever comes first; answers wake it sooner.
                [cc.min_rate_due(), cc.delay_due(h)]
                    .into_iter()
                    .flatten()
                    .min()
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
        assert_eq!(state.timeout(a, &limits, Duration::ZERO), ms(1000));
        assert_eq!(state.group_timeout(&limits, Duration::ZERO), ms(1000));
        state.observe(a, ms(40), &limits, Duration::ZERO);
        assert_eq!(state.timeout(a, &limits, Duration::ZERO), ms(200));
        // b has not answered: it gets the group's timeout.
        assert_eq!(state.timeout(b, &limits, Duration::ZERO), ms(200));
        assert_eq!(state.group_timeout(&limits, Duration::ZERO), ms(200));
        assert_eq!(state.srtt(a), Some(ms(40)));
        assert_eq!(state.srtt(b), None);
        // Clones share the estimates.
        let other = state.clone();
        other.observe(b, ms(1), &limits, Duration::ZERO);
        assert_eq!(state.timeout(b, &limits, Duration::ZERO), ms(100));
    }

    #[test]
    fn cached_timeouts_follow_the_current_limits() {
        let state = RttState::new();
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        state.observe(a, ms(40), &RttTimeouts::default(), Duration::ZERO);
        assert_eq!(
            state.timeout(a, &RttTimeouts::default(), Duration::ZERO),
            ms(200)
        );
        let fixed = RttTimeouts::fixed(ms(800));
        assert_eq!(state.timeout(a, &fixed, Duration::ZERO), ms(800));
        assert_eq!(state.group_timeout(&fixed, Duration::ZERO), ms(800));
    }

    #[test]
    fn answers_to_resent_probes_are_not_timed() {
        let cfg = cfg(500, 3);
        let addrs: Vec<IpAddr> = vec!["10.0.0.1".parse().unwrap()];
        let mut f: Flight<u16> = Flight::new(&cfg, &addrs, vec![1]);
        let now = Instant::now();
        f.start([(0, 80)]);
        assert_eq!(f.next(now), Next::Send(0, 80));
        f.sent(0, 80, now);
        // It times out (1 s initial timeout) and goes again.
        let again = now + ms(1500);
        assert_eq!(f.next(again), Next::Send(0, 80));
        assert!(f.is_resend(0, 80));
        f.sent(0, 80, again);
        assert_eq!(f.answered(0, 80, again + ms(3), false, None), Some(ms(3)));
        assert_eq!(cfg.rtt_state.srtt(addrs[0]), None);
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
        // A floor above the maximum (a host job's share) stays within it.
        let perf = Perf::for_config(&ScanConfig {
            min_parallelism: 32,
            ..cfg(1, 3)
        });
        assert_eq!(
            (perf.low_cwnd, perf.max_cwnd, perf.initial_cwnd),
            (1.0, 1.0, 1.0)
        );
    }

    #[test]
    fn resends_grow_with_answered_resends_like_nmap() {
        let now = Instant::now();
        let mut cc = Congestion::new(&cfg(500, 3), vec![100, 100]);
        // One resend until a resend is answered.
        assert_eq!(cc.allowed_tryno(0), 1);
        cc.adjust(0, now, 0, Outcome::Answered, now);
        cc.adjust(0, now, 0, Outcome::TimedOut, now);
        assert_eq!(cc.allowed_tryno(0), 1);
        // An answer to try 1: up to try 2, for this host only.
        cc.adjust(0, now, 1, Outcome::Answered, now);
        assert_eq!((cc.allowed_tryno(0), cc.allowed_tryno(1)), (2, 1));
        // Timeouts and ICMP errors to resends (filtered scans) do not count.
        cc.adjust(0, now, 2, Outcome::TimedOut, now);
        cc.adjust(0, now, 2, Outcome::FilteredError, now);
        assert_eq!(cc.allowed_tryno(0), 2);
        // Never past --max-retries.
        for tryno in 2..20 {
            cc.adjust(0, now, tryno, Outcome::Answered, now);
        }
        assert_eq!(cc.allowed_tryno(0), 10);
        let capped = ScanConfig {
            retries: 0,
            ..cfg(500, 3)
        };
        assert_eq!(Congestion::new(&capped, vec![1]).allowed_tryno(0), 0);
    }

    #[test]
    fn late_answers_raise_the_delay_like_nmap() {
        let ms = Duration::from_millis;
        let start = Instant::now();
        let later = start + ms(1);
        let mut cc = Congestion::new(&cfg(500, 3), vec![100]);
        assert_eq!(cc.host_delay(0), Duration::ZERO);
        // Answers after 1, 2 and 3 resends: no delay yet.
        for tryno in 1..=3 {
            cc.adjust(0, later, tryno, Outcome::Answered, later);
        }
        assert_eq!(cc.host_delay(0), Duration::ZERO);
        // After 4 (more than 3 at -T3): 5 ms.
        cc.adjust(0, later, 4, Outcome::Answered, later);
        assert_eq!(cc.host_delay(0), ms(5));
        // -T4 waits for more than 4.
        let mut fast = Congestion::new(&cfg(500, 4), vec![100]);
        fast.adjust(0, later, 4, Outcome::Answered, later);
        assert_eq!(fast.host_delay(0), Duration::ZERO);
        fast.adjust(0, later, 5, Outcome::Answered, later);
        assert_eq!(fast.host_delay(0), ms(5));
        // But -T4 caps TCP delays at 10 ms.
        let t4 = crate::timing::Timing::Aggressive.config();
        let mut fast = Congestion::new(&t4, vec![100]);
        for _ in 0..5 {
            fast.boost(0, later);
        }
        assert_eq!(fast.host_delay(0), ms(10));
        // UDP starts at 50 ms and keeps the 1 s cap even at -T4.
        let mut udp = Congestion::new(&t4, vec![100]).for_udp(&t4);
        udp.boost(0, later);
        assert_eq!(udp.host_delay(0), ms(50));
        for _ in 0..10 {
            udp.boost(0, later);
        }
        assert_eq!(udp.host_delay(0), ms(1000));
    }

    #[test]
    fn many_resent_answers_raise_the_delay() {
        let ms = Duration::from_millis;
        let start = Instant::now();
        let mut cc = Congestion::new(&cfg(500, 3), vec![1000]);
        let at = |n: u64| start + ms(n);
        // 10 answers to resends are not enough...
        for n in 1..=10 {
            cc.adjust(0, at(n), 1, Outcome::Answered, at(n));
        }
        assert_eq!(cc.host_delay(0), Duration::ZERO);
        // ... the 11th, at over 30 % of answers, is.
        cc.adjust(0, at(11), 1, Outcome::Answered, at(11));
        assert_eq!(cc.host_delay(0), ms(5));
        // The count starts over. Answers to probes sent before the raise
        // count as good ones, and plenty of good answers keep the ratio
        // under 30 %.
        for n in 1..=30 {
            cc.adjust(0, at(n), 0, Outcome::Answered, at(20 + n));
        }
        for n in 12..=23 {
            cc.adjust(0, at(n), 1, Outcome::Answered, at(60 + n));
        }
        assert_eq!(cc.host_delay(0), ms(5));
        // Then the ratio passes 30 %: doubled.
        for n in 24..=40 {
            cc.adjust(0, at(n), 1, Outcome::Answered, at(100 + n));
        }
        assert_eq!(cc.host_delay(0), ms(10));
    }

    #[test]
    fn the_delay_holds_probes_back_and_starts_at_scan_delay() {
        let ms = Duration::from_millis;
        let now = Instant::now();
        let gentle = ScanConfig {
            scan_delay: ms(200),
            max_scan_delay: ms(10),
            ..cfg(500, 3)
        };
        let mut cc = Congestion::new(&gentle, vec![10, 10]);
        assert_eq!(cc.host_delay(0), ms(200));
        assert!(cc.may_send(0, now));
        cc.sent(0, now);
        assert!(!cc.may_send(0, now + ms(100)), "sent within the delay");
        assert!(cc.may_send(1, now + ms(100)), "the delay is per host");
        assert_eq!(cc.delay_due(0), Some(now + ms(200)));
        assert!(cc.may_send(0, now + ms(200)));
        // --scan-delay above --max-scan-delay raises the cap to itself, so
        // a raise leaves it there, and never takes it lower.
        cc.boost(0, now);
        assert_eq!(cc.host_delay(0), ms(200));
        // Even --min-rate waits for it.
        let rushed = ScanConfig {
            min_rate: 1_000_000,
            ..gentle
        };
        let mut cc = Congestion::new(&rushed, vec![10]);
        cc.sent(0, now);
        assert!(!cc.may_send(0, now + ms(100)));
    }

    #[test]
    fn flight_resends_only_what_the_host_allows() {
        let ms = Duration::from_millis;
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        let cfg = ScanConfig {
            rtt: RttTimeouts::fixed(ms(100)),
            ..cfg(500, 3)
        };
        let mut f: Flight<u16> = Flight::new(&cfg, &[a, b], vec![2, 2]);
        let t0 = Instant::now();
        f.start([(0, 1), (0, 2), (1, 1), (1, 2)]);
        let send_all = |f: &mut Flight<u16>, t: Instant| {
            let mut out = Vec::new();
            while let Next::Send(h, k) = f.next(t) {
                f.sent(h, k, t);
                out.push((h, k));
            }
            out
        };
        assert_eq!(send_all(&mut f, t0).len(), 4);
        // All four time out. The first resends wait out each host's pause,
        // then go.
        let t1 = t0 + ms(150);
        assert_eq!(send_all(&mut f, t1), vec![]);
        let t1 = t1 + RATE_LIMIT_PAUSE;
        assert_eq!(send_all(&mut f, t1), vec![(0, 1), (0, 2), (1, 1), (1, 2)]);
        // Host 0 answers a resend: it may now resend a second time.
        f.answered(0, 1, t1 + ms(5), false, None);
        assert_eq!(f.allowed_tryno(0), 2);
        assert_eq!(f.allowed_tryno(1), 1);
        // So its other probe goes a third time, after another pause; host
        // 1's give up.
        let t2 = t1 + ms(150);
        assert_eq!(send_all(&mut f, t2), vec![]);
        assert!(f.settled.contains(&(1, 1)) && f.settled.contains(&(1, 2)));
        let t2 = t2 + RATE_LIMIT_PAUSE;
        assert_eq!(send_all(&mut f, t2), vec![(0, 2)]);
        // That one times out too, and the scan is over.
        assert_eq!(f.next(t2 + ms(150)), Next::Idle);
    }

    #[test]
    fn flight_resends_a_benched_probe_when_the_host_allows_more() {
        let ms = Duration::from_millis;
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let cfg = ScanConfig {
            rtt: RttTimeouts::fixed(ms(100)),
            ..cfg(500, 3)
        };
        let mut f: Flight<u16> = Flight::new(&cfg, &[a], vec![2]);
        let t0 = Instant::now();
        f.start([(0, 1), (0, 2)]);
        for k in [1, 2] {
            assert_eq!(f.next(t0), Next::Send(0, k));
            f.sent(0, k, t0);
        }
        // Both go again after the host's pause, port 2 a little later.
        assert!(matches!(f.next(t0 + ms(150)), Next::Wait(_)));
        let t1 = t0 + ms(150) + RATE_LIMIT_PAUSE;
        assert_eq!(f.next(t1), Next::Send(0, 1));
        f.sent(0, 1, t1);
        assert_eq!(f.next(t1 + ms(50)), Next::Send(0, 2));
        f.sent(0, 2, t1 + ms(50));
        // Port 1's resend times out: one resend is all it may have, so it
        // waits on the bench while port 2's resend is still out.
        assert!(matches!(f.next(t1 + ms(120)), Next::Wait(_)));
        assert!(!f.settled.contains(&(0, 1)));
        // Port 2's resend is answered: the host loses packets, so port 1
        // goes a third time, after a pause for the new try.
        f.answered(0, 2, t1 + ms(130), false, None);
        assert!(matches!(f.next(t1 + ms(130)), Next::Wait(_)));
        assert_eq!(f.next(t1 + ms(130) + RATE_LIMIT_PAUSE), Next::Send(0, 1));
    }

    #[test]
    fn resends_go_before_first_tries_after_a_pause() {
        let ms = Duration::from_millis;
        let cfg = ScanConfig {
            rtt: RttTimeouts::fixed(ms(100)),
            ..cfg(2, 3)
        };
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let mut f: Flight<u16> = Flight::new(&cfg, &[a], vec![4]);
        let t0 = Instant::now();
        f.start([(0, 1), (0, 2), (0, 3), (0, 4)]);
        // A window of two: ports 1 and 2 go.
        for k in [1, 2] {
            assert_eq!(f.next(t0), Next::Send(0, k));
            f.sent(0, k, t0);
        }
        // Both time out. The host is paused for a second before the first
        // resend, so a host that limits its answers' rate can recover;
        // nothing goes then, not even a first try.
        let t1 = t0 + ms(150);
        let Next::Wait(until) = f.next(t1) else {
            panic!("the host should be paused");
        };
        assert_eq!(until, t1 + RATE_LIMIT_PAUSE);
        // Then the resends go first, in order, before ports 3 and 4.
        let t2 = t1 + RATE_LIMIT_PAUSE;
        assert_eq!(f.next(t2), Next::Send(0, 1));
        f.sent(0, 1, t2);
        assert_eq!(f.next(t2), Next::Send(0, 2));
        assert!(f.is_resend(0, 2));
    }

    #[test]
    fn a_single_probe_is_resent_without_a_pause() {
        let ms = Duration::from_millis;
        let cfg = ScanConfig {
            rtt: RttTimeouts::fixed(ms(100)),
            ..cfg(500, 3)
        };
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let mut f: Flight<u16> = Flight::new(&cfg, &[a], vec![1]);
        let t0 = Instant::now();
        f.start([(0, 80)]);
        assert_eq!(f.next(t0), Next::Send(0, 80));
        f.sent(0, 80, t0);
        assert_eq!(f.next(t0 + ms(150)), Next::Send(0, 80));
    }

    #[test]
    fn answers_naming_their_try_are_timed_from_that_try() {
        let ms = Duration::from_millis;
        let cfg = ScanConfig {
            rtt: RttTimeouts::fixed(ms(100)),
            ..cfg(500, 3)
        };
        let addrs: Vec<IpAddr> = vec!["10.0.0.1".parse().unwrap()];
        let mut f: Flight<u16> = Flight::new(&cfg, &addrs, vec![1]);
        let t0 = Instant::now();
        f.start([(0, 80)]);
        assert_eq!(f.next(t0), Next::Send(0, 80));
        f.sent(0, 80, t0);
        let t1 = t0 + ms(150);
        assert_eq!(f.next(t1), Next::Send(0, 80));
        f.sent(0, 80, t1);
        assert_eq!(f.tryno(0, 80), 1);
        // A try that was never sent is no answer.
        assert_eq!(f.answered(0, 80, t1 + ms(10), false, Some(2)), None);
        // The first copy's late answer: timed from the first send, and no
        // loss, so the host's resends do not grow.
        assert_eq!(
            f.answered(0, 80, t1 + ms(10), false, Some(0)),
            Some(ms(160))
        );
        assert_eq!(cfg.rtt_state.srtt(addrs[0]), Some(ms(160)));
        assert_eq!(f.allowed_tryno(0), 1);
    }

    #[test]
    fn flight_waits_out_a_hosts_delay() {
        let ms = Duration::from_millis;
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let cfg = ScanConfig {
            scan_delay: ms(50),
            ..cfg(500, 3)
        };
        let mut f: Flight<u16> = Flight::new(&cfg, &[a], vec![2]);
        let t0 = Instant::now();
        f.start([(0, 1), (0, 2)]);
        assert_eq!(f.next(t0), Next::Send(0, 1));
        f.sent(0, 1, t0);
        assert_eq!(f.next(t0 + ms(10)), Next::Wait(t0 + ms(50)));
        assert_eq!(f.next(t0 + ms(50)), Next::Send(0, 2));
    }

    #[test]
    fn window_grows_and_shrinks_like_nmap() {
        let cfg = cfg(500, 3);
        let mut cc = Congestion::new(&cfg, vec![100, 100]);
        let now = Instant::now();
        assert_eq!(cc.host_window(0).cwnd(), 10.0);
        // Slow start: one more per answer.
        for _ in 0..5 {
            cc.sent(0, Instant::now());
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
        cc.sent(0, Instant::now());
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
        cc.sent(0, Instant::now());
        // 100 ms at 1000/s wants 100 sent; only 1 was.
        assert!(cc.may_send(0, Instant::now()));
    }

    #[test]
    fn flight_holds_back_a_full_host_and_sends_the_others() {
        // No resends, to follow the first tries alone.
        let cfg = ScanConfig {
            retries: 0,
            ..cfg(500, 3)
        };
        let addrs: Vec<IpAddr> = vec!["10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap()];
        let mut f: Flight<u16> = Flight::new(&cfg, &addrs, vec![20, 6]);
        let now = Instant::now();
        // Host 1 answers five probes: its window and the group's grow to
        // 15, host 0's stays at 10.
        f.start(
            (1..=5)
                .map(|p| (1, p))
                .chain((1..=20).map(|p| (0, p)))
                .chain([(1, 6)]),
        );
        for p in 1..=5 {
            assert_eq!(f.next(now), Next::Send(1, p));
            f.sent(1, p, now);
            f.answered(1, p, now + ms(5), false, None);
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
        f.answered(0, 1, t, false, None);
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
        f.start((1..=30).map(|p| (0, p)));
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
        let a = w.acquire(0, 0).await.unwrap();
        let _b = w.acquire(0, 0).await.unwrap();
        // The third waits until one finishes.
        let third = w.acquire(0, 0);
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

    #[tokio::test]
    async fn async_window_skips_finished_hosts() {
        let cfg = cfg(1, 3);
        let up = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = up.clone();
        let w = AsyncWindow::new(&cfg, vec![3])
            .with_skip(move |_| flag.load(std::sync::atomic::Ordering::Relaxed));
        let a = w.acquire(0, 0).await.unwrap();
        // The second waits for the full window; meanwhile the host is
        // proven up, so when a place frees it is not sent.
        let second = w.acquire(0, 0);
        tokio::pin!(second);
        assert!(tokio::time::timeout(ms(50), second.as_mut()).await.is_err());
        up.store(true, std::sync::atomic::Ordering::Relaxed);
        a.finish(Instant::now(), 0, Outcome::Answered);
        let got = tokio::time::timeout(ms(500), second).await.unwrap();
        assert!(got.is_none(), "a probe went to a host already up");
    }

    #[test]
    fn scan_delay_floors_a_measured_timeout() {
        let state = RttState::new();
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let limits = RttTimeouts {
            min: ms(100),
            max: ms(1250),
            initial: ms(500),
        };
        state.observe(a, ms(40), &limits, ms(2000));
        assert_eq!(state.timeout(a, &limits, ms(2000)), ms(2000));
        assert_eq!(state.group_timeout(&limits, ms(2000)), ms(2000));
        let cfg = ScanConfig {
            rtt: limits,
            rtt_state: state,
            scan_delay: ms(2000),
            ..ScanConfig::default()
        };
        assert_eq!(cfg.probe_timeout(a), ms(2000));
    }
}
