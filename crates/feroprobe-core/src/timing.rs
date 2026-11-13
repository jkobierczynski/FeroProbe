//! Timing templates (`-T0` to `-T5`) and probe spacing.
//!
//! Like nmap's templates, each one is a bundle of the existing knobs:
//! per-probe timeout, retries, parallelism, packet rate and a minimum delay
//! between probes. Flags given explicitly on the command line override the
//! template's value for that knob.

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use crate::model::ScanConfig;

/// nmap-style timing template, from slowest and stealthiest to fastest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Timing {
    /// `-T0`: one probe at a time, five minutes apart (IDS evasion)
    Paranoid,
    /// `-T1`: one probe at a time, 15 seconds apart
    Sneaky,
    /// `-T2`: few probes in flight, 0.4 s apart, to spare the network and target
    Polite,
    /// `-T3`: the defaults
    #[default]
    Normal,
    /// `-T4`: shorter timeouts and more parallelism, for fast, reliable networks
    Aggressive,
    /// `-T5`: as fast as possible, trading accuracy for speed
    Insane,
}

/// The lowest timeout a template may set on Windows, which reports a refused
/// connection only about two seconds after the reset arrives.
const WINDOWS_MIN_TIMEOUT: Duration = Duration::from_millis(3000);

impl Timing {
    pub const ALL: [Timing; 6] = [
        Timing::Paranoid,
        Timing::Sneaky,
        Timing::Polite,
        Timing::Normal,
        Timing::Aggressive,
        Timing::Insane,
    ];

    /// The template's number, 0 to 5.
    pub fn level(self) -> u8 {
        self as u8
    }

    pub fn name(self) -> &'static str {
        match self {
            Timing::Paranoid => "paranoid",
            Timing::Sneaky => "sneaky",
            Timing::Polite => "polite",
            Timing::Normal => "normal",
            Timing::Aggressive => "aggressive",
            Timing::Insane => "insane",
        }
    }

    /// The scan settings this template stands for.
    pub fn config(self) -> ScanConfig {
        let ms = Duration::from_millis;
        let (timeout, retries, concurrency, max_rate, scan_delay) = match self {
            Timing::Paranoid => (ms(5000), 2, 1, 1, Duration::from_secs(300)),
            Timing::Sneaky => (ms(5000), 2, 1, 1, Duration::from_secs(15)),
            Timing::Polite => (ms(3000), 2, 10, 100, ms(400)),
            Timing::Normal => return ScanConfig::default(),
            Timing::Aggressive => (ms(1000), 1, 1000, 10_000, Duration::ZERO),
            Timing::Insane => (ms(300), 0, 2000, 50_000, Duration::ZERO),
        };
        let timeout = if cfg!(windows) {
            timeout.max(WINDOWS_MIN_TIMEOUT)
        } else {
            timeout
        };
        ScanConfig {
            timeout,
            retries,
            concurrency,
            max_rate,
            scan_delay,
            ..ScanConfig::default()
        }
    }
}

impl fmt::Display for Timing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.name())
    }
}

impl FromStr for Timing {
    type Err = String;

    /// Accepts `0`-`5` or the template names, like nmap.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim().to_ascii_lowercase();
        Timing::ALL
            .into_iter()
            .find(|t| s == t.level().to_string() || s == t.name())
            .ok_or_else(|| {
                format!("unknown timing template '{s}' (use 0-5 or paranoid, sneaky, polite, normal, aggressive, insane)")
            })
    }
}

/// Parse a duration like nmap's: a number with an optional `ms`, `s`, `m`
/// or `h` suffix. A bare number means seconds, as in nmap (`--scan-delay 2`
/// is two seconds).
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim().to_ascii_lowercase();
    let split = s
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let value: f64 = num
        .parse()
        .map_err(|_| format!("invalid duration '{s}' (e.g. 500ms, 2s, 5m)"))?;
    let secs = match unit {
        "ms" => value / 1000.0,
        "" | "s" => value,
        "m" => value * 60.0,
        "h" => value * 3600.0,
        _ => return Err(format!("unknown unit in '{s}' (use ms, s, m or h)")),
    };
    Duration::try_from_secs_f64(secs).map_err(|_| format!("duration '{s}' is out of range"))
}

/// When the next probe may go, shared by every technique in this process so
/// the scan delay holds across all of them (ICMP and TCP discovery running
/// side by side, retries, service-detection fallbacks).
static NEXT_SLOT: std::sync::Mutex<Option<std::time::Instant>> = std::sync::Mutex::new(None);

/// Claim the next send slot and return how long to wait for it. Slots are
/// handed out in call order, each at least `delay` after the previous one
/// and never in the past, so a pause cannot be made up with a burst.
fn reserve(delay: Duration) -> Duration {
    let now = std::time::Instant::now();
    let mut next = NEXT_SLOT.lock().unwrap_or_else(|e| e.into_inner());
    let slot = next.map_or(now, |n| n.max(now));
    *next = Some(slot + delay);
    slot - now
}

/// Wait until the next probe may be sent, from async code.
pub(crate) async fn pace(delay: Duration) {
    if !delay.is_zero() {
        tokio::time::sleep(reserve(delay)).await;
    }
}

/// Wait until the next probe may be sent, from a blocking thread.
pub(crate) fn pace_blocking(delay: Duration) {
    if !delay.is_zero() {
        std::thread::sleep(reserve(delay));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_levels_and_names() {
        assert_eq!("4".parse::<Timing>(), Ok(Timing::Aggressive));
        assert_eq!("Insane".parse::<Timing>(), Ok(Timing::Insane));
        assert_eq!("0".parse::<Timing>(), Ok(Timing::Paranoid));
        assert!("6".parse::<Timing>().is_err());
        assert!("fast".parse::<Timing>().is_err());
        assert_eq!(Timing::default(), Timing::Normal);
    }

    #[test]
    fn templates_get_faster() {
        let cfgs: Vec<ScanConfig> = Timing::ALL.iter().map(|t| t.config()).collect();
        for pair in cfgs.windows(2) {
            let (slow, fast) = (&pair[0], &pair[1]);
            assert!(slow.scan_delay >= fast.scan_delay);
            assert!(slow.concurrency <= fast.concurrency);
            assert!(slow.max_rate <= fast.max_rate);
            assert!(slow.timeout >= fast.timeout);
        }
        let normal = Timing::Normal.config();
        let default = ScanConfig::default();
        assert_eq!(
            (
                normal.timeout,
                normal.retries,
                normal.concurrency,
                normal.max_rate
            ),
            (
                default.timeout,
                default.retries,
                default.concurrency,
                default.max_rate
            )
        );
        assert_eq!(Timing::Sneaky.config().scan_delay, Duration::from_secs(15));
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("500ms"), Ok(Duration::from_millis(500)));
        assert_eq!(parse_duration("2"), Ok(Duration::from_secs(2)));
        assert_eq!(parse_duration("1.5s"), Ok(Duration::from_millis(1500)));
        assert_eq!(parse_duration("5m"), Ok(Duration::from_secs(300)));
        assert_eq!(parse_duration("1h"), Ok(Duration::from_secs(3600)));
        assert!(parse_duration("fast").is_err());
        assert!(parse_duration("5d").is_err());
        assert!(parse_duration("").is_err());
    }

    #[tokio::test]
    async fn probes_share_one_schedule() {
        // The only test that uses a non-zero delay, since the slot is global.
        let delay = Duration::from_millis(40);
        let start = std::time::Instant::now();
        // Async and blocking callers interleave on the same schedule.
        pace(delay).await;
        pace(delay).await;
        tokio::task::spawn_blocking(move || pace_blocking(delay))
            .await
            .unwrap();
        pace(delay).await;
        // Three gaps after the first probe, which went at once.
        assert!(
            start.elapsed() >= Duration::from_millis(120),
            "{:?}",
            start.elapsed()
        );

        // After a pause longer than the delay, the next probe goes at once
        // but the one after still waits a full delay: no catch-up burst.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let t = std::time::Instant::now();
        pace(delay).await;
        assert!(t.elapsed() < Duration::from_millis(20), "{:?}", t.elapsed());
        pace(delay).await;
        assert!(
            t.elapsed() >= Duration::from_millis(40),
            "{:?}",
            t.elapsed()
        );

        let t = std::time::Instant::now();
        for _ in 0..1000 {
            pace(Duration::ZERO).await;
        }
        assert!(t.elapsed() < Duration::from_millis(100));
    }
}
