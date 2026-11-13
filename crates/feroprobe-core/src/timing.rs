//! Timing templates (`-T0` to `-T5`) and probe spacing.
//!
//! Like nmap's templates, each one is a bundle of the existing knobs:
//! per-probe timeout, retries, parallelism, packet rate and a minimum delay
//! between probes. Flags given explicitly on the command line override the
//! template's value for that knob.

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use tokio::sync::Mutex;
use tokio::time::Instant;

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

/// Spaces out the start of async probes (connect, UDP, service detection)
/// by at least the scan delay, whatever the parallelism.
pub(crate) struct Gate {
    delay: Duration,
    next: Mutex<Option<Instant>>,
}

impl Gate {
    pub(crate) fn new(delay: Duration) -> Self {
        Self {
            delay,
            next: Mutex::new(None),
        }
    }

    /// Wait until this probe may start.
    pub(crate) async fn wait(&self) {
        if self.delay.is_zero() {
            return;
        }
        // Holding the lock while sleeping lines the probes up in order.
        let mut next = self.next.lock().await;
        if let Some(at) = *next {
            tokio::time::sleep_until(at).await;
        }
        *next = Some(Instant::now() + self.delay);
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
    async fn gate_spaces_probes() {
        let gate = Gate::new(Duration::from_millis(40));
        let start = std::time::Instant::now();
        for _ in 0..4 {
            gate.wait().await;
        }
        // Three gaps after the first probe.
        assert!(
            start.elapsed() >= Duration::from_millis(120),
            "{:?}",
            start.elapsed()
        );

        let open = Gate::new(Duration::ZERO);
        let start = std::time::Instant::now();
        for _ in 0..1000 {
            open.wait().await;
        }
        assert!(start.elapsed() < Duration::from_millis(100));
    }
}
