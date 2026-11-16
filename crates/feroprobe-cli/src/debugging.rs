//! `-v` and `-d` levels, and what `-d` prints before a scan.

use std::time::Duration;

use clap::{CommandFactory, FromArgMatches};
use feroprobe_core::ScanConfig;
use feroprobe_core::debug::MAX_LEVEL;

use crate::Args;

/// Parse the (already nmap-style rewritten) command line, and set the
/// run's verbosity and debugging level from `-v` and `-d`.
pub(crate) fn parse_args(argv: Vec<String>) -> Args {
    let matches = Args::command().get_matches_from(&argv);
    let args = Args::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());
    match levels(&argv) {
        Ok((verbose, debug)) => {
            feroprobe_core::debug::set_verbosity(verbose);
            feroprobe_core::debug::set_debugging(debug);
        }
        Err(e) => Args::command()
            .error(clap::error::ErrorKind::InvalidValue, e)
            .exit(),
    }
    args
}

/// One `-v` or `-d` on the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Level<'a> {
    Verbose,
    Debug(&'a str),
}

/// The verbosity and debugging level the options set, applied in command
/// line order as nmap does: `-v` raises the verbosity; `-d` raises both
/// (`-dd` by two, and so on); `-d<n>` sets both to `n`. Both stop at 10.
/// Read from the rewritten command line (see `nmap_style_args`), where
/// every `-d` form is a `--debug` argument; clap has already accepted it,
/// so a `-v...` argument is the flag, never another option's value.
fn levels(argv: &[String]) -> Result<(u8, u8), String> {
    // Short options can be grouped (`-nv`, `-vp22`): each `v` among the
    // flags counts, up to the first option that takes a value, as the rest
    // of the group is that option's value.
    let (flags, valued): (Vec<_>, Vec<_>) = Args::command()
        .get_arguments()
        .flat_map(|a| {
            let flag = matches!(
                a.get_action(),
                clap::ArgAction::SetTrue | clap::ArgAction::Count
            );
            // Short aliases group the same way (`-vM7` is `-v -c 7`).
            a.get_short()
                .into_iter()
                .chain(a.get_all_short_aliases().unwrap_or_default())
                .map(move |c| (c, flag))
        })
        .partition(|(_, flag)| *flag);
    let is = |set: &[(char, bool)], c: char| set.iter().any(|(s, _)| *s == c);
    let group = |g: &str| -> usize {
        let mut n = 0;
        for c in g.chars() {
            if is(&valued, c) {
                break;
            }
            if !is(&flags, c) {
                return 0;
            }
            n += usize::from(c == 'v');
        }
        n
    };
    let seen = argv
        .iter()
        .skip(1)
        .take_while(|a| *a != "--")
        .flat_map(|a| -> Vec<Level<'_>> {
            if a == "--debug" {
                vec![Level::Debug("")]
            } else if let Some(v) = a.strip_prefix("--debug=") {
                vec![Level::Debug(v)]
            } else if a.len() > 1 && a.starts_with('-') && !a.starts_with("--") {
                vec![Level::Verbose; group(&a[1..])]
            } else {
                Vec::new()
            }
        });
    apply(seen)
}

fn apply<'a>(options: impl IntoIterator<Item = Level<'a>>) -> Result<(u8, u8), String> {
    let (mut verbose, mut debug) = (0u8, 0u8);
    let up = |n: &mut u8| *n = (*n + 1).min(MAX_LEVEL);
    for o in options {
        match o {
            Level::Verbose => up(&mut verbose),
            Level::Debug(v) if v.starts_with(|c: char| c.is_ascii_digit()) => {
                // nmap reads the leading number (atoi) and boxes it to 0-10.
                let digits: String = v.chars().take_while(char::is_ascii_digit).collect();
                let n = digits
                    .parse::<u32>()
                    .unwrap_or(u32::MAX)
                    .min(u32::from(MAX_LEVEL)) as u8;
                verbose = n;
                debug = n;
            }
            Level::Debug(v) if v.chars().all(|c| c == 'd') => {
                for _ in 0..=v.len() {
                    up(&mut verbose);
                    up(&mut debug);
                }
            }
            Level::Debug(v) => return Err(format!("Invalid argument to -d: \"{v}\".")),
        }
    }
    Ok((verbose, debug))
}

/// nmap's "Timing report", printed at `-d` once the settings are final.
/// Times are in milliseconds, as nmap writes them. `group` is how many
/// hosts are scanned together.
pub(crate) fn timing_report(
    cfg: &ScanConfig,
    group_min: usize,
    group_max: usize,
    host_timeout: Option<Duration>,
) -> String {
    let ms = |d: Duration| d.as_millis();
    format!(
        "--------------- Timing report ---------------
  hostgroups: min {group_min}, max {group_max}
  rtt-timeouts: init {}, min {}, max {}
  max-scan-delay: TCP {}, UDP {}, SCTP {}
  parallelism: min {}, max {}
  max-retries: {}, host-timeout: {}
  min-rate: {}, max-rate: {}
---------------------------------------------",
        ms(cfg.rtt.initial),
        ms(cfg.rtt.min),
        ms(cfg.rtt.max),
        ms(cfg.max_scan_delay),
        ms(cfg.max_udp_scan_delay),
        ms(cfg.max_scan_delay),
        cfg.min_parallelism,
        cfg.concurrency,
        cfg.retries,
        host_timeout.map_or(0, ms),
        cfg.min_rate,
        cfg.max_rate.unwrap_or(0),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nmap_style_args;

    fn run(args: &[&str]) -> Result<(u8, u8), String> {
        let mut argv = vec!["feroprobe".to_string()];
        argv.extend(args.iter().map(|s| s.to_string()));
        let argv = nmap_style_args(argv);
        Args::command()
            .try_get_matches_from(&argv)
            .map_err(|e| e.to_string())?;
        levels(&argv)
    }

    #[test]
    fn debug_levels_follow_nmap() {
        assert_eq!(run(&["h"]), Ok((0, 0)));
        assert_eq!(run(&["-d", "h"]), Ok((1, 1)));
        assert_eq!(run(&["-dd", "h"]), Ok((2, 2)));
        assert_eq!(run(&["-ddd", "h"]), Ok((3, 3)));
        assert_eq!(run(&["-d4", "h"]), Ok((4, 4)));
        assert_eq!(run(&["--debug=2", "h"]), Ok((2, 2)));
        assert_eq!(run(&["--debug", "h"]), Ok((1, 1)));
        // Capped at 10, as nmap's box(0, 10, n).
        assert_eq!(run(&["-d99", "h"]), Ok((10, 10)));
        assert_eq!(run(&["-d0", "h"]), Ok((0, 0)));
        // In command line order: -v before -d1 is overridden by it.
        assert_eq!(run(&["-v", "-d", "h"]), Ok((2, 1)));
        assert_eq!(run(&["-vv", "-d1", "h"]), Ok((1, 1)));
        assert_eq!(run(&["-d1", "-vv", "h"]), Ok((3, 1)));
        assert_eq!(run(&["-d", "-d", "h"]), Ok((2, 2)));
        // -v grouped with other flags, as in nmap's common -nv.
        assert_eq!(run(&["-nv", "h"]), Ok((1, 0)));
        assert_eq!(run(&["-vnv", "h"]), Ok((2, 0)));
        assert_eq!(run(&["-n", "h"]), Ok((0, 0)));
        // Up to an option that takes a value; its value is not counted.
        assert_eq!(run(&["-vp22", "h"]), Ok((1, 0)));
        assert_eq!(run(&["-vvpv", "h"]), Ok((2, 0)));
        assert_eq!(run(&["-vM7", "h"]), Ok((1, 0)));
        assert!(
            run(&["-dx", "h"])
                .unwrap_err()
                .contains("Invalid argument to -d")
        );
    }

    #[test]
    fn a_bare_d_keeps_the_next_argument_as_a_target() {
        let mut argv = vec!["feroprobe".to_string()];
        argv.extend(["-d", "3", "-v"].map(String::from));
        let args = Args::command()
            .try_get_matches_from(nmap_style_args(argv))
            .unwrap();
        let args = Args::from_arg_matches(&args).unwrap();
        assert_eq!(args.targets, vec!["3".to_string()]);
        assert_eq!(args.debug, vec![String::new()]);
    }

    #[test]
    fn timing_report_has_nmaps_lines() {
        let cfg = ScanConfig::default();
        let r = timing_report(&cfg, 1, 100_000, Some(Duration::from_secs(60)));
        assert!(r.starts_with("--------------- Timing report"));
        assert!(r.contains("\n  rtt-timeouts: init "));
        assert!(r.contains("host-timeout: 60000\n"));
        assert_eq!(r.lines().count(), 8);
    }
}
