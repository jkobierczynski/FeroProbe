//! FeroProbe's OS signature database: its file format, and matching a
//! fingerprint against it.
//!
//! The database is FeroProbe's own (`data/os-fingerprints.txt`, compiled
//! in). nmap's `nmap-os-db` is not used or copied: its license does not
//! allow redistribution. The format is described in
//! `docs/os-fingerprints.md`; in short:
//!
//! ```text
//! Fingerprint Linux 4.19 - 6.x
//! Like Linux common
//! Class Linux, Linux, 4.X|5.X|6.X, general purpose
//! CPE cpe:/o:linux:linux_kernel:5
//! s1.w = m*max
//! ts = 1000
//! ```
//!
//! A value lists alternatives separated by `|`. An alternative is a word
//! compared as is, a number range `a-b`, `*` (anything), or for a window
//! `m*N` (N times the answer's MSS, or N times the MSS less the 12 bytes
//! timestamps take) or `m*max` (the largest such multiple up to 65535).
//! `Like <name>` copies the tests of an earlier block (often a `Template`,
//! which is never reported as a match by itself), then the block's own
//! lines override them.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use super::fingerprint::Fingerprint;

/// The database compiled into the binary.
pub const BUILT_IN: &str = include_str!("../../data/os-fingerprints.txt");

/// What a signature names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Class {
    pub vendor: String,
    pub family: String,
    /// Such as `5.X|6.X`, or empty.
    pub generation: String,
    pub device_type: String,
}

/// One signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub name: String,
    pub class: Class,
    pub cpe: Vec<String>,
    /// Test name to expected values.
    pub tests: BTreeMap<String, String>,
    /// Line number in the file, for messages and XML (`line=`).
    pub line: usize,
    /// A template only exists to be copied with `Like`.
    template: bool,
}

/// Parse a database. Errors name the line.
pub fn parse(text: &str) -> Result<Vec<Signature>, String> {
    let mut sigs: Vec<Signature> = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let n = n + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (word, rest) = line.split_once(' ').unwrap_or((line, ""));
        let rest = rest.trim();
        match word {
            "Fingerprint" | "Template" => {
                if rest.is_empty() {
                    return Err(format!("line {n}: {word} needs a name"));
                }
                if sigs.iter().any(|s| s.name == rest) {
                    return Err(format!("line {n}: \"{rest}\" is defined twice"));
                }
                sigs.push(Signature {
                    name: rest.to_string(),
                    class: Class {
                        vendor: String::new(),
                        family: String::new(),
                        generation: String::new(),
                        device_type: String::new(),
                    },
                    cpe: Vec::new(),
                    tests: BTreeMap::new(),
                    line: n,
                    template: word == "Template",
                });
                continue;
            }
            _ => {}
        }
        let Some(cur) = sigs.len().checked_sub(1) else {
            return Err(format!("line {n}: expected \"Fingerprint <name>\" first"));
        };
        match word {
            "Like" => {
                let Some(base) = sigs[..cur].iter().find(|s| s.name == rest) else {
                    return Err(format!("line {n}: Like \"{rest}\": no such earlier block"));
                };
                let (tests, class, cpe) =
                    (base.tests.clone(), base.class.clone(), base.cpe.clone());
                let s = &mut sigs[cur];
                s.tests.extend(tests);
                if s.class.vendor.is_empty() {
                    s.class = class;
                }
                if s.cpe.is_empty() {
                    s.cpe = cpe;
                }
            }
            "Class" => {
                let parts: Vec<&str> = rest.split(',').map(str::trim).collect();
                let [vendor, family, generation, device_type] = parts[..] else {
                    return Err(format!(
                        "line {n}: Class needs vendor, family, generation, device type"
                    ));
                };
                sigs[cur].class = Class {
                    vendor: vendor.into(),
                    family: family.into(),
                    generation: generation.into(),
                    device_type: device_type.into(),
                };
            }
            "CPE" => sigs[cur].cpe.push(rest.to_string()),
            _ => {
                let Some((test, values)) = line.split_once('=') else {
                    return Err(format!("line {n}: expected \"test = values\""));
                };
                let (test, values) = (test.trim(), values.trim());
                if test.is_empty() || values.is_empty() || test.contains(' ') {
                    return Err(format!("line {n}: expected \"test = values\""));
                }
                for alt in values.split('|') {
                    check_alternative(alt.trim()).map_err(|e| format!("line {n}: {e}"))?;
                }
                sigs[cur].tests.insert(test.to_string(), values.to_string());
            }
        }
    }
    for s in &sigs {
        if !s.template && s.class.vendor.is_empty() {
            return Err(format!("line {}: \"{}\" has no Class", s.line, s.name));
        }
    }
    Ok(sigs)
}

fn check_alternative(alt: &str) -> Result<(), String> {
    if alt.is_empty() {
        return Err("empty alternative".into());
    }
    if let Some(n) = alt.strip_prefix("m*")
        && n != "max"
        && n.parse::<u32>().is_err()
    {
        return Err(format!("bad window multiple \"{alt}\""));
    }
    Ok(())
}

/// The built-in database, parsed once.
pub fn built_in() -> &'static [Signature] {
    static DB: OnceLock<Vec<Signature>> = OnceLock::new();
    DB.get_or_init(|| parse(BUILT_IN).expect("the built-in OS database parses"))
}

/// How much a test counts. A signature's accuracy is the weight of its
/// tests that match over the weight of its tests the fingerprint has.
pub fn weight(test: &str) -> u32 {
    match test {
        "ttl" => 30,
        "s1.o" => 25,
        "s1.w" => 20,
        "ipid" | "ts" => 15,
        "ws" | "ipid.rst" | "e.f" | "s1.df" => 10,
        "ipid.shared" => 5,
        t if t.ends_with(".m") => 0,
        t if t.ends_with(".o") => 10,
        t if t.ends_with(".ack") || t.ends_with(".seq") => 3,
        _ => 5,
    }
}

/// Whether `value` (of test `test` in `fp`) fits one alternative.
fn fits(alt: &str, value: &str, test: &str, fp: &Fingerprint) -> bool {
    if alt == "*" || alt == value {
        return true;
    }
    if let Some(mult) = alt.strip_prefix("m*") {
        let probe = test.strip_suffix(".w").unwrap_or(test);
        let (Ok(win), Some(Ok(mss))) = (
            value.parse::<u32>(),
            fp.get(&format!("{probe}.m")).map(str::parse::<u32>),
        ) else {
            return false;
        };
        // Linux measures its window in the MSS less the timestamps when it
        // sends them; check both.
        return [mss, mss.saturating_sub(12)].into_iter().any(|m| {
            m > 0
                && match mult {
                    "max" => win == 65535 / m * m,
                    n => n.parse::<u32>().is_ok_and(|n| win == n * m),
                }
        });
    }
    if let Some((lo, hi)) = alt.split_once('-')
        && let (Ok(lo), Ok(hi), Ok(v)) =
            (lo.parse::<u64>(), hi.parse::<u64>(), value.parse::<u64>())
    {
        return (lo..=hi).contains(&v);
    }
    false
}

/// A signature's accuracy for `fp`, in percent, rounded down. `None` when
/// they share no weighted test.
pub fn accuracy(sig: &Signature, fp: &Fingerprint) -> Option<u8> {
    let (mut got, mut possible) = (0u32, 0u32);
    for (test, values) in &sig.tests {
        let Some(value) = fp.get(test) else { continue };
        let w = weight(test);
        possible += w;
        if values
            .split('|')
            .any(|alt| fits(alt.trim(), value, test, fp))
        {
            got += w;
        }
    }
    (possible > 0).then(|| (u64::from(got) * 100 / u64::from(possible)) as u8)
}

/// nmap's guess threshold: matches below 85% are not reported.
pub const GUESS_THRESHOLD: u8 = 85;

/// The signatures that match `fp` at [`GUESS_THRESHOLD`] or better, best
/// first (database order among equals), with their accuracy. A
/// fingerprint without an answered `s1` matches nothing: the TCP tests
/// carry the weight.
pub fn matches<'a>(db: &'a [Signature], fp: &Fingerprint) -> Vec<(&'a Signature, u8)> {
    if fp.get("s1") != Some("Y") {
        return Vec::new();
    }
    let mut out: Vec<(&Signature, u8)> = db
        .iter()
        .filter(|s| !s.template)
        .filter_map(|s| Some((s, accuracy(s, fp)?)))
        .filter(|&(_, a)| a >= GUESS_THRESHOLD)
        .collect();
    out.sort_by_key(|&(_, a)| std::cmp::Reverse(a));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(tests: &[(&str, &str)]) -> Fingerprint {
        Fingerprint {
            tests: tests
                .iter()
                .map(|(t, v)| (t.to_string(), v.to_string()))
                .collect(),
        }
    }

    #[test]
    fn built_in_database_parses_and_is_complete() {
        let db = built_in();
        assert!(db.iter().filter(|s| !s.template).count() >= 10);
        // Every reported signature can be told apart on the main tests.
        for s in db.iter().filter(|s| !s.template) {
            for t in ["ttl", "s1", "s1.o", "s1.w", "s2.o", "s3.o", "s4.o", "e.o"] {
                assert!(s.tests.contains_key(t), "{} lacks {t}", s.name);
            }
            assert!(!s.cpe.is_empty(), "{} has no CPE", s.name);
        }
    }

    #[test]
    fn parse_errors_name_the_line() {
        assert!(parse("ttl = 64").unwrap_err().contains("line 1"));
        assert!(
            parse("Fingerprint A\nttl 64")
                .unwrap_err()
                .contains("line 2")
        );
        assert!(
            parse("Fingerprint A\nLike B")
                .unwrap_err()
                .contains("no such")
        );
        assert!(
            parse("Fingerprint A\nttl = 64")
                .unwrap_err()
                .contains("no Class")
        );
        assert!(parse("Fingerprint A\nClass a, b, c, d\ns1.w = m*x").is_err());
        let ok = parse(
            "Template T\nttl = 64\ns1 = Y\nFingerprint A\nLike T\nClass V, F, 1.X, general purpose\nttl = 128",
        )
        .unwrap();
        assert_eq!(ok[1].tests["ttl"], "128");
        assert_eq!(ok[1].tests["s1"], "Y");
    }

    #[test]
    fn values_and_windows() {
        let f = fp(&[
            ("s1.w", "65160"),
            ("s1.m", "1460"),
            ("s2.w", "64240"),
            ("s2.m", "1460"),
        ]);
        assert!(fits("m*45", "65160", "s1.w", &f)); // 45 x 1448
        assert!(fits("m*max", "65160", "s1.w", &f));
        assert!(fits("m*max", "64240", "s2.w", &f)); // 44 x 1460
        assert!(!fits("m*20", "65160", "s1.w", &f));
        assert!(fits("5-10", "7", "ws", &f));
        assert!(!fits("5-10", "11", "ws", &f));
        assert!(fits("*", "x", "ws", &f));
        // Loopback: MSS 65495 with timestamps gives one segment of 65483.
        let lo = fp(&[("s1.w", "65483"), ("s1.m", "65495")]);
        assert!(fits("m*max", "65483", "s1.w", &lo));
    }

    #[test]
    fn accuracy_counts_only_shared_tests() {
        let db = parse(
            "Fingerprint A\nClass V, F, , general purpose\nCPE cpe:/o:v:f\nttl = 64\ns1 = Y\ns1.o = M\nc1 = Y",
        )
        .unwrap();
        // No closed port: c1 is not counted.
        let f = fp(&[("ttl", "64"), ("s1", "Y"), ("s1.o", "M")]);
        assert_eq!(accuracy(&db[0], &f), Some(100));
        let f = fp(&[("ttl", "64"), ("s1", "Y"), ("s1.o", "M,S")]);
        // 30 + 5 of 30 + 5 + 25.
        assert_eq!(accuracy(&db[0], &f), Some(58));
        assert!(matches(&db, &f).is_empty());
        assert!(matches(&db, &fp(&[("ttl", "64"), ("s1", "N")])).is_empty());
    }
}
