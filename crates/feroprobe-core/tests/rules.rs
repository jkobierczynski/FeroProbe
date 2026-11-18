//! The IDS rule files in `rules/` stay in step: the Snort 2.9 and Snort 3
//! files hold the same rules (by SID and revision), the Snort 3 file uses
//! no 2.9-style content modifiers, and every SID is in the Suricata file.

use std::collections::BTreeMap;

fn rules(name: &str) -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../rules/");
    std::fs::read_to_string(format!("{path}{name}")).unwrap()
}

/// SID -> (revision, the rule line), for each `alert` line.
fn sids(text: &str) -> BTreeMap<u32, (u32, String)> {
    let num = |line: &str, key: &str| -> u32 {
        let start = line
            .find(key)
            .unwrap_or_else(|| panic!("no {key} in {line}"))
            + key.len();
        let digits: String = line[start..]
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        digits.parse().unwrap()
    };
    let mut out = BTreeMap::new();
    for line in text
        .lines()
        .map(str::trim_start)
        .filter(|l| l.starts_with("alert "))
    {
        let sid = num(line, "sid:");
        assert!(
            out.insert(sid, (num(line, "rev:"), line.to_string()))
                .is_none(),
            "duplicate sid {sid}"
        );
    }
    out
}

#[test]
fn snort_rule_files_match() {
    let snort2 = sids(&rules("feroprobe.snort.rules"));
    let snort3 = sids(&rules("feroprobe.snort3.rules"));
    let suricata = sids(&rules("feroprobe.rules"));
    assert!(!snort2.is_empty());
    let revs = |m: &BTreeMap<u32, (u32, String)>| -> Vec<(u32, u32)> {
        m.iter().map(|(s, (r, _))| (*s, *r)).collect()
    };
    assert_eq!(revs(&snort2), revs(&snort3));
    assert_eq!(revs(&snort2), revs(&suricata));
    for (sid, (_, line)) in &snort3 {
        // Top-level options are split by `;`; a modifier must not be one.
        let body = &line[line.find('(').unwrap() + 1..line.rfind(')').unwrap()];
        for opt in body.split(';') {
            let name = opt.trim().split([':', ' ', '\t']).next().unwrap();
            assert!(
                !["depth", "offset", "distance", "within", "nocase"].contains(&name),
                "sid {sid}: Snort 3 wants `, {name}` after its content"
            );
        }
        // Without the modifiers folded in, each rule reads the same. SID
        // 9100006 reads the parsed User-Agent in Snort 3 (http_inspect keeps
        // HTTP headers out of the default buffer), so exactly its expected
        // User-Agent match is taken out of each version; the header and
        // every other option, including any further content, must match.
        let (s3, s2) = if *sid == 9100006 {
            let ua3 = " http_header:field user-agent; \
                       content:\"FeroProbe Scripting Engine\", nocase;";
            let ua2 = " content:\"User-Agent|3A| Mozilla/5.0 (compatible|3B| \
                       FeroProbe Scripting Engine\"; nocase;";
            let two = &snort2[sid].1;
            assert_eq!(line.matches(ua3).count(), 1, "sid {sid}: Snort 3 UA match");
            assert_eq!(two.matches(ua2).count(), 1, "sid {sid}: Snort 2 UA match");
            (line.replacen(ua3, "", 1), two.replacen(ua2, "", 1))
        } else {
            (line.clone(), snort2[sid].1.clone())
        };
        let strip = |l: &str| -> String {
            l.split([';', ','])
                .map(|p| p.trim().replacen(':', " ", 1))
                .filter(|p| !p.is_empty())
                .collect::<Vec<_>>()
                .join("|")
        };
        assert_eq!(strip(&s3), strip(&s2), "sid {sid}");
    }
}
