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
    for line in text.lines().filter(|l| l.starts_with("alert ")) {
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
        for m in ["depth", "offset", "distance", "within", "nocase"] {
            assert!(
                !line.contains(&format!("; {m}")),
                "sid {sid}: Snort 3 wants `, {m}` after its content"
            );
        }
        // Without the modifiers folded in, each rule reads the same.
        let strip = |l: &str| -> String {
            l.split([';', ','])
                .map(|p| p.trim().replacen(':', " ", 1))
                .filter(|p| !p.is_empty())
                .collect::<Vec<_>>()
                .join("|")
        };
        assert_eq!(strip(line), strip(&snort2[sid].1), "sid {sid}");
    }
}
