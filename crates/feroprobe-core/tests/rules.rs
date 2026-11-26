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

/// The `content` matches of a Suricata rule, with their modifiers:
/// (bytes, offset, depth, distance, within).
type Content = (
    Vec<u8>,
    Option<usize>,
    Option<usize>,
    Option<usize>,
    Option<usize>,
);

fn contents(rule: &str) -> Vec<Content> {
    let mut out: Vec<Content> = Vec::new();
    for part in rule.split("; ") {
        if let Some(text) = part.strip_prefix("content:\"") {
            let text = text.trim_end_matches('"');
            let mut bytes = Vec::new();
            for (i, piece) in text.split('|').enumerate() {
                if i % 2 == 1 {
                    for hex in piece.split_whitespace() {
                        bytes.push(u8::from_str_radix(hex, 16).unwrap());
                    }
                } else {
                    bytes.extend_from_slice(piece.as_bytes());
                }
            }
            out.push((bytes, None, None, None, None));
        } else if let Some((key, value)) = part.split_once(':')
            && let Ok(n) = value.parse::<usize>()
            && let Some(last) = out.last_mut()
        {
            match key {
                "offset" => last.1 = Some(n),
                "depth" => last.2 = Some(n),
                "distance" => last.3 = Some(n),
                "within" => last.4 = Some(n),
                _ => {}
            }
        }
    }
    out
}

/// Whether the contents match `data` in order, as an IDS reads them.
fn content_match(contents: &[Content], data: &[u8]) -> bool {
    let mut end = 0;
    for (i, (bytes, offset, depth, distance, within)) in contents.iter().enumerate() {
        let (from, limit) = if i == 0 || (distance.is_none() && within.is_none()) {
            let from = offset.unwrap_or(0);
            (from, depth.map_or(data.len(), |d| from + d))
        } else {
            let from = end + distance.unwrap_or(0);
            (from, within.map_or(data.len(), |w| from + w))
        };
        let window = &data[from.min(data.len())..limit.min(data.len())];
        match window.windows(bytes.len()).position(|w| w == &bytes[..]) {
            Some(at) => end = from + at + bytes.len(),
            None => return false,
        }
    }
    true
}

/// The rules for -sV probes match the probes FeroProbe sends.
#[test]
fn service_probe_rules_match_the_probes() {
    let suricata = sids(&rules("feroprobe.rules"));
    let db = feroprobe_core::ServiceDb::builtin();
    for (sid, probe) in [
        (9100022, "msrpc"),
        (9100023, "kerberos"),
        (9100024, "kerberos-udp"),
        (9100025, "netbios-ssn"),
        (9100026, "mc-nmf"),
        (9100027, "stun"),
        (9100028, "ike"),
        (9100028, "ike-natt"),
        (9100029, "l2tp"),
        (9100030, "mdns"),
        (9100031, "iax2"),
    ] {
        let rule = &suricata[&sid].1;
        assert!(!contents(rule).is_empty(), "sid {sid}: {rule}");
        let payload = db.probe(probe).unwrap().payload();
        assert!(
            content_match(&contents(rule), payload),
            "sid {sid} vs probe {probe}"
        );
        // And not every other probe.
        // The IKE rule covers both IKE probes.
        let same = |name: &str| name == probe || (sid == 9100028 && name.starts_with("ike"));
        for other in db.probes.iter().filter(|p| !same(&p.name)) {
            assert!(
                !content_match(&contents(rule), other.payload()),
                "sid {sid} matches probe {}",
                other.name
            );
        }
    }
}

/// The rules for the NSE dns module match its queries and updates, over
/// UDP and TCP, and not a query with another transaction ID.
#[test]
fn nse_dns_rules_match_its_queries() {
    let suricata = sids(&rules("feroprobe.rules"));
    let pcre = |sid: u32| -> regex::bytes::Regex {
        let rule = &suricata[&sid].1;
        let start = rule.find("pcre:\"/").unwrap() + 7;
        let end = rule[start..].find("/s\"").unwrap() + start;
        regex::bytes::Regex::new(&format!("(?s-u){}", &rule[start..end])).unwrap()
    };
    // www.example A, with and without recursion; with an EDNS0 OPT record.
    let q = |flags: u8, ar: u8| -> Vec<u8> {
        let mut p = vec![b'F', b'P', flags, 0, 0, 1, 0, 0, 0, 0, 0, ar];
        p.extend_from_slice(b"\x03www\x07example\x00\x00\x01\x00\x01");
        p
    };
    // An update (opcode 5): zone example, one A record to add.
    let mut update = vec![b'F', b'P', 0x28, 0, 0, 1, 0, 0, 0, 1, 0, 0];
    update.extend_from_slice(b"\x07example\x00\x00\x06\x00\x01");
    for pkt in [q(1, 0), q(0, 0), q(1, 1), update] {
        let mut tcp = (pkt.len() as u16).to_be_bytes().to_vec();
        tcp.extend_from_slice(&pkt);
        assert!(content_match(&contents(&suricata[&9100032].1), &pkt));
        assert!(pcre(9100032).is_match(&pkt), "{pkt:02x?}");
        assert!(content_match(&contents(&suricata[&9100033].1), &tcp));
        assert!(pcre(9100033).is_match(&tcp), "{tcp:02x?}");
    }
    let mut other = q(1, 0);
    other[1] = b'Q';
    assert!(!pcre(9100032).is_match(&other));
}

/// The rule for the NSE mysql module's login matches its connection
/// attributes.
#[test]
fn nse_mysql_rule_matches_the_login() {
    let suricata = sids(&rules("feroprobe.rules"));
    let mut login = vec![0u8; 32];
    login.extend_from_slice(b"fp\0\0mysql_native_password\0");
    login.extend_from_slice(b"\x2c\x0c_client_name\x09FeroProbe\x0cprogram_name\x09FeroProbe");
    assert!(content_match(&contents(&suricata[&9100034].1), &login));
    assert!(!content_match(
        &contents(&suricata[&9100034].1),
        b"\x0cprogram_name\x05mysql"
    ));
}

/// The rule for the NSE netbios module's NAME QUERY matches it, and not a
/// query with another transaction ID.
#[test]
fn nse_netbios_rule_matches_the_name_query() {
    let suricata = sids(&rules("feroprobe.rules"));
    let rule = &suricata[&9100035].1;
    let start = rule.find("pcre:\"/").unwrap() + 7;
    let end = rule[start..].find("/s\"").unwrap() + start;
    let pcre = regex::bytes::Regex::new(&format!("(?s-u){}", &rule[start..end])).unwrap();
    // "VM" padded with spaces (suffix 0x20), first-level encoded.
    let mut q = b"FP\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20".to_vec();
    for b in b"VM              " {
        q.push(b'A' + (b >> 4));
        q.push(b'A' + (b & 0xf));
    }
    q.extend_from_slice(b"\x00\x00\x20\x00\x01");
    assert!(content_match(&contents(rule), &q));
    assert!(pcre.is_match(&q), "{q:02x?}");
    let mut other = q.clone();
    other[0] = b'Q';
    assert!(!pcre.is_match(&other));
}

/// The NSE rpc module's calls: XID "FP" + 16 bits, CALL, RPC version 2;
/// over TCP after the record mark.
#[test]
fn nse_rpc_rules_match_its_calls() {
    let suricata = sids(&rules("feroprobe.rules"));
    let call = b"FP\x12\x34\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa0\x00\x00\x00\x02\x00\x00\x00\x04\
                 \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    assert!(content_match(&contents(&suricata[&9100036].1), call));
    let mut tcp = (0x8000_0000u32 | call.len() as u32).to_be_bytes().to_vec();
    tcp.extend_from_slice(call);
    assert!(content_match(&contents(&suricata[&9100037].1), &tcp));
    assert!(!content_match(&contents(&suricata[&9100037].1), call));
    // A reply (message type 1) is not a call.
    let mut reply = call.to_vec();
    reply[7] = 1;
    assert!(!content_match(&contents(&suricata[&9100036].1), &reply));
}

#[test]
fn nse_ldap_rules_match_its_requests() {
    let suricata = sids(&rules("feroprobe.rules"));
    // A search for the root DSE with message ID 0x46500001.
    let search =
        b"\x30\x25\x02\x04\x46\x50\x00\x01\x63\x1d\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\
                   \x02\x01\x00\x01\x01\x00\x87\x0bobjectClass\x30\x00";
    assert!(content_match(&contents(&suricata[&9100038].1), search));
    assert!(content_match(&contents(&suricata[&9100039].1), search));
    // A long length form still matches.
    let mut long = b"\x30\x82\x00\x25".to_vec();
    long.extend_from_slice(&search[2..]);
    assert!(content_match(&contents(&suricata[&9100038].1), &long));
    // Another client's message ID, and a server's entry (tag 0x64).
    let mut other = search.to_vec();
    other[4] = 0x00;
    assert!(!content_match(&contents(&suricata[&9100038].1), &other));
    let mut entry = search.to_vec();
    entry[8] = 0x64;
    assert!(!content_match(&contents(&suricata[&9100039].1), &entry));
}
