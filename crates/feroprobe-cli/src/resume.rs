//! `--resume FILE`: carry on with a scan that was aborted, as nmap does.
//!
//! The normal (`-oN`), grepable (`-oG`) or XML (`-oX`) report of the
//! aborted run holds everything needed: its first line (in XML, the comment
//! before `<nmaprun>`) records the command line after ` as: `, and the last
//! host it reports is the last one finished, because reports are written a
//! host group at a time. The resumed run parses that command line again,
//! skips every target up to and including that host, and appends to the same
//! report files.
//!
//! Like nmap, the file is searched for a grepable `Host:` line first, then
//! an XML `<address>`, then a normal `Scan report for` line, and only the
//! last match counts.

use std::net::IpAddr;

use anyhow::{Context, Result, bail};
use feroprobe_core::Target;

/// What an aborted run's report says.
#[derive(Debug, PartialEq)]
pub struct Resume {
    /// The command line, without the program name.
    pub args: Vec<String>,
    /// The last host the report finished, if it finished any.
    pub last: Option<IpAddr>,
}

/// Quote one argument the way [`split_quoted`] reads it back: in double
/// quotes, with `"` and `\` escaped, when it is empty or holds whitespace or
/// a quote. nmap quotes the same way (`join_quoted` in its output.cc).
fn quote(arg: &str) -> String {
    let special = arg.is_empty()
        || arg
            .chars()
            .any(|c| c.is_whitespace() || c == '"' || c == '\'' || c == '\\');
    if !special {
        return arg.to_string();
    }
    let mut s = String::from("\"");
    for c in arg.chars() {
        if c == '"' || c == '\\' {
            s.push('\\');
        }
        // A line break would end the report's header line.
        s.push(if c == '\n' || c == '\r' { ' ' } else { c });
    }
    s.push('"');
    s
}

/// A command line as the reports record it: the arguments separated by
/// spaces, each quoted if it needs to be.
pub fn join_quoted(args: &[String]) -> String {
    args.iter().map(|a| quote(a)).collect::<Vec<_>>().join(" ")
}

/// Split a recorded command line back into arguments: whitespace separates
/// them, and double or single quotes group (a backslash escapes the next
/// character inside double quotes). `None` if a quote is left open.
pub fn split_quoted(line: &str) -> Option<Vec<String>> {
    let mut args = Vec::new();
    let mut chars = line.chars().peekable();
    loop {
        while chars.peek().is_some_and(|c| c.is_whitespace()) {
            chars.next();
        }
        let Some(&first) = chars.peek() else {
            return Some(args);
        };
        let mut arg = String::new();
        if first == '"' || first == '\'' {
            chars.next();
            loop {
                match chars.next()? {
                    c if c == first => break,
                    '\\' if first == '"' => arg.push(chars.next()?),
                    c => arg.push(c),
                }
            }
        } else {
            while let Some(&c) = chars.peek() {
                if c.is_whitespace() {
                    break;
                }
                arg.push(c);
                chars.next();
            }
        }
        args.push(arg);
    }
}

/// Undo the escaping of an XML comment or attribute.
fn xml_unescape(s: &str) -> String {
    // "&#45;" breaks up "--", which a comment cannot hold.
    s.replace("&#45;", "-")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// Read the report of an aborted run.
pub fn read(path: &str) -> Result<Resume> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {path}"))?;
    let text = String::from_utf8_lossy(&bytes);
    parse(&text).with_context(|| format!("cannot resume from {path}"))
}

/// Parse a report: the command line and the last finished host.
pub fn parse(text: &str) -> Result<Resume> {
    // nmap's limit: a report this short holds no host.
    if text.len() < 20 {
        bail!("the file is too short to be a report, so there is nothing to resume");
    }
    let Some(at) = text.find(" as: ") else {
        bail!("no \" as: <command line>\" found; is this a FeroProbe -oN, -oG or -oX report?");
    };
    let rest = &text[at + 5..];
    let Some(end) = rest.find('\n') else {
        bail!("the command line is not complete; the run had not finished a host");
    };
    let args = command_line(&rest[..end])?;
    if args
        .iter()
        .any(|a| a == "--resume" || a.starts_with("--resume="))
    {
        bail!("the recorded command line itself uses --resume");
    }
    let body = &text[at..];
    Ok(Resume {
        last: last_host(body)?,
        args,
    })
}

/// The arguments (without the program name) of a command line as a
/// report records it after ` as: `, up to the end of its line.
fn command_line(recorded: &str) -> Result<Vec<String>> {
    let mut line = recorded.trim_end().to_string();
    // The XML report keeps it in a comment, escaped.
    if let Some(cut) = line.find("-->") {
        line.truncate(cut);
        line = xml_unescape(line.trim_end());
    }
    let Some(mut args) = split_quoted(&line) else {
        bail!("the command line has an unclosed quote");
    };
    if args.len() < 2 {
        bail!("the command line names no options or targets");
    }
    // The program name.
    args.remove(0);
    Ok(args)
}

/// The kinds of report file a resumed scan appends to, as far as
/// [`continues_scan`] tells them apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    /// `-oN`, `-oG` and `-oX`: they start with the `scan initiated ... as:`
    /// line (in XML, a comment).
    Recorded,
    /// `-oS`: the normal report in script kiddie spelling, which starts with
    /// a mangled `Starting FeroProbe` line and records no command line.
    Skid,
    /// `-oJ`: written only when a run ends, so an aborted run leaves it
    /// empty; a run resumed and finished before leaves a FeroProbe document.
    Json,
}

/// How much of a report file [`continues_scan`] needs: its first lines.
pub const HEAD_LEN: usize = 64 * 1024;

/// Whether `head` (the start of an existing file) is a report of the scan
/// whose command line is `args`, so that a resumed run may append to it.
///
/// The command line comes from the report given to `--resume`, which may
/// have been written by anyone: without this check it could name any file
/// (a shell start-up file, a cron table) as a report and have the resumed
/// run append text to it that the scanned hosts chose, such as a service's
/// version string. A file that already holds this scan's report can only
/// gain more of it.
pub fn continues_scan(kind: FileKind, head: &str, args: &[String]) -> bool {
    match kind {
        FileKind::Recorded => {
            let Some(recorded) = head.lines().find_map(|l| {
                let header = l.starts_with("# FeroProbe ") || l.starts_with("<!-- FeroProbe ");
                let at = l.find(" as: ")?;
                (header && l[..at].contains(" scan initiated ")).then(|| &l[at + 5..])
            }) else {
                return false;
            };
            // A resumed run records the command with --append-output added.
            let without = |v: &[String]| -> Vec<String> {
                v.iter()
                    .filter(|a| *a != "--append-output")
                    .cloned()
                    .collect()
            };
            command_line(recorded).is_ok_and(|r| without(&r) == without(args))
        }
        FileKind::Skid => {
            let first = head.lines().next().unwrap_or("");
            crate::output::could_be_skid("Starting FeroProbe ", first)
        }
        FileKind::Json => {
            let t = head.trim_start();
            t.is_empty() || (t.starts_with('{') && t.contains("\"scanner\": \"feroprobe\""))
        }
    }
}

/// The last host the report finished, in nmap's order of trying: grepable,
/// XML, normal.
fn last_host(body: &str) -> Result<Option<IpAddr>> {
    let parse = |s: &str| -> Result<IpAddr> {
        s.parse()
            .with_context(|| format!("{s:?} in the report is not an IP address"))
    };
    if let Some(i) = body.rfind("\nHost: ") {
        let rest = &body[i + 7..];
        let addr = rest.split(|c: char| c.is_whitespace()).next().unwrap_or("");
        return parse(addr).map(Some);
    }
    let mut last = None;
    let mut from = 0;
    while let Some(i) = body[from..].find("\n<address addr=\"") {
        let start = from + i + 16;
        let Some(len) = body[start..].find('"') else {
            bail!("an <address> element is cut off");
        };
        let after = &body[start + len..];
        // MAC addresses are listed too; only IP addresses are targets.
        if after.starts_with("\" addrtype=\"ipv4\"") || after.starts_with("\" addrtype=\"ipv6\"") {
            last = Some(&body[start..start + len]);
        }
        from = start + len;
    }
    if let Some(addr) = last {
        return parse(addr).map(Some);
    }
    if let Some(i) = body.rfind("\nScan report for ") {
        let rest = &body[i + 17..];
        let line = rest.lines().next().unwrap_or("").trim_end();
        // "Scan report for name (address)" when the host has a name.
        let addr = match (line.rfind('('), line.ends_with(')')) {
            (Some(open), true) => &line[open + 1..line.len() - 1],
            _ => line,
        };
        return parse(addr).map(Some);
    }
    Ok(None)
}

/// Drop the targets the aborted run finished: everything up to and
/// including `last`, as nmap does. Returns how many were dropped, or
/// `None` if `last` is not among the targets (then all of them are kept).
pub fn skip_finished(targets: &mut Vec<Target>, last: IpAddr) -> Option<usize> {
    let pos = targets.iter().position(|t| t.addr == last)?;
    targets.drain(..=pos);
    Some(pos + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn quoting_round_trips() {
        let args = strings(&[
            "feroprobe",
            "-p",
            "22,80",
            "--exclude",
            "a b",
            "",
            "say \"hi\"",
            "back\\slash",
            "it's",
        ]);
        let line = join_quoted(&args);
        assert_eq!(
            line,
            r#"feroprobe -p 22,80 --exclude "a b" "" "say \"hi\"" "back\\slash" "it's""#
        );
        assert_eq!(split_quoted(&line).unwrap(), args);
        // nmap's own single quotes.
        assert_eq!(
            split_quoted("nmap 'a b' c").unwrap(),
            strings(&["nmap", "a b", "c"])
        );
        assert_eq!(split_quoted("nmap \"open"), None);
    }

    #[test]
    fn resumed_files_must_hold_the_same_scan() {
        let args = strings(&["-oN", "r.nmap", "-oG", "r.gnmap", "10.0.0.0/24"]);
        let normal = "# FeroProbe 0.5.0 scan initiated Mon Nov 16 10:00:00 2026 UTC as: feroprobe -oN r.nmap -oG r.gnmap 10.0.0.0/24\n\nScan report for 10.0.0.1\n";
        assert!(continues_scan(FileKind::Recorded, normal, &args));
        // Resumed before: the second header adds --append-output.
        let again = "# FeroProbe 0.5.0 scan initiated Mon Nov 16 11:00:00 2026 UTC as: /usr/bin/feroprobe --append-output -oN r.nmap -oG r.gnmap 10.0.0.0/24\n";
        assert!(continues_scan(FileKind::Recorded, again, &args));
        let xml = "<?xml version=\"1.0\"?>\n<!-- FeroProbe 0.5.0 scan initiated Mon Nov 16 10:00:00 2026 UTC as: feroprobe -oN r.nmap -oG r.gnmap 10.0.0.0/24 -->\n<nmaprun>\n";
        assert!(continues_scan(FileKind::Recorded, xml, &args));
        // Another scan's report, or no report at all.
        let other = normal.replace("10.0.0.0/24", "10.0.1.0/24");
        assert!(!continues_scan(FileKind::Recorded, &other, &args));
        assert!(!continues_scan(FileKind::Recorded, "", &args));
        let bashrc =
            "# ~/.bashrc\nalias ll='ls -l' # as: feroprobe -oN r.nmap -oG r.gnmap 10.0.0.0/24\n";
        assert!(!continues_scan(FileKind::Recorded, bashrc, &args));
        // -oS records no command line, only its mangled first line.
        assert!(continues_scan(
            FileKind::Skid,
            "$tArt!ng F3r0Pr0b3 0.5.0\n",
            &args
        ));
        assert!(!continues_scan(FileKind::Skid, "#!/bin/sh\n", &args));
        // -oJ: empty after an aborted run, or a FeroProbe document.
        assert!(continues_scan(FileKind::Json, "", &args));
        assert!(continues_scan(
            FileKind::Json,
            "{\n  \"scanner\": \"feroprobe\",\n",
            &args
        ));
        assert!(!continues_scan(
            FileKind::Json,
            "* * * * * root sh\n",
            &args
        ));
    }

    #[test]
    fn normal_report() {
        let text = "# FeroProbe 0.4.0 scan initiated Mon Nov 16 10:00:00 2026 UTC as: feroprobe -oN \"my scan.nmap\" -p 22 10.0.0.0/24\n\
            \n\
            Scan report for 10.0.0.1\n\
            Host is up (0.10 ms latency).\n\
            \n\
            Scan report for gw.example (10.0.0.7)\n\
            Host is up.\n";
        let r = parse(text).unwrap();
        assert_eq!(
            r.args,
            strings(&["-oN", "my scan.nmap", "-p", "22", "10.0.0.0/24"])
        );
        assert_eq!(r.last, Some("10.0.0.7".parse().unwrap()));
    }

    #[test]
    fn grepable_report() {
        let text = "# FeroProbe 0.4.0 scan initiated Mon Nov 16 10:00:00 2026 UTC as: feroprobe -oG r.gnmap 10.0.0.0/24\n\
            Host: 10.0.0.1 ()\tStatus: Up\n\
            Host: 10.0.0.1 ()\tPorts: 22/open/tcp//ssh///\n\
            Host: 10.0.0.9 (nine)\tStatus: Up\n";
        let r = parse(text).unwrap();
        assert_eq!(r.last, Some("10.0.0.9".parse().unwrap()));
    }

    #[test]
    fn xml_report() {
        let text = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE nmaprun>\n\
            <?xml-stylesheet href=\"x.xsl\" type=\"text/xsl\"?>\n\
            <!-- FeroProbe 0.4.0 scan initiated Mon Nov 16 10:00:00 2026 UTC as: feroprobe -oX r.xml -&#45;exclude &quot;a b&quot; 2001:db8::/120 -->\n\
            <nmaprun scanner=\"feroprobe\" args=\"\">\n\
            <host>\n<address addr=\"2001:db8::5\" addrtype=\"ipv6\"/>\n\
            <address addr=\"00:11:22:33:44:55\" addrtype=\"mac\"/>\n</host>\n";
        let r = parse(text).unwrap();
        assert_eq!(
            r.args,
            strings(&["-oX", "r.xml", "--exclude", "a b", "2001:db8::/120"])
        );
        assert_eq!(r.last, Some("2001:db8::5".parse().unwrap()));
    }

    #[test]
    fn no_host_finished_yet() {
        let text = "# FeroProbe 0.4.0 scan initiated Mon Nov 16 10:00:00 2026 UTC as: feroprobe -oN r 10.0.0.1\n";
        assert_eq!(parse(text).unwrap().last, None);
    }

    #[test]
    fn rejects_what_is_not_a_report() {
        assert!(parse("short").is_err());
        assert!(parse("this is just some text file\nwith lines\n").is_err());
        assert!(
            parse("# FeroProbe 0.4.0 scan initiated x as: feroprobe --resume r.nmap\n").is_err()
        );
    }

    #[test]
    fn skips_up_to_the_last_finished_host() {
        let t = |s: &str| Target {
            addr: s.parse().unwrap(),
            hostname: None,
        };
        let mut targets = vec![t("10.0.0.1"), t("10.0.0.2"), t("10.0.0.3")];
        assert_eq!(
            skip_finished(&mut targets, "10.0.0.2".parse().unwrap()),
            Some(2)
        );
        assert_eq!(targets, vec![t("10.0.0.3")]);
        assert_eq!(
            skip_finished(&mut targets, "10.0.0.9".parse().unwrap()),
            None
        );
        assert_eq!(targets.len(), 1);
    }
}
