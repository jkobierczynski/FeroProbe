//! The text comparison: a unified diff of the normal output. Each line
//! starts with `-` (only in the first scan), `+` (only in the second) or a
//! space (in both), as ndiff writes it.

use std::fmt::Write;

use crate::diff::{HostDiff, Op, ScanDiff, ScriptDiff, opcodes};
use crate::scan::{Port, Scan};

/// A column table like the normal output's port table: a mark column with
/// no space after it, then space-separated, left-aligned columns. Raw rows
/// (script lines) are printed as they are.
struct Table {
    rows: Vec<Row>,
}

enum Row {
    Cells(Vec<String>),
    Raw(String),
}

impl Table {
    fn new() -> Table {
        Table { rows: Vec::new() }
    }

    fn cells(&mut self, mark: &str, cols: &[Option<String>]) {
        let mut row = vec![mark.to_string()];
        row.extend(cols.iter().map(|c| c.clone().unwrap_or_default()));
        // Empty trailing columns add no padding.
        while row.len() > 1 && row.last().is_some_and(String::is_empty) {
            row.pop();
        }
        self.rows.push(Row::Cells(row));
    }

    fn raw(&mut self, line: String) {
        self.rows.push(Row::Raw(line));
    }

    fn render(&self, out: &mut String) {
        let mut widths: Vec<usize> = Vec::new();
        for r in &self.rows {
            if let Row::Cells(c) = r {
                for (i, s) in c.iter().enumerate() {
                    let w = s.chars().count();
                    match widths.get_mut(i) {
                        Some(x) => *x = (*x).max(w),
                        None => widths.push(w),
                    }
                }
            }
        }
        for r in &self.rows {
            match r {
                Row::Raw(s) => out.push_str(s),
                Row::Cells(c) => {
                    let mut line = String::new();
                    for (i, s) in c.iter().enumerate() {
                        // No gap after the mark column.
                        if i > 1 {
                            line.push(' ');
                        }
                        let _ = write!(line, "{s:<w$}", w = widths[i]);
                    }
                    out.push_str(line.trim_end());
                }
            }
            out.push('\n');
        }
    }
}

fn columns(p: &Port) -> [Option<String>; 4] {
    [
        Some(p.spec_string()),
        Some(p.state_string()),
        p.service.name_string(),
        p.service.version_string(),
    ]
}

fn script_lines(table: &mut Table, d: &ScriptDiff, verbose: bool) {
    let a = d.a.as_ref().map(|s| s.lines()).unwrap_or_default();
    let b = d.b.as_ref().map(|s| s.lines()).unwrap_or_default();
    if a == b && !verbose {
        return;
    }
    for (op, i1, i2, j1, j2) in opcodes(&a, &b) {
        if matches!(op, Op::Replace | Op::Delete) {
            for l in &a[i1..i2] {
                table.raw(format!("-{l}"));
            }
        }
        if matches!(op, Op::Replace | Op::Insert) {
            for l in &b[j1..j2] {
                table.raw(format!("+{l}"));
            }
        }
        if op == Op::Equal {
            for l in &a[i1..i2] {
                table.raw(format!(" {l}"));
            }
        }
    }
}

/// A "Host script results:"-style block, after a blank line.
fn script_section(
    out: &mut String,
    title: &str,
    in_a: bool,
    in_b: bool,
    diffs: &[ScriptDiff],
    verbose: bool,
) {
    let mut table = Table::new();
    for d in diffs {
        script_lines(&mut table, d, verbose);
    }
    if table.rows.is_empty() {
        return;
    }
    let mark = match (in_a, in_b) {
        (true, false) => '-',
        (false, true) => '+',
        _ => ' ',
    };
    let _ = writeln!(out, "\n{mark}{title}:");
    table.render(out);
}

/// `Sat Nov 14 05:40:00 2026 UTC`.
pub fn time_string(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    const WEEKDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    format!(
        "{} {} {:02} {:02}:{:02}:{:02} {} UTC",
        WEEKDAYS[days.rem_euclid(7) as usize],
        MONTHS[(month - 1) as usize],
        day,
        rem / 3600,
        rem / 60 % 60,
        rem % 60,
        year
    )
}

/// `FeroProbe 0.5.0 scan initiated <time> as: <command>`.
pub fn banner(scan: &Scan) -> String {
    let scanner = match scan.scanner.as_deref() {
        None | Some("nmap") => "Nmap",
        Some("feroprobe") => "FeroProbe",
        Some(other) => other,
    };
    let mut parts = vec![scanner.to_string()];
    parts.extend(scan.version.clone());
    parts.push("scan".to_string());
    if let Some(t) = scan.start {
        parts.push(format!("initiated {}", time_string(t)));
    }
    if let Some(args) = &scan.args {
        parts.push(format!("as: {args}"));
    }
    parts.join(" ")
}

fn host(out: &mut String, h: &HostDiff, verbose: bool) {
    let (a, b) = (&h.a, &h.b);
    let state = |s: &Option<String>| s.clone().unwrap_or_else(|| "unknown".to_string());

    if h.id_changed {
        if h.in_a {
            let _ = writeln!(out, "-{}:", a.display_name());
        }
        if h.in_b {
            let _ = writeln!(out, "+{}:", b.display_name());
        }
    } else {
        let _ = writeln!(out, " {}:", a.display_name());
    }

    if h.state_changed {
        if h.in_a {
            let _ = writeln!(out, "-Host is {}.", state(&a.state));
        }
        if h.in_b {
            let _ = writeln!(out, "+Host is {}.", state(&b.state));
        }
    } else if verbose {
        let _ = writeln!(out, " Host is {}.", state(&b.state));
    }

    if h.extraports_changed {
        if !a.extraports.is_empty() {
            let _ = writeln!(out, "-Not shown: {}", a.extraports_string());
        }
        if !b.extraports.is_empty() {
            let _ = writeln!(out, "+Not shown: {}", b.extraports_string());
        }
    } else if verbose && !a.extraports.is_empty() {
        let _ = writeln!(out, " Not shown: {}", a.extraports_string());
    }

    let mut table = Table::new();
    let mark = match (h.in_a, h.in_b) {
        (false, _) => "+",
        (_, false) => "-",
        _ => " ",
    };
    table.cells(
        mark,
        &["PORT", "STATE", "SERVICE", "VERSION"].map(|s| Some(s.to_string())),
    );
    for p in &h.ports {
        let (ca, cb) = (columns(&p.a), columns(&p.b));
        if ca == cb {
            if verbose || !p.scripts.is_empty() {
                table.cells(" ", &ca);
            }
        } else {
            if !a.is_extraports(p.a.state.as_deref()) {
                table.cells("-", &ca);
            }
            if !b.is_extraports(p.b.state.as_deref()) {
                table.cells("+", &cb);
            }
        }
        for s in &p.scripts {
            script_lines(&mut table, s, verbose);
        }
    }
    if table.rows.len() > 1 {
        table.render(out);
    }

    if h.os_changed || verbose {
        match (a.os.is_empty(), b.os.is_empty()) {
            (false, false) => out.push_str(" OS details:\n"),
            (false, true) => out.push_str("-OS details:\n"),
            (true, false) => out.push_str("+OS details:\n"),
            (true, true) => {}
        }
        for &(op, i1, i2, j1, j2) in &h.os {
            if matches!(op, Op::Replace | Op::Delete) {
                for m in &a.os[i1..i2] {
                    let _ = writeln!(out, "-  {m}");
                }
            }
            if matches!(op, Op::Replace | Op::Insert) {
                for m in &b.os[j1..j2] {
                    let _ = writeln!(out, "+  {m}");
                }
            }
            if op == Op::Equal {
                for m in &a.os[i1..i2] {
                    let _ = writeln!(out, "   {m}");
                }
            }
        }
    }

    script_section(
        out,
        "Host script results",
        !a.scripts.is_empty(),
        !b.scripts.is_empty(),
        &h.scripts,
        verbose,
    );
}

pub fn render(d: &ScanDiff) -> String {
    let mut out = String::new();
    let (ba, bb) = (banner(d.a), banner(d.b));
    if ba != bb {
        let _ = writeln!(out, "-{ba}\n+{bb}");
    } else if d.verbose {
        let _ = writeln!(out, " {ba}");
    }
    script_section(
        &mut out,
        "Pre-scan script results",
        !d.a.pre_scripts.is_empty(),
        !d.b.pre_scripts.is_empty(),
        &d.pre_scripts,
        d.verbose,
    );
    for h in d.shown() {
        out.push('\n');
        host(&mut out, h, d.verbose);
    }
    script_section(
        &mut out,
        "Post-scan script results",
        !d.a.post_scripts.is_empty(),
        !d.b.post_scripts.is_empty(),
        &d.post_scripts,
        d.verbose,
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_are_utc() {
        assert_eq!(time_string(0), "Thu Jan 01 00:00:00 1970 UTC");
        assert_eq!(time_string(1_763_289_000), "Sun Nov 16 10:30:00 2025 UTC");
    }

    #[test]
    fn banner_names_the_scanner() {
        let mut s = Scan {
            scanner: Some("feroprobe".into()),
            version: Some("0.5.0".into()),
            args: Some("feroprobe -F 10.0.0.1".into()),
            start: Some(0),
            ..Default::default()
        };
        assert_eq!(
            banner(&s),
            "FeroProbe 0.5.0 scan initiated Thu Jan 01 00:00:00 1970 UTC as: feroprobe -F 10.0.0.1"
        );
        s.scanner = Some("nmap".into());
        s.start = None;
        s.args = None;
        assert_eq!(banner(&s), "Nmap 0.5.0 scan");
    }

    fn scan(port_script: &str, host_script: &str) -> Scan {
        let xml = format!(
            r#"<nmaprun scanner="nmap" version="7.99"><host><status state="up"/>
<address addr="10.0.0.1" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/>{port_script}</port></ports>
<hostscript>{host_script}</hostscript></host></nmaprun>"#
        );
        Scan::parse(&xml).unwrap().0
    }

    #[test]
    fn script_output_changes_are_shown_under_their_port() {
        let a = scan(
            r#"<script id="http-title" output="Welcome"/>"#,
            r#"<script id="smb-os" output="Windows&#10;build 1"/><script id="nbstat" output="NAME"/>"#,
        );
        let b = scan(
            r#"<script id="http-title" output="Login"/>"#,
            r#"<script id="smb-os" output="Windows&#10;build 2"/><script id="nbstat" output="NAME"/>"#,
        );
        let d = crate::diff::ScanDiff::new(&a, &b, false);
        assert_eq!(d.cost, 2);
        assert_eq!(
            render(&d),
            "\n 10.0.0.1:\n PORT   STATE SERVICE VERSION\n 80/tcp open  http\n\
             -|_ http-title: Welcome\n+|_ http-title: Login\n\
             \n Host script results:\n |  smb-os: Windows\n-|_ build 1\n+|_ build 2\n"
        );
        let same = crate::diff::ScanDiff::new(&a, &a, false);
        assert_eq!(same.cost, 0);
        assert_eq!(render(&same), "");
    }

    #[test]
    fn table_lines_up_columns() {
        let mut t = Table::new();
        t.cells(
            " ",
            &["PORT", "STATE", "SERVICE", "VERSION"].map(|s| Some(s.into())),
        );
        t.cells(
            "-",
            &[
                Some("80/tcp".into()),
                Some("open".into()),
                Some("http".into()),
                None,
            ],
        );
        t.cells(
            "+",
            &[
                Some("80/tcp".into()),
                Some("open".into()),
                Some("http".into()),
                Some("nginx 1.24".into()),
            ],
        );
        let mut out = String::new();
        t.render(&mut out);
        assert_eq!(
            out,
            " PORT   STATE SERVICE VERSION\n-80/tcp open  http\n+80/tcp open  http    nginx 1.24\n"
        );
    }
}
