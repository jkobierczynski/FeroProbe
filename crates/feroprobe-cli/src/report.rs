//! Writing the reports as the scan goes: the start of each report before
//! the first host group, each group's hosts as soon as the group is done,
//! and the end after the last one, like nmap. An aborted run so leaves
//! reports of every group it finished, which `--resume` picks up from.
//!
//! JSON is one document, so it is written whole at the end.

use std::io::Write;
use std::time::SystemTime;

use anyhow::{Context, Result};
use feroprobe_core::HostResult;

use crate::output::{self, RunInfo, counted_up};
use crate::{Format, ReportFiles, grep, xml};

/// What a report holds.
#[derive(Clone, Copy)]
pub enum Kind {
    Format(Format),
    /// `-oS`: the normal report, garbled.
    Skid,
}

struct Report {
    kind: Kind,
    /// The file it goes to (opened up front in [`ReportFiles`]), or
    /// standard output.
    path: Option<String>,
}

/// Every report of a run.
pub struct Reports {
    list: Vec<Report>,
    files: ReportFiles,
    /// The hosts so far, for the JSON reports (empty if there are none).
    json: Vec<HostResult>,
    /// Hosts written so far, and how many of them were reported up.
    total: usize,
    up: usize,
    /// `--resume`: the XML document of the aborted run is continued, not
    /// started again.
    resuming: bool,
}

impl Reports {
    pub fn new(resuming: bool, files: ReportFiles) -> Self {
        Reports {
            list: Vec::new(),
            files,
            json: Vec::new(),
            total: 0,
            up: 0,
            resuming,
        }
    }

    /// Add a report, going to `path` or (with `None`) standard output.
    pub fn add(&mut self, kind: Kind, path: Option<String>) {
        self.list.push(Report { kind, path });
    }

    fn write(files: &mut ReportFiles, path: &Option<String>, text: &str) -> Result<()> {
        if text.is_empty() {
            return Ok(());
        }
        match path {
            None => {
                let mut out = std::io::stdout().lock();
                out.write_all(text.as_bytes())
                    .and_then(|()| out.flush())
                    .context("writing to standard output")
            }
            Some(path) => files.write(path, text),
        }
    }

    /// Write the start of every report.
    pub fn start(&mut self, info: &RunInfo) -> Result<()> {
        for r in &self.list {
            // The normal report in an -oN file gets nmap's comment lines
            // first and last instead of the screen's.
            let file = r.path.is_some();
            let text = match r.kind {
                Kind::Format(Format::Table) => output::table_header(info, file),
                Kind::Skid => output::skid(&output::table_header(info, false)),
                Kind::Format(Format::Grepable) => grep::header(info),
                // A resumed file continues the aborted run's document; standard
                // output starts a new one.
                Kind::Format(Format::Xml) if self.resuming && file => String::new(),
                Kind::Format(Format::Xml) => xml::header(info),
                Kind::Format(Format::Json) => String::new(),
            };
            Self::write(&mut self.files, &r.path, &text)?;
        }
        Ok(())
    }

    /// Write a finished host group, scanned from `start` to `end`.
    pub fn group(
        &mut self,
        hosts: &[HostResult],
        info: &RunInfo,
        start: SystemTime,
        end: SystemTime,
    ) -> Result<()> {
        self.total += hosts.len();
        self.up += hosts.iter().filter(|h| counted_up(h, info)).count();
        let mut json = false;
        for r in &self.list {
            let text = match r.kind {
                Kind::Format(Format::Table) => output::table_hosts(hosts, info),
                Kind::Skid => output::skid(&output::table_hosts(hosts, info)),
                Kind::Format(Format::Grepable) => grep::hosts(hosts, info),
                Kind::Format(Format::Xml) => xml::hosts(hosts, info, start, end),
                Kind::Format(Format::Json) => {
                    json = true;
                    String::new()
                }
            };
            Self::write(&mut self.files, &r.path, &text)?;
        }
        if json {
            self.json.extend_from_slice(hosts);
        }
        Ok(())
    }

    /// Write the end of every report, and the JSON ones.
    pub fn finish(&mut self, info: &RunInfo) -> Result<()> {
        let (total, up) = (self.total, self.up);
        for r in &self.list {
            let file = r.path.is_some();
            let text = match r.kind {
                Kind::Format(Format::Table) => output::table_footer(total, up, info, file),
                Kind::Skid => output::skid(&output::table_footer(total, up, info, false)),
                Kind::Format(Format::Grepable) => grep::footer(total, up, info),
                Kind::Format(Format::Xml) => xml::footer(total, up, info),
                Kind::Format(Format::Json) => output::render_json(&self.json, info)?,
            };
            Self::write(&mut self.files, &r.path, &text)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::tests::info;

    fn up(addr: &str) -> HostResult {
        let mut h = HostResult::new(addr.parse().unwrap(), None);
        h.up_reason = Some("echo-reply");
        h
    }

    /// A run cut short after its first group, then resumed: each report
    /// file holds both parts, and the XML document is whole.
    #[test]
    fn group_by_group_then_resumed() {
        let dir = std::env::temp_dir().join(format!("feroprobe-report-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = |name: &str| dir.join(name).to_string_lossy().into_owned();
        let open = |append: bool| {
            let outputs = crate::Outputs {
                xml: vec![path("r.xml")],
                grep: vec![path("r.gnmap")],
                append,
                ..Default::default()
            };
            let mut reports = Reports::new(append, outputs.open_files(None).unwrap());
            for (format, name) in [(Format::Xml, "r.xml"), (Format::Grepable, "r.gnmap")] {
                reports.add(Kind::Format(format), Some(path(name)));
            }
            reports
        };
        let info = info();
        let t = info.start;

        // The aborted run: header and one group, no footer.
        let mut first = open(false);
        first.start(&info).unwrap();
        first.group(&[up("10.0.0.1")], &info, t, t).unwrap();
        drop(first);
        let partial = std::fs::read_to_string(path("r.xml")).unwrap();
        assert!(partial.contains("<address addr=\"10.0.0.1\""));
        assert!(!partial.contains("</nmaprun>"));
        let r = crate::resume::read(&path("r.gnmap")).unwrap();
        assert_eq!(r.last, Some("10.0.0.1".parse().unwrap()));

        // The resumed run appends.
        let mut second = open(true);
        second.start(&info).unwrap();
        second.group(&[up("10.0.0.2")], &info, t, t).unwrap();
        second.finish(&info).unwrap();

        let xml = std::fs::read_to_string(path("r.xml")).unwrap();
        let opts = roxmltree::ParsingOptions {
            allow_dtd: true,
            ..Default::default()
        };
        let doc = roxmltree::Document::parse_with_options(&xml, opts).unwrap();
        let addrs: Vec<&str> = doc
            .descendants()
            .filter(|n| n.has_tag_name("address"))
            .filter_map(|n| n.attribute("addr"))
            .collect();
        assert_eq!(addrs, ["10.0.0.1", "10.0.0.2"]);
        assert_eq!(
            crate::resume::read(&path("r.xml")).unwrap().last,
            Some("10.0.0.2".parse().unwrap())
        );

        let grep = std::fs::read_to_string(path("r.gnmap")).unwrap();
        assert_eq!(grep.matches("scan initiated").count(), 2);
        assert!(grep.ends_with("(1 host up) scanned in 1.50 seconds\n"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
