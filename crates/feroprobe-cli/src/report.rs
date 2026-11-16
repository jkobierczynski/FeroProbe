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

use crate::output::{self, RunInfo, reported};
use crate::{Format, grep, xml};

/// Where one report goes.
enum Sink {
    Stdout,
    File { path: String, file: std::fs::File },
}

struct Report {
    format: Format,
    /// The normal report in an `-oN` file, with nmap's comment lines first
    /// and last instead of the screen's.
    file_layout: bool,
    sink: Sink,
}

/// Every report of a run.
pub struct Reports {
    list: Vec<Report>,
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
    pub fn new(resuming: bool) -> Self {
        Reports {
            list: Vec::new(),
            json: Vec::new(),
            total: 0,
            up: 0,
            resuming,
        }
    }

    /// Add a report going to standard output.
    pub fn stdout(&mut self, format: Format) {
        self.list.push(Report {
            format,
            file_layout: false,
            sink: Sink::Stdout,
        });
    }

    /// Add a report going to an open file.
    pub fn file(&mut self, format: Format, path: String, file: std::fs::File) {
        self.list.push(Report {
            format,
            file_layout: true,
            sink: Sink::File { path, file },
        });
    }

    fn write(sink: &mut Sink, text: &str) -> Result<()> {
        if text.is_empty() {
            return Ok(());
        }
        match sink {
            Sink::Stdout => {
                let mut out = std::io::stdout().lock();
                out.write_all(text.as_bytes())
                    .and_then(|()| out.flush())
                    .context("writing to standard output")
            }
            Sink::File { path, file } => file
                .write_all(text.as_bytes())
                .and_then(|()| file.flush())
                .with_context(|| format!("writing {path}")),
        }
    }

    /// Write the start of every report.
    pub fn start(&mut self, info: &RunInfo) -> Result<()> {
        for r in &mut self.list {
            let text = match r.format {
                Format::Table => output::table_header(info, r.file_layout),
                Format::Grepable => grep::header(info),
                Format::Xml if self.resuming => String::new(),
                Format::Xml => xml::header(info),
                Format::Json => String::new(),
            };
            Self::write(&mut r.sink, &text)?;
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
        self.up += hosts.iter().filter(|h| reported(h, info)).count();
        let mut json = false;
        for r in &mut self.list {
            let text = match r.format {
                Format::Table => output::table_hosts(hosts, info),
                Format::Grepable => grep::hosts(hosts, info),
                Format::Xml => xml::hosts(hosts, info, start, end),
                Format::Json => {
                    json = true;
                    String::new()
                }
            };
            Self::write(&mut r.sink, &text)?;
        }
        if json {
            self.json.extend_from_slice(hosts);
        }
        Ok(())
    }

    /// Write the end of every report, and the JSON ones.
    pub fn finish(&mut self, info: &RunInfo) -> Result<()> {
        let (total, up) = (self.total, self.up);
        for r in &mut self.list {
            let text = match r.format {
                Format::Table => output::table_footer(total, up, info, r.file_layout),
                Format::Grepable => grep::footer(total, up, info),
                Format::Xml => xml::footer(total, up, info),
                Format::Json => output::render_json(&self.json, info)?,
            };
            Self::write(&mut r.sink, &text)?;
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
        let open = |name: &str, append: bool| {
            std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .append(append)
                .truncate(!append)
                .open(path(name))
                .unwrap()
        };
        let info = info();
        let t = info.start;

        // The aborted run: header and one group, no footer.
        let mut first = Reports::new(false);
        for (format, name) in [(Format::Xml, "r.xml"), (Format::Grepable, "r.gnmap")] {
            first.file(format, path(name), open(name, false));
        }
        first.start(&info).unwrap();
        first.group(&[up("10.0.0.1")], &info, t, t).unwrap();
        drop(first);
        let partial = std::fs::read_to_string(path("r.xml")).unwrap();
        assert!(partial.contains("<address addr=\"10.0.0.1\""));
        assert!(!partial.contains("</nmaprun>"));
        let r = crate::resume::read(&path("r.gnmap")).unwrap();
        assert_eq!(r.last, Some("10.0.0.1".parse().unwrap()));

        // The resumed run appends.
        let mut second = Reports::new(true);
        for (format, name) in [(Format::Xml, "r.xml"), (Format::Grepable, "r.gnmap")] {
            second.file(format, path(name), open(name, true));
        }
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
