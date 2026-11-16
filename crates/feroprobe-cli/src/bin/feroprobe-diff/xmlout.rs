//! The XML comparison, in ndiff's document layout (`<nmapdiff>`,
//! `<scandiff>`, `<hostdiff>`, `<portdiff>`): the scan report's own
//! elements, with `<a>` around what only the first scan has and `<b>`
//! around what only the second has.

use std::fmt::Write;

use crate::diff::{HostDiff, Op, PortDiff, ScanDiff, ScriptDiff};
use crate::scan::{Address, Host, Port, Scan, Script, Service};
use crate::text::time_string;

/// The version of this document layout (ndiff's is 1).
const NDIFF_XML_VERSION: &str = "1";

/// Escape text for an attribute value. Line breaks and tabs are escaped
/// too, so multi-line script output keeps its lines.
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\n' => out.push_str("&#10;"),
            '\r' => out.push_str("&#13;"),
            '\t' => out.push_str("&#9;"),
            c => out.push(c),
        }
    }
    out
}

/// `<tag a="1" b="2"` for the attributes that are set.
fn open(x: &mut String, tag: &str, attrs: &[(&str, Option<&str>)]) {
    let _ = write!(x, "<{tag}");
    for (k, v) in attrs {
        if let Some(v) = v {
            let _ = write!(x, " {k}=\"{}\"", esc(v));
        }
    }
}

fn wrap(x: &mut String, tag: &str, inner: impl FnOnce(&mut String)) {
    let _ = writeln!(x, "<{tag}>");
    inner(x);
    let _ = writeln!(x, "</{tag}>");
}

fn nmaprun(x: &mut String, s: &Scan) {
    let start = s.start.map(|t| t.to_string());
    let startstr = s.start.map(time_string);
    open(
        x,
        "nmaprun",
        &[
            ("scanner", s.scanner.as_deref()),
            ("args", s.args.as_deref()),
            ("start", start.as_deref()),
            ("startstr", startstr.as_deref()),
            ("version", s.version.as_deref()),
        ],
    );
    x.push_str("/>\n");
}

fn status(x: &mut String, state: Option<&str>) {
    if let Some(s) = state {
        let _ = writeln!(x, "<status state=\"{}\"/>", esc(s));
    }
}

fn address(x: &mut String, a: &Address) {
    let _ = writeln!(
        x,
        "<address addr=\"{}\" addrtype=\"{}\"/>",
        esc(&a.to_string()),
        a.kind()
    );
}

fn hostname(x: &mut String, n: &str) {
    let _ = writeln!(x, "<hostname name=\"{}\"/>", esc(n));
}

fn extraports(x: &mut String, h: &Host) {
    for (state, n) in &h.extraports {
        let _ = writeln!(x, "<extraports state=\"{}\" count=\"{n}\"/>", esc(state));
    }
}

fn service(x: &mut String, s: &Service) {
    if s.is_empty() {
        return;
    }
    open(
        x,
        "service",
        &[
            ("name", s.name.as_deref()),
            ("product", s.product.as_deref()),
            ("version", s.version.as_deref()),
            ("extrainfo", s.extrainfo.as_deref()),
            ("tunnel", s.tunnel.as_deref()),
        ],
    );
    x.push_str("/>\n");
}

fn script(x: &mut String, s: &Script) {
    let _ = writeln!(
        x,
        "<script id=\"{}\" output=\"{}\"/>",
        esc(&s.id),
        esc(&s.output)
    );
}

fn osmatch(x: &mut String, name: &str) {
    let _ = writeln!(x, "<osmatch name=\"{}\"/>", esc(name));
}

fn port_open(x: &mut String, p: &Port) {
    let _ = writeln!(
        x,
        "<port portid=\"{}\" protocol=\"{}\">",
        p.spec.0,
        esc(&p.spec.1)
    );
    if let Some(s) = &p.state {
        let _ = writeln!(x, "<state state=\"{}\"/>", esc(s));
    }
}

fn port(x: &mut String, p: &Port) {
    if p.state.is_none() && p.service.is_empty() && p.scripts.is_empty() {
        // Not in this scan's port list.
        let _ = writeln!(
            x,
            "<port portid=\"{}\" protocol=\"{}\"/>",
            p.spec.0,
            esc(&p.spec.1)
        );
        return;
    }
    port_open(x, p);
    service(x, &p.service);
    for s in &p.scripts {
        script(x, s);
    }
    x.push_str("</port>\n");
}

/// A whole host, for a host only one scan has.
fn host(x: &mut String, h: &Host) {
    wrap(x, "host", |x| {
        status(x, h.state.as_deref());
        for a in &h.addresses {
            address(x, a);
        }
        if !h.hostnames.is_empty() {
            wrap(x, "hostnames", |x| {
                for n in &h.hostnames {
                    hostname(x, n);
                }
            });
        }
        let listed: Vec<&Port> = h
            .ports
            .values()
            .filter(|p| !h.is_extraports(p.state.as_deref()))
            .collect();
        if !h.extraports.is_empty() || !listed.is_empty() {
            wrap(x, "ports", |x| {
                extraports(x, h);
                for p in listed {
                    port(x, p);
                }
            });
        }
        if !h.os.is_empty() {
            wrap(x, "os", |x| {
                for m in &h.os {
                    osmatch(x, m);
                }
            });
        }
        if !h.scripts.is_empty() {
            wrap(x, "hostscript", |x| {
                for s in &h.scripts {
                    script(x, s);
                }
            });
        }
    });
}

fn script_diff(x: &mut String, d: &ScriptDiff) {
    if !d.changed()
        && let Some(s) = &d.a
    {
        script(x, s);
        return;
    }
    if let Some(s) = &d.a {
        wrap(x, "a", |x| script(x, s));
    }
    if let Some(s) = &d.b {
        wrap(x, "b", |x| script(x, s));
    }
}

/// A `<prescript>`-style block: whole in `<a>` or `<b>` when only one scan
/// has results, else the results with their differences marked.
fn script_block(x: &mut String, tag: &str, a: &[Script], b: &[Script], diffs: &[ScriptDiff]) {
    match (a.is_empty(), b.is_empty()) {
        (true, true) => {}
        (false, true) => wrap(x, "a", |x| {
            wrap(x, tag, |x| a.iter().for_each(|s| script(x, s)));
        }),
        (true, false) => wrap(x, "b", |x| {
            wrap(x, tag, |x| b.iter().for_each(|s| script(x, s)));
        }),
        (false, false) => wrap(x, tag, |x| diffs.iter().for_each(|d| script_diff(x, d))),
    }
}

fn port_diff(x: &mut String, d: &PortDiff) {
    wrap(x, "portdiff", |x| {
        if d.a.state == d.b.state {
            port_open(x, &d.a);
            if d.a.service == d.b.service {
                service(x, &d.a.service);
            } else {
                wrap(x, "a", |x| service(x, &d.a.service));
                wrap(x, "b", |x| service(x, &d.b.service));
            }
            for s in &d.scripts {
                script_diff(x, s);
            }
            x.push_str("</port>\n");
        } else {
            wrap(x, "a", |x| port(x, &d.a));
            wrap(x, "b", |x| port(x, &d.b));
        }
    });
}

/// Items in both lists plain, then `<a>` for those only in `a`, `<b>` for
/// those only in `b`.
fn split<T: Ord + Clone>(x: &mut String, a: &[T], b: &[T], each: impl Fn(&mut String, &T)) {
    let mut a: Vec<T> = a.to_vec();
    let mut b: Vec<T> = b.to_vec();
    a.sort();
    b.sort();
    for v in a.iter().filter(|v| b.contains(v)) {
        each(x, v);
    }
    let only_a: Vec<&T> = a.iter().filter(|v| !b.contains(v)).collect();
    let only_b: Vec<&T> = b.iter().filter(|v| !a.contains(v)).collect();
    if !only_a.is_empty() {
        wrap(x, "a", |x| only_a.iter().for_each(|v| each(x, v)));
    }
    if !only_b.is_empty() {
        wrap(x, "b", |x| only_b.iter().for_each(|v| each(x, v)));
    }
}

fn host_diff(x: &mut String, d: &HostDiff, verbose: bool) {
    wrap(x, "hostdiff", |x| {
        if !d.in_a || !d.in_b {
            // In one scan only: the whole host.
            let (tag, h) = if d.in_a { ("a", &d.a) } else { ("b", &d.b) };
            wrap(x, tag, |x| host(x, h));
            return;
        }
        let (a, b) = (&d.a, &d.b);
        wrap(x, "host", |x| {
            if a.state != b.state {
                wrap(x, "a", |x| status(x, a.state.as_deref()));
                wrap(x, "b", |x| status(x, b.state.as_deref()));
            } else if verbose {
                status(x, a.state.as_deref());
            }
            split(x, &a.addresses, &b.addresses, address);

            let mut names = String::new();
            split(&mut names, &a.hostnames, &b.hostnames, |x, n| {
                hostname(x, n)
            });
            if !names.is_empty() {
                wrap(x, "hostnames", |x| x.push_str(&names));
            }

            let mut ports = String::new();
            if a.extraports == b.extraports {
                extraports(&mut ports, a);
            } else {
                wrap(&mut ports, "a", |x| extraports(x, a));
                wrap(&mut ports, "b", |x| extraports(x, b));
            }
            for p in &d.ports {
                if p.cost == 0 {
                    if verbose {
                        port(&mut ports, &p.a);
                    }
                } else {
                    port_diff(&mut ports, p);
                }
            }
            if !ports.is_empty() {
                wrap(x, "ports", |x| x.push_str(&ports));
            }

            if d.os_changed || verbose {
                let mut os = String::new();
                for &(op, i1, i2, j1, j2) in &d.os {
                    if matches!(op, Op::Replace | Op::Delete) {
                        wrap(&mut os, "a", |x| {
                            a.os[i1..i2].iter().for_each(|m| osmatch(x, m))
                        });
                    }
                    if matches!(op, Op::Replace | Op::Insert) {
                        wrap(&mut os, "b", |x| {
                            b.os[j1..j2].iter().for_each(|m| osmatch(x, m))
                        });
                    }
                    if op == Op::Equal {
                        a.os[i1..i2].iter().for_each(|m| osmatch(&mut os, m));
                    }
                }
                if !os.is_empty() {
                    wrap(x, "os", |x| x.push_str(&os));
                }
            }

            if d.scripts.iter().any(ScriptDiff::changed) || verbose {
                script_block(x, "hostscript", &a.scripts, &b.scripts, &d.scripts);
            }
        });
    });
}

pub fn render(d: &ScanDiff) -> String {
    let mut x = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    let _ = writeln!(x, "<nmapdiff version=\"{NDIFF_XML_VERSION}\">");
    wrap(&mut x, "scandiff", |x| {
        if d.run_changed {
            wrap(x, "a", |x| nmaprun(x, d.a));
            wrap(x, "b", |x| nmaprun(x, d.b));
        } else if d.verbose {
            nmaprun(x, d.a);
        }
        if d.pre_scripts.iter().any(ScriptDiff::changed) || d.verbose {
            script_block(
                x,
                "prescript",
                &d.a.pre_scripts,
                &d.b.pre_scripts,
                &d.pre_scripts,
            );
        }
        for h in d.shown() {
            host_diff(x, h, d.verbose);
        }
        if d.post_scripts.iter().any(ScriptDiff::changed) || d.verbose {
            script_block(
                x,
                "postscript",
                &d.a.post_scripts,
                &d.b.post_scripts,
                &d.post_scripts,
            );
        }
    });
    x.push_str("</nmapdiff>\n");
    x
}
