//! What changed between two scans: host by host, port by port, as ndiff
//! compares them. Hosts are paired by address and ports by number and
//! protocol; each difference adds to a cost, and a cost of 0 means the scans
//! are the same in everything compared.

use crate::scan::{Host, Port, Scan, Script};

/// One step of an edit script between two sequences.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Equal,
    Delete,
    Insert,
    Replace,
}

/// The largest LCS table (cells) built for one comparison. Script outputs
/// differing in many scattered lines beyond this are shown as one
/// replaced block instead of a line-by-line diff.
const MAX_LCS_CELLS: usize = 4_000_000;

/// An edit script turning `a` into `b`: `(op, a_start, a_end, b_start,
/// b_end)` steps over a longest common subsequence, with a delete next to an
/// insert merged into a replace. The common start and end are matched
/// first, so only the part that differs needs the LCS table.
pub fn opcodes<T: PartialEq>(a: &[T], b: &[T]) -> Vec<(Op, usize, usize, usize, usize)> {
    let pre = a.iter().zip(b).take_while(|(x, y)| x == y).count();
    let suf = a[pre..]
        .iter()
        .rev()
        .zip(b[pre..].iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    let (am, bm) = (&a[pre..a.len() - suf], &b[pre..b.len() - suf]);
    let mut ops = Vec::new();
    if pre > 0 {
        ops.push((Op::Equal, 0, pre, 0, pre));
    }
    let middle = if am.len().saturating_mul(bm.len()) > MAX_LCS_CELLS {
        vec![(Op::Replace, 0, am.len(), 0, bm.len())]
    } else {
        lcs_opcodes(am, bm)
    };
    ops.extend(
        middle
            .into_iter()
            .map(|(op, i1, i2, j1, j2)| (op, i1 + pre, i2 + pre, j1 + pre, j2 + pre)),
    );
    if suf > 0 {
        ops.push((Op::Equal, a.len() - suf, a.len(), b.len() - suf, b.len()));
    }
    ops
}

fn lcs_opcodes<T: PartialEq>(a: &[T], b: &[T]) -> Vec<(Op, usize, usize, usize, usize)> {
    let (n, m) = (a.len(), b.len());
    // lcs[i][j]: length of the longest common subsequence of a[i..], b[j..].
    let mut lcs = vec![vec![0usize; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let mut ops: Vec<(Op, usize, usize, usize, usize)> = Vec::new();
    let (mut i, mut j) = (0, 0);
    let (mut di, mut dj) = (0, 0);
    let flush = |ops: &mut Vec<_>, i: usize, j: usize, di: usize, dj: usize| {
        let op = match (i > di, j > dj) {
            (true, true) => Op::Replace,
            (true, false) => Op::Delete,
            (false, true) => Op::Insert,
            (false, false) => return,
        };
        ops.push((op, di, i, dj, j));
    };
    while i < n || j < m {
        if i < n && j < m && a[i] == b[j] {
            flush(&mut ops, i, j, di, dj);
            let (si, sj) = (i, j);
            while i < n && j < m && a[i] == b[j] {
                i += 1;
                j += 1;
            }
            ops.push((Op::Equal, si, i, sj, j));
            (di, dj) = (i, j);
        } else if j < m && (i == n || lcs[i][j + 1] >= lcs[i + 1][j]) {
            j += 1;
        } else {
            i += 1;
        }
    }
    flush(&mut ops, i, j, di, dj);
    ops
}

/// A script result in either scan, or both.
#[derive(Debug, Clone)]
pub struct ScriptDiff {
    pub a: Option<Script>,
    pub b: Option<Script>,
}

impl ScriptDiff {
    pub fn changed(&self) -> bool {
        self.a != self.b
    }
}

/// Pairs script results by id (both lists sorted). Unchanged results are
/// kept only when `verbose`.
pub fn diff_scripts(a: &[Script], b: &[Script], verbose: bool) -> Vec<ScriptDiff> {
    let mut out = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        let pick = match (a.get(i), b.get(j)) {
            (Some(x), Some(y)) => x.id.cmp(&y.id),
            (Some(_), None) => std::cmp::Ordering::Less,
            _ => std::cmp::Ordering::Greater,
        };
        match pick {
            std::cmp::Ordering::Less => {
                out.push(ScriptDiff {
                    a: Some(a[i].clone()),
                    b: None,
                });
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                out.push(ScriptDiff {
                    a: None,
                    b: Some(b[j].clone()),
                });
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                if a[i].output != b[j].output || verbose {
                    out.push(ScriptDiff {
                        a: Some(a[i].clone()),
                        b: Some(b[j].clone()),
                    });
                }
                i += 1;
                j += 1;
            }
        }
    }
    out
}

fn script_cost(d: &[ScriptDiff]) -> usize {
    d.iter().filter(|s| s.changed()).count()
}

/// One port in both scans. A port missing from a scan is an empty one
/// (no state, no service).
#[derive(Debug, Clone)]
pub struct PortDiff {
    pub a: Port,
    pub b: Port,
    pub scripts: Vec<ScriptDiff>,
    pub cost: usize,
}

impl PortDiff {
    fn new(a: Port, b: Port, verbose: bool) -> PortDiff {
        let scripts = diff_scripts(&a.scripts, &b.scripts, verbose);
        // The service compares with its SSL tunnel: http becoming ssl/http
        // is a change (ndiff leaves the tunnel out).
        let cost = usize::from(a.state != b.state)
            + usize::from(a.service != b.service)
            + script_cost(&scripts);
        PortDiff {
            a,
            b,
            scripts,
            cost,
        }
    }
}

/// One host in both scans. A host missing from a scan is an empty one and
/// `in_a`/`in_b` say which scans have it.
#[derive(Debug, Clone)]
pub struct HostDiff {
    pub a: Host,
    pub b: Host,
    pub in_a: bool,
    pub in_b: bool,
    pub state_changed: bool,
    pub id_changed: bool,
    pub extraports_changed: bool,
    /// The ports to show: changed ones, and every listed one when verbose.
    pub ports: Vec<PortDiff>,
    pub os: Vec<(Op, usize, usize, usize, usize)>,
    pub os_changed: bool,
    pub scripts: Vec<ScriptDiff>,
    pub cost: usize,
}

impl HostDiff {
    fn new(a: Option<&Host>, b: Option<&Host>, verbose: bool) -> HostDiff {
        let (in_a, in_b) = (a.is_some(), b.is_some());
        let a = a.cloned().unwrap_or_default();
        let b = b.cloned().unwrap_or_default();
        let mut cost = 0;
        let state_changed = in_a != in_b || a.state != b.state;
        cost += usize::from(state_changed);

        fn set<T: Ord>(v: &[T]) -> std::collections::BTreeSet<&T> {
            v.iter().collect()
        }
        let id_changed =
            set(&a.addresses) != set(&b.addresses) || set(&a.hostnames) != set(&b.hostnames);
        cost += usize::from(id_changed);

        let mut specs: Vec<_> = a.ports.keys().chain(b.ports.keys()).cloned().collect();
        specs.sort();
        specs.dedup();
        let mut ports = Vec::new();
        for spec in specs {
            let pa = a
                .ports
                .get(&spec)
                .cloned()
                .unwrap_or_else(|| Port::empty(spec.clone()));
            let pb = b
                .ports
                .get(&spec)
                .cloned()
                .unwrap_or_else(|| Port::empty(spec.clone()));
            let d = PortDiff::new(pa, pb, verbose);
            // A port both reports fold into "Not shown" is not compared on
            // its own: the extraports counts cover it.
            if a.is_extraports(d.a.state.as_deref()) && b.is_extraports(d.b.state.as_deref()) {
                continue;
            }
            if d.cost > 0 || verbose {
                cost += d.cost;
                ports.push(d);
            }
        }

        let os = opcodes(&a.os, &b.os);
        let os_cost = os.iter().filter(|o| o.0 != Op::Equal).count();
        cost += os_cost;

        let extraports_changed = a.extraports != b.extraports;
        cost += usize::from(extraports_changed);

        let scripts = diff_scripts(&a.scripts, &b.scripts, verbose);
        cost += script_cost(&scripts);

        HostDiff {
            a,
            b,
            in_a,
            in_b,
            state_changed,
            id_changed,
            extraports_changed,
            ports,
            os,
            os_changed: os_cost > 0,
            scripts,
            cost,
        }
    }
}

/// The whole comparison.
#[derive(Debug, Clone)]
pub struct ScanDiff<'s> {
    pub a: &'s Scan,
    pub b: &'s Scan,
    pub verbose: bool,
    /// Whether the run details (scanner, version, command, times) differ.
    pub run_changed: bool,
    pub pre_scripts: Vec<ScriptDiff>,
    /// Every host pair; those to show are `shown()`.
    pub hosts: Vec<HostDiff>,
    pub post_scripts: Vec<ScriptDiff>,
    pub cost: usize,
}

impl<'s> ScanDiff<'s> {
    pub fn new(a: &'s Scan, b: &'s Scan, verbose: bool) -> ScanDiff<'s> {
        let mut ha: Vec<&Host> = a.hosts.iter().collect();
        let mut hb: Vec<&Host> = b.hosts.iter().collect();
        ha.sort_by_key(|h| h.key());
        hb.sort_by_key(|h| h.key());
        let mut hosts = Vec::new();
        let (mut i, mut j) = (0, 0);
        while i < ha.len() || j < hb.len() {
            let order = match (ha.get(i), hb.get(j)) {
                (Some(x), Some(y)) => x.key().cmp(&y.key()),
                (Some(_), None) => std::cmp::Ordering::Less,
                _ => std::cmp::Ordering::Greater,
            };
            let (x, y) = match order {
                std::cmp::Ordering::Less => {
                    i += 1;
                    (Some(ha[i - 1]), None)
                }
                std::cmp::Ordering::Greater => {
                    j += 1;
                    (None, Some(hb[j - 1]))
                }
                std::cmp::Ordering::Equal => {
                    i += 1;
                    j += 1;
                    (Some(ha[i - 1]), Some(hb[j - 1]))
                }
            };
            hosts.push(HostDiff::new(x, y, verbose));
        }
        let pre_scripts = diff_scripts(&a.pre_scripts, &b.pre_scripts, verbose);
        let post_scripts = diff_scripts(&a.post_scripts, &b.post_scripts, verbose);
        // Pre- and post-scan script changes count too (ndiff prints them
        // but leaves them out of its exit status).
        let cost = hosts.iter().map(|h| h.cost).sum::<usize>()
            + script_cost(&pre_scripts)
            + script_cost(&post_scripts);
        let run_changed = a.scanner != b.scanner
            || a.version != b.version
            || a.args != b.args
            || a.start != b.start
            || a.end != b.end;
        ScanDiff {
            a,
            b,
            verbose,
            run_changed,
            pre_scripts,
            hosts,
            post_scripts,
            cost,
        }
    }

    /// The hosts to report: those that changed, or all when verbose.
    pub fn shown(&self) -> impl Iterator<Item = &HostDiff> {
        self.hosts.iter().filter(|h| h.cost > 0 || self.verbose)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcodes_cover_both_sequences() {
        let a = ["Linux 5.x", "Linux 4.x", "FreeBSD"];
        let b = ["Linux 6.x", "Linux 4.x", "FreeBSD", "OpenBSD"];
        assert_eq!(
            opcodes(&a, &b),
            [
                (Op::Replace, 0, 1, 0, 1),
                (Op::Equal, 1, 3, 1, 3),
                (Op::Insert, 3, 3, 3, 4)
            ]
        );
        assert_eq!(opcodes::<&str>(&[], &[]), []);
        assert_eq!(opcodes(&["x"], &[]), [(Op::Delete, 0, 1, 0, 0)]);
        assert_eq!(opcodes(&["x"], &["x"]), [(Op::Equal, 0, 1, 0, 1)]);
        assert_eq!(
            opcodes(&["p", "a", "s"], &["p", "b", "s"]),
            [
                (Op::Equal, 0, 1, 0, 1),
                (Op::Replace, 1, 2, 1, 2),
                (Op::Equal, 2, 3, 2, 3)
            ]
        );
    }

    #[test]
    fn huge_scattered_differences_stay_bounded() {
        let a: Vec<u32> = (0..3000).map(|i| i * 2).collect();
        let b: Vec<u32> = (0..3000).map(|i| i * 2 + 1).collect();
        assert_eq!(opcodes(&a, &b), [(Op::Replace, 0, 3000, 0, 3000)]);
    }

    #[test]
    fn scripts_pair_by_id() {
        let s = |id: &str, out: &str| Script {
            id: id.into(),
            output: out.into(),
        };
        let a = [s("a", "1"), s("b", "2")];
        let b = [s("b", "3"), s("c", "4")];
        let d = diff_scripts(&a, &b, false);
        assert_eq!(d.len(), 3);
        assert!(d.iter().all(ScriptDiff::changed));
        assert!(diff_scripts(&a, &a, false).is_empty());
        assert_eq!(diff_scripts(&a, &a, true).len(), 2);
    }
}
