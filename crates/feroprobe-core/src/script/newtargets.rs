//! Hosts that scripts add to the scan (nmap's `newtargets`), and the name
//! lookups scripts may make (`nmap.resolve`).
//!
//! A script adds a host with `fero.add_targets` (the NSE layer's
//! `target.add` and `nmap.add_targets` call it). As in nmap, a target is
//! any target expression (an address, a name, a range), each distinct
//! string is queued once per run, and adding is refused after the scan,
//! in the postrule phase. Whether a script may add at all is up to the
//! caller: the `newtargets` script argument, checked in the `target`
//! module and the built-in scripts, as nmap does. The CLI scans the
//! queued targets after the ones on the command line.

use std::collections::{HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;

use mlua::{Lua, MultiValue, Table, Value};

/// The longest target string nmap accepts (`NewTargets::insert`).
const MAX_TARGET_LEN: usize = 1023;

/// The run's queue of script-added targets.
#[derive(Debug, Default)]
pub struct NewTargets {
    inner: Mutex<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    /// Every target ever added, so each is queued once.
    history: HashSet<String>,
    queue: VecDeque<String>,
}

/// Why [`NewTargets::insert`] refused a target.
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    PostScan,
    TooLong,
}

impl NewTargets {
    /// Queues `target` unless it was added before. Ok(true) when it is
    /// new, Ok(false) when it was already added (which nmap still counts
    /// as added). An empty string adds nothing.
    pub fn insert(&self, target: &str, post_scan: bool) -> Result<bool, Refused> {
        if target.is_empty() {
            return Ok(false);
        }
        if post_scan {
            return Err(Refused::PostScan);
        }
        if target.len() > MAX_TARGET_LEN {
            return Err(Refused::TooLong);
        }
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.history.insert(target.to_string()) {
            inner.queue.push_back(target.to_string());
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Targets waiting to be scanned.
    pub fn queued(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .queue
            .len()
    }

    /// Distinct targets added during the run.
    pub fn total(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .history
            .len()
    }

    /// Takes every queued target, in the order they were added.
    pub fn take(&self) -> Vec<String> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .queue
            .drain(..)
            .collect()
    }
}

/// The addresses `name` resolves to through the system resolver, in its
/// order, each once; only IPv4 ones for `inet`, IPv6 ones for `inet6`.
pub async fn resolve(name: &str, family: Family) -> std::io::Result<Vec<IpAddr>> {
    let mut out: Vec<IpAddr> = Vec::new();
    for sa in tokio::net::lookup_host((name, 0)).await? {
        let ip = sa.ip();
        let wanted = match family {
            Family::Inet => ip.is_ipv4(),
            Family::Inet6 => ip.is_ipv6(),
            Family::Unspec => true,
        };
        if wanted && !out.contains(&ip) {
            out.push(ip);
        }
    }
    Ok(out)
}

/// nmap.resolve's address family argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Inet,
    Inet6,
    Unspec,
}

impl Family {
    fn parse(s: Option<&str>) -> Option<Family> {
        match s {
            None | Some("unspec") => Some(Family::Unspec),
            Some("inet") => Some(Family::Inet),
            Some("inet6") => Some(Family::Inet6),
            Some(_) => None,
        }
    }
}

/// Installs `fero.resolve`, `fero.add_targets` and `fero.new_targets_num`
/// in a state that runs a rule or action (`kind` is its SCRIPT_TYPE), and
/// sets `fero.address_family` to `inet6` for scripts without a host in a
/// `-6` run.
pub(crate) fn install(
    lua: &Lua,
    targets: &std::sync::Arc<NewTargets>,
    kind: &str,
    ipv6: bool,
) -> mlua::Result<()> {
    let fero: Table = lua.globals().raw_get("fero")?;
    // Scripts without a host see the run's address family (-6).
    if ipv6 && matches!(kind, "prerule" | "postrule") {
        fero.raw_set("address_family", "inet6")?;
    }
    // fero.resolve(name [, family]) -> true, { addresses } | false, message
    fero.raw_set(
        "resolve",
        lua.create_async_function(|lua, (name, family): (String, Option<String>)| async move {
            let Some(fam) = Family::parse(family.as_deref()) else {
                return Err(mlua::Error::runtime(format!(
                    "bad argument #2 to 'resolve' (invalid option '{}')",
                    family.unwrap_or_default()
                )));
            };
            let mut out = MultiValue::new();
            match resolve(&name, fam).await {
                Ok(addrs) if !addrs.is_empty() => {
                    let list = lua.create_sequence_from(addrs.iter().map(|a| a.to_string()))?;
                    out.push_back(Value::Boolean(true));
                    out.push_back(Value::Table(list));
                }
                _ => {
                    out.push_back(Value::Boolean(false));
                    out.push_back(Value::String(lua.create_string("Failed to resolve")?));
                }
            }
            Ok(out)
        })?,
    )?;
    // fero.add_targets(t1, t2, ...) -> count | 0, message; with no
    // arguments the number of targets waiting in the queue.
    let post_scan = kind == "postrule";
    {
        let targets = targets.clone();
        fero.raw_set(
            "add_targets",
            lua.create_function(move |lua, args: MultiValue| {
                let mut out = MultiValue::new();
                if args.is_empty() {
                    out.push_back(Value::Integer(targets.queued() as i64));
                    return Ok(out);
                }
                let mut added = 0i64;
                let mut why = None;
                for (i, v) in args.iter().enumerate() {
                    let s = match v {
                        Value::String(s) => s.to_str()?.to_string(),
                        Value::Integer(n) => n.to_string(),
                        Value::Number(n) => n.to_string(),
                        _ => {
                            return Err(mlua::Error::runtime(format!(
                                "bad argument #{} to 'add_targets' (string expected)",
                                i + 1
                            )));
                        }
                    };
                    match targets.insert(&s, post_scan) {
                        Ok(_) => added += 1,
                        Err(e) => {
                            why = Some(e);
                            break;
                        }
                    }
                }
                out.push_back(Value::Integer(added));
                if added == 0 {
                    let msg = match why {
                        Some(Refused::PostScan) => {
                            "adding targets is disabled in the postrule phase"
                        }
                        Some(Refused::TooLong) => {
                            "new target is too long (1024 characters or more)"
                        }
                        None => "failed to add new targets",
                    };
                    out.push_back(Value::String(lua.create_string(msg)?));
                }
                Ok(out)
            })?,
        )?;
    }
    {
        let targets = targets.clone();
        fero.raw_set(
            "new_targets_num",
            lua.create_function(move |_, ()| Ok(targets.total() as i64))?,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_target_queued_once_and_none_after_the_scan() {
        let t = NewTargets::default();
        assert_eq!(t.insert("10.0.0.1", false), Ok(true));
        assert_eq!(t.insert("10.0.0.1", false), Ok(false));
        assert_eq!(t.insert("", false), Ok(false));
        assert_eq!(t.insert("10.0.0.2", true), Err(Refused::PostScan));
        assert_eq!(t.insert(&"a".repeat(1024), false), Err(Refused::TooLong));
        assert_eq!((t.queued(), t.total()), (1, 1));
        assert_eq!(t.take(), vec!["10.0.0.1".to_string()]);
        assert_eq!((t.queued(), t.total()), (0, 1));
        assert_eq!(
            t.insert("10.0.0.1", false),
            Ok(false),
            "kept in the history"
        );
    }

    #[tokio::test]
    async fn resolves_names_by_family() {
        let all = resolve("localhost", Family::Unspec).await.unwrap();
        assert!(all.iter().any(|a| a.is_loopback()), "{all:?}");
        let v4 = resolve("127.0.0.1", Family::Inet).await.unwrap();
        assert_eq!(v4, vec!["127.0.0.1".parse::<IpAddr>().unwrap()]);
        assert!(
            resolve("127.0.0.1", Family::Inet6)
                .await
                .unwrap()
                .is_empty()
        );
    }
}
