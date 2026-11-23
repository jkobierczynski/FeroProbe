//! `fero.registry` and `fero.host_registry`: values scripts leave for
//! other scripts, as nmap's `nmap.registry` and `host.registry`.
//!
//! Every script run has a Lua state of its own, so the registry lives
//! here, outside them all, and holds copies: `set` and `append` copy a
//! value in, `get` copies it out. Only plain data is kept (nil, booleans,
//! numbers, strings and tables of them), never functions or userdata, so
//! nothing can run in another script's state. A script that needs another
//! one's values names it in `dependencies`, so that it runs after it.
//!
//! The run-wide registry is shared by every script of the run, the
//! prerule and postrule ones included; each host has one more, for the
//! scripts that run against it.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use mlua::{Lua, Table, Value};

/// Deepest table nesting a stored value may have.
const MAX_DEPTH: usize = 32;
/// Most bytes all stored values may take together (strings counted in
/// full, every other value and table entry as 16 bytes).
pub(crate) const MAX_BYTES: usize = 16 * 1024 * 1024;
/// What each entry costs on top of its strings.
const ENTRY_COST: usize = 16;

/// A key in a stored table.
#[derive(Debug, Clone, PartialEq)]
enum Key {
    Int(i64),
    Num(f64),
    Bool(bool),
    Str(Vec<u8>),
}

/// A stored value.
#[derive(Debug, Clone, PartialEq)]
enum Stored {
    Bool(bool),
    Int(i64),
    Num(f64),
    Str(Vec<u8>),
    Table(Vec<(Key, Stored)>),
}

/// One stored value, with the bytes it takes and, for a table, its
/// highest positive whole-number key (where `append` goes next).
#[derive(Debug)]
struct Entry {
    value: Stored,
    size: usize,
    last: i64,
}

/// The highest positive whole-number key of a table, else 0.
fn last_index(s: &Stored) -> i64 {
    match s {
        Stored::Table(entries) => entries
            .iter()
            .filter_map(|(k, _)| match k {
                Key::Int(i) if *i > 0 => Some(*i),
                _ => None,
            })
            .max()
            .unwrap_or(0),
        _ => 0,
    }
}

/// One registry: names to values.
#[derive(Debug, Default)]
struct Map {
    values: HashMap<Vec<u8>, Entry>,
}

/// The registries of a run.
#[derive(Debug, Default)]
pub(crate) struct Registry {
    inner: Mutex<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    run: Map,
    hosts: HashMap<IpAddr, Map>,
    /// Bytes stored in all of them.
    bytes: usize,
}

/// Which registry a call uses.
#[derive(Debug, Clone, Copy)]
enum Which {
    Run,
    Host(IpAddr),
}

/// Copy a Lua value in, counting its size; an error for what cannot be
/// stored.
fn store(v: &Value, depth: usize, size: &mut usize) -> Result<Option<Stored>, String> {
    *size = size.saturating_add(ENTRY_COST);
    if *size > MAX_BYTES {
        return Err("value too large for the registry".into());
    }
    Ok(Some(match v {
        Value::Nil => return Ok(None),
        Value::Boolean(b) => Stored::Bool(*b),
        Value::Integer(i) => Stored::Int(*i),
        Value::Number(n) => Stored::Num(*n),
        Value::String(s) => {
            let b = s.as_bytes().to_vec();
            *size = size.saturating_add(b.len());
            if *size > MAX_BYTES {
                return Err("value too large for the registry".into());
            }
            Stored::Str(b)
        }
        Value::Table(t) => {
            if depth >= MAX_DEPTH {
                return Err(format!(
                    "table nested too deeply for the registry (at most {MAX_DEPTH} levels)"
                ));
            }
            let mut entries = Vec::new();
            // The numbered entries first, in order, then the rest.
            let mut n = 0i64;
            loop {
                match t.raw_get::<Value>(n + 1).map_err(|e| e.to_string())? {
                    Value::Nil => break,
                    x => {
                        n += 1;
                        if let Some(s) = store(&x, depth + 1, size)? {
                            entries.push((Key::Int(n), s));
                        }
                    }
                }
            }
            for pair in t.pairs::<Value, Value>() {
                let (k, x) = pair.map_err(|e| e.to_string())?;
                let key = match k {
                    Value::Integer(i) if (1..=n).contains(&i) => continue,
                    Value::Integer(i) => Key::Int(i),
                    Value::Number(f) => Key::Num(f),
                    Value::Boolean(b) => Key::Bool(b),
                    Value::String(s) => {
                        let b = s.as_bytes().to_vec();
                        *size = size.saturating_add(b.len());
                        Key::Str(b)
                    }
                    other => {
                        return Err(format!(
                            "a {} cannot be a key in the registry",
                            other.type_name()
                        ));
                    }
                };
                if let Some(s) = store(&x, depth + 1, size)? {
                    entries.push((key, s));
                }
            }
            Stored::Table(entries)
        }
        other => {
            return Err(format!(
                "a {} cannot be stored in the registry",
                other.type_name()
            ));
        }
    }))
}

/// Copy a stored value out into `lua`.
fn load(lua: &Lua, s: &Stored) -> mlua::Result<Value> {
    Ok(match s {
        Stored::Bool(b) => Value::Boolean(*b),
        Stored::Int(i) => Value::Integer(*i),
        Stored::Num(n) => Value::Number(*n),
        Stored::Str(b) => Value::String(lua.create_string(b)?),
        Stored::Table(entries) => {
            let t = lua.create_table()?;
            for (k, v) in entries {
                let key = match k {
                    Key::Int(i) => Value::Integer(*i),
                    Key::Num(n) => Value::Number(*n),
                    Key::Bool(b) => Value::Boolean(*b),
                    Key::Str(b) => Value::String(lua.create_string(b)?),
                };
                t.raw_set(key, load(lua, v)?)?;
            }
            Value::Table(t)
        }
    })
}

impl Registry {
    fn with<R>(&self, which: Which, f: impl FnOnce(&mut Map, &mut usize) -> R) -> R {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Inner { run, hosts, bytes } = &mut *g;
        let map = match which {
            Which::Run => run,
            Which::Host(ip) => hosts.entry(ip).or_default(),
        };
        f(map, bytes)
    }

    fn get(&self, lua: &Lua, which: Which, name: &[u8]) -> mlua::Result<Value> {
        // Copied out of the lock first, so no Lua code runs under it.
        let found = self.with(which, |m, _| m.values.get(name).map(|e| e.value.clone()));
        match found {
            Some(s) => load(lua, &s),
            None => Ok(Value::Nil),
        }
    }

    fn set(&self, which: Which, name: &[u8], v: &Value) -> Result<(), String> {
        let mut size = name.len();
        let stored = store(v, 0, &mut size)?;
        self.with(which, |m, bytes| {
            let old = m.values.get(name).map_or(0, |e| e.size);
            match stored {
                None => {
                    m.values.remove(name);
                    *bytes -= old;
                }
                Some(s) => {
                    let total = bytes.saturating_sub(old).saturating_add(size);
                    if total > MAX_BYTES {
                        return Err("the registry is full".to_string());
                    }
                    *bytes = total;
                    let last = last_index(&s);
                    m.values.insert(
                        name.to_vec(),
                        Entry {
                            value: s,
                            size,
                            last,
                        },
                    );
                }
            }
            Ok(())
        })
    }

    /// Apply what a script changed in the value under `name` (`new`, made
    /// from `base`, the copy it read) to the value there now, in one step;
    /// see [`merge`].
    fn merge(&self, which: Which, name: &[u8], base: &Value, new: &Value) -> Result<(), String> {
        let mut size = 0;
        let base = store(base, 0, &mut size)?;
        let mut size = 0;
        let new = store(new, 0, &mut size)?;
        self.with(which, |m, bytes| {
            let (cur, old) = match m.values.remove(name) {
                Some(e) => (Some(e.value), e.size),
                None => (None, 0),
            };
            let kept = cur.clone();
            match merge(cur, base.as_ref(), new) {
                None => {
                    *bytes -= old;
                }
                Some(s) => {
                    let size = name.len() + stored_size(&s);
                    let total = bytes.saturating_sub(old).saturating_add(size);
                    if total > MAX_BYTES {
                        if let Some(value) = kept {
                            let last = last_index(&value);
                            m.values.insert(
                                name.to_vec(),
                                Entry {
                                    value,
                                    size: old,
                                    last,
                                },
                            );
                        }
                        return Err("the registry is full".to_string());
                    }
                    *bytes = total;
                    let last = last_index(&s);
                    m.values.insert(
                        name.to_vec(),
                        Entry {
                            value: s,
                            size,
                            last,
                        },
                    );
                }
            }
            Ok(())
        })
    }

    /// Add `v` to the end of the list under `name`, making the list when
    /// there is none. One call, so scripts running at once never lose
    /// each other's entries.
    fn append(&self, which: Which, name: &[u8], v: &Value) -> Result<(), String> {
        let mut size = 0;
        let Some(stored) = store(v, 1, &mut size)? else {
            return Ok(());
        };
        self.with(which, |m, bytes| {
            if *bytes + size + name.len() > MAX_BYTES {
                return Err("the registry is full".to_string());
            }
            match m.values.get_mut(name) {
                Some(Entry {
                    value: Stored::Table(entries),
                    size: n,
                    last,
                }) => {
                    let Some(next) = last.checked_add(1) else {
                        return Err("the list has no room for another entry".to_string());
                    };
                    entries.push((Key::Int(next), stored));
                    *last = next;
                    *n += size;
                    *bytes += size;
                }
                Some(_) => return Err("the value under that name is not a list".to_string()),
                None => {
                    let n = size + name.len() + ENTRY_COST;
                    m.values.insert(
                        name.to_vec(),
                        Entry {
                            value: Stored::Table(vec![(Key::Int(1), stored)]),
                            size: n,
                            last: 1,
                        },
                    );
                    *bytes += n;
                }
            }
            Ok(())
        })
    }
}

/// What a stored value counts against [`MAX_BYTES`], as [`store`] counts it.
fn stored_size(s: &Stored) -> usize {
    ENTRY_COST
        + match s {
            Stored::Str(b) => b.len(),
            Stored::Table(entries) => entries
                .iter()
                .map(|(k, v)| {
                    stored_size(v)
                        + match k {
                            Key::Str(b) => b.len(),
                            _ => 0,
                        }
                })
                .sum(),
            _ => 0,
        }
}

fn lookup<'a>(entries: &'a [(Key, Stored)], k: &Key) -> Option<&'a Stored> {
    entries.iter().find(|(x, _)| x == k).map(|(_, v)| v)
}

/// Three-way merge: `new` is what a script made of `base`, the value it
/// read; `cur` is the value now, which other scripts may have changed
/// since. Only the script's own changes are applied to `cur`: entries it
/// set or removed, and entries it added past the end of a list, which go
/// after the list's end now (so two scripts adding to one list both
/// keep their entries, as with `append`).
fn merge(cur: Option<Stored>, base: Option<&Stored>, new: Option<Stored>) -> Option<Stored> {
    if new.as_ref() == base {
        return cur;
    }
    // A table the script made where there was none (`t = t or {}`) is
    // merged as if it had found an empty one, so two scripts that both
    // start the same list keep both their entries.
    let empty = Stored::Table(Vec::new());
    let base = match (base, &cur, &new) {
        (None, Some(Stored::Table(_)), Some(Stored::Table(_))) => Some(&empty),
        _ => base,
    };
    let (Some(Stored::Table(mut cur)), Some(Stored::Table(base)), Some(Stored::Table(new))) =
        (cur, base, new.clone())
    else {
        return new;
    };
    let base_last = last_index(&Stored::Table(base.clone()));
    let mut added = Vec::new();
    for (k, v) in new.iter() {
        if let Key::Int(i) = k
            && *i > base_last
            && lookup(base, k).is_none()
        {
            added.push((*i, v.clone()));
            continue;
        }
        let merged = merge(lookup(&cur, k).cloned(), lookup(base, k), Some(v.clone()));
        cur.retain(|(x, _)| x != k);
        if let Some(m) = merged {
            cur.push((k.clone(), m));
        }
    }
    for (k, v) in base.iter() {
        if lookup(&new, k).is_none() {
            let merged = merge(lookup(&cur, k).cloned(), Some(v), None);
            cur.retain(|(x, _)| x != k);
            if let Some(m) = merged {
                cur.push((k.clone(), m));
            }
        }
    }
    added.sort_by_key(|(i, _)| *i);
    let mut last = last_index(&Stored::Table(cur.clone()));
    for (_, v) in added {
        last = last.saturating_add(1);
        cur.push((Key::Int(last), v));
    }
    Some(Stored::Table(cur))
}

/// The `get`, `set`, `append` and `merge` functions of one registry, as a table.
fn functions(
    lua: &Lua,
    reg: &Arc<Registry>,
    which: Which,
    label: &'static str,
) -> mlua::Result<Table> {
    let t = lua.create_table()?;
    let r = reg.clone();
    t.raw_set(
        "get",
        lua.create_function(move |lua, name: mlua::LuaString| r.get(lua, which, &name.as_bytes()))?,
    )?;
    let r = reg.clone();
    t.raw_set(
        "set",
        lua.create_function(move |_, (name, v): (mlua::LuaString, Value)| {
            r.set(which, &name.as_bytes(), &v)
                .map_err(|e| mlua::Error::runtime(format!("{label}.set: {e}")))
        })?,
    )?;
    let r = reg.clone();
    t.raw_set(
        "append",
        lua.create_function(move |_, (name, v): (mlua::LuaString, Value)| {
            r.append(which, &name.as_bytes(), &v)
                .map_err(|e| mlua::Error::runtime(format!("{label}.append: {e}")))
        })?,
    )?;
    let r = reg.clone();
    t.raw_set(
        "merge",
        lua.create_function(
            move |_, (name, base, new): (mlua::LuaString, Value, Value)| {
                r.merge(which, &name.as_bytes(), &base, &new)
                    .map_err(|e| mlua::Error::runtime(format!("{label}.merge: {e}")))
            },
        )?,
    )?;
    Ok(t)
}

/// Put `fero.registry` (the run's) and, for a script that runs against a
/// host, `fero.host_registry` (that host's) into `fero`.
pub(crate) fn install(
    lua: &Lua,
    fero: &Table,
    reg: &Arc<Registry>,
    host: Option<IpAddr>,
) -> mlua::Result<()> {
    fero.raw_set(
        "registry",
        functions(lua, reg, Which::Run, "fero.registry")?,
    )?;
    if let Some(ip) = host {
        fero.raw_set(
            "host_registry",
            functions(lua, reg, Which::Host(ip), "fero.host_registry")?,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copies_in_and_out() {
        let reg = Arc::new(Registry::default());
        let a = Lua::new();
        let b = Lua::new();
        let fa = a.create_table().unwrap();
        let fb = b.create_table().unwrap();
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        install(&a, &fa, &reg, Some(ip)).unwrap();
        install(&b, &fb, &reg, Some(ip)).unwrap();
        a.globals().set("fero", fa).unwrap();
        b.globals().set("fero", fb).unwrap();
        a.load(
            r#"
            local t = { 1, 2, x = { y = "z" }, [true] = 3.5 }
            fero.registry.set("t", t)
            t.x.y = "changed"
            fero.host_registry.append("l", 5)
            fero.host_registry.append("l", "six")
            "#,
        )
        .exec()
        .unwrap();
        let (y, n, l2, b3, other) = b
            .load(
                r#"
                local t = fero.registry.get("t")
                local l = fero.host_registry.get("l")
                return t.x.y, #t, l[2], t[true], fero.registry.get("l")
                "#,
            )
            .eval::<(String, i64, String, f64, Value)>()
            .unwrap();
        assert_eq!((y.as_str(), n, l2.as_str(), b3), ("z", 2, "six", 3.5));
        assert!(other.is_nil());
        // Appends go after the highest positive whole-number key.
        let (a3, n1) = a
            .load(
                r#"
                fero.registry.set("p", { 1, 2, [-5] = "neg" })
                fero.registry.append("p", "three")
                fero.registry.set("q", { [-5] = "neg" })
                fero.registry.append("q", "one")
                return fero.registry.get("p")[3], fero.registry.get("q")[1]
                "#,
            )
            .eval::<(String, String)>()
            .unwrap();
        assert_eq!((a3.as_str(), n1.as_str()), ("three", "one"));
        a.load(r#"fero.registry.set("p", nil) fero.registry.set("q", nil)"#)
            .exec()
            .unwrap();
        // Another host has its own registry; nil removes a value.
        let c = Lua::new();
        let fc = c.create_table().unwrap();
        install(&c, &fc, &reg, Some("192.0.2.2".parse().unwrap())).unwrap();
        c.globals().set("fero", fc).unwrap();
        let none: Value = c
            .load(r#"return fero.host_registry.get("l")"#)
            .eval()
            .unwrap();
        assert!(none.is_nil());
        a.load(r#"fero.registry.set("t", nil)"#).exec().unwrap();
        let gone: Value = b.load(r#"return fero.registry.get("t")"#).eval().unwrap();
        assert!(gone.is_nil());
        let g = reg.inner.lock().unwrap();
        assert_eq!(g.bytes, g.hosts[&ip].values[&b"l".to_vec()].size);
    }

    #[test]
    fn refuses_what_cannot_be_kept() {
        let reg = Arc::new(Registry::default());
        let a = Lua::new();
        let f = a.create_table().unwrap();
        install(&a, &f, &reg, None).unwrap();
        a.globals().set("fero", f).unwrap();
        // No host registry outside a host.
        let h: Value = a.load("return fero.host_registry").eval().unwrap();
        assert!(h.is_nil());
        for bad in [
            r#"fero.registry.set("f", print)"#,
            r#"fero.registry.set("f", { print })"#,
            r#"local t = {} t.t = t fero.registry.set("c", t)"#,
            r#"fero.registry.set("big", string.rep("x", 17 * 1024 * 1024))"#,
            r#"fero.registry.set("s", 1) fero.registry.append("s", 2)"#,
            r#"fero.registry.set("m", { [math.maxinteger] = true }) fero.registry.append("m", 1)"#,
        ] {
            assert!(a.load(bad).exec().is_err(), "{bad}");
        }
        // Filling it up stops at the limit.
        let fill = r#"
            local chunk = string.rep("x", 1024 * 1024)
            for i = 1, 20 do fero.registry.append("many", chunk) end
        "#;
        assert!(a.load(fill).exec().is_err());
        assert!(reg.inner.lock().unwrap().bytes <= MAX_BYTES);
    }
}
