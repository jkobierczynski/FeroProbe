//! Running scripts: their rules decide where they run, then their
//! actions run, many at once, each in its own sandbox.

use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::{Duration, Instant};

use futures::StreamExt;
use mlua::{Function, Lua, MultiValue, Table, Value};

use super::args::{ArgTable, ArgValue};
use super::output::{ScriptResult, ScriptTable, ScriptValue, bytes_to_text};
use super::sandbox::{self, Budget};
use super::socket::{Scope, ScriptSocket};
use super::{Script, ScriptError};
use crate::model::{HostResult, PortResult, PortState};

/// How long one rule function may run.
const RULE_TIMEOUT: Duration = Duration::from_secs(10);

/// Script runs at once, by default.
pub const DEFAULT_PARALLEL: usize = 32;

/// Deepest table nesting kept from a script's output.
const MAX_DEPTH: usize = 32;
/// Most values kept from a script's output table.
const MAX_VALUES: usize = 100_000;
/// Most bytes of text (values and names) kept from a script's output
/// table. A table can hold one string many times at no cost to the
/// script, but every copy costs FeroProbe, so copies count in full.
const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

/// What converting a script's output table has kept so far.
#[derive(Default)]
struct Kept {
    values: usize,
    bytes: usize,
}

impl Kept {
    fn full(&self) -> bool {
        self.values > MAX_VALUES || self.bytes > MAX_OUTPUT_BYTES
    }

    /// `text` if it still fits, else "...", and from then on nothing more.
    fn text(&mut self, text: String) -> String {
        self.bytes = self.bytes.saturating_add(text.len());
        if self.bytes > MAX_OUTPUT_BYTES {
            return "...".into();
        }
        text
    }
}

/// The library every script gets, written for FeroProbe, on top of the
/// `fero` table the engine fills in.
const LIBRARY: &str = r##"
local fero, args = ...
local function lookup(name)
  local v = args[name]
  if v ~= nil then return v end
  for _, flag in ipairs(args) do
    if flag == name then return true end
  end
  return nil
end
local function find(name)
  local v = lookup(name)
  if v ~= nil then return v end
  -- "script.arg" falls back to "arg", as in nmap.
  local short = name:match("%.([^.]*)$")
  if short then return lookup(short) end
  return nil
end
fero.args = {
  table = args,
  get = function(...)
    local n = select("#", ...)
    local out = {}
    for i = 1, n do
      local names = select(i, ...)
      if type(names) == "string" then names = { names } end
      for _, name in ipairs(names) do
        local v = find(name)
        if v ~= nil then out[i] = v; break end
      end
    end
    return table.unpack(out, 1, n)
  end,
}
"##;

fn arg_to_lua(lua: &Lua, v: &ArgValue) -> mlua::Result<Value> {
    Ok(match v {
        ArgValue::Str(s) => Value::String(lua.create_string(s)?),
        ArgValue::Table(t) => Value::Table(args_to_lua(lua, t)?),
    })
}

fn args_to_lua(lua: &Lua, t: &ArgTable) -> mlua::Result<Table> {
    let out = lua.create_table()?;
    for (i, v) in t.list.iter().enumerate() {
        out.raw_set(i + 1, arg_to_lua(lua, v)?)?;
    }
    for (k, v) in &t.named {
        out.raw_set(k.as_str(), arg_to_lua(lua, v)?)?;
    }
    Ok(out)
}

/// Set up the `fero` library and the script's globals in a new state.
pub(crate) fn install_library(
    lua: &Lua,
    id: &str,
    kind: &str,
    args: &ArgTable,
    scope: &Arc<Scope>,
) -> mlua::Result<()> {
    let g = lua.globals();
    g.raw_set("SCRIPT_NAME", id)?;
    g.raw_set("SCRIPT_TYPE", kind)?;
    let fero = lua.create_table()?;
    let socket = lua.create_table()?;
    let scope = scope.clone();
    let open = Arc::new(AtomicUsize::new(0));
    socket.raw_set(
        "new",
        lua.create_function(move |_, ()| Ok(ScriptSocket::new(scope.clone(), open.clone())))?,
    )?;
    fero.raw_set("socket", socket)?;
    fero.raw_set(
        "verbosity",
        lua.create_function(|_, ()| Ok(crate::debug::verbosity()))?,
    )?;
    fero.raw_set(
        "debugging",
        lua.create_function(|_, ()| Ok(crate::debug::debugging()))?,
    )?;
    let who = id.to_string();
    let debug = lua.create_function(move |_, (level, msg): (u8, mlua::LuaString)| {
        let msg = bytes_to_text(&msg.as_bytes());
        crate::debug::debug(level, || format!("{who}: {msg}"));
        Ok(())
    })?;
    fero.raw_set("debug", debug)?;
    // print() goes to the debugging output, as -d shows it.
    let who = id.to_string();
    let tostring: Function = g.get("tostring")?;
    g.raw_set(
        "print",
        lua.create_function(move |_, vals: MultiValue| {
            let parts: Vec<String> = vals
                .iter()
                .map(|v| {
                    tostring
                        .call::<mlua::LuaString>(v.clone())
                        .map(|s| bytes_to_text(&s.as_bytes()))
                        .unwrap_or_default()
                })
                .collect();
            crate::debug::debug(1, || format!("{who}: {}", parts.join("\t")));
            Ok(())
        })?,
    )?;
    g.raw_set("fero", fero.clone())?;
    lua.load(LIBRARY)
        .set_name("=fero")
        .call::<()>((fero, args_to_lua(lua, args)?))?;
    Ok(())
}

/// The host table scripts get: `ip`, `name` (reverse DNS, or ""),
/// `targetname` (the name given on the command line), `mac_addr` and `os`
/// (the names of the OS matches, best first).
fn host_table(lua: &Lua, h: &HostResult) -> mlua::Result<Table> {
    let t = lua.create_table()?;
    t.raw_set("ip", h.addr.to_string())?;
    t.raw_set("name", h.rdns.clone().unwrap_or_default())?;
    if let Some(n) = &h.hostname {
        t.raw_set("targetname", n.as_str())?;
    }
    if let Some(m) = &h.mac {
        t.raw_set("mac_addr", m.addr.to_string())?;
    }
    if let Some(os) = &h.os {
        let list = lua.create_table()?;
        for (i, m) in os.matches.iter().enumerate() {
            list.raw_set(i + 1, m.name.as_str())?;
        }
        t.raw_set("os", list)?;
    }
    Ok(t)
}

/// The port table scripts get: `number`, `protocol`, `state`, `reason`,
/// `service`, and `version` with what `-sV` found.
fn port_table(lua: &Lua, p: &PortResult) -> mlua::Result<Table> {
    let t = lua.create_table()?;
    t.raw_set("number", p.port)?;
    t.raw_set("protocol", p.protocol.to_string())?;
    t.raw_set("state", p.state.to_string())?;
    t.raw_set("reason", p.reason)?;
    let v = lua.create_table()?;
    match &p.service {
        Some(s) => {
            t.raw_set("service", s.name.as_str())?;
            v.raw_set("name", s.name.as_str())?;
            for (k, val) in [
                ("product", &s.product),
                ("version", &s.version),
                ("extrainfo", &s.extra_info),
                ("hostname", &s.hostname),
                ("ostype", &s.os_type),
                ("devicetype", &s.device_type),
            ] {
                if let Some(val) = val {
                    v.raw_set(k, val.as_str())?;
                }
            }
            v.raw_set("service_tunnel", s.tunnel.unwrap_or("none"))?;
            let cpe = lua.create_table()?;
            for (i, c) in s.cpe.iter().enumerate() {
                cpe.raw_set(i + 1, c.as_str())?;
            }
            v.raw_set("cpe", cpe)?;
        }
        None => {
            let name = crate::service_name(p.protocol, p.port);
            t.raw_set("service", name)?;
            v.raw_set("name", name)?;
            v.raw_set("service_tunnel", "none")?;
        }
    }
    t.raw_set("version", v)?;
    Ok(t)
}

/// The ports a portrule is asked about, as in nmap: those that may be open.
fn rule_port(p: &PortResult) -> bool {
    matches!(
        p.state,
        PortState::Open | PortState::OpenFiltered | PortState::Unfiltered
    )
}

/// Where a script run's sockets may go: the host and the ports the scan
/// probed on it.
fn scope_of(id: &str, h: Option<&HostResult>) -> Scope {
    let Some(h) = h else {
        return Scope {
            script: id.to_string(),
            ..Scope::default()
        };
    };
    let mut s = Scope {
        addr: Some(h.addr),
        names: h.hostname.iter().chain(h.rdns.iter()).cloned().collect(),
        script: id.to_string(),
        ..Scope::default()
    };
    for p in &h.ports {
        match p.protocol {
            crate::Protocol::Tcp => {
                s.tcp.insert(p.port);
            }
            crate::Protocol::Udp => {
                s.udp.insert(p.port);
            }
            _ => {}
        }
    }
    s
}

fn truthy(v: &Value) -> bool {
    !matches!(v, Value::Nil | Value::Boolean(false))
}

fn tostring(lua: &Lua, v: &Value) -> String {
    let f: Option<Function> = lua.globals().get("tostring").ok();
    f.and_then(|f| f.call::<mlua::LuaString>(v.clone()).ok())
        .map(|s| bytes_to_text(&s.as_bytes()))
        .unwrap_or_default()
}

/// A Lua string as text, cut before copying to what the budget still
/// allows (plus one byte, so [`Kept::text`] sees that it overflowed).
fn budgeted_text(s: &mlua::LuaString, kept: &Kept) -> String {
    let b = s.as_bytes();
    let room = MAX_OUTPUT_BYTES.saturating_sub(kept.bytes);
    bytes_to_text(&b[..b.len().min(room + 1)])
}

fn convert(lua: &Lua, v: &Value, depth: usize, kept: &mut Kept) -> ScriptValue {
    kept.values += 1;
    if kept.full() {
        return ScriptValue::Str("...".into());
    }
    let Value::Table(t) = v else {
        let text = match v {
            // Cut before copying, so a huge string is never copied whole.
            Value::String(s) => budgeted_text(s, kept),
            other => tostring(lua, other),
        };
        return ScriptValue::Str(kept.text(text));
    };
    if t.metatable()
        .is_some_and(|m| m.raw_get::<Value>("__tostring").is_ok_and(|f| !f.is_nil()))
    {
        return ScriptValue::Str(kept.text(tostring(lua, v)));
    }
    if depth >= MAX_DEPTH {
        return ScriptValue::Str("...".into());
    }
    let mut out = ScriptTable::default();
    for i in 1.. {
        if kept.full() {
            break;
        }
        match t.raw_get::<Value>(i) {
            Ok(Value::Nil) | Err(_) => break,
            Ok(x) => out.list.push(convert(lua, &x, depth + 1, kept)),
        }
    }
    // The names stay Lua strings (references, not copies) until kept, so
    // the budget bounds them too.
    let mut named: Vec<(mlua::LuaString, Value)> = t
        .pairs::<Value, Value>()
        .filter_map(Result::ok)
        .filter_map(|(k, v)| match k {
            Value::String(s) => Some((s, v)),
            _ => None,
        })
        .collect();
    named.sort_by(|a, b| a.0.as_bytes()[..].cmp(&b.0.as_bytes()[..]));
    for (k, x) in named {
        if kept.full() {
            break;
        }
        let k = kept.text(budgeted_text(&k, kept));
        out.named.push((k, convert(lua, &x, depth + 1, kept)));
    }
    ScriptValue::Table(out)
}

/// An action's return values as a result, like nmap: a string is the
/// output; a table is laid out as the output and kept as data; a table
/// and a string are the data and the output. Nothing (or an empty
/// output) is no result.
fn to_result(lua: &Lua, id: &str, ret: MultiValue) -> Option<ScriptResult> {
    let mut it = ret.into_iter();
    let r1 = it.next().unwrap_or(Value::Nil);
    let r2 = it.next().unwrap_or(Value::Nil);
    let mut kept = Kept::default();
    let (data, output) = if !r2.is_nil() {
        let data = (!r1.is_nil()).then(|| convert(lua, &r1, 0, &mut kept));
        (data, tostring(lua, &r2))
    } else {
        match &r1 {
            Value::Nil => return None,
            Value::String(s) => (None, bytes_to_text(&s.as_bytes())),
            Value::Table(_) => {
                let d = convert(lua, &r1, 0, &mut kept);
                let text = d.layout();
                (Some(d), text)
            }
            other => (None, tostring(lua, other)),
        }
    };
    (!output.is_empty() || data.is_some()).then(|| ScriptResult {
        id: id.to_string(),
        output,
        data,
    })
}

/// What a script run is against.
#[derive(Clone, Copy)]
enum Against<'a> {
    Pre,
    Post,
    Host(&'a HostResult),
    Port(&'a HostResult, &'a PortResult),
}

impl Against<'_> {
    fn kind(&self) -> &'static str {
        match self {
            Against::Pre => "prerule",
            Against::Post => "postrule",
            Against::Host(_) => "hostrule",
            Against::Port(..) => "portrule",
        }
    }

    fn host(&self) -> Option<&HostResult> {
        match self {
            Against::Host(h) | Against::Port(h, _) => Some(h),
            _ => None,
        }
    }

    fn describe(&self) -> String {
        match self {
            Against::Pre | Against::Post => String::new(),
            Against::Host(h) => format!(" against {}", h.addr),
            Against::Port(h, p) => {
                format!(" against {}", std::net::SocketAddr::new(h.addr, p.port))
            }
        }
    }
}

/// The scripts of a run, ready to run.
#[derive(Debug)]
pub struct ScriptScan {
    scripts: Vec<Arc<Script>>,
    levels: Vec<Vec<Arc<Script>>>,
    args: Arc<ArgTable>,
    /// `--script-timeout`: the longest one script run against one host
    /// or port may take. `None` for no limit.
    pub timeout: Option<Duration>,
    /// Script runs at once.
    pub parallel: usize,
}

impl ScriptScan {
    /// The engine for `scripts`, with `--script-args`.
    pub fn new(
        scripts: Vec<Script>,
        args: ArgTable,
        timeout: Option<Duration>,
    ) -> Result<Self, ScriptError> {
        let scripts: Vec<Arc<Script>> = scripts.into_iter().map(Arc::new).collect();
        let levels = super::run_levels(&scripts)?;
        Ok(ScriptScan {
            scripts,
            levels,
            args: Arc::new(args),
            timeout,
            parallel: DEFAULT_PARALLEL,
        })
    }

    pub fn scripts(&self) -> &[Arc<Script>] {
        &self.scripts
    }

    /// A fresh state with `script` loaded, for its rules or action.
    fn state(&self, script: &Script, on: Against<'_>, budget: &Arc<Budget>) -> Result<Lua, String> {
        let lua = sandbox::new_state(budget).map_err(|e| e.to_string())?;
        let scope = Arc::new(scope_of(&script.id, on.host()));
        install_library(&lua, &script.id, on.kind(), &self.args, &scope)
            .map_err(|e| e.to_string())?;
        let name = script.path.as_ref().map_or_else(
            || format!("{}.{}", script.id, super::EXTENSION),
            |p| p.display().to_string(),
        );
        lua.load(&*script.source)
            .set_name(format!("@{name}"))
            .exec()
            .map_err(|e| sandbox::error_text(&e, budget))?;
        Ok(lua)
    }

    fn rule_deadline(&self) -> Option<Instant> {
        let d = self.timeout.map_or(RULE_TIMEOUT, |t| t.min(RULE_TIMEOUT));
        Some(Instant::now() + d)
    }

    /// Whether `script`'s rule says it runs on `on`.
    fn rule_says(&self, lua: &Lua, budget: &Budget, script: &Script, on: Against<'_>) -> bool {
        let name = on.kind();
        let Ok(f) = lua.globals().raw_get::<Function>(name) else {
            return false;
        };
        if script.forced {
            return true;
        }
        // One state serves a script's hostrule and portrules on a host.
        if lua.globals().raw_set("SCRIPT_TYPE", name).is_err() {
            return false;
        }
        budget.reset(self.rule_deadline());
        let r = match on {
            Against::Pre | Against::Post => f.call::<Value>(()),
            Against::Host(h) => host_table(lua, h).and_then(|t| f.call::<Value>(t)),
            Against::Port(h, p) => host_table(lua, h)
                .and_then(|ht| port_table(lua, p).and_then(|pt| f.call::<Value>((ht, pt)))),
        };
        match r {
            Ok(v) => truthy(&v),
            Err(e) => {
                crate::debug::debug(1, || {
                    format!(
                        "Script {}{}: {name} failed: {}",
                        script.id,
                        on.describe(),
                        sandbox::error_text(&e, budget)
                    )
                });
                false
            }
        }
    }

    /// Run `script`'s action against `on`.
    async fn action(&self, script: &Script, on: Against<'_>) -> Option<ScriptResult> {
        let budget = Budget::new();
        let started = Instant::now();
        budget.reset(self.timeout.map(|t| started + t));
        let what = format!("Script {}{}", script.id, on.describe());
        crate::debug::debug(2, || format!("Starting {what}"));
        let run = async {
            let lua = self.state(script, on, &budget)?;
            let action: Function = lua.globals().raw_get("action").map_err(|e| e.to_string())?;
            let args = match on {
                Against::Pre | Against::Post => MultiValue::new(),
                Against::Host(h) => MultiValue::from_vec(vec![Value::Table(
                    host_table(&lua, h).map_err(|e| e.to_string())?,
                )]),
                Against::Port(h, p) => MultiValue::from_vec(vec![
                    Value::Table(host_table(&lua, h).map_err(|e| e.to_string())?),
                    Value::Table(port_table(&lua, p).map_err(|e| e.to_string())?),
                ]),
            };
            let ret = action
                .call_async::<MultiValue>(args)
                .await
                .map_err(|e| sandbox::error_text(&e, &budget))?;
            Ok::<_, String>(to_result(&lua, &script.id, ret))
        };
        let outcome = match self.timeout {
            Some(t) => tokio::time::timeout(t, run)
                .await
                .unwrap_or_else(|_| Err(sandbox::TIMED_OUT.to_string())),
            None => run.await,
        };
        match outcome {
            Ok(r) => {
                crate::debug::debug(2, || {
                    format!("Finished {what} in {:.2}s", started.elapsed().as_secs_f64())
                });
                r
            }
            Err(e) if e == sandbox::TIMED_OUT => {
                crate::debug::debug(1, || format!("{what} timed out"));
                None
            }
            Err(e) => {
                crate::debug::debug(1, || format!("{what} threw an error: {e}"));
                None
            }
        }
    }

    /// The prerule or postrule scripts, which run once with no host.
    async fn whole_run(&self, on: Against<'_>) -> Vec<ScriptResult> {
        let mut results = Vec::new();
        for level in &self.levels {
            let chosen: Vec<&Arc<Script>> = level
                .iter()
                .filter(|s| {
                    let defined = match on {
                        Against::Pre => s.rules.prerule,
                        _ => s.rules.postrule,
                    };
                    defined && {
                        let budget = Budget::new();
                        match self.state(s, on, &budget) {
                            Ok(lua) => self.rule_says(&lua, &budget, s, on),
                            Err(e) => {
                                crate::debug::debug(1, || {
                                    format!("Script {} could not start: {e}", s.id)
                                });
                                false
                            }
                        }
                    }
                })
                .collect();
            let mut runs = futures::stream::iter(chosen)
                .map(|s| self.action(s, on))
                .buffer_unordered(self.parallel.max(1));
            while let Some(r) = runs.next().await {
                results.extend(r);
            }
        }
        results.sort_by(|a, b| a.id.cmp(&b.id));
        results
    }

    /// Run the prerule scripts (before the scan).
    pub async fn pre_scan(&self) -> Vec<ScriptResult> {
        self.whole_run(Against::Pre).await
    }

    /// Run the postrule scripts (after every host is done).
    pub async fn post_scan(&self) -> Vec<ScriptResult> {
        self.whole_run(Against::Post).await
    }

    /// Whether any chosen script has a hostrule or portrule.
    pub fn has_host_scripts(&self) -> bool {
        self.scripts
            .iter()
            .any(|s| s.rules.hostrule || s.rules.portrule)
    }

    /// Run the hostrule and portrule scripts on `hosts`, adding their
    /// output to the hosts and ports. Hosts cut short by
    /// `--host-timeout` are left alone.
    pub async fn scan_hosts(&self, hosts: &mut [HostResult]) {
        for level in &self.levels {
            // Where each script runs: (host, port index or None, script).
            let mut jobs: Vec<(usize, Option<usize>, Arc<Script>)> = Vec::new();
            for (hi, h) in hosts.iter().enumerate() {
                if h.timed_out {
                    continue;
                }
                for s in level {
                    if !s.rules.hostrule && !s.rules.portrule {
                        continue;
                    }
                    let budget = Budget::new();
                    let lua = match self.state(s, Against::Host(h), &budget) {
                        Ok(l) => l,
                        Err(e) => {
                            crate::debug::debug(1, || {
                                format!("Script {} could not start against {}: {e}", s.id, h.addr)
                            });
                            continue;
                        }
                    };
                    if s.rules.hostrule && self.rule_says(&lua, &budget, s, Against::Host(h)) {
                        jobs.push((hi, None, s.clone()));
                    }
                    if s.rules.portrule {
                        for (pi, p) in h.ports.iter().enumerate() {
                            if rule_port(p) && self.rule_says(&lua, &budget, s, Against::Port(h, p))
                            {
                                jobs.push((hi, Some(pi), s.clone()));
                            }
                        }
                    }
                }
            }
            let done: Vec<(usize, Option<usize>, ScriptResult)> = {
                let hosts: &[HostResult] = hosts;
                futures::stream::iter(jobs)
                    .map(|(hi, pi, s)| async move {
                        let h = &hosts[hi];
                        let on = match pi {
                            None => Against::Host(h),
                            Some(pi) => Against::Port(h, &h.ports[pi]),
                        };
                        self.action(&s, on).await.map(|r| (hi, pi, r))
                    })
                    .buffer_unordered(self.parallel.max(1))
                    .filter_map(|r| async move { r })
                    .collect()
                    .await
            };
            for (hi, pi, r) in done {
                match pi {
                    None => hosts[hi].scripts.push(r),
                    Some(pi) => hosts[hi].ports[pi].scripts.push(r),
                }
            }
        }
        for h in hosts.iter_mut() {
            h.scripts.sort_by(|a, b| a.id.cmp(&b.id));
            for p in &mut h.ports {
                p.scripts.sort_by(|a, b| a.id.cmp(&b.id));
            }
        }
    }
}
