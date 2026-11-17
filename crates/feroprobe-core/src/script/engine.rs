//! Running scripts: their rules decide where they run, then their
//! actions run, many at once, each in its own sandbox.

use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::{Duration, Instant};

use futures::StreamExt;
use mlua::{Function, Lua, MultiValue, Table, Value};

use super::args::{ArgTable, ArgValue};
use super::output::{ScriptResult, ScriptTable, ScriptValue, bytes_to_text_max, name_to_text_max};
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

    /// `text` if it still fits, else as much as fits followed by "...",
    /// and from then on nothing more.
    fn text(&mut self, mut text: String) -> String {
        let room = MAX_OUTPUT_BYTES.saturating_sub(self.bytes);
        self.bytes = self.bytes.saturating_add(text.len());
        if self.bytes > MAX_OUTPUT_BYTES {
            let mut end = room.min(text.len());
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            text.truncate(end);
            text.push_str("...");
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

-- Port-rule helpers.
local function set_of(x)
  if x == nil then return nil end
  if type(x) ~= "table" then x = { x } end
  local s = {}
  for _, v in ipairs(x) do s[v] = true end
  return s
end
local function rule_for(ports, services, protos, states)
  local P, S = set_of(ports), set_of(services)
  local PR = set_of(protos or "tcp")
  local ST = set_of(states or { "open", "open|filtered" })
  return function(host, port)
    if not (PR[port.protocol] and ST[port.state]) then return false end
    return (P ~= nil and P[port.number] == true)
      or (S ~= nil and S[port.service] == true)
  end
end
local http_rule = rule_for(
  { 80, 443, 591, 631, 3000, 5000, 7080, 8000, 8008, 8080, 8081, 8088, 8180,
    8443, 8888, 9000, 9443 },
  { "http", "https", "http-alt", "https-alt", "http-proxy", "http-mgmt",
    "ssl/http", "ipp" })
local ssl_rule = rule_for(
  { 443, 465, 636, 989, 990, 992, 993, 995, 4443, 5061, 6697, 8443, 9443 },
  { "https", "https-alt", "ssl", "ssl/http", "imaps", "pop3s", "smtps",
    "submissions", "ldaps", "ftps", "ftps-data", "ircs", "sip-tls", "telnets" })
fero.portrule = {
  match = rule_for,
  http = function(host, port) return http_rule(host, port) end,
  ssl = function(host, port)
    if port.protocol == "tcp" and (port.state == "open" or port.state == "open|filtered")
      and type(port.version) == "table" and port.version.service_tunnel == "ssl" then
      return true
    end
    return ssl_rule(host, port)
  end,
}

-- HTTP: the defaults --script-args give, around the client.
local raw_request = fero.http.request
local function truthy_arg(v)
  return v == true or v == "true" or v == "1" or v == "yes"
end
local function with_defaults(options)
  local o = {}
  if options ~= nil then
    for k, v in pairs(options) do o[k] = v end
  end
  local header = {}
  if type(o.header) == "table" then
    for k, v in pairs(o.header) do header[k] = v end
  end
  o.header = header
  local ua, maxbody, truncok, hosthdr = fero.args.get(
    "http.useragent", "http.max-body-size", "http.truncated-ok", "http.host")
  if o.user_agent == nil and type(ua) == "string" then o.user_agent = ua end
  if o.max_body_size == nil and tonumber(maxbody) then
    o.max_body_size = math.tointeger(tonumber(maxbody))
  end
  if o.truncated_ok == nil and truthy_arg(truncok) then o.truncated_ok = true end
  if type(hosthdr) == "string" then
    local has = false
    for k in pairs(header) do
      if type(k) == "string" and k:lower() == "host" then has = true end
    end
    if not has then header.Host = hosthdr end
  end
  return o
end
local function form_encode(t)
  local parts = {}
  local function enc(s)
    return (tostring(s):gsub("[^%w%-%._~]", function(c)
      return string.format("%%%02X", c:byte())
    end))
  end
  local items = {}
  for k, v in pairs(t) do items[#items + 1] = { tostring(k), v } end
  table.sort(items, function(a, b)
    if a[1] ~= b[1] then return a[1] < b[1] end
    return tostring(a[2]) < tostring(b[2])
  end)
  for _, kv in ipairs(items) do
    parts[#parts + 1] = enc(kv[1]) .. "=" .. enc(kv[2])
  end
  return table.concat(parts, "&")
end
fero.http.request = function(method, host, port, path, options)
  return raw_request(method, host, port, path, with_defaults(options))
end
fero.http.get = function(host, port, path, options)
  return raw_request("GET", host, port, path, with_defaults(options))
end
fero.http.head = function(host, port, path, options)
  return raw_request("HEAD", host, port, path, with_defaults(options))
end
fero.http.post = function(host, port, path, options, content)
  local o = with_defaults(options)
  if type(content) == "table" then
    o.content = form_encode(content)
    local has = false
    for k in pairs(o.header) do
      if type(k) == "string" and k:lower() == "content-type" then has = true end
    end
    if not has then o.header["Content-Type"] = "application/x-www-form-urlencoded" end
  elseif content ~= nil then
    o.content = content
  end
  return raw_request("POST", host, port, path, o)
end
fero.http.form_encode = form_encode
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

/// Most text one `print` or `fero.debug` call writes to the debugging
/// output.
const MAX_DEBUG_BYTES: usize = 64 * 1024;

/// `bytes` as text for the debugging output, at most `room` bytes of it
/// (then "..."), taking what it uses from `room`.
pub(crate) fn debug_text(bytes: &[u8], room: &mut usize) -> String {
    let mut text = bytes_to_text_max(bytes, *room);
    if text.len() > *room {
        let mut end = *room;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text.push_str("...");
        *room = 0;
    } else {
        *room -= text.len();
    }
    text
}

/// `print`'s arguments as one tab-separated line of at most
/// [`MAX_DEBUG_BYTES`] (then "..."), tabs counted, converting each only as
/// far as the line still has room: `convert` (`tostring` for `print`) is
/// not called once the line is full.
pub(crate) fn debug_join<T>(
    parts: impl Iterator<Item = T>,
    mut convert: impl FnMut(T) -> Option<mlua::LuaString>,
) -> String {
    let mut room = MAX_DEBUG_BYTES;
    let mut line = String::new();
    for (i, part) in parts.enumerate() {
        if i > 0 {
            // No room for the tab and at least one byte of the next value:
            // stop before converting it.
            if room <= 1 {
                line.push_str("...");
                break;
            }
            line.push('\t');
            room -= 1;
        }
        if let Some(s) = convert(part) {
            line.push_str(&debug_text(&s.as_bytes(), &mut room));
        }
        if room == 0 && line.ends_with("...") {
            break;
        }
    }
    line
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
    let open = Arc::new(AtomicUsize::new(0));
    {
        let scope = scope.clone();
        let open = open.clone();
        socket.raw_set(
            "new",
            lua.create_function(move |_, ()| Ok(ScriptSocket::new(scope.clone(), open.clone())))?,
        )?;
    }
    fero.raw_set("socket", socket)?;
    let http = lua.create_table()?;
    {
        let scope = scope.clone();
        http.raw_set(
            "request",
            lua.create_async_function(move |lua, args| {
                super::http::request(lua, scope.clone(), open.clone(), args)
            })?,
        )?;
    }
    http.raw_set("USER_AGENT", super::http::USER_AGENT)?;
    fero.raw_set("http", http)?;
    let base64 = lua.create_table()?;
    base64.raw_set(
        "encode",
        lua.create_function(|_, s: mlua::LuaString| Ok(super::base64::encode(&s.as_bytes())))?,
    )?;
    base64.raw_set(
        "decode",
        lua.create_function(|lua, s: mlua::LuaString| {
            super::base64::decode(&s.as_bytes())
                .map(|b| lua.create_string(b))
                .transpose()
        })?,
    )?;
    fero.raw_set("base64", base64)?;
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
        if crate::debug::debugging() >= level {
            let mut room = MAX_DEBUG_BYTES;
            let msg = debug_text(&msg.as_bytes(), &mut room);
            eprintln!("{who}: {msg}");
        }
        Ok(())
    })?;
    fero.raw_set("debug", debug)?;
    // print() goes to the debugging output, as -d shows it.
    let who = id.to_string();
    let tostring: Function = g.get("tostring")?;
    g.raw_set(
        "print",
        lua.create_function(move |_, vals: MultiValue| {
            // Nothing is converted unless it is shown, and then at most
            // MAX_DEBUG_BYTES of it.
            if crate::debug::debugging() < 1 {
                return Ok(());
            }
            let line = debug_join(vals.iter(), |v| {
                tostring.call::<mlua::LuaString>(v.clone()).ok()
            });
            eprintln!("{who}: {line}");
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

/// `tostring(v)` as Lua gives it, before any copy is made.
fn lua_tostring(lua: &Lua, v: &Value) -> Option<mlua::LuaString> {
    let f: Function = lua.globals().get("tostring").ok()?;
    f.call::<mlua::LuaString>(v.clone()).ok()
}

/// A Lua string as text, converted only as far as the budget still
/// allows, and counted against it.
fn budgeted_text(s: &mlua::LuaString, kept: &mut Kept) -> String {
    let room = MAX_OUTPUT_BYTES.saturating_sub(kept.bytes);
    kept.text(bytes_to_text_max(&s.as_bytes(), room))
}

/// `tostring(v)` as text, within the budget.
fn tostring(lua: &Lua, v: &Value, kept: &mut Kept) -> String {
    lua_tostring(lua, v)
        .map(|s| budgeted_text(&s, kept))
        .unwrap_or_default()
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
            other => tostring(lua, other, kept),
        };
        return ScriptValue::Str(text);
    };
    if t.metatable()
        .is_some_and(|m| m.raw_get::<Value>("__tostring").is_ok_and(|f| !f.is_nil()))
    {
        return ScriptValue::Str(tostring(lua, v, kept));
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
        let room = MAX_OUTPUT_BYTES.saturating_sub(kept.bytes);
        let k = kept.text(name_to_text_max(&k.as_bytes(), room));
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
        // The text has a budget of its own, as large as the data's.
        (data, tostring(lua, &r2, &mut Kept::default()))
    } else {
        match &r1 {
            Value::Nil => return None,
            Value::String(s) => (None, budgeted_text(s, &mut kept)),
            Value::Table(_) => {
                let d = convert(lua, &r1, 0, &mut kept);
                let text = d.layout();
                (Some(d), text)
            }
            other => (None, tostring(lua, other, &mut kept)),
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
                        // Loading the rule state runs the script's top level.
                        budget.reset(self.rule_deadline());
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
                    // Loading the rule state runs the script's top level.
                    budget.reset(self.rule_deadline());
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
