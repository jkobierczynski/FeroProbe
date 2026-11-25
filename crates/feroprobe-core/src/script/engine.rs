//! Running scripts: their rules decide where they run, then their
//! actions run, many at once, each in its own sandbox.

use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::{Duration, Instant};

use futures::StreamExt;
use mlua::{Function, Lua, MultiValue, Table, Value};

use super::args::{ArgTable, ArgValue};
use super::output::{ScriptResult, ScriptTable, ScriptValue, bytes_to_text_max, name_to_text_max};
use super::refused::Refusals;
use super::registry::Registry;
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

/// `fero.smb`: the SMB2 NEGOTIATE exchange.
const SMB_LIBRARY: &str = include_str!("smb.lua");

/// `fero.ntlm`: the NTLM NEGOTIATE and CHALLENGE messages.
const NTLM_LIBRARY: &str = include_str!("ntlm.lua");

/// `fero.ssh`: the SSH version exchange and KEXINIT.
const SSH_LIBRARY: &str = include_str!("ssh.lua");

/// `fero.starttls`: switching a plain-text connection to TLS.
const STARTTLS_LIBRARY: &str = include_str!("starttls.lua");

/// `fero.tls`: TLS and SSLv2 hellos built and read by hand.
const TLS_LIBRARY: &str = include_str!("tls.lua");

/// `fero.snmp`: SNMP requests, walks and SNMPv3 engine discovery.
const SNMP_LIBRARY: &str = include_str!("snmp.lua");

/// The NSE compatibility layer (roadmap 7.6): modules under nmap's
/// library names, written for FeroProbe on top of `fero` from nmap's
/// public API documentation (never from nselib). `require` loads one the
/// first time a script asks for it, so scripts that never ask pay nothing.
const NSE_MODULES: &[(&str, &str)] = &[
    ("base64", include_str!("nse/base64.lua")),
    ("bits", include_str!("nse/bits.lua")),
    ("brute", include_str!("nse/brute.lua")),
    ("comm", include_str!("nse/comm.lua")),
    ("creds", include_str!("nse/creds.lua")),
    ("datetime", include_str!("nse/datetime.lua")),
    ("formulas", include_str!("nse/formulas.lua")),
    ("ftp", include_str!("nse/ftp.lua")),
    ("geoip", include_str!("nse/geoip.lua")),
    ("http", include_str!("nse/http.lua")),
    ("io", include_str!("nse/io.lua")),
    ("ipOps", include_str!("nse/ipOps.lua")),
    ("irc", include_str!("nse/irc.lua")),
    ("json", include_str!("nse/json.lua")),
    ("knx", include_str!("nse/knx.lua")),
    ("lfs", include_str!("nse/lfs.lua")),
    ("listop", include_str!("nse/listop.lua")),
    ("match", include_str!("nse/match.lua")),
    ("nmap", include_str!("nse/nmap.lua")),
    ("oops", include_str!("nse/oops.lua")),
    ("openssl", include_str!("nse/openssl.lua")),
    ("outlib", include_str!("nse/outlib.lua")),
    ("rand", include_str!("nse/rand.lua")),
    ("shortport", include_str!("nse/shortport.lua")),
    ("smb", include_str!("nse/smb.lua")),
    ("snmp", include_str!("nse/snmp.lua")),
    ("ssh2", include_str!("nse/ssh2.lua")),
    ("sslcert", include_str!("nse/sslcert.lua")),
    ("stdnse", include_str!("nse/stdnse.lua")),
    ("strbuf", include_str!("nse/strbuf.lua")),
    ("stringaux", include_str!("nse/stringaux.lua")),
    ("tab", include_str!("nse/tab.lua")),
    ("tableaux", include_str!("nse/tableaux.lua")),
    ("target", include_str!("nse/target.lua")),
    ("tls", include_str!("nse/tls.lua")),
    ("unpwdb", include_str!("nse/unpwdb.lua")),
    ("url", include_str!("nse/url.lua")),
    ("vulns", include_str!("nse/vulns.lua")),
];

/// Lua's own libraries a script may `require` by name, as NSE scripts do
/// (`local string = require "string"`).
const STANDARD_MODULES: &[&str] = &["string", "table", "math", "coroutine", "utf8", "os"];

/// Where the loaded modules of a state are kept.
const NSE_LOADED: &str = "feroprobe.nse.loaded";

/// Set in a state once its script used `require`: it is an NSE script, and
/// gets the host table and registry in nmap's form.
pub(crate) struct NseScript;

/// `require(name)`: one of [`NSE_MODULES`] or [`STANDARD_MODULES`], loaded
/// once per state; anything else is an error naming the module.
fn install_require(lua: &Lua, fero: &Table) -> mlua::Result<()> {
    lua.set_named_registry_value(NSE_LOADED, lua.create_table()?)?;
    let fero = fero.clone();
    let require = lua.create_function(move |lua, name: String| {
        // The first `require` makes this an NSE script: `nmap` is loaded
        // with it, as it sets up the host table and registries.
        let first = lua.app_data_ref::<NseScript>().is_none();
        lua.set_app_data(NseScript);
        if first {
            let require: Function = lua.globals().raw_get("require")?;
            // nmap preloads `nmap` and Lua's `io` as globals, so NSE
            // scripts use `nmap.registry`, `nmap.new_socket`, `io.open`,
            // ... without requiring them (239 of nmap 7.99's scripts use
            // the `nmap` global without a require). FeroProbe loads both
            // on the first require (which is what makes this an NSE
            // script) and sets them as globals too.
            let nmap: Value = require.call("nmap")?;
            lua.globals().raw_set("nmap", nmap)?;
            let io: Value = require.call("io")?;
            lua.globals().raw_set("io", io)?;
        }
        let loaded: Table = lua.named_registry_value(NSE_LOADED)?;
        let have: Value = loaded.raw_get(name.as_str())?;
        if !have.is_nil() {
            return Ok(have);
        }
        let g = lua.globals();
        let module: Value = if name == "_G" {
            Value::Table(g)
        } else if STANDARD_MODULES.contains(&name.as_str()) {
            g.raw_get(name.as_str())?
        } else if let Some((_, src)) = NSE_MODULES.iter().find(|(n, _)| *n == name) {
            // Marked loaded before it runs, so modules that need each
            // other do not loop.
            loaded.raw_set(name.as_str(), true)?;
            let v: Value = lua
                .load(*src)
                .set_name(format!("=nse.{name}"))
                .call(fero.clone())?;
            if v.is_nil() { Value::Boolean(true) } else { v }
        } else {
            return Err(mlua::Error::runtime(format!(
                "module '{name}' is not available in FeroProbe (its NSE compatibility layer has: {})",
                NSE_MODULES
                    .iter()
                    .map(|(n, _)| *n)
                    .chain(STANDARD_MODULES.iter().copied())
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        };
        loaded.raw_set(name.as_str(), module.clone())?;
        Ok(module)
    })?;
    lua.globals().raw_set("require", require)
}

/// After a rule or action of an NSE script: write what it changed in
/// `nmap.registry` and `host.registry` back to the run's registries. A
/// value the registry cannot keep (a function, say) is left out, as
/// `-d` says.
fn nse_flush(lua: &Lua, script: &str) {
    if lua.app_data_ref::<NseScript>().is_none() {
        return;
    }
    let Ok(fero) = lua.globals().raw_get::<Table>("fero") else {
        return;
    };
    if let Ok(f) = fero.raw_get::<Function>("__nse_flush")
        && let Err(e) = f.call::<()>(())
    {
        crate::debug::debug(1, || {
            format!(
                "Script {script}: registry not saved: {}",
                e.to_string().lines().next().unwrap_or("")
            )
        });
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

-- A table for a script's output that keeps its names in the order they
-- are set, as nmap's stdnse.output_table: the normal report, XML and
-- JSON then show them in that order instead of sorted.
fero.output_table = function()
  local order = {}
  return setmetatable({}, {
    __fero_order = order,
    __newindex = function(t, k, v)
      if v ~= nil and type(k) == "string" then order[#order + 1] = k end
      rawset(t, k, v)
    end,
    -- How many entries are set, as nmap's: scripts test `#out > 0`.
    __len = function(t)
      local n = 0
      for _ in next, t do n = n + 1 end
      return n
    end,
  })
end

-- A number of seconds as nmap writes a time span: "0s", "5s", "-1m05s",
-- "2h03m04s", "1d02h03m04s".
fero.format_time = function(d)
  d = math.tointeger(d) or math.floor(d + 0.5)
  if d == 0 then return "0s" end
  local sign = d < 0 and "-" or ""
  d = math.abs(d)
  local days, h, m, s = d // 86400, d // 3600 % 24, d // 60 % 60, d % 60
  if days > 0 then return string.format("%s%dd%02dh%02dm%02ds", sign, days, h, m, s) end
  if h > 0 then return string.format("%s%dh%02dm%02ds", sign, h, m, s) end
  if m > 0 then return string.format("%s%dm%02ds", sign, m, s) end
  return string.format("%s%ds", sign, s)
end

-- fero.record_skew(remote, scanner): note how far the clock of a service
-- on this host (Unix seconds `remote`) is from the scanner's when the
-- answer came (`scanner`, os.time() when left out), for clock-skew.
fero.record_skew = function(remote, scanner)
  if fero.host_registry == nil or type(remote) ~= "number" then return end
  scanner = scanner or os.time()
  -- A full registry loses the sample, never the calling script's output.
  pcall(fero.host_registry.append, "clock_skew", {
    script = SCRIPT_NAME, skew = math.floor(remote - scanner + 0.5),
  })
end

-- Bytes as lower-case hex, with an optional separator between bytes.
fero.hex = function(s, sep)
  local t = {}
  for i = 1, #s do t[i] = string.format("%02x", s:byte(i)) end
  return table.concat(t, sep or "")
end

-- A buffered reader over a connected socket, for line protocols and
-- length-prefixed records: r:line() (without its CR LF), r:bytes(n), and
-- r:reply() for FTP/SMTP-style replies ("250-..." lines up to "250 ...").
-- Each returns nil and a message on a timeout, the end of the
-- connection, or a line or reply too long to be one.
local MAX_LINE, MAX_REPLY_LINES = 65536, 1000
fero.reader = function(sock)
  local buf = ""
  local r = {}
  local function fill()
    local ok, data = sock:receive()
    if not ok then return false, data end
    buf = buf .. data
    return true
  end
  function r:line()
    while true do
      local i = buf:find("\n", 1, true)
      if i then
        if i - 1 > MAX_LINE then return nil, "line too long" end
        local line = buf:sub(1, i - 1)
        buf = buf:sub(i + 1)
        return (line:gsub("\r$", ""))
      end
      if #buf > MAX_LINE then return nil, "line too long" end
      local ok, err = fill()
      if not ok then return nil, err end
    end
  end
  function r:bytes(n)
    while #buf < n do
      local ok, err = fill()
      if not ok then return nil, err end
    end
    local out = buf:sub(1, n)
    buf = buf:sub(n + 1)
    return out
  end
  function r:reply()
    local line, err = self:line()
    if not line then return nil, err end
    local code, sep = line:match("^(%d%d%d)([ -]?)")
    if code and sep == "" and #line > 3 then code = nil end
    if not code then return nil, "not a numbered reply: " .. line:sub(1, 80) end
    local lines = { line }
    if sep == "-" then
      while #lines < MAX_REPLY_LINES do
        line, err = self:line()
        if not line then return nil, err end
        lines[#lines + 1] = line
        if line:sub(1, 4) == code .. " " or line == code then
          return tonumber(code), lines
        end
      end
      return nil, "reply too long"
    end
    return tonumber(code), lines
  end
  return r
end
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
    registry: &Arc<Registry>,
    by_name: bool,
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
    super::registry::install(lua, &fero, registry, scope.addr)?;
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
    let crypto = lua.create_table()?;
    crypto.raw_set(
        "digest",
        lua.create_function(|lua, (name, data): (String, mlua::LuaString)| {
            match super::digest::digest(&name, &data.as_bytes()) {
                Some(d) => Ok(Value::String(lua.create_string(d)?)),
                None => Err(mlua::Error::runtime(format!(
                    "fero.crypto.digest: unknown algorithm {name:?}"
                ))),
            }
        })?,
    )?;
    crypto.raw_set(
        "random_bytes",
        lua.create_function(|lua, n: usize| {
            if n > 65536 {
                return Err(mlua::Error::runtime(
                    "fero.crypto.random_bytes: at most 65536 bytes",
                ));
            }
            let bytes = super::digest::random(n)
                .ok_or_else(|| mlua::Error::runtime("no random bytes available"))?;
            lua.create_string(bytes)
        })?,
    )?;
    fero.raw_set("crypto", crypto)?;
    // For the NSE layer's `openssl` module: the bignum_* calls.
    let bignum = lua.create_table()?;
    super::bignum::install(lua, &bignum)?;
    fero.raw_set("__bignum", bignum)?;
    // For the NSE layer's `nmap.fetchfile` and `io`: read-only access to
    // the data directories and the files named in --script-args.
    fero.raw_set(
        "__fetchfile",
        lua.create_function(|_, name: String| {
            Ok(super::files::fetch(super::files::data_roots(), &name))
        })?,
    )?;
    {
        let named = super::files::arg_paths(args);
        fero.raw_set(
            "__read_file",
            lua.create_function(move |lua, path: String| {
                match super::files::read(super::files::data_roots(), &named, &path) {
                    Ok(b) => Ok((Value::String(lua.create_string(b)?), Value::Nil, Value::Nil)),
                    Err(e) => {
                        let (msg, code) = e.describe(&path);
                        Ok((
                            Value::Nil,
                            Value::String(lua.create_string(msg)?),
                            Value::Integer(code.into()),
                        ))
                    }
                }
            })?,
        )?;
    }
    // fero.tls.parse_certificate(der): a certificate read from a TLS
    // handshake, as sock:get_ssl_certificate() gives it; the rest of
    // fero.tls is in tls.lua.
    let tls = lua.create_table()?;
    tls.raw_set(
        "parse_certificate",
        lua.create_function(|lua, der: mlua::LuaString| {
            super::tls::cert_table(lua, &der.as_bytes())
        })?,
    )?;
    fero.raw_set("tls", tls)?;
    // fero.sleep(seconds): wait without blocking other scripts, as nmap's
    // stdnse.sleep; at most ten minutes per call.
    fero.raw_set(
        "sleep",
        lua.create_async_function(|_, secs: f64| async move {
            if secs.is_finite() && secs > 0.0 {
                tokio::time::sleep(std::time::Duration::from_secs_f64(secs.min(600.0))).await;
            }
            Ok(())
        })?,
    )?;
    // fero.mac_vendor("00:0c:29:01:02:03"): the vendor the OUI list
    // (`--oui-file` or the system's) gives for a MAC address, or nil.
    fero.raw_set(
        "mac_vendor",
        lua.create_function(|_, mac: String| {
            let mut b = [0u8; 6];
            let mut parts = mac.split([':', '-']);
            for byte in &mut b {
                match parts.next().and_then(|p| u8::from_str_radix(p, 16).ok()) {
                    Some(v) => *byte = v,
                    None => return Ok(None),
                }
            }
            if parts.next().is_some() {
                return Ok(None);
            }
            Ok(crate::oui::lookup(crate::arp::MacAddr(b)).map(str::to_string))
        })?,
    )?;
    // fero.clock_ms(): milliseconds on a monotonic clock, for deadlines
    // finer than os.time's whole seconds.
    let start = std::time::Instant::now();
    fero.raw_set(
        "clock_ms",
        lua.create_function(move |_, ()| Ok(start.elapsed().as_millis() as i64))?,
    )?;
    fero.raw_set(
        "verbosity",
        // Like nmap, a script chosen by name or file path sees one level
        // more than -v gave, so it shows the detail it was asked for.
        lua.create_function(move |_, ()| {
            Ok(crate::debug::verbosity().saturating_add(u8::from(by_name)))
        })?,
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
    // The platform's path separator, for the NSE layer's `lfs`.
    fero.raw_set("path_separator", std::path::MAIN_SEPARATOR_STR)?;
    fero.raw_set(
        "address_family",
        if scope.addr.is_some_and(|a| a.is_ipv6()) {
            "inet6"
        } else {
            "inet"
        },
    )?;
    g.raw_set("fero", fero.clone())?;
    install_require(lua, &fero)?;
    lua.load(LIBRARY)
        .set_name("=fero")
        .call::<()>((fero.clone(), args_to_lua(lua, args)?))?;
    lua.load(SMB_LIBRARY)
        .set_name("=fero.smb")
        .call::<()>(fero.clone())?;
    lua.load(NTLM_LIBRARY)
        .set_name("=fero.ntlm")
        .call::<()>(fero.clone())?;
    lua.load(SSH_LIBRARY)
        .set_name("=fero.ssh")
        .call::<()>(fero.clone())?;
    lua.load(STARTTLS_LIBRARY)
        .set_name("=fero.starttls")
        .call::<()>(fero.clone())?;
    lua.load(TLS_LIBRARY)
        .set_name("=fero.tls")
        .call::<()>(fero.clone())?;
    lua.load(SNMP_LIBRARY)
        .set_name("=fero.snmp")
        .call::<()>(fero)?;
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
    if lua.app_data_ref::<NseScript>().is_some()
        && let Ok(f) = lua
            .globals()
            .raw_get::<Table>("fero")
            .and_then(|f| f.raw_get::<Function>("__nse_host"))
    {
        f.call::<()>(t.clone())?;
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

/// `fero.get_port_state(host, port)`: the port table of the scanned port
/// `port` names (`number`, and `protocol`, `"tcp"` when left out) when it
/// may be open, else `nil`. Hostrule scripts use it to find the service
/// they need, as nmap's `nmap.get_port_state`; only the ports a portrule
/// would be asked about are known, so a closed or filtered port is `nil`.
fn install_port_state(lua: &Lua, h: &HostResult) -> mlua::Result<()> {
    let ports: Vec<PortResult> = h.ports.iter().filter(|p| rule_port(p)).cloned().collect();
    let f = lua.create_function(move |lua, (_host, port): (Value, Table)| {
        let number: i64 = port.get("number")?;
        let proto: Option<String> = port.get("protocol")?;
        let proto = proto.as_deref().unwrap_or("tcp");
        match ports
            .iter()
            .find(|p| i64::from(p.port) == number && p.protocol.to_string() == proto)
        {
            Some(p) => Ok(Value::Table(port_table(lua, p)?)),
            None => Ok(Value::Nil),
        }
    })?;
    lua.globals()
        .get::<Table>("fero")?
        .raw_set("get_port_state", f)
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
fn scope_of(id: &str, h: Option<&HostResult>, refusals: &Arc<Refusals>) -> Scope {
    let Some(h) = h else {
        return Scope {
            script: id.to_string(),
            refusals: refusals.clone(),
            ..Scope::default()
        };
    };
    let mut s = Scope {
        addr: Some(h.addr),
        names: h.hostname.iter().chain(h.rdns.iter()).cloned().collect(),
        script: id.to_string(),
        refusals: refusals.clone(),
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
    // A table from `fero.output_table()` keeps its names in the order
    // they were first set (a name removed and set again goes last); any
    // other table's names, and names set without the table seeing them
    // (`rawset`), are sorted.
    let order = output_order(t);
    named.sort_by(|a, b| {
        let pos = |k: &mlua::LuaString| {
            order
                .as_ref()
                .and_then(|o| o.get(&k.as_bytes()[..]).copied())
                .unwrap_or(usize::MAX)
        };
        pos(&a.0)
            .cmp(&pos(&b.0))
            .then_with(|| a.0.as_bytes()[..].cmp(&b.0.as_bytes()[..]))
    });
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

/// The metatable field where `fero.output_table()` lists its names in
/// the order they were set.
const ORDER_FIELD: &str = "__fero_order";

/// Where each name of an ordered table comes: its last place in the
/// table's list of names, or `None` for a table that keeps no order.
fn output_order(t: &Table) -> Option<std::collections::HashMap<Vec<u8>, usize>> {
    let list: Table = t.metatable()?.raw_get(ORDER_FIELD).ok()?;
    let mut order = std::collections::HashMap::new();
    for (i, k) in list.sequence_values::<Value>().enumerate() {
        if let Ok(Value::String(s)) = k {
            order.insert(s.as_bytes().to_vec(), i);
        }
    }
    Some(order)
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
    /// What the scripts leave for each other (`fero.registry`).
    registry: Arc<Registry>,
    /// `--script-timeout`: the longest one script run against one host
    /// or port may take. `None` for no limit.
    pub timeout: Option<Duration>,
    /// Script runs at once.
    pub parallel: usize,
    /// Connections the scopes refused, told once per script at the end
    /// of each phase.
    refusals: Arc<Refusals>,
    /// Hosts the scripts added to the scan (`newtargets`).
    new_targets: Arc<super::newtargets::NewTargets>,
    /// `-6`: prerule and postrule scripts see `inet6` as the address
    /// family (host scripts see their host's).
    pub ipv6: bool,
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
            registry: Arc::new(Registry::default()),
            timeout,
            parallel: DEFAULT_PARALLEL,
            refusals: Arc::default(),
            new_targets: Arc::default(),
            ipv6: false,
        })
    }

    pub fn scripts(&self) -> &[Arc<Script>] {
        &self.scripts
    }

    /// The hosts scripts added to the scan so far, for the CLI to scan
    /// after the command line's targets.
    pub fn new_targets(&self) -> &super::newtargets::NewTargets {
        &self.new_targets
    }

    /// A fresh state with `script` loaded, for its rules or action.
    fn state(&self, script: &Script, on: Against<'_>, budget: &Arc<Budget>) -> Result<Lua, String> {
        let lua = sandbox::new_state(budget).map_err(|e| e.to_string())?;
        let scope = Arc::new(scope_of(&script.id, on.host(), &self.refusals));
        install_library(
            &lua,
            &script.id,
            on.kind(),
            &self.args,
            &scope,
            &self.registry,
            script.selection.raises_verbosity(),
        )
        .map_err(|e| e.to_string())?;
        super::newtargets::install(&lua, &self.new_targets, on.kind(), self.ipv6)
            .map_err(|e| e.to_string())?;
        if let Some(h) = on.host() {
            install_port_state(&lua, h).map_err(|e| e.to_string())?;
        }
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
        nse_flush(lua, &script.id);
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
            let ret = action.call_async::<MultiValue>(args).await;
            nse_flush(&lua, &script.id);
            let ret = ret.map_err(|e| sandbox::error_text(&e, &budget))?;
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
        self.warn_refused();
        results
    }

    /// One warning per script for the connections its scope refused in
    /// the phase just done.
    fn warn_refused(&self) {
        for w in self.refusals.warnings() {
            eprintln!("{w}");
        }
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
        self.warn_refused();
    }
}
