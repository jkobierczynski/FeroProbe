-- NSE compatibility layer: the `nmap` module.
-- Written for FeroProbe from nmap's public API documentation (not from
-- nselib); GPL-3.0-or-later, like FeroProbe. Calls map onto `fero`.
local fero = ...
local nmap = {}

local function unsupported(name)
  return function()
    error("nmap." .. name .. " is not available in FeroProbe", 2)
  end
end

nmap.verbosity = fero.verbosity
nmap.debugging = fero.debugging
nmap.have_ssl = function() return true end
-- Scripts cannot send raw packets in FeroProbe, so they are told they
-- have no privileges and take their unprivileged path.
nmap.is_privileged = function() return false end
nmap.address_family = function() return fero.address_family end
nmap.timing_level = function() return fero.timing_level or 3 end
nmap.version_intensity = function() return 7 end

-- Wall-clock milliseconds, advancing with the monotonic clock.
local epoch_ms = os.time() * 1000 - fero.clock_ms()
nmap.clock_ms = function() return epoch_ms + fero.clock_ms() end
nmap.clock = function() return nmap.clock_ms() / 1000 end

-- Copy-on-read view of a FeroProbe registry that looks like a plain
-- table: each top-level entry is read (copied) the first time the script
-- touches it, changed in place, and written back after every rule and
-- action by fero.__nse_flush, merged with what other scripts did meanwhile.
local flushes = {}

local function deep_copy(v, seen)
  if type(v) ~= "table" then return v end
  seen = seen or {}
  if seen[v] then return seen[v] end
  local c = {}
  seen[v] = c
  for k, x in pairs(v) do c[deep_copy(k, seen)] = deep_copy(x, seen) end
  return c
end

-- The merge puts entries the script added after the end of a list after
-- the list's end at the time, which moves them when another script
-- added entries meanwhile; `moves` (from fero.registry.merge) says where
-- they went: { from =, n =, to =, sub = { [key] = moves } }. Move the
-- script's own entries in dst there too, so a table it still holds
-- stays tied to its own entry, not another script's.
local function follow_moves(dst, moves)
  if not moves or not moves.from then return end
  local from, n, to = moves.from, moves.n, moves.to
  local held = {}
  for i = 0, n - 1 do
    held[i] = dst[from + i]
    dst[from + i] = nil
  end
  for i = 0, n - 1 do dst[to + i] = held[i] end
end

-- Make table dst hold what src holds, keeping dst's nested tables where
-- src has a table under the same key, after following the merge's
-- moves. The registry keeps no shared tables, so a table the script put
-- in two places (already in `seen`) is not synced twice: the second
-- place gets its own copy, and the view then matches what is stored
-- entry for entry.
local function sync(dst, src, moves, seen)
  seen[dst] = true
  follow_moves(dst, moves)
  local sub = moves and moves.sub or {}
  for key in pairs(dst) do
    if src[key] == nil then dst[key] = nil end
  end
  for key, v in pairs(src) do
    local d = dst[key]
    if type(v) == "table" and type(d) == "table" and not seen[d] then
      sync(d, v, sub[key], seen)
    else
      dst[key] = v
    end
  end
end

local function registry_view(reg)
  local base, live, touched = {}, {}, {}
  local function touch(k)
    if type(k) ~= "string" then
      error("FeroProbe's registry takes only string names at its top level", 3)
    end
    if not touched[k] then
      touched[k] = true
      base[k] = reg.get(k)
      live[k] = deep_copy(base[k])
    end
  end
  flushes[#flushes + 1] = function()
    -- Every name is merged before any live table is synced, so a table
    -- the script put under two names is written as the script left it,
    -- not as another name's merged value. A name whose merge fails (its
    -- value cannot be stored) keeps its old base and is not synced; the
    -- others still are, so a merge already stored is never applied twice.
    local stored, first_err = {}, nil
    for k in pairs(touched) do
      local ok, v, moves = pcall(reg.merge, k, base[k], live[k])
      if ok then
        stored[k] = { v, moves }
      elseif first_err == nil then
        first_err = v
      end
    end
    local seen = {}
    for k, s in pairs(stored) do
      -- The script now sees the merged value, with what other scripts
      -- added meanwhile, as it would in nmap's shared table: its tables
      -- are updated in place (references it holds stay valid), and the
      -- next round's changes are measured against that value, so a later
      -- edit or removal hits the entry it names now, not another script's.
      local v, moves = s[1], s[2]
      if type(live[k]) == "table" and type(v) == "table" and not seen[live[k]] then
        sync(live[k], v, moves, seen)
      else
        live[k] = v
      end
      base[k] = deep_copy(v)
    end
    if first_err ~= nil then error(first_err, 0) end
  end
  return setmetatable({}, {
    __index = function(_, k)
      if type(k) ~= "string" then return nil end
      touch(k)
      return live[k]
    end,
    __newindex = function(_, k, v)
      touch(k)
      live[k] = v
    end,
    -- Only the entries this script has touched can be listed.
    __pairs = function()
      return function(_, k)
        local nk, v = next(live, k)
        while nk ~= nil and v == nil do nk, v = next(live, nk) end
        return nk, v
      end, nil, nil
    end,
  })
end

nmap.registry = registry_view(fero.registry)

fero.__nse_flush = function()
  local first_err
  for _, f in ipairs(flushes) do
    local ok, err = pcall(f)
    if not ok and not first_err then first_err = err end
  end
  if first_err then error(first_err, 0) end
end

-- The host table in nmap's form: bin_ip, raw mac_addr, os as tables,
-- and host.registry.
local host_view
fero.__nse_host = function(host)
  if host_view == nil and fero.host_registry then
    host_view = registry_view(fero.host_registry)
  end
  host.registry = host_view
  local ip = host.ip
  local ipOps = require "ipOps"
  host.bin_ip = ipOps.ip_to_str(ip)
  if type(host.mac_addr) == "string" and #host.mac_addr == 17 then
    host.mac_addr = host.mac_addr:gsub("[:-]", ""):gsub("%x%x", function(h)
      return string.char(tonumber(h, 16))
    end)
  end
  if type(host.os) == "table" then
    local list = {}
    for i, name in ipairs(host.os) do
      list[i] = { name = name, classes = {} }
    end
    host.os = list
  end
  host.times = host.times or { srtt = nil, rttvar = nil, timeout = 1 }
end

-- nmap.new_try: a function that passes on what follows a true status
-- and raises the error otherwise, calling the handler first.
nmap.new_try = function(handler)
  return function(status, ...)
    if status then return ... end
    if handler then handler() end
    error((...) or "try failed", 0)
  end
end

-- Threads in FeroProbe's NSE layer run to completion when started
-- (stdnse.new_thread), so locks and condition variables never wait.
nmap.mutex = function()
  return function(op)
    if op == "trylock" or op == "lock" then return true end
    if op == "running" then return nil end
    return true
  end
end
nmap.condvar = function()
  return function() end
end

nmap.get_port_state = function(host, port)
  if fero.get_port_state == nil then return nil end
  return fero.get_port_state(host, port)
end

-- Scripts cannot change port results in FeroProbe.
nmap.set_port_state = function(_, port, state)
  fero.debug(2, string.format("nmap.set_port_state(%s, %s) ignored: scripts do not change port results",
    tostring(type(port) == "table" and port.number or port), tostring(state)))
end
nmap.set_port_version = function(_, port)
  fero.debug(2, string.format("nmap.set_port_version(%s) ignored: scripts do not change port results",
    tostring(type(port) == "table" and port.number or port)))
end

nmap.port_is_excluded = function() return false end
-- No data files are shipped for NSE scripts: this finds the user's own,
-- in FeroProbe's data directory or an installed nmap's (files.rs).
nmap.fetchfile = function(name)
  if type(name) ~= "string" then return nil end
  return fero.__fetchfile(name)
end
-- nmap.resolve(name [, family]): true and every address of name ("inet"
-- or "inet6" for one family), or false and "Failed to resolve".
nmap.resolve = function(name, family)
  if not fero.resolve then return false, "Failed to resolve" end
  return fero.resolve(name, family)
end
-- nmap.add_targets(t1, ...): queues hosts for the scan (see the target
-- module, which checks newtargets first, as nmap's does); the count
-- added, or 0 and a message. With no arguments, the targets waiting.
nmap.add_targets = function(...)
  if not fero.add_targets then return 0, "failed to add new targets." end
  return fero.add_targets(...)
end
nmap.new_targets_num = function()
  if not fero.new_targets_num then return 0 end
  return fero.new_targets_num()
end
-- nmap.get_dns_servers(): the addresses of the run's DNS servers
-- (--dns-servers, or the system's), which scripts may query.
nmap.get_dns_servers = function()
  local out = {}
  for _, s in ipairs(fero.dns_servers and fero.dns_servers() or {}) do
    out[#out + 1] = s.ip
  end
  return out
end
nmap.log_write = function(_, msg)
  fero.debug(0, tostring(msg))
end
nmap.get_payload_length = function() return 0 end

for _, name in ipairs({ "new_dnet", "pcap_open", "get_interface_info", "list_interfaces",
  "get_interface", "get_ports", "get_ttl" }) do
  nmap[name] = unsupported(name)
end

-- Sockets: fero.socket with nmap's methods. The engine keeps every
-- connection to the scanned host and the ports the scan probed.
local Socket = {}
Socket.__index = Socket

function Socket:connect(host, port, proto)
  return self.s:connect(host, port, proto or self.proto)
end
function Socket:send(data) return self.s:send(data) end
function Socket:sendto(host, port, data)
  local ok, err = self.s:connect(host, port, self.proto or "udp")
  if not ok then return ok, err end
  return self.s:send(data)
end
function Socket:receive() return self.s:receive() end
function Socket:receive_bytes(n) return self.s:receive_bytes(n) end
function Socket:receive_lines(n) return self.s:receive_lines(n) end
function Socket:receive_buf(delim, keep) return self.s:receive_buf(delim, keep) end
function Socket:set_timeout(ms) return self.s:set_timeout(math.max(0, math.floor(tonumber(ms) or 0))) end
function Socket:close() return self.s:close() end
function Socket:get_info() return self.s:get_info() end
function Socket:reconnect_ssl() return self.s:reconnect_ssl() end
function Socket:get_ssl_certificate()
  local raw, err = self.s:get_ssl_certificate()
  if not raw then return nil, err end
  return require("sslcert").parse_ssl_certificate(raw.der)
end
function Socket:bind() return false, "bind is not available in FeroProbe" end
function Socket:pcap_open() return false, "raw packets are not available in FeroProbe" end

nmap.new_socket = function(proto)
  local s = setmetatable({ s = fero.socket.new(), proto = proto }, Socket)
  -- nmap's default timeout is 30 seconds.
  s.s:set_timeout(30000)
  return s
end

return nmap
