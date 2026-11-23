-- NSE compatibility layer: the `stdnse` module.
-- Written for FeroProbe from nmap's public API documentation (not from
-- nselib); GPL-3.0-or-later, like FeroProbe. Calls map onto `fero`.
local fero = ...
local nmap = require "nmap"
local stdnse = {}

-- A message from (fmt, ...) as string.format makes it; a lone value as
-- tostring gives it.
local function text(fmt, ...)
  if select("#", ...) == 0 then return tostring(fmt) end
  return string.format(fmt, ...)
end

-- debug(level, fmt, ...), or debug(fmt, ...) at level 1.
local function leveled(show)
  return function(level, ...)
    if type(level) ~= "number" then return show(1, level, ...) end
    return show(level, ...)
  end
end

local function show_debug(level, fmt, ...)
  if fero.debugging() >= level then fero.debug(level, text(fmt, ...)) end
end
local function show_verbose(level, fmt, ...)
  if fero.verbosity() >= level or fero.debugging() >= level then
    fero.debug(0, text(fmt, ...))
  end
end

stdnse.debug = leveled(show_debug)
stdnse.print_debug = stdnse.debug
stdnse.verbose = leveled(show_verbose)
stdnse.print_verbose = stdnse.verbose
for i = 0, 9 do
  stdnse["debug" .. i] = function(...) return show_debug(i, ...) end
  stdnse["verbose" .. i] = function(...) return show_verbose(i, ...) end
end
stdnse.log_error = function(fmt, ...)
  fero.debug(0, "ERROR: " .. text(fmt, ...))
end
stdnse.warn = function(fmt, ...)
  fero.debug(0, "WARNING: " .. text(fmt, ...))
end

stdnse.get_script_args = fero.args.get
stdnse.output_table = fero.output_table
stdnse.sleep = fero.sleep
stdnse.clock_ms = nmap.clock_ms
stdnse.clock_us = function() return nmap.clock_ms() * 1000 end

-- Text output from a table: each string a line, each table its `name`
-- (if any) and then its entries one level deeper; `warning` entries
-- become "WARNING: ..." lines. Every line is indented two spaces per
-- level, and the result starts with a line break, so the report puts
-- the list under the script's name.
local function format_lines(data, indent, lines)
  local pad = string.rep("  ", indent)
  if data.warning then
    lines[#lines + 1] = pad .. "WARNING: " .. tostring(data.warning)
  end
  for _, v in ipairs(data) do
    if type(v) == "table" then
      local deeper = indent
      if v.name then
        lines[#lines + 1] = pad .. tostring(v.name)
        deeper = indent + 1
      end
      format_lines(v, deeper + (v.name and 0 or 1), lines)
    else
      for line in (tostring(v) .. "\n"):gmatch("([^\n]*)\n") do
        lines[#lines + 1] = pad .. line
      end
    end
  end
end

stdnse.format_output = function(status, data, indent)
  if not status then
    if fero.debugging() > 0 then return "ERROR: " .. tostring(data) end
    return nil
  end
  if type(data) ~= "table" then return data end
  local lines = {}
  format_lines(data, (indent or 0) + 1, lines)
  if #lines == 0 then return nil end
  return "\n" .. table.concat(lines, "\n")
end

-- Hex: tohex("ab") == "6162"; options.separator goes between groups of
-- options.group hex digits (2 by default). A number is written in hex.
stdnse.tohex = function(s, options)
  options = options or {}
  local hex
  if type(s) == "number" then
    hex = string.format("%x", s)
  else
    hex = fero.hex(tostring(s))
  end
  local sep = options.separator
  if sep and sep ~= "" then
    local group = options.group or 2
    local parts = {}
    -- Groups are counted from the right, as for a number.
    local first = #hex % group
    if first > 0 then parts[1] = hex:sub(1, first) end
    for i = first + 1, #hex, group do parts[#parts + 1] = hex:sub(i, i + group - 1) end
    hex = table.concat(parts, sep)
  end
  return hex
end

stdnse.fromhex = function(hex)
  hex = tostring(hex):gsub("[%s:]", "")
  if #hex % 2 == 1 or hex:find("%X") then return nil end
  return (hex:gsub("%x%x", function(h) return string.char(tonumber(h, 16)) end))
end

-- "10", "10ms", "1.5s", "5m", "2h" in seconds; nil and a message for
-- anything else.
stdnse.parse_timespec = function(spec)
  if type(spec) == "number" then return spec end
  if type(spec) ~= "string" then return nil, "Can't parse nil timespec" end
  local n, unit = spec:match("^%s*(%d*%.?%d+)%s*(%a*)%s*$")
  local mult = ({ [""] = 1, ms = 0.001, s = 1, m = 60, h = 3600 })[unit and unit:lower() or "?"]
  if not n or not mult then return nil, "Can't parse timespec: " .. spec end
  return tonumber(n) * mult
end

-- A connection timeout in milliseconds for this host: FeroProbe gives
-- scripts no round-trip times, so it is the middle of the range asked
-- for (5 seconds when no range is given).
stdnse.get_timeout = function(_, max_timeout, min_timeout)
  local t = 5000
  if max_timeout and t > max_timeout then t = max_timeout end
  if min_timeout and t < min_timeout then t = min_timeout end
  return t
end

stdnse.get_hostname = function(host)
  if type(host) ~= "table" then return host end
  if host.targetname and host.targetname ~= "" then return host.targetname end
  if host.name and host.name ~= "" then return host.name end
  return host.ip
end

stdnse.format_mac = function(mac)
  if type(mac) ~= "string" then return nil end
  if #mac == 17 and mac:find("^%x%x[:-]") then return mac:lower():gsub("-", ":") end
  local t = {}
  for i = 1, #mac do t[i] = string.format("%02x", mac:byte(i)) end
  return table.concat(t, ":")
end

stdnse.string_or_blank = function(s, blank)
  if s == nil or s == "" then return blank or "<blank>" end
  return s
end

stdnse.generate_random_string = function(len, charset)
  return (require "rand").random_string(len, charset)
end

stdnse.gettid = function()
  return tostring(coroutine.running()):match("0x%x+") or "1"
end

-- Whether port's number is in a range list such as "22,80,8000-8100".
stdnse.in_port_range = function(port, range)
  local n = type(port) == "table" and port.number or tonumber(port)
  for part in tostring(range):gmatch("[^,]+") do
    local a, b = part:match("^%s*(%d+)%s*%-%s*(%d+)%s*$")
    if a then
      if n >= tonumber(a) and n <= tonumber(b) then return true end
    elseif tonumber(part) == n then
      return true
    end
  end
  return false
end

-- A line reader over a connected socket: each call gives the next piece
-- of data up to (not including) the separator pattern, or nil and a
-- message.
stdnse.make_buffer = function(socket, sep)
  sep = sep or "\r?\n"
  return function()
    local ok, data = socket:receive_buf(sep, false)
    if ok then return data end
    return nil, data
  end
end

-- Threads run to completion when started; the returned coroutine is
-- already dead, so a wait for it ends at once. Errors in the worker are
-- shown with -d and end only that worker, as in nmap. The second result
-- is nmap's status function: "dead" and the worker's error, if any.
stdnse.new_thread = function(f, ...)
  local ok, err = pcall(f, ...)
  if not ok then fero.debug(1, "thread failed: " .. tostring(err)) end
  local co = coroutine.create(function() end)
  coroutine.resume(co)
  local failure = (not ok) and err or nil
  return co, function() return "dead", failure end
end
stdnse.base = function() return coroutine.running() end

stdnse.get_script_interfaces = function() return {} end

stdnse.silent_require = require

-- registry_get({"a", "b"}): nmap.registry.a.b, or nil if any step is missing.
stdnse.registry_get = function(subkeys)
  local t = nmap.registry
  for _, k in ipairs(subkeys) do
    if type(t) ~= "table" then return nil end
    t = t[k]
  end
  return t
end
local function registry_walk(subkeys)
  local t = nmap.registry
  for _, k in ipairs(subkeys) do
    if t[k] == nil then t[k] = {} end
    t = t[k]
  end
  return t
end
stdnse.registry_add_table = function(subkeys, key, value, allow_duplicates)
  local t = registry_walk(subkeys)
  if not allow_duplicates and t[key] ~= nil then return end
  t[key] = value
end
stdnse.registry_add_array = function(subkeys, value, allow_duplicates)
  local t = registry_walk(subkeys)
  if not allow_duplicates then
    for _, v in ipairs(t) do if v == value then return end end
  end
  t[#t + 1] = value
end

-- Old names kept in nselib for scripts written against them.
stdnse.strsplit = function(pattern, text) return (require "stringaux").strsplit(pattern, text) end
stdnse.keys = function(t) return (require "tableaux").keys(t) end
stdnse.contains = function(t, v) return (require "tableaux").contains(t, v) end
stdnse.format_time = function(...) return (require "datetime").format_time(...) end
stdnse.format_timestamp = function(...) return (require "datetime").format_timestamp(...) end
stdnse.format_difftime = function(...) return (require "datetime").format_difftime(...) end
stdnse.escape_filename = function(s) return (require "stringaux").filename_escape(s) end

return stdnse
