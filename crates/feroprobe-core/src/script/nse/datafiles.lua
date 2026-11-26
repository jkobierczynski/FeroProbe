-- NSE compatibility layer: the `datafiles` module, which reads nmap's
-- data files (nmap-services, nmap-protocols, nmap-rpc, nmap-mac-prefixes)
-- and word lists. Written for FeroProbe from nmap's public API
-- documentation and the files' documented line formats (not from
-- nselib); GPL-3.0-or-later, like FeroProbe.
--
-- Files are found with nmap.fetchfile (FeroProbe's data directory,
-- $NMAPDIR, an installed nmap's data directory), or read as given when a
-- script argument names them. Without an installed nmap-services or
-- nmap-protocols, FeroProbe's own port and protocol names are used, and
-- without nmap-mac-prefixes, the OUI list FeroProbe reports vendors from.
local fero = ...
local nmap = require "nmap"
local io = require "io"
local datafiles = {}

-- The capture patterns of the common files: the key's captures become
-- keys, the value's the values. Comments start with "#".
local common_files = {
  ["nmap-rpc"] = { [function(l) return tonumber(l:match("^%s*[^%s#]+%s+(%d+)")) end] = "^%s*([^%s#]+)%s+%d+" },
  ["nmap-protocols"] = { [function(l) return tonumber(l:match("^%s*[^%s#]+%s+(%d+)")) end] = "^%s*([^%s#]+)%s+%d+" },
  ["nmap-services"] = {
    tcp = { [function(l) return tonumber(l:match("^%s*[^%s#]+%s+(%d+)/tcp")) end] = "^%s*([^%s#]+)%s+%d+/tcp" },
    udp = { [function(l) return tonumber(l:match("^%s*[^%s#]+%s+(%d+)/udp")) end] = "^%s*([^%s#]+)%s+%d+/udp" },
    sctp = { [function(l) return tonumber(l:match("^%s*[^%s#]+%s+(%d+)/sctp")) end] = "^%s*([^%s#]+)%s+%d+/sctp" },
  },
  ["nmap-mac-prefixes"] = { ["^%s*(%x+)%s"] = "^%s*%x+%s+(.-)%s*$" },
}
datafiles.common_files = common_files

-- A capture: a pattern's first capture (or whole match), or a function's
-- value for the line.
local function capture(c, line)
  if type(c) == "function" then return c(line) end
  return line:match(c)
end

---
-- datafiles.get_array(lines, v_pattern): the values v_pattern captures,
-- one per line that it matches.
function datafiles.get_array(lines, v_pattern)
  local out = {}
  for _, line in ipairs(lines) do
    local v = capture(v_pattern, line)
    if v ~= nil then out[#out + 1] = v end
  end
  return out
end

---
-- datafiles.get_assoc_array(lines, i_pattern, v_pattern): key-value pairs
-- from the lines both patterns match; the first line wins for a key.
function datafiles.get_assoc_array(lines, i_pattern, v_pattern)
  local out = {}
  for _, line in ipairs(lines) do
    local k = capture(i_pattern, line)
    if k ~= nil and out[k] == nil then
      local v = capture(v_pattern, line)
      if v ~= nil then out[k] = v end
    end
  end
  return out
end

---
-- datafiles.parse_lines(lines, data_struct): a table shaped like
-- data_struct: an array entry (pattern or function) gives an array of its
-- captures, a key and value given as patterns or functions give a table
-- of captured keys to captured values, a table value is filled the same
-- way under its key. An empty data_struct gives the lines themselves.
function datafiles.parse_lines(lines, data_struct)
  if type(data_struct) ~= "table" then
    error("datafiles.parse_lines: the capture patterns must be a table", 2)
  end
  if next(data_struct) == nil then
    local out = {}
    for _, line in ipairs(lines) do out[#out + 1] = line end
    return out
  end
  local out = {}
  for k, v in pairs(data_struct) do
    if math.type(k) == "integer" then
      if type(v) == "table" then
        out[k] = datafiles.parse_lines(lines, v)
      else
        out[k] = datafiles.get_array(lines, v)
      end
    elseif type(v) == "table" then
      out[k] = datafiles.parse_lines(lines, v)
    else
      -- Several key patterns may fill the same table.
      for key, value in pairs(datafiles.get_assoc_array(lines, k, v)) do
        if out[key] == nil then out[key] = value end
      end
    end
  end
  -- A struct of only key patterns fills one table, not one per pattern.
  return out
end

---
-- datafiles.read_from_file(file): true and the file's lines (empty lines
-- and lines starting with "#" left out), or false and an error.
function datafiles.read_from_file(file)
  if type(file) ~= "string" or file == "" then return false, "no file name" end
  local path = nmap.fetchfile(file) or file
  local ok, f, err = pcall(io.open, path, "r")
  if not ok or not f then
    return false, string.format("Error opening %s: %s", file, tostring(ok and err or f))
  end
  local lines = {}
  for line in f:lines() do
    line = line:gsub("\r$", "")
    if line:match("%S") and not line:match("^%s*#") then lines[#lines + 1] = line end
  end
  f:close()
  return true, lines
end

---
-- datafiles.parse_file(filename, data_struct): true and the file parsed
-- with data_struct (or its own patterns when it is one of the common
-- files), or false and an error.
function datafiles.parse_file(filename, ...)
  local data_struct = ...
  local base = type(filename) == "string" and filename:match("([^/\\]+)$")
  if data_struct == nil and base and common_files[base] then
    data_struct = common_files[base]
  end
  if type(data_struct) ~= "table" then
    return false, "datafiles.parse_file: " .. tostring(filename) .. " needs a table of capture patterns"
  end
  local ok, lines = datafiles.read_from_file(filename)
  if not ok then return false, lines end
  return true, datafiles.parse_lines(lines, data_struct)
end

---
-- datafiles.parse_rpc(): true and RPC program numbers to names, from
-- nmap-rpc.
function datafiles.parse_rpc()
  return datafiles.parse_file("nmap-rpc")
end

---
-- datafiles.parse_protocols(): true and IP protocol numbers to names,
-- from nmap-protocols, else FeroProbe's own names.
function datafiles.parse_protocols()
  local ok, t = datafiles.parse_file("nmap-protocols")
  if ok then return true, t end
  return true, fero.__service_names("ip")
end

---
-- datafiles.parse_services(protocol): true and the tables "tcp", "udp"
-- and "sctp" of port numbers to service names, or with protocol, only
-- that table; from nmap-services, else FeroProbe's own names.
function datafiles.parse_services(protocol)
  if protocol ~= nil and protocol ~= "tcp" and protocol ~= "udp" and protocol ~= "sctp" then
    return false, "Bad protocol for nmap-services: use tcp, udp or sctp"
  end
  local ok, t = datafiles.parse_file("nmap-services")
  if not ok then
    t = {}
    for _, p in ipairs({ "tcp", "udp", "sctp" }) do t[p] = fero.__service_names(p) end
  end
  if protocol then return true, t[protocol] end
  return true, t
end

-- "00:0C:29:01:02:03", "000c29010203" or "000C29" as the 6-hex-digit
-- prefix nmap-mac-prefixes keys on, upper case.
local function prefix_of(key)
  if type(key) ~= "string" then return nil end
  local hex = key:gsub("[:%-%.]", ""):upper()
  if not hex:match("^%x+$") or #hex < 6 then return nil end
  return hex
end

---
-- datafiles.parse_mac_prefixes(): true and a table of MAC prefixes (six
-- hex digits, upper case) to vendor names; a whole MAC works as a key
-- too. From nmap-mac-prefixes, else the OUI list FeroProbe uses.
function datafiles.parse_mac_prefixes()
  local ok, t = datafiles.parse_file("nmap-mac-prefixes")
  if not ok then t = {} end
  local upper = {}
  for k, v in pairs(t) do upper[k:upper()] = v end
  return true, setmetatable(upper, {
    __index = function(self, key)
      local hex = prefix_of(key)
      if not hex then return nil end
      -- Longer prefixes (the file's MA-M and MA-S blocks) first.
      for n = math.min(#hex, 9), 6, -1 do
        local v = rawget(self, hex:sub(1, n))
        if v then return v end
      end
      local full = (hex .. "000000000000"):sub(1, 12)
      return fero.mac_vendor(full:gsub("(%x%x)", "%1:"):sub(1, 17))
    end,
  })
end

return datafiles
