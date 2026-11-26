-- NSE compatibility layer: the `netbios` module (name encoding and the
-- NODE STATUS query). Written for FeroProbe from nmap's public API
-- documentation and RFC 1001/1002 (not from nselib); GPL-3.0-or-later,
-- like FeroProbe.
--
-- The NODE STATUS request is FeroProbe's own, as its nbstat sends it:
-- transaction ID "FP" (0x4650, IDS rule 9100013) where nmap uses 0x1337.
-- It goes to UDP 137 of the scanned host, so only when that port was
-- scanned, as every script socket.
local fero = ...
local nmap = require "nmap"
local netbios = {}

local TRN_ID = 0x4650

---
-- netbios.name_encode(name, scope): name upper-cased, padded to 16 bytes
-- (spaces, or NULs for "*"), first-level encoded (each half-byte plus
-- "A") and length-prefixed, followed by the scope's labels.
function netbios.name_encode(name, scope)
  name = tostring(name):upper()
  local pad = name == "*" and "\0" or " "
  name = (name .. string.rep(pad, 16)):sub(1, 16)
  local enc = {}
  for i = 1, 16 do
    local b = name:byte(i)
    enc[i] = string.char(0x41 + (b >> 4), 0x41 + (b & 0xf))
  end
  local out = { string.char(32) .. table.concat(enc) }
  if scope and scope ~= "" then
    for label in tostring(scope):gmatch("[^%.]+") do
      out[#out + 1] = string.char(#label) .. label
    end
  end
  return table.concat(out)
end

---
-- netbios.name_decode(encoded_name): the decoded name (still padded) and
-- the scope ("" when none); bad encodings are decoded as far as possible.
function netbios.name_decode(encoded_name)
  local s = tostring(encoded_name)
  local len = s:byte(1) or 0
  local half = s:sub(2, 1 + len)
  local name = {}
  for i = 1, #half - 1, 2 do
    local hi, lo = half:byte(i) - 0x41, half:byte(i + 1) - 0x41
    name[#name + 1] = string.char(((hi & 0xf) << 4) | (lo & 0xf))
  end
  local labels, pos = {}, 2 + len
  while pos <= #s do
    local n = s:byte(pos)
    if not n or n == 0 then break end
    labels[#labels + 1] = s:sub(pos + 1, pos + n)
    pos = pos + 1 + n
  end
  return table.concat(name), table.concat(labels, ".")
end

---
-- netbios.flags_to_string(flags): a name's flags as "<unique><active>".
function netbios.flags_to_string(flags)
  flags = tonumber(flags) or 0
  local out = (flags & 0x8000 ~= 0) and "<group>" or "<unique>"
  if flags & 0x0400 ~= 0 then out = out .. "<active>" end
  if flags & 0x0200 ~= 0 then out = out .. "<permanent>" end
  if flags & 0x0800 ~= 0 then out = out .. "<conflict>" end
  if flags & 0x1000 ~= 0 then out = out .. "<deregister>" end
  return out
end

local function request()
  return string.pack(">I2I2I2I2I2I2", TRN_ID, 0, 1, 0, 0, 0)
    .. netbios.name_encode("*") .. "\0"
    .. string.pack(">I2I2", 0x21, 1)
end

-- The names and statistics of a NODE STATUS response, or nil.
local function parse(r)
  if #r < 12 then return nil end
  local id, flags, _, ancount = string.unpack(">I2I2I2I2", r)
  if id ~= TRN_ID or flags & 0x8000 == 0 or flags & 0xf ~= 0 or ancount < 1 then
    return nil
  end
  local pos = 13
  local first = r:byte(pos)
  if not first then return nil end
  if first >= 0xc0 then
    pos = pos + 2
  else
    while true do
      local len = r:byte(pos)
      if not len or len >= 0xc0 then return nil end
      pos = pos + 1 + len
      if len == 0 then break end
    end
  end
  if #r < pos + 10 then return nil end
  local rtype, _, _, rdlen, count = string.unpack(">I2I2I4I2B", r, pos)
  local rdata_end = pos + 10 + rdlen - 1
  pos = pos + 11
  if rtype ~= 0x21 or rdlen < 1 + count * 18 or rdata_end > #r then return nil end
  local names = {}
  for i = 1, count do
    local raw, suffix, nflags = string.unpack(">c15BI2", r, pos)
    pos = pos + 18
    names[i] = { name = (raw:gsub("[ %z]+$", "")), suffix = suffix, flags = nflags }
  end
  return names, r:sub(pos, rdata_end)
end

local function host_key(host)
  return type(host) == "table" and (host.ip or host.targetname) or tostring(host)
end

---
-- netbios.do_nbstat(host): true, the names ({ name, suffix, flags }) and
-- the statistics (the MAC first) the host's NODE STATUS answer holds, or
-- false and a message. One answer per host is kept for the run.
function netbios.do_nbstat(host)
  local key = "nbstat_" .. host_key(host)
  local cached = nmap.registry[key]
  if type(cached) == "table" and cached.names then
    return true, cached.names, cached.statistics
  end
  local sock = nmap.new_socket("udp")
  sock:set_timeout(tonumber(fero.args.get("nbstat.timeout")) or 5000)
  local ok, err = sock:connect(host, { number = 137, protocol = "udp" }, "udp")
  if not ok then return false, "Couldn't connect to UDP 137: " .. tostring(err) end
  local names, stats
  for _ = 1, 2 do
    if not sock:send(request()) then break end
    local rok, reply = sock:receive()
    if rok then
      names, stats = parse(reply)
      if names then break end
    end
  end
  sock:close()
  if not names then return false, "No NBSTAT response" end
  nmap.registry[key] = { names = names, statistics = stats }
  return true, names, stats
end

local function names_of(host, names)
  if names then return true, names end
  local ok, n = netbios.do_nbstat(host)
  return ok, n
end

---
-- netbios.get_server_name(host, names): true and the unique name with
-- suffix 0x20, or false and a message.
function netbios.get_server_name(host, names)
  local ok, n = names_of(host, names)
  if not ok then return false, n end
  for _, e in ipairs(n) do
    if e.suffix == 0x20 and e.flags & 0x8000 == 0 then return true, e.name end
  end
  return false, "Couldn't find NetBIOS server name"
end

---
-- netbios.get_workstation_name(host, names): true and the unique name with
-- suffix 0x00, or false and a message.
function netbios.get_workstation_name(host, names)
  local ok, n = names_of(host, names)
  if not ok then return false, n end
  for _, e in ipairs(n) do
    if e.suffix == 0x00 and e.flags & 0x8000 == 0 then return true, e.name end
  end
  return false, "Couldn't find NetBIOS workstation name"
end

---
-- netbios.get_user_name(host, names): true and a 0x03 name that is not
-- the server's, or true and nil when there is none; false and a message
-- when the query fails.
function netbios.get_user_name(host, names)
  local ok, n = names_of(host, names)
  if not ok then return false, n end
  local _, server = netbios.get_server_name(host, n)
  local _, ws = netbios.get_workstation_name(host, n)
  for _, e in ipairs(n) do
    if e.suffix == 0x03 and e.name ~= server and e.name ~= ws then return true, e.name end
  end
  return true, nil
end

---
-- netbios.get_names(host, prefix): true and the names as text, one per
-- line ("NAME<20> Flags: <unique><active>"), or false and a message.
function netbios.get_names(host, prefix)
  local ok, n = netbios.do_nbstat(host)
  if not ok then return false, n end
  local lines = {}
  for _, e in ipairs(n) do
    lines[#lines + 1] = string.format("%s%s<%02x>%s Flags: %s", prefix or "", e.name, e.suffix,
      string.rep(" ", math.max(0, 17 - #e.name)), netbios.flags_to_string(e.flags))
  end
  return true, table.concat(lines, "\n")
end

---
-- netbios.nbquery(host, name): a NAME QUERY for name (as name_encode
-- pads it: the <20> server name) sent to the host's UDP 137; true and its
-- answers ({ name, type, class, ttl, data }; an NB answer's data is
-- 6 bytes per address: flags, then the IPv4 address), or false and a
-- message. Not on nmap's NSEDoc page; its shape is what nbns-interfaces
-- reads.
function netbios.nbquery(host, name)
  local sock = nmap.new_socket("udp")
  sock:set_timeout(tonumber(fero.args.get("nbstat.timeout")) or 5000)
  local ok, err = sock:connect(host, { number = 137, protocol = "udp" }, "udp")
  if not ok then return false, "Couldn't connect to UDP 137: " .. tostring(err) end
  local query = string.pack(">I2I2I2I2I2I2", TRN_ID, 0, 1, 0, 0, 0)
    .. netbios.name_encode(name) .. "\0" .. string.pack(">I2I2", 0x20, 1)
  local reply
  for _ = 1, 2 do
    if not sock:send(query) then break end
    local rok, r = sock:receive()
    if rok and #r >= 12 and string.unpack(">I2", r) == TRN_ID then reply = r break end
  end
  sock:close()
  if not reply then return false, "No NAME QUERY response" end
  local flags, _, ancount = string.unpack(">I2I2I2", reply, 3)
  if flags & 0x8000 == 0 or flags & 0xf ~= 0 or ancount < 1 then
    return false, "Name not found"
  end
  local answers, pos = {}, 13
  for _ = 1, ancount do
    local first = reply:byte(pos)
    if not first then break end
    local rname
    if first >= 0xc0 then
      pos = pos + 2
    else
      local start = pos
      while true do
        local len = reply:byte(pos)
        if not len or len >= 0xc0 then return false, "Bad answer" end
        pos = pos + 1 + len
        if len == 0 then break end
      end
      rname = netbios.name_decode(reply:sub(start, pos - 1))
    end
    if #reply < pos + 9 then break end
    local rtype, class, ttl, rdlen = string.unpack(">I2I2I4I2", reply, pos)
    pos = pos + 10
    if pos + rdlen - 1 > #reply then break end
    answers[#answers + 1] = { name = rname, type = rtype, class = class, ttl = ttl,
      data = reply:sub(pos, pos + rdlen - 1) }
    pos = pos + rdlen
  end
  return true, answers
end

return netbios
