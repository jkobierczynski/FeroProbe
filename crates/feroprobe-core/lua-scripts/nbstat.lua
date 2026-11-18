-- FeroProbe script: nbstat
-- Written for FeroProbe from scratch, from RFC 1001 14.1 (name encoding)
-- and RFC 1002 4.2.1, 4.2.17 and 4.2.18 (NODE STATUS request and
-- response); GPL-3.0-or-later.

description = [[
Asks a host's NetBIOS name service (UDP 137) for its name table with one
NODE STATUS request, the question `nbtstat -A` asks, and shows the
host's NetBIOS name, the logged-in user when the table names one, and
the MAC address the host reports, with its vendor from the OUI list.
With -v the whole name table is listed.

Runs only when UDP 137 was part of the scan (-sU -p U:137), since
FeroProbe sends nothing to ports outside the scan. The request's
transaction ID is 0x4650 ("FP").

Script arguments:
  nbstat.port     The UDP port of the name service (default 137); it must
                  be one the scan probed.
  nbstat.timeout  How long to wait for the answer, in milliseconds
                  (default 5000); the request is sent twice at most.
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "default", "discovery", "safe" }

-- FeroProbe's mark: the transaction ID of every request, "FP".
local TRN_ID = 0x4650

local function target(host)
  local n = math.tointeger(tonumber(fero.args.get(SCRIPT_NAME .. ".port")) or 137)
  if not n then return nil end
  return fero.get_port_state(host, { number = n, protocol = "udp" })
end

hostrule = function(host)
  return target(host) ~= nil
end

-- The NODE STATUS request for the name "*": one question, type NBSTAT
-- (0x21), class IN. The name is "*" padded with NULs, first-level
-- encoded: each half-byte as a letter from "A".
local function request()
  local name = "*" .. string.rep("\0", 15)
  local enc = {}
  for i = 1, 16 do
    local b = name:byte(i)
    enc[i] = string.char(0x41 + (b >> 4), 0x41 + (b & 0xf))
  end
  return string.pack(">I2I2I2I2I2I2", TRN_ID, 0, 1, 0, 0, 0)
    .. "\32" .. table.concat(enc) .. "\0"
    .. string.pack(">I2I2", 0x21, 1)
end

-- Printable name text: trailing spaces dropped, other bytes escaped.
local function text(s)
  s = s:gsub(" +$", "")
  return (s:gsub("[^\32-\126]", function(c)
    return string.format("\\x%02x", c:byte())
  end))
end

-- The name table and MAC of a NODE STATUS response, or nil.
local function parse(r)
  if #r < 12 then return nil end
  local id, flags, _, ancount = string.unpack(">I2I2I2I2", r)
  if id ~= TRN_ID or flags & 0x8000 == 0 or ancount < 1 then return nil end
  -- The answer's name: the encoded name in full, or a pointer to it.
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
  pos = pos + 11
  if rtype ~= 0x21 or rdlen < 1 + count * 18 or #r < pos - 1 + count * 18 then
    return nil
  end
  local names = {}
  for i = 1, count do
    local raw, suffix, nflags = string.unpack(">c15BI2", r, pos)
    pos = pos + 18
    names[i] = { name = text(raw), suffix = suffix, flags = nflags }
  end
  local mac
  if #r >= pos + 5 then
    local b = { r:byte(pos, pos + 5) }
    mac = string.format("%02x:%02x:%02x:%02x:%02x:%02x", table.unpack(b))
  end
  return names, mac
end

-- The first unique name with `suffix`, other than `except`.
local function unique(names, suffix, except)
  for _, n in ipairs(names) do
    if n.suffix == suffix and n.flags & 0x8000 == 0 and n.name ~= except then
      return n.name
    end
  end
end

-- A name's flags as nmap writes them: "<unique><active>".
local function flag_text(f)
  local out = (f & 0x8000 ~= 0) and "<group>" or "<unique>"
  if f & 0x0400 ~= 0 then out = out .. "<active>" end
  if f & 0x0200 ~= 0 then out = out .. "<permanent>" end
  if f & 0x0800 ~= 0 then out = out .. "<conflict>" end
  if f & 0x1000 ~= 0 then out = out .. "<deregister>" end
  return out
end

action = function(host)
  local port = target(host)
  local timeout = tonumber(fero.args.get(SCRIPT_NAME .. ".timeout")) or 5000
  local sock = fero.socket.new()
  sock:set_timeout(timeout)
  if not sock:connect(host, port, "udp") then return nil end
  local names, mac
  for _ = 1, 2 do
    if not sock:send(request()) then break end
    local ok, reply = sock:receive()
    if ok then
      names, mac = parse(reply)
      if names then break end
    end
  end
  sock:close()
  if not names then return nil end

  local server = unique(names, 0x20) or unique(names, 0x00)
  local user = unique(names, 0x03, server)
  local mac_text = "<unknown>"
  if mac and mac ~= "00:00:00:00:00:00" then
    mac_text = string.format("%s (%s)", mac, fero.mac_vendor(mac) or "unknown")
  end
  local line = string.format("NetBIOS name: %s, NetBIOS user: %s, NetBIOS MAC: %s",
    server or "<unknown>", user or "<unknown>", mac_text)

  local data = {
    server_name = server,
    user = user,
    mac = mac,
    names = {},
  }
  local lines = { line }
  if fero.verbosity() >= 1 and #names > 0 then
    lines[#lines + 1] = "Names:"
  end
  for i, n in ipairs(names) do
    data.names[i] = { name = n.name, suffix = string.format("0x%02x", n.suffix),
      flags = flag_text(n.flags) }
    if fero.verbosity() >= 1 then
      local label = string.format("%s<%02x>", n.name, n.suffix)
      lines[#lines + 1] = string.format("  %-20s Flags: %s", label, flag_text(n.flags))
    end
  end
  return data, table.concat(lines, "\n")
end
