-- FeroProbe script: dns-nsid
-- Written for FeroProbe from scratch, from RFC 1035 (DNS messages),
-- RFC 6891 (EDNS(0)), RFC 5001 (the NSID option) and RFC 4892 (the
-- id.server and version.bind CHAOS names); GPL-3.0-or-later.

description = [[
Asks a DNS server who it is: the name server identifier (NSID, RFC 5001)
it puts in an EDNS(0) reply, and the CHAOS-class TXT records "id.server"
and "version.bind", which many servers answer with their host name and
software version. Useful to tell apart the servers behind one anycast or
load-balanced address.

Sends at most three small queries to the scanned DNS port (UDP, or TCP
when that is the port that was scanned): "id.server" with an NSID
request, again without EDNS if the server rejects EDNS, and
"version.bind". Every query has transaction ID 0x4650 ("FP").

Script arguments:
  dns-nsid.timeout  How long to wait for each answer, in milliseconds
                    (default 5000).
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "default", "discovery", "safe" }

portrule = fero.portrule.match({ 53 }, { "domain" }, { "tcp", "udp" })

-- FeroProbe's mark: the transaction ID of every query, "FP".
local TRN_ID = 0x4650

local TXT, OPT, CH = 16, 41, 3
local NSID = 3

-- A domain name in wire format.
local function wire_name(name)
  local out = {}
  for label in name:gmatch("[^.]+") do
    out[#out + 1] = string.char(#label) .. label
  end
  return table.concat(out) .. "\0"
end

-- A query for `name` CHAOS TXT, with no recursion wanted; with `nsid`,
-- an EDNS(0) OPT record asking for the NSID (an empty option 3).
local function query(name, nsid)
  local q = string.pack(">I2I2I2I2I2I2", TRN_ID, 0, 1, 0, 0, nsid and 1 or 0)
    .. wire_name(name) .. string.pack(">I2I2", TXT, CH)
  if nsid then
    -- Root name, type OPT, UDP payload size 1232, no extended RCODE,
    -- version 0, no flags, then the option.
    q = q .. "\0" .. string.pack(">I2I2I4I2", OPT, 1232, 0, 4)
      .. string.pack(">I2I2", NSID, 0)
  end
  return q
end

-- The position after the name at `pos`, or nil when it runs out.
local function skip_name(m, pos)
  for _ = 1, 128 do
    local len = m:byte(pos)
    if not len then return nil end
    if len >= 0xc0 then return pos + 2 end
    if len > 63 then return nil end
    pos = pos + 1 + len
    if len == 0 then return pos end
  end
  return nil
end

-- Printable text: control and other non-ASCII bytes escaped.
local function text(s)
  return (s:gsub("[^\32-\126]", function(c)
    return string.format("\\x%02x", c:byte())
  end))
end

-- A reply to our query: its RCODE, the TXT strings of its CHAOS TXT
-- answer (joined), and the NSID value of its OPT record. Nil if the
-- message is not a well-formed answer to our query.
local function parse(m)
  if #m < 12 then return nil end
  local id, flags, qd, an, ns, ar = string.unpack(">I2I2I2I2I2I2", m)
  -- A response (QR bit) to a standard query (OPCODE 0).
  if id ~= TRN_ID or flags & 0x8000 == 0 or flags & 0x7800 ~= 0 then
    return nil
  end
  local pos = 13
  for _ = 1, qd do
    pos = skip_name(m, pos)
    if not pos or pos + 4 > #m + 1 then return nil end
    pos = pos + 4
  end
  local txt, nsid
  for i = 1, an + ns + ar do
    pos = skip_name(m, pos)
    if not pos or pos + 10 > #m + 1 then return nil end
    local rtype, rclass, _, rdlen = string.unpack(">I2I2I4I2", m, pos)
    pos = pos + 10
    local rd_end = pos + rdlen
    if rd_end > #m + 1 then return nil end
    if i <= an and rtype == TXT and rclass == CH and not txt then
      local parts, p = {}, pos
      while p < rd_end do
        local n = m:byte(p)
        if p + 1 + n > rd_end then return nil end
        parts[#parts + 1] = m:sub(p + 1, p + n)
        p = p + 1 + n
      end
      txt = table.concat(parts)
    elseif i > an + ns and rtype == OPT then
      local p = pos
      while p + 4 <= rd_end do
        local code, len = string.unpack(">I2I2", m, p)
        if p + 4 + len > rd_end then return nil end
        if code == NSID and len > 0 then nsid = m:sub(p + 4, p + 3 + len) end
        p = p + 4 + len
      end
    end
    pos = rd_end
  end
  -- RCODE: the low four bits of the header.
  return flags & 0xf, txt, nsid
end

-- Send one query and return the parsed reply, or nil.
local function ask(host, port, timeout, msg)
  local sock = fero.socket.new()
  sock:set_timeout(timeout)
  if not sock:connect(host, port, port.protocol) then return nil end
  local reply
  if port.protocol == "tcp" then
    -- Over TCP each message has a two-byte length in front (RFC 1035
    -- 4.2.2).
    if sock:send(string.pack(">s2", msg)) then
      local buf = ""
      local function fill(n)
        while #buf < n do
          local ok, more = sock:receive_bytes(n - #buf)
          if not ok then return false end
          buf = buf .. more
        end
        return true
      end
      if fill(2) then
        local want = 2 + string.unpack(">I2", buf)
        if fill(want) then reply = buf:sub(3, want) end
      end
    end
  else
    -- Over UDP a query is sent twice at most.
    for _ = 1, 2 do
      if not sock:send(msg) then break end
      local ok, r = sock:receive()
      if ok and parse(r) then
        reply = r
        break
      end
    end
  end
  sock:close()
  if not reply then return nil end
  return parse(reply)
end

action = function(host, port)
  local timeout = tonumber(fero.args.get(SCRIPT_NAME .. ".timeout")) or 5000
  local data, lines = {}, {}

  local rcode, id_server, nsid = ask(host, port, timeout, query("id.server", true))
  -- FORMERR (1) or NOTIMP (4): a server without EDNS; ask again plainly.
  if rcode == 1 or rcode == 4 then
    rcode, id_server = ask(host, port, timeout, query("id.server", false))
  end
  local _, version = ask(host, port, timeout, query("version.bind", false))

  if nsid then
    local hex = nsid:gsub(".", function(c) return string.format("%02x", c:byte()) end)
    data.NSID = string.format("%s (%s)", text(nsid), hex)
    lines[#lines + 1] = "NSID: " .. data.NSID
  end
  if id_server then
    data["id.server"] = text(id_server)
    lines[#lines + 1] = "id.server: " .. data["id.server"]
  end
  if version then
    data["bind.version"] = text(version)
    lines[#lines + 1] = "bind.version: " .. data["bind.version"]
  end
  if #lines == 0 then return nil end
  return data, "\n  " .. table.concat(lines, "\n  ")
end
