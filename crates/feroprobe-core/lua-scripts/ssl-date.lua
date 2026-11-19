-- FeroProbe script: ssl-date
-- Written for FeroProbe from scratch, from RFC 5246 7.4.1.2 and 7.4.1.3
-- (ClientHello, ServerHello: gmt_unix_time) and RFC 6066 3 (server
-- name); GPL-3.0-or-later.

description = [[
Shows a TLS server's clock, from the time many TLS 1.2 and older servers
put in the first four bytes of their ServerHello random, and how far it
is from the scanner's clock (also noted for clock-skew). Sends a TLS 1.2
ClientHello and reads the ServerHello; no handshake is finished. Two hellos are sent, and when
both answers came within one second a third one two seconds later: when
the server's values do not move with the scanner's clock, the server
fills the field with random bytes (as most current servers do) or never
changes it, and the script says so.

The ClientHello random carries "FeroProbeSSLDate" after its time field,
so the target's logs and IDS can tell the hello apart.

Script arguments:
  ssl-date.timeout  How long to wait for each answer, in milliseconds
                    (default 8000).
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "default", "discovery", "safe" }

portrule = fero.portrule.ssl

local MARK = "FeroProbeSSLDate"

local CIPHERS = {
  0xc02f, 0xc030, 0xc02b, 0xc02c, 0xcca8, 0xcca9, 0xc013, 0xc014,
  0x009c, 0x009d, 0x002f, 0x0035, 0x000a,
}
local GROUPS = { 0x001d, 0x0017, 0x0018 }
local SIGNATURES = {
  0x0401, 0x0501, 0x0601, 0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806,
  0x0201, 0x0203,
}

local function u16_list(list)
  local t = {}
  for i, v in ipairs(list) do t[i] = string.pack(">I2", v) end
  return table.concat(t)
end

local function ext(kind, data)
  return string.pack(">I2s2", kind, data)
end

-- A TLS 1.2 ClientHello in one record. The server name is sent when the
-- target was given by name.
local function client_hello(name)
  local random = string.pack(">I4", os.time()) .. MARK .. fero.crypto.random_bytes(12)
  local exts = ext(0x000a, string.pack(">s2", u16_list(GROUPS)))
    .. ext(0x000b, "\1\0")
    .. ext(0x000d, string.pack(">s2", u16_list(SIGNATURES)))
    .. ext(0xff01, "\0")
  if name and name ~= "" and not name:match("^[%d.]+$") and not name:find(":", 1, true) then
    exts = ext(0x0000, string.pack(">s2", "\0" .. string.pack(">s2", name))) .. exts
  end
  local body = string.pack(">I2", 0x0303) .. random .. "\0"
    .. string.pack(">s2", u16_list(CIPHERS)) .. "\1\0"
    .. string.pack(">s2", exts)
  local hs = "\1" .. string.pack(">I3", #body) .. body
  return "\22\3\1" .. string.pack(">s2", hs)
end

-- The gmt_unix_time of the server's ServerHello and the scanner's clock
-- when it came, or nil.
local function server_time(host, port, timeout)
  local sock = fero.socket.new()
  sock:set_timeout(timeout)
  if not sock:connect(host, port) then return nil end
  local function done(t, now)
    sock:close()
    return t, now
  end
  if not sock:send(client_hello(host.targetname)) then return done(nil) end
  local r = fero.reader(sock)
  -- The ServerHello opens the server's handshake records; it may be split
  -- across several. Only its first 10 bytes are read (handshake type and
  -- length, version, gmt_unix_time), from at most 10 records (each
  -- non-empty), 60 bytes with their headers. They are read one at a time, each receive waiting only for
  -- what is left of one `timeout` (counted in whole seconds, as os.time
  -- is), so a server that trickles bytes cannot stretch the wait.
  local deadline = os.time() + math.max(1, timeout // 1000)
  local function take(n)
    local out = {}
    for i = 1, n do
      local left = deadline - os.time()
      if left <= 0 then return nil end
      sock:set_timeout(math.min(left * 1000, timeout))
      out[i] = r:bytes(1)
      if not out[i] then return nil end
    end
    return table.concat(out)
  end
  local hs = ""
  for _ = 1, 10 do
    local head = take(5)
    if not head then return done(nil) end
    local kind, major, len = string.unpack(">BBxI2", head)
    if kind ~= 22 or major ~= 3 or len == 0 or len > 18432 then return done(nil) end
    local chunk = take(math.min(len, 10 - #hs))
    if not chunk then return done(nil) end
    hs = hs .. chunk
    if #hs >= 10 then
      local now = os.time()
      local typ, hlen = string.unpack(">BI3", hs)
      if typ ~= 2 or hlen < 38 then return done(nil) end
      return done(string.unpack(">I4", hs, 7), now)
    end
  end
  return done(nil)
end

action = function(host, port)
  local timeout = tonumber(fero.args.get(SCRIPT_NAME .. ".timeout")) or 8000
  local t1, n1 = server_time(host, port, timeout)
  if not t1 then return nil end
  local t2, n2 = server_time(host, port, timeout)
  if not t2 then return nil end
  if t2 == t1 then
    -- Both hellos may have come within one second, or the field never
    -- changes: ask again once our clock has moved two seconds, so that a
    -- real clock must have moved too.
    fero.sleep(2)
    t2, n2 = server_time(host, port, timeout)
    if not t2 then return nil end
    if t2 == t1 then return "TLS randomness does not represent time" end
  end
  -- A real clock moves with ours between the hellos (allowing a second
  -- either way for rounding and the trip).
  if math.abs((t2 - t1) - (n2 - n1)) > 2 then
    return "TLS randomness does not represent time"
  end
  local d = t2 - n2
  fero.record_skew(t2, n2)
  local date = os.date("!%Y-%m-%dT%H:%M:%S+00:00", t2)
  return { date = date, delta = tostring(d) },
    date .. "; " .. (d > 0 and "+" or "") .. fero.format_time(d) .. " from scanner time."
end
