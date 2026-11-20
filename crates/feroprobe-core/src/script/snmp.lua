-- fero.snmp: SNMP requests over UDP, for scripts that read a device's
-- system and interface tables: SNMPv1 and v2c GetRequest and
-- GetNextRequest with a community string, table walks, and the SNMPv3
-- engine discovery request.
-- Written for FeroProbe from scratch, from RFC 1157 (SNMPv1), RFC 3416
-- (the v2 PDUs), RFC 3412 section 6 and RFC 3414 section 2.4 (the v3
-- message and USM engine discovery), RFC 3411 section 5 (SnmpEngineID)
-- and X.690 (BER); GPL-3.0-or-later.
local fero = ...
local snmp = {}

-- FeroProbe's mark: the request-id of every PDU and the msgID of every
-- SNMPv3 message, 0x4650 ("FP") (IDS rule 9100021).
snmp.REQUEST_ID = 0x4650

-- Most variables one walk reads.
snmp.MAX_WALK = 65536

-- ASN.1 / SNMP tags.
local INTEGER, OCTETS, NULL, OID, SEQUENCE = 0x02, 0x04, 0x05, 0x06, 0x30
local GET, GETNEXT, RESPONSE, REPORT = 0xa0, 0xa1, 0xa2, 0xa8
snmp.TAG = {
  integer = INTEGER, octets = OCTETS, null = NULL, oid = OID,
  ipaddress = 0x40, counter32 = 0x41, gauge32 = 0x42, timeticks = 0x43,
  opaque = 0x44, counter64 = 0x46,
}
-- The v2 exceptions a variable can carry instead of a value.
local EXCEPTION = { [0x80] = "noSuchObject", [0x81] = "noSuchInstance", [0x82] = "endOfMibView" }

-- ---------------------------------------------------------------- BER out

local function length(n)
  if n < 0x80 then return string.char(n) end
  local s = ""
  while n > 0 do
    s = string.char(n & 0xff) .. s
    n = n >> 8
  end
  return string.char(0x80 | #s) .. s
end

local function tlv(tag, value) return string.char(tag) .. length(#value) .. value end

-- An INTEGER: the shortest two's complement form.
local function integer(n)
  local out = {}
  while true do
    local b = n & 0xff
    table.insert(out, 1, string.char(b))
    n = n // 256
    if (n == 0 and b < 0x80) or (n == -1 and b >= 0x80) then break end
  end
  return tlv(INTEGER, table.concat(out))
end

local function octets(s) return tlv(OCTETS, s) end
local function sequence(s) return tlv(SEQUENCE, s) end

-- The arcs of a dotted OID ("1.3.6.1.2.1.1.1.0"), or nil when it is not one.
local function arcs(s)
  if type(s) ~= "string" or not s:match("^%d+%.%d+[%d.]*$") or s:find("..", 1, true)
    or s:sub(-1) == "." then
    return nil
  end
  local t = {}
  for a in s:gmatch("%d+") do
    local n = math.tointeger(tonumber(a))
    if not n or n < 0 or n > 0xffffffff then return nil end
    t[#t + 1] = n
  end
  if t[1] > 2 or (t[1] < 2 and t[2] > 39) then return nil end
  return t
end

local function oid(s)
  local t = arcs(s)
  if not t then error("fero.snmp: not an OID: " .. tostring(s), 3) end
  -- Each subidentifier in base 128, the first two arcs combined into
  -- one (X.690 8.19): "2.100" is 180, 81 34.
  local function base128(n)
    local b = { string.char(n & 0x7f) }
    n = n >> 7
    while n > 0 do
      table.insert(b, 1, string.char(0x80 | (n & 0x7f)))
      n = n >> 7
    end
    return table.concat(b)
  end
  local out = { base128(t[1] * 40 + t[2]) }
  for i = 3, #t do out[#out + 1] = base128(t[i]) end
  return tlv(OID, table.concat(out))
end

-- A PDU asking for `oids`, each with a NULL value.
local function pdu(tag, oids)
  local binds = {}
  for i, o in ipairs(oids) do binds[i] = sequence(oid(o) .. tlv(NULL, "")) end
  return tlv(tag, integer(snmp.REQUEST_ID) .. integer(0) .. integer(0)
    .. sequence(table.concat(binds)))
end

-- A v1 (0) or v2c (1) message carrying a PDU with `tag` for `oids`.
function snmp.message(version, community, tag, oids)
  return sequence(integer(version) .. octets(community) .. pdu(tag, oids))
end

-- The SNMPv3 engine discovery request (RFC 3414 section 4): no user, no
-- engine ID, reportable, User-based Security Model, an empty GetRequest.
-- A v3 agent answers with a Report carrying its engine ID, boots and time.
function snmp.discovery_request()
  local global = sequence(integer(snmp.REQUEST_ID) .. integer(65507) .. octets("\4")
    .. integer(3))
  local usm = sequence(octets("") .. integer(0) .. integer(0) .. octets("")
    .. octets("") .. octets(""))
  local scoped = sequence(octets("") .. octets("") .. pdu(GET, {}))
  return sequence(integer(3) .. global .. octets(usm) .. scoped)
end

-- ----------------------------------------------------------------- BER in

-- The tag, contents and next position of the element at `pos` in `s`,
-- or nil when it is malformed or runs past `limit` (default: the end).
local function read(s, pos, limit)
  limit = limit or #s
  if pos + 1 > limit then return nil end
  local tag, len = s:byte(pos, pos + 1)
  pos = pos + 2
  if tag & 0x1f == 0x1f then return nil end
  if len >= 0x80 then
    local n = len & 0x7f
    if n == 0 or n > 4 or pos + n - 1 > limit then return nil end
    len = 0
    for i = 0, n - 1 do len = (len << 8) | s:byte(pos + i) end
    pos = pos + n
  end
  if pos + len - 1 > limit then return nil end
  return tag, s:sub(pos, pos + len - 1), pos + len
end

-- The elements of a constructed value, as { tag, contents } pairs, or nil.
local function items(c)
  local out, pos = {}, 1
  while pos <= #c do
    local tag, v, nxt = read(c, pos)
    if not tag then return nil end
    out[#out + 1] = { tag = tag, value = v }
    pos = nxt
  end
  return out
end

local function signed(c)
  if #c == 0 or #c > 8 then return nil end
  local v = 0
  for i = 1, #c do v = (v << 8) | c:byte(i) end
  if #c < 8 and c:byte(1) >= 0x80 then v = v - (1 << (8 * #c)) end
  return v
end

-- An unsigned value (Counter, Gauge, TimeTicks); a float above 2^63 - 1.
local function unsigned(c)
  local i = 1
  while i < #c and c:byte(i) == 0 do i = i + 1 end
  local n = #c - i + 1
  if #c == 0 or n > 9 then return nil end
  if n > 8 or (n == 8 and c:byte(i) >= 0x80) then
    local v = 0.0
    for j = i, #c do v = v * 256 + c:byte(j) end
    return v
  end
  local v = 0
  for j = i, #c do v = (v << 8) | c:byte(j) end
  return v
end

local function oid_text(c)
  if #c == 0 then return nil end
  local t, n = {}, 0
  for i = 1, #c do
    local b = c:byte(i)
    if n > 0xffffffff then return nil end
    n = (n << 7) | (b & 0x7f)
    if b < 0x80 then
      if #t == 0 then
        local first = math.min(n // 40, 2)
        t[1], t[2] = first, n - first * 40
      else
        t[#t + 1] = n
      end
      n = 0
    elseif i == #c then
      return nil
    end
  end
  return table.concat(t, ".")
end

-- A variable's value as Lua sees it: integers, strings, dotted OIDs and
-- IP addresses; nil for NULL and the exceptions.
local function value(tag, c)
  if tag == INTEGER then return signed(c)
  elseif tag == OCTETS or tag == 0x44 then return c
  elseif tag == OID then return oid_text(c)
  elseif tag == 0x40 then
    if #c ~= 4 then return nil end
    return string.format("%d.%d.%d.%d", c:byte(1, 4))
  elseif tag == 0x41 or tag == 0x42 or tag == 0x43 or tag == 0x46 or tag == 0x47 then
    return unsigned(c)
  end
  return nil
end

-- A v1/v2c response: { version, community, tag, request_id,
-- error_status, error_index, varbinds = { { oid, tag, value,
-- exception } } }, or nil.
function snmp.parse(msg)
  local tag, body = read(msg, 1)
  if tag ~= SEQUENCE then return nil end
  local top = items(body)
  if not top or #top ~= 3 or top[1].tag ~= INTEGER or top[2].tag ~= OCTETS then
    return nil
  end
  local r = { version = signed(top[1].value), community = top[2].value, tag = top[3].tag }
  local p = items(top[3].value)
  if not p or #p ~= 4 or p[1].tag ~= INTEGER or p[2].tag ~= INTEGER or p[3].tag ~= INTEGER
    or p[4].tag ~= SEQUENCE then
    return nil
  end
  r.request_id, r.error_status, r.error_index =
    signed(p[1].value), signed(p[2].value), signed(p[3].value)
  local binds = items(p[4].value)
  if not binds then return nil end
  r.varbinds = {}
  for i, b in ipairs(binds) do
    local vb = b.tag == SEQUENCE and items(b.value)
    if not vb or #vb ~= 2 or vb[1].tag ~= OID then return nil end
    local name = oid_text(vb[1].value)
    if not name then return nil end
    r.varbinds[i] = {
      oid = name, tag = vb[2].tag, value = value(vb[2].tag, vb[2].value),
      exception = EXCEPTION[vb[2].tag],
    }
  end
  return r
end

-- An SNMPv3 answer to the discovery request: { msg_id, security_model,
-- engine_id, boots, time, tag }, or nil.
function snmp.parse_v3(msg)
  local tag, body = read(msg, 1)
  if tag ~= SEQUENCE then return nil end
  local top = items(body)
  if not top or #top < 4 or top[1].tag ~= INTEGER or signed(top[1].value) ~= 3
    or top[2].tag ~= SEQUENCE or top[3].tag ~= OCTETS then
    return nil
  end
  local g = items(top[2].value)
  if not g or #g < 4 or g[1].tag ~= INTEGER or g[4].tag ~= INTEGER then return nil end
  local r = { msg_id = signed(g[1].value), security_model = signed(g[4].value) }
  -- The security parameters: an OCTET STRING holding the USM sequence.
  local stag, sbody = read(top[3].value, 1)
  local usm = stag == SEQUENCE and items(sbody)
  if usm and #usm >= 3 and usm[1].tag == OCTETS and usm[2].tag == INTEGER
    and usm[3].tag == INTEGER then
    r.engine_id = usm[1].value
    r.boots = signed(usm[2].value)
    r.time = signed(usm[3].value)
  end
  -- The PDU type, when the scoped PDU is in clear.
  if top[4].tag == SEQUENCE then
    local s = items(top[4].value)
    if s and s[3] then r.tag = s[3].tag end
  end
  return r
end

-- ------------------------------------------------------------- OIDs

-- -1, 0 or 1 as OID `a` sorts before, equal to or after `b`.
local function parts(s)
  local t = {}
  for a in tostring(s):gmatch("%d+") do t[#t + 1] = tonumber(a) end
  return t
end

function snmp.compare(a, b)
  local x, y = parts(a), parts(b)
  for i = 1, math.min(#x, #y) do
    if x[i] ~= y[i] then return x[i] < y[i] and -1 or 1 end
  end
  if #x == #y then return 0 end
  return #x < #y and -1 or 1
end

-- Whether `o` lies under `base` (and is not `base` itself).
function snmp.under(o, base)
  return o:sub(1, #base + 1) == base .. "."
end

-- ---------------------------------------------------------------- args

-- A time from --script-args: milliseconds, or a number with ms, s, m or h.
local function ms(v, default)
  if type(v) ~= "string" then return default end
  local n, unit = v:match("^%s*(%d+%.?%d*)%s*(%a*)%s*$")
  n = tonumber(n)
  if not n then return default end
  local scale = ({ [""] = 1, ms = 1, s = 1000, m = 60000, h = 3600000 })[unit]
  if not scale then return default end
  return math.max(1, math.floor(n * scale))
end

-- The community: from creds.snmp ("community", or nmap's "user:pass"
-- form, where the password is the community and an empty one leaves the
-- user name), else "public".
function snmp.community()
  local c = fero.args.get("creds.snmp")
  if type(c) ~= "string" or c == "" then return "public" end
  local user, pass = c:match("^(.-):(.*)$")
  if not user then return c end
  if pass ~= "" and pass ~= "<empty>" then return pass end
  if user ~= "" then return user end
  return "public"
end

-- The options --script-args give: snmp.version (v1 or 0, the default;
-- v2c or 1), snmp.timeout (ms, default 5000), snmp.retries (default 1).
function snmp.options()
  local version, timeout, retries = fero.args.get("snmp.version", "snmp.timeout", "snmp.retries")
  local v = 0
  if version == "v2c" or version == "1" or version == "2c" then v = 1 end
  local r = math.tointeger(tonumber(retries)) or 1
  return {
    version = v,
    timeout = ms(timeout, 5000),
    retries = math.max(0, math.min(r, 10)),
    community = snmp.community(),
  }
end

-- -------------------------------------------------------------- session

local Session = {}
Session.__index = Session

-- A session with the agent on `port` (a scanned UDP port), or nil and a
-- message. `opts` overrides snmp.options().
function snmp.session(host, port, opts)
  local o = snmp.options()
  for k, v in pairs(opts or {}) do o[k] = v end
  local sock = fero.socket.new()
  sock:set_timeout(o.timeout)
  local ok, err = sock:connect(host, port, "udp")
  if not ok then return nil, err end
  return setmetatable({ sock = sock, opts = o }, Session)
end

function Session:close() self.sock:close() end

-- Send `msg` and return the first answer `parse` turns into a value that
-- `accept` takes, sending again up to `retries` times; nil and a message
-- when none comes. Other datagrams (late answers to an earlier request)
-- are skipped.
function Session:exchange(msg, parse, accept)
  local o = self.opts
  for _ = 0, o.retries do
    local ok, err = self.sock:send(msg)
    if not ok then return nil, err end
    local deadline = fero.clock_ms() + o.timeout
    while true do
      local left = deadline - fero.clock_ms()
      if left <= 0 then break end
      self.sock:set_timeout(left)
      local got, data = self.sock:receive()
      if not got then break end
      local r = parse(data)
      if r and accept(r) then
        self.sock:set_timeout(o.timeout)
        return r
      end
    end
  end
  self.sock:set_timeout(o.timeout)
  return nil, "no answer"
end

-- An answer to our v1/v2c request: a Response with our request-id,
-- version and community.
function Session:response_to(r)
  return r.tag == RESPONSE and r.request_id == snmp.REQUEST_ID
    and r.version == self.opts.version and r.community == self.opts.community
end

-- Whether the variables of `r` are exactly `oids`, as in an answer to a
-- GetRequest and in an error answer, which echoes the request's
-- variables (RFC 3416 4.2.1); an error answer may also carry none.
local function names(r, oids)
  if r.error_status ~= 0 and #r.varbinds == 0 then return true end
  if #r.varbinds ~= #oids then return false end
  for i, o in ipairs(oids) do
    if r.varbinds[i].oid ~= o then return false end
  end
  return true
end

-- GetRequest for `oids`: the response (see snmp.parse), or nil and a
-- message. A response naming other variables is not ours.
function Session:get(...)
  local oids = { ... }
  return self:exchange(snmp.message(self.opts.version, self.opts.community, GET, oids),
    snmp.parse, function(r)
      return self:response_to(r) and names(r, oids)
    end)
end

-- GetNextRequest for one OID: the response, or nil and a message. Its
-- variable must come after `o`, so a late answer to an earlier step of a
-- walk is not taken for this one; an error answer or a v2 endOfMibView
-- names `o` itself.
function Session:getnext(o)
  return self:exchange(snmp.message(self.opts.version, self.opts.community, GETNEXT, { o }),
    snmp.parse, function(r)
      if not self:response_to(r) then return false end
      if r.error_status ~= 0 then return names(r, { o }) end
      if #r.varbinds ~= 1 then return false end
      local vb = r.varbinds[1]
      if vb.exception == "endOfMibView" then return vb.oid == o end
      return snmp.compare(vb.oid, o) > 0
    end)
end

-- The variables under `base`, in order, read with GetNextRequest (at
-- most `max`, default snmp.MAX_WALK); nil and a message when the first
-- request gets no answer. The walk ends at the first variable outside
-- `base`, an error, an exception or an unanswered request.
function Session:walk(base, max)
  max = max or snmp.MAX_WALK
  local out, cur = {}, base
  while #out < max do
    local r, err = self:getnext(cur)
    if not r then
      if #out == 0 then return nil, err end
      break
    end
    if r.error_status ~= 0 then break end
    local vb = r.varbinds[1]
    if vb.exception or not snmp.under(vb.oid, base) then break end
    out[#out + 1] = vb
    cur = vb.oid
  end
  return out
end

-- The SNMPv3 engine discovery: the agent's Report (see snmp.parse_v3), or
-- nil and a message.
function Session:discover()
  return self:exchange(snmp.discovery_request(), snmp.parse_v3, function(r)
    return r.msg_id == snmp.REQUEST_ID
  end)
end

-- ------------------------------------------------------------- formats

-- TimeTicks (hundredths of a second) as nmap writes an uptime:
-- "28d17h18m59.00s", "5m3.25s", "0.50s".
function snmp.format_ticks(t)
  t = math.tointeger(t) or math.floor(t)
  local days, hr, min = t // 8640000, t // 360000 % 24, t // 6000 % 60
  local sec = (t % 6000) / 100
  if days > 0 then return string.format("%dd%02dh%02dm%02.2fs", days, hr, min, sec) end
  if hr > 0 then return string.format("%dh%02dm%02.2fs", hr, min, sec) end
  if min > 0 then return string.format("%dm%02.2fs", min, sec) end
  return string.format("%.2fs", sec)
end

fero.snmp = snmp
