-- NSE compatibility layer: the `ldap` module, LDAPv3 search over TCP
-- (and CLDAP over UDP) with BER encoding. Written for FeroProbe from
-- nmap's public API documentation and RFC 4511 (LDAP), RFC 4515 (search
-- filters) and X.690 (BER); not from nselib. GPL-3.0-or-later, like
-- FeroProbe.
--
-- Messages FeroProbe numbers itself carry message IDs 0x4650nnnn ("FP"
-- then a counter; IDS rules 9100038 TCP and 9100039 UDP). Only anonymous
-- binds are made: a bind with a user name or password is refused here,
-- so no credentials leave FeroProbe. Every connection is the script's
-- own nmap socket, so only scanned ports are reached.
local fero = ...
local nmap = require "nmap"
local stdnse = require "stdnse"

local ldap = {}

local MAX_MESSAGE = 16 * 1024 * 1024
local MAX_ENTRIES = 100000
local MAX_DEPTH = 64
local ID_MARK = 0x46500000

---------------------------------------------------------------------------
-- Constants (RFC 4511).

--- Application constants: the protocolOp tag numbers.
ldap.APPNO = {
  BindRequest = 0, BindResponse = 1, UnbindRequest = 2, SearchRequest = 3,
  SearchResponse = 4, SearchResDone = 5, ModifyRequest = 6, ModifyResponse = 7,
  AddRequest = 8, AddResponse = 9, DelRequest = 10, DelResponse = 11,
  ModifyDNRequest = 12, ModifyDNResponse = 13, CompareRequest = 14,
  CompareResponse = 15, AbandonRequest = 16, SearchResultReference = 19,
  ExtendedRequest = 23, ExtendedResponse = 24, IntermediateResponse = 25,
}

--- Search scopes.
ldap.SCOPE = { base = 0, one = 1, sub = 2, children = 3 }

--- Alias dereferencing policies.
ldap.DEREFPOLICY = { default = 0, never = 0, searching = 1, finding = 2, always = 3 }

--- Filter choices (the context tag numbers).
ldap.FILTER = {
  _and = 0, _or = 1, _not = 2, equalityMatch = 3, substrings = 4,
  greaterOrEqual = 5, lessOrEqual = 6, present = 7, approxMatch = 8,
  extensibleMatch = 9,
}

--- Result codes and their names.
ldap.ERRORS = {
  [0] = "Success", [1] = "Operations error", [2] = "Protocol error",
  [3] = "Time limit exceeded", [4] = "Size limit exceeded", [5] = "Compare false",
  [6] = "Compare true", [7] = "Auth method not supported",
  [8] = "Strong authentication required", [10] = "Referral",
  [11] = "Admin limit exceeded", [12] = "Unavailable critical extension",
  [13] = "Confidentiality required", [14] = "SASL bind in progress",
  [16] = "No such attribute", [17] = "Undefined attribute type",
  [18] = "Inappropriate matching", [19] = "Constraint violation",
  [20] = "Attribute or value exists", [21] = "Invalid attribute syntax",
  [32] = "No such object", [33] = "Alias problem", [34] = "Invalid DN syntax",
  [36] = "Alias dereferencing problem", [48] = "Inappropriate authentication",
  [49] = "Invalid credentials", [50] = "Insufficient access rights", [51] = "Busy",
  [52] = "Unavailable", [53] = "Unwilling to perform", [54] = "Loop detect",
  [64] = "Naming violation", [65] = "Object class violation",
  [66] = "Not allowed on non-leaf", [67] = "Not allowed on RDN",
  [68] = "Entry already exists", [69] = "Object class mods prohibited",
  [71] = "Affects multiple DSAs", [80] = "Other",
}

---------------------------------------------------------------------------
-- BER.

local function enc_len(n)
  if n < 0x80 then return string.char(n) end
  local s = ""
  while n > 0 do
    s = string.char(n & 0xff) .. s
    n = n >> 8
  end
  return string.char(0x80 | #s) .. s
end

local function tlv(tag, content)
  return string.char(tag) .. enc_len(#content) .. content
end

local function enc_int(tag, n)
  n = math.floor(n)
  local s = ""
  repeat
    s = string.char(n & 0xff) .. s
    n = n // 256 -- floor division keeps the sign, unlike >>
  until (n == 0 and s:byte(1) < 0x80) or (n == -1 and s:byte(1) >= 0x80)
  return tlv(tag, s)
end

---
-- ldap.encode(val): val in BER. A number is an INTEGER, a boolean a
-- BOOLEAN, a string an OCTET STRING; a table with _ldaptype (the tag as
-- hex, "30" for a SEQUENCE) is that tag around its elements, strings
-- taken as they are (already encoded) and other values encoded.
function ldap.encode(val, depth)
  depth = (depth or 0) + 1
  if depth > MAX_DEPTH then error("ldap.encode: nested too deep") end
  local t = type(val)
  if t == "number" then return enc_int(0x02, val) end
  if t == "boolean" then return tlv(0x01, val and "\xff" or "\0") end
  if t == "string" then return tlv(0x04, val) end
  if t == "table" then
    local tag = tonumber(val._ldaptype or "30", 16) or 0x30
    local parts = {}
    for _, v in ipairs(val) do
      parts[#parts + 1] = type(v) == "string" and v or ldap.encode(v, depth)
    end
    return tlv(tag, table.concat(parts))
  end
  return ""
end

-- One TLV from pos: tag, content, position after it; nil when cut short.
local function read_tlv(s, pos)
  local tag = s:byte(pos)
  local b = s:byte(pos + 1)
  if not tag or not b then return nil end
  pos = pos + 2
  local len = b
  if b & 0x80 ~= 0 then
    local n = b & 0x7f
    if n == 0 or n > 4 or #s < pos + n - 1 then return nil end
    len = 0
    for i = 0, n - 1 do len = (len << 8) | s:byte(pos + i) end
    pos = pos + n
  end
  if #s < pos + len - 1 then return nil end
  return tag, s:sub(pos, pos + len - 1), pos + len
end

local function dec_int(c)
  if #c == 0 or #c > 8 then return nil end
  local n = c:byte(1)
  if n >= 0x80 then n = n - 0x100 end
  for i = 2, #c do n = (n << 8) | c:byte(i) end
  return n
end

local function decode(s, pos, depth)
  if depth > MAX_DEPTH then return nil, pos end
  local tag, c, nxt = read_tlv(s, pos)
  if not tag then return nil, pos end
  if tag == 0x02 or tag == 0x0a then return dec_int(c), nxt end
  if tag == 0x01 then return c ~= "\0", nxt end
  if tag & 0x20 ~= 0 then
    local out = { _ldaptype = string.format("%02X", tag) }
    local p = 1
    while p <= #c do
      local v, np = decode(c, p, depth + 1)
      if np == p then return nil, pos end
      out[#out + 1] = v
      p = np
    end
    return out, nxt
  end
  return c, nxt
end

---
-- ldap.decode(encStr, pos): the value at pos (default 1) and the
-- position after it. INTEGER and ENUMERATED give numbers, BOOLEAN a
-- boolean, other primitives their bytes; a constructed value is a table
-- of its decoded elements with _ldaptype (the tag as hex).
function ldap.decode(encStr, pos)
  return decode(encStr, pos or 1, 0)
end

---------------------------------------------------------------------------
-- Filters (RFC 4511 section 4.5.1).

local function str(tag, s) return tlv(tag, tostring(s or "")) end

---
-- ldap.createFilter(filter): the BER of a filter table { op = one of
-- ldap.FILTER, obj = attribute, val = value }; for _and and _or, val is
-- a list of filters, for _not a filter. A substrings value takes "*" as
-- the wildcard; an extensibleMatch value is "rule:=value".
function ldap.createFilter(filter, depth)
  depth = (depth or 0) + 1
  if depth > MAX_DEPTH then error("ldap.createFilter: nested too deep") end
  local F = ldap.FILTER
  local op = filter.op
  if op == F._and or op == F._or then
    local parts = {}
    for _, f in ipairs(filter.val or {}) do parts[#parts + 1] = ldap.createFilter(f, depth) end
    return tlv(0xa0 | op, table.concat(parts))
  elseif op == F._not then
    return tlv(0xa2, ldap.createFilter(filter.val, depth))
  elseif op == F.present then
    return str(0x87, filter.obj)
  elseif op == F.substrings then
    local val = tostring(filter.val or "")
    -- "a*b*c" splits into a (initial), b (any) and c (final).
    local pieces = {}
    for piece in (val .. "*"):gmatch("([^*]*)%*") do pieces[#pieces + 1] = piece end
    local subs = {}
    for i, piece in ipairs(pieces) do
      if piece ~= "" then
        local t = 0x81
        if #pieces > 1 and i == 1 then
          t = 0x80
        elseif #pieces > 1 and i == #pieces then
          t = 0x82
        end
        subs[#subs + 1] = tlv(t, piece)
      end
    end
    return tlv(0xa4, str(0x04, filter.obj) .. tlv(0x30, table.concat(subs)))
  elseif op == F.extensibleMatch then
    local val = tostring(filter.val or "")
    local rule, value = val:match("^(.-):=(.*)$")
    local parts = {}
    if rule and rule ~= "" then parts[#parts + 1] = tlv(0x81, rule) end
    if filter.obj then parts[#parts + 1] = tlv(0x82, tostring(filter.obj)) end
    parts[#parts + 1] = tlv(0x83, value or val)
    return tlv(0xa9, table.concat(parts))
  elseif op == F.equalityMatch or op == F.greaterOrEqual or op == F.lessOrEqual
    or op == F.approxMatch then
    return tlv(0xa0 | op, str(0x04, filter.obj) .. str(0x04, filter.val))
  end
  -- No filter: every object, (objectClass=*).
  return str(0x87, "objectClass")
end

---------------------------------------------------------------------------
-- Messages.

local counter = 0
local function next_id()
  counter = (counter % 0xffff) + 1
  return ID_MARK + counter
end

local function message(op)
  return tlv(0x30, enc_int(0x02, next_id()) .. op)
end

-- Reads one LDAPMessage from the socket (buffered on the socket table):
-- the message's bytes, or nil and an error.
local buffers = setmetatable({}, { __mode = "k" })

local function receive_message(socket)
  local buf = buffers[socket] or ""
  while true do
    if #buf >= 2 then
      if buf:byte(1) ~= 0x30 then
        buffers[socket] = nil
        return nil, "Not an LDAP message"
      end
      local b = buf:byte(2)
      local hdr, len = 2, b
      if b & 0x80 ~= 0 then
        local n = b & 0x7f
        if n == 0 or n > 4 then
          buffers[socket] = nil
          return nil, "Bad LDAP message length"
        end
        if #buf >= 2 + n then
          len = 0
          for i = 3, 2 + n do len = (len << 8) | buf:byte(i) end
          hdr = 2 + n
        else
          len = nil
        end
      end
      if len then
        if len > MAX_MESSAGE then
          buffers[socket] = nil
          return nil, "LDAP message too long"
        end
        if #buf >= hdr + len then
          buffers[socket] = buf:sub(hdr + len + 1)
          return buf:sub(1, hdr + len)
        end
      end
    end
    local ok, data = socket:receive()
    if not ok then
      buffers[socket] = nil
      return nil, data
    end
    buf = buf .. data
  end
end

-- An LDAPMessage's protocolOp: tag, content (the op's elements as BER),
-- or nil and an error.
local function protocol_op(msg)
  local _, body = read_tlv(msg, 1)
  if not body then return nil, "Short LDAP message" end
  local tag, _, pos = read_tlv(body, 1) -- messageID
  if tag ~= 0x02 then return nil, "LDAP message without an ID" end
  local optag, op = read_tlv(body, pos)
  if not optag then return nil, "LDAP message without an operation" end
  return optag, op
end

-- An LDAPResult (resultCode, matchedDN, diagnosticMessage) from an op's
-- content: code, message, or nil and an error.
local function ldap_result(op)
  local tag, c, pos = read_tlv(op, 1)
  if tag ~= 0x0a then return nil, "Short LDAP result" end
  local code = dec_int(c)
  local _, _, p2 = read_tlv(op, pos)
  if not p2 then return nil, "Short LDAP result" end
  local _, diag = read_tlv(op, p2)
  return code, diag or ""
end

local function result_text(code, diag)
  local name = ldap.ERRORS[code] or ("Result code " .. tostring(code))
  if diag and diag ~= "" then return string.format("%s: %s", name, diag) end
  return name
end

---
-- ldap.bindRequest(socket, params): an anonymous simple bind (params
-- { version = 3, username, password }); true, or false and an error.
-- FeroProbe makes anonymous binds only: with a user name or password it
-- sends nothing and returns false.
function ldap.bindRequest(socket, params)
  params = params or {}
  local user, pass = params.username or "", params.password or ""
  if user ~= "" or pass ~= "" then
    return false, "Binding with credentials is not supported by FeroProbe (anonymous binds only)"
  end
  local op = tlv(0x60, enc_int(0x02, tonumber(params.version) or 3) .. str(0x04, "") .. tlv(0x80, ""))
  local ok, err = socket:send(message(op))
  if not ok then return false, err end
  local msg
  msg, err = receive_message(socket)
  if not msg then return false, err end
  local tag, body = protocol_op(msg)
  if not tag then return false, body end
  if tag ~= 0x61 then return false, "Unexpected reply to a bind" end
  local code, diag = ldap_result(body)
  if not code then return false, diag end
  if code ~= 0 then return false, result_text(code, diag) end
  return true
end

---
-- ldap.unbindRequest(socket): sends an unbind; true, or false and an
-- error.
function ldap.unbindRequest(socket)
  local ok, err = socket:send(message(tlv(0x42, "")))
  buffers[socket] = nil
  if not ok then return false, err end
  return true
end

local function search_op(params)
  local attrs = {}
  local list = params.attributes
  if type(list) == "string" then list = { list } end
  for _, a in ipairs(list or {}) do attrs[#attrs + 1] = str(0x04, a) end
  local max = tonumber(params.maxObjects)
  local filter = params.filter and ldap.createFilter(params.filter) or ldap.createFilter({})
  return tlv(0x63, str(0x04, params.baseObject)
    .. enc_int(0x0a, tonumber(params.scope) or ldap.SCOPE.base)
    .. enc_int(0x0a, tonumber(params.derefPolicy) or ldap.DEREFPOLICY.default)
    .. enc_int(0x02, (max and max > 0) and max or 0)
    .. enc_int(0x02, 0)
    .. tlv(0x01, "\0")
    .. filter
    .. tlv(0x30, table.concat(attrs)))
end

-- A SearchResultEntry's content: { objectName = dn, attributes = {
-- { name, value, ... } ... } }, or nil.
local function search_entry(op)
  local tag, dn, pos = read_tlv(op, 1)
  if tag ~= 0x04 then return nil end
  local atag, list = read_tlv(op, pos)
  if atag ~= 0x30 then return nil end
  local entry = { objectName = dn, attributes = {} }
  local p = 1
  while p <= #list do
    local t, attr, np = read_tlv(list, p)
    if t ~= 0x30 then return nil end
    local nt, name, vp = read_tlv(attr, 1)
    local st, vals = read_tlv(attr, vp or 1)
    if nt ~= 0x04 or st ~= 0x31 then return nil end
    local a = { name }
    local q = 1
    while q <= #vals do
      local vt, v, nq = read_tlv(vals, q)
      if not vt then return nil end
      a[#a + 1] = v
      q = nq
    end
    entry.attributes[#entry.attributes + 1] = a
    p = np
  end
  return entry
end

-- Collects search replies from next_msg() until SearchResultDone.
local function collect(next_msg, params)
  local entries = {}
  local max = tonumber(params.maxObjects)
  while true do
    local msg, err = next_msg()
    if not msg then
      if #entries > 0 then
        entries.resultCode, entries.errorMessage = 80, tostring(err)
        return true, entries
      end
      return false, err
    end
    local tag, op = protocol_op(msg)
    if not tag then return false, op end
    if tag == 0x64 then
      local e = search_entry(op)
      if not e then return false, "Bad search result entry" end
      if (not max or max <= 0 or #entries < max) and #entries < MAX_ENTRIES then
        entries[#entries + 1] = e
      end
    elseif tag == 0x65 then
      local code, diag = ldap_result(op)
      if not code then return false, diag end
      -- A size limit the caller set itself (maxObjects) is not an error.
      if code == 4 and max and max > 0 and #entries >= max then code = 0 end
      entries.resultCode = code
      if code ~= 0 then
        if #entries == 0 then return false, result_text(code, diag) end
        entries.errorMessage = result_text(code, diag)
      end
      return true, entries
    end
    -- References (0x73) and anything else are skipped.
  end
end

---
-- ldap.searchRequest(socket, params): a search with params { baseObject,
-- scope, derefPolicy, filter, attributes, maxObjects }; true and the
-- entries (each { objectName, attributes }, the table's resultCode and,
-- on a soft error, errorMessage set), or false and an error.
function ldap.searchRequest(socket, params)
  params = params or {}
  local ok, err = socket:send(message(search_op(params)))
  if not ok then return false, err end
  return collect(function() return receive_message(socket) end, params)
end

---
-- ldap.udpSearchRequest(host, port, params): searchRequest over UDP
-- (CLDAP), one datagram out and the replies in.
function ldap.udpSearchRequest(host, port, params)
  params = params or {}
  local socket = nmap.new_socket("udp")
  socket:set_timeout(5000)
  local ok, err = socket:connect(host, port, "udp")
  if not ok then return false, err end
  ok, err = socket:send(message(search_op(params)))
  if not ok then
    socket:close()
    return false, err
  end
  -- Each datagram holds one or more whole messages.
  local pending = {}
  local function next_msg()
    while #pending == 0 do
      local got, data = socket:receive()
      if not got then return nil, data end
      local p = 1
      while p <= #data do
        local tag, _, np = read_tlv(data, p)
        if tag ~= 0x30 then return nil, "Not an LDAP message" end
        pending[#pending + 1] = data:sub(p, np - 1)
        p = np
      end
    end
    return table.remove(pending, 1)
  end
  local status, result = collect(next_msg, params)
  socket:close()
  return status, result
end

---
-- ldap.extractAttribute(searchEntries, attributeName): the values of the
-- attribute (its name matched without regard to case) over all entries,
-- or nil when none has it.
function ldap.extractAttribute(searchEntries, attributeName)
  if type(searchEntries) ~= "table" or not attributeName then return nil end
  local want = tostring(attributeName):lower()
  local out = {}
  for _, e in ipairs(searchEntries) do
    for _, a in ipairs(e.attributes or {}) do
      if tostring(a[1]):lower() == want then
        for i = 2, #a do out[#out + 1] = a[i] end
      end
    end
  end
  if #out == 0 then return nil end
  return out
end

---------------------------------------------------------------------------
-- Value conversion.

---
-- ldap.convertADTimeStamp(timestamp): an Active Directory time (100 ns
-- steps from 1601-01-01) as "2010/08/27 17:30:16 UTC". 0 and the largest
-- value mean "never" and are given as they are.
function ldap.convertADTimeStamp(timestamp)
  local n = math.tointeger(tonumber(timestamp))
  if not n or n <= 0 or n == math.maxinteger then return tostring(timestamp) end
  local secs = n // 10000000 - 11644473600
  return os.date("!%Y/%m/%d %H:%M:%S UTC", secs)
end

---
-- ldap.convertZuluTimeStamp(timestamp): "20110904003302.0Z" as
-- "2011/09/04 00:33:02 UTC".
function ldap.convertZuluTimeStamp(timestamp)
  local y, mo, d, h, mi, s = tostring(timestamp):match("^(%d%d%d%d)(%d%d)(%d%d)(%d%d)(%d%d)(%d%d)")
  if not y then return tostring(timestamp) end
  return string.format("%s/%s/%s %s:%s:%s UTC", y, mo, d, h, mi, s)
end

---
-- ldap.convertObjectSid(data): a binary objectSid as
-- "1-5-21-542885397-2936741293-3965599772-500" (revision, authority,
-- then the sub-authorities).
function ldap.convertObjectSid(data)
  if type(data) ~= "string" or #data < 8 then return tostring(data) end
  local rev, count = data:byte(1), data:byte(2)
  if #data < 8 + 4 * count then return stdnse.tohex(data) end
  local auth = 0
  for i = 3, 8 do auth = (auth << 8) | data:byte(i) end
  local parts = { tostring(rev), tostring(auth) }
  for i = 0, count - 1 do
    parts[#parts + 1] = tostring((string.unpack("<I4", data, 9 + 4 * i)))
  end
  return table.concat(parts, "-")
end

---
-- ldap.copyTable(targetTable): a deep copy of the table.
function ldap.copyTable(targetTable, seen)
  if type(targetTable) ~= "table" then return targetTable end
  seen = seen or {}
  if seen[targetTable] then return seen[targetTable] end
  local out = {}
  seen[targetTable] = out
  for k, v in pairs(targetTable) do out[ldap.copyTable(k, seen)] = ldap.copyTable(v, seen) end
  return setmetatable(out, getmetatable(targetTable))
end

local AD_TIME = {
  pwdlastset = true, lastlogon = true, lastlogontimestamp = true, badpasswordtime = true,
  accountexpires = true, lastlogoff = true, lockouttime = true, creationtime = true,
}
local ZULU_TIME = { whencreated = true, whenchanged = true, dscorepropagationdata = true }

local function printable(s)
  return not s:find("[%z\1-\8\11\12\14-\31\127-\255]")
end

local function show(name, value)
  local n = tostring(name):lower()
  if n == "objectsid" then return ldap.convertObjectSid(value) end
  if n == "objectguid" and #value == 16 then return stdnse.tohex(value) end
  if AD_TIME[n] then return ldap.convertADTimeStamp(value) end
  if ZULU_TIME[n] then return ldap.convertZuluTimeStamp(value) end
  if not printable(value) then return stdnse.tohex(value) end
  return value
end

---
-- ldap.searchResultToTable(searchEntries): a table for
-- stdnse.format_output, named "LDAP Results": per entry one named
-- "dn: <name>" ("<ROOT>" for the root DSE) holding its "attribute:
-- value" lines. Times, SIDs and binary values are decoded.
function ldap.searchResultToTable(searchEntries)
  local result = { name = "LDAP Results" }
  for _, e in ipairs(searchEntries or {}) do
    local lines = {}
    for _, a in ipairs(e.attributes or {}) do
      for i = 2, #a do lines[#lines + 1] = string.format("%s: %s", a[1], show(a[1], a[i])) end
    end
    local name = (e.objectName and e.objectName ~= "") and ("dn: " .. e.objectName) or "<ROOT>"
    result[#result + 1] = { name = name, lines }
  end
  return result
end

local function csv(s)
  s = tostring(s)
  if s:find('[",\r\n]') then return '"' .. s:gsub('"', '""') .. '"' end
  return s
end

---
-- ldap.searchResultToFile(searchEntries, filename): saves the entries as
-- CSV (a "dn" column, then one per attribute name); true, or false and
-- an error.
function ldap.searchResultToFile(searchEntries, filename)
  local names, seen = {}, {}
  for _, e in ipairs(searchEntries or {}) do
    for _, a in ipairs(e.attributes or {}) do
      local k = tostring(a[1])
      if not seen[k:lower()] then
        seen[k:lower()] = true
        names[#names + 1] = k
      end
    end
  end
  local f, err = io.open(filename, "w")
  if not f then return false, err end
  local head = { "dn" }
  for _, n in ipairs(names) do head[#head + 1] = csv(n) end
  f:write(table.concat(head, ","), "\n")
  for _, e in ipairs(searchEntries or {}) do
    local row = { csv(e.objectName or "") }
    for _, n in ipairs(names) do
      local vals = {}
      for _, a in ipairs(e.attributes or {}) do
        if tostring(a[1]):lower() == n:lower() then
          for i = 2, #a do vals[#vals + 1] = show(a[1], a[i]) end
        end
      end
      row[#row + 1] = csv(table.concat(vals, ";"))
    end
    f:write(table.concat(row, ","), "\n")
  end
  f:close()
  return true
end

return ldap
