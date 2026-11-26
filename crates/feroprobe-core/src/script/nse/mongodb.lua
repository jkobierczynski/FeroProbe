-- NSE compatibility layer: the `mongodb` module, MongoDB commands over
-- the legacy OP_QUERY wire message with BSON documents. Written for
-- FeroProbe from nmap's public API documentation, the MongoDB wire
-- protocol and the BSON 1.1 specification; not from nselib.
-- GPL-3.0-or-later, like FeroProbe.
--
-- A query FeroProbe builds carries a request ID whose first two bytes on
-- the wire are "FP" (IDS rule 9100040). No logins: mongodb.login refuses
-- before anything is sent, as logins stay unbuilt in the compatibility
-- layer (maintainer's choice for ldap, 2026-11-26). MongoDB 5.1 and later
-- answer OP_QUERY only for the handshake commands, so these queries (as
-- nmap's) get an error from them.
local fero = ...
local nmap = require "nmap"
local stdnse = require "stdnse"

local mongodb = {}

local MAX_MESSAGE = 48 * 1024 * 1024
local MAX_DEPTH = 64
local OP_REPLY, OP_QUERY = 1, 2004

---------------------------------------------------------------------------
-- BSON.

-- Values that print as nmap's mongodb scripts print them.
local function tagged(text) return setmetatable({}, { __tostring = function() return text end, __bson = true }) end

local function cstring(s, pos)
  local z = s:find("\0", pos, true)
  if not z then return nil end
  return s:sub(pos, z - 1), z + 1
end

local decode_doc

local function decode_value(t, s, pos, depth)
  if t == 0x01 then
    if #s < pos + 7 then return nil end
    return (string.unpack("<d", s, pos)), pos + 8
  elseif t == 0x02 or t == 0x0d or t == 0x0e then
    if #s < pos + 3 then return nil end
    local len = string.unpack("<i4", s, pos)
    if len < 1 or #s < pos + 3 + len then return nil end
    return s:sub(pos + 4, pos + 2 + len), pos + 4 + len
  elseif t == 0x03 or t == 0x04 then
    return decode_doc(s, pos, depth + 1, t == 0x04)
  elseif t == 0x05 then
    if #s < pos + 4 then return nil end
    local len, sub = string.unpack("<i4B", s, pos)
    if len < 0 or #s < pos + 4 + len then return nil end
    local data = s:sub(pos + 5, pos + 4 + len)
    return tagged(string.format("Binary subtype %d: %s", sub, stdnse.tohex(data))), pos + 5 + len
  elseif t == 0x06 or t == 0x0a or t == 0xff or t == 0x7f then
    return nil, pos, true -- undefined, null, min and max key: left out
  elseif t == 0x07 then
    if #s < pos + 11 then return nil end
    return s:sub(pos, pos + 11), pos + 12
  elseif t == 0x08 then
    if #s < pos then return nil end
    return s:byte(pos) ~= 0, pos + 1
  elseif t == 0x09 or t == 0x12 then
    if #s < pos + 7 then return nil end
    return (string.unpack("<i8", s, pos)), pos + 8
  elseif t == 0x0b then
    local re, p = cstring(s, pos)
    if not re then return nil end
    local opts, p2 = cstring(s, p)
    if not opts then return nil end
    return tagged(string.format("/%s/%s", re, opts)), p2
  elseif t == 0x10 then
    if #s < pos + 3 then return nil end
    return (string.unpack("<i4", s, pos)), pos + 4
  elseif t == 0x11 then
    if #s < pos + 7 then return nil end
    local inc, time = string.unpack("<I4I4", s, pos)
    return tagged(string.format("Timestamp(%d, %d)", time, inc)), pos + 8
  elseif t == 0x13 then
    if #s < pos + 15 then return nil end
    return tagged("Decimal128: " .. stdnse.tohex(s:sub(pos, pos + 15))), pos + 16
  end
  return nil
end

-- A document from pos: the table (keys in order in its metatable's
-- __keys; an array's elements under 0, 1, ... as nmap gives them) and the
-- position after it; nil when malformed.
function decode_doc(s, pos, depth, array)
  if depth > MAX_DEPTH or #s < pos + 4 then return nil end
  local len = string.unpack("<i4", s, pos)
  if len < 5 or #s < pos + len - 1 or s:byte(pos + len - 1) ~= 0 then return nil end
  local stop = pos + len - 1
  local doc, keys = {}, {}
  local p = pos + 4
  while p < stop do
    local t = s:byte(p)
    local name, np = cstring(s, p + 1)
    if not name or np > stop then return nil end
    local v, after, skip = decode_value(t, s, np, depth)
    if not after then return nil end
    if not skip then
      local key = name
      if array then key = math.tointeger(tonumber(name)) or name end
      if doc[key] == nil then keys[#keys + 1] = key end
      doc[key] = v
    end
    p = after
  end
  return setmetatable(doc, { __keys = keys }), stop + 1
end

local function encode_doc(pairs_list)
  local parts = {}
  for _, kv in ipairs(pairs_list) do
    local k, v = kv[1], kv[2]
    local t = math.type(v)
    if t == "integer" and v >= -0x80000000 and v <= 0x7fffffff then
      parts[#parts + 1] = "\x10" .. k .. "\0" .. string.pack("<i4", v)
    elseif t == "integer" then
      parts[#parts + 1] = "\x12" .. k .. "\0" .. string.pack("<i8", v)
    elseif t == "float" then
      parts[#parts + 1] = "\x01" .. k .. "\0" .. string.pack("<d", v)
    elseif type(v) == "boolean" then
      parts[#parts + 1] = "\x08" .. k .. "\0" .. (v and "\1" or "\0")
    else
      v = tostring(v)
      parts[#parts + 1] = "\x02" .. k .. "\0" .. string.pack("<i4", #v + 1) .. v .. "\0"
    end
  end
  local body = table.concat(parts)
  return string.pack("<i4", #body + 5) .. body .. "\0"
end

---------------------------------------------------------------------------
-- Messages.

local counter = 0

-- An OP_QUERY for the command document cmd on collection coll. The
-- request ID's first two bytes on the wire are "FP".
local function op_query(coll, cmd)
  counter = (counter % 0x7fff) + 1
  local request_id = 0x5046 | (counter << 16)
  local body = string.pack("<i4", 0) .. coll .. "\0" .. string.pack("<i4i4", 0, -1) .. encode_doc(cmd)
  return string.pack("<i4i4i4i4", 16 + #body, request_id, 0, OP_QUERY) .. body
end

---
-- mongodb.serverStatusQuery(): true and an OP_QUERY packet for the
-- serverStatus command.
function mongodb.serverStatusQuery()
  return true, op_query("test.$cmd", { { "serverStatus", 1 } })
end

---
-- mongodb.buildInfoQuery(): true and an OP_QUERY packet for buildinfo.
function mongodb.buildInfoQuery()
  return true, op_query("admin.$cmd", { { "buildinfo", 1 } })
end

---
-- mongodb.listDbQuery(): true and an OP_QUERY packet for listDatabases.
function mongodb.listDbQuery()
  return true, op_query("admin.$cmd", { { "listDatabases", 1 } })
end

local function read(socket, n, state)
  while #state.buf < n do
    local ok, data = socket:receive_bytes(n - #state.buf)
    if not ok then return nil, data end
    state.buf = state.buf .. data
  end
  local out = state.buf:sub(1, n)
  state.buf = state.buf:sub(n + 1)
  return out
end

---
-- mongodb.query(socket, packet): sends the packet and reads the reply;
-- true and its first document (a table; nested documents and arrays as
-- tables), or false and an error.
function mongodb.query(socket, packet)
  local ok, err = socket:send(packet)
  if not ok then return false, err end
  local state = { buf = "" }
  local head
  head, err = read(socket, 16, state)
  if not head then return false, err end
  local len, _, _, op = string.unpack("<i4i4i4i4", head)
  if op ~= OP_REPLY or len < 36 or len > MAX_MESSAGE then return false, "Not a MongoDB reply" end
  local body
  body, err = read(socket, len - 16, state)
  if not body then return false, err end
  local flags, _, _, count = string.unpack("<i4i8i4i4", body)
  if count < 1 then return false, "No documents returned" end
  local doc = decode_doc(body, 21, 0, false)
  if not doc then return false, "Malformed BSON document" end
  if flags & 2 ~= 0 then return false, tostring(doc["$err"] or "Query failure") end
  return true, doc
end

---
-- mongodb.login(socket, db, username, password): FeroProbe makes no
-- MongoDB logins; false and an error, nothing sent.
function mongodb.login(socket, db, username, password)
  return false, "MongoDB logins are not supported by FeroProbe"
end

local function keys_of(t)
  local mt = getmetatable(t)
  if mt and mt.__keys then return mt.__keys end
  local keys = {}
  for k in pairs(t) do keys[#keys + 1] = k end
  table.sort(keys, function(a, b) return tostring(a) < tostring(b) end)
  return keys
end

local function to_table(doc, depth)
  local out = {}
  for _, k in ipairs(keys_of(doc)) do
    local v = doc[k]
    local mt = type(v) == "table" and getmetatable(v)
    if type(v) == "table" and not (mt and mt.__bson) and depth < MAX_DEPTH then
      local sub = to_table(v, depth + 1)
      sub.name = tostring(k)
      out[#out + 1] = sub
    else
      out[#out + 1] = string.format("%s = %s", tostring(k), tostring(v))
    end
  end
  return out
end

---
-- mongodb.queryResultToTable(resultTable): the document as a table for
-- stdnse.format_output: "key = value" lines, a nested document or array
-- as a table named by its key; in the document's own order.
function mongodb.queryResultToTable(resultTable)
  if type(resultTable) ~= "table" then return {} end
  return to_table(resultTable, 0)
end

---
-- mongodb.testBson(): nmap's debugging helper; does nothing here.
function mongodb.testBson()
  return true
end

return mongodb
