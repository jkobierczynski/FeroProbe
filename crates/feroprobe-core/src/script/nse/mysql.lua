-- NSE compatibility layer: the `mysql` module, a small MySQL client
-- (greeting, login, queries). Written for FeroProbe from nmap's public
-- API documentation and the MySQL client/server protocol documentation
-- (not from nselib); GPL-3.0-or-later, like FeroProbe.
--
-- Logins use mysql_native_password (protocol 4.1 authentication). When
-- the server takes connection attributes, the login names the client:
-- program_name=FeroProbe, the mark IDS rule 9100034 looks for.
local fero = ...
local openssl = require "openssl"
local tab = require "tab"
local mysql = {}

-- Capability flags of the greeting's lower and upper 16 bits, named as
-- in the protocol documentation (CLIENT_...).
mysql.Capabilities = {
  LONG_PASSWORD = 0x1, FOUND_ROWS = 0x2, LONG_FLAG = 0x4, CONNECT_WITH_DB = 0x8,
  NO_SCHEMA = 0x10, COMPRESS = 0x20, ODBC = 0x40, LOCAL_FILES = 0x80,
  IGNORE_SPACE = 0x100, PROTOCOL_41 = 0x200, INTERACTIVE = 0x400, SSL = 0x800,
  IGNORE_SIGPIPE = 0x1000, TRANSACTIONS = 0x2000, RESERVED = 0x4000,
  SECURE_CONNECTION = 0x8000,
}
mysql.ExtCapabilities = {
  MULTI_STATEMENTS = 0x1, MULTI_RESULTS = 0x2, PS_MULTI_RESULTS = 0x4, PLUGIN_AUTH = 0x8,
  CONNECT_ATTRS = 0x10, PLUGIN_AUTH_LENENC_CLIENT_DATA = 0x20,
  CAN_HANDLE_EXPIRED_PASSWORDS = 0x40, SESSION_TRACK = 0x80, DEPRECATE_EOF = 0x100,
}

local CLIENT_PROTOCOL_41 = 0x200
local CLIENT_SECURE_CONNECTION = 0x8000
local CLIENT_PLUGIN_AUTH = 0x80000
local CLIENT_CONNECT_ATTRS = 0x100000

-- The capabilities each socket's server announced, for the login.
local server_caps = setmetatable({}, { __mode = "k" })

-- Data read past the packet a call returned, per socket.
local pending = setmetatable({}, { __mode = "k" })

local function read_bytes(socket, n)
  local buf = pending[socket] or ""
  while #buf < n do
    local ok, more = socket:receive_bytes(n - #buf)
    if not ok then
      pending[socket] = buf
      return nil, more or "EOF"
    end
    buf = buf .. more
  end
  pending[socket] = buf:sub(n + 1)
  return buf:sub(1, n)
end

-- One packet: its payload and sequence number, or nil and an error.
local function read_packet(socket)
  local head, err = read_bytes(socket, 4)
  if not head then return nil, err end
  local len, seq = string.unpack("<I3B", head)
  local payload
  payload, err = read_bytes(socket, len)
  if not payload then return nil, err end
  return payload, seq
end

local function send_packet(socket, seq, payload)
  return socket:send(string.pack("<I3B", #payload, seq & 0xff) .. payload)
end

-- An ERR packet's message.
local function err_message(p)
  local code = string.unpack("<I2", p, 2)
  local msg = p:sub(4)
  if msg:sub(1, 1) == "#" then msg = msg:sub(7) end
  return msg, code
end

-- A length-encoded integer at pos: the value (nil for NULL, 0xfb) and the
-- next position.
local function lenenc_int(p, pos)
  local b = p:byte(pos)
  if not b then return nil, pos end
  if b < 0xfb then return b, pos + 1 end
  if b == 0xfb then return nil, pos + 1 end
  if b == 0xfc then return string.unpack("<I2", p, pos + 1) end
  if b == 0xfd then return string.unpack("<I3", p, pos + 1) end
  return string.unpack("<I8", p, pos + 1)
end

local function lenenc_str(p, pos)
  local n
  n, pos = lenenc_int(p, pos)
  if n == nil then return nil, pos end
  return p:sub(pos, pos + n - 1), pos + n
end

---
-- mysql.receiveGreeting(socket): the server's greeting: true and { proto,
-- version, threadid, salt, capabilities, extcapabilities, charset, status,
-- auth_plugin_name }, or false and the server's error message.
function mysql.receiveGreeting(socket)
  local p, err = read_packet(socket)
  if not p then return false, err end
  local proto = p:byte(1)
  if proto == 0xff and #p >= 3 then return false, (err_message(p)) end
  local ok, r = pcall(function()
    local version, pos = string.unpack("z", p, 2)
    local threadid, salt1
    threadid, salt1, pos = string.unpack("<I4c8", p, pos)
    pos = pos + 1
    local caps
    caps, pos = string.unpack("<I2", p, pos)
    local g = { proto = proto, version = version, threadid = threadid, capabilities = caps,
      salt = salt1 }
    if pos <= #p then
      local charset, status, ext, auth_len
      charset, status, ext, auth_len, pos = string.unpack("<BI2I2B", p, pos)
      g.charset, g.status, g.extcapabilities = charset, status, ext
      pos = pos + 10
      local n = math.max(13, auth_len - 8)
      g.salt = salt1 .. p:sub(pos, pos + n - 1):gsub("%z$", "")
      pos = pos + n
      if ext & (CLIENT_PLUGIN_AUTH >> 16) ~= 0 and pos <= #p then
        g.auth_plugin_name = p:sub(pos):match("^[^%z]*")
      end
    end
    return g
  end)
  if not ok then return false, "Failed to decode the server greeting" end
  server_caps[socket] = r.capabilities | ((r.extcapabilities or 0) << 16)
  return true, r
end

-- mysql_native_password: SHA1(password) XOR SHA1(salt .. SHA1(SHA1(password))).
local function scramble(password, salt)
  if password == nil or password == "" then return "" end
  local h1 = openssl.sha1(password)
  local h3 = openssl.sha1(salt:sub(1, 20) .. openssl.sha1(h1))
  local out = {}
  for i = 1, #h1 do out[i] = string.char(h1:byte(i) ~ h3:byte(i)) end
  return table.concat(out)
end

local function lenenc(s)
  return string.char(#s) .. s
end

---
-- mysql.loginRequest(socket, params, username, password, salt): logs in
-- (params.charset; only "post41" authentication). true and { errorcode =
-- 0 }, or false and the server's error message.
function mysql.loginRequest(socket, params, username, password, salt)
  params = params or {}
  if params.authversion and params.authversion ~= "post41" then
    return false, "Unsupported authentication version"
  end
  local server = server_caps[socket] or 0
  local flags = 0x1 | 0x4 | CLIENT_PROTOCOL_41 | 0x2000 | CLIENT_SECURE_CONNECTION
  local plugin = ""
  if server & CLIENT_PLUGIN_AUTH ~= 0 then
    flags = flags | CLIENT_PLUGIN_AUTH
    plugin = "mysql_native_password\0"
  end
  local attrs = ""
  if server & CLIENT_CONNECT_ATTRS ~= 0 then
    flags = flags | CLIENT_CONNECT_ATTRS
    local kv = lenenc("_client_name") .. lenenc("FeroProbe") .. lenenc("program_name")
      .. lenenc("FeroProbe")
    attrs = lenenc(kv)
  end
  local auth = scramble(password, salt or "")
  local packet = string.pack("<I4I4B", flags, 0x1000000, tonumber(params.charset) or 33)
    .. string.rep("\0", 23) .. (username or "") .. "\0" .. string.char(#auth) .. auth
    .. plugin .. attrs
  local ok, err = send_packet(socket, 1, packet)
  if not ok then return false, err end
  local p, seq = read_packet(socket)
  if not p then return false, seq end
  -- An auth switch request: answer for mysql_native_password only.
  if p:byte(1) == 0xfe and #p > 1 then
    local plugin, pos = string.unpack("z", p, 2)
    if plugin ~= "mysql_native_password" then
      return false, "Unsupported authentication plugin " .. plugin
    end
    local nsalt = p:sub(pos):gsub("%z$", "")
    ok, err = send_packet(socket, seq + 1, scramble(password, nsalt))
    if not ok then return false, err end
    p, seq = read_packet(socket)
    if not p then return false, seq end
  end
  local first = p:byte(1)
  if first == 0x00 then return true, { errorcode = 0 } end
  if first == 0xff then return false, (err_message(p)) end
  return false, "Unexpected reply to the login"
end

---
-- mysql.decodeField(data, pos): one column definition; the position
-- after it and { catalog, database, table, origt_table, name, orig_name,
-- length, type }.
function mysql.decodeField(data, pos)
  local f = {}
  f.catalog, pos = lenenc_str(data, pos)
  f.database, pos = lenenc_str(data, pos)
  f.table, pos = lenenc_str(data, pos)
  f.origt_table, pos = lenenc_str(data, pos)
  f.name, pos = lenenc_str(data, pos)
  f.orig_name, pos = lenenc_str(data, pos)
  pos = pos + 1 -- length of the fixed fields (0x0c)
  f.charset, f.length, f.type, pos = string.unpack("<I2I4B", data, pos)
  pos = pos + 5 -- flags, decimals, filler
  return pos, f
end

-- Packets until an EOF (0xfe, short) packet; false and a message on ERR.
local function read_until_eof(socket)
  local list = {}
  while true do
    local p, err = read_packet(socket)
    if not p then return false, err end
    local b = p:byte(1)
    if b == 0xfe and #p < 9 then return true, list end
    if b == 0xff then return false, (err_message(p)) end
    list[#list + 1] = p
  end
end

---
-- mysql.decodeFieldPackets(data, count) and mysql.decodeDataPackets(data,
-- count): column definitions and rows from consecutive packets in data.
function mysql.decodeFieldPackets(data, count)
  local fields, pos = {}, 1
  local ok, err = pcall(function()
    for _ = 1, count do
      local f
      pos, f = mysql.decodeField(data, pos + 4)
      fields[#fields + 1] = f
    end
  end)
  if not ok then return false, "Failed to decode field packets" end
  return true, fields
end

local function decode_row(p, count)
  local row, pos = {}, 1
  for i = 1, count do
    local v
    v, pos = lenenc_str(p, pos)
    row[i] = v == nil and "NULL" or v
  end
  return row
end

function mysql.decodeDataPackets(data, count)
  local rows, pos = {}, 1
  local ok = pcall(function()
    while pos <= #data do
      local len = string.unpack("<I3", data, pos)
      local p = data:sub(pos + 4, pos + 3 + len)
      pos = pos + 4 + len
      if p:byte(1) == 0xfe and #p < 9 then break end
      rows[#rows + 1] = decode_row(p, count)
    end
  end)
  if not ok then return false, "Failed to decode row data" end
  return true, rows
end

---
-- mysql.decodeQueryResponse(socket): the reply to a query: { header,
-- fields, data }, data being the rows; or false and the error.
function mysql.decodeQueryResponse(socket)
  local p, err = read_packet(socket)
  if not p then return false, err end
  local b = p:byte(1)
  if b == 0xff then return false, (err_message(p)) end
  if b == 0x00 then return true, { header = 0, fields = {}, data = {} } end
  local count = lenenc_int(p, 1)
  local ok, defs = read_until_eof(socket)
  if not ok then return false, defs end
  local fields = {}
  for i, d in ipairs(defs) do
    local s, _, f = pcall(mysql.decodeField, d, 1)
    fields[i] = s and f or {}
  end
  local rows_p
  ok, rows_p = read_until_eof(socket)
  if not ok then return false, rows_p end
  local rows = {}
  for _, rp in ipairs(rows_p) do rows[#rows + 1] = decode_row(rp, count) end
  return true, { header = count, fields = fields, data = rows }
end

---
-- mysql.sqlQuery(socket, query): runs query; true and { cols, rows } (rows
-- are lists of column values, "NULL" for NULL), or false and the error.
function mysql.sqlQuery(socket, query)
  local ok, err = send_packet(socket, 0, "\3" .. tostring(query))
  if not ok then return false, err end
  local r
  ok, r = mysql.decodeQueryResponse(socket)
  if not ok then return false, r end
  return true, { cols = r.fields, rows = r.data }
end

---
-- mysql.formatResultset(rs, options): the result set as text, one row per
-- line and columns aligned; options.noheaders leaves out the names.
function mysql.formatResultset(rs, options)
  options = options or {}
  local t = tab.new()
  if not options.noheaders then
    local names = {}
    for i, c in ipairs(rs.cols or {}) do names[i] = c.name or "" end
    if #names > 0 then tab.addrow(t, table.unpack(names)) end
  end
  for _, row in ipairs(rs.rows or {}) do tab.addrow(t, table.unpack(row)) end
  return tab.dump(t)
end

return mysql
