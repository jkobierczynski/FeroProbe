-- NSE compatibility layer: the `afp` module, the Apple Filing Protocol
-- over DSI (TCP 548). Written for FeroProbe from nmap's public API
-- documentation and Apple's AFP Reference (DSI, FPGetSrvrInfo,
-- FPLogin, FPGetSrvrParms, FPOpenVol, FPEnumerateExt2,
-- FPGetFileDirParms); not from nselib. GPL-3.0-or-later, like FeroProbe.
--
-- The first DSI request on every connection carries request ID 0x4650,
-- "FP" (IDS rule 9100042); later ones count up from there. Only guest
-- logins ("No User Authent"): a login with a user name or password fails
-- before anything is sent, as logins stay unbuilt in the compatibility
-- layer (maintainer's choice for ldap, 2026-11-26). Paths are looked up
-- inside a share only: a ".." element fails, so nothing outside a share
-- is listed.
local fero = ...
local nmap = require "nmap"
local stdnse = require "stdnse"

local afp = {}

local FIRST_REQUEST_ID = 0x4650
local MAX_REPLY = 1024 * 1024
local MAX_ENTRIES = 10000
local AFP_EPOCH = 946684800 -- 2000-01-01 00:00:00 UTC
local AFP_VERSION = "AFP3.1"
local GUEST_UAM = "No User Authent"
local NOT_SUPPORTED = "AFP logins are not supported by FeroProbe (guest only)"

local DSI = { CloseSession = 1, Command = 2, GetStatus = 3, OpenSession = 4 }
local FP = {
  CloseVol = 2, GetSrvrParms = 16, Login = 18, Logout = 20, OpenVol = 24,
  GetFileDirParms = 34, EnumerateExt2 = 68,
}

afp.ERROR = {
  ObjectNotFound = -5018, AccessDenied = -5000, ParamErr = -5019,
}

local ROOT_DID = 2
local DIR_TYPE = 0x80

---------------------------------------------------------------------------
-- DSI connection.

local Conn = {}
Conn.__index = Conn

local function new_conn(socket)
  return setmetatable({ socket = socket, buf = "", id = FIRST_REQUEST_ID }, Conn)
end

function Conn:read(n)
  while #self.buf < n do
    local ok, data = self.socket:receive_bytes(n - #self.buf)
    if not ok then return nil, data end
    self.buf = self.buf .. data
  end
  local out = self.buf:sub(1, n)
  self.buf = self.buf:sub(n + 1)
  return out
end

-- Sends one DSI request and reads its reply: the reply's data and its
-- error code (0 for success), or nil and an error.
function Conn:request(command, payload)
  local id = self.id
  self.id = (self.id + 1) & 0xFFFF
  payload = payload or ""
  local ok, err = self.socket:send(string.pack(">BBI2I4I4I4", 0, command, id, 0, #payload, 0) .. payload)
  if not ok then return nil, err end
  while true do
    local head
    head, err = self:read(16)
    if not head then return nil, err end
    local flags, cmd, rid, code, len = string.unpack(">BBI2i4I4", head)
    if len > MAX_REPLY then return nil, "AFP reply too large" end
    local data
    data, err = self:read(len)
    if not data then return nil, err end
    -- A request from the server (an attention or a tickle) is skipped.
    if flags == 1 and rid == id and cmd == command then return data, code end
  end
end

local function pstring(s, pos)
  local n = s:byte(pos)
  if not n or #s < pos + n then return nil end
  return s:sub(pos + 1, pos + n), pos + 1 + n
end

local function afp_error(code)
  return ("AFP error %d"):format(code)
end

---------------------------------------------------------------------------
-- Proto: the server information.

afp.Proto = {}
afp.Proto.__index = afp.Proto

---
-- Proto:new(o): o.socket is a connected socket.
function afp.Proto:new(o)
  o = o or {}
  return setmetatable(o, self)
end

local FLAG_NAMES = {
  { "CopyFile", 0x0001 }, { "ChangeablePasswords", 0x0002 }, { "NoPasswordSaving", 0x0004 },
  { "ServerMessages", 0x0008 }, { "ServerSignature", 0x0010 }, { "TCPoverIP", 0x0020 },
  { "ServerNotifications", 0x0040 }, { "Reconnect", 0x0080 }, { "OpenDirectory", 0x0100 },
  { "UTF8ServerName", 0x0200 }, { "UUIDs", 0x0400 }, { "ExtendedSleep", 0x0800 },
  { "SuperClient", 0x8000 },
}

local function address(entry)
  local tag = entry:byte(1)
  local body = entry:sub(2)
  if (tag == 1 or tag == 2) and #body >= 4 then
    local ip = ("%d.%d.%d.%d"):format(body:byte(1, 4))
    if tag == 2 and #body >= 6 then return ("%s:%d"):format(ip, string.unpack(">I2", body, 5)) end
    return ip
  elseif tag == 3 and #body >= 4 then
    return ("DDP %d.%d socket %d"):format(string.unpack(">I2", body, 1), body:byte(3), body:byte(4))
  elseif tag == 4 or tag == 5 then
    return body
  elseif (tag == 6 or tag == 7) and #body >= 16 then
    local words = {}
    for i = 1, 16, 2 do words[#words + 1] = ("%x"):format(string.unpack(">I2", body, i)) end
    local ip = table.concat(words, ":")
    if tag == 7 and #body >= 18 then return ("[%s]:%d"):format(ip, string.unpack(">I2", body, 17)) end
    return ip
  end
  return ("tag %d: %s"):format(tag or 0, stdnse.tohex(body))
end

local function count_strings(s, pos)
  local out = {}
  local n = s:byte(pos)
  if not n then return out end
  pos = pos + 1
  for _ = 1, n do
    local v
    v, pos = pstring(s, pos)
    if not v then break end
    out[#out + 1] = v
  end
  return out
end

-- The FPGetSrvrInfo reply as a table, or nil when malformed.
local function parse_server_info(p)
  if #p < 11 then return nil end
  local machine_off, versions_off, uams_off, _, raw = string.unpack(">I2I2I2I2I2", p)
  local r = { flags = { raw = raw } }
  for _, f in ipairs(FLAG_NAMES) do r.flags[f[1]] = (raw & f[2]) ~= 0 end
  local pos
  r.server_name, pos = pstring(p, 11)
  if not r.server_name then return nil end
  if pos % 2 == 0 then pos = pos + 1 end -- the next field starts on an even offset
  r.machine_type = pstring(p, machine_off + 1) or ""
  r.afp_versions = count_strings(p, versions_off + 1)
  r.uams = count_strings(p, uams_off + 1)
  local sig_off, addr_off, dir_off, utf8_off = 0, 0, 0, 0
  if #p >= pos + 7 then sig_off, addr_off, dir_off, utf8_off = string.unpack(">I2I2I2I2", p, pos) end
  if sig_off > 0 and #p >= sig_off + 16 then r.server_signature = p:sub(sig_off + 1, sig_off + 16) end
  r.network_addresses = {}
  if addr_off > 0 and #p > addr_off then
    local n = p:byte(addr_off + 1)
    local q = addr_off + 2
    for _ = 1, n do
      local len = p:byte(q)
      if not len or len < 2 or #p < q + len - 1 then break end
      r.network_addresses[#r.network_addresses + 1] = address(p:sub(q + 1, q + len - 1))
      q = q + len
    end
  end
  r.network_addresses_count = #r.network_addresses
  r.directory_names = dir_off > 0 and count_strings(p, dir_off + 1) or {}
  r.directory_names_count = #r.directory_names
  if utf8_off > 0 and #p >= utf8_off + 2 then
    local n = string.unpack(">I2", p, utf8_off + 1)
    r.utf8_server_name = p:sub(utf8_off + 3, utf8_off + 2 + n)
  end
  return r
end

---
-- Proto:fp_get_server_info([socket]): a DSIGetStatus on the socket; a
-- table whose `result` holds flags (raw and by name), server_name,
-- machine_type, afp_versions, uams, server_signature, network_addresses
-- (and _count), directory_names (and _count) and utf8_server_name.
function afp.Proto:fp_get_server_info(socket)
  local conn = new_conn(socket or self.socket)
  local data, code = conn:request(DSI.GetStatus)
  if not data then return { status = false, result = nil, error = code } end
  if code ~= 0 then return { status = false, result = nil, error = afp_error(code) } end
  local r = parse_server_info(data)
  if not r then return { status = false, result = nil, error = "Malformed AFP server information" } end
  return { status = true, result = r }
end

---------------------------------------------------------------------------
-- Helper.

afp.Helper = {}
afp.Helper.__index = afp.Helper

---
-- Helper:new(): a helper; OpenSession connects it.
function afp.Helper:new()
  return setmetatable({}, self)
end

---
-- Helper:OpenSession(host, port): connects and opens a DSI session;
-- true, or false and an error.
function afp.Helper:OpenSession(host, port)
  self.socket = nmap.new_socket()
  self.socket:set_timeout(5000)
  local ok, err = self.socket:connect(host, port, "tcp")
  if not ok then return false, err end
  self.conn = new_conn(self.socket)
  -- Option: attention quantum 1024.
  local data, code = self.conn:request(DSI.OpenSession, "\x01\x04\x00\x00\x04\x00")
  if not data then return false, code end
  if code ~= 0 then return false, afp_error(code) end
  return true
end

function afp.Helper:command(payload)
  if not self.conn then return nil, "No AFP session" end
  return self.conn:request(DSI.Command, payload)
end

---
-- Helper:Login([username, password]): a guest login ("No User
-- Authent"); with a user name or password it fails before sending.
function afp.Helper:Login(username, password)
  if username ~= nil or password ~= nil then return false, NOT_SUPPORTED end
  local data, code = self:command(string.char(FP.Login) .. string.pack(">s1s1", AFP_VERSION, GUEST_UAM))
  if not data then return false, code end
  if code ~= 0 then return false, afp_error(code) end
  self.logged_in = true
  return true
end

---
-- Helper:Logout(): true, or false and an error.
function afp.Helper:Logout()
  local data, code = self:command(string.char(FP.Logout, 0))
  if not data then return false, code end
  if code ~= 0 then return false, afp_error(code) end
  self.logged_in = false
  return true
end

---
-- Helper:CloseSession(): closes the DSI session and the connection.
function afp.Helper:CloseSession()
  if self.socket then
    if self.conn then
      local s = self.conn
      s.socket:send(string.pack(">BBI2I4I4I4", 0, DSI.CloseSession, s.id, 0, 0, 0))
    end
    self.socket:close()
  end
  self.socket, self.conn = nil, nil
  return true
end

---
-- Helper:ListShares(): true and the volume names, or false and an error.
function afp.Helper:ListShares()
  local data, code = self:command(string.char(FP.GetSrvrParms, 0))
  if not data then return false, code end
  if code ~= 0 then return false, afp_error(code) end
  if #data < 5 then return false, "Malformed AFP server parameters" end
  local shares = {}
  local pos = 6
  for _ = 1, data:byte(5) do
    local name
    name, pos = pstring(data, pos + 1) -- skip the volume's flags byte
    if not name then break end
    shares[#shares + 1] = name
  end
  return true, shares
end

local function open_vol(self, name)
  if #name > 255 then return nil, "AFP volume name too long" end
  local data, code = self:command(string.char(FP.OpenVol, 0) .. string.pack(">I2s1", 0x0020, name))
  if not data then return nil, code end
  if code ~= 0 then return nil, afp_error(code) end
  if #data < 4 then return nil, "Malformed AFP volume reply" end
  return (string.unpack(">I2", data, 3))
end

local function close_vol(self, vol)
  self:command(string.char(FP.CloseVol, 0) .. string.pack(">I2", vol))
end

local RIGHTS = { { "Search", 0x01 }, { "Read", 0x02 }, { "Write", 0x04 } }

local function rights_of(byte)
  local out = {}
  for _, r in ipairs(RIGHTS) do
    if byte & r[2] ~= 0 then out[#out + 1] = r[1] end
  end
  return table.concat(out, ",")
end

---
-- Helper:GetSharePermissions(name): true and the share's access rights
-- as lines ("Owner: Search,Read,Write", Group, Everyone, User and the
-- Options), or false and an error.
function afp.Helper:GetSharePermissions(name)
  local vol, err = open_vol(self, name)
  if not vol then return false, err end
  -- The root directory's access rights (directory bitmap bit 12).
  local data, code = self:command(string.char(FP.GetFileDirParms, 0)
    .. string.pack(">I2I4I2I2", vol, ROOT_DID, 0, 0x1000) .. "\x02\x00")
  close_vol(self, vol)
  if not data then return false, code end
  if code ~= 0 then return false, afp_error(code) end
  if #data < 10 then return false, "Malformed AFP directory reply" end
  local rights = string.unpack(">I4", data, 7)
  local out = {
    "Owner: " .. rights_of(rights & 0xFF),
    "Group: " .. rights_of((rights >> 8) & 0xFF),
    "Everyone: " .. rights_of((rights >> 16) & 0xFF),
    "User: " .. rights_of((rights >> 24) & 0xFF),
  }
  if rights & 0x80000000 ~= 0 then out[#out + 1] = "Options: IsOwner" end
  return true, out
end

local function mode_string(mode, isdir)
  local chars = { isdir and "d" or ((mode & 0xF000) == 0xA000 and "l" or "-") }
  local bits = { 0x100, 0x80, 0x40, 0x20, 0x10, 0x8, 0x4, 0x2, 0x1 }
  local letters = { "r", "w", "x", "r", "w", "x", "r", "w", "x" }
  for i, b in ipairs(bits) do chars[#chars + 1] = (mode & b ~= 0) and letters[i] or "-" end
  return table.concat(chars)
end

local FILE_BITMAP = 0x8000 | 0x0800 | 0x0100 | 0x0040 | 0x0008 | 0x0004 | 0x0002
local DIR_BITMAP = 0x8000 | 0x0100 | 0x0040 | 0x0008 | 0x0004 | 0x0002

-- One FPEnumerateExt2 entry's parameters (from after the flag and pad).
local function parse_entry(p, isdir)
  local pos = 1
  if #p < 18 then return nil end
  local parent, create, modify, name_off, node = string.unpack(">I4i4i4I2I4", p, pos)
  pos = pos + 18
  local fsize = 0
  if not isdir then
    if #p < pos + 7 then return nil end
    fsize = string.unpack(">I8", p, pos)
    pos = pos + 8
  end
  if #p < pos + 15 then return nil end
  local uid, gid, mode = string.unpack(">I4I4I4", p, pos)
  local name = pstring(p, name_off + 1)
  if not name then return nil end
  return {
    name = name, type = isdir and DIR_TYPE or 0, id = node, parent = parent,
    fsize = fsize, uid = uid, gid = gid, privs = mode_string(mode, isdir),
    create = stdnse.format_timestamp(AFP_EPOCH + create),
    modify = stdnse.format_timestamp(AFP_EPOCH + modify),
  }
end

-- The entries of directory did: a list, or nil and an error.
local function enumerate(self, vol, did)
  local out = {}
  local start = 1
  while #out < MAX_ENTRIES do
    local data, code = self:command(string.char(FP.EnumerateExt2, 0)
      .. string.pack(">I2I4I2I2I2I4I4", vol, did, FILE_BITMAP, DIR_BITMAP, 1000, start, 300000) .. "\x02\x00")
    if not data then return nil, code end
    if code == afp.ERROR.ObjectNotFound then break end
    if code ~= 0 then return nil, afp_error(code) end
    if #data < 6 then return nil, "Malformed AFP directory listing" end
    local count = string.unpack(">I2", data, 5)
    local pos = 7
    for _ = 1, count do
      if #data < pos + 1 then return nil, "Malformed AFP directory listing" end
      local len = string.unpack(">I2", data, pos)
      if len < 4 or #data < pos + len - 1 then return nil, "Malformed AFP directory listing" end
      local isdir = data:byte(pos + 2) & 0x80 ~= 0
      local entry = parse_entry(data:sub(pos + 4, pos + len - 1), isdir)
      if not entry then return nil, "Malformed AFP directory entry" end
      out[#out + 1] = entry
      pos = pos + len
    end
    if count == 0 then break end
    start = start + count
  end
  return out
end

local function walk(self, vol, did, depth, max_depth)
  local entries, err = enumerate(self, vol, did)
  if not entries then return nil, err end
  local out = {}
  for _, e in ipairs(entries) do
    out[#out + 1] = e
    if e.type == DIR_TYPE and depth < max_depth then
      local sub = walk(self, vol, e.id, depth + 1, max_depth)
      if sub then out[#out + 1] = sub end
    end
  end
  return out
end

---
-- Helper:Dir(path[, options]): true and the listing of path ("Share" or
-- "Share/dir/sub"), or false and an error. The listing is a table whose
-- first element lists the entries (name, type 0x80 for a directory, id,
-- privs, uid, gid, fsize, create, modify); a directory's own listing
-- follows it as a table while options.max_depth (default 1) allows.
function afp.Helper:Dir(path, options)
  options = options or {}
  local max_depth = math.max(1, math.min(tonumber(options.max_depth) or 1, 8))
  local parts = {}
  for p in tostring(path):gmatch("[^/]+") do parts[#parts + 1] = p end
  if #parts == 0 then return false, "No AFP share given" end
  for _, p in ipairs(parts) do
    if p == ".." or p == "." then
      return false, "Paths outside a share are not supported by FeroProbe"
    end
  end
  local vol, err = open_vol(self, parts[1])
  if not vol then return false, err end
  local did = ROOT_DID
  for i = 2, #parts do
    local entries
    entries, err = enumerate(self, vol, did)
    if not entries then close_vol(self, vol); return false, err end
    local found
    for _, e in ipairs(entries) do
      if e.name == parts[i] and e.type == DIR_TYPE then found = e.id end
    end
    if not found then close_vol(self, vol); return false, ("No such directory: %s"):format(parts[i]) end
    did = found
  end
  local listing
  listing, err = walk(self, vol, did, 1, max_depth)
  close_vol(self, vol)
  if not listing then return false, err end
  return true, { listing }
end

return afp
