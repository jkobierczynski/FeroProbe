-- NSE compatibility layer: the `vnc` module, the RFB (VNC) handshake:
-- protocol version, security types, the VeNCrypt and Tight sub-type
-- lists, and ClientInit/ServerInit on a server that asks for no
-- authentication. Written for FeroProbe from nmap's public API
-- documentation and RFC 6143 (RFB 3.8), with the VeNCrypt and Tight
-- extensions as the RFB community documents them; not from nselib.
-- GPL-3.0-or-later, like FeroProbe.
--
-- No logins: VNC Authentication (and any other method that sends a
-- password) is refused before anything is sent, the maintainer's choice
-- for the compatibility layer (logins stay unbuilt). The RFB handshake has
-- no field FeroProbe could mark, so these connections carry no signature
-- beyond the scan itself. Anonymous TLS (security type 18 and the
-- VeNCrypt TLS sub-types) needs anonymous Diffie-Hellman, which
-- FeroProbe's TLS stack does not offer, so handshake_tls fails.
local fero = ...
local nmap = require "nmap"
local stdnse = require "stdnse"

local vnc = {}

-- Security type numbers (the RFB registry).
local SECTYPES = {
  INVALID = 0, NONE = 1, VNCAUTH = 2, RA2 = 5, RA2NE = 6, TIGHT = 16,
  ULTRA = 17, TLS = 18, VENCRYPT = 19, GTK_VNC_SASL = 20, MD5 = 21,
  COLIN_DEAN_XVP = 22, ARD = 30, MAC_OSX_SECTYPE_35 = 35,
}

-- Names as nmap 7.94's vnc-info prints them (compared black-box).
local SECTYPE_NAMES = {
  [1] = "None", [2] = "VNC Authentication", [5] = "RA2", [6] = "RA2ne",
  [16] = "Tight", [17] = "Ultra", [18] = "TLS", [19] = "VeNCrypt",
  [20] = "GTK-VNC SASL", [21] = "MD5 hash authentication",
  [22] = "Colin Dean xvp", [30] = "Apple Remote Desktop",
  [35] = "Mac OS X security type",
}

--- VeNCrypt sub-types.
vnc.VENCRYPT_SUBTYPES = {
  PLAIN = 256, TLSNONE = 257, TLSVNC = 258, TLSPLAIN = 259, X509NONE = 260,
  X509VNC = 261, X509PLAIN = 262, TLSSASL = 263, X509SASL = 264,
}

-- 263 is SASL over anonymous TLS and 264 over server-authenticated TLS
-- (VeNCrypt's TLSSASL and X509SASL); nmap 7.94 prints the two the other
-- way round, which we do not copy.
local VENCRYPT_NAMES = {
  [256] = "Plain", [257] = "None, Anonymous TLS", [258] = "VNC auth, Anonymous TLS",
  [259] = "Plain, Anonymous TLS", [260] = "None, Server-authenticated TLS",
  [261] = "VNC auth, Server-authenticated TLS", [262] = "Plain, Server-authenticated TLS",
  [263] = "SASL, Anonymous TLS", [264] = "SASL, Server-authenticated TLS",
}

local MAX_LIST = 255
local MAX_TIGHT = 64
local MAX_NAME = 64 * 1024

local entry_mt = {
  __tostring = function(t) return string.format("%s (%d)", t.name, t.type) end,
}

local function named(names, t)
  return setmetatable({ name = names[t] or "Unknown security type", type = t }, entry_mt)
end

---------------------------------------------------------------------------
-- VNC.
local VNC = { sectypes = SECTYPES }
VNC.__index = VNC
vnc.VNC = VNC

---
-- VNC:new(host, port): a VNC object for the host and port.
function VNC:new(host, port)
  local o = setmetatable({
    host = host, port = port, socket = nmap.new_socket(), buf = "",
    sectypes = SECTYPES, sectypes_offered = {}, vencrypt = { count = 0, types = {} },
    tight = { tunnels = {}, types = {} }, aten = false,
  }, self)
  return o
end

---
-- VNC:connect(): connects the socket; true, or false and an error.
function VNC:connect()
  self.socket = nmap.new_socket()
  self.socket:set_timeout(tonumber(stdnse.get_script_args("vnc.timeout")) or 5000)
  self.buf = ""
  local ok, err = self.socket:connect(self.host, self.port, "tcp")
  if not ok then return false, err end
  return true
end

---
-- VNC:disconnect(): closes the socket.
function VNC:disconnect()
  if self.socket then self.socket:close() end
  self.buf = ""
  return true
end

local function read(self, n)
  while #self.buf < n do
    local ok, data = self.socket:receive_bytes(n - #self.buf)
    if not ok then return nil, data end
    self.buf = self.buf .. data
  end
  local out = self.buf:sub(1, n)
  self.buf = self.buf:sub(n + 1)
  return out
end

local function read_u32(self)
  local d, err = read(self, 4)
  if not d then return nil, err end
  return (string.unpack(">I4", d))
end

-- A reason string (u32 length, text) after a failure.
local function reason(self)
  local len = read_u32(self)
  if not len or len > MAX_NAME then return "Server closed the connection" end
  local text = read(self, len)
  return text or "Server closed the connection"
end

---
-- VNC:handshake(): reads the server's protocol version, answers with the
-- version to use (3.8 at most) and reads the security types it offers;
-- true, or false and an error.
function VNC:handshake()
  local banner, err = read(self, 12)
  if not banner then return false, err end
  local major, minor = banner:match("^RFB (%d%d%d)%.(%d%d%d)\n$")
  if not major then return false, "Not a VNC server" end
  major, minor = tonumber(major), tonumber(minor)
  self.protocol_version = string.format("%d.%d", major, minor)
  -- 3.3 and 3.7 as the server says; anything newer (Apple's 3.889) as
  -- 3.8, the newest this module speaks.
  local use = 8
  if major == 3 and minor < 7 then
    use = 3
  elseif major == 3 and minor == 7 then
    use = 7
  end
  self.version = use == 8 and 3.8 or (use == 7 and 3.7 or 3.3)
  local ok
  ok, err = self.socket:send(string.format("RFB 003.%03d\n", use))
  if not ok then return false, err end
  self.sectypes_offered = {}
  if use == 3 then
    local t = read_u32(self)
    if not t then return false, "Server closed the connection" end
    if t == 0 then return false, reason(self) end
    self.sectypes_offered[1] = t
    return true
  end
  local c = read(self, 1)
  if not c then return false, "Server closed the connection" end
  local count = c:byte()
  if count == 0 then return false, reason(self) end
  local list = read(self, count)
  if not list then return false, "Server closed the connection" end
  for i = 1, #list do self.sectypes_offered[i] = list:byte(i) end
  return true
end

---
-- VNC:getProtocolVersion(): the server's protocol version, as "3.8".
function VNC:getProtocolVersion()
  return self.protocol_version
end

---
-- VNC:getSecTypesAsTable(): the offered security types, in the server's
-- order, each { name, type } (shown as "name (type)").
function VNC:getSecTypesAsTable()
  local out = {}
  for i, t in ipairs(self.sectypes_offered) do
    if i > MAX_LIST then break end
    out[#out + 1] = named(SECTYPE_NAMES, t)
  end
  return out
end

---
-- VNC:supportsSecType(sectype): whether the server offered it.
function VNC:supportsSecType(sectype)
  for _, t in ipairs(self.sectypes_offered) do
    if t == sectype then return true end
  end
  return false
end

---
-- VNC:sendSecType(sectype): chooses a security type (protocol 3.7 and
-- later; with 3.3 the server has chosen); true, or false and an error.
function VNC:sendSecType(sectype)
  if self.version == 3.3 then return true end
  return self.socket:send(string.char(sectype & 0xff))
end

---
-- VNC:handshake_vencrypt(): after choosing VeNCrypt (19), agrees on
-- VeNCrypt 0.2 and reads its sub-types into self.vencrypt = { version,
-- count, types }; true, or false and an error.
function VNC:handshake_vencrypt()
  local v, err = read(self, 2)
  if not v then return false, err end
  local major, minor = v:byte(1), v:byte(2)
  self.vencrypt.version = string.format("%d.%d", major, minor)
  if major ~= 0 or minor < 2 then
    return false, string.format("Unknown VeNCrypt version: %d.%d", major, minor)
  end
  local ok
  ok, err = self.socket:send("\0\2")
  if not ok then return false, err end
  local ack = read(self, 1)
  if not ack then return false, "Server closed the connection" end
  if ack ~= "\0" then return false, "Server refused VeNCrypt 0.2" end
  local c = read(self, 1)
  if not c then return false, "Server closed the connection" end
  local count = c:byte()
  local data = read(self, 4 * count)
  if not data then return false, "Server closed the connection" end
  local types = {}
  for i = 0, count - 1 do types[#types + 1] = (string.unpack(">I4", data, 1 + 4 * i)) end
  self.vencrypt.count, self.vencrypt.types = count, types
  return true
end

---
-- VNC:getVencryptTypesAsTable(): the VeNCrypt sub-types, each { name,
-- type } (shown as "name (type)").
function VNC:getVencryptTypesAsTable()
  local out = {}
  for _, t in ipairs(self.vencrypt.types) do out[#out + 1] = named(VENCRYPT_NAMES, t) end
  return out
end

local function capabilities(self, count)
  local list = {}
  if count > MAX_TIGHT then return nil, "Too many Tight capabilities" end
  local data, err = read(self, 16 * count)
  if not data then return nil, err end
  for i = 0, count - 1 do
    local code, vendor, signature = string.unpack(">I4c4c8", data, 1 + 16 * i)
    list[#list + 1] = { code = code, vendor = vendor, signature = signature }
  end
  return list
end

---
-- VNC:handshake_tight(): after choosing Tight (16), reads its tunnel
-- list (answering with no tunnel) and its authentication list into
-- self.tight = { tunnels, types }, each { code, vendor, signature };
-- true, or false and an error.
function VNC:handshake_tight()
  local n, err = read_u32(self)
  if not n then return false, err end
  local tunnels
  tunnels, err = capabilities(self, n)
  if not tunnels then return false, err end
  self.tight.tunnels = tunnels
  if n > 0 then
    local ok
    ok, err = self.socket:send(string.pack(">I4", 0))
    if not ok then return false, err end
  end
  n, err = read_u32(self)
  if not n then return false, err end
  local types
  types, err = capabilities(self, n)
  if not types then return false, err end
  self.tight.types = types
  return true
end

---
-- VNC:handshake_tls(): anonymous TLS (security type 18); FeroProbe's TLS
-- has no anonymous Diffie-Hellman, so this returns false and an error.
function VNC:handshake_tls()
  return false, "Anonymous TLS is not available in FeroProbe"
end

---
-- VNC:login_none(): after choosing None (1), reads the security result
-- (protocol 3.8); true, or false and an error.
function VNC:login_none()
  if self.version ~= 3.8 then return true end
  local r, err = read_u32(self)
  if not r then return false, err end
  if r ~= 0 then return false, reason(self) end
  return true
end

local NO_LOGIN = "VNC logins are not supported by FeroProbe (only servers that ask for no authentication)"

---
-- VNC:login(username, password, authtype): on a server that offers None
-- (security type 1), chooses it; true, or false and an error. FeroProbe
-- makes no logins: any other method is refused before a password is sent.
function VNC:login(username, password, authtype)
  if (authtype == nil or authtype == SECTYPES.NONE) and self:supportsSecType(SECTYPES.NONE) then
    local ok, err = self:sendSecType(SECTYPES.NONE)
    if not ok then return false, err end
    return self:login_none()
  end
  return false, NO_LOGIN
end

---
-- VNC:login_vncauth(username, password): VNC Authentication, which
-- FeroProbe does not make; false and an error.
function VNC:login_vncauth(username, password)
  return false, NO_LOGIN
end

---
-- VNC:createVNCDESKey and VNC:encryptVNCDES belong to VNC
-- Authentication, which FeroProbe does not make; they raise an error.
function VNC:createVNCDESKey()
  error("vnc.VNC:createVNCDESKey is not available in FeroProbe (no VNC logins)", 2)
end
function VNC:encryptVNCDES()
  error("vnc.VNC:encryptVNCDES is not available in FeroProbe (no VNC logins)", 2)
end

---
-- VNC:client_init(shared): sends ClientInit and reads ServerInit; true
-- and { width, height, bpp, depth, bigendian, truecolor, red_max,
-- green_max, blue_max, red_shift, green_shift, blue_shift, name }, or
-- false and an error.
function VNC:client_init(shared)
  local ok, err = self.socket:send(shared and "\1" or "\0")
  if not ok then return false, err end
  local head
  head, err = read(self, 24)
  if not head then return false, err end
  local s = {}
  local len
  s.width, s.height, s.bpp, s.depth, s.bigendian, s.truecolor, s.red_max, s.green_max,
    s.blue_max, s.red_shift, s.green_shift, s.blue_shift, len =
    string.unpack(">I2I2BBBBI2I2I2BBBxxxI4", head)
  s.bigendian, s.truecolor = s.bigendian ~= 0, s.truecolor ~= 0
  if len > MAX_NAME then return false, "Desktop name too long" end
  s.name, err = read(self, len)
  if not s.name then return false, err end
  return true, s
end

return vnc
