-- NSE compatibility layer: the `ajp` module, requests over the Apache
-- JServ Protocol 1.3 (AJP13). Written for FeroProbe from nmap's public API
-- documentation and the AJP13 protocol description of Apache Tomcat and
-- mod_proxy_ajp; not from nselib. GPL-3.0-or-later, like FeroProbe.
--
-- Every request carries FeroProbe's User-Agent unless the script gives
-- its own (IDS rule 9100041). No logins: a request with a user name or
-- password, an Authorization header or the `secret` or `remote_user`
-- attribute fails before anything is sent, as logins stay unbuilt in the
-- compatibility layer (maintainer's choice for ldap, 2026-11-26).
local fero = ...
local nmap = require "nmap"
local stdnse = require "stdnse"
local http = require "http"

local ajp = {}

local MAX_BODY = 16 * 1024 * 1024
local MAX_CHUNK = 8186 -- body bytes in one packet to the container
local NOT_SUPPORTED = "AJP logins are not supported by FeroProbe"

local METHODS = {
  OPTIONS = 1, GET = 2, HEAD = 3, POST = 4, PUT = 5, DELETE = 6, TRACE = 7,
  PROPFIND = 8, PROPPATCH = 9, MKCOL = 10, COPY = 11, MOVE = 12, LOCK = 13,
  UNLOCK = 14, ACL = 15, REPORT = 16, ["VERSION-CONTROL"] = 17, CHECKIN = 18,
  CHECKOUT = 19, UNCHECKOUT = 20, SEARCH = 21, MKWORKSPACE = 22, UPDATE = 23,
  LABEL = 24, MERGE = 25, ["BASELINE-CONTROL"] = 26, MKACTIVITY = 27,
}

local REQUEST_HEADERS = {
  ["accept"] = 0xA001, ["accept-charset"] = 0xA002, ["accept-encoding"] = 0xA003,
  ["accept-language"] = 0xA004, ["authorization"] = 0xA005, ["connection"] = 0xA006,
  ["content-type"] = 0xA007, ["content-length"] = 0xA008, ["cookie"] = 0xA009,
  ["cookie2"] = 0xA00A, ["host"] = 0xA00B, ["pragma"] = 0xA00C, ["referer"] = 0xA00D,
  ["user-agent"] = 0xA00E,
}

local RESPONSE_HEADERS = {
  [0xA001] = "Content-Type", [0xA002] = "Content-Language", [0xA003] = "Content-Length",
  [0xA004] = "Date", [0xA005] = "Last-Modified", [0xA006] = "Location",
  [0xA007] = "Set-Cookie", [0xA008] = "Set-Cookie2", [0xA009] = "Servlet-Engine",
  [0xA00A] = "Status", [0xA00B] = "WWW-Authenticate",
}

local ATTRIBUTES = {
  context = 0x01, servlet_path = 0x02, remote_user = 0x03, auth_type = 0x04,
  query_string = 0x05, route = 0x06, ssl_cert = 0x07, ssl_cipher = 0x08,
  ssl_session = 0x09, ssl_key_size = 0x0B, secret = 0x0C, stored_method = 0x0D,
}

local function str(s)
  if s == nil then return "\xff\xff" end
  s = tostring(s)
  if #s >= 0xFFFF then error("AJP request too large", 0) end
  return string.pack(">s2", s) .. "\0"
end

local function to_container(payload)
  return "\x12\x34" .. string.pack(">I2", #payload) .. payload
end

---------------------------------------------------------------------------
-- Helper.

ajp.Helper = {}
ajp.Helper.__index = ajp.Helper

---
-- Helper:new(host, port, opt): a helper for the AJP port; opt.timeout in
-- milliseconds (default 5000).
function ajp.Helper:new(host, port, opt)
  local o = { host = host, port = port, opt = opt or {}, buf = "" }
  return setmetatable(o, self)
end

---
-- Helper:connect([socket]): true, or false and an error.
function ajp.Helper:connect(socket)
  self.socket = socket or nmap.new_socket()
  self.buf = ""
  self.socket:set_timeout((self.opt.timeout or 5000))
  local ok, err = self.socket:connect(self.host, self.port, "tcp")
  if not ok then return false, err end
  return true
end

---
-- Helper:close(): disconnects.
function ajp.Helper:close()
  if self.socket then self.socket:close() end
  self.socket = nil
  return true
end

function ajp.Helper:read(n)
  while #self.buf < n do
    local ok, data = self.socket:receive_bytes(n - #self.buf)
    if not ok then return nil, data end
    self.buf = self.buf .. data
  end
  local out = self.buf:sub(1, n)
  self.buf = self.buf:sub(n + 1)
  return out
end

-- The next packet from the container: its payload, or nil and an error.
function ajp.Helper:packet()
  local head, err = self:read(4)
  if not head then return nil, err end
  if head:sub(1, 2) ~= "AB" then return nil, "Not an AJP reply" end
  local len = string.unpack(">I2", head, 3)
  if len < 1 then return nil, "Empty AJP packet" end
  return self:read(len)
end

local function reply_string(p, pos)
  if #p < pos + 1 then return nil end
  local len = string.unpack(">I2", p, pos)
  if len == 0xFFFF then return false, pos + 2 end
  if #p < pos + 2 + len then return nil end
  return p:sub(pos + 2, pos + 1 + len), pos + 3 + len
end

local function parse_headers(p)
  if #p < 3 then return nil end
  local status = string.unpack(">I2", p, 2)
  local msg, pos = reply_string(p, 4)
  if msg == nil or #p < pos + 1 then return nil end
  local count = string.unpack(">I2", p, pos)
  pos = pos + 2
  local resp = {
    status = status,
    status_line = ("AJP/1.3 %d %s"):format(status, msg or ""),
    headers = {},
    rawheaders = {},
  }
  for _ = 1, count do
    if #p < pos + 1 then return nil end
    local code = string.unpack(">I2", p, pos)
    local name
    if code >= 0xA000 then
      name = RESPONSE_HEADERS[code] or ("0x%04X"):format(code)
      pos = pos + 2
    else
      name, pos = reply_string(p, pos)
      if not name then return nil end
    end
    local value
    value, pos = reply_string(p, pos)
    if value == nil then return nil end
    value = value or ""
    local key = name:lower()
    if resp.headers[key] then
      resp.headers[key] = resp.headers[key] .. ", " .. value
    else
      resp.headers[key] = value
    end
    resp.rawheaders[#resp.rawheaders + 1] = name .. ": " .. value
  end
  return resp
end

-- A request option, else the helper's own (Helper:new's opt).
local function option(self, options, name)
  if type(options) == "table" and options[name] ~= nil then return options[name] end
  return self.opt[name]
end

local function has_login(auth, headers, attributes)
  if type(auth) == "table" and (auth.username ~= nil or auth.password ~= nil) then return true end
  for k in pairs(headers or {}) do
    if tostring(k):lower() == "authorization" then return true end
  end
  for k in pairs(attributes or {}) do
    local name = tostring(k):lower()
    if name == "secret" or name == "remote_user" then return true end
  end
  return false
end

local function sorted_keys(t)
  local keys = {}
  for k in pairs(t or {}) do keys[#keys + 1] = k end
  table.sort(keys, function(a, b) return tostring(a) < tostring(b) end)
  return keys
end

---
-- Helper:request(method, url, headers, attributes, options[, body]): true
-- and the response table (status, status_line, headers with lower-case
-- names, rawheaders, body), or false and an error.
function ajp.Helper:request(method, url, headers, attributes, options, body)
  method = tostring(method or "GET"):upper()
  local code = METHODS[method]
  if not code then return false, ("Unsupported AJP method: %s"):format(method) end
  if has_login(option(self, options, "auth"), headers, attributes) then return false, NOT_SUPPORTED end
  if not self.socket then return false, "Not connected" end
  self.socket:set_timeout(option(self, options, "timeout") or 5000)
  url = tostring(url or "/")
  local path, query = url:match("^([^?]*)%?(.*)$")
  path = path or url
  if path == "" then path = "/" end

  -- Headers: Host, Connection and the User-Agent signature, replaced by
  -- the script's own of the same name; then the script's others.
  local given = {}
  for k, v in pairs(headers or {}) do given[tostring(k):lower()] = { tostring(k), tostring(v) } end
  if body ~= nil then
    body = tostring(body)
    if not given["content-length"] then given["content-length"] = { "Content-Length", tostring(#body) } end
  end
  local list = {}
  for _, def in ipairs({ { "host", stdnse.get_hostname(self.host) }, { "connection", "keep-alive" },
                         { "user-agent", http.USER_AGENT } }) do
    local g = given[def[1]]
    list[#list + 1] = g and { def[1], g[2] } or def
    given[def[1]] = nil
  end
  for _, k in ipairs(sorted_keys(given)) do list[#list + 1] = { given[k][1], given[k][2] } end

  local function build()
    local parts = {
      "\x02", string.char(code), str("HTTP/1.1"), str(path), str(self.host.ip), str(nil),
      str(self.host.ip), string.pack(">I2", self.port.number), "\0", string.pack(">I2", #list),
    }
    for _, h in ipairs(list) do
      local hc = REQUEST_HEADERS[h[1]:lower()]
      parts[#parts + 1] = (hc and string.pack(">I2", hc) or str(h[1])) .. str(h[2])
    end
    local attrs = {}
    for k, v in pairs(attributes or {}) do attrs[tostring(k)] = tostring(v) end
    if query and not attrs.query_string then attrs.query_string = query end
    for _, k in ipairs(sorted_keys(attrs)) do
      local ac = ATTRIBUTES[k]
      if ac == 0x0B then
        local n = math.tointeger(tonumber(attrs[k]))
        if not n or n < 0 or n > 0xFFFF then error("Invalid AJP ssl_key_size", 0) end
        parts[#parts + 1] = "\x0b" .. string.pack(">I2", n)
      elseif ac then
        parts[#parts + 1] = string.char(ac) .. str(attrs[k])
      else
        parts[#parts + 1] = "\x0a" .. str(k) .. str(attrs[k])
      end
    end
    parts[#parts + 1] = "\xff"
    local payload = table.concat(parts)
    if #payload > 0xFFFF - 4 then error("AJP request too large", 0) end
    return to_container(payload)
  end
  local built, packet = pcall(build)
  if not built then return false, tostring(packet) end

  local sent = 0
  local function next_chunk(want)
    local n = math.min(want or MAX_CHUNK, MAX_CHUNK, #body - sent)
    local chunk = body:sub(sent + 1, sent + n)
    sent = sent + n
    if #chunk == 0 then return to_container("") end
    return to_container(string.pack(">I2", #chunk) .. chunk)
  end
  if body ~= nil and #body > 0 then packet = packet .. next_chunk() end
  local ok, err = self.socket:send(packet)
  if not ok then return false, err end

  local resp
  local chunks, size = {}, 0
  while true do
    local p
    p, err = self:packet()
    if not p then return false, err end
    local t = p:byte(1)
    if t == 4 then
      resp = parse_headers(p)
      if not resp then return false, "Malformed AJP headers" end
    elseif t == 3 then
      if #p < 3 then return false, "Malformed AJP body chunk" end
      local n = string.unpack(">I2", p, 2)
      if #p < 3 + n then return false, "Malformed AJP body chunk" end
      size = size + n
      if size > MAX_BODY then return false, "AJP response body too large" end
      chunks[#chunks + 1] = p:sub(4, 3 + n)
    elseif t == 6 then
      local want = #p >= 3 and string.unpack(">I2", p, 2) or MAX_CHUNK
      ok, err = self.socket:send(body and next_chunk(want) or to_container(""))
      if not ok then return false, err end
    elseif t == 5 then
      break
    elseif t == 9 then
      -- A CPong without a request: ignored.
    else
      return false, ("Unexpected AJP packet type %d"):format(t)
    end
  end
  if not resp then return false, "No AJP headers received" end
  if #chunks > 0 then resp.body = table.concat(chunks) end
  return true, resp
end

for _, m in ipairs({ "GET", "HEAD", "OPTIONS", "TRACE", "DELETE" }) do
  ajp.Helper[m:lower()] = function(self, url, headers, attributes, options)
    return self:request(m, url, headers, attributes, options)
  end
end

---
-- Helper:put(url, headers, attributes, options[, body]): a PUT; the body
-- (nil for none) is sent with its Content-Length.
function ajp.Helper:put(url, headers, attributes, options, body)
  return self:request("PUT", url, headers, attributes, options, body)
end

return ajp
