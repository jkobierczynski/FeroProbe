-- fero.starttls: switch a plain-text connection to TLS the way each
-- protocol asks for it (STARTTLS and its kin), for scripts that read a
-- certificate or talk over TLS on ports that start in plain text.
-- Written for FeroProbe from scratch, from RFC 3207 (SMTP), RFC 2033
-- (LMTP), RFC 9051 and 3501 (IMAP), RFC 2595 (POP3), RFC 4642 (NNTP),
-- RFC 4217 (FTP), RFC 4511 4.14 (LDAP), the PostgreSQL protocol's
-- SSLRequest and RFC 6120 5 (XMPP); GPL-3.0-or-later.
local fero = ...
local starttls = {}

-- The default EHLO/LHLO name, as smtp-commands sends it: a reserved
-- name, so mail logs show who asked. smtp.domain replaces it.
local function ehlo_name(opts)
  local domain = opts.domain
  if type(domain) ~= "string" then domain = fero.args.get("smtp.domain") end
  if type(domain) ~= "string" or not domain:match("^[%w%.%-%[%]:]+$") then
    domain = "feroprobe.invalid"
  end
  return domain
end

-- SMTP and LMTP: greeting 220, EHLO (or LHLO) 250, STARTTLS 220.
local function smtp_like(hello)
  return function(sock, r, _, _, opts)
    if r:reply() ~= 220 then return nil, "no SMTP greeting" end
    sock:send(hello .. " " .. ehlo_name(opts) .. "\r\n")
    if r:reply() ~= 250 then return nil, hello .. " refused" end
    sock:send("STARTTLS\r\n")
    local code = r:reply()
    if code ~= 220 then
      sock:send("QUIT\r\n")
      return nil, "STARTTLS refused"
    end
    return true
  end
end

-- IMAP: greeting "* OK", CAPABILITY must list STARTTLS, then STARTTLS
-- answered "OK" under its tag.
local function imap(sock, r)
  local greeting = r:line()
  if not greeting or not greeting:upper():match("^%* OK") then
    return nil, "no IMAP greeting"
  end
  local function tagged(tag)
    local seen = {}
    for _ = 1, 1000 do
      local line = r:line()
      if not line then return nil end
      if line:sub(1, #tag + 1) == tag .. " " then
        return line:sub(#tag + 2):upper(), seen
      end
      seen[#seen + 1] = line:upper()
    end
  end
  sock:send("fp1 CAPABILITY\r\n")
  local status, lines = tagged("fp1")
  if not status or not status:match("^OK") then return nil, "CAPABILITY failed" end
  local offered = false
  for _, l in ipairs(lines) do
    if l:match("^%* CAPABILITY ") and (" " .. l .. " "):find(" STARTTLS ", 1, true) then
      offered = true
    end
  end
  if not offered then
    sock:send("fp2 LOGOUT\r\n")
    return nil, "STARTTLS not offered"
  end
  sock:send("fp2 STARTTLS\r\n")
  status = tagged("fp2")
  if not status or not status:match("^OK") then return nil, "STARTTLS refused" end
  return true
end

-- POP3: greeting "+OK", STLS "+OK".
local function pop3(sock, r)
  local greeting = r:line()
  if not greeting or greeting:sub(1, 3) ~= "+OK" then return nil, "no POP3 greeting" end
  sock:send("STLS\r\n")
  local line = r:line()
  if not line or line:sub(1, 3) ~= "+OK" then
    sock:send("QUIT\r\n")
    return nil, "STLS refused"
  end
  return true
end

-- NNTP: greeting 200 or 201, STARTTLS 382.
local function nntp(sock, r)
  local code = r:reply()
  if code ~= 200 and code ~= 201 then return nil, "no NNTP greeting" end
  sock:send("STARTTLS\r\n")
  if r:reply() ~= 382 then
    sock:send("QUIT\r\n")
    return nil, "STARTTLS refused"
  end
  return true
end

-- FTP: greeting 220, AUTH TLS 234.
local function ftp(sock, r)
  if r:reply() ~= 220 then return nil, "no FTP greeting" end
  sock:send("AUTH TLS\r\n")
  if r:reply() ~= 234 then
    sock:send("QUIT\r\n")
    return nil, "AUTH TLS refused"
  end
  return true
end

-- LDAP: an ExtendedRequest (message 1) for the StartTLS OID, answered by
-- an ExtendedResponse with result code 0 (success).
local LDAP_OID = "1.3.6.1.4.1.1466.20037"
local function ldap(sock, r)
  local req = "\x02\x01\x01" .. "\x77" .. string.char(#LDAP_OID + 2)
    .. "\x80" .. string.char(#LDAP_OID) .. LDAP_OID
  sock:send("\x30" .. string.char(#req) .. req)
  local head = r:bytes(2)
  if not head or head:byte(1) ~= 0x30 then return nil, "not an LDAP answer" end
  local n = head:byte(2)
  if n >= 0x80 then
    local k = n & 0x7f
    if k < 1 or k > 3 then return nil, "bad LDAP length" end
    local more = r:bytes(k)
    if not more then return nil, "short LDAP answer" end
    n = 0
    for i = 1, k do n = (n << 8) | more:byte(i) end
  end
  if n > 65536 then return nil, "LDAP answer too long" end
  local body = r:bytes(n)
  if not body then return nil, "short LDAP answer" end
  -- messageID (INTEGER), then [APPLICATION 24] with its result code
  -- (ENUMERATED) first.
  if #body < 2 or body:byte(1) ~= 0x02 or body:byte(2) >= 0x80 then
    return nil, "not an LDAP message"
  end
  local pos = 3 + body:byte(2)
  if pos + 1 > #body then return nil, "short LDAP answer" end
  if body:byte(pos) ~= 0x78 then return nil, "not an ExtendedResponse" end
  pos = pos + 1
  local l = body:byte(pos)
  if not l then return nil, "short LDAP answer" end
  pos = pos + 1 + (l >= 0x80 and (l & 0x7f) or 0)
  if body:byte(pos) ~= 0x0a or body:byte(pos + 1) ~= 1 then
    return nil, "no LDAP result code"
  end
  if body:byte(pos + 2) ~= 0 then return nil, "StartTLS refused" end
  return true
end

-- PostgreSQL: an SSLRequest, answered "S" (v3) or "Y" (v2).
local function postgres(sock, r)
  sock:send(string.pack(">I4I4", 8, 80877103))
  local b = r:bytes(1)
  if b ~= "S" and b ~= "Y" then return nil, "SSL refused" end
  return true
end

-- Read until `pattern` (plain text) has come, at most 64 KiB.
local function read_until(sock, buf, pattern)
  while not buf:find(pattern, 1, true) do
    if #buf > 65536 then return nil end
    local ok, data = sock:receive()
    if not ok then return nil end
    buf = buf .. data
  end
  return buf
end

-- XMPP: a stream header to the target's name, the features must offer
-- <starttls/>, then <starttls/> answered <proceed/>. Port 5269 or an
-- xmpp-server service is spoken to as a server (jabber:server).
local TLS_NS = "urn:ietf:params:xml:ns:xmpp-tls"
local function xmpp(sock, _, host, port)
  local ns = (port.number == 5269 or port.service == "xmpp-server")
    and "jabber:server" or "jabber:client"
  local to = host.targetname or host.ip
  if not to:match("^[%w%.%-:]+$") then to = host.ip end
  sock:send("<?xml version='1.0'?><stream:stream xmlns:stream="
    .. "'http://etherx.jabber.org/streams' xmlns='" .. ns .. "' to='" .. to
    .. "' version='1.0'>")
  local buf = read_until(sock, "", "</stream:features>")
  if not buf then return nil, "no XMPP stream features" end
  if not buf:find("urn:ietf:params:xml:ns:xmpp-tls", 1, true) then
    sock:send("</stream:stream>")
    return nil, "STARTTLS not offered"
  end
  -- Prefixes the stream header binds to the TLS namespace
  -- (xmlns:tls='...' on <stream:stream>), which the answer may use.
  local bound = {}
  local hs = buf:find("<[%w_%.%-]*:?stream[%s>]")
  local he = hs and buf:find(">", hs, true)
  local header = he and buf:sub(hs, he) or ""
  for prefix, uri in header:gmatch("xmlns:([%w_%.%-]+)%s*=%s*['\"]([^'\"]*)['\"]") do
    if uri == TLS_NS then bound[prefix .. ":"] = true end
  end
  sock:send("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
  -- The answer is a whole <proceed/> or <failure/> element in the TLS
  -- namespace, with or without a prefix. A binding on the element itself
  -- (<tls:proceed xmlns:tls='...'/>, or xmlns='...' when unprefixed) wins;
  -- otherwise a prefix must be one the stream header bound. A bare
  -- <proceed/> is taken as is, like nmap: a wrong guess only ends in a
  -- failed TLS handshake, which is reported.
  local function answer(b, name)
    local s, e, prefix = b:find("<([%w_%.%-]*:?)" .. name .. "[%s/>]")
    if not s then return false end
    local close = b:find(">", e, true)
    if not close then return false end
    local attr = prefix == "" and "xmlns" or "xmlns:" .. prefix:sub(1, -2)
    local own
    for a, uri in b:sub(s, close):gmatch("([%w_%.%-:]+)%s*=%s*['\"]([^'\"]*)['\"]") do
      if a == attr then own = uri end
    end
    if own then return own == TLS_NS end
    return prefix == "" or bound[prefix] == true
  end
  buf = ""
  while #buf <= 65536 do
    if answer(buf, "proceed") then return true end
    if answer(buf, "failure") then break end
    local ok, data = sock:receive()
    if not ok then break end
    buf = buf .. data
  end
  return nil, "STARTTLS refused"
end

-- Each protocol, by service name and by port number, as nmap's table.
local BY_NAME = {
  smtp = smtp_like("EHLO"), submission = smtp_like("EHLO"),
  lmtp = smtp_like("LHLO"), imap = imap, pop3 = pop3, nntp = nntp,
  ftp = ftp, ldap = ldap, postgresql = postgres,
  xmpp = xmpp, ["xmpp-client"] = xmpp, ["xmpp-server"] = xmpp,
}
local BY_NUMBER = {
  [21] = "ftp", [25] = "smtp", [110] = "pop3", [119] = "nntp",
  [143] = "imap", [389] = "ldap", [587] = "submission", [5222] = "xmpp",
  [5269] = "xmpp-server", [5432] = "postgresql",
}

-- The STARTTLS protocol a TCP port speaks (its service name first, then
-- its number, as nmap looks it up), or nil when none is known.
function starttls.protocol(port)
  if type(port) ~= "table" or port.protocol ~= "tcp" then return nil end
  if BY_NAME[port.service] then return port.service end
  return BY_NUMBER[port.number]
end

-- Connect to `port` and switch to TLS as its protocol asks. Returns the
-- socket, now speaking TLS (an SMTP server then wants EHLO again), or nil
-- and a reason. `opts.timeout` (milliseconds, default 10000) bounds each
-- wait; `opts.protocol` names the protocol instead of the port;
-- `opts.domain` is the name SMTP and LMTP say EHLO/LHLO with (else
-- smtp.domain, else feroprobe.invalid).
function starttls.connect(host, port, opts)
  opts = opts or {}
  local name = opts.protocol or starttls.protocol(port)
  local talk = name and BY_NAME[name]
  if not talk then return nil, "no STARTTLS for this port" end
  local sock = fero.socket.new()
  sock:set_timeout(tonumber(opts.timeout) or 10000)
  local ok, err = sock:connect(host, port, "tcp")
  if not ok then return nil, err end
  ok, err = talk(sock, fero.reader(sock), host, port, opts)
  if not ok then
    sock:close()
    return nil, err
  end
  ok, err = sock:reconnect_ssl()
  if not ok then
    sock:close()
    return nil, err
  end
  return sock
end

fero.starttls = starttls
