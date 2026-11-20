-- fero.smb: SMB NEGOTIATE exchanges (SMB2/SMB3 and SMB1), and the first
-- leg of an SMB1 session setup, for scripts that read what an SMB server
-- says about itself before any login.
-- Written for FeroProbe from scratch, from [MS-SMB2] (2.2.1, 2.2.3,
-- 2.2.4), [MS-CIFS] (2.2.3.1, 2.2.4.52, 2.2.4.53), [MS-SMB] (2.2.4.5,
-- 2.2.4.6), [MS-SMB2] 2.1 (Direct TCP transport), RFC 1001/1002 (NetBIOS
-- session service) and RFC 4178 (SPNEGO); GPL-3.0-or-later.
local fero = ...
local smb = {}

-- The SMB2 dialects, oldest first: SMB 2.0.2 up to 3.1.1.
local DIALECTS = { 0x0202, 0x0210, 0x0300, 0x0302, 0x0311 }

-- The SMB2 dialects FeroProbe knows, oldest first (a copy).
function smb.dialects()
  return table.move(DIALECTS, 1, #DIALECTS, 1, {})
end

-- The client capabilities offered when an SMB 3.x dialect is: DFS,
-- leasing, large MTU, multi-channel, persistent handles, directory leasing
-- and encryption, so the server shows the SMB3 capabilities it would only
-- grant a client that has them ([MS-SMB2] 3.3.5.4). Older dialects get 0.
local SMB3_CLIENT_CAPS = 0x7f

-- FeroProbe's mark: the client GUID of every SMB2 NEGOTIATE it sends.
smb.CLIENT_GUID = "FeroProbeSMBScan"

-- FeroProbe's mark in SMB1: the process ID of every SMB1 request (the
-- bytes "FP"), and the NativeOS and NativeLanMan of its session setup.
local SMB1_PID = 0x5046
local SMB1_NATIVE = "FeroProbe"

-- The one SMB1 dialect offered, as nmap offers it.
smb.SMB1_DIALECT = "NT LM 0.12"

-- A dialect as nmap (7.94 and 7.95) writes it, one digit per nibble:
-- 0x0311 is "3:1:1", 0x0210 is "2:1:0".
function smb.dialect_name(d)
  return string.format("%d:%d:%d", d >> 8, (d >> 4) & 0xf, d & 0xf)
end

-- The port to reach SMB on: --script-args smbport=N when given (and that
-- port may be open), else TCP 445, else TCP 139 (NetBIOS session service);
-- nil when none of them is open.
function smb.port(host)
  local want = tonumber(fero.args.get("smbport"))
  local candidates = want and { math.tointeger(want) } or { 445, 139 }
  for _, n in ipairs(candidates) do
    local p = fero.get_port_state(host, { number = n, protocol = "tcp" })
    if p then return p end
  end
  return nil
end

-- A NetBIOS name, first-level encoded (RFC 1001 14.1), as the session
-- request carries it.
local function netbios_name(name, suffix)
  local padded = (name .. string.rep(" ", 15)):sub(1, 15) .. string.char(suffix)
  local out = { string.char(32) }
  for i = 1, 16 do
    local b = padded:byte(i)
    out[#out + 1] = string.char(0x41 + (b >> 4), 0x41 + (b & 0xf))
  end
  out[#out + 1] = "\0"
  return table.concat(out)
end

-- One message with its 4-byte length prefix (type 0, then 24 bits of
-- length): the framing of both transports.
local function frame(msg)
  return "\0" .. string.pack(">I3", #msg) .. msg
end

local MAX_MESSAGE = 65536

-- A connection to `port`, past the NetBIOS session request on 139 (the
-- caller names itself FEROPROBE, the server the generic *SMBSERVER).
-- Returns { sock, r } or nil and a reason.
local function open(host, port, timeout)
  local sock = fero.socket.new()
  sock:set_timeout(timeout or 8000)
  local ok, err = sock:connect(host, port)
  if not ok then return nil, err end
  local r = fero.reader(sock)
  local function fail(why)
    sock:close()
    return nil, why
  end
  if port.number == 139 or port.service == "netbios-ssn" then
    local names = netbios_name("*SMBSERVER", 0x20) .. netbios_name("FEROPROBE", 0x00)
    ok, err = sock:send(string.char(0x81, 0) .. string.pack(">I2", #names) .. names)
    if not ok then return fail(err) end
    local head = r:bytes(4)
    if not head then return fail("no NetBIOS session") end
    local kind, len = string.unpack(">BxI2", head)
    if len > 0 and not r:bytes(len) then return fail("no NetBIOS session") end
    if kind ~= 0x82 then return fail("NetBIOS session refused") end
  end
  return { sock = sock, r = r }
end

-- Send one message and read the answer; nil and a reason when there is
-- none.
local function exchange(c, msg)
  local ok, err = c.sock:send(frame(msg))
  if not ok then return nil, err end
  local head
  head, err = c.r:bytes(4)
  if not head then return nil, err end
  local kind, len = string.unpack(">BI3", head)
  if kind ~= 0 then return nil, "not a session message" end
  if len > MAX_MESSAGE then return nil, "message too long" end
  return c.r:bytes(len)
end

-- Windows FILETIME (100 ns since 1601) as Unix seconds; nil for 0.
local function unix_time(ft)
  if ft == 0 then return nil end
  return ft // 10000000 - 11644473600
end

------------------------------------------------------------------------
-- SMB2 / SMB3

-- The NEGOTIATE request offering `dialects`: the 64-byte SMB2 header,
-- the request, its dialects, then (only when 3.1.1 is offered) the
-- preauth-integrity context that 3.1.1 needs.
local function negotiate_request(dialects)
  local header = "\xfeSMB" .. string.pack("<I2I2I4I2I2I4I4I8I4I4I8",
    64, 0, 0, 0, 1, 0, 0, 0, 0xfeff, 0, 0) .. string.rep("\0", 16)
  local list, has311, caps = {}, false, 0
  for i, d in ipairs(dialects) do
    list[i] = string.pack("<I2", d)
    if d == 0x0311 then has311 = true end
    if d >= 0x0300 then caps = SMB3_CLIENT_CAPS end
  end
  list = table.concat(list)
  local tail, ctx_offset, ctx_count = "", 0, 0
  if has311 then
    -- Contexts start on an 8-byte boundary after the dialects.
    local fixed = 64 + 36 + #list
    local pad = (8 - fixed % 8) % 8
    local salt = string.rep("\0", 32)
    local preauth = string.pack("<I2I2I2", 1, #salt, 0x0001) .. salt
    tail = string.rep("\0", pad)
      .. string.pack("<I2I2I4", 0x0001, #preauth, 0) .. preauth
    ctx_offset, ctx_count = fixed + pad, 1
  end
  local body = string.pack("<I2I2I2I2I4", 36, #dialects, 0x0001, 0, caps)
    .. smb.CLIENT_GUID
    .. string.pack("<I4I2I2", ctx_offset, ctx_count, 0)
    .. list .. tail
  return header .. body
end

-- Connect to `port` (from smb.port) and NEGOTIATE, offering `dialects`
-- (default: all of smb.dialects()). Returns a table:
--   dialect           the dialect the server chose (0x0311 ...)
--   security_mode     its SecurityMode bits (1 signing enabled, 2 required)
--   capabilities      its Capabilities bits
--   server_guid       16 bytes
--   time, start_time  its clock and boot time, Unix seconds (start_time
--                     nil when the server does not give it)
-- or nil and a reason. Logs in to nothing.
function smb.negotiate(host, port, timeout, dialects)
  local c, err = open(host, port, timeout)
  if not c then return nil, err end
  local msg
  msg, err = exchange(c, negotiate_request(dialects or DIALECTS))
  c.sock:close()
  if not msg then return nil, err end
  if #msg < 64 + 64 or msg:sub(1, 4) ~= "\xfeSMB" then
    return nil, "not an SMB2 reply"
  end
  local status, command = string.unpack("<I4I2", msg, 9)
  if command ~= 0 then return nil, "not a NEGOTIATE reply" end
  if status ~= 0 then return nil, string.format("status 0x%08x", status) end
  local size, mode, dialect, _, guid, caps, _, _, _, now, boot =
    string.unpack("<I2I2I2I2c16I4I4I4I4i8i8", msg, 65)
  if size ~= 65 then return nil, "not a NEGOTIATE reply" end
  return {
    dialect = dialect,
    security_mode = mode,
    capabilities = caps,
    server_guid = guid,
    time = unix_time(now),
    start_time = unix_time(boot),
  }
end

------------------------------------------------------------------------
-- SMB1

local SMB_COM_NEGOTIATE = 0x72
local SMB_COM_SESSION_SETUP_ANDX = 0x73

-- Flags2: long names, extended security, 32-bit status codes, Unicode.
local FLAGS2_LONG_NAMES = 0x0001
local FLAGS2_EXTENDED_SECURITY = 0x0800
local FLAGS2_NT_STATUS = 0x4000
local FLAGS2_UNICODE = 0x8000

-- Capabilities: NT status codes, NT SMBs, extended security.
local CAP_NT_SMBS = 0x00000010
local CAP_STATUS32 = 0x00000040
local CAP_EXTENDED_SECURITY = 0x80000000

local STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016

-- The 32-byte SMB1 header of a request: no tree, no user, FeroProbe's
-- process ID, and `mid` to tell the requests apart.
local function smb1_header(command, flags2, mid)
  return "\xffSMB" .. string.pack("<BI4BI2I2", command, 0, 0x18, flags2, 0)
    .. string.rep("\0", 8)
    .. string.pack("<I2I2I2I2I2", 0, 0, SMB1_PID, 0, mid)
end

-- An SMB1 reply to `command`: its status, Flags2, parameter words, data,
-- and where the data starts (bytes from the header's start); nil and a
-- reason when it is not one.
local function parse_smb1(msg, command)
  if msg:sub(1, 4) == "\xfeSMB" then return nil, "SMB1 not supported" end
  if #msg < 35 or msg:sub(1, 4) ~= "\xffSMB" then
    return nil, "not an SMB1 reply"
  end
  local cmd, status, _, flags2 = string.unpack("<BI4BI2", msg, 5)
  if cmd ~= command then return nil, "not the reply asked for" end
  local wc = msg:byte(33)
  local bpos = 34 + 2 * wc
  if bpos + 1 > #msg then return nil, "reply too short" end
  local bc = string.unpack("<I2", msg, bpos)
  local dpos = bpos + 2
  if dpos + bc - 1 > #msg then return nil, "reply too short" end
  return {
    status = status,
    flags2 = flags2,
    words = msg:sub(34, bpos - 1),
    data = msg:sub(dpos, dpos + bc - 1),
    data_offset = dpos - 1,
  }
end

-- A zero-terminated string in `data` at `pos` (UTF-16LE when `unicode`,
-- else OEM text shown as ASCII with other bytes escaped). Returns the
-- text (nil when empty) and the position after it.
local function read_string(data, pos, unicode)
  local text, after
  if unicode then
    local i = pos
    while i + 1 <= #data and not (data:byte(i) == 0 and data:byte(i + 1) == 0) do
      i = i + 2
    end
    text, after = fero.ntlm.utf16(data:sub(pos, i - 1)), i + 2
  else
    local z = data:find("\0", pos, true) or #data + 1
    text = data:sub(pos, z - 1):gsub("[^\32-\126]", function(c)
      return string.format("\\x%02x", c:byte())
    end)
    after = z + 1
  end
  if text == "" then text = nil end
  return text, after
end

-- NEGOTIATE on connection `c`, offering only NT LM 0.12; `extended` asks
-- for extended security (SPNEGO/NTLMSSP) and leaves the names out.
local function negotiate_v1_on(c, extended)
  local flags2 = FLAGS2_LONG_NAMES | FLAGS2_NT_STATUS
  if extended then flags2 = flags2 | FLAGS2_EXTENDED_SECURITY end
  local dialects = "\2" .. smb.SMB1_DIALECT .. "\0"
  local msg, err = exchange(c, smb1_header(SMB_COM_NEGOTIATE, flags2, 1)
    .. "\0" .. string.pack("<I2", #dialects) .. dialects)
  if not msg then return nil, err end
  local m
  m, err = parse_smb1(msg, SMB_COM_NEGOTIATE)
  if not m then return nil, err end
  if m.status ~= 0 then return nil, string.format("status 0x%08x", m.status) end
  if #m.words >= 2 and string.unpack("<I2", m.words) == 0xffff then
    return nil, "SMB1 not supported"
  end
  if #m.words ~= 34 then return nil, "not an NT LM 0.12 reply" end
  local _, mode, _, _, _, _, key, caps, now, tz, clen =
    string.unpack("<I2BI2I2I4I4I4I4i8i2B", m.words)
  local out = {
    dialect = smb.SMB1_DIALECT,
    security_mode = mode,
    capabilities = caps,
    session_key = key,
    time = unix_time(now),
    -- ServerTimeZone counts minutes west of UTC; this is seconds east.
    timezone = -tz * 60,
    extended = caps & CAP_EXTENDED_SECURITY ~= 0,
  }
  if out.extended then
    out.server_guid = m.data:sub(1, 16)
    out.security_blob = m.data:sub(17)
  else
    -- The names are UTF-16 even when the request did not ask for
    -- Unicode (Windows and Samba both send them so).
    local pos
    out.domain, pos = read_string(m.data, clen + 1, true)
    out.server = read_string(m.data, pos, true)
  end
  return out
end

-- Connect to `port` and NEGOTIATE in SMB1, offering NT LM 0.12 only (as
-- nmap does); `extended` asks for extended security. Returns a table:
--   dialect         "NT LM 0.12"
--   security_mode   its SecurityMode bits (1 user-level, 2 challenge/
--                   response, 4 signing enabled, 8 signing required)
--   capabilities    its Capabilities bits
--   time            its clock, Unix seconds (nil when it gives none)
--   timezone        its time zone, seconds east of UTC
--   extended        whether it chose extended security
--   domain, server  its domain or workgroup and its name (only without
--                   extended security)
-- or nil and a reason ("SMB1 not supported" when it answers in SMB2 or
-- accepts no dialect). Logs in to nothing.
function smb.negotiate_v1(host, port, timeout, extended)
  local c, err = open(host, port, timeout)
  if not c then return nil, err end
  local n
  n, err = negotiate_v1_on(c, extended)
  c.sock:close()
  return n, err
end

-- A DER element: tag, length, value.
local function der(tag, value)
  local n = #value
  local len
  if n < 0x80 then
    len = string.char(n)
  elseif n < 0x100 then
    len = string.char(0x81, n)
  else
    len = string.char(0x82) .. string.pack(">I2", n)
  end
  return string.char(tag) .. len .. value
end

-- The OIDs of SPNEGO (1.3.6.1.5.5.2) and NTLMSSP (1.3.6.1.4.1.311.2.2.10).
local SPNEGO_OID = "\x2b\x06\x01\x05\x05\x02"
local NTLMSSP_OID = "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"

-- An NTLM NEGOTIATE wrapped in an SPNEGO NegTokenInit offering NTLMSSP.
local function spnego_init(token)
  local mech_types = der(0xa0, der(0x30, der(0x06, NTLMSSP_OID)))
  local mech_token = der(0xa2, der(0x04, token))
  return der(0x60, der(0x06, SPNEGO_OID)
    .. der(0xa0, der(0x30, mech_types .. mech_token)))
end

-- The first leg of an extended-security session setup on `c`, after the
-- NEGOTIATE `neg`: FeroProbe's NTLM NEGOTIATE (in SPNEGO when the server
-- offered SPNEGO, as Windows and Samba do). The server answers with its
-- NTLM CHALLENGE and its NativeOS and NativeLanMan; FeroProbe never sends
-- the third message, so it logs in to nothing.
local function session_setup_ntlm(c, neg)
  local token = fero.ntlm.negotiate_message()
  local blob = (neg.security_blob and #neg.security_blob > 0)
    and spnego_init(token) or token
  local bytes = blob .. SMB1_NATIVE .. "\0" .. SMB1_NATIVE .. "\0"
  local words = string.pack("<BBI2I2I2I2I4I2I4I4", 0xff, 0, 0, 4356, 1, 1,
    neg.session_key, #blob, 0, CAP_EXTENDED_SECURITY | CAP_STATUS32 | CAP_NT_SMBS)
  local flags2 = FLAGS2_LONG_NAMES | FLAGS2_NT_STATUS | FLAGS2_EXTENDED_SECURITY
  local msg, err = exchange(c, smb1_header(SMB_COM_SESSION_SETUP_ANDX, flags2, 2)
    .. string.char(#words // 2) .. words .. string.pack("<I2", #bytes) .. bytes)
  if not msg then return nil, err end
  local m
  m, err = parse_smb1(msg, SMB_COM_SESSION_SETUP_ANDX)
  if not m then return nil, err end
  if m.status ~= STATUS_MORE_PROCESSING_REQUIRED and m.status ~= 0 then
    return nil, string.format("status 0x%08x", m.status)
  end
  if #m.words ~= 8 then return nil, "not a session setup reply" end
  local blob_len = string.unpack("<I2", m.words, 7)
  if blob_len > #m.data then return nil, "reply too short" end
  local pos = blob_len + 1
  local unicode = m.flags2 & FLAGS2_UNICODE ~= 0
  -- Unicode strings start on an even offset from the header.
  if unicode and (m.data_offset + blob_len) % 2 == 1 then pos = pos + 1 end
  local out = { challenge = fero.ntlm.parse_challenge(m.data:sub(1, blob_len)) }
  out.os, pos = read_string(m.data, pos, unicode)
  out.lanmanager, pos = read_string(m.data, pos, unicode)
  out.domain = read_string(m.data, pos, unicode)
  return out
end

-- What an SMB1 server says about itself, as nmap's smb.get_os gathers
-- it, over two connections: an NT LM 0.12 NEGOTIATE without extended
-- security (the server's clock, time zone, domain or workgroup, name),
-- then one with extended security and the first leg of a session setup
-- (its NativeOS and NativeLanMan, and the names in its NTLM challenge).
-- Returns a table with any of
--   os, lanmanager            NativeOS, NativeLanMan
--   server, domain            NetBIOS computer and domain names
--   workgroup                 set (and domain nil) when the host is in a
--                             workgroup rather than a domain
--   fqdn, domain_dns, forest_dns   DNS names from the NTLM challenge
--   time, timezone            clock (Unix seconds) and seconds east of UTC
--   received                  the scanner's os.time() when the clock came
-- or nil and a reason (no OS details, as nmap, gives nil). Logs in to
-- nothing.
function smb.os_info(host, port, timeout)
  local basic = smb.negotiate_v1(host, port, timeout, false)
  local basic_at = os.time()
  local c, err = open(host, port, timeout)
  if not c then return nil, err end
  local neg, setup
  neg, err = negotiate_v1_on(c, true)
  local neg_at = os.time()
  if neg then setup, err = session_setup_ntlm(c, neg) end
  c.sock:close()
  if not setup then return nil, err end
  if not setup.os and not setup.lanmanager then
    return nil, "no OS details"
  end
  local ch = setup.challenge or {}
  local b = basic or {}
  local clock, received = neg, neg_at
  if b.time then clock, received = b, basic_at end
  local out = {
    os = setup.os,
    lanmanager = setup.lanmanager,
    server = b.server or ch.netbios_computer,
    domain = b.domain or ch.netbios_domain,
    time = clock.time,
    timezone = clock.timezone,
    received = received,
  }
  if ch.dns_computer or ch.dns_domain or ch.dns_tree then
    out.fqdn, out.domain_dns, out.forest_dns = ch.dns_computer, ch.dns_domain, ch.dns_tree
    -- In a workgroup Windows gives its own name as the NTLM domain, so a
    -- NetBIOS domain that differs from the NEGOTIATE's is a workgroup.
    if ch.netbios_domain and out.domain ~= ch.netbios_domain then
      out.workgroup, out.domain = out.domain, nil
    end
  end
  return out
end

-- The dialects the server accepts, each tried as nmap's smb-protocols
-- tries them: NT LM 0.12 on its own, then SMB2/SMB3 all together (the
-- server picks the newest it speaks), then each older one alone. A list
-- of names ("NT LM 0.12", "2:0:2" ... "3:1:1"), oldest first; empty when
-- it accepts none.
function smb.list_dialects(host, port, timeout)
  local out = {}
  if smb.negotiate_v1(host, port, timeout, true) then
    out[#out + 1] = smb.SMB1_DIALECT
  end
  local top = smb.negotiate(host, port, timeout)
  if not top then return out end
  for _, d in ipairs(DIALECTS) do
    if d == top.dialect then break end
    if smb.negotiate(host, port, timeout, { d }) then
      out[#out + 1] = smb.dialect_name(d)
    end
  end
  out[#out + 1] = smb.dialect_name(top.dialect)
  return out
end

fero.smb = smb
