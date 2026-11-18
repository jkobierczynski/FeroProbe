-- fero.smb: the SMB2 NEGOTIATE exchange, for scripts that read what an
-- SMB server says about itself before any login.
-- Written for FeroProbe from scratch, from [MS-SMB2] (2.2.1, 2.2.3,
-- 2.2.4), [MS-SMB2] 2.1 (Direct TCP transport) and RFC 1001/1002
-- (NetBIOS session service); GPL-3.0-or-later.
local fero = ...
local smb = {}

-- The dialects offered, oldest first: SMB 2.0.2 up to 3.1.1.
local DIALECTS = { 0x0202, 0x0210, 0x0300, 0x0302, 0x0311 }

-- FeroProbe's mark: the client GUID of every NEGOTIATE it sends.
smb.CLIENT_GUID = "FeroProbeSMBScan"

-- A dialect as nmap writes it: 0x0311 is "3:1:1".
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

-- The NEGOTIATE request: the 64-byte SMB2 header, the request, its
-- dialects, then the preauth-integrity context that 3.1.1 needs.
local function negotiate_request()
  local header = "\xfeSMB" .. string.pack("<I2I2I4I2I2I4I4I8I4I4I8",
    64, 0, 0, 0, 1, 0, 0, 0, 0xfeff, 0, 0) .. string.rep("\0", 16)
  local dialects = {}
  for i, d in ipairs(DIALECTS) do dialects[i] = string.pack("<I2", d) end
  dialects = table.concat(dialects)
  -- Contexts start on an 8-byte boundary after the dialects.
  local fixed = 64 + 36 + #dialects
  local pad = (8 - fixed % 8) % 8
  local salt = string.rep("\0", 32)
  local preauth = string.pack("<I2I2I2", 1, #salt, 0x0001) .. salt
  local context = string.pack("<I2I2I4", 0x0001, #preauth, 0) .. preauth
  local body = string.pack("<I2I2I2I2I4", 36, #DIALECTS, 0x0001, 0, 0)
    .. smb.CLIENT_GUID
    .. string.pack("<I4I2I2", fixed + pad, 1, 0)
    .. dialects .. string.rep("\0", pad) .. context
  return header .. body
end

-- One message with its 4-byte length prefix (type 0, then 24 bits of
-- length): the framing of both transports.
local function frame(msg)
  return "\0" .. string.pack(">I3", #msg) .. msg
end

local MAX_MESSAGE = 65536

-- Read one framed message; nil and a reason when there is none.
local function read_message(r)
  local head, err = r:bytes(4)
  if not head then return nil, err end
  local kind, len = string.unpack(">BI3", head)
  if kind ~= 0 then return nil, "not a session message" end
  if len > MAX_MESSAGE then return nil, "message too long" end
  return r:bytes(len)
end

-- Windows FILETIME (100 ns since 1601) as Unix seconds; nil for 0.
local function unix_time(ft)
  if ft == 0 then return nil end
  return ft // 10000000 - 11644473600
end

-- Connect to `port` (from smb.port) and NEGOTIATE. Returns a table:
--   dialect           the dialect the server chose (0x0311 ...)
--   security_mode     its SecurityMode bits (1 signing enabled, 2 required)
--   capabilities      its Capabilities bits
--   server_guid       16 bytes
--   time, start_time  its clock and boot time, Unix seconds (start_time
--                     nil when the server does not give it)
-- or nil and a reason. Logs in to nothing.
function smb.negotiate(host, port, timeout)
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
    -- A NetBIOS session first, to the generic server name; the caller
    -- names itself FEROPROBE.
    local names = netbios_name("*SMBSERVER", 0x20) .. netbios_name("FEROPROBE", 0x00)
    ok, err = sock:send(string.char(0x81, 0) .. string.pack(">I2", #names) .. names)
    if not ok then return fail(err) end
    local head = r:bytes(4)
    if not head then return fail("no NetBIOS session") end
    local kind, len = string.unpack(">BxI2", head)
    if len > 0 and not r:bytes(len) then return fail("no NetBIOS session") end
    if kind ~= 0x82 then return fail("NetBIOS session refused") end
  end
  ok, err = sock:send(frame(negotiate_request()))
  if not ok then return fail(err) end
  local msg
  msg, err = read_message(r)
  sock:close()
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

fero.smb = smb
