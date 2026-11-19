-- FeroProbe script: ms-sql-ntlm-info
-- Written for FeroProbe from scratch, from [MS-TDS] 2.2.3.1 (packet
-- header), 2.2.6.4 (LOGIN7) and 2.2.7.22 (SSPI token) and [MS-NLMP]
-- (through fero.ntlm); GPL-3.0-or-later.

description = [[
Reads what a Microsoft SQL Server says about itself in the NTLM
challenge of a Windows-authentication login: its NetBIOS and DNS
computer and domain names and the Windows version (its clock is noted
for clock-skew). Sends one TDS LOGIN7 packet that asks for integrated
security and carries an NTLM NEGOTIATE naming the workstation FEROPROBE
and no user (host name FEROPROBE, application "FeroProbe Scripting
Engine"), reads the server's SSPI answer and closes. Nothing logs in.
The output is listed under the instance it came from (address:port),
as in nmap.

Only the TCP ports the scan found: unlike nmap, the SQL Server Browser
(UDP 1434) is not asked for other instances.

Script arguments:
  ms-sql-ntlm-info.timeout  How long to wait for the answer, in
                            milliseconds (default 10000).
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "default", "discovery", "safe" }

portrule = fero.portrule.match({ 1433 }, { "ms-sql-s" })

-- UTF-16LE of ASCII text.
local function ucs2(s)
  return (s:gsub(".", "%0\0"))
end

-- A TDS 7.1 LOGIN7 message ([MS-TDS] 2.2.6.4) for integrated security:
-- no user name or password, `sspi` as the security data.
local function login7(server, sspi)
  local fields = {
    ucs2("FEROPROBE"),                  -- HostName
    "",                                 -- UserName
    "",                                 -- Password
    ucs2("FeroProbe Scripting Engine"), -- AppName
    ucs2(server),                       -- ServerName
    false,                              -- (unused)
    ucs2("fero"),                       -- CltIntName (the library)
    "",                                 -- Language
    "",                                 -- Database
  }
  local FIXED = 86
  local offsets, data, at = {}, {}, FIXED
  for _, f in ipairs(fields) do
    if f == false then
      offsets[#offsets + 1] = string.pack("<I2I2", 0, 0)
    else
      offsets[#offsets + 1] = string.pack("<I2I2", at, #f // 2)
      data[#data + 1] = f
      at = at + #f
    end
  end
  local sspi_at = at
  local total = at + #sspi
  local head = string.pack("<I4I4I4I4I4I4", total,
      0x71000001,   -- TDS 7.1
      4096,         -- packet size
      7,            -- client program version
      0,            -- client process ID
      0)            -- connection ID
    .. string.char(
      0xa0,         -- OptionFlags1: USE DB and SET LANGUAGE warnings
      0x83,         -- OptionFlags2: initial language fatal, ODBC, integrated security
      0x00,         -- TypeFlags
      0x00)         -- OptionFlags3
    .. string.pack("<i4I4", 0, 0) -- time zone, LCID
  return head .. table.concat(offsets)
    .. string.rep("\0", 6)                       -- ClientID (MAC)
    .. string.pack("<I2I2", sspi_at, #sspi)      -- SSPI
    .. string.pack("<I2I2", total, 0)            -- AtchDBFile (none)
    .. table.concat(data) .. sspi
end

-- One TDS packet: type, status "end of message", length, SPID 0,
-- packet 1, window 0.
local function tds_packet(kind, body)
  return string.pack(">BBI2I2BB", kind, 0x01, #body + 8, 0, 1, 0) .. body
end

local MAX_REPLY = 65536

action = function(host, port)
  local timeout = tonumber(fero.args.get(SCRIPT_NAME .. ".timeout")) or 10000
  local sock = fero.socket.new()
  sock:set_timeout(timeout)
  if not sock:connect(host, port) then return nil end
  local function done(...)
    sock:close()
    return ...
  end
  local server = host.targetname or host.ip
  if not sock:send(tds_packet(0x10, login7(server, fero.ntlm.negotiate_message()))) then
    return done(nil)
  end
  -- The answer: tabular-result packets (type 4) up to the one marked
  -- end of message.
  local r, body = fero.reader(sock), ""
  repeat
    local head = r:bytes(8)
    if not head then return done(nil) end
    local kind, status, len = string.unpack(">BBI2", head)
    if kind ~= 0x04 or len < 8 or #body + len > MAX_REPLY then return done(nil) end
    local part = r:bytes(len - 8)
    if not part then return done(nil) end
    body = body .. part
  until status & 0x01 ~= 0
  sock:close()
  -- An SSPI token (0xED) first, with a two-byte length: the challenge.
  if body:byte(1) ~= 0xed or #body < 3 then return nil end
  local n = string.unpack("<I2", body, 2)
  local info = fero.ntlm.info(body:sub(4, 3 + n))
  if not info then return nil end
  local out = fero.output_table()
  out[host.ip .. ":" .. port.number] = info
  return out
end
