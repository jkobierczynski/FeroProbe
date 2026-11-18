-- fero.ntlm: the first two NTLM messages, for scripts that read what a
-- server says about itself in its NTLM challenge, before any login.
-- Written for FeroProbe from scratch, from [MS-NLMP] 2.2.1.1, 2.2.1.2,
-- 2.2.2.1 and 2.2.2.10; GPL-3.0-or-later.
local fero = ...
local ntlm = {}

local SIGNATURE = "NTLMSSP\0"

-- NEGOTIATE flags: UNICODE, REQUEST_TARGET, NTLM, ALWAYS_SIGN,
-- EXTENDED_SESSIONSECURITY, VERSION, 128, 56.
local FLAGS = 0x00000001 | 0x00000004 | 0x00000200 | 0x00008000
  | 0x00080000 | 0x02000000 | 0x20000000 | 0x80000000

-- The NEGOTIATE message: no domain or workstation named; the version
-- field is empty but for the NTLM revision (15).
function ntlm.negotiate_message()
  return SIGNATURE .. string.pack("<I4I4", 1, FLAGS)
    .. string.pack("<I2I2I4", 0, 0, 0) .. string.pack("<I2I2I4", 0, 0, 0)
    .. string.rep("\0", 7) .. "\x0f"
end

-- UTF-16LE as UTF-8; unprintable characters escaped.
local function utf16(s)
  local out, i = {}, 1
  while i + 1 <= #s do
    local c = string.unpack("<I2", s, i)
    i = i + 2
    if c >= 0xd800 and c <= 0xdbff and i + 1 <= #s then
      local lo = string.unpack("<I2", s, i)
      if lo >= 0xdc00 and lo <= 0xdfff then
        c = 0x10000 + ((c - 0xd800) << 10) + (lo - 0xdc00)
        i = i + 2
      end
    end
    if c < 0x20 or c == 0x7f or (c >= 0xd800 and c <= 0xdfff) then
      out[#out + 1] = string.format("\\x%02x", c & 0xff)
    else
      out[#out + 1] = utf8.char(c)
    end
  end
  return table.concat(out)
end

-- A field (len, maxlen, offset) of the message `m`, or nil when it points
-- outside it.
local function field(m, at)
  local len, _, off = string.unpack("<I2I2I4", m, at)
  if len == 0 or off + len > #m then return nil end
  return m:sub(off + 1, off + len)
end

-- The AV pair names, as nmap's scripts label them.
local AV = {
  [1] = "netbios_computer", [2] = "netbios_domain", [3] = "dns_computer",
  [4] = "dns_domain", [5] = "dns_tree",
}

-- Find and read the CHALLENGE message in `data` (it may be wrapped, as in
-- a CredSSP or SPNEGO reply). Returns a table with any of
--   target_name, netbios_computer, netbios_domain, dns_computer,
--   dns_domain, dns_tree (text), timestamp (Unix seconds),
--   version ("10.0.14393"), flags
-- or nil and a reason.
function ntlm.parse_challenge(data)
  local start = data:find(SIGNATURE, 1, true)
  if not start then return nil, "no NTLM message" end
  local m = data:sub(start)
  if #m < 48 or string.unpack("<I4", m, 9) ~= 2 then
    return nil, "not an NTLM challenge"
  end
  local out = { flags = string.unpack("<I4", m, 21) }
  local name = field(m, 13)
  if name then out.target_name = utf16(name) end
  local info = field(m, 41)
  if info then
    local pos = 1
    while pos + 3 <= #info do
      local id, len = string.unpack("<I2I2", info, pos)
      pos = pos + 4
      if id == 0 or pos + len - 1 > #info then break end
      local v = info:sub(pos, pos + len - 1)
      pos = pos + len
      if AV[id] then
        out[AV[id]] = utf16(v)
      elseif id == 7 and len == 8 then
        local ft = string.unpack("<i8", v)
        if ft > 0 then out.timestamp = ft // 10000000 - 11644473600 end
      end
    end
  end
  -- The version follows the target-info field when the server sets
  -- NEGOTIATE_VERSION, and only fits when the payload starts after it.
  if out.flags & 0x02000000 ~= 0 and #m >= 56 then
    local major, minor, build = string.unpack("<BBI2", m, 49)
    if major > 0 then out.version = string.format("%d.%d.%d", major, minor, build) end
  end
  return out
end

fero.ntlm = ntlm
