-- NSE compatibility layer: the `smb2` module, the SMB2/SMB3 NEGOTIATE
-- over fero.smb. Written for FeroProbe from nmap's public API
-- documentation and [MS-SMB2] (not from nselib); GPL-3.0-or-later, like
-- FeroProbe. The NEGOTIATE carries FeroProbe's client GUID
-- "FeroProbeSMBScan" (IDS rule 9100010).
--
-- The raw packet functions (smb2_encode_header_sync, smb2_send,
-- smb2_read) need a connection kept open between calls, which FeroProbe's
-- SMB state does not hold: they raise an error naming themselves.
local fero = ...
local smb2 = {}

local function timeout()
  return tonumber(fero.args.get("smbtimeout")) or 10000
end

---
-- smb2.dialects(): the SMB2 dialect codes, oldest first (0x0202, 0x0210,
-- 0x0300, 0x0302, 0x0311).
function smb2.dialects()
  return fero.smb.dialects()
end

---
-- smb2.dialect_name(dialect): the dialect as nmap's scripts print it
-- ("3:1:1"; the NSEDoc page says "3.1.1", nmap 7.94 and 7.95 print the
-- colon form), or nil for one FeroProbe does not know.
function smb2.dialect_name(dialect)
  for _, d in ipairs(fero.smb.dialects()) do
    if d == dialect then return fero.smb.dialect_name(d) end
  end
  return nil
end

-- A time (Unix seconds) as nmap's scripts print it, or "N/A" when the server gives
-- none (as nmap's smb2-time prints a missing start time).
local function when(t)
  if not t or t == 0 then return "N/A" end
  return os.date("!%Y-%m-%dT%H:%M:%S", t)
end

---
-- smb2.negotiate_v2(smb, overrides): NEGOTIATE on the state from
-- smb.start, offering every dialect or overrides.Dialects. Fills the
-- state's dialect, security_mode, capabilities, server_guid, time and
-- date, start_time (0 when the server does not say) and start_date
-- ("N/A" for a time the server does not give).
-- Returns true and the dialect, or false and a message.
function smb2.negotiate_v2(smb, overrides)
  if type(smb) ~= "table" or not smb.port_table then
    return false, "smb2.negotiate_v2 needs the state smb.start gives"
  end
  local dialects = overrides and overrides.Dialects
  local n, err = fero.smb.negotiate(smb.host, smb.port_table, timeout(), dialects)
  if not n then return false, err end
  smb.dialect = n.dialect
  smb.security_mode = n.security_mode
  smb.capabilities = n.capabilities
  smb.server_guid = n.server_guid
  smb.time = n.time
  smb.date = when(n.time)
  smb.start_time = n.start_time or 0
  smb.start_date = when(n.start_time)
  return true, n.dialect
end

for _, name in ipairs({ "smb2_encode_header_sync", "smb2_send", "smb2_read" }) do
  smb2[name] = function()
    error("smb2." .. name .. " is not available in FeroProbe (no open SMB connection is kept)", 2)
  end
end

return smb2
