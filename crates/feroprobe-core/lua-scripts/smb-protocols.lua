-- FeroProbe script: smb-protocols
-- Written for FeroProbe from scratch, from [MS-CIFS] 2.2.4.52 and
-- [MS-SMB2] 2.2.3 and 2.2.4 (NEGOTIATE); GPL-3.0-or-later.

description = [[
Lists the SMB dialects a server accepts: NT LM 0.12 (SMBv1, marked as
dangerous), then SMB 2.0.2, 2.1, 3.0, 3.0.2 and 3.1.1. One NEGOTIATE per
connection on TCP 445 (or 139, after a NetBIOS session request): NT LM
0.12 alone, all SMB2/SMB3 dialects together (the server picks the newest
it speaks), then each older one alone. Logs in to nothing.

Script arguments:
  smbport          The port to use instead of 445 and 139.
  smb-protocols.timeout
                   How long to wait for each answer, in milliseconds
                   (default 8000).
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "discovery", "safe" }

hostrule = function(host)
  return fero.smb.port(host) ~= nil
end

action = function(host)
  local port = fero.smb.port(host)
  if not port then return nil end
  local timeout = tonumber(fero.args.get(SCRIPT_NAME .. ".timeout")) or 8000
  local dialects = fero.smb.list_dialects(host, port, timeout)
  if #dialects == 0 then
    if fero.verbosity() > 1 then
      return "No dialects accepted. Something may be blocking the responses"
    end
    return nil
  end
  for i, d in ipairs(dialects) do
    if d == fero.smb.SMB1_DIALECT then
      dialects[i] = d .. " (SMBv1) [dangerous, but default]"
    end
  end
  local out = fero.output_table()
  out.dialects = dialects
  return out
end
