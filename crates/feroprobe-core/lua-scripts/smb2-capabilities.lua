-- FeroProbe script: smb2-capabilities
-- Written for FeroProbe from scratch, from [MS-SMB2] 2.2.3 and 2.2.4
-- (NEGOTIATE); GPL-3.0-or-later.

description = [[
Lists the capabilities an SMB2/SMB3 server gives for each dialect it
speaks. One NEGOTIATE offering every dialect finds the newest the server
speaks; then one NEGOTIATE per dialect, from 2.0.2 up to that one, each
on its own connection to TCP 445 (or 139, after a NetBIOS session
request). Logs in to nothing.

Script arguments:
  smbport          The port to use instead of 445 and 139.
  smb2-capabilities.timeout
                   How long to wait for each answer, in milliseconds
                   (default 8000).
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "discovery", "safe" }

hostrule = function(host)
  return fero.smb.port(host) ~= nil
end

-- The SMB2 global capability bits, as nmap names them.
local CAPS = {
  { 0x01, "Distributed File System" },
  { 0x02, "Leasing" },
  { 0x04, "Multi-credit operations" },
  { 0x08, "Multiple Channel support" },
  { 0x10, "Persistent handles" },
  { 0x20, "Directory Leasing" },
  { 0x40, "Encryption" },
}

action = function(host)
  local port = fero.smb.port(host)
  if not port then return nil end
  local timeout = tonumber(fero.args.get(SCRIPT_NAME .. ".timeout")) or 8000
  local top = fero.smb.negotiate(host, port, timeout)
  if not top then return nil end
  local out, any = fero.output_table(), false
  for _, d in ipairs(fero.smb.dialects()) do
    local n = fero.smb.negotiate(host, port, timeout, { d })
    if n then
      local caps = {}
      for _, c in ipairs(CAPS) do
        if n.capabilities & c[1] ~= 0 then caps[#caps + 1] = c[2] end
      end
      if #caps == 0 then caps[1] = "All capabilities are disabled" end
      out[fero.smb.dialect_name(d)] = caps
      any = true
    end
    if d == top.dialect then break end
  end
  if not any then
    if fero.verbosity() > 1 then return "Couldn't establish a SMBv2 connection." end
    return nil
  end
  return out
end
