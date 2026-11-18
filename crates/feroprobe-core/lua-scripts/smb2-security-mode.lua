-- FeroProbe script: smb2-security-mode
-- Written for FeroProbe from scratch, from [MS-SMB2] 2.2.3 and 2.2.4
-- (NEGOTIATE); GPL-3.0-or-later.

description = [[
Shows whether an SMB2/SMB3 server signs its messages: whether signing is
enabled and whether it is required. One NEGOTIATE exchange on TCP 445 (or
139, after a NetBIOS session request) offering SMB 2.0.2 to 3.1.1; the
answer is shown under the dialect the server chose. Logs in to nothing.

Script arguments:
  smbport              The port to use instead of 445 and 139.
  smb2-security-mode.timeout
                       How long to wait for each answer, in milliseconds
                       (default 8000).
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "default", "discovery", "safe" }

hostrule = function(host)
  return fero.smb.port(host) ~= nil
end

action = function(host)
  local port = fero.smb.port(host)
  if not port then return nil end
  local timeout = tonumber(fero.args.get(SCRIPT_NAME .. ".timeout")) or 8000
  local n = fero.smb.negotiate(host, port, timeout)
  if not n then return nil end
  local mode
  if n.security_mode & 2 ~= 0 then
    mode = "Message signing enabled and required"
  elseif n.security_mode & 1 ~= 0 then
    mode = "Message signing enabled but not required"
  else
    mode = "Message signing is disabled and not required!"
  end
  return { [fero.smb.dialect_name(n.dialect)] = { mode } }
end
