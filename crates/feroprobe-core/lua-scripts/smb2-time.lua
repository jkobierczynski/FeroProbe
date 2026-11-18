-- FeroProbe script: smb2-time
-- Written for FeroProbe from scratch, from [MS-SMB2] 2.2.3 and 2.2.4
-- (NEGOTIATE); GPL-3.0-or-later.

description = [[
Shows an SMB2/SMB3 server's clock, and when it started if it says, from
its answer to one NEGOTIATE exchange on TCP 445 (or 139, after a NetBIOS
session request). Times are in UTC. Logs in to nothing.

Script arguments:
  smbport          The port to use instead of 445 and 139.
  smb2-time.timeout
                   How long to wait for each answer, in milliseconds
                   (default 8000).
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "default", "discovery", "safe" }

hostrule = function(host)
  return fero.smb.port(host) ~= nil
end

local function when(t)
  if not t then return "N/A" end
  return os.date("!%Y-%m-%dT%H:%M:%S", t)
end

action = function(host)
  local port = fero.smb.port(host)
  if not port then return nil end
  local timeout = tonumber(fero.args.get(SCRIPT_NAME .. ".timeout")) or 8000
  local n = fero.smb.negotiate(host, port, timeout)
  if not n or not n.time then return nil end
  return { date = when(n.time), start_date = when(n.start_time) }
end
