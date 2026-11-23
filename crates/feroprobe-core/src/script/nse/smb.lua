-- NSE compatibility layer: the `smb` module, the parts of SMB that need
-- no login (fero.smb): the port, the NEGOTIATE, the OS details and the
-- dialects. Written for FeroProbe from nmap's public API documentation
-- (not from nselib) and MS-CIFS/MS-SMB2; GPL-3.0-or-later, like
-- FeroProbe. FeroProbe never logs in to an SMB server, not even as a
-- guest or anonymously: session setup, shares, files and accounts are
-- refused with a message.
local fero = ...
local smb = {}

local NO_LOGIN = "FeroProbe does not log in to SMB servers"

-- Seconds east of UTC as hours: a whole number when it is one (5.5 for
-- India).
local function hours(secs)
  if not secs then return nil end
  local h = secs / 3600
  return math.tointeger(h) or h
end

local function timeout()
  return tonumber(fero.args.get("smbtimeout")) or 10000
end

-- The TCP port SMB is reached on (445, else 139, or the smbport
-- argument), or nil when none of them is open.
function smb.get_port(host)
  local p = fero.smb.port(host)
  return p and p.number or nil
end

-- nmap's name for a Windows version string ("Windows 5.1" is
-- "Windows XP"); other strings come back unchanged.
local WINDOWS = {
  ["Windows 5.0"] = "Windows 2000",
  ["Windows 5.1"] = "Windows XP",
}
function smb.get_windows_version(os)
  return WINDOWS[os] or os
end

-- What the server says about itself before any login: true and a table
-- with os, lanmanager, server, domain or workgroup, fqdn, domain_dns,
-- forest_dns, time (Unix seconds), timezone (hours east of UTC),
-- timezone_str ("UTC+1") and port; or false and a message.
function smb.get_os(host)
  local p = fero.smb.port(host)
  if not p then return false, "No accessible SMB port" end
  local info, err = fero.smb.os_info(host, p, timeout())
  if not info then return false, err end
  local out = {}
  for k, v in pairs(info) do out[k] = v end
  out.received = nil
  out.port = p.number
  if info.timezone then
    local h = hours(info.timezone)
    out.timezone = h
    out.timezone_str = "UTC" .. (h >= 0 and "+" or "") .. h
  end
  return true, out
end

-- The dialects the server accepts: true and a list of names ("NT LM
-- 0.12", "2:0:2" ... "3:1:1"), oldest first; or false and a message.
function smb.list_dialects(host, overrides)
  local p = fero.smb.port(host)
  if not p then return false, "No accessible SMB port" end
  return true, fero.smb.list_dialects(host, p, timeout()), overrides
end

-- A connection state, as smb.start gives it. Holds no socket: each step
-- connects on its own, as fero.smb does.
function smb.start(host)
  local p = fero.smb.port(host)
  if not p then return false, "No accessible SMB port" end
  return true, { host = host, port = p.number, port_table = p }
end

-- NEGOTIATE in SMB1 (NT LM 0.12, extended security): fills the state's
-- dialect, security_mode, capabilities, time and timezone (hours), and,
-- when the server gives them, domain and server. true, or false and a
-- message.
function smb.negotiate_protocol(state)
  local n, err = fero.smb.negotiate_v1(state.host, state.port_table, timeout(), true)
  if not n then return false, err end
  state.dialect = n.dialect
  state.security_mode = n.security_mode
  state.capabilities = n.capabilities
  state.time = n.time
  state.timezone = hours(n.timezone)
  state.extended_security = n.extended
  state.domain, state.server = n.domain, n.server
  return true
end

-- smb.start, then the NEGOTIATE when asked; a session (a login) is
-- refused.
function smb.start_ex(host, negotiate, start_session)
  if start_session then return false, NO_LOGIN end
  local ok, state = smb.start(host)
  if not ok then return false, state end
  if negotiate then
    local nok, err = smb.negotiate_protocol(state)
    if not nok then return false, err end
  end
  return true, state
end

function smb.stop() return true end

function smb.get_overrides() return {} end

-- A name made from the host's address, the same for every run against
-- that host, as scripts use for files they would leave behind.
function smb.get_uniqueish_name(host, extension, seed)
  local d = fero.crypto.digest("sha1", tostring(host.ip) .. tostring(seed or ""))
  local name = {}
  for i = 1, 8 do
    name[i] = string.char(string.byte("a") + d:byte(i) % 26)
  end
  local s = table.concat(name)
  if extension then s = s .. "." .. extension end
  return true, s
end

-- Everything else (session setup, trees, files, shares, accounts, raw
-- messages) needs a login or a raw SMB session: refused when called.
setmetatable(smb, {
  __index = function(_, name)
    return function()
      return false, "smb." .. tostring(name) .. ": " .. NO_LOGIN
    end
  end,
})

return smb
