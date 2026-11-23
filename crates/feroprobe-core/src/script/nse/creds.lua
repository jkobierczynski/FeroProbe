-- NSE compatibility layer: the `creds` module, credentials scripts found.
-- Written for FeroProbe from nmap's public API documentation (not from
-- nselib); GPL-3.0-or-later, like FeroProbe.
-- Credentials are kept in the run's registry (nmap.registry.creds), so a
-- later script can use what an earlier one found, on any host.
local nmap = require "nmap"
local creds = {}

-- Account states, as bit flags that can be added: getCredentials takes
-- a sum of them.
creds.State = {
  LOCKED = 1,
  VALID = 2,
  DISABLED = 4,
  CHANGEPW = 8,
  PARAM = 16,
  EXPIRED = 32,
  TIME_RESTRICTED = 64,
  HOST_RESTRICTED = 128,
}
creds.State.LOCKED_VALID = creds.State.LOCKED + creds.State.VALID
creds.State.DISABLED_VALID = creds.State.DISABLED + creds.State.VALID

-- What each state is shown as.
creds.StateMsg = {
  [creds.State.LOCKED] = "Account locked",
  [creds.State.VALID] = "Valid credentials",
  [creds.State.DISABLED] = "Account disabled",
  [creds.State.CHANGEPW] = "Valid credentials, password change needed",
  [creds.State.PARAM] = "Given as a script argument",
  [creds.State.EXPIRED] = "Valid credentials, account expired",
  [creds.State.TIME_RESTRICTED] = "Valid credentials, no logins allowed at this time",
  [creds.State.HOST_RESTRICTED] = "Valid credentials, no logins allowed from this host",
  [creds.State.LOCKED_VALID] = "Valid credentials, account locked",
  [creds.State.DISABLED_VALID] = "Valid credentials, account disabled",
}

-- Every state at once, for getCredentials.
creds.ALL_DATA = "all_script_data"

local ALL_STATES = 0
for _, v in pairs(creds.State) do ALL_STATES = ALL_STATES | v end

local function state_text(state)
  if creds.StateMsg[state] then return creds.StateMsg[state] end
  local parts = {}
  for _, v in ipairs({ 1, 2, 4, 8, 16, 32, 64, 128 }) do
    if state & v ~= 0 then parts[#parts + 1] = creds.StateMsg[v] end
  end
  return table.concat(parts, ", ")
end

-- One account: username, password and state.
creds.Account = {}
creds.Account.__index = creds.Account

function creds.Account:new(username, password, state)
  return setmetatable({ username = username, password = password,
    state = tonumber(state) or 0 }, self)
end

creds.Account.__tostring = function(a)
  local user = (a.username and a.username ~= "") and a.username or "<empty>"
  local pass = (a.password and a.password ~= "") and a.password or "<empty>"
  local text = user .. ":" .. pass
  local s = state_text(a.state or 0)
  if s ~= "" then text = text .. " - " .. s end
  return text
end

creds.Account.__lt = function(a, b)
  return tostring(a.username) < tostring(b.username)
end

-- The credentials of a script on a host and port (or, with
-- creds.ALL_DATA, of every script, and of every host when none is given).
creds.Credentials = {}
creds.Credentials.__index = creds.Credentials

local function ip_of(host)
  if type(host) == "table" then return host.ip end
  return host
end

local function port_of(port)
  if type(port) == "table" then return port.number end
  return tonumber(port)
end

function creds.Credentials:new(scriptname, host, port)
  return setmetatable({ scriptname = scriptname, host = host, port = port }, self)
end

local function store()
  local list = nmap.registry.creds
  if list == nil then
    nmap.registry.creds = {}
    list = nmap.registry.creds
  end
  return list
end

-- Record an account found by this script on its host and port.
function creds.Credentials:add(username, password, state)
  local list = store()
  local port = type(self.port) == "table" and self.port or {}
  list[#list + 1] = {
    scriptname = self.scriptname,
    ip = ip_of(self.host),
    port = port_of(self.port),
    service = port.service,
    username = username,
    password = password,
    state = tonumber(state) or 0,
  }
  return true
end

-- Iterate over the matching accounts as creds.Account objects. `state`
-- is a sum of creds.State flags (all states when not given).
function creds.Credentials:getCredentials(state)
  state = tonumber(state) or ALL_STATES
  local list = nmap.registry.creds or {}
  local all_scripts = self.scriptname == creds.ALL_DATA
  local ip, port = ip_of(self.host), port_of(self.port)
  local i = 0
  return function()
    while true do
      i = i + 1
      local e = list[i]
      if e == nil then return nil end
      if (all_scripts or e.scriptname == self.scriptname)
        and (ip == nil or e.ip == ip)
        and (port == nil or e.port == port)
        and (state & (e.state or 0)) ~= 0 then
        return creds.Account:new(e.username, e.password, e.state)
      end
    end
  end
end

-- The matching accounts as text, one entry per account, for output.
function creds.Credentials:getTable()
  local out = {}
  for a in self:getCredentials() do out[#out + 1] = tostring(a) end
  if #out == 0 then return nil end
  return out
end

creds.Credentials.__tostring = function(c)
  local t = c:getTable()
  if not t then return "" end
  return table.concat(t, "\n")
end

return creds
