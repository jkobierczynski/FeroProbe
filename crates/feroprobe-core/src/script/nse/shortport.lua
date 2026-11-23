-- NSE compatibility layer: the `shortport` module.
-- Written for FeroProbe from nmap's public API documentation (not from
-- nselib); GPL-3.0-or-later, like FeroProbe.
local fero = ...
local shortport = {}

local function set_of(x)
  if x == nil then return {} end
  if type(x) ~= "table" then x = { x } end
  local s = {}
  for _, v in ipairs(x) do s[v] = true end
  return s
end

local function base(protos, states)
  local P = set_of(protos or "tcp")
  local S = set_of(states or { "open", "open|filtered" })
  return function(port) return P[port.protocol] and S[port.state] end
end

shortport.portnumber = function(ports, protos, states)
  local N, ok = set_of(ports), base(protos, states)
  return function(_, port) return ok(port) and N[port.number] == true end
end

shortport.service = function(services, protos, states)
  local V, ok = set_of(services), base(protos, states)
  return function(_, port) return ok(port) and V[port.service] == true end
end

shortport.port_or_service = function(ports, services, protos, states)
  local N, V, ok = set_of(ports), set_of(services), base(protos, states)
  return function(_, port)
    return ok(port) and (N[port.number] == true or V[port.service] == true)
  end
end

-- nmap also weighs the probe's rarity against --version-intensity;
-- FeroProbe's -sV has no such scale for scripts, so this is
-- port_or_service.
shortport.version_port_or_service = function(ports, services, protos, states)
  return shortport.port_or_service(ports, services, protos, states)
end

-- "1-100,443" as a list of the port numbers, for portnumber.
shortport.port_range = function(range)
  local list = {}
  for part in tostring(range):gmatch("[^,]+") do
    local a, b = part:match("^%s*(%d+)%s*%-%s*(%d+)%s*$")
    a, b = tonumber(a or part), tonumber(b or part)
    if a and b then
      for n = math.max(a, 0), math.min(b, 65535) do list[#list + 1] = n end
    end
  end
  return list
end

shortport.LIKELY_HTTP_PORTS = { 80, 443, 591, 631, 3000, 5000, 7080, 8000, 8008,
  8080, 8081, 8088, 8180, 8443, 8888, 9000, 9443 }
shortport.LIKELY_HTTP_SERVICES = { "http", "https", "http-alt", "https-alt",
  "http-proxy", "http-mgmt", "ssl/http", "ipp" }
shortport.LIKELY_SSL_PORTS = { 443, 465, 636, 989, 990, 992, 993, 995, 4443,
  5061, 6697, 8443, 9443 }
shortport.LIKELY_SSL_SERVICES = { "https", "https-alt", "ssl", "ssl/http", "imaps",
  "pop3s", "smtps", "submissions", "ldaps", "ftps", "ftps-data", "ircs",
  "sip-tls", "telnets" }

-- FeroProbe's own HTTP and TLS rules, which the built-in scripts use.
shortport.http = fero.portrule.http
shortport.ssl = fero.portrule.ssl
shortport.ssh = shortport.port_or_service(22, "ssh")
shortport.port_is_excluded = function() return false end

return shortport
