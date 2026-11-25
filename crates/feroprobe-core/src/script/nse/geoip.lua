-- NSE compatibility layer: the `geoip` module, a shared registry of
-- geolocated addresses (kept in nmap.registry, so a postrule script sees
-- what host scripts added).
-- Written for FeroProbe from nmap's public API documentation (not from
-- nselib); GPL-3.0-or-later, like FeroProbe.
local nmap = require "nmap"
local geoip = {}

local KEY = "geoip_locations"

local function store()
  local r = nmap.registry[KEY]
  if not r then
    nmap.registry[KEY] = {}
    r = nmap.registry[KEY]
  end
  return r
end

-- Records ip at latitude lat, longitude lon (degrees).
geoip.add = function(ip, lat, lon)
  store()[tostring(ip)] = { lat = tonumber(lat), lon = tonumber(lon) }
end

-- True when no location has been recorded yet.
geoip.empty = function()
  return next(nmap.registry[KEY] or {}) == nil
end

-- Locations keyed by IP: { [ip] = { lat = ..., lon = ... } }.
geoip.get_all_by_ip = function()
  local out = {}
  for ip, c in pairs(nmap.registry[KEY] or {}) do out[ip] = { lat = c.lat, lon = c.lon } end
  return out
end

-- IPs keyed by "lat,lon": { ["lat,lon"] = { ip, ... } }.
geoip.get_all_by_gps = function()
  local out = {}
  for ip, c in pairs(nmap.registry[KEY] or {}) do
    local k = tostring(c.lat) .. "," .. tostring(c.lon)
    out[k] = out[k] or {}
    table.insert(out[k], ip)
  end
  for _, ips in pairs(out) do table.sort(ips) end
  return out
end

return geoip
