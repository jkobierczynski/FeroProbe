-- FeroProbe script: clock-skew
-- Written for FeroProbe from scratch; GPL-3.0-or-later.

description = [[
Sums up how far a host's clocks are from the scanner's, from what other
scripts saw of it: http-date, ntp-info, rdp-ntlm-info, smb2-time and
ssl-date note each service's clock (fero.record_skew), and this script,
which runs after them, shows the difference for the host: the one value
when there is one, else the mean, the standard deviation and the
median. It sends nothing itself.

After the scan, when two or more hosts had a value, it lists the hosts
grouped by their median difference.
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "default", "safe" }

dependencies = {
  "http-date", "ntp-info", "rdp-ntlm-info", "smb2-time", "ssl-date",
  "http-ntlm-info", "imap-ntlm-info", "ms-sql-ntlm-info", "nntp-ntlm-info",
  "pop3-ntlm-info", "smtp-ntlm-info", "telnet-ntlm-info",
  "smb-os-discovery", "smb-security-mode",
}

local function skews()
  local list = fero.host_registry and fero.host_registry.get("clock_skew")
  if type(list) ~= "table" then return nil end
  local v = {}
  for _, e in ipairs(list) do
    if type(e) == "table" and math.type(e.skew) == "integer" then v[#v + 1] = e.skew end
  end
  if #v == 0 then return nil end
  table.sort(v)
  return v
end

hostrule = function(host)
  return skews() ~= nil
end

postrule = function()
  local hosts = fero.registry.get("clock_skew_hosts")
  return type(hosts) == "table" and #hosts >= 2
end

local function median(v)
  local n = #v
  if n % 2 == 1 then return v[(n + 1) // 2] end
  return (v[n // 2] + v[n // 2 + 1]) / 2
end

local function host_action(host)
  local v = skews()
  if not v then return nil end
  local n, sum = #v, 0
  for _, x in ipairs(v) do sum = sum + x end
  local mean = sum / n
  local sq = 0
  for _, x in ipairs(v) do sq = sq + (x - mean) ^ 2 end
  local stddev = math.sqrt(sq / n)
  local med = median(v)
  fero.registry.append("clock_skew_hosts", {
    ip = host.ip,
    name = host.targetname or (host.name ~= "" and host.name) or nil,
    skew = math.floor(med + 0.5),
  })
  local out = fero.output_table()
  out.mean = math.floor(mean + 0.5)
  out.stddev = math.floor(stddev + 0.5)
  out.median = math.floor(med + 0.5)
  out.count = n
  if n == 1 then
    return out, fero.format_time(v[1])
  end
  return out, string.format("mean: %s, deviation: %s, median: %s",
    fero.format_time(mean), fero.format_time(stddev), fero.format_time(med))
end

local function post_action()
  local hosts = fero.registry.get("clock_skew_hosts")
  if type(hosts) ~= "table" then return nil end
  table.sort(hosts, function(a, b)
    if a.skew ~= b.skew then return a.skew < b.skew end
    return a.ip < b.ip
  end)
  local out = fero.output_table()
  for _, h in ipairs(hosts) do
    local key = fero.format_time(h.skew)
    if not out[key] then out[key] = {} end
    local list = out[key]
    list[#list + 1] = h.name and (h.ip .. " (" .. h.name .. ")") or h.ip
  end
  return out
end

action = function(host)
  if SCRIPT_TYPE == "postrule" then return post_action() end
  return host_action(host)
end
