-- FeroProbe script: smb-os-discovery
-- Written for FeroProbe from scratch, from [MS-CIFS] 2.2.4.52 and
-- 2.2.4.53, [MS-SMB] 2.2.4.5 and 2.2.4.6 and [MS-NLMP] 2.2.1.2;
-- GPL-3.0-or-later.

description = [[
Shows what an SMB1 server says about itself: its operating system and
LAN manager, its computer, domain or workgroup names (NetBIOS and DNS),
and its clock in its own time zone. Two connections to TCP 445 (or 139,
after a NetBIOS session request): an NT LM 0.12 NEGOTIATE without
extended security, then one with extended security and the first leg of
a session setup carrying FeroProbe's NTLM NEGOTIATE. The server's answer
holds its NativeOS, NativeLanMan and NTLM challenge; FeroProbe never
answers the challenge, so it logs in to nothing. Servers that no longer
speak SMB1 (Windows 10 and Server 2016 on, by default) give no output.
How far the server's clock is from the scanner's is noted for
clock-skew.

Script arguments:
  smbport          The port to use instead of 445 and 139.
  smb-os-discovery.timeout
                   How long to wait for each answer, in milliseconds
                   (default 8000).
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "default", "discovery", "safe" }

hostrule = function(host)
  return fero.smb.port(host) ~= nil
end

-- The names nmap gives the oldest Windows versions.
local function windows_name(os)
  if os == "Windows 5.0" then return "Windows 2000" end
  if os == "Windows 5.1" then return "Windows XP" end
  return os
end

-- A CPE for the Windows versions nmap knows by their NativeOS, with the
-- service pack, and "professional" for Professional editions.
local CPE = {
  { "^Windows 5%.0", "windows_2000" },
  { "^Windows 5%.1", "windows_xp" },
  { "^Windows Server.*2003", "windows_server_2003" },
  { "^Windows Vista", "windows_vista" },
  { "^Windows Server.*2008", "windows_server_2008" },
  { "^Windows 7", "windows_7" },
  { "^Windows 8%f[^%d.]", "windows_8" },
  { "^Windows 8%.1", "windows_8.1" },
  { "^Windows 10%f[^%d.]", "windows_10" },
  { "^Windows Server.*2012", "windows_server_2012" },
}

local function cpe(os)
  if not os then return nil end
  for _, c in ipairs(CPE) do
    if os:match(c[1]) then
      local sp = os:match("Service Pack (%d+)")
      local out = "cpe:/o:microsoft:" .. c[2] .. "::" .. (sp and ("sp" .. sp) or "-")
      if os:find("Professional", 1, true) then out = out .. ":professional" end
      return out
    end
  end
  return nil
end

-- A time in the server's zone (`offset` seconds east of UTC), as nmap
-- writes it: 2026-01-02T04:04:05+01:00.
local function local_time(t, offset)
  local sign = offset < 0 and "-" or "+"
  local m = math.abs(offset) // 60
  return os.date("!%Y-%m-%dT%H:%M:%S", t + offset)
    .. string.format("%s%02d:%02d", sign, m // 60, m % 60)
end

action = function(host)
  local port = fero.smb.port(host)
  if not port then return nil end
  local timeout = tonumber(fero.args.get(SCRIPT_NAME .. ".timeout")) or 8000
  local r = fero.smb.os_info(host, port, timeout)
  if not r then return nil end

  local out = fero.output_table()
  out.os = r.os
  out.lanmanager = r.lanmanager
  out.domain = r.domain
  out.server = r.server
  if r.time then
    out.date = local_time(r.time, r.timezone)
    -- SMB's SystemTime is UTC, so the clock is compared as it is (nmap
    -- also takes the time zone off it, a skew of the zone's size).
    fero.record_skew(r.time)
  end
  out.fqdn = r.fqdn
  out.domain_dns = r.domain_dns
  out.forest_dns = r.forest_dns
  out.workgroup = r.workgroup
  out.cpe = cpe(r.os)

  local lines = {}
  local function add(label, value)
    if value then lines[#lines + 1] = label .. ": " .. value end
  end
  if r.os and r.lanmanager then
    add("OS", string.format("%s (%s)", windows_name(r.os), r.lanmanager))
  else
    add("OS", "Unknown")
  end
  add("OS CPE", out.cpe)
  if r.fqdn then add("Computer name", r.fqdn:match("^([^.]+)")) end
  add("NetBIOS computer name", r.server)
  if r.fqdn and r.domain_dns and r.fqdn ~= r.domain_dns then
    -- A computer whose name differs from its domain's is a domain member.
    add("Domain name", r.domain_dns)
    add("Forest name", r.forest_dns)
    add("FQDN", r.fqdn)
    add("NetBIOS domain name", r.domain)
  else
    add("Workgroup", r.workgroup or r.domain)
  end
  add("System time", out.date or "Unknown")
  return out, "\n  " .. table.concat(lines, "\n  ")
end
