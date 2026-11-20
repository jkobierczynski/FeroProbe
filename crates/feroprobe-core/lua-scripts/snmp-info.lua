-- FeroProbe script: snmp-info
-- Written for FeroProbe from scratch, from RFC 3412 section 6, RFC 3414
-- section 4 (SNMPv3 engine discovery) and RFC 3411 section 5
-- (SnmpEngineID), with names of common vendors from the IANA Private
-- Enterprise Numbers registry; GPL-3.0-or-later.

description = [[
Asks an SNMPv3 agent who it is, without credentials: the engine discovery
request every SNMPv3 manager sends first is answered with the agent's
engine ID, how often the engine has booted and how long it has run since.
The engine ID names the vendor (its IANA enterprise number) and usually
holds a MAC address, an IP address or a text the vendor chose.

Sends one SNMPv3 GetRequest without a user name (sent twice at most) to
UDP 161, or a UDP port -sV named snmp, only when that port was scanned
(-sU -p U:161). Its msgID and request-id are 0x4650 ("FP").

Script arguments (of the SNMP library):
  snmp.timeout   How long to wait for the answer (default 5000 ms; a
                 number is milliseconds, or give a unit: 5s).
  snmp.retries   How often the request is sent again (default 1).
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "default", "version", "safe" }

portrule = fero.portrule.match({ 161 }, { "snmp" }, "udp")

-- Vendors seen most often in engine IDs, by IANA Private Enterprise
-- Number, as the registry spells them. Other numbers are shown as such.
local ENTERPRISE = {
  [2] = "IBM", [9] = "ciscoSystems", [11] = "Hewlett-Packard", [23] = "Novell",
  [42] = "Sun Microsystems", [43] = "3Com", [171] = "D-Link Systems, Inc.",
  [232] = "Compaq", [311] = "Microsoft", [674] = "Dell Inc.",
  [1588] = "Brocade Communications Systems, Inc.",
  [1872] = "Alteon Networks, Inc.", [1916] = "Extreme Networks",
  [1991] = "Brocade Communication Systems, Inc. (formerly 'Foundry Networks, Inc.')",
  [2011] = "HUAWEI Technology Co.,Ltd", [2021] = "U.C. Davis, ECE Dept. Tom",
  [2620] = "Check Point Software Technologies Ltd", [2636] = "Juniper Networks, Inc.",
  [3076] = "Altiga Networks, Inc.", [3375] = "F5 Labs, Inc.", [4413] = "Broadcom Limited",
  [4526] = "Netgear", [5624] = "Enterasys Networks", [5951] = "Netscaler",
  [6486] = "Alcatel-Lucent Enterprise (previous was 'Alcatel')",
  [6574] = "Synology Inc.", [6876] = "VMware Inc.", [8072] = "net-snmp",
  [8741] = "SonicWALL, Inc.", [11863] = "TP-Link Corporation Limited.",
  [12356] = "Fortinet, Inc.", [14823] = "Aruba, a Hewlett Packard Enterprise company",
  [14988] = "MikroTik", [24681] = "QNAP SYSTEMS, INC", [25053] = "Ruckus Wireless, Inc.",
  [25461] = "PALO ALTO NETWORKS", [25506] = "H3C", [27282] = "Realtek Semiconductor corp.",
  [30065] = "Arista Networks, Inc. (formerly 'Arastra, Inc.')",
  [41112] = "Ubiquiti Networks, Inc.",
}

-- An IPv6 address in its short text form (RFC 5952).
local function ipv6(b)
  local g = {}
  for i = 1, 16, 2 do g[#g + 1] = (b:byte(i) << 8) | b:byte(i + 1) end
  local best, len, i = nil, 1, 1
  while i <= 8 do
    if g[i] == 0 then
      local j = i
      while j <= 8 and g[j] == 0 do j = j + 1 end
      if j - i > len then best, len = i, j - i end
      i = j
    else
      i = i + 1
    end
  end
  local function hex(from, to)
    local t = {}
    for k = from, to do t[#t + 1] = string.format("%x", g[k]) end
    return table.concat(t, ":")
  end
  if not best then return hex(1, 8) end
  return hex(1, best - 1) .. "::" .. hex(best + len, 8)
end

-- The parts of an engine ID (RFC 3411 section 5): enterprise, format and
-- data, as nmap names them.
local function engine(id)
  local out = fero.output_table()
  if #id < 5 then
    out.engineIDFormat = "unknown"
    out.engineIDData = fero.hex(id)
    return out
  end
  local ent = string.unpack(">I4", id)
  if ent & 0x80000000 == 0 then
    -- The SNMPv1-era form: the enterprise number, then 8 bytes of its own.
    out.enterprise = ENTERPRISE[ent] or tostring(ent)
    out.engineIDFormat = "unknown"
    out.engineIDData = fero.hex(id:sub(5))
    return out
  end
  ent = ent & 0x7fffffff
  out.enterprise = ENTERPRISE[ent] or tostring(ent)
  local format, rest = id:byte(5), id:sub(6)
  if format == 1 and #rest == 4 then
    out.engineIDFormat = "ipv4"
    out.engineIDData = string.format("%d.%d.%d.%d", rest:byte(1, 4))
  elseif format == 2 and #rest == 16 then
    out.engineIDFormat = "ipv6"
    out.engineIDData = ipv6(rest)
  elseif format == 3 and #rest >= 6 then
    out.engineIDFormat = "mac"
    out.engineIDData = fero.hex(rest:sub(1, 6), ":")
  elseif format == 4 then
    out.engineIDFormat = "text"
    out.engineIDData = rest
  elseif format == 5 then
    out.engineIDFormat = "octets"
    out.engineIDData = fero.hex(rest)
  else
    out.engineIDFormat = "unknown"
    out.engineIDData = fero.hex(rest)
  end
  return out
end

action = function(host, port)
  local s = fero.snmp.session(host, port)
  if not s then return nil end
  local r = s:discover()
  s:close()
  -- Only the User-based Security Model (3) carries the engine fields.
  if not r or r.security_model ~= 3 or not r.engine_id or #r.engine_id == 0 then
    return nil
  end
  local out = engine(r.engine_id)
  if r.boots then out.snmpEngineBoots = r.boots end
  if r.time then out.snmpEngineTime = fero.format_time(r.time) end
  local lines = {}
  for _, k in ipairs({ "enterprise", "engineIDFormat", "engineIDData", "snmpEngineBoots",
    "snmpEngineTime" }) do
    if out[k] ~= nil then lines[#lines + 1] = string.format("%s: %s", k, out[k]) end
  end
  return out, "\n  " .. table.concat(lines, "\n  ")
end
