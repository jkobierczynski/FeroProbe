-- FeroProbe script: snmp-sysdescr
-- Written for FeroProbe from scratch, from RFC 1213 / RFC 3418 (the
-- SNMPv2-MIB system group); GPL-3.0-or-later.

description = [[
Asks an SNMP agent for its system description (sysDescr.0), which names
the device, its operating system and often its version, and for how long
it has been up (sysUpTime.0).

Sends two GetRequests (each sent twice at most) with community "public"
(creds.snmp sets another) to UDP 161, or a UDP port -sV named snmp, only
when that port was scanned (-sU -p U:161). Every request has request-id
0x4650 ("FP").

Script arguments (of the SNMP library):
  creds.snmp     The community ("private", or nmap's form ":private").
  snmp.version   v1 (default) or v2c.
  snmp.timeout   How long to wait for each answer (default 5000 ms; a
                 number is milliseconds, or give a unit: 5s).
  snmp.retries   How often a request is sent again (default 1).
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "default", "discovery", "safe" }

portrule = fero.portrule.match({ 161 }, { "snmp" }, "udp")

local SYSDESCR = "1.3.6.1.2.1.1.1.0"
local SYSUPTIME = "1.3.6.1.2.1.1.3.0"

-- The value of the one variable `oid` asked for, with its tag, or nil.
local function get(s, oid)
  local r = s:get(oid)
  if not r or r.error_status ~= 0 or #r.varbinds ~= 1 then return nil end
  local vb = r.varbinds[1]
  if vb.exception then return nil end
  return vb.value, vb.tag
end

action = function(host, port)
  local s = fero.snmp.session(host, port)
  if not s then return nil end
  local descr, tag = get(s, SYSDESCR)
  if type(descr) ~= "string" or tag ~= fero.snmp.TAG.octets then
    s:close()
    return nil
  end
  local ticks, ttag = get(s, SYSUPTIME)
  s:close()
  descr = descr:gsub("\r\n", "\n")
  local out = fero.output_table()
  out.description = descr
  local text = descr
  if math.type(ticks) == "integer" and ttag == fero.snmp.TAG.timeticks then
    out.uptime = fero.snmp.format_ticks(ticks)
    out.timeticks = ticks
    text = text .. string.format("\n  System uptime: %s (%d timeticks)", out.uptime, ticks)
  end
  return out, text
end
