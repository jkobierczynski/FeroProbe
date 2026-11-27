-- NSE compatibility layer: the `dnssd` module, DNS Service Discovery
-- (RFC 6763) over unicast mDNS (RFC 6762, UDP 5353). Written for
-- FeroProbe from nmap's public API documentation and the RFCs; not from
-- nselib. GPL-3.0-or-later, like FeroProbe.
--
-- Queries go to the scanned host only, through the `dns` module, so they
-- carry its transaction ID 0x4650 "FP" (IDS rule 9100043 on port 5353).
-- Multicast queries (the broadcast scripts) are refused: they would
-- reach every host on the link, outside the scan's scope.
local fero = ...
local dns = require "dns"
local stdnse = require "stdnse"

local dnssd = {}

local SERVICES = "_services._dns-sd._udp.local"
local DEVICE_INFO = "_device-info._tcp.local"
local NO_MULTICAST = "Multicast DNS-SD queries are not supported by FeroProbe (outside the scan's scope)"
local MAX_TYPES = 256

dnssd.Util = {}

---
-- Util.sortByPort(a, b): orders results by port number, entries without
-- a port (Device Information) last, then by name.
function dnssd.Util.sortByPort(a, b)
  local pa = tonumber(tostring(a.name):match("^(%d+)/")) or math.huge
  local pb = tonumber(tostring(b.name):match("^(%d+)/")) or math.huge
  if pa ~= pb then return pa < pb end
  return tostring(a.name) < tostring(b.name)
end

-- The records of both the answer and the additional section.
local function records(pkt)
  local out = {}
  for _, section in ipairs({ pkt.answers or {}, pkt.add or {} }) do
    for _, rec in ipairs(section) do out[#out + 1] = rec end
  end
  return out
end

dnssd.Comm = {}

---
-- Comm.sendQuery(host, port, name, dtype, timeout): one unicast query;
-- true and the decoded reply, or false and an error.
function dnssd.Comm.sendQuery(host, port, name, dtype, timeout)
  return dns.query(name, {
    host = host, port = port or 5353, dtype = dtype or "PTR",
    retPkt = true, timeout = timeout, sendCount = 1,
  })
end

---
-- Comm.queryAllServices(host, port, timeout): the service types the host
-- lists under _services._dns-sd._udp.local, or false and an error.
function dnssd.Comm.queryAllServices(host, port, timeout)
  local ok, pkt = dnssd.Comm.sendQuery(host, port, SERVICES, "PTR", timeout)
  if not ok then return false, pkt end
  local seen, types = {}, {}
  for _, rec in ipairs(records(pkt)) do
    if rec.dtype == dns.types.PTR and rec.domain and rec.dname:lower() == SERVICES
      and not seen[rec.domain:lower()] and #types < MAX_TYPES then
      seen[rec.domain:lower()] = true
      types[#types + 1] = rec.domain
    end
  end
  return true, types
end

-- One result entry from a service type's reply: the first SRV's port,
-- every non-empty TXT string, the first A and first AAAA address.
local function service_entry(stype, pkt)
  local srv, ipv4, ipv6
  local txt = {}
  for _, rec in ipairs(records(pkt)) do
    if rec.dtype == dns.types.SRV and rec.SRV and not srv then
      srv = rec.SRV
    elseif rec.dtype == dns.types.TXT and rec.TXT then
      for _, s in ipairs(rec.TXT.text) do
        if s ~= "" then txt[#txt + 1] = s end
      end
    elseif rec.dtype == dns.types.A and rec.ip and not ipv4 then
      ipv4 = rec.ip
    elseif rec.dtype == dns.types.AAAA and rec.ipv6 and not ipv6 then
      ipv6 = rec.ipv6
    end
  end
  local entry
  if stype:lower() == DEVICE_INFO then
    entry = { name = "Device Information" }
  else
    if not srv then return nil end
    local svc, proto = stype:match("^_?([^.]+)%._([^.]+)")
    if not svc then return nil end
    entry = { name = ("%d/%s %s"):format(srv.port, proto, svc) }
  end
  for _, s in ipairs(txt) do entry[#entry + 1] = s end
  local addrs = {}
  if ipv4 then addrs[#addrs + 1] = ipv4 end
  if ipv6 then addrs[#addrs + 1] = ipv6 end
  if #addrs > 0 then entry[#entry + 1] = "Address=" .. table.concat(addrs, " ") end
  return entry
end

dnssd.Helper = {}
dnssd.Helper.__index = dnssd.Helper

---
-- Helper:new(host, port): a helper for the host's mDNS port (default
-- 5353).
function dnssd.Helper:new(host, port)
  return setmetatable({ host = host, port = port, mcast = false, timeout = 5000 }, self)
end

---
-- Helper:setMulticast(flag): asks for multicast queries; queryServices
-- then fails, as FeroProbe sends none.
function dnssd.Helper:setMulticast(flag)
  self.mcast = flag and true or false
end

---
-- Helper:setTimeout(ms): the time to wait for each reply.
function dnssd.Helper:setTimeout(ms)
  self.timeout = tonumber(ms) or self.timeout
end

---
-- Helper:queryServices([service]): true and a list of entries, each
-- named "port/proto service" (or "Device Information") and holding the
-- TXT strings and an "Address=" line, sorted by port; or false and an
-- error. With service, only that type is asked for.
function dnssd.Helper:queryServices(service)
  if self.mcast or not self.host then return false, NO_MULTICAST end
  local types
  if service then
    types = { service }
  else
    local ok, t = dnssd.Comm.queryAllServices(self.host, self.port, self.timeout)
    if not ok then return false, t end
    types = t
  end
  local out = {}
  for _, stype in ipairs(types) do
    local ok, pkt = dnssd.Comm.sendQuery(self.host, self.port, stype, "PTR", self.timeout)
    if ok then
      local entry = service_entry(stype, pkt)
      if entry then out[#out + 1] = entry end
    else
      stdnse.debug2("dnssd: %s: %s", stype, tostring(pkt))
    end
  end
  table.sort(out, dnssd.Util.sortByPort)
  return true, out
end

return dnssd
