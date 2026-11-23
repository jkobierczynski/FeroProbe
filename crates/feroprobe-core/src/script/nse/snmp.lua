-- NSE compatibility layer: the `snmp` module's Helper, reads over
-- SNMPv1 and v2c (fero.snmp). Written for FeroProbe from nmap's public
-- API documentation (not from nselib) and RFC 1157 and 3416;
-- GPL-3.0-or-later, like FeroProbe. FeroProbe never writes to a device:
-- SetRequest is refused, as are the raw BER encoders.
local fero = ...
local snmp = {}

local function oid_text(o)
  if type(o) == "table" then return table.concat(o, ".") end
  return (tostring(o):gsub("^%.", ""))
end

-- A dotted OID as a list of numbers, and back.
function snmp.str2oid(s)
  local t = {}
  for a in tostring(s):gmatch("%d+") do t[#t + 1] = tonumber(a) end
  return t
end
function snmp.oid2str(t) return oid_text(t) end

local Helper = {}
Helper.__index = Helper
snmp.Helper = Helper

-- A helper for `port` on `host`. `community` replaces the one
-- --script-args give (creds.snmp, else "public"); `options` may set
-- version (0 v1, 1 v2c) and timeout (ms).
function Helper:new(host, port, community, options)
  local o = {}
  if type(options) == "table" then
    o.version = options.version
    o.timeout = options.timeout
  end
  if type(community) == "string" then o.community = community end
  return setmetatable({ host = host, port = port, opts = o }, self)
end

-- Open the UDP socket: true, or false and a message.
function Helper:connect()
  local s, err = fero.snmp.session(self.host, self.port, self.opts)
  if not s then return false, err end
  self.session = s
  return true
end

local function answer(r, err)
  if not r then return false, err end
  if r.error_status ~= 0 then return false, "SNMP error " .. tostring(r.error_status) end
  local out = {}
  for i, vb in ipairs(r.varbinds) do
    out[i] = { vb.value, vb.oid }
  end
  return true, out
end

-- GetRequest for the OIDs: true and { { value, oid }, ... }, or false
-- and a message.
function Helper:get(_, ...)
  if not self.session and not self:connect() then return false, "not connected" end
  local oids = {}
  for i, o in ipairs({ ... }) do oids[i] = oid_text(o) end
  return answer(self.session:get(table.unpack(oids)))
end

-- GetNextRequest for one OID, answered as Helper:get.
function Helper:getnext(_, o)
  if not self.session and not self:connect() then return false, "not connected" end
  return answer(self.session:getnext(oid_text(o)))
end

-- The variables under `base`, in order: true and { { oid, value }, ... },
-- or false and a message.
function Helper:walk(base)
  if not self.session and not self:connect() then return false, "not connected" end
  local list, err = self.session:walk(oid_text(base))
  if not list then return false, err end
  local out = {}
  for i, vb in ipairs(list) do out[i] = { oid = vb.oid, value = vb.value } end
  return true, out
end

function Helper:set()
  return false, "FeroProbe does not write to devices (SNMP SetRequest refused)"
end

function Helper:close()
  if self.session then self.session:close() end
  self.session = nil
end

for _, name in ipairs({ "encode", "decode", "buildPacket", "buildGetRequest",
  "buildGetNextRequest", "buildSetRequest", "buildTrap", "buildGetResponse" }) do
  snmp[name] = function()
    error("snmp." .. name .. " is not available in FeroProbe", 2)
  end
end

return snmp
