-- NSE compatibility layer: the `knx` module, KNXnet/IP (ISO/IEC 14543-3)
-- headers, addresses and requests. Written for FeroProbe from nmap's
-- public API documentation (not from nselib) and the KNXnet/IP
-- specification's field layout and code values; GPL-3.0-or-later, like
-- FeroProbe.
local ipOps = require "ipOps"
local knx = {}

-- Code values from the KNXnet/IP specification, named in FeroProbe's
-- own words.
knx.knxServiceFamilies = {
  [0x02] = "KNXnet/IP Core",
  [0x03] = "KNXnet/IP Device Management",
  [0x04] = "KNXnet/IP Tunnelling",
  [0x05] = "KNXnet/IP Routing",
  [0x06] = "KNXnet/IP Remote Logging",
  [0x07] = "KNXnet/IP Remote Configuration and Diagnosis",
  [0x08] = "KNXnet/IP Object Server",
}

knx.knxMediumTypes = {
  [0x01] = "reserved",
  [0x02] = "KNX TP1",
  [0x04] = "KNX PL110",
  [0x08] = "reserved",
  [0x10] = "KNX RF",
  [0x20] = "KNX IP",
}

knx.knxDibDescriptionTypes = {
  [0x01] = "DEVICE_INFO",
  [0x02] = "SUPP_SVC_FAMILIES",
  [0x03] = "IP_CONFIG",
  [0x04] = "IP_CUR_CONFIG",
  [0x05] = "KNX_ADDRESSES",
  [0xFE] = "MFR_DATA",
}

local HEADER_LEN = 0x06
local VERSION = 0x10

-- The fixed 6-byte header of a KNXnet/IP message: header length, protocol
-- version, service type, total length, and the position just after it;
-- nil and a message when there is no whole header.
knx.parseHeader = function(knxMessage)
  if type(knxMessage) ~= "string" or #knxMessage < HEADER_LEN then
    return nil, "KNX message too short for a header"
  end
  local hlen, version, service, total, pos = string.unpack(">BBI2I2", knxMessage)
  if hlen ~= HEADER_LEN then
    return nil, "not a KNXnet/IP header (header length " .. hlen .. ")"
  end
  return hlen, version, service, total, pos
end

-- A 16-bit KNX individual address as area.line.device.
knx.parseKnxAddress = function(addr)
  addr = math.tointeger(addr) or 0
  return string.format("%d.%d.%d", (addr >> 12) & 0x0F, (addr >> 8) & 0x0F, addr & 0xFF)
end

-- A KNXnet/IP request of type service (a search or description request)
-- whose HPAI asks for the answer at ip_address:port over UDP.
knx.query = function(service, ip_address, port)
  local ip = ipOps.ip_to_str(ip_address)
  if not ip or #ip ~= 4 then ip = "\0\0\0\0" end
  local hpai = string.pack(">BB", 0x08, 0x01) .. ip .. string.pack(">I2", port)
  return string.pack(">BBI2I2", HEADER_LEN, VERSION, service, HEADER_LEN + #hpai) .. hpai
end

return knx
