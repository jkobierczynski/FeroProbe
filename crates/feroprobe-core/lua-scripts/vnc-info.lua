-- FeroProbe script: vnc-info
-- Written for FeroProbe from scratch (RFC 6143, the RFB protocol);
-- GPL-3.0-or-later.

description = [[
Reads the RFB (VNC) protocol version a server offers and the security
types it accepts, such as "VNC Authentication" or "None", which means
anyone can connect. Answers the version handshake, reads the list and
closes the connection without choosing a type, so nothing logs in.

Script arguments:
  vnc-info.timeout  How long to wait for each answer, in milliseconds
                    (default 8000).
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "default", "discovery", "safe" }

local VNC_PORTS = {}
for p = 5900, 5910 do VNC_PORTS[#VNC_PORTS + 1] = p end
portrule = fero.portrule.match(VNC_PORTS, { "vnc" })

-- Security types by number: RFC 6143 section 7.1.2 and the IANA RFB
-- registry.
local TYPES = {
  [0] = "Invalid", [1] = "None", [2] = "VNC Authentication",
  [5] = "RA2", [6] = "RA2ne", [16] = "Tight", [17] = "Ultra", [18] = "TLS",
  [19] = "VeNCrypt", [20] = "GTK-VNC SASL", [21] = "MD5 hash authentication",
  [22] = "Colin Dean xvp", [30] = "Apple Remote Desktop",
}

action = function(host, port)
  local timeout = tonumber(fero.args.get(SCRIPT_NAME .. ".timeout")) or 8000
  local sock = fero.socket.new()
  sock:set_timeout(timeout)
  if not sock:connect(host, port) then return nil end
  local r = fero.reader(sock)
  local hello = r:bytes(12)
  local major, minor = (hello or ""):match("^RFB (%d%d%d)%.(%d%d%d)\n$")
  if not major then
    sock:close()
    return nil
  end
  major, minor = tonumber(major), tonumber(minor)
  -- Answer with the highest version both sides know (3.3, 3.7 or 3.8).
  local mine = 3
  if major > 3 or minor >= 8 then mine = 8 elseif minor >= 7 then mine = 7 end
  sock:send(string.format("RFB 003.%03d\n", mine))
  local data = { ["Protocol version"] = major .. "." .. minor }
  local lines = { "Protocol version: " .. data["Protocol version"] }
  local types = {}
  if mine == 3 then
    local b = r:bytes(4)
    if b then types[1] = string.unpack(">I4", b) end
  else
    local b = r:bytes(1)
    local n = b and b:byte() or 0
    local list = n > 0 and r:bytes(n) or nil
    if list then
      for i = 1, #list do types[#types + 1] = list:byte(i) end
    end
  end
  if #types == 0 or types[1] == 0 then
    -- The server refuses, with a reason (RFC 6143 section 7.1.2).
    local b = r:bytes(4)
    local reason = b and r:bytes(math.min(string.unpack(">I4", b), 1024))
    sock:close()
    if reason then
      reason = reason:gsub("[^\32-\126]", "?")
      data["Error"] = reason
      lines[#lines + 1] = "Error: " .. reason
      return data, "\n  " .. table.concat(lines, "\n  ")
    end
    return nil
  end
  sock:close()
  local named = {}
  lines[#lines + 1] = "Security types:"
  for _, t in ipairs(types) do
    local name = (TYPES[t] or "Unknown security type") .. " (" .. t .. ")"
    named[#named + 1] = name
    lines[#lines + 1] = "  " .. name
  end
  data["Security types"] = named
  for _, t in ipairs(types) do
    if t == 1 then
      lines[#lines + 1] = "WARNING: the server accepts connections without authentication"
      break
    end
  end
  return data, "\n  " .. table.concat(lines, "\n  ")
end
