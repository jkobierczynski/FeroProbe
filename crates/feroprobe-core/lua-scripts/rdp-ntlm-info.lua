-- FeroProbe script: rdp-ntlm-info
-- Written for FeroProbe from scratch, from [MS-RDPBCGR] 2.2.1.1 and
-- 2.2.1.2 (connection request and confirm), [MS-CSSP] 2.2.1 (TSRequest)
-- and [MS-NLMP] (through fero.ntlm); GPL-3.0-or-later.

description = [[
Reads what a Remote Desktop server says about itself in the NTLM
challenge of a Network Level Authentication (CredSSP) exchange: its
NetBIOS and DNS computer and domain names, the Windows version and its
clock. Asks for TLS and CredSSP in the connection request, sends an NTLM
NEGOTIATE inside a CredSSP message over TLS, reads the server's
CHALLENGE and closes; no credentials are sent and nothing logs in. A
server that does not offer CredSSP gives no output.

The connection request carries the routing cookie
"Cookie: mstshash=FeroProbe", so the server's logs name the client.

Script arguments:
  rdp-ntlm-info.timeout  How long to wait for each answer, in
                         milliseconds (default 8000).
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "default", "discovery", "safe" }

portrule = fero.portrule.match({ 3389 }, { "ms-wbt-server" })

local COOKIE = "Cookie: mstshash=FeroProbe\r\n"

-- A DER element: tag, length, content.
local function der(tag, content)
  local n = #content
  local len
  if n < 0x80 then
    len = string.char(n)
  elseif n < 0x100 then
    len = string.char(0x81, n)
  else
    len = string.char(0x82) .. string.pack(">I2", n)
  end
  return string.char(tag) .. len .. content
end

-- The connection request: TPKT, X.224 CR, the cookie, and an RDP
-- negotiation request for TLS and CredSSP.
local function connection_request()
  local neg = string.pack("<BBI2I4", 0x01, 0, 8, 0x00000003)
  local x224 = string.char(0xe0, 0, 0, 0, 0, 0) .. COOKIE .. neg
  x224 = string.char(#x224) .. x224
  return string.pack(">BBI2", 3, 0, #x224 + 4) .. x224
end

-- A TSRequest (version 2) carrying `token`.
local function ts_request(token)
  return der(0x30,
    der(0xa0, der(0x02, "\2"))
    .. der(0xa1, der(0x30, der(0x30, der(0xa0, der(0x04, token))))))
end

local MAX_REPLY = 65536

-- Read one DER element (the TSRequest reply) whole.
local function read_der(r)
  local head, err = r:bytes(2)
  if not head then return nil, err end
  local tag, n = head:byte(1, 2)
  if tag ~= 0x30 then return nil, "not a TSRequest" end
  if n >= 0x80 then
    local k = n & 0x7f
    if k < 1 or k > 3 then return nil, "bad length" end
    local more = r:bytes(k)
    if not more then return nil, "short reply" end
    n = 0
    for i = 1, k do n = (n << 8) | more:byte(i) end
  end
  if n > MAX_REPLY then return nil, "reply too long" end
  return r:bytes(n)
end

local LABELS = {
  { "target_name", "Target_Name" },
  { "netbios_domain", "NetBIOS_Domain_Name" },
  { "netbios_computer", "NetBIOS_Computer_Name" },
  { "dns_domain", "DNS_Domain_Name" },
  { "dns_computer", "DNS_Computer_Name" },
  { "dns_tree", "DNS_Tree_Name" },
  { "version", "Product_Version" },
}

action = function(host, port)
  local timeout = tonumber(fero.args.get(SCRIPT_NAME .. ".timeout")) or 8000
  local sock = fero.socket.new()
  sock:set_timeout(timeout)
  if not sock:connect(host, port) then return nil end
  local function done(...)
    sock:close()
    return ...
  end
  if not sock:send(connection_request()) then return done(nil) end
  local r = fero.reader(sock)
  local tpkt = r:bytes(4)
  if not tpkt or tpkt:byte(1) ~= 3 then return done(nil) end
  local len = string.unpack(">I2", tpkt, 3)
  if len < 4 + 7 + 8 or len > 1024 then return done(nil) end
  local cc = r:bytes(len - 4)
  -- X.224 connection confirm, then an RDP negotiation response (type 2)
  -- that selects CredSSP (2) or CredSSP with early user authorization (8).
  if not cc or cc:byte(2) ~= 0xd0 then return done(nil) end
  local kind, _, _, selected = string.unpack("<BBI2I4", cc, #cc - 7)
  if kind ~= 2 or selected & 0x0a == 0 then return done(nil) end
  if not sock:reconnect_ssl() then return done(nil) end
  if not sock:send(ts_request(fero.ntlm.negotiate_message())) then return done(nil) end
  local reply = read_der(fero.reader(sock))
  sock:close()
  if not reply then return nil end
  local c = fero.ntlm.parse_challenge(reply)
  if not c then return nil end
  local data, lines = {}, {}
  for _, l in ipairs(LABELS) do
    if c[l[1]] then
      data[l[2]] = c[l[1]]
      lines[#lines + 1] = l[2] .. ": " .. c[l[1]]
    end
  end
  if c.timestamp then
    data.System_Time = os.date("!%Y-%m-%dT%H:%M:%S+00:00", c.timestamp)
    lines[#lines + 1] = "System_Time: " .. data.System_Time
  end
  if #lines == 0 then return nil end
  return data, "\n  " .. table.concat(lines, "\n  ")
end
