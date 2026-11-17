-- FeroProbe script: pop3-capabilities
-- Written for FeroProbe from scratch (RFC 2449, RFC 1939); GPL-3.0-or-later.

description = [[
Lists the capabilities a POP3 server announces in its answer to CAPA,
such as TOP, UIDL, SASL mechanisms and STLS; APOP too when the greeting
carries an APOP timestamp. Logs in to nothing. Port 995 and services
found to run over TLS are spoken to over TLS.

Script arguments:
  pop3-capabilities.timeout  How long to wait for each reply, in
                             milliseconds (default 10000).
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "default", "discovery", "safe" }

portrule = fero.portrule.match({ 110, 995 }, { "pop3", "pop3s" })

local function tls(port)
  return port.number == 995 or port.service == "pop3s"
    or (type(port.version) == "table" and port.version.service_tunnel == "ssl")
end

action = function(host, port)
  local timeout = tonumber(fero.args.get(SCRIPT_NAME .. ".timeout")) or 10000
  local sock = fero.socket.new()
  sock:set_timeout(timeout)
  if not sock:connect(host, port, tls(port) and "ssl" or "tcp") then return nil end
  local r = fero.reader(sock)
  local greeting = r:line()
  if not greeting or greeting:sub(1, 3) ~= "+OK" then
    sock:close()
    return nil
  end
  local caps, names = {}, {}
  local function add(name, args)
    if caps[name] == nil then names[#names + 1] = name end
    caps[name] = args
  end
  sock:send("CAPA\r\n")
  local line = r:line()
  if line and line:sub(1, 3) == "+OK" then
    for _ = 1, 1000 do
      line = r:line()
      if not line or line == "." then break end
      local name, args = line:match("^(%S+)%s*(.-)%s*$")
      if name then add(name:upper(), args ~= "" and args or true) end
    end
  end
  if greeting:find("<[^>]+@[^>]+>") then add("APOP", true) end
  sock:send("QUIT\r\n")
  sock:close()
  if #names == 0 then return nil end
  local out = {}
  for _, name in ipairs(names) do
    local args = caps[name]
    out[#out + 1] = args == true and name or (name .. "(" .. args .. ")")
  end
  return caps, table.concat(out, " ")
end
