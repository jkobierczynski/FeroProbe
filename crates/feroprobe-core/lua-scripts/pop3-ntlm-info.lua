-- FeroProbe script: pop3-ntlm-info
-- Written for FeroProbe from scratch, from RFC 1939, RFC 5034 (AUTH),
-- RFC 2595 (STLS) and [MS-NLMP] (through fero.ntlm); GPL-3.0-or-later.

description = [[
Reads what a POP3 server that offers NTLM authentication (Microsoft
Exchange, for one) says about itself in its NTLM challenge: its NetBIOS
and DNS computer and domain names and the Windows version (its clock is
noted for clock-skew). Switches to TLS with STLS where the server allows
it (otherwise it starts again in plain text), sends AUTH NTLM and an
NTLM NEGOTIATE that names the workstation FEROPROBE and no user, reads
the challenge, then cancels the exchange ("*") and says QUIT. Nothing
logs in. Port 995 and services found to run over TLS are spoken to over
TLS from the start.

Script arguments:
  pop3-ntlm-info.timeout  How long to wait for each reply, in
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
  local sock
  if not tls(port) then
    sock = fero.starttls.connect(host, port, { protocol = "pop3", timeout = timeout })
  end
  local r
  if sock then
    r = fero.reader(sock)
  else
    sock = fero.socket.new()
    sock:set_timeout(timeout)
    if not sock:connect(host, port, tls(port) and "ssl" or "tcp") then return nil end
    r = fero.reader(sock)
    local greeting = r:line()
    if not greeting or greeting:sub(1, 3) ~= "+OK" then
      sock:close()
      return nil
    end
  end
  sock:send("AUTH NTLM\r\n")
  local line = r:line()
  local challenge
  if line and line:sub(1, 1) == "+" and line:sub(1, 3) ~= "+OK" then
    sock:send(fero.ntlm.negotiate_base64() .. "\r\n")
    line = r:line()
    if line and line:sub(1, 2) == "+ " then
      challenge = line:sub(3):match("^%s*(%S*)")
      sock:send("*\r\n")
      r:line()
    end
  end
  sock:send("QUIT\r\n")
  sock:close()
  if not challenge then return nil end
  return fero.ntlm.info(fero.base64.decode(challenge))
end
