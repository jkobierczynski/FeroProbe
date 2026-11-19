-- FeroProbe script: nntp-ntlm-info
-- Written for FeroProbe from scratch, from RFC 3977, RFC 4642
-- (STARTTLS), RFC 2980 (AUTHINFO GENERIC) and [MS-NLMP] (through
-- fero.ntlm); GPL-3.0-or-later.

description = [[
Reads what a news (NNTP) server that offers NTLM authentication
(Microsoft's NNTP service, for one) says about itself in its NTLM
challenge: its NetBIOS and DNS computer and domain names and the Windows
version (its clock is noted for clock-skew). Switches to TLS with
STARTTLS where the server allows it (otherwise it starts again in plain
text), sends AUTHINFO GENERIC NTLM and an NTLM NEGOTIATE that names the
workstation FEROPROBE and no user, reads the challenge and says QUIT.
Nothing logs in. Port 563 and services found to run over TLS are spoken
to over TLS from the start.

Script arguments:
  nntp-ntlm-info.timeout  How long to wait for each reply, in
                          milliseconds (default 10000).
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "default", "discovery", "safe" }

portrule = fero.portrule.match({ 119, 433, 563 }, { "nntp", "snews" })

local function tls(port)
  return port.number == 563 or port.service == "snews"
    or (type(port.version) == "table" and port.version.service_tunnel == "ssl")
end

action = function(host, port)
  local timeout = tonumber(fero.args.get(SCRIPT_NAME .. ".timeout")) or 10000
  local sock
  if not tls(port) then
    sock = fero.starttls.connect(host, port, { protocol = "nntp", timeout = timeout })
  end
  local r
  if sock then
    r = fero.reader(sock)
  else
    sock = fero.socket.new()
    sock:set_timeout(timeout)
    if not sock:connect(host, port, tls(port) and "ssl" or "tcp") then return nil end
    r = fero.reader(sock)
    local code = r:reply()
    if code ~= 200 and code ~= 201 then
      sock:close()
      return nil
    end
  end
  sock:send("AUTHINFO GENERIC NTLM\r\n")
  local challenge, received
  if r:reply() == 381 then
    sock:send("AUTHINFO GENERIC " .. fero.ntlm.negotiate_base64() .. "\r\n")
    local code, lines = r:reply()
    if code == 381 then
      challenge = lines[1]:sub(5):match("^%s*(%S*)")
      received = os.time()
    end
  end
  sock:send("QUIT\r\n")
  sock:close()
  if not challenge then return nil end
  return fero.ntlm.info(fero.base64.decode(challenge), { received = received })
end
