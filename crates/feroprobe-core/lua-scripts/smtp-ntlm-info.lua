-- FeroProbe script: smtp-ntlm-info
-- Written for FeroProbe from scratch, from RFC 5321, RFC 4954 (AUTH),
-- RFC 3207 (STARTTLS) and [MS-NLMP] (through fero.ntlm);
-- GPL-3.0-or-later.

description = [[
Reads what a mail server that offers NTLM authentication (Microsoft
Exchange, for one) says about itself in its NTLM challenge: its NetBIOS
and DNS computer and domain names and the Windows version (its clock is
noted for clock-skew). Says EHLO feroprobe.invalid, switches to TLS with
STARTTLS where the server allows it (some servers take AUTH only then;
otherwise it starts again in plain text), sends AUTH NTLM and an NTLM
NEGOTIATE that names the workstation FEROPROBE and no user, reads the
challenge, then cancels the exchange ("*") and says QUIT. Nothing logs
in. Port 465 and services found to run over TLS are spoken to over TLS
from the start.

Script arguments:
  smtp.domain                The name to send with EHLO instead.
  smtp-ntlm-info.domain      The same, for this script only (nmap's
                             argument name).
  smtp-ntlm-info.timeout     How long to wait for each reply, in
                             milliseconds (default 10000).
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "default", "discovery", "safe" }

portrule = fero.portrule.match({ 25, 465, 587 }, { "smtp", "smtps", "submission" })

local function tls(port)
  return port.number == 465 or port.service == "smtps" or port.service == "submissions"
    or (type(port.version) == "table" and port.version.service_tunnel == "ssl")
end

local function ehlo_name()
  local domain = fero.args.get(SCRIPT_NAME .. ".domain")
  if type(domain) ~= "string" then domain = fero.args.get("smtp.domain") end
  if type(domain) ~= "string" or not domain:match("^[%w%.%-%[%]:]+$") then
    domain = "feroprobe.invalid"
  end
  return domain
end

action = function(host, port)
  local timeout = tonumber(fero.args.get(SCRIPT_NAME .. ".timeout")) or 10000
  local name = ehlo_name()
  local sock
  if not tls(port) then
    sock = fero.starttls.connect(host, port, { protocol = "smtp", timeout = timeout, domain = name })
  end
  local r
  if sock then
    r = fero.reader(sock)
  else
    sock = fero.socket.new()
    sock:set_timeout(timeout)
    if not sock:connect(host, port, tls(port) and "ssl" or "tcp") then return nil end
    r = fero.reader(sock)
    if r:reply() ~= 220 then
      sock:close()
      return nil
    end
  end
  local function done(...)
    sock:close()
    return ...
  end
  sock:send("EHLO " .. name .. "\r\n")
  if r:reply() ~= 250 then return done(nil) end
  sock:send("AUTH NTLM\r\n")
  if r:reply() ~= 334 then
    sock:send("QUIT\r\n")
    return done(nil)
  end
  sock:send(fero.ntlm.negotiate_base64() .. "\r\n")
  local code, lines = r:reply()
  local received = os.time()
  if code == 334 then
    sock:send("*\r\n")
    r:reply()
  end
  sock:send("QUIT\r\n")
  sock:close()
  if code ~= 334 then return nil end
  return fero.ntlm.info(fero.base64.decode(lines[1]:sub(5):match("^%s*(%S*)")),
    { received = received })
end
