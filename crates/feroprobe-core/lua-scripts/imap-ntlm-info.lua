-- FeroProbe script: imap-ntlm-info
-- Written for FeroProbe from scratch, from RFC 9051 and RFC 3501
-- (AUTHENTICATE, STARTTLS) and [MS-NLMP] (through fero.ntlm);
-- GPL-3.0-or-later.

description = [[
Reads what an IMAP server that offers NTLM authentication (Microsoft
Exchange, for one) says about itself in its NTLM challenge: its NetBIOS
and DNS computer and domain names and the Windows version (its clock is
noted for clock-skew). Switches to TLS with STARTTLS where the server
offers it (otherwise it starts again in plain text), sends AUTHENTICATE
NTLM and an NTLM NEGOTIATE that names the workstation FEROPROBE and no
user, reads the challenge, then cancels the exchange ("*") and logs out.
Nothing logs in. Port 993 and services found to run over TLS are spoken
to over TLS from the start.

Script arguments:
  imap-ntlm-info.timeout  How long to wait for each reply, in
                          milliseconds (default 10000).
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "default", "discovery", "safe" }

portrule = fero.portrule.match({ 143, 993 }, { "imap", "imaps" })

local function tls(port)
  return port.number == 993 or port.service == "imaps"
    or (type(port.version) == "table" and port.version.service_tunnel == "ssl")
end

action = function(host, port)
  local timeout = tonumber(fero.args.get(SCRIPT_NAME .. ".timeout")) or 10000
  local sock
  if not tls(port) then
    sock = fero.starttls.connect(host, port, { protocol = "imap", timeout = timeout })
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
    if not greeting or not greeting:upper():match("^%* OK") then
      sock:close()
      return nil
    end
  end
  -- The next line that is not an untagged ("* ...") one.
  local function answer()
    for _ = 1, 1000 do
      local line = r:line()
      if not line or line:sub(1, 2) ~= "* " then return line end
    end
  end
  sock:send("fp1 AUTHENTICATE NTLM\r\n")
  local line = answer()
  local challenge
  if line and line:sub(1, 1) == "+" then
    sock:send(fero.ntlm.negotiate_base64() .. "\r\n")
    line = answer()
    if line and line:sub(1, 2) == "+ " then
      challenge = line:sub(3):match("^%s*(%S*)")
      sock:send("*\r\n")
      answer()
    end
  end
  sock:send("fp2 LOGOUT\r\n")
  sock:close()
  if not challenge then return nil end
  return fero.ntlm.info(fero.base64.decode(challenge))
end
