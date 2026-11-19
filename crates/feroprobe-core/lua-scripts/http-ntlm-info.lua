-- FeroProbe script: http-ntlm-info
-- Written for FeroProbe from scratch, from RFC 4559 (the NTLM/Negotiate
-- HTTP exchange) and [MS-NLMP] (through fero.ntlm); GPL-3.0-or-later.

description = [[
Reads what a web server that offers NTLM authentication says about
itself in its NTLM challenge: its NetBIOS and DNS computer and domain
names and the Windows version (its clock is noted for clock-skew).
Sends one GET with "Authorization: NTLM" and an NTLM NEGOTIATE that
names the workstation FEROPROBE and no user, and reads the challenge in
the WWW-Authenticate header of the 401 answer; nothing logs in. The
request carries FeroProbe's User-Agent.

Script arguments:
  http-ntlm-info.root  The path to ask for (default "/"), one that needs
                       authentication.
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "default", "discovery", "safe" }

portrule = fero.portrule.http

action = function(host, port)
  local root = fero.args.get(SCRIPT_NAME .. ".root")
  if type(root) ~= "string" or root == "" then root = "/" end
  local resp, err = fero.http.get(host, port, root, {
    header = { Authorization = "NTLM " .. fero.ntlm.negotiate_base64() },
  })
  if not resp then
    fero.debug(1, "request failed: " .. tostring(err))
    return nil
  end
  local received = os.time()
  local auth = resp.header["www-authenticate"]
  if not auth then return nil end
  -- Several challenges may share the header ("Negotiate, NTLM TlRM...");
  -- the scheme name is case-insensitive (RFC 9110 11.1).
  local blob = auth:match("%f[%w][Nn][Tt][Ll][Mm] +([A-Za-z0-9+/=]+)")
  if not blob then return nil end
  return fero.ntlm.info(fero.base64.decode(blob), { received = received })
end
