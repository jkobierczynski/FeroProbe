-- FeroProbe script: tls-nextprotoneg
-- Written for FeroProbe from scratch, from draft-agl-tls-nextprotoneg-04
-- (Next Protocol Negotiation); GPL-3.0-or-later.

description = [[
Lists the protocols a TLS server advertises through NPN (Next Protocol
Negotiation, the extension SPDY used before ALPN): sends one TLS 1.2
ClientHello with an empty NPN extension and lists the protocols in the
server's answer, in its order. No handshake is finished.

The ClientHello random carries "FeroProbeTLSScan" (see fero.tls).

Script arguments:
  tls-nextprotoneg.timeout  How long to wait for the answer, in
                            milliseconds (default 5000).
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "discovery", "safe", "default" }

portrule = fero.portrule.ssl

action = function(host, port)
  local timeout = tonumber(fero.args.get(SCRIPT_NAME .. ".timeout")) or 5000
  local answer, err = fero.tls.hello(host, port, {
    version = 0x0303, npn = true, timeout = timeout, hello_only = true,
  })
  if not answer then
    fero.debug(1, "no answer: " .. tostring(err))
    return nil
  end
  local sh = answer.server_hello
  if not sh or not sh.npn or #sh.npn == 0 then return nil end
  return sh.npn
end
