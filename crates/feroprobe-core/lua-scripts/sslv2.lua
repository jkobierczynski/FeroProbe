-- FeroProbe script: sslv2
-- Written for FeroProbe from scratch, from the SSL 2.0 draft (Hickman,
-- 1995: CLIENT-HELLO and SERVER-HELLO); GPL-3.0-or-later.

description = [[
Says whether a server still speaks the obsolete SSL 2.0, and lists the
SSLv2 ciphers it takes: sends one SSLv2 CLIENT-HELLO offering every
SSLv2 cipher kind and reads the SERVER-HELLO. No handshake is finished
and no key is sent.

The CLIENT-HELLO's challenge is "FeroProbeTLSScan" (see fero.tls).

Script arguments:
  sslv2.timeout  How long to wait for the answer, in milliseconds
                 (default 5000).
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "default", "safe" }

portrule = fero.portrule.ssl

action = function(host, port)
  local timeout = tonumber(fero.args.get(SCRIPT_NAME .. ".timeout")) or 5000
  local sock, err = fero.tls.connect(host, port, { timeout = timeout })
  if not sock then
    fero.debug(1, "connect failed: " .. tostring(err))
    return nil
  end
  local ok, serr = sock:send(fero.tls.sslv2_client_hello())
  if not ok then
    sock:close()
    fero.debug(1, "send failed: " .. tostring(serr))
    return nil
  end
  local hello, why = fero.tls.sslv2_read_server_hello(sock, timeout)
  sock:close()
  if not hello then
    fero.debug(1, "no SSLv2: " .. tostring(why))
    return nil
  end
  local out = { "SSLv2 supported" }
  if #hello.ciphers > 0 then
    out.ciphers = hello.ciphers
  else
    out.ciphers = "none"
  end
  return out
end
