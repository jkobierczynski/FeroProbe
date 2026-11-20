-- FeroProbe script: tls-alpn
-- Written for FeroProbe from scratch, from RFC 7301 (ALPN) and the IANA
-- ALPN protocol ID registry; GPL-3.0-or-later.

description = [[
Lists the application protocols a TLS server takes through ALPN
(Application-Layer Protocol Negotiation, RFC 7301): sends a TLS 1.2
ClientHello offering the registered protocol IDs, notes the one the
server picks, and asks again without it until the server picks none.
The protocols are listed in the order the server picked them, which is
usually its own order of preference. No handshake is finished.

TLS 1.3 servers put their choice in an encrypted message, so the hellos
ask for TLS 1.2; a server that speaks only TLS 1.3 gives no output.

The ClientHello random carries "FeroProbeTLSScan" (see fero.tls).

Script arguments:
  tls-alpn.timeout  How long to wait for each answer, in milliseconds
                    (default 5000).
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "discovery", "safe", "default" }

portrule = fero.portrule.ssl

-- The IANA registry's protocol IDs, most used first (acme-tls/1 is left
-- out: it asks an ACME client for a validation certificate).
local PROTOCOLS = {
  "h2", "http/1.1", "http/1.0", "http/0.9", "spdy/3", "spdy/2", "spdy/1",
  "h3", "h2c", "stun.turn", "stun.nat-discovery", "webrtc", "c-webrtc",
  "ftp", "imap", "pop3", "managesieve", "coap", "xmpp-client",
  "xmpp-server", "mqtt", "dot", "ntske/1", "sunrpc", "smb", "irc", "nntp",
  "nnsp", "doq", "sip/2", "tds/8.0", "dicom", "postgresql", "radius/1.0",
  "radius/1.1",
}

action = function(host, port)
  local timeout = tonumber(fero.args.get(SCRIPT_NAME .. ".timeout")) or 5000
  local offer = {}
  for i, p in ipairs(PROTOCOLS) do offer[i] = p end
  local chosen = {}
  while #offer > 0 do
    local answer, err = fero.tls.hello(host, port, {
      version = 0x0303, alpn = offer, timeout = timeout, hello_only = true,
    })
    if not answer then
      fero.debug(1, "no answer: " .. tostring(err))
      break
    end
    local sh = answer.server_hello
    if not sh or not sh.alpn then break end
    local found
    for i, p in ipairs(offer) do
      if p == sh.alpn then found = i end
    end
    if not found then
      -- A protocol it was not offered: a server that ignores the list.
      fero.debug(1, "server chose " .. sh.alpn .. ", which was not offered")
      break
    end
    chosen[#chosen + 1] = sh.alpn
    table.remove(offer, found)
  end
  if #chosen == 0 then return nil end
  return chosen
end
