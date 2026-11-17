-- FeroProbe script: ssl-cert
-- Written for FeroProbe from scratch; GPL-3.0-or-later, like FeroProbe.

description = [[
Shows the certificate a TLS service presents: its subject and subject
alternative names, issuer, public key, signature algorithm, validity
dates and SHA-1 and SHA-256 fingerprints; with -v, the certificate in
PEM form too. The certificate is read, never checked or trusted.

Runs on ports where -sV found TLS, or whose service or port number is a
TLS one. Services that switch to TLS on request (STARTTLS) are not
covered yet. TLS 1.2 and 1.3 only.
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "default", "discovery", "safe" }

portrule = fero.portrule.ssl

action = function(host, port)
  local sock = fero.socket.new()
  sock:set_timeout(10000)
  local ok, err = sock:connect(host, port, "ssl")
  if not ok then
    fero.debug(1, "TLS connection failed: " .. tostring(err))
    return nil
  end
  local cert, why = sock:get_ssl_certificate()
  sock:close()
  if not cert then
    fero.debug(1, "no certificate: " .. tostring(why))
    return nil
  end
  local lines = {}
  local function add(s) lines[#lines + 1] = s end
  add("Subject: " .. cert.subject_text)
  if #cert.san > 0 then
    add("Subject Alternative Name: " .. table.concat(cert.san, ", "))
  end
  add("Issuer: " .. cert.issuer_text)
  add("Public Key type: " .. tostring(cert.pubkey.type))
  if cert.pubkey.bits then
    add("Public Key bits: " .. cert.pubkey.bits)
  end
  add("Signature Algorithm: " .. cert.sig_algorithm)
  add("Not valid before: " .. cert.validity.notBefore)
  add("Not valid after:  " .. cert.validity.notAfter)
  add("SHA-1:   " .. cert.sha1)
  add("SHA-256: " .. cert.sha256)
  if fero.verbosity() >= 1 then
    add(cert.pem:gsub("\n$", ""))
  end
  local data = {
    subject = cert.subject,
    issuer = cert.issuer,
    pubkey = cert.pubkey,
    sig_algo = cert.sig_algorithm,
    validity = cert.validity,
    san = cert.san,
    sha1 = cert.sha1,
    sha256 = cert.sha256,
    pem = cert.pem,
  }
  return data, table.concat(lines, "\n")
end
