-- NSE compatibility layer: the `sslcert` module, certificates over TLS
-- and over the protocols that switch to TLS on request (fero.starttls).
-- Written for FeroProbe from nmap's public API documentation (not from
-- nselib); GPL-3.0-or-later, like FeroProbe. TLS 1.2 and 1.3 only, as
-- for every FeroProbe TLS connection; the certificate is read, never
-- checked or trusted.
local fero = ...
local nmap = require "nmap"
local sslcert = {}

-- "YYYY-MM-DDTHH:MM:SS" as nmap's date table; the text itself when it
-- does not read.
local function date_table(s)
  local y, mo, d, h, mi, se = tostring(s):match("^(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)$")
  if not y then return s end
  return {
    year = tonumber(y), month = tonumber(mo), day = tonumber(d),
    hour = tonumber(h), min = tonumber(mi), sec = tonumber(se),
  }
end

local function tunnelled(port)
  return type(port.version) == "table" and port.version.service_tunnel == "ssl"
end

local Cert = {}
Cert.__index = Cert

-- cert:digest(name): the certificate's digest, raw bytes ("md5", "sha1",
-- "sha256", "sha384", "sha512").
function Cert:digest(name)
  name = tostring(name):lower():gsub("-", "")
  return fero.crypto.digest(name, self.der)
end

-- The certificate in nmap's form, from its DER bytes, or nil when it does
-- not read: subject and issuer (attribute short name to value), pubkey
-- (type "rsa", "ec", "dsa", "ed25519"...; bits; an EC key's curve also
-- as ecdhparams.curve_params), validity (date tables), sig_algorithm,
-- version, serial (hex), extensions (only subjectAltName, as text), pem,
-- der and the digest method. An RSA key's modulus and exponent are
-- openssl bignums, as in nmap.
function sslcert.parse_ssl_certificate(der)
  if type(der) ~= "string" then return nil end
  local raw = fero.tls.parse_certificate(der)
  if not raw then return nil end
  local pubkey = {}
  for k, v in pairs(raw.pubkey) do pubkey[k] = v end
  if pubkey.type == "rsa" and pubkey.modulus then
    local openssl = require "openssl"
    pubkey.modulus = openssl.bignum_bin2bn(pubkey.modulus)
    pubkey.exponent = openssl.bignum_bin2bn(pubkey.exponent)
  end
  if pubkey.type == "ec" and pubkey.curve then
    pubkey.ecdhparams = { curve_params = { ec_curve_type = "namedcurve", curve = pubkey.curve } }
  end
  local extensions = {}
  if #raw.san > 0 then
    extensions[1] = { name = "X509v3 Subject Alternative Name", value = table.concat(raw.san, ", ") }
  end
  return setmetatable({
    subject = raw.subject,
    issuer = raw.issuer,
    pubkey = pubkey,
    validity = {
      notBefore = date_table(raw.validity.notBefore),
      notAfter = date_table(raw.validity.notAfter),
    },
    sig_algorithm = raw.sig_algorithm,
    version = raw.version,
    serial = raw.serial,
    extensions = extensions,
    pem = raw.pem,
    der = raw.der,
  }, Cert)
end

-- A function(host, port) that connects and asks the server to switch to
-- TLS, returning true and an nmap socket still in plain text (the caller
-- sends its own hello), or false and a message; nil when the port has no
-- such protocol.
function sslcert.getPrepareTLSWithoutReconnect(port)
  if tunnelled(port) or not fero.starttls.protocol(port) then return nil end
  return function(host, p)
    local raw, err = fero.starttls.connect(host, p, { plain = true })
    if not raw then return false, err end
    local s = nmap.new_socket()
    s.s:close()
    s.s = raw
    return true, s
  end
end

-- A function(host, port) that connects and switches to TLS, returning
-- true and an nmap socket speaking TLS, or false and a message; nil when
-- the port has no such protocol.
function sslcert.isPortSupported(port)
  if tunnelled(port) or not fero.starttls.protocol(port) then return nil end
  return function(host, p)
    local raw, err = fero.starttls.connect(host, p)
    if not raw then return false, err end
    local s = nmap.new_socket()
    s.s:close()
    s.s = raw
    return true, s
  end
end

local cache = {}

-- The server's certificate: true and the certificate (see
-- parse_ssl_certificate), or false and a message. Ports that switch to
-- TLS on request are asked to first; when that fails, or for other
-- ports, a TLS handshake is tried straight away. Kept for the script's
-- run, so asking again does not connect again.
function sslcert.getCertificate(host, port)
  local key = tostring(host.ip) .. "/" .. tostring(port.number) .. "/" .. tostring(port.protocol)
  if cache[key] then return true, cache[key] end
  local raw, err
  if not tunnelled(port) and fero.starttls.protocol(port) then
    raw, err = fero.starttls.connect(host, port)
  end
  if not raw then
    raw = fero.socket.new()
    raw:set_timeout(10000)
    local ok
    ok, err = raw:connect(host, port, "ssl")
    if not ok then return false, "Failed to connect: " .. tostring(err) end
  end
  local c
  c, err = raw:get_ssl_certificate()
  raw:close()
  if not c then return false, "Failed to get certificate: " .. tostring(err) end
  local cert = sslcert.parse_ssl_certificate(c.der)
  if not cert then return false, "Failed to read the certificate" end
  cache[key] = cert
  return true, cert
end

return sslcert
