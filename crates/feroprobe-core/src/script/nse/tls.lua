-- NSE compatibility layer: the `tls` module, TLS records and hellos
-- built and read by hand (fero.tls), for scripts that ask a server what
-- it offers without finishing a handshake. Written for FeroProbe from
-- nmap's public API documentation (not from nselib), RFC 5246, RFC 8446
-- and the IANA TLS registries; GPL-3.0-or-later, like FeroProbe. Every
-- ClientHello carries FeroProbe's mark in its random (IDS rule 9100019).
-- Key exchange details (KEX_ALGORITHMS, rsa_equiv) are not offered.
local fero = ...
local ftls = fero.tls
local tls = {}

-- Name to number tables, as nmap's.
tls.PROTOCOLS = {}
for name, v in pairs(ftls.VERSIONS) do tls.PROTOCOLS[name] = v end

tls.CIPHERS = {}
for _, c in ipairs(ftls.CIPHERS) do tls.CIPHERS[c[2]] = c[1] end

tls.COMPRESSORS = { NULL = 0, DEFLATE = 1, LZS = 64 }

tls.ELLIPTIC_CURVES = {}
for code, name in pairs(ftls.GROUPS) do tls.ELLIPTIC_CURVES[name] = code end

tls.DEFAULT_ELLIPTIC_CURVES = { "secp256r1", "secp384r1", "secp521r1", "ecdh_x25519" }

tls.EC_POINT_FORMATS = {
  uncompressed = 0, ansiX962_compressed_prime = 1, ansiX962_compressed_char2 = 2,
}

tls.HashAlgorithms = {
  none = 0, md5 = 1, sha1 = 2, sha224 = 3, sha256 = 4, sha384 = 5, sha512 = 6, intrinsic = 8,
}
tls.SignatureAlgorithms = {
  anonymous = 0, rsa = 1, dsa = 2, ecdsa = 3, ed25519 = 7, ed448 = 8,
}

tls.EXTENSIONS = {
  server_name = 0, max_fragment_length = 1, client_certificate_url = 2,
  trusted_ca_keys = 3, truncated_hmac = 4, status_request = 5,
  elliptic_curves = 10, ec_point_formats = 11, signature_algorithms = 13,
  use_srtp = 14, heartbeat = 15, application_layer_protocol_negotiation = 16,
  signed_certificate_timestamp = 18, padding = 21, encrypt_then_mac = 22,
  extended_master_secret = 23, session_ticket = 35, pre_shared_key = 41,
  early_data = 42, supported_versions = 43, cookie = 44,
  psk_key_exchange_modes = 45, certificate_authorities = 47,
  signature_algorithms_cert = 50, key_share = 51,
  next_protocol_negotiation = 13172, renegotiation_info = 65281,
}

tls.TLS_ALERT_REGISTRY = {}
for code, name in pairs(ftls.ALERTS) do tls.TLS_ALERT_REGISTRY[name] = code end

tls.TLS_CONTENTTYPE_REGISTRY = {
  change_cipher_spec = 20, alert = 21, handshake = 22, application_data = 23, heartbeat = 24,
}
tls.TLS_HANDSHAKETYPE_REGISTRY = {
  hello_request = 0, client_hello = 1, server_hello = 2, hello_verify_request = 3,
  new_session_ticket = 4, end_of_early_data = 5, encrypted_extensions = 8,
  certificate = 11, server_key_exchange = 12, certificate_request = 13,
  server_hello_done = 14, certificate_verify = 15, client_key_exchange = 16,
  finished = 20, certificate_url = 21, certificate_status = 22, key_update = 24,
  next_protocol = 67, message_hash = 254,
}

local function invert(t)
  local out = {}
  for k, v in pairs(t) do out[v] = k end
  return out
end
local PROTOCOL_NAME = invert(tls.PROTOCOLS)
local CIPHER_NAME = invert(tls.CIPHERS)
local COMPRESSOR_NAME = invert(tls.COMPRESSORS)
local EXTENSION_NAME = invert(tls.EXTENSIONS)
local CONTENT_NAME = invert(tls.TLS_CONTENTTYPE_REGISTRY)
local HANDSHAKE_NAME = invert(tls.TLS_HANDSHAKETYPE_REGISTRY)
local ALERT_LEVEL = { [1] = "warning", [2] = "fatal" }

local function code_of(map, v, what)
  if type(v) == "number" then return v end
  local c = map[v]
  if not c then error("unknown " .. what .. " " .. tostring(v), 3) end
  return c
end

local function u16_list(list, map, what)
  local t = {}
  for i, v in ipairs(list) do t[i] = string.pack(">I2", code_of(map, v, what)) end
  return table.concat(t)
end

-- The signature algorithms a TLS 1.2 or later hello offers when the
-- script gives none (RFC 8446 4.2.3; the SHA-1 ones for old servers).
local SIGNATURES = {
  0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0807, 0x0808,
  0x0401, 0x0501, 0x0601, 0x0303, 0x0203, 0x0201, 0x0402, 0x0202,
}

-- Encoders for extension data, by extension name.
tls.EXTENSION_HELPERS = {
  server_name = function(name)
    return string.pack(">s2", "\0" .. string.pack(">s2", name))
  end,
  max_fragment_length = function(n) return string.char(n) end,
  elliptic_curves = function(list)
    return string.pack(">s2", u16_list(list, tls.ELLIPTIC_CURVES, "curve"))
  end,
  ec_point_formats = function(list)
    local t = {}
    for i, v in ipairs(list) do t[i] = string.char(code_of(tls.EC_POINT_FORMATS, v, "point format")) end
    return string.pack(">s1", table.concat(t))
  end,
  signature_algorithms = function(list)
    local t = {}
    for i, v in ipairs(list) do
      if type(v) == "table" then
        t[i] = string.char(code_of(tls.HashAlgorithms, v[1], "hash"),
          code_of(tls.SignatureAlgorithms, v[2], "signature"))
      else
        t[i] = string.pack(">I2", v)
      end
    end
    return string.pack(">s2", table.concat(t))
  end,
  application_layer_protocol_negotiation = function(list)
    local t = {}
    for i, n in ipairs(list) do t[i] = string.pack(">s1", n) end
    return string.pack(">s2", table.concat(t))
  end,
  next_protocol_negotiation = function(s) return s or "" end,
  supported_versions = function(list)
    return string.pack(">s1", u16_list(list, tls.PROTOCOLS, "protocol"))
  end,
  renegotiation_info = function(s) return string.pack(">s1", s or "") end,
}

-- The name for SNI: the target's name, not an address; nil when it has
-- none.
function tls.servername(host)
  if type(host) ~= "table" then return nil end
  for _, key in ipairs({ "targetname", "name" }) do
    local n = host[key]
    if type(n) == "string" and n ~= "" and not n:match("^[%d.]+$") and not n:find(":", 1, true) then
      return n
    end
  end
  return nil
end

-- What a cipher suite's name says about it (fero.tls.cipher_info, with
-- nmap's block_size for the block).
function tls.cipher_info(name)
  local info = ftls.cipher_info(name)
  if not info then
    -- A name it cannot read (TLS_NULL_WITH_NULL_NULL, the RIPEMD and
    -- double-named suites): what the name gives, with no key size.
    local kex, rest = tostring(name):match("^TLS_(.-)_WITH_(.+)$")
    info = { kex = kex or "NULL", cipher = rest or "NULL", mode = "unknown" }
    if rest == "NULL_NULL" then
      info.cipher, info.mode, info.size = "NULL", "none", 0
    end
    local body = rest and rest:match("^(.-)_RMD$")
    if body == "3DES_EDE_CBC" then
      info.cipher, info.mode, info.size, info.block, info.hash = "3DES", "CBC", 112, 64, "RMD"
    end
  end
  info.block_size = info.block
  -- nmap's names for which protocols the suite fits: TLS 1.3 suites are
  -- TLS 1.3 only, and no earlier suite works in TLS 1.3.
  info.tls13only = info.tls13 == true
  info.tls13ok = info.tls13 == true
  return info
end

-- A record of content type `type` (name or number) and `protocol` (name
-- or number) holding `body`. TLS 1.3 records carry TLS 1.2's version
-- (RFC 8446 5.1).
function tls.record_write(kind, protocol, body)
  local version = code_of(tls.PROTOCOLS, protocol, "protocol")
  if version > 0x0303 then version = 0x0303 end
  return string.pack(">BI2s2", code_of(tls.TLS_CONTENTTYPE_REGISTRY, kind, "content type"),
    version, body)
end

-- A ClientHello record. `t`: protocol (default "TLSv1.2"),
-- record_protocol, ciphers (names or codes; default every suite of that
-- protocol), compressors (default { "NULL" }), session_id, extensions
-- (extension name or code to its data, see EXTENSION_HELPERS). A
-- TLSv1.3 hello gets supported_versions and an x25519 key_share when
-- the extensions do not give them.
function tls.client_hello(t)
  t = t or {}
  local protocol = t.protocol or "TLSv1.2"
  local version = code_of(tls.PROTOCOLS, protocol, "protocol")
  local tls13 = version >= 0x0304
  local ciphers = {}
  if t.ciphers then
    for i, c in ipairs(t.ciphers) do ciphers[i] = code_of(tls.CIPHERS, c, "cipher") end
  else
    for _, c in ipairs(ftls.CIPHERS) do
      local is13 = c[1] >= 0x1301 and c[1] <= 0x13ff
      if tls13 == is13 then ciphers[#ciphers + 1] = c[1] end
    end
  end
  local comps = {}
  for i, c in ipairs(t.compressors or { "NULL" }) do
    comps[i] = string.char(code_of(tls.COMPRESSORS, c, "compressor"))
  end
  local exts = {}
  for k, v in pairs(t.extensions or {}) do
    exts[code_of(tls.EXTENSIONS, k, "extension")] = v
  end
  -- Like nmap's, a hello without them offers the common curves and,
  -- from TLS 1.2 on, signature algorithms: servers refuse a hello that
  -- leaves no way to sign their key exchange.
  if version >= 0x0301 then
    exts[10] = exts[10] or tls.EXTENSION_HELPERS.elliptic_curves(tls.DEFAULT_ELLIPTIC_CURVES)
    exts[11] = exts[11] or tls.EXTENSION_HELPERS.ec_point_formats({ "uncompressed" })
  end
  if version >= 0x0303 then
    exts[13] = exts[13] or string.pack(">s2", u16_list(SIGNATURES, {}, "signature"))
  end
  if tls13 then
    exts[43] = exts[43] or tls.EXTENSION_HELPERS.supported_versions({ protocol })
    exts[45] = exts[45] or "\1\1"
    exts[51] = exts[51] or string.pack(">s2", string.pack(">I2s2", 29, fero.crypto.random_bytes(32)))
  end
  local codes = {}
  for c in pairs(exts) do codes[#codes + 1] = c end
  table.sort(codes)
  local ext_data = {}
  for i, c in ipairs(codes) do ext_data[i] = string.pack(">I2s2", c, exts[c]) end
  local random = string.pack(">I4", os.time()) .. ftls.MARK .. fero.crypto.random_bytes(12)
  local session = t.session_id or (tls13 and fero.crypto.random_bytes(32)) or ""
  local body = string.pack(">I2", tls13 and 0x0303 or version) .. random
    .. string.pack(">s1", session)
    .. string.pack(">s2", u16_list(ciphers, tls.CIPHERS, "cipher"))
    .. string.pack(">s1", table.concat(comps))
  if #ext_data > 0 then body = body .. string.pack(">s2", table.concat(ext_data)) end
  local hs = "\1" .. string.pack(">I3", #body) .. body
  local record_version = t.record_protocol and code_of(tls.PROTOCOLS, t.record_protocol, "protocol")
    or (version == 0x0300 and 0x0300 or 0x0301)
  return string.pack(">BI2s2", 22, record_version, hs)
end

-- Whether a record's protocol `received` (name or number) fits the
-- protocol `requested`: the same one, or TLS 1.2 for TLS 1.3 (whose
-- records carry TLS 1.2's version). Without `requested`, whether
-- `received` is a known version.
function tls.record_version_ok(received, requested)
  local function name(v)
    if type(v) == "number" then return PROTOCOL_NAME[v] end
    if tls.PROTOCOLS[v] then return v end
    return nil
  end
  local got = name(received)
  if requested == nil then return got ~= nil end
  local want = name(requested)
  return got ~= nil and (got == want or (want == "TLSv1.3" and got == "TLSv1.2"))
end

-- One handshake message's body, read by its type.
local function handshake_body(typ, msg, b)
  if typ == 2 then
    local sh = ftls.parse_server_hello(msg)
    if not sh then return end
    b.protocol = PROTOCOL_NAME[sh.version] or sh.version
    b.time = string.unpack(">I4", sh.random)
    b.random = sh.random:sub(5)
    b.session_id = sh.session_id
    b.cipher = CIPHER_NAME[sh.cipher] or sh.cipher
    b.compressor = COMPRESSOR_NAME[sh.compressor] or sh.compressor
    b.extensions = {}
    for code, data in pairs(sh.extensions) do
      b.extensions[EXTENSION_NAME[code] or code] = data
    end
  elseif typ == 11 then
    local certs = {}
    local ok, all = pcall(string.unpack, ">s3", msg)
    if ok then
      local p = 1
      while p <= #all do
        local okc, der, nextp = pcall(string.unpack, ">s3", all, p)
        if not okc then break end
        certs[#certs + 1] = der
        p = nextp
      end
    end
    b.certificates = certs
  else
    b.data = msg
  end
end

-- Read the handshake messages of `data`; what is left of a message cut
-- at the end of the record comes back.
function tls.handshake_parse(data)
  local list, p = {}, 1
  while p + 3 <= #data do
    local typ, len = string.unpack(">BI3", data, p)
    if p + 3 + len > #data then break end
    local b = { type = HANDSHAKE_NAME[typ] or typ }
    handshake_body(typ, data:sub(p + 4, p + 3 + len), b)
    list[#list + 1] = b
    p = p + 4 + len
  end
  return list, data:sub(p)
end

-- The record at position `i` of `buffer`: the position after it, the
-- record { type, protocol, length, body, fragment } and true; `i`, nil
-- and true (read more and try again) when the record is not all there. `fragment` is the start of a handshake
-- message an earlier record cut, from that record's `fragment`.
function tls.record_read(buffer, i, fragment)
  i = i or 1
  if #buffer - i + 1 < 5 then return i, nil, true end
  local typ, version, len = string.unpack(">BI2I2", buffer, i)
  if #buffer - i + 1 < 5 + len then return i, nil, true end
  local data = buffer:sub(i + 5, i + 4 + len)
  local r = {
    type = CONTENT_NAME[typ] or typ,
    protocol = PROTOCOL_NAME[version] or version,
    length = len,
  }
  if typ == 22 then
    r.body, r.fragment = tls.handshake_parse((fragment or "") .. data)
    if r.fragment == "" then r.fragment = nil end
  elseif typ == 21 then
    r.body = {}
    for p = 1, #data - 1, 2 do
      local level, code = data:byte(p, p + 1)
      r.body[#r.body + 1] = {
        level = ALERT_LEVEL[level] or level,
        description = ftls.ALERTS[code] or code,
      }
    end
  elseif typ == 20 then
    r.body = { { type = "change_cipher_spec" } }
  else
    r.body = data
  end
  return i + 5 + len, r, true
end

-- Read from `sock` until `buffer` holds a whole record from position `i`
-- (at most 64 KiB): true and the buffer, or false, what was read and a
-- message.
function tls.record_buffer(sock, buffer, i)
  buffer, i = buffer or "", i or 1
  while true do
    if #buffer - i + 1 >= 5 then
      local _, _, len = string.unpack(">BI2I2", buffer, i)
      if #buffer - i + 1 >= 5 + len then return true, buffer end
    end
    if #buffer > 65536 then return false, buffer, "record too long" end
    local ok, data = sock:receive()
    if not ok then return false, buffer, data end
    buffer = buffer .. data
  end
end

tls.html = function()
  error("tls.html is not available in FeroProbe", 2)
end

-- A key's strength as RSA bits (NIST SP 800-57 part 1, table 2): RSA,
-- DSA and finite-field DH keys count their own bits; elliptic-curve keys
-- are mapped. nil for a kind it does not know.
function tls.rsa_equiv(kind, bits)
  bits = tonumber(bits)
  if not bits then return nil end
  if kind == "rsa" or kind == "dh" or kind == "dsa" then return bits end
  if kind == "ec" then return ftls.ec_strength(bits) end
  return nil
end

-- Bits in a big-endian number.
local function bit_length(n)
  n = n:gsub("^%z+", "")
  if #n == 0 then return 0 end
  local top, b = n:byte(1), 0
  while top > 0 do b = b + 1; top = top >> 1 end
  return (#n - 1) * 8 + b
end

-- The bits of a named curve's key.
local function curve_bits(name)
  if name == "ecdh_x25519" then return 256 end
  if name == "ecdh_x448" then return 448 end
  return tonumber(tostring(name):match("^%a+(%d+)"))
end

-- ServerKeyExchange readers (RFC 5246 7.4.3, RFC 8422 5.4, RFC 4279 2):
-- what the server's parameters are and how strong, as nmap's: `type`,
-- `strength` (bits: the prime's, the curve's or the modulus's) and
-- `dhparams` { p, g, y }, `ecdhparams` { curve_params = { ec_curve_type,
-- curve } } or `rsa` { modulus, exponent }. nil when it cannot be read.
local function skip_hint(blob, psk)
  if not psk then return 1 end
  local ok, _, p = pcall(string.unpack, ">s2", blob)
  return ok and p or nil
end
local function dh_ske(psk)
  return function(blob)
    local p = skip_hint(blob, psk)
    if not p then return nil end
    local ok, prime, g, y = pcall(string.unpack, ">s2s2s2", blob, p)
    if not ok then return nil end
    return { type = "dh", strength = bit_length(prime), dhparams = { p = prime, g = g, y = y } }
  end
end
local EC_CURVE_TYPE = { [1] = "explicit_prime", [2] = "explicit_char2", [3] = "namedcurve" }
local function ec_ske(psk)
  return function(blob)
    local p = skip_hint(blob, psk)
    if not p then return nil end
    local ok, kind = pcall(string.unpack, ">B", blob, p)
    if not ok then return nil end
    local params = { ec_curve_type = EC_CURVE_TYPE[kind] or kind }
    local out = { type = "ec", ecdhparams = { curve_params = params } }
    if kind == 3 then
      local okn, code = pcall(string.unpack, ">I2", blob, p + 1)
      if not okn then return nil end
      params.curve = ftls.GROUPS[code] or code
      out.strength = curve_bits(params.curve)
    end
    return out
  end
end
local function rsa_ske(blob)
  local ok, modulus, exponent = pcall(string.unpack, ">s2s2", blob)
  if not ok then return nil end
  return { type = "rsa", strength = bit_length(modulus), rsa = { modulus = modulus, exponent = exponent } }
end

-- What each key exchange (the part of a suite's name before "_WITH_")
-- is: `type` ("rsa", "dh", "ec", "psk", "srp", "krb5", "gost", "null"),
-- `pubkey` (the certificate's key kind it needs, if any), `anon`,
-- `export`, `pfs`, `tls13` and `server_key_exchange(blob, protocol)`
-- for the ones whose server sends its parameters.
tls.KEX_ALGORITHMS = {
  NULL = { type = "null", anon = true },
  RSA = { type = "rsa", pubkey = "rsa" },
  RSA_EXPORT = { type = "rsa", pubkey = "rsa", export = true, server_key_exchange = rsa_ske },
  RSA_EXPORT1024 = { type = "rsa", pubkey = "rsa", export = true, server_key_exchange = rsa_ske },
  DHE_RSA = { type = "dh", pubkey = "rsa", pfs = true, server_key_exchange = dh_ske() },
  DHE_RSA_EXPORT = { type = "dh", pubkey = "rsa", pfs = true, export = true, server_key_exchange = dh_ske() },
  DHE_DSS = { type = "dh", pubkey = "dsa", pfs = true, server_key_exchange = dh_ske() },
  DHE_DSS_EXPORT = { type = "dh", pubkey = "dsa", pfs = true, export = true, server_key_exchange = dh_ske() },
  DHE_DSS_EXPORT1024 = { type = "dh", pubkey = "dsa", pfs = true, export = true, server_key_exchange = dh_ske() },
  DH_RSA = { type = "dh", pubkey = "dh" },
  DH_RSA_EXPORT = { type = "dh", pubkey = "dh", export = true },
  DH_DSS = { type = "dh", pubkey = "dh" },
  DH_DSS_EXPORT = { type = "dh", pubkey = "dh", export = true },
  DH_anon = { type = "dh", anon = true, server_key_exchange = dh_ske() },
  DH_anon_EXPORT = { type = "dh", anon = true, export = true, server_key_exchange = dh_ske() },
  ECDHE_RSA = { type = "ec", pubkey = "rsa", pfs = true, server_key_exchange = ec_ske() },
  ECDHE_ECDSA = { type = "ec", pubkey = "ec", pfs = true, server_key_exchange = ec_ske() },
  ECDH_RSA = { type = "ec", pubkey = "ec" },
  ECDH_ECDSA = { type = "ec", pubkey = "ec" },
  ECDH_anon = { type = "ec", anon = true, server_key_exchange = ec_ske() },
  PSK = { type = "psk" },
  RSA_PSK = { type = "rsa", pubkey = "rsa" },
  DHE_PSK = { type = "dh", pfs = true, server_key_exchange = dh_ske(true) },
  ECDHE_PSK = { type = "ec", pfs = true, server_key_exchange = ec_ske(true) },
  SRP_SHA = { type = "srp" },
  SRP_SHA_RSA = { type = "srp", pubkey = "rsa" },
  SRP_SHA_DSS = { type = "srp", pubkey = "dsa" },
  KRB5 = { type = "krb5" },
  KRB5_EXPORT = { type = "krb5", export = true },
  GOSTR341001 = { type = "gost" },
  GOSTR341094 = { type = "gost" },
  -- TLS 1.3: the server's key_share (RFC 8446 4.2.8) in place of a
  -- ServerKeyExchange.
  AKE = { type = "ec", pfs = true, tls13 = true, server_key_exchange = function(blob)
    local ok, code = pcall(string.unpack, ">I2", blob or "")
    if not ok then return nil end
    local name = ftls.GROUPS[code] or code
    local ff = tostring(name):match("^ffdhe(%d+)$")
    if ff then return { type = "dh", strength = tonumber(ff) } end
    return {
      type = "ec", strength = curve_bits(name) or ftls.group_strength(tostring(name)),
      ecdhparams = { curve_params = { ec_curve_type = "namedcurve", curve = name } },
    }
  end },
}

return tls
