-- FeroProbe script: ssl-enum-ciphers
-- Written for FeroProbe from scratch, from RFC 5246, RFC 8446, RFC 6101
-- and RFC 3749 (through fero.tls), RFC 7465 (RC4), CVE-2014-3566
-- (POODLE), CVE-2016-2183 (SWEET32), NIST SP 800-57 part 1 (key
-- strengths) and the Qualys SSL Labs SSL Server Rating Guide (the
-- grading); GPL-3.0-or-later.

description = [[
Lists the cipher suites and compression methods a TLS server takes, for
each protocol version from SSLv3 to TLS 1.3, with a letter grade (A to F)
for each suite and the weakest grade over all, as "least strength".

For each version it sends ClientHellos offering the suites in groups of
64, and each time the server picks one, asks again without it, until the
server picks none. It then offers the suites found in their order and in
reverse: when the server picks the same one both times, it chooses by its
own preference, and the suites are listed in that order (found with
further hellos); when it picks the first offered both times, it follows
the client's, and the suites are listed by name. Compression methods
(DEFLATE, LZS, NULL) are found the same way; TLS 1.3 has none. No
handshake is ever finished: each connection ends after the server's
first flight (ServerHelloDone, or the TLS 1.3 ServerHello).

Each suite is shown with what its key exchange used: the certificate's
RSA key ("rsa 2048"), the Diffie-Hellman group size ("dh 2048") or the
named curve ("secp256r1", "ecdh_x25519"). The grade weighs the key
exchange (3/7: under 512 RSA-equivalent bits 20%, under 1024 40%, under
2048 80%, under 4096 90%, else 100%; elliptic curves converted with NIST
SP 800-57's table) and the cipher's key size (4/7: none 0%, under 128
bits 20%, under 256 80%, else 100%), as the SSL Labs guide does without
its protocol part: A from 80%, B 65%, C 50%, D 35%, E 20%, else F. Grades
are then capped: F for anonymous or export key exchange, a NULL cipher,
or a certificate signed with MD5 or SHA-1; C for RC4 (RFC 7465), a 64-bit
block cipher (SWEET32) and CBC suites under SSLv3 (POODLE). Each cap, a
key exchange weaker than the certificate's key, MD5 message integrity
and the lack of forward secrecy are listed as warnings.

On ports that switch to TLS on request (fero.starttls: SMTP, IMAP, POP3,
FTP, LDAP, PostgreSQL, XMPP...) each connection asks first; when that
fails the hellos go straight to the port.

The ClientHello random carries "FeroProbeTLSScan" (see fero.tls). This
script makes many connections (often over a hundred), which is why it is
in the intrusive category, as nmap's is.

Script arguments:
  ssl-enum-ciphers.timeout  How long to wait for each answer, in
                            milliseconds (default 5000).
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "discovery", "intrusive" }

portrule = function(host, port)
  if fero.portrule.ssl(host, port) then return true end
  return (port.state == "open" or port.state == "open|filtered")
    and fero.starttls.protocol(port) ~= nil
end

local tls = fero.tls

-- How many suites one ClientHello offers.
local CHUNK = 64

local GRADES = { "A", "B", "C", "D", "E", "F" }
local RANK = {}
for i, g in ipairs(GRADES) do RANK[g] = i end

local COMPRESSORS = { [0] = "NULL", [1] = "DEFLATE", [64] = "LZS" }

local function tunnelled(port)
  return type(port.version) == "table" and port.version.service_tunnel == "ssl"
end

-- One ClientHello. Returns the answer when the server took the hello at
-- `version` with one of `ciphers`; else nil and "version" when the
-- server refused the version itself, or another reason.
local function ask(ctx, version, ciphers, compressors)
  local answer, err = tls.hello(ctx.host, ctx.port, {
    version = version, ciphers = ciphers, compressors = compressors,
    timeout = ctx.timeout, starttls = ctx.starttls,
  })
  if not answer then return nil, err end
  local sh = answer.server_hello
  if not sh then
    if answer.alert and answer.alert.code == 70 then return nil, "version" end
    return nil, answer.alert and answer.alert.name or "no ServerHello"
  end
  if sh.version ~= version then return nil, "version" end
  for _, c in ipairs(ciphers) do
    if c == sh.cipher then return answer end
  end
  return nil, "cipher not offered"
end

local function index_of(list, v)
  for i, x in ipairs(list) do
    if x == v then return i end
  end
  return nil
end

-- The suites worth offering at `version`.
local function candidates(version)
  local out = {}
  for _, c in ipairs(tls.CIPHERS) do
    local info = tls.cipher_info(c[2])
    local is13 = c[1] >= 0x1301 and c[1] <= 0x13ff
    if version >= 0x0304 then
      if is13 then out[#out + 1] = c[1] end
    elseif not is13 and not (version < 0x0303 and info and info.tls12) then
      out[#out + 1] = c[1]
    end
  end
  return out
end

-- The suites the server takes at `version`, in the order found, and the
-- answer that took each; nil when the server refuses the version.
local function find_ciphers(ctx, version)
  local all = candidates(version)
  local accepted, answers = {}, {}
  for first = 1, #all, CHUNK do
    local offer = table.move(all, first, math.min(first + CHUNK - 1, #all), 1, {})
    while #offer > 0 do
      local answer, why = ask(ctx, version, offer)
      if not answer then
        if why == "version" and #accepted == 0 then return nil end
        break
      end
      local c = answer.server_hello.cipher
      accepted[#accepted + 1] = c
      answers[c] = answer
      table.remove(offer, index_of(offer, c))
    end
  end
  if #accepted == 0 then return nil end
  return accepted, answers
end

-- Whether the server picks by its own preference ("server"), the
-- client's ("client") or neither ("indeterminate", with a reason); for
-- "server", the suites in its order.
local function preference(ctx, version, accepted)
  if #accepted < 2 then return "indeterminate", "Too few ciphers supported" end
  local a1 = ask(ctx, version, accepted)
  local reversed = {}
  for i = #accepted, 1, -1 do reversed[#reversed + 1] = accepted[i] end
  local a2 = ask(ctx, version, reversed)
  if not a1 or not a2 then return "indeterminate", "Network error" end
  local c1, c2 = a1.server_hello.cipher, a2.server_hello.cipher
  if c1 == accepted[1] and c2 == reversed[1] then return "client" end
  if c1 ~= c2 then return "indeterminate", "Unknown preference" end
  local order, left = { c1 }, {}
  for _, c in ipairs(accepted) do
    if c ~= c1 then left[#left + 1] = c end
  end
  while #left > 1 do
    local a = ask(ctx, version, left)
    -- An order with a gap would be a guess: say so instead.
    if not a then return "indeterminate", "Network error" end
    local c = a.server_hello.cipher
    order[#order + 1] = c
    table.remove(left, index_of(left, c))
  end
  -- The one suite left is the server's last.
  if left[1] then order[#order + 1] = left[1] end
  return "server", nil, order
end

-- The compression methods the server takes at `version`.
local function find_compressors(ctx, version, accepted)
  local offer, found = { 1, 64, 0 }, {}
  while #offer > 0 do
    local a = ask(ctx, version, accepted, offer)
    if not a then break end
    local c = a.server_hello.compressor
    local i = index_of(offer, c)
    if not i then break end
    found[#found + 1] = COMPRESSORS[c] or tostring(c)
    if c == 0 then break end
    table.remove(offer, i)
  end
  return found
end

-- A certificate's key strength as RSA bits, and its label.
local function cert_strength(cert)
  local key = cert and cert.pubkey
  if not key or not key.bits then return nil end
  local kind = key.type
  if kind == "ec" then return tls.ec_strength(key.bits), "ec " .. key.bits end
  if kind == "ed25519" then return 3072, "ed25519" end
  if kind == "ed448" then return 7680, "ed448" end
  return key.bits, tostring(kind) .. " " .. key.bits
end

-- What the key exchange of suite `info` used, from the answer that took
-- it: the label nmap shows ("rsa 2048", "dh 2048", "secp256r1") and its
-- strength in RSA bits, or nil.
local function key_exchange(answer, info, cert)
  if info.tls13 then
    local g = answer.server_hello.group
    if not g then return nil end
    local name = tls.group_name(g)
    return name, tls.group_strength(name)
  end
  local ske = tls.parse_server_key_exchange(answer.server_key_exchange, info)
  if ske then
    if ske.type == "ec" then return ske.group, tls.group_strength(ske.group) end
    return ske.type .. " " .. ske.bits, ske.bits
  end
  local kex = info.kex
  if kex == "PSK" or kex:match("^KRB5") or kex:match("^SRP") then return nil end
  -- Static key exchange: the certificate's own key.
  local strength, label = cert_strength(cert)
  if not strength then return nil end
  if kex:match("^ECDH_") and cert.pubkey.curve then
    return cert.pubkey.curve, strength
  end
  return label, strength
end

-- The SSL Labs scores, in percent.
local function kex_score(bits)
  if bits <= 0 then return 0
  elseif bits < 512 then return 20
  elseif bits < 1024 then return 40
  elseif bits < 2048 then return 80
  elseif bits < 4096 then return 90
  end
  return 100
end

local function cipher_score(size)
  if size == 0 then return 0
  elseif size < 128 then return 20
  elseif size < 256 then return 80
  end
  return 100
end

-- The letter for 7 times a score in percent (3 parts key exchange, 4
-- parts cipher), compared in whole numbers so no rounding moves a
-- suite across a boundary.
local function letter(score7)
  if score7 >= 7 * 80 then return "A"
  elseif score7 >= 7 * 65 then return "B"
  elseif score7 >= 7 * 50 then return "C"
  elseif score7 >= 7 * 35 then return "D"
  elseif score7 >= 7 * 20 then return "E"
  end
  return "F"
end

-- The grade of one suite, adding its warnings to `warn` (a set).
local function grade(version, info, kex_strength, cert, warn)
  local cap = "A"
  local function capped(at, why)
    if RANK[at] > RANK[cap] then cap = at end
    warn[why] = true
  end
  if info.anon then capped("F", "Anonymous key exchange, score capped at F") end
  if info.export then capped("F", "Export key exchange, score capped at F") end
  if info.cipher == "NULL" then capped("F", "Null cipher, score capped at F") end
  if info.cipher == "RC4" then capped("C", "Broken cipher RC4 is deprecated by RFC 7465") end
  if info.block == 64 then
    capped("C", "64-bit block cipher " .. info.cipher .. " vulnerable to SWEET32 attack")
  end
  if version == 0x0300 and info.mode == "CBC" then
    capped("C", "CBC-mode cipher in SSLv3 (CVE-2014-3566)")
  end
  if info.hash == "MD5" then warn["Ciphersuite uses MD5 for message integrity"] = true end
  if cert and not info.anon and cert.sig_algorithm then
    local sig = cert.sig_algorithm:lower()
    if sig:find("md5", 1, true) or sig:find("md2", 1, true) then
      capped("F", "Insecure certificate signature (MD5), score capped at F")
    elseif sig:find("sha1", 1, true) then
      capped("F", "Insecure certificate signature (SHA1), score capped at F")
    end
  end
  -- A cap at F needs no score; otherwise a missing input leaves it open.
  if not kex_strength or not info.size then
    return cap == "F" and "F" or "unknown"
  end
  local g = letter(3 * kex_score(kex_strength) + 4 * cipher_score(info.size))
  if RANK[cap] > RANK[g] then g = cap end
  return g
end

-- Everything about one protocol version, or nil when the server does not
-- speak it: the output table, its lines, and the weakest grade.
local function enumerate(ctx, name)
  local version = tls.VERSIONS[name]
  local accepted, answers = find_ciphers(ctx, version)
  if not accepted then return nil end
  local pref, pref_err, order = preference(ctx, version, accepted)
  if not order then
    order = table.move(accepted, 1, #accepted, 1, {})
    table.sort(order, function(x, y) return tls.cipher_name(x) < tls.cipher_name(y) end)
  end
  local warn, any_fs, worst = {}, false, nil
  local ciphers, lines = {}, {}
  lines[#lines + 1] = "\n  " .. name .. ": \n    ciphers: "
  for _, c in ipairs(order) do
    local cname = tls.cipher_name(c)
    local info = tls.cipher_info(cname) or { kex = "", size = nil }
    local answer = answers[c]
    local cert = answer.certificates and answer.certificates[1]
      and tls.parse_certificate(answer.certificates[1])
    local kex, strength = key_exchange(answer, info, cert)
    local g = grade(version, info, strength, cert, warn)
    if info.forward_secrecy then any_fs = true end
    local cstrength = cert_strength(cert)
    if kex and strength and cstrength and not info.anon and strength < cstrength then
      warn["Key exchange (" .. kex .. ") of lower strength than certificate key"] = true
    end
    if RANK[g] and (not worst or RANK[g] > RANK[worst]) then worst = g end
    ciphers[#ciphers + 1] = { name = cname, kex_info = kex, strength = g }
    lines[#lines + 1] = "\n      " .. cname .. (kex and (" (" .. kex .. ")") or "") .. " - " .. g
  end
  if not any_fs and version < 0x0304 then
    warn["Forward Secrecy not supported by any cipher"] = true
  end
  local t = fero.output_table()
  t.ciphers = ciphers
  if version < 0x0304 then
    t.compressors = find_compressors(ctx, version, accepted)
    lines[#lines + 1] = "\n    compressors: "
    for _, c in ipairs(t.compressors) do lines[#lines + 1] = "\n      " .. c end
  end
  t["cipher preference"] = pref
  lines[#lines + 1] = "\n    cipher preference: " .. pref
  if pref_err then
    t["cipher preference error"] = pref_err
    lines[#lines + 1] = "\n    cipher preference error: " .. pref_err
  end
  local warnings = {}
  for w in pairs(warn) do warnings[#warnings + 1] = w end
  if #warnings > 0 then
    table.sort(warnings)
    t.warnings = warnings
    lines[#lines + 1] = "\n    warnings: "
    for _, w in ipairs(warnings) do lines[#lines + 1] = "\n      " .. w end
  end
  return t, table.concat(lines), worst
end

action = function(host, port)
  local ctx = {
    host = host, port = port,
    timeout = tonumber(fero.args.get(SCRIPT_NAME .. ".timeout")) or 5000,
  }
  if not tunnelled(port) then ctx.starttls = fero.starttls.protocol(port) end
  if ctx.starttls then
    -- A server that will not switch is asked straight away instead.
    -- Two tries, so one dropped connection does not turn every hello
    -- into a plain one.
    local sock
    for _ = 1, 2 do
      sock = tls.connect(host, port, { starttls = ctx.starttls, timeout = ctx.timeout })
      if sock then break end
    end
    if sock then
      sock:close()
    else
      fero.debug(1, "STARTTLS failed; trying TLS straight away")
      ctx.starttls = nil
    end
  end
  local out, text, worst = fero.output_table(), {}, nil
  for _, name in ipairs(tls.PROTOCOLS) do
    local t, lines, w = enumerate(ctx, name)
    if t then
      out[name] = t
      text[#text + 1] = lines
      if w and (not worst or RANK[w] > RANK[worst]) then worst = w end
    end
  end
  if #text == 0 then return nil end
  worst = worst or "unknown"
  out["least strength"] = worst
  text[#text + 1] = "\n  least strength: " .. worst
  return out, table.concat(text)
end
