-- NSE compatibility layer: the `openssl` module, the digests, HMAC,
-- random bytes and big numbers FeroProbe has (no OpenSSL, no ciphers).
-- Written for FeroProbe from nmap's public API documentation (not from
-- nselib); GPL-3.0-or-later, like FeroProbe.
local fero = ...
local openssl = {}

local BLOCK = { md4 = 64, md5 = 64, sha1 = 64, sha256 = 64, sha384 = 128, sha512 = 128 }

local function algo(name)
  name = tostring(name):lower():gsub("-", "")
  if not BLOCK[name] then error("digest " .. tostring(name) .. " is not available in FeroProbe", 3) end
  return name
end

openssl.digest = function(name, msg) return fero.crypto.digest(algo(name), msg) end
openssl.md4 = function(msg) return fero.crypto.digest("md4", msg) end
openssl.md5 = function(msg) return fero.crypto.digest("md5", msg) end
openssl.sha1 = function(msg) return fero.crypto.digest("sha1", msg) end
openssl.supported_digests = function()
  return { "md4", "md5", "sha1", "sha256", "sha384", "sha512" }
end

-- RFC 2104.
openssl.hmac = function(name, key, msg)
  name = algo(name)
  local block = BLOCK[name]
  if #key > block then key = fero.crypto.digest(name, key) end
  key = key .. string.rep("\0", block - #key)
  local function xor(pad)
    return (key:gsub(".", function(c) return string.char(c:byte() ~ pad) end))
  end
  local inner = fero.crypto.digest(name, xor(0x36) .. msg)
  return fero.crypto.digest(name, xor(0x5c) .. inner)
end

openssl.rand_bytes = function(n) return fero.crypto.random_bytes(n) end
openssl.rand_pseudo_bytes = openssl.rand_bytes

-- bignum_*: big numbers in Rust (bignum.rs), with size limits.
for name, f in pairs(fero.__bignum) do openssl[name] = f end

for _, name in ipairs({ "encrypt", "decrypt", "DES_string_to_key", "md4", "ripemd160",
  "supported_ciphers" }) do
  openssl[name] = function()
    error("openssl." .. name .. " is not available in FeroProbe", 2)
  end
end

return openssl
