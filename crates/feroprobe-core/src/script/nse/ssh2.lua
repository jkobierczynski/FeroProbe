-- NSE compatibility layer: the `ssh2` module, an SSH-2 server's host key
-- read from its key exchange reply (fero.ssh). Nothing logs in.
-- Written for FeroProbe from nmap's public API documentation (not from
-- nselib) and RFC 4253, 5656 and 8709; GPL-3.0-or-later, like FeroProbe.
local fero = ...
local ssh2 = {}

-- The host key algorithms to offer for a key type: an RSA key is also
-- sent for the SHA-2 signature names (RFC 8332), which servers that
-- turned ssh-rsa off still accept.
local OFFER = {
  ["ssh-rsa"] = { "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa" },
}

local ALGORITHM = {
  ["ssh-rsa"] = "RSA", ["ssh-dss"] = "DSA", ["ssh-ed25519"] = "ED25519",
  ["ssh-ed448"] = "ED448",
}

-- The server's host key of type `key_type` (default "ssh-rsa"; also
-- "ssh-dss", "ecdsa-sha2-nistp256/384/521", "ssh-ed25519"), as nmap
-- gives it: key (base64), key_type, fp_input (the key blob), bits,
-- full_key ("type base64"), algorithm ("RSA", "DSA", "ECDSA",
-- "ED25519"), fingerprint (MD5, raw) and fp_sha256 (SHA-256, raw); or
-- nil when it has none or does not answer.
function ssh2.fetch_host_key(host, port, key_type)
  key_type = key_type or "ssh-rsa"
  local blob, _, err = fero.ssh.host_key(host, port, OFFER[key_type] or { key_type }, 10000)
  if not blob then
    if err then fero.debug(1, "ssh2.fetch_host_key: " .. tostring(err)) end
    return nil
  end
  local bits, kind = fero.ssh.key_bits(blob)
  kind = kind or key_type
  local key = fero.base64.encode(blob)
  return {
    key = key,
    key_type = kind,
    fp_input = blob,
    bits = bits,
    full_key = kind .. " " .. key,
    algorithm = ALGORITHM[kind] or (kind:match("^ecdsa%-") and "ECDSA") or kind,
    fingerprint = fero.crypto.digest("md5", blob),
    fp_sha256 = fero.crypto.digest("sha256", blob),
  }
end

-- The SSH transport layer (packets, key exchange, banners) is not
-- offered: scripts using it fail with a clear message.
ssh2.transport = setmetatable({}, {
  __index = function(_, name)
    return function()
      error("ssh2.transport." .. tostring(name) .. " is not available in FeroProbe", 2)
    end
  end,
})

return ssh2
