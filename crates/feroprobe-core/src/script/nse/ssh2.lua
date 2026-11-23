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

-- The unencrypted SSH transport (RFC 4253 6 and 7.1): enough to read a
-- server's KEXINIT. Key exchange replies (kexdh_init and the like) are
-- built, but nothing goes further than the key exchange.
local fssh = fero.ssh
local transport = {}
ssh2.transport = transport

-- The packet around `payload`.
function transport.build(payload)
  return fssh.packet(payload)
end

-- The payload of a received packet (length, padding length, payload,
-- padding); nil for one too short.
function transport.payload(packet)
  local ok, len, pad = pcall(string.unpack, ">I4B", packet or "")
  if not ok or len < 1 + pad or #packet < 4 + len then return nil end
  return packet:sub(6, 4 + len - pad)
end

-- How long the packet at the start of `buffer` is, as string.find
-- gives it (1 and the length), or nil when it is not all there.
function ssh2.check_packet_length(buffer)
  if #buffer < 4 then return nil end
  local len = string.unpack(">I4", buffer) + 4
  if #buffer < len then return nil end
  return len, len
end

-- Bytes read past a packet, kept for the next receive_packet.
local leftover = setmetatable({}, { __mode = "k" })

-- Read one whole packet: true and the packet, or false and a message.
function transport.receive_packet(socket)
  local buf = leftover[socket] or ""
  leftover[socket] = nil
  while true do
    local len = ssh2.check_packet_length(buf)
    if len then
      if len - 4 > 35000 then return false, "packet too long" end
      if #buf > len then leftover[socket] = buf:sub(len + 1) end
      return true, buf:sub(1, len)
    end
    if #buf >= 4 and string.unpack(">I4", buf) > 35000 then
      return false, "packet too long"
    end
    local ok, data = socket:receive_bytes(1)
    if not ok then
      -- Keep what came, so a later call goes on from the same packet.
      if buf ~= "" then leftover[socket] = buf end
      return false, data
    end
    buf = buf .. data
  end
end

-- The name-lists of a KEXINIT, by the names RFC 4253 7.1 gives them,
-- with nmap's option names as other names for the first five.
local LISTS = fssh.KEXINIT_LISTS
local OPTION = {
  kex_algorithms = { "kex_algorithms" },
  server_host_key_algorithms = { "host_key_algorithms", "server_host_key_algorithms" },
  encryption_algorithms_client_to_server = { "encryption_algorithms" },
  encryption_algorithms_server_to_client = { "encryption_algorithms" },
  mac_algorithms_client_to_server = { "mac_algorithms" },
  mac_algorithms_server_to_client = { "mac_algorithms" },
  compression_algorithms_client_to_server = { "compression_algorithms" },
  compression_algorithms_server_to_client = { "compression_algorithms" },
}
local DEFAULT = {
  kex_algorithms = "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,"
    .. "ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,"
    .. "diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,"
    .. "diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,"
    .. "diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1",
  server_host_key_algorithms = "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,"
    .. "ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256,ssh-rsa,ssh-dss",
  encryption_algorithms_client_to_server = "chacha20-poly1305@openssh.com,aes128-ctr,"
    .. "aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com,"
    .. "aes128-cbc,aes192-cbc,aes256-cbc,3des-cbc",
  mac_algorithms_client_to_server = "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,"
    .. "hmac-sha2-256,hmac-sha2-512,hmac-sha1,umac-64@openssh.com,umac-128@openssh.com",
  compression_algorithms_client_to_server = "none,zlib@openssh.com,zlib",
}
DEFAULT.encryption_algorithms_server_to_client = DEFAULT.encryption_algorithms_client_to_server
DEFAULT.mac_algorithms_server_to_client = DEFAULT.mac_algorithms_client_to_server
DEFAULT.compression_algorithms_server_to_client = DEFAULT.compression_algorithms_client_to_server

-- A KEXINIT payload. `options` may give `cookie` (16 bytes) and any
-- name-list, as a comma-separated string or an array, by its RFC name
-- or by nmap's shorter one (kex_algorithms, host_key_algorithms,
-- encryption_algorithms, mac_algorithms, compression_algorithms).
function transport.kex_init(options)
  options = options or {}
  local lists = {}
  for _, name in ipairs(LISTS) do
    local v = options[name]
    for _, alias in ipairs(OPTION[name] or {}) do
      if v == nil then v = options[alias] end
    end
    if v == nil then v = DEFAULT[name] or "" end
    if type(v) == "table" then v = table.concat(v, ",") end
    lists[name] = v
  end
  local payload = fssh.kexinit(lists)
  local cookie = options.cookie
  if type(cookie) == "string" and #cookie == 16 then
    payload = payload:sub(1, 1) .. cookie .. payload:sub(18)
  end
  return payload
end

-- A KEXINIT payload's name-lists as comma-separated strings by their RFC
-- names, plus `cookie` and `first_kex_packet_follows`; {} when it cannot
-- be read.
function transport.parse_kex_init(payload)
  payload = payload or ""
  if payload:byte(1) ~= 20 then payload = string.char(20) .. payload end
  local t = fssh.parse_kexinit(payload)
  if not t then return {} end
  local out = { cookie = payload:sub(2, 17), first_kex_packet_follows = t.first_kex_packet_follows }
  for _, name in ipairs(LISTS) do out[name] = table.concat(t[name], ",") end
  return out
end

-- SSH_MSG_KEXDH_INIT (RFC 4253 8) and SSH_MSG_KEX_DH_GEX_INIT (RFC 4419
-- 3) carrying `e`, an mpint's bytes.
local function mpint(e)
  e = tostring(e or ""):gsub("^%z+", "")
  if #e > 0 and e:byte(1) >= 0x80 then e = "\0" .. e end
  return string.pack(">s4", e)
end
function transport.kexdh_init(e) return string.char(30) .. mpint(e) end
function transport.kexdh_gex_init(e) return string.char(32) .. mpint(e) end

return ssh2
