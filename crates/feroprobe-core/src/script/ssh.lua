-- fero.ssh: the clear-text start of an SSH-2 connection (version
-- exchange and KEXINIT), for scripts that read what a server offers
-- before any key exchange or login.
-- Written for FeroProbe from scratch, from RFC 4253 sections 4.2, 6 and
-- 7.1 and RFC 4251 section 5; GPL-3.0-or-later.
local fero = ...
local ssh = {}

-- The client version line: FeroProbe's mark, the same in every SSH
-- connection a script makes (IDS rule 9100007).
ssh.IDENT = "SSH-2.0-FeroProbe_Scripting_Engine"

-- The largest packet read (RFC 4253 section 6.1 asks for 35000).
local MAX_PACKET = 35000

-- The name-lists of a KEXINIT, in their order on the wire (RFC 4253
-- section 7.1), by the names the RFC gives them.
ssh.KEXINIT_LISTS = {
  "kex_algorithms",
  "server_host_key_algorithms",
  "encryption_algorithms_client_to_server",
  "encryption_algorithms_server_to_client",
  "mac_algorithms_client_to_server",
  "mac_algorithms_server_to_client",
  "compression_algorithms_client_to_server",
  "compression_algorithms_server_to_client",
  "languages_client_to_server",
  "languages_server_to_client",
}

-- A string as SSH sends it: a 32-bit length, then the bytes.
function ssh.string(s) return string.pack(">s4", s) end

-- An unencrypted binary packet around `payload`, padded to a multiple of
-- 8 bytes with at least 4 bytes of padding.
function ssh.packet(payload)
  local pad = 8 - ((5 + #payload) % 8)
  if pad < 4 then pad = pad + 8 end
  return string.pack(">I4B", 1 + #payload + pad, pad) .. payload .. string.rep("\0", pad)
end

-- The payload of the next unencrypted packet read through `r` (a
-- fero.reader), or nil and a message.
function ssh.read_packet(r)
  local head, err = r:bytes(5)
  if not head then return nil, err end
  local len, pad = string.unpack(">I4B", head)
  if len < 1 + pad or len > MAX_PACKET then return nil, "bad packet length" end
  local body, err2 = r:bytes(len - 1)
  if not body then return nil, err2 end
  return body:sub(1, len - 1 - pad)
end

-- The names in a name-list, in order; {} for an empty one.
function ssh.name_list(s)
  local t = {}
  for name in s:gmatch("[^,]+") do t[#t + 1] = name end
  return t
end

-- A KEXINIT payload. `lists` has an array of names, or one string of
-- comma-separated names, for each of ssh.KEXINIT_LISTS (a missing one is
-- sent empty). The cookie is random; no guessed packet follows.
function ssh.kexinit(lists)
  local parts = { string.char(20), fero.crypto.random_bytes(16) }
  for _, name in ipairs(ssh.KEXINIT_LISTS) do
    local v = lists[name] or ""
    if type(v) == "table" then v = table.concat(v, ",") end
    parts[#parts + 1] = ssh.string(v)
  end
  parts[#parts + 1] = "\0" .. string.pack(">I4", 0)
  return table.concat(parts)
end

-- The name-lists of a KEXINIT payload, each as an array of names, by
-- the names of ssh.KEXINIT_LISTS, plus `first_kex_packet_follows`
-- (a boolean); or nil and a message.
function ssh.parse_kexinit(p)
  if p:byte(1) ~= 20 or #p < 17 then return nil, "not a KEXINIT" end
  local out, pos = {}, 18
  for _, name in ipairs(ssh.KEXINIT_LISTS) do
    local ok, s, nextpos = pcall(string.unpack, ">s4", p, pos)
    if not ok then return nil, "truncated KEXINIT" end
    out[name] = ssh.name_list(s)
    pos = nextpos
  end
  if pos > #p then return nil, "truncated KEXINIT" end
  out.first_kex_packet_follows = p:byte(pos) ~= 0
  return out
end

-- Connect, read the server's version line (up to 20 lines may come
-- before it, RFC 4253 section 4.2) and send ours. Returns the socket, a
-- fero.reader on it and the server's version line; or nil and a
-- message (the socket closed). Only SSH 2.0 and 1.99 servers are taken.
function ssh.connect(host, port, timeout)
  local sock = fero.socket.new()
  sock:set_timeout(timeout or 10000)
  local ok, err = sock:connect(host, port)
  if not ok then return nil, err end
  local r = fero.reader(sock)
  local server_ident
  for _ = 1, 20 do
    local line = r:line()
    if not line then break end
    if line:sub(1, 4) == "SSH-" then server_ident = line break end
  end
  if not server_ident or not server_ident:match("^SSH%-2%.0%-") and not server_ident:match("^SSH%-1%.99%-") then
    sock:close()
    return nil, "not an SSH-2 server"
  end
  local sent, serr = sock:send(ssh.IDENT .. "\r\n")
  if not sent then
    sock:close()
    return nil, serr
  end
  return sock, r, server_ident
end

-- Read packets through `r` until the server's KEXINIT, and return it
-- parsed (see ssh.parse_kexinit); nil and a message when the server
-- disconnects, sends something else first, or sends nothing.
function ssh.read_kexinit(r)
  -- RFC 4253 section 11: IGNORE, DEBUG and UNIMPLEMENTED may come at any
  -- time; anything else before the KEXINIT ends the wait.
  for _ = 1, 50 do
    local p, err = ssh.read_packet(r)
    if not p then return nil, err end
    local msg = p:byte(1)
    if msg == 20 then return ssh.parse_kexinit(p) end
    if msg == 1 then return nil, "the server disconnected" end
    if msg ~= 2 and msg ~= 3 and msg ~= 4 then
      return nil, "unexpected message " .. tostring(msg)
    end
  end
  return nil, "no KEXINIT"
end

-- Reading a host key: key exchange up to the server's reply (RFC 4253
-- section 8, RFC 5656, RFC 8731), as ssh-hostkey does.
local KEX = {
  "curve25519-sha256", "curve25519-sha256@libssh.org",
  "diffie-hellman-group14-sha256", "diffie-hellman-group16-sha512",
  "diffie-hellman-group18-sha512", "diffie-hellman-group14-sha1",
  "diffie-hellman-group1-sha1",
}
local CIPHERS = "aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,"
  .. "aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes128-cbc,3des-cbc"
local MACS = "hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-sha2-256-etm@openssh.com,"
  .. "hmac-sha2-512-etm@openssh.com,umac-64@openssh.com"

local str = ssh.string
local packet = ssh.packet
local read_packet = ssh.read_packet

local function first_common(mine, theirs)
  local set = {}
  for _, v in ipairs(theirs) do set[v] = true end
  for _, v in ipairs(mine) do
    if set[v] then return v end
  end
  return nil
end

-- The size in bits of an SSH mpint's value.
local function mpint_bits(m)
  local i = 1
  while i <= #m and m:byte(i) == 0 do i = i + 1 end
  if i > #m then return 0 end
  local bits = (#m - i + 1) * 8
  local top = m:byte(i)
  while top < 0x80 do
    bits = bits - 1
    top = top << 1
  end
  return bits
end

local CURVE_BITS = { nistp256 = 256, nistp384 = 384, nistp521 = 521 }

-- The size in bits and the type of an SSH public key blob.
function ssh.key_bits(blob)
  local ok, kind, pos = pcall(string.unpack, ">s4", blob)
  if not ok then return nil end
  if kind == "ssh-rsa" then
    local ok2, _, n = pcall(string.unpack, ">s4s4", blob, pos)
    return ok2 and mpint_bits(n) or nil, kind
  elseif kind == "ssh-dss" then
    local ok2, p = pcall(string.unpack, ">s4", blob, pos)
    return ok2 and mpint_bits(p) or nil, kind
  elseif kind:match("^ecdsa%-sha2%-") then
    local ok2, curve = pcall(string.unpack, ">s4", blob, pos)
    return ok2 and CURVE_BITS[curve] or nil, kind
  elseif kind == "ssh-ed25519" then
    return 256, kind
  end
  return nil, kind
end

-- Connect and read the server's host key for one of the host key
-- algorithms `algs` (in order of preference), from its key exchange
-- reply; nothing logs in. Returns the key blob; or nil and the server's
-- host key algorithms when it offers none of `algs` (so a caller can skip
-- other families without connecting); or nil, nil and a message.
function ssh.host_key(host, port, algs, timeout)
  local sock, r = ssh.connect(host, port, timeout)
  if not sock then return nil, nil, r end
  local kexinit = ssh.kexinit({
    kex_algorithms = KEX, server_host_key_algorithms = algs,
    encryption_algorithms_client_to_server = CIPHERS,
    encryption_algorithms_server_to_client = CIPHERS,
    mac_algorithms_client_to_server = MACS, mac_algorithms_server_to_client = MACS,
    compression_algorithms_client_to_server = "none",
    compression_algorithms_server_to_client = "none",
  })
  sock:send(packet(kexinit))
  local kex
  for _ = 1, 50 do
    local p, perr = read_packet(r)
    if not p then
      sock:close()
      return nil, nil, perr
    end
    local msg = p:byte(1)
    if msg == 20 and not kex then
      local theirs = ssh.parse_kexinit(p)
      if not theirs then break end
      local their_kex, their_keys = theirs.kex_algorithms, theirs.server_host_key_algorithms
      if not first_common(algs, their_keys) then
        sock:close()
        return nil, their_keys
      end
      kex = first_common(KEX, their_kex)
      if not kex then
        sock:close()
        return nil, nil, "no key exchange method in common"
      end
      if kex:match("^curve25519") then
        sock:send(packet(string.char(30) .. str(fero.crypto.random_bytes(32))))
      else
        -- A random 512-bit public value: below every group's prime, with
        -- the top bit clear (a positive mpint) and plenty of bits set, as
        -- servers check (OpenSSH wants 1 < e < p-1 and at least 4 bits).
        -- No shared secret is computed, so it need not come from a
        -- private exponent.
        local e = fero.crypto.random_bytes(64)
        e = string.char(e:byte(1) & 0x3f | 0x40) .. e:sub(2, 63)
          .. string.char(e:byte(64) | 0x0f)
        sock:send(packet(string.char(30) .. str(e)))
      end
    elseif msg == 31 and kex then
      sock:close()
      local okb, blob = pcall(string.unpack, ">s4", p, 2)
      if okb then return blob end
      return nil, nil, "bad key exchange reply"
    elseif msg == 1 then
      break -- SSH_MSG_DISCONNECT
    end
  end
  sock:close()
  return nil, nil, "no host key"
end

fero.ssh = ssh
