-- FeroProbe script: ssh-hostkey
-- Written for FeroProbe from scratch (RFC 4253, RFC 4250, RFC 5656,
-- RFC 8709, RFC 8731); GPL-3.0-or-later.

description = [[
Shows the host keys of an SSH server: for each key type the server
offers (DSA, RSA, ECDSA, Ed25519), its size in bits and its MD5
fingerprint, as ssh-keygen -l -E md5 prints it; with -vv also the
public key itself. The ssh-hostkey.format argument picks other forms.

Each key is read from the server's key exchange reply on a connection
of its own, which is closed as soon as the key has arrived: nothing
logs in. The client announces itself as "SSH-2.0-FeroProbe_Scripting_Engine".
Key exchange is offered with curve25519 and the classic Diffie-Hellman
groups 14, 16, 18 and 1, which nearly every server supports.

Script arguments:
  ssh-hostkey.format   Which forms to show, separated by commas or
                       spaces: md5 (the default), sha256 (as ssh-keygen
                       prints by default), full (the public key), or
                       all. Also read as ssh_hostkey, nmap's name.
  ssh-hostkey.timeout  How long to wait for each answer, in milliseconds
                       (default 10000).
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "default", "discovery", "safe" }

portrule = fero.portrule.match({ 22 }, { "ssh" })

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

-- One key family per connection, in the order they are shown.
local FAMILIES = {
  { label = "DSA", algs = { "ssh-dss" } },
  { label = "RSA", algs = { "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa" } },
  { label = "ECDSA", algs = { "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521" } },
  { label = "ED25519", algs = { "ssh-ed25519" } },
}

local str = fero.ssh.string
local packet = fero.ssh.packet
local read_packet = fero.ssh.read_packet

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

local function key_bits(blob)
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

-- Connect and read the host key of one family. Returns the key blob, or
-- nil and the server's host key algorithms when it has none of this
-- family's (so later families can be skipped without connecting).
local function fetch(host, port, family, timeout)
  local sock, r = fero.ssh.connect(host, port, timeout)
  if not sock then return nil, nil, r end
  local kexinit = fero.ssh.kexinit({
    kex_algorithms = KEX, server_host_key_algorithms = family.algs,
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
      local theirs = fero.ssh.parse_kexinit(p)
      if not theirs then break end
      local their_kex, their_keys = theirs.kex_algorithms, theirs.server_host_key_algorithms
      if not first_common(family.algs, their_keys) then
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

action = function(host, port)
  local timeout = tonumber(fero.args.get(SCRIPT_NAME .. ".timeout")) or 10000
  local format = fero.args.get({ SCRIPT_NAME .. ".format", "ssh_hostkey" })
  local want = {}
  if type(format) == "string" then
    for f in format:lower():gmatch("[^,%s]+") do want[f] = true end
  end
  if want.all then want.md5, want.sha256, want.full = true, true, true end
  if not (want.md5 or want.sha256 or want.full) then want.md5 = true end
  if fero.verbosity() >= 2 then want.full = true end
  local offered -- the server's host key algorithms, once known
  local keys, lines = {}, {}
  for _, family in ipairs(FAMILIES) do
    if offered == nil or first_common(family.algs, offered) then
      local blob, their_keys, err = fetch(host, port, family, timeout)
      if their_keys then offered = their_keys end
      if blob then
        local bits, kind = key_bits(blob)
        local md5 = fero.hex(fero.crypto.digest("md5", blob), ":")
        local sha256 = "SHA256:" .. fero.base64.encode(fero.crypto.digest("sha256", blob)):gsub("=+$", "")
        local b64 = fero.base64.encode(blob)
        keys[#keys + 1] = {
          type = kind, bits = tostring(bits or "?"), fingerprint = md5,
          sha256 = sha256, key = b64,
        }
        if want.md5 then
          lines[#lines + 1] = string.format("%s %s (%s)", bits or "?", md5, family.label)
        end
        if want.sha256 then
          lines[#lines + 1] = string.format("%s %s (%s)", bits or "?", sha256, family.label)
        end
        if want.full then
          lines[#lines + 1] = kind .. " " .. b64
        end
      elseif err then
        fero.debug(1, family.label .. ": " .. tostring(err))
        -- Not an SSH-2 server, or no answer at all: stop here.
        if not offered and #keys == 0 then break end
      end
    end
  end
  if #keys == 0 then return nil end
  return keys, "\n  " .. table.concat(lines, "\n  ")
end
