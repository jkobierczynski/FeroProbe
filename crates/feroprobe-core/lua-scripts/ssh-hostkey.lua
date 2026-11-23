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

-- One key family per connection, in the order they are shown.
local FAMILIES = {
  { label = "DSA", algs = { "ssh-dss" } },
  { label = "RSA", algs = { "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa" } },
  { label = "ECDSA", algs = { "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521" } },
  { label = "ED25519", algs = { "ssh-ed25519" } },
}

local function first_common(mine, theirs)
  local set = {}
  for _, v in ipairs(theirs) do set[v] = true end
  for _, v in ipairs(mine) do
    if set[v] then return v end
  end
  return nil
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
      local blob, their_keys, err = fero.ssh.host_key(host, port, family.algs, timeout)
      if their_keys then offered = their_keys end
      if blob then
        local bits, kind = fero.ssh.key_bits(blob)
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
