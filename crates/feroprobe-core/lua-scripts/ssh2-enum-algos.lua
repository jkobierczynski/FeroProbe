-- FeroProbe script: ssh2-enum-algos
-- Written for FeroProbe from scratch (RFC 4253 section 7.1, RFC 4251);
-- GPL-3.0-or-later.

description = [[
Lists the algorithms an SSH-2 server offers in its key exchange
initialisation (KEXINIT): key exchange methods, host key types,
ciphers, MACs and compression. Without -v only the number of each is
shown; with -v each algorithm is listed, in the server's order of
preference. When the server offers the same list in both directions
(client to server and server to client), it is shown once.

The script reads the server's version line, sends its own
("SSH-2.0-FeroProbe_Scripting_Engine") and a KEXINIT, reads the
server's KEXINIT and closes the connection: no key exchange happens and
nothing logs in.

Script arguments:
  ssh2-enum-algos.timeout  How long to wait for each answer, in
                           milliseconds (default 10000).
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "discovery", "safe" }

portrule = fero.portrule.match({ 22 }, { "ssh" })

-- What FeroProbe's KEXINIT offers. The server sends its own lists
-- whatever ours say; these are common names so that a server reading
-- ours finds nothing odd in them.
local OFFER = {
  kex_algorithms = "curve25519-sha256,curve25519-sha256@libssh.org,"
    .. "diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,"
    .. "diffie-hellman-group18-sha512,diffie-hellman-group14-sha1",
  server_host_key_algorithms = "ssh-ed25519,ecdsa-sha2-nistp256,"
    .. "rsa-sha2-512,rsa-sha2-256,ssh-rsa",
  encryption_algorithms_client_to_server = "chacha20-poly1305@openssh.com,"
    .. "aes128-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com",
  mac_algorithms_client_to_server = "hmac-sha2-256-etm@openssh.com,"
    .. "hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1",
  compression_algorithms_client_to_server = "none",
}
OFFER.encryption_algorithms_server_to_client = OFFER.encryption_algorithms_client_to_server
OFFER.mac_algorithms_server_to_client = OFFER.mac_algorithms_client_to_server
OFFER.compression_algorithms_server_to_client = OFFER.compression_algorithms_client_to_server

-- The groups shown, in order; the directional ones are folded into one
-- entry when both directions are the same.
local SHOWN = {
  "kex_algorithms", "server_host_key_algorithms",
  "encryption_algorithms", "mac_algorithms", "compression_algorithms",
}

local function same(a, b)
  if #a ~= #b then return false end
  for i = 1, #a do
    if a[i] ~= b[i] then return false end
  end
  return true
end

action = function(host, port)
  local timeout = tonumber(fero.args.get(SCRIPT_NAME .. ".timeout")) or 10000
  local sock, r = fero.ssh.connect(host, port, timeout)
  if not sock then
    fero.debug(1, tostring(r))
    return nil
  end
  sock:send(fero.ssh.packet(fero.ssh.kexinit(OFFER)))
  local theirs, err = fero.ssh.read_kexinit(r)
  sock:close()
  if not theirs then
    fero.debug(1, tostring(err))
    return nil
  end

  local out = fero.output_table()
  local lines = {}
  local verbose = fero.verbosity() >= 1
  local function add(name, list)
    out[name] = list
    lines[#lines + 1] = string.format("%s: (%d)", name, #list)
    if verbose then
      for _, alg in ipairs(list) do lines[#lines + 1] = "    " .. alg end
    end
  end
  for _, name in ipairs(SHOWN) do
    local whole = theirs[name]
    if whole then
      add(name, whole)
    else
      local c2s = theirs[name .. "_client_to_server"]
      local s2c = theirs[name .. "_server_to_client"]
      if same(c2s, s2c) then
        add(name, c2s)
      else
        add(name .. "_client_to_server", c2s)
        add(name .. "_server_to_client", s2c)
      end
    end
  end
  return out, "\n  " .. table.concat(lines, "\n  ")
end
