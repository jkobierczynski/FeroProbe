-- FeroProbe script: sshv1
-- Written for FeroProbe from scratch (RFC 4253 section 5.1);
-- GPL-3.0-or-later.

description = [[
Says whether an SSH server still accepts the obsolete and insecure
SSH protocol version 1, from the version it announces in its greeting
("SSH-1.5-..." or "SSH-1.99-..."). Reads the greeting only and sends
nothing. Shows nothing for a server that speaks version 2 only.

Unlike nmap's script of the same name it does not go on to read the
server's version 1 keys and ciphers.
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "default", "safe" }

portrule = fero.portrule.match({ 22 }, { "ssh" })

action = function(host, port)
  local sock = fero.socket.new()
  sock:set_timeout(8000)
  if not sock:connect(host, port) then return nil end
  local r = fero.reader(sock)
  -- RFC 4253 allows other lines before the version line.
  for _ = 1, 20 do
    local line = r:line()
    if not line then break end
    local version = line:match("^SSH%-(%d+%.%d+)%-")
    if version then
      sock:close()
      if version:match("^1%.") then
        return "Server supports SSHv1 (announces protocol " .. version .. ")"
      end
      return nil
    end
  end
  sock:close()
  return nil
end
