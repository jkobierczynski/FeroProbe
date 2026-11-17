-- FeroProbe script: x11-access
-- Written for FeroProbe from scratch (X Window System Protocol, X11R7,
-- chapter 8 "Connection Setup"); GPL-3.0-or-later.

description = [[
Says whether an X11 display server lets anyone connect, which would
let them watch the screen and send it keystrokes. Sends an X11
connection setup request without credentials and reads only whether the
server accepts it, then closes the connection. Shows nothing when the
server asks for authentication or refuses.
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "default", "auth", "safe" }

local X11_PORTS = {}
for p = 6000, 6009 do X11_PORTS[#X11_PORTS + 1] = p end
portrule = fero.portrule.match(X11_PORTS, { "X11", "x11" })

action = function(host, port)
  local sock = fero.socket.new()
  sock:set_timeout(8000)
  if not sock:connect(host, port) then return nil end
  -- Little-endian ('l'), protocol 11.0, no authorization name or data.
  sock:send(string.pack("<c1xI2I2I2I2xx", "l", 11, 0, 0, 0))
  local r = fero.reader(sock)
  local first = r:bytes(1)
  sock:close()
  if first and first:byte() == 1 then
    return "X server access is granted"
  end
  return nil
end
