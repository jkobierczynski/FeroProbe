-- FeroProbe script: imap-capabilities
-- Written for FeroProbe from scratch (RFC 9051, RFC 3501); GPL-3.0-or-later.

description = [[
Lists the capabilities an IMAP server announces in its answer to
CAPABILITY, such as IMAP4rev1, STARTTLS, IDLE and AUTH= mechanisms.
Logs in to nothing. Port 993 and services found to run over TLS are
spoken to over TLS.

Script arguments:
  imap-capabilities.timeout  How long to wait for each reply, in
                             milliseconds (default 10000).
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "default", "safe" }

portrule = fero.portrule.match({ 143, 993 }, { "imap", "imaps" })

local function tls(port)
  return port.number == 993 or port.service == "imaps"
    or (type(port.version) == "table" and port.version.service_tunnel == "ssl")
end

action = function(host, port)
  local timeout = tonumber(fero.args.get(SCRIPT_NAME .. ".timeout")) or 10000
  local sock = fero.socket.new()
  sock:set_timeout(timeout)
  if not sock:connect(host, port, tls(port) and "ssl" or "tcp") then return nil end
  local r = fero.reader(sock)
  local greeting = r:line()
  if not greeting or not greeting:match("^%* OK") and not greeting:match("^%* PREAUTH") then
    sock:close()
    return nil
  end
  sock:send("fp1 CAPABILITY\r\n")
  local caps
  for _ = 1, 1000 do
    local line = r:line()
    if not line then break end
    local list = line:match("^%* CAPABILITY (.*)$")
    if list then caps = list end
    if line:sub(1, 4) == "fp1 " then break end
  end
  sock:send("fp2 LOGOUT\r\n")
  sock:close()
  if not caps then return nil end
  local items = {}
  for item in caps:gmatch("%S+") do items[#items + 1] = item end
  if #items == 0 then return nil end
  return items, table.concat(items, " ")
end
