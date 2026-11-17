-- FeroProbe script: smtp-commands
-- Written for FeroProbe from scratch (RFC 5321); GPL-3.0-or-later.

description = [[
Lists the extensions an SMTP server announces in its answer to EHLO,
such as PIPELINING, SIZE, STARTTLS and AUTH, after the name it gives
for itself. Sends "EHLO feroprobe.invalid" (a reserved name, so it is
recognizable in mail logs), then QUIT. Ports 465 and services found to
run over TLS are spoken to over TLS.

Script arguments:
  smtp.domain            The name to send with EHLO instead (nmap's
                         argument name).
  smtp-commands.timeout  How long to wait for each reply, in
                         milliseconds (default 10000).
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "default", "discovery", "safe" }

portrule = fero.portrule.match({ 25, 465, 587 }, { "smtp", "smtps", "submission", "submissions" })

local function tls(port)
  return port.number == 465 or port.service == "smtps" or port.service == "submissions"
    or (type(port.version) == "table" and port.version.service_tunnel == "ssl")
end

action = function(host, port)
  local timeout = tonumber(fero.args.get(SCRIPT_NAME .. ".timeout")) or 10000
  local sock = fero.socket.new()
  sock:set_timeout(timeout)
  if not sock:connect(host, port, tls(port) and "ssl" or "tcp") then return nil end
  local r = fero.reader(sock)
  local code = r:reply()
  if code ~= 220 then
    sock:close()
    return nil
  end
  local domain = fero.args.get("smtp.domain")
  if type(domain) ~= "string" or not domain:match("^[%w%.%-%[%]:]+$") then
    domain = "feroprobe.invalid"
  end
  sock:send("EHLO " .. domain .. "\r\n")
  local lines
  code, lines = r:reply()
  sock:send("QUIT\r\n")
  sock:close()
  if code ~= 250 then return nil end
  local items = {}
  for _, line in ipairs(lines) do
    local item = line:sub(5)
    if item ~= "" then items[#items + 1] = item end
  end
  if #items == 0 then return nil end
  return items, table.concat(items, ", ")
end
