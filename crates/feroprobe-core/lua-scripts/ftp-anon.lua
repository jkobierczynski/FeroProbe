-- FeroProbe script: ftp-anon
-- Written for FeroProbe from scratch (RFC 959, RFC 1635); GPL-3.0-or-later.

description = [[
Says whether an FTP server lets anyone log in anonymously: logs in as
"anonymous" with the password "feroprobe@" (RFC 1635), then quits.

Unlike nmap's script of the same name it lists no files: a listing
comes over a second connection to a port the server picks, which is
outside what the scan probed, so FeroProbe's scope rule does not allow
it.

Script arguments:
  ftp-anon.timeout  How long to wait for each reply, in milliseconds
                    (default 8000).
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "default", "auth", "safe" }

portrule = fero.portrule.match({ 21 }, { "ftp" })

action = function(host, port)
  local timeout = tonumber(fero.args.get(SCRIPT_NAME .. ".timeout")) or 8000
  local sock = fero.socket.new()
  sock:set_timeout(timeout)
  local ok, err = sock:connect(host, port)
  if not ok then
    fero.debug(1, "connect failed: " .. tostring(err))
    return nil
  end
  local r = fero.reader(sock)
  local code, lines = r:reply()
  if code ~= 220 then
    fero.debug(1, "no FTP greeting: " .. tostring(lines))
    sock:close()
    return nil
  end
  local result
  sock:send("USER anonymous\r\n")
  code, lines = r:reply()
  if code == 331 then
    sock:send("PASS feroprobe@\r\n")
    code, lines = r:reply()
  end
  if code == 230 then
    result = "Anonymous FTP login allowed (FTP code 230)"
  elseif code then
    fero.debug(1, "anonymous login refused: " .. lines[#lines])
  end
  sock:send("QUIT\r\n")
  sock:close()
  return result
end
