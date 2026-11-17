-- FeroProbe script: banner
-- Written for FeroProbe from scratch; GPL-3.0-or-later, like FeroProbe.

description = [[
Shows the first line of text a TCP service sends when a connection
opens, such as an SSH, SMTP or FTP greeting. Sends nothing itself, so
services that wait for the client to speak first show no banner.

Script arguments:
  banner.timeout  How long to wait for the greeting, in milliseconds
                  (default 5000).
  banner.length   The most characters of the line to show (default 200).
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "discovery", "safe" }

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end

action = function(host, port)
  local timeout = tonumber(fero.args.get(SCRIPT_NAME .. ".timeout")) or 5000
  local length = tonumber(fero.args.get(SCRIPT_NAME .. ".length")) or 200
  local sock = fero.socket.new()
  sock:set_timeout(timeout)
  local ok, err = sock:connect(host, port)
  if not ok then
    fero.debug(1, "connect failed: " .. tostring(err))
    return nil
  end
  local status, data = sock:receive_lines(1)
  sock:close()
  if not status then
    return nil
  end
  local line = data:match("^([^\r\n]*)")
  if line == nil or line == "" then
    return nil
  end
  if #line > length then
    line = line:sub(1, length) .. "..."
  end
  return line
end
