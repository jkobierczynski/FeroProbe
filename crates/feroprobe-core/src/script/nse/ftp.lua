-- NSE compatibility layer: the `ftp` module (RFC 959 control channel).
-- Written for FeroProbe from nmap's public API documentation (not from
-- nselib); GPL-3.0-or-later, like FeroProbe.
-- Data connections (ftp.pasv) go to the port the server names, which the
-- scan did not probe; FeroProbe's scope rule refuses them, so pasv fails.
local fero = ...
local nmap = require "nmap"
local stdnse = require "stdnse"
local ftp = {}

-- Read one reply, single- or multi-line ("123-" ... "123 "), through a
-- buffer from stdnse.make_buffer: the code as a number and the text (lines
-- joined with newlines), or nil and a message.
function ftp.read_reply(buffer)
  local line, err = buffer()
  if not line then return nil, err or "no reply" end
  local code, sep, text = line:match("^(%d%d%d)([ -]?)(.*)$")
  if not code then return nil, "not an FTP reply: " .. line end
  local lines = { text }
  if sep == "-" then
    for _ = 1, 1000 do
      line, err = buffer()
      if not line then return nil, err or "reply cut short" end
      local c2, s2, t2 = line:match("^(%d%d%d)([ -]?)(.*)$")
      if c2 == code and s2 ~= "-" then
        lines[#lines + 1] = t2
        break
      end
      lines[#lines + 1] = line
    end
  end
  return tonumber(code), table.concat(lines, "\n")
end

-- Connect and read the greeting: the socket, the greeting's code and
-- text, and the reply buffer; or nil and a message. opts.request_timeout
-- (milliseconds) sets the socket's timeout.
function ftp.connect(host, port, opts)
  opts = opts or {}
  local sock = nmap.new_socket()
  sock:set_timeout(tonumber(opts.request_timeout) or 10000)
  local ok, err = sock:connect(host, port, "tcp")
  if not ok then return nil, err end
  local buffer = stdnse.make_buffer(sock, "\r?\n")
  local code, message = ftp.read_reply(buffer)
  if not code then
    sock:close()
    return nil, message
  end
  return sock, code, message, buffer
end

-- Log in with USER, PASS and, if asked for, ACCT: true or false, then the
-- last reply's code and text (nil and a message when the connection fails).
function ftp.auth(socket, buffer, username, password, acct)
  local function cmd(line)
    local ok, err = socket:send(line .. "\r\n")
    if not ok then return nil, err end
    return ftp.read_reply(buffer)
  end
  local code, message = cmd("USER " .. tostring(username))
  if code == 331 then code, message = cmd("PASS " .. tostring(password or "")) end
  if code == 332 and acct then code, message = cmd("ACCT " .. tostring(acct)) end
  if not code then return nil, message end
  return code == 230 or code == 202, code, message
end

-- Ask for passive mode and connect to the data port the server names: the
-- data socket, or nil and a message. Within a scan that port is out of
-- scope unless the scan probed it, so this usually fails.
function ftp.pasv(socket, buffer)
  local ok, err = socket:send("PASV\r\n")
  if not ok then return nil, err end
  local code, message = ftp.read_reply(buffer)
  if code ~= 227 then return nil, message or "no passive mode" end
  local a, b, c, d, p1, p2 = message:match("(%d+),(%d+),(%d+),(%d+),(%d+),(%d+)")
  if not a then return nil, "cannot read the PASV reply" end
  local _, _, _, peer = socket:get_info()
  local data = nmap.new_socket()
  local port = tonumber(p1) * 256 + tonumber(p2)
  -- The address in the reply is not trusted: the data connection goes to
  -- the host the control connection is on.
  ok, err = data:connect(peer, port, "tcp")
  if not ok then return nil, err end
  return data
end

-- Say QUIT and close the connection.
function ftp.close(socket)
  socket:send("QUIT\r\n")
  return socket:close()
end

return ftp
