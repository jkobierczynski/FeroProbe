-- FeroProbe script: ftp-syst
-- Written for FeroProbe from scratch (RFC 959); GPL-3.0-or-later.

description = [[
Asks an FTP server which system it runs on (SYST) and for its status
(STAT), without logging in. Many servers answer STAT only after a
login; then only the SYST answer is shown.

Script arguments:
  ftp-syst.timeout  How long to wait for each reply, in milliseconds
                    (default 8000).
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "default", "discovery", "safe" }

portrule = fero.portrule.match({ 21 }, { "ftp" })

-- The text of a reply, without its reply codes.
local function text(code, lines)
  local out = {}
  for i, line in ipairs(lines) do
    if (i == 1 or i == #lines) and line:sub(1, 3) == tostring(code) then
      line = line:sub(5)
    end
    out[#out + 1] = line
  end
  return out
end

action = function(host, port)
  local timeout = tonumber(fero.args.get(SCRIPT_NAME .. ".timeout")) or 8000
  local sock = fero.socket.new()
  sock:set_timeout(timeout)
  if not sock:connect(host, port) then return nil end
  local r = fero.reader(sock)
  local code = r:reply()
  if code ~= 220 then
    sock:close()
    return nil
  end
  local data, out = {}, {}
  sock:send("SYST\r\n")
  local lines
  code, lines = r:reply()
  if code == 215 then
    data.SYST = table.concat(text(code, lines), " ")
    out[#out + 1] = "SYST: " .. data.SYST
  end
  sock:send("STAT\r\n")
  code, lines = r:reply()
  if code == 211 or code == 212 or code == 213 then
    local t = text(code, lines)
    data.STAT = table.concat(t, "\n")
    out[#out + 1] = "STAT:"
    for _, l in ipairs(t) do out[#out + 1] = "  " .. l end
  end
  sock:send("QUIT\r\n")
  sock:close()
  if #out == 0 then return nil end
  return data, table.concat(out, "\n")
end
