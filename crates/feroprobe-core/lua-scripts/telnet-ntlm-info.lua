-- FeroProbe script: telnet-ntlm-info
-- Written for FeroProbe from scratch, from RFC 854 and RFC 2941 (the
-- telnet AUTHENTICATION option), [MS-TNAP] 2.2 and [MS-NLMP] (through
-- fero.ntlm); GPL-3.0-or-later.

description = [[
Reads what a Microsoft telnet server with NTLM authentication says about
itself in its NTLM challenge: its NetBIOS and DNS computer and domain
names and the Windows version (its clock is noted for clock-skew). Sends
one telnet AUTHENTICATION IS NTLM sub-negotiation ([MS-TNAP]) carrying
an NTLM NEGOTIATE that names the workstation FEROPROBE and no user,
reads the server's REPLY with the challenge and closes. Nothing logs in.

Script arguments:
  telnet-ntlm-info.timeout  How long to wait for the answer, in
                            milliseconds (default 10000).
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "default", "discovery", "safe" }

portrule = fero.portrule.match({ 23 }, { "telnet" })

local IAC, SB, SE = "\xff", "\xfa", "\xf0"

-- IAC SB AUTHENTICATION IS, NTLM with the modifiers client-to-server and
-- one-way, then [MS-TNAP]'s NTLM_NEGOTIATE command, data size, buffer
-- type 2 and the message; IAC SE. (The message has no 0xff byte to
-- double.)
local function login_request()
  local m = fero.ntlm.negotiate_message()
  return IAC .. SB .. "\x25\x00\x0f\x00" .. "\x00"
    .. string.pack("<I4I4", #m, 2) .. m .. IAC .. SE
end

-- The data of the first AUTHENTICATION REPLY sub-negotiation in `buf`,
-- with doubled IAC bytes undone; nil when it has not come whole yet.
local function reply_data(buf)
  local start = buf:find(IAC .. SB .. "\x25\x02", 1, true)
  if not start then return nil end
  local out, i = {}, start + 4
  while i <= #buf do
    local c = buf:sub(i, i)
    if c == IAC then
      local n = buf:sub(i + 1, i + 1)
      if n == SE then return table.concat(out) end
      if n == "" then return nil end
      if n == IAC then out[#out + 1] = IAC end
      i = i + 2
    else
      out[#out + 1] = c
      i = i + 1
    end
  end
  return nil
end

action = function(host, port)
  local timeout = tonumber(fero.args.get(SCRIPT_NAME .. ".timeout")) or 10000
  local sock = fero.socket.new()
  sock:set_timeout(timeout)
  if not sock:connect(host, port) then return nil end
  if not sock:send(login_request()) then
    sock:close()
    return nil
  end
  -- The server's own option negotiation may come first; skip it.
  local buf, data = "", nil
  while not data and #buf <= 65536 do
    local ok, got = sock:receive()
    if not ok then break end
    buf = buf .. got
    data = reply_data(buf)
  end
  sock:close()
  if not data then return nil end
  return fero.ntlm.info(data)
end
