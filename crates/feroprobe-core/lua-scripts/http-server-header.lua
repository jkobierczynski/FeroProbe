-- FeroProbe script: http-server-header
-- Written for FeroProbe from scratch (RFC 9110); GPL-3.0-or-later.

description = [[
Shows the Server header of a web server's answer: the software it says
it runs, such as "nginx/1.24.0". Useful where -sV finds no version, or
on a port it was not run on. One GET request for the front page, no
redirect followed. Shows nothing when the server sends no Server header.
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "discovery", "safe", "version" }

portrule = fero.portrule.http

action = function(host, port)
  local resp, err = fero.http.get(host, port, "/", { truncated_ok = true, redirect_ok = false })
  if not resp then
    fero.debug(1, "request failed: " .. tostring(err))
    return nil
  end
  -- Each Server header, in order, without repeats.
  local servers, seen = {}, {}
  for _, h in ipairs(resp.rawheader) do
    local value = h:match("^[Ss][Ee][Rr][Vv][Ee][Rr]%s*:%s*(.-)%s*$")
    if value and value ~= "" and not seen[value] then
      seen[value] = true
      servers[#servers + 1] = value
    end
  end
  if #servers == 0 then return nil end
  return servers, table.concat(servers, "\n")
end
