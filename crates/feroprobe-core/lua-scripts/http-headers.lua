-- FeroProbe script: http-headers
-- Written for FeroProbe from scratch (RFC 9110); GPL-3.0-or-later.

description = [[
Lists the headers a web server sends back for its front page, as they
came: server software, cookies, security headers, caching and the rest.
Asks with HEAD, which carries no page, and with GET when the server
does not answer HEAD usefully (an error status, or no answer at all).
Follows no redirect: the headers shown are the first answer's.

Script arguments:
  http-headers.path    The page to ask for (default "/").
  http-headers.useget  Ask with GET straight away.
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "discovery", "safe" }

portrule = fero.portrule.http

action = function(host, port)
  local path = fero.args.get(SCRIPT_NAME .. ".path")
  if type(path) ~= "string" then path = "/" end
  local opts = { truncated_ok = true, redirect_ok = false }
  local method, resp, err = "HEAD", nil, nil
  if not fero.args.get(SCRIPT_NAME .. ".useget") then
    resp, err = fero.http.head(host, port, path, opts)
  end
  -- Some servers refuse HEAD (405, 501) or close without answering it.
  if not resp or resp.status >= 400 then
    method = "GET"
    resp, err = fero.http.get(host, port, path, opts)
  end
  if not resp then
    fero.debug(1, "request failed: " .. tostring(err))
    return nil
  end
  -- The text as nmap's: one header a line, indented under the name.
  local lines = { "" }
  local result = { status = resp["status-line"], headers = {} }
  for i, h in ipairs(resp.rawheader) do
    lines[#lines + 1] = "  " .. h
    result.headers[i] = h
  end
  lines[#lines + 1] = "  "
  lines[#lines + 1] = "  (Request type: " .. method .. ")"
  result.request_type = method
  return result, table.concat(lines, "\n")
end
