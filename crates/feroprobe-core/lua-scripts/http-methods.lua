-- FeroProbe script: http-methods
-- Written for FeroProbe from scratch (RFC 9110 section 9.3.7);
-- GPL-3.0-or-later.

description = [[
Asks a web server which request methods it supports, with an OPTIONS
request, and lists them from its Allow header. Methods beyond GET,
HEAD, POST and OPTIONS (such as PUT, DELETE or TRACE) are listed again
as potentially risky, since they may let a client change or reflect
content. Only OPTIONS is sent; no method is tried.

Script arguments:
  http-methods.url-path  The path to ask about (default "/").
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "default", "safe" }

portrule = fero.portrule.http

local PLAIN = { GET = true, HEAD = true, POST = true, OPTIONS = true }

action = function(host, port)
  local path = fero.args.get(SCRIPT_NAME .. ".url-path")
  if type(path) ~= "string" then path = "/" end
  local resp, err = fero.http.request("OPTIONS", host, port, path, { redirect_ok = false })
  if not resp then
    fero.debug(1, "request failed: " .. tostring(err))
    return nil
  end
  local allow = resp.header["allow"] or resp.header["public"]
  if not allow then return nil end
  local methods, risky, seen = {}, {}, {}
  for m in allow:gmatch("[^,%s]+") do
    m = m:upper()
    if not seen[m] then
      seen[m] = true
      methods[#methods + 1] = m
      if not PLAIN[m] then risky[#risky + 1] = m end
    end
  end
  if #methods == 0 then return nil end
  local data = { ["Supported Methods"] = methods }
  local lines = { "Supported Methods: " .. table.concat(methods, " ") }
  if #risky > 0 then
    data["Potentially risky methods"] = risky
    lines[#lines + 1] = "Potentially risky methods: " .. table.concat(risky, " ")
  end
  if path ~= "/" then
    lines[#lines + 1] = "Path tested: " .. path
  end
  return data, "\n  " .. table.concat(lines, "\n  ")
end
