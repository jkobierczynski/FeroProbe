-- FeroProbe script: http-cors
-- Written for FeroProbe from scratch, from the Fetch standard's CORS
-- protocol (preflight requests); GPL-3.0-or-later.

description = [[
Asks a web server which request methods it lets other web sites' pages
use (Cross-Origin Resource Sharing). Sends one CORS preflight (OPTIONS
with Origin and Access-Control-Request-Method) per method: HEAD, GET,
POST, PUT, DELETE, TRACE, OPTIONS, CONNECT and PATCH, and lists the
methods whose answer allows both the origin (by name or "*") and the
method. Only OPTIONS is sent; no method is tried. FeroProbe's
User-Agent marks each request.

Script arguments:
  http-cors.path    The path to ask about (default "/").
  http-cors.origin  The Origin to name (default "example.com").
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "default", "discovery", "safe" }

portrule = fero.portrule.http

local METHODS = { "HEAD", "GET", "POST", "PUT", "DELETE", "TRACE", "OPTIONS", "CONNECT", "PATCH" }

local function origin_ok(allowed, origin)
  if not allowed then return false end
  for o in allowed:gmatch("%S+") do
    if o == "*" or o == origin then return true end
  end
  return false
end

local function method_ok(allowed, method)
  if not allowed then return false end
  for m in allowed:gmatch("[^,%s]+") do
    if m == method then return true end
  end
  return false
end

action = function(host, port)
  local path = fero.args.get(SCRIPT_NAME .. ".path")
  if type(path) ~= "string" or path == "" then path = "/" end
  local origin = fero.args.get(SCRIPT_NAME .. ".origin")
  if type(origin) ~= "string" or origin == "" then origin = "example.com" end
  local allowed = {}
  for _, method in ipairs(METHODS) do
    local resp, err = fero.http.request("OPTIONS", host, port, path, {
      header = { Origin = origin, ["Access-Control-Request-Method"] = method },
      redirect_ok = false,
    })
    if not resp then
      fero.debug(1, method .. ": " .. tostring(err))
      -- A server that does not answer one preflight will not answer the
      -- next ones either.
      if err == "TIMEOUT" then break end
    elseif origin_ok(resp.header["access-control-allow-origin"], origin)
      and method_ok(resp.header["access-control-allow-methods"], method) then
      allowed[#allowed + 1] = method
    end
  end
  if #allowed == 0 then return nil end
  return table.concat(allowed, " ")
end
