-- FeroProbe script: http-cookie-flags
-- Written for FeroProbe from scratch, from RFC 6265 section 4.1 (the
-- Secure and HttpOnly cookie attributes); GPL-3.0-or-later.

description = [[
Checks the session cookies a web page sets (PHPSESSID, JSESSIONID,
ASP.NET_SessionId and the like): reports each one set without the
HttpOnly flag, and each one set over TLS without the Secure flag.
Other cookies are not reported. One GET with FeroProbe's User-Agent.

Script arguments:
  http-cookie-flags.path    The page to ask for (default "/").
  http-cookie-flags.cookie  Check only the cookie of this name, whatever
                            it is called.
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "default", "safe", "vuln" }

portrule = fero.portrule.http

-- Names that session cookies are commonly given.
local SESSION_NAMES = {
  "^PHPSESSID$",
  "^CFID$",
  "^CFTOKEN$",
  "^VOXSQSESS$",
  "^CAKEPHP$",
  "^FedAuth$",
  "^ASPXAUTH$",
  "^session$",
  "[Ss][Ee][Ss][Ss][Ii][Oo][Nn][^%a]*[Ii][Dd]",
}

local function default_is_session(name)
  for _, p in ipairs(SESSION_NAMES) do
    if name:find(p) then return true end
  end
  return false
end

action = function(host, port)
  local path = fero.args.get(SCRIPT_NAME .. ".path")
  if type(path) ~= "string" or path == "" then path = "/" end
  local only = fero.args.get(SCRIPT_NAME .. ".cookie")
  local is_session = default_is_session
  if type(only) == "string" then
    is_session = function(name) return name == only end
  end

  local resp, err = fero.http.get(host, port, path, { truncated_ok = true })
  if not resp then
    fero.debug(1, "request failed: " .. tostring(err))
    return nil
  end
  local found = fero.output_table()
  local count = 0
  for _, cookie in ipairs(resp.cookies) do
    if is_session(cookie.name) then
      local issues = {}
      if resp.ssl and not cookie.secure then
        issues[#issues + 1] = "secure flag not set and HTTPS in use"
      end
      if not cookie.httponly then
        issues[#issues + 1] = "httponly flag not set"
      end
      if #issues > 0 then
        if found[cookie.name] == nil then count = count + 1 end
        found[cookie.name] = issues
      end
    end
  end
  if count == 0 then return nil end
  local out = fero.output_table()
  out[path] = found
  return out
end
