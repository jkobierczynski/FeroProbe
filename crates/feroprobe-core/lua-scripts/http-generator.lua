-- FeroProbe script: http-generator
-- Written for FeroProbe from scratch (the HTML "generator" meta name);
-- GPL-3.0-or-later.

description = [[
Shows the "generator" meta tag of a web page, in which content
management systems and site builders often name themselves and their
version (WordPress, Joomla!, TYPO3, Drupal, ...). One GET with
FeroProbe's User-Agent, following up to three redirects that stay on
the scanned host.

Script arguments:
  http-generator.path       The page to read (default "/").
  http-generator.redirects  How many redirects to follow (default 3).
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "default", "discovery", "safe" }

portrule = fero.portrule.http

-- The attributes of one tag's text, names in lower case.
local function attributes(tag)
  local attrs = {}
  for name, _, value in tag:gmatch("([%w%-:]+)%s*=%s*([\"'])(.-)%2") do
    attrs[name:lower()] = attrs[name:lower()] or value
  end
  for name, value in tag:gmatch("([%w%-:]+)%s*=%s*([^%s\"'>]+)") do
    attrs[name:lower()] = attrs[name:lower()] or value
  end
  return attrs
end

action = function(host, port)
  local path = fero.args.get(SCRIPT_NAME .. ".path")
  if type(path) ~= "string" or path == "" then path = "/" end
  local redirects = math.tointeger(tonumber(fero.args.get(SCRIPT_NAME .. ".redirects"))) or 3
  local resp, err = fero.http.get(host, port, path, { redirect_ok = redirects, truncated_ok = true })
  if not resp then
    fero.debug(1, "request failed: " .. tostring(err))
    return nil
  end
  local body = resp.body
  local pos = 1
  while true do
    local s, e = body:find("<%s*[Mm][Ee][Tt][Aa][%s/]", pos)
    if not s then return nil end
    local close = body:find(">", e, true) or #body
    local attrs = attributes(body:sub(e, close))
    pos = close + 1
    if attrs.name and attrs.name:lower() == "generator" and attrs.content and attrs.content ~= "" then
      return attrs.content
    end
  end
end
