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

-- The position of the ">" that ends the tag whose text starts at `pos`,
-- skipping any ">" inside a quoted attribute value; the body's end when
-- there is none.
local function tag_end(body, pos)
  while true do
    local i = body:find("[\"'>]", pos)
    if not i then return #body end
    local c = body:sub(i, i)
    if c == ">" then return i end
    local close = body:find(c, i + 1, true)
    if not close then return #body end
    pos = close + 1
  end
end

-- The attributes of one tag's text, names in lower case: read from left
-- to right, each value (quoted, ending at the quote it started with, or
-- bare) taken whole before the next name, so text inside a value is
-- never read as an attribute.
local function attributes(tag)
  local attrs, pos = {}, 1
  while true do
    local s, e, name = tag:find("([%w%-:]+)", pos)
    if not s then break end
    name = name:lower()
    local _, eq = tag:find("^%s*=%s*", e + 1)
    if not eq then
      pos = e + 1
    else
      local q = tag:sub(eq + 1, eq + 1)
      local value
      if q == '"' or q == "'" then
        local close = tag:find(q, eq + 2, true) or (#tag + 1)
        value = tag:sub(eq + 2, close - 1)
        pos = close + 1
      else
        local _, ve = tag:find("^[^%s>]*", eq + 1)
        value = tag:sub(eq + 1, ve)
        pos = ve + 1
      end
      if attrs[name] == nil then attrs[name] = value end
    end
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
    local close = tag_end(body, e)
    local attrs = attributes(body:sub(e, close))
    pos = close + 1
    if attrs.name and attrs.name:lower() == "generator" and attrs.content and attrs.content ~= "" then
      return attrs.content
    end
  end
end
