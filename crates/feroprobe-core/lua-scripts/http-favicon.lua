-- FeroProbe script: http-favicon
-- Written for FeroProbe from scratch (the HTML "icon" link type and the
-- /favicon.ico convention, MD5 from RFC 1321); GPL-3.0-or-later.

description = [[
Fetches a web site's favicon (the small icon a browser shows for it)
and shows the MD5 hash of the icon, which identifies the software or
device behind many web interfaces. The icon is the one the front page
names in a <link rel="icon"> element, when that stays on the scanned
host and port, else /favicon.ico. FeroProbe carries no database of
known icons, so the hash is shown as unknown, and, as nmap does for an
unknown icon, only with -v. GETs with FeroProbe's User-Agent, three at
most.

Script arguments:
  favicon.uri   The icon's path, used instead of looking for it.
  favicon.root  The site's root path (default ""), prefixed to the
                paths asked for.
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
-- to right, each name taken whole (any character but space, quotes, ">",
-- "/" and "="), each value (quoted, ending at the quote it started with, or
-- bare) taken whole before the next name, so text inside a value is
-- never read as an attribute.
local function attributes(tag)
  local attrs, pos = {}, 1
  while true do
    local s, e, name = tag:find("([^%s\"'>/=]+)", pos)
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

-- The href of the first <link> whose rel names "icon", or nil.
local function find_icon(body)
  local pos = 1
  while true do
    local s, e = body:find("<%s*[Ll][Ii][Nn][Kk][%s/]", pos)
    if not s then return nil end
    local close = tag_end(body, e)
    local attrs = attributes(body:sub(e, close))
    pos = close + 1
    if attrs.rel and attrs.href then
      for word in attrs.rel:gmatch("%S+") do
        if word:lower() == "icon" then
          return (attrs.href:gsub("&amp;", "&"))
        end
      end
    end
  end
end

-- Whether `name` is the scanned host: its address, the name it was given
-- or its reverse DNS name.
local function is_target(host, name)
  name = name:lower():gsub("^%[(.*)%]$", "%1")
  return name == host.ip:lower()
    or (host.targetname and name == host.targetname:lower())
    or (host.name ~= "" and name == host.name:lower())
end

-- The path of `href` on this host and port, or nil when it points
-- elsewhere. `base` is the directory of the page it was found on.
local function same_site_path(host, port, href, base, ssl)
  local scheme, rest = href:match("^(%a[%w+.%-]*):(.*)$")
  if scheme then
    scheme = scheme:lower()
    if scheme ~= "http" and scheme ~= "https" then return nil end
  elseif href:sub(1, 2) == "//" then
    rest = href
  else
    if href:sub(1, 1) == "/" then return href end
    return base .. href
  end
  local authority, path = rest:match("^//([^/?#]*)(.*)$")
  if not authority then return nil end
  authority = authority:gsub("^.*@", "")
  local name, num = authority:match("^(%[[^%]]+%]):?(%d*)$")
  if not name then name, num = authority:match("^([^:]*):?(%d*)$") end
  if not name then return nil end
  local default = ((scheme or (ssl and "https" or "http")) == "https") and 443 or 80
  if (tonumber(num) or default) ~= port.number or not is_target(host, name) then
    return nil
  end
  if path == "" then path = "/" end
  return path
end

local function fetch(host, port, path)
  local resp, err = fero.http.get(host, port, path, { truncated_ok = true })
  if not resp then
    fero.debug(1, path .. ": " .. tostring(err))
  end
  return resp
end

action = function(host, port)
  local root = fero.args.get("favicon.root")
  if type(root) ~= "string" then root = "" end
  local uri = fero.args.get("favicon.uri")
  local icon
  if type(uri) == "string" then
    icon = fetch(host, port, root .. "/" .. (uri:gsub("^/+", "")))
  else
    local page = fetch(host, port, root .. "/")
    if page and (page.status == 200 or page.status == 503) then
      local href = find_icon(page.body)
      local path = href and same_site_path(host, port, href, root .. "/", page.ssl)
      if path then
        fero.debug(1, "icon named by the page: " .. path)
        icon = fetch(host, port, path)
      elseif href then
        fero.debug(1, "icon elsewhere, not fetched: " .. href)
      end
    end
    if not icon or icon.status ~= 200 or icon.truncated then
      icon = fetch(host, port, root .. "/favicon.ico")
    end
  end
  -- An icon cut short by the body size limit would give a wrong hash.
  if not icon or icon.status ~= 200 or icon.truncated then return nil end
  local md5 = fero.hex(fero.crypto.digest("md5", icon.body)):upper()
  fero.debug(1, "favicon MD5 " .. md5)
  if fero.verbosity() > 0 then
    return "Unknown favicon MD5: " .. md5
  end
  return nil
end
