-- FeroProbe script: http-robots.txt
-- Written for FeroProbe from scratch (RFC 9309); GPL-3.0-or-later.

description = [[
Reads a web server's /robots.txt and lists the paths it asks crawlers
not to visit (its Disallow lines), which often name the parts of a site
its owner considers private. At most 100 paths are shown.
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "default", "discovery", "safe" }

portrule = fero.portrule.http

local MAX_SHOWN = 100

action = function(host, port)
  local resp, err = fero.http.get(host, port, "/robots.txt", { truncated_ok = true, redirect_ok = false })
  if not resp then
    fero.debug(1, "request failed: " .. tostring(err))
    return nil
  end
  if resp.status ~= 200 then return nil end
  local paths, seen = {}, {}
  local count = 0
  for line in resp.body:gmatch("[^\r\n]+") do
    local path = line:gsub("#.*$", ""):match("^%s*[Dd][Ii][Ss][Aa][Ll][Ll][Oo][Ww]%s*:%s*(%S*)")
    if path and path ~= "" and not seen[path] then
      seen[path] = true
      count = count + 1
      if #paths < MAX_SHOWN then paths[#paths + 1] = path end
    end
  end
  if count == 0 then return nil end
  local head = count == 1 and "1 disallowed entry" or (count .. " disallowed entries")
  local lines = { head }
  -- Several paths per line, as a crawler file is often long.
  local row = {}
  for _, p in ipairs(paths) do
    row[#row + 1] = p
    if #row == 8 then
      lines[#lines + 1] = table.concat(row, " ")
      row = {}
    end
  end
  if #row > 0 then lines[#lines + 1] = table.concat(row, " ") end
  if count > #paths then lines[#lines + 1] = "... and " .. (count - #paths) .. " more" end
  return { count = tostring(count), paths = paths }, table.concat(lines, "\n")
end
