-- FeroProbe script: http-title
-- Written for FeroProbe from scratch; GPL-3.0-or-later, like FeroProbe.

description = [[
Shows the title of a web server's front page: the text of its HTML
<title> element. Follows up to three redirects, as long as they stay on
the scanned host and on ports the scan probed there, and says where the
page it shows came from when a redirect was followed. Over TLS or not,
as the port suggests, trying the other when the first gets no answer.

Script arguments:
  http-title.path  The page to fetch (default "/").
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "default", "discovery", "safe" }

portrule = fero.portrule.http

local entities = { amp = "&", lt = "<", gt = ">", quot = '"', apos = "'", nbsp = " " }

-- Character references, each decoded once, in one pass, so the text one
-- produces is never read as another. Unknown or invalid ones stay as
-- they are.
local function decode(s)
  return (s:gsub("&(#?)([xX]?)(%w+);", function(hash, x, body)
    if hash == "" then
      return entities[(x .. body):lower()]
    end
    local n
    if x ~= "" then
      if #body <= 6 and not body:find("%X") then n = tonumber(body, 16) end
    elseif #body <= 7 and not body:find("%D") then
      n = tonumber(body)
    end
    if n and n >= 0 and n < 0x110000 then return utf8.char(n) end
    return nil
  end))
end

action = function(host, port)
  local path = fero.args.get(SCRIPT_NAME .. ".path")
  if type(path) ~= "string" then path = "/" end
  local resp, err = fero.http.get(host, port, path, { truncated_ok = true })
  if not resp then
    fero.debug(1, "request failed: " .. tostring(err))
    return nil
  end
  local result = {}
  local lines = {}
  if resp.status >= 300 and resp.status < 400 and resp.header.location then
    result.redirect_url = resp.header.location
    return result, "Did not follow redirect to " .. resp.header.location
  end
  local lower = resp.body:lower()
  local open_end = select(2, lower:find("<title[^>]*>"))
  local title
  if open_end then
    local close = lower:find("</title", open_end + 1, true)
    title = resp.body:sub(open_end + 1, (close or (open_end + 1025)) - 1)
    title = decode(title):gsub("%s+", " "):match("^%s*(.-)%s*$")
  end
  if title and title ~= "" then
    if #title > 300 then title = title:sub(1, 300) .. "..." end
    result.title = title
    lines[#lines + 1] = title
  else
    local ctype = resp.header["content-type"]
    ctype = ctype and ctype:match("^[^;]+") or "no Content-Type"
    lines[#lines + 1] = "Site doesn't have a title (" .. ctype .. ")."
  end
  if #resp.location > 0 then
    result.redirect_url = resp.location[#resp.location]
    lines[#lines + 1] = "Requested resource was " .. result.redirect_url
  end
  return result, table.concat(lines, "\n")
end
