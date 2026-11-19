-- FeroProbe script: http-webdav-scan
-- Written for FeroProbe from scratch, from RFC 4918 (WebDAV: the DAV
-- header, PROPFIND and the 207 Multi-Status answer); GPL-3.0-or-later.

description = [[
Detects WebDAV on a web server. Sends an OPTIONS request: a DAV header
naming compliance class 1 marks WebDAV, and the answer's allowed methods,
server name and date are shown. Then sends one PROPFIND (Depth: 1, no
body, which asks for all properties) and, when the server answers with
a WebDAV Multi-Status, lists the resources it names and any private
(RFC 1918) IPv4 addresses that leak in it. Nothing is created, changed
or deleted. Two requests with FeroProbe's User-Agent.

Script arguments:
  http-webdav-scan.path  The path to ask about (default "/").
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "default", "discovery", "safe" }

portrule = fero.portrule.http

-- At most this many resources are listed.
local MAX_LISTED = 100

local function options(host, port, path)
  local resp, err = fero.http.request("OPTIONS", host, port, path, { redirect_ok = false })
  if not resp then
    fero.debug(1, "OPTIONS failed: " .. tostring(err))
    return nil
  end
  if resp.status ~= 200 then return nil end
  local h = resp.header
  local dav = h["dav"]
  if not dav or not dav:find("%f[%w]1%f[^%w]") then return nil end
  local kind = "Unknown"
  if h["x-msdavext"] then kind = "SHAREPOINT DAV" end
  if dav:lower():find("apache", 1, true) then kind = "Apache DAV" end
  return {
    ["Allowed Methods"] = h["allow"],
    ["Public Options"] = h["public"],
    ["Server Type"] = h["server"],
    ["Server Date"] = h["date"],
    ["WebDAV type"] = kind,
  }
end

-- Private IPv4 addresses (RFC 1918) in `body`, each once, in the order
-- they first appear.
local function private_ips(body)
  local list, seen = {}, {}
  for a, b, c, d in body:gmatch("%f[%d](%d+)%.(%d+)%.(%d+)%.(%d+)%f[%D]") do
    local n = { tonumber(a), tonumber(b), tonumber(c), tonumber(d) }
    local valid = #a <= 3 and #b <= 3 and #c <= 3 and #d <= 3
    for _, x in ipairs(n) do
      if x > 255 then valid = false end
    end
    local private = n[1] == 10
      or (n[1] == 172 and n[2] >= 16 and n[2] <= 31)
      or (n[1] == 192 and n[2] == 168)
    local ip = table.concat(n, ".")
    if valid and private and not seen[ip] then
      seen[ip] = true
      list[#list + 1] = ip
    end
  end
  return list
end

local function propfind(host, port, path)
  local resp, err = fero.http.request("PROPFIND", host, port, path, {
    header = { Depth = "1" },
    content = "",
    redirect_ok = false,
    truncated_ok = true,
  })
  if not resp then
    fero.debug(1, "PROPFIND failed: " .. tostring(err))
    return nil
  end
  if resp.status ~= 207 then return nil end
  local body = resp.body
  -- A Multi-Status with at least one property found ("200 OK"), whatever
  -- the XML prefix of the DAV: namespace.
  if not body:find("<[%w%-%._]*:?[Ss][Tt][Aa][Tt][Uu][Ss]>%s*HTTP/1%.[01] 200") then
    return nil
  end
  local ret = {
    ["Server Type"] = resp.header["server"],
    ["Server Date"] = resp.header["date"],
  }
  local ips = private_ips(body)
  if #ips > 0 then ret["Exposed Internal IPs"] = ips end
  local listing = {}
  for href in body:gmatch("<[%w%-%._]*:?[Hh][Rr][Ee][Ff]>%s*([^<]-)%s*</") do
    if #listing >= MAX_LISTED then break end
    listing[#listing + 1] = href
  end
  if #listing > 0 then ret["Directory Listing"] = listing end
  return ret
end

local ORDER = {
  "Allowed Methods",
  "Public Options",
  "Server Type",
  "Server Date",
  "WebDAV type",
  "Exposed Internal IPs",
  "Directory Listing",
}

action = function(host, port)
  local path = fero.args.get(SCRIPT_NAME .. ".path")
  if type(path) ~= "string" or path == "" then path = "/" end
  local opt = options(host, port, path) or {}
  local prop = propfind(host, port, path) or {}
  local out = fero.output_table()
  for _, name in ipairs(ORDER) do
    local v = opt[name]
    if v == nil then v = prop[name] end
    if v ~= nil then out[name] = v end
  end
  if next(out) == nil then return nil end
  return out
end
