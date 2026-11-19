-- FeroProbe script: http-webdav-scan
-- Written for FeroProbe from scratch, from RFC 4918 (WebDAV: the DAV
-- header, PROPFIND and the 207 Multi-Status answer); GPL-3.0-or-later.

description = [[
Detects WebDAV on a web server. Sends an OPTIONS request: a successful
answer whose DAV header names compliance class 1 marks WebDAV, and its
allowed methods, server name and date are shown. Then sends one
PROPFIND (Depth: 1, no body, which asks for all properties) and, when
the server answers with a WebDAV Multi-Status (207, a DAV: multistatus
document), lists the resources it names and any private (RFC 1918)
IPv4 addresses that leak in it. Nothing is created, changed or deleted.
Two requests with FeroProbe's User-Agent.

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
  if resp.status < 200 or resp.status >= 300 then return nil end
  local h = resp.header
  local dav = h["dav"]
  -- Compliance class 1 as one member of the DAV list (RFC 4918 10.1).
  local class1 = false
  for member in (dav or ""):gmatch("[^,]+") do
    if member:match("^%s*(.-)%s*$") == "1" then class1 = true end
  end
  if not class1 then return nil end
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
  -- A WebDAV Multi-Status: a multistatus element in the DAV: namespace,
  -- whatever prefix it carries, whatever its properties' own results.
  local _, _, prefix = body:find("<([%w%-%._]*:?)multistatus[%s>/]")
  if not prefix then return nil end
  -- The prefix as a pattern: its "-" and "." are magic there.
  local p = prefix:gsub("%p", "%%%0")
  local ns = prefix == "" and "xmlns" or ("xmlns:" .. p:sub(1, -3))
  if not body:find(ns .. "%s*=%s*[\"']DAV:[\"']") then return nil end
  local ret = {
    ["Server Type"] = resp.header["server"],
    ["Server Date"] = resp.header["date"],
  }
  local ips = private_ips(body)
  if #ips > 0 then ret["Exposed Internal IPs"] = ips end
  -- Each response's own href (its first child), not hrefs inside its
  -- properties (such as a lock root). The patterns never backtrack far:
  -- the href text runs to the next "<".
  local listing = {}
  -- Children may carry another prefix bound to DAV: (or none, under a
  -- default namespace), so any prefix is taken inside this document.
  local resp_pat = "<[%w%-%._]*:?response[%s>]"
  local href_pat = "^[^<]*<[%w%-%._]*:?href>%s*([^<]*)"
  local pos = 1
  while #listing < MAX_LISTED do
    local _, e = body:find(resp_pat, pos)
    if not e then break end
    local gt = body:find(">", e, true)
    if not gt then break end
    local href = body:match(href_pat, gt + 1)
    if href then
      href = href:gsub("%s+$", ""):gsub("&lt;", "<"):gsub("&gt;", ">")
        :gsub("&quot;", '"'):gsub("&apos;", "'"):gsub("&amp;", "&")
      listing[#listing + 1] = href
    end
    pos = gt + 1
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
