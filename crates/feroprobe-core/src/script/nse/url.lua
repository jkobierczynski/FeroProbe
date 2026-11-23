-- NSE compatibility layer: the `url` module (RFC 3986 URLs).
-- Written for FeroProbe from nmap's public API documentation (not from
-- nselib); GPL-3.0-or-later, like FeroProbe.
local url = {}

url.escape = function(s)
  return (tostring(s):gsub("[^%w%-%._~]", function(c)
    return string.format("%%%02X", c:byte())
  end))
end

url.unescape = function(s)
  return (tostring(s):gsub("%%(%x%x)", function(h) return string.char(tonumber(h, 16)) end))
end

local DEFAULT_PORTS = { http = 80, https = 443, ftp = 21, ftps = 990, ws = 80, wss = 443 }
url.get_default_port = function(scheme)
  return DEFAULT_PORTS[tostring(scheme):lower()]
end

-- The parts of a URL: scheme, authority, userinfo, user, password,
-- host, port (a number), path, params, query, fragment; nil parts left
-- out. "ascii_host" repeats host.
url.parse = function(s, default)
  local p = {}
  if default then for k, v in pairs(default) do p[k] = v end end
  s = tostring(s)
  local hash = s:find("#", 1, true)
  if hash then
    p.fragment = s:sub(hash + 1)
    s = s:sub(1, hash - 1)
  end
  local scheme, rest = s:match("^([%a][%w+%-.]*):(.*)$")
  if scheme then p.scheme = scheme:lower(); s = rest end
  local authority, path = s:match("^//([^/?]*)(.*)$")
  if authority then
    p.authority = authority
    local userinfo, hostport = authority:match("^(.*)@(.*)$")
    if userinfo then
      p.userinfo = userinfo
      p.user, p.password = userinfo:match("^([^:]*):?(.*)$")
      if p.password == "" and not userinfo:find(":") then p.password = nil end
    else
      hostport = authority
    end
    local host, port = hostport:match("^%[(.-)%]:?(%d*)$")
    if not host then host, port = hostport:match("^([^:]*):?(%d*)$") end
    if host then
      p.host = host
      p.ascii_host = host
      if port and port ~= "" then p.port = tonumber(port) end
    end
    s = path
  end
  local q = s:find("?", 1, true)
  if q then
    p.query = s:sub(q + 1)
    s = s:sub(1, q - 1)
  end
  local params
  local path_only, ps = s:match("^([^;]*);(.*)$")
  if path_only then s, params = path_only, ps; p.params = params end
  if s ~= "" then p.path = s end
  return p
end

url.build = function(p)
  local out = {}
  if p.scheme then out[#out + 1] = p.scheme .. ":" end
  local authority = p.authority
  if p.host then
    local h = p.host
    if h:find(":") then h = "[" .. h .. "]" end
    authority = h
    if p.port then authority = authority .. ":" .. p.port end
    if p.userinfo then
      authority = p.userinfo .. "@" .. authority
    elseif p.user then
      authority = p.user .. (p.password and (":" .. p.password) or "") .. "@" .. authority
    end
  end
  if authority then out[#out + 1] = "//" .. authority end
  out[#out + 1] = p.path or ""
  if p.params then out[#out + 1] = ";" .. p.params end
  if p.query then out[#out + 1] = "?" .. p.query end
  if p.fragment then out[#out + 1] = "#" .. p.fragment end
  return table.concat(out)
end

url.parse_query = function(q)
  local t = {}
  for part in tostring(q):gmatch("[^&;]+") do
    local k, v = part:match("^([^=]*)=?(.*)$")
    t[url.unescape((k:gsub("%+", " ")))] = url.unescape((v:gsub("%+", " ")))
  end
  return t
end

url.build_query = function(t)
  local keys = {}
  for k in pairs(t) do keys[#keys + 1] = tostring(k) end
  table.sort(keys)
  local parts = {}
  for _, k in ipairs(keys) do
    parts[#parts + 1] = url.escape(k) .. "=" .. url.escape(tostring(t[k]))
  end
  return table.concat(parts, "&")
end

-- "/a/b/" as { "a", "b", is_absolute = 1, is_directory = 1 }.
url.parse_path = function(path)
  local t = {}
  path = tostring(path)
  for seg in path:gmatch("[^/]+") do t[#t + 1] = url.unescape(seg) end
  if path:sub(1, 1) == "/" then t.is_absolute = 1 end
  if path:sub(-1) == "/" and #path > 1 then t.is_directory = 1 end
  return t
end

url.build_path = function(parsed, unsafe)
  local segs = {}
  for i, s in ipairs(parsed) do segs[i] = unsafe and s or url.escape(s) end
  local p = table.concat(segs, "/")
  if parsed.is_absolute then p = "/" .. p end
  if parsed.is_directory and #segs > 0 then p = p .. "/" end
  return p
end

-- RFC 3986 section 5.2.4: remove "." and ".." segments.
local function remove_dots(path)
  local out = {}
  local input = path
  while input ~= "" do
    if input:sub(1, 3) == "../" then input = input:sub(4)
    elseif input:sub(1, 2) == "./" then input = input:sub(3)
    elseif input:sub(1, 3) == "/./" then input = input:sub(3)
    elseif input == "/." then input = "/"
    elseif input:sub(1, 4) == "/../" then input = input:sub(4); out[#out] = nil
    elseif input == "/.." then input = "/"; out[#out] = nil
    elseif input == "." or input == ".." then input = ""
    else
      local seg, rest = input:match("^(/?[^/]*)(.*)$")
      out[#out + 1] = seg
      input = rest
    end
  end
  return table.concat(out)
end

-- The URL `rel` refers to when found on the page at `base` (RFC 3986 5.2.2).
url.absolute = function(base, rel)
  local b = type(base) == "table" and base or url.parse(base)
  local r = url.parse(rel)
  local t = {}
  if r.scheme then
    t = r
    t.path = remove_dots(r.path or "")
  else
    if r.authority then
      t.authority, t.host, t.port, t.userinfo = r.authority, r.host, r.port, r.userinfo
      t.path, t.query = remove_dots(r.path or ""), r.query
    else
      t.authority, t.host, t.port, t.userinfo = b.authority, b.host, b.port, b.userinfo
      if (r.path or "") == "" then
        t.path = b.path
        t.query = r.query or b.query
      else
        if r.path:sub(1, 1) == "/" then
          t.path = remove_dots(r.path)
        else
          local merged
          if b.authority and (b.path or "") == "" then
            merged = "/" .. r.path
          else
            merged = (b.path or ""):match("^(.*/)") or ""
            merged = merged .. r.path
          end
          t.path = remove_dots(merged)
        end
        t.query = r.query
      end
    end
    t.scheme = b.scheme
  end
  t.params = r.params
  t.fragment = r.fragment
  return url.build(t)
end

return url
