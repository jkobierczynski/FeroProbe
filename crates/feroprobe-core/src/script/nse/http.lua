-- NSE compatibility layer: the `http` module, over fero.http.
-- Written for FeroProbe from nmap's public API documentation (not from
-- nselib); GPL-3.0-or-later, like FeroProbe. Requests go only to the
-- scanned host and the ports the scan probed there, redirects too.
local fero = ...
local url = require "url"
local http = {}

http.USER_AGENT = fero.http.USER_AGENT

-- nmap's request options as fero.http's.
local function options_of(options, scheme)
  local o = {}
  options = options or {}
  if type(options.header) == "table" then
    o.header = {}
    for k, v in pairs(options.header) do o.header[k] = tostring(v) end
  end
  if options.content ~= nil then
    if type(options.content) == "table" then
      o.content = fero.http.form_encode(options.content)
      o.header = o.header or {}
      local has = false
      for k in pairs(o.header) do
        if k:lower() == "content-type" then has = true end
      end
      if not has then o.header["Content-Type"] = "application/x-www-form-urlencoded" end
    else
      o.content = tostring(options.content)
    end
  end
  if type(options.cookies) == "string" then
    o.cookies = options.cookies
  elseif type(options.cookies) == "table" then
    -- nmap takes a list of { name = ..., value = ... } cookies.
    local parts = {}
    for _, c in ipairs(options.cookies) do
      if type(c) == "table" and c.name then parts[#parts + 1] = c.name .. "=" .. (c.value or "") end
    end
    if #parts > 0 then o.cookies = table.concat(parts, "; ") end
  end
  if type(options.auth) == "table" and options.auth.username then
    o.auth = { username = options.auth.username, password = options.auth.password }
  end
  if options.timeout then o.timeout = math.floor(options.timeout) end
  -- A redirect_ok function cannot be run by FeroProbe's client; it then
  -- follows its own rule (scanned host and ports only, at most three).
  if options.redirect_ok == false then
    o.redirect_ok = false
  elseif type(options.redirect_ok) == "number" then
    o.redirect_ok = options.redirect_ok
  end
  if options.max_body_size then o.max_body_size = options.max_body_size end
  if options.truncated_ok ~= nil then o.truncated_ok = options.truncated_ok and true or false end
  if scheme == "https" or options.scheme == "https" then o.ssl = true
  elseif scheme == "http" or options.scheme == "http" then o.ssl = false end
  return o
end

-- A failure as nmap's response table: status nil, the reason in
-- status-line.
local function failure(err)
  return {
    status = nil,
    ["status-line"] = tostring(err or "request failed"),
    header = {},
    rawheader = {},
    cookies = {},
    location = {},
    incomplete = nil,
  }
end

local function result(resp, err)
  if not resp then return failure(err) end
  resp.rawbody = resp.body
  resp.decoded = {}
  return resp
end

http.generic_request = function(host, port, method, path, options)
  return result(fero.http.request(method, host, port, path, options_of(options)))
end

http.get = function(host, port, path, options)
  return http.generic_request(host, port, "GET", path, options)
end

http.head = function(host, port, path, options)
  return http.generic_request(host, port, "HEAD", path, options)
end

http.post = function(host, port, path, options, _, postdata)
  local o = {}
  for k, v in pairs(options or {}) do o[k] = v end
  o.content = postdata
  if o.redirect_ok == nil then o.redirect_ok = false end
  return http.generic_request(host, port, "POST", path, o)
end

http.put = function(host, port, path, options, putdata)
  local o = {}
  for k, v in pairs(options or {}) do o[k] = v end
  o.content = putdata
  return http.generic_request(host, port, "PUT", path, o)
end

-- A whole URL; its host must be the scanned host and its port one the
-- scan probed, like any other request.
http.get_url = function(u, options)
  local p = url.parse(u)
  if not p.host then return failure("no host in URL") end
  local port = p.port or url.get_default_port(p.scheme or "http") or 80
  local path = (p.path or "/") .. (p.query and ("?" .. p.query) or "")
  return result(fero.http.request("GET", p.host, port, path, options_of(options, p.scheme)))
end

-- Pipelining is not used: the requests go one after another.
http.pipeline_add = function(path, options, all_requests, method)
  all_requests = all_requests or {}
  all_requests[#all_requests + 1] = { method = method or "GET", path = path, options = options }
  return all_requests
end

http.pipeline_go = function(host, port, all_requests)
  local responses = {}
  for i, r in ipairs(all_requests or {}) do
    responses[i] = http.generic_request(host, port, r.method, r.path, r.options)
  end
  return responses
end

http.get_status_string = function(data)
  if type(data) ~= "table" or not data.status then return "<unknown status>" end
  return (data["status-line"] or tostring(data.status)):gsub("^HTTP/%S+%s*", ""):gsub("[\r\n]+$", "")
end

-- Whether pattern is in the response's header lines or body; the
-- captures of the first match follow true.
http.response_contains = function(response, pattern, case_sensitive)
  if type(response) ~= "table" then return false end
  local function find(s)
    if not case_sensitive then
      s = s:lower()
      return s:match((require "stringaux").ipattern(pattern):lower())
    end
    return s:match(pattern)
  end
  for _, line in ipairs(response.rawheader or {}) do
    local m = table.pack(find(line))
    if m[1] then return true, table.unpack(m, 1, m.n) end
  end
  if response.body then
    local m = table.pack(find(response.body))
    if m[1] then return true, table.unpack(m, 1, m.n) end
  end
  return false
end

-- WWW-Authenticate as a list of { scheme = ..., params = { ... } }.
http.parse_www_authenticate = function(s)
  local list = {}
  local i = 1
  s = tostring(s)
  while i <= #s do
    local scheme, after = s:match("^%s*,?%s*([%w!#$%%&'*+.^_`|~-]+)%s*()", i)
    if not scheme then break end
    local challenge = { scheme = scheme, params = {} }
    i = after
    while true do
      local name, j = s:match("^([%w!#$%%&'*+.^_`|~-]+)%s*=%s*()", i)
      if not name then break end
      local value, k
      if s:sub(j, j) == '"' then
        -- A quoted string, with backslash escapes.
        local buf, q = {}, j + 1
        while q <= #s do
          local c = s:sub(q, q)
          if c == "\\" then
            buf[#buf + 1] = s:sub(q + 1, q + 1)
            q = q + 2
          elseif c == '"' then
            break
          else
            buf[#buf + 1] = c
            q = q + 1
          end
        end
        value, k = table.concat(buf), q + 1
      else
        value, k = s:match("^([^,%s]*)()", j)
      end
      if not k then break end
      challenge.params[name:lower()] = value
      i = k
      local nexti = s:match("^%s*,%s*()", i)
      if not nexti then break end
      -- A comma followed by a new scheme ends this challenge.
      if not s:match("^[%w!#$%%&'*+.^_`|~-]+%s*=", nexti) then i = nexti break end
      i = nexti
    end
    list[#list + 1] = challenge
  end
  return list
end

-- How the server answers a page that does not exist: true and its
-- status, or false and why. Used with page_exists.
http.identify_404 = function(host, port)
  local name = "/feroprobe-no-such-page-" .. fero.hex(fero.crypto.random_bytes(6))
  local r = http.get(host, port, name, { redirect_ok = false })
  if not r.status then return false, "no answer to the test request" end
  if r.status == 404 then return true, 404 end
  if r.status == 200 then
    return true, 200, r.body
  end
  return true, r.status
end

http.clean_404 = function(body) return body end

-- Whether `data` (a response) shows that the page exists, given what
-- identify_404 learned.
http.page_exists = function(data, result_404, known_404, page, displayall)
  if type(data) ~= "table" or not data.status then return false end
  if data.status == 200 then
    if result_404 == 200 then
      return data.body ~= known_404
    end
    return true
  end
  if data.status == result_404 then return false end
  if data.status == 401 or data.status == 403 or (data.status >= 300 and data.status < 400) then
    return true
  end
  return displayall and data.status ~= 404 and data.status < 500 or false
end

http.can_use_head = function(host, port, result_404, path)
  local r = http.head(host, port, path or "/", { redirect_ok = false })
  if r.status == 200 then return true, r end
  return false, r
end

http.request = function()
  error("http.request with a raw request is not available in FeroProbe; use http.generic_request", 2)
end

return http
