-- FeroProbe script: http-auth
-- Written for FeroProbe from scratch, from RFC 9110 section 11 (HTTP
-- authentication); GPL-3.0-or-later.

description = [[
Shows how a web page that needs a login asks for it: when the page
answers 401 Unauthorized, lists each authentication scheme in its
WWW-Authenticate header (Basic, Digest, NTLM, Negotiate, Bearer, ...)
with its parameters, such as the realm. One GET with FeroProbe's
User-Agent; no credentials are sent.

Script arguments:
  http-auth.path  The page to ask for (default "/").
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "default", "auth", "safe" }

portrule = fero.portrule.http

-- RFC 9110 5.6.2: tchar.
local TOKEN = "[%w!#$%%&'*+%-%.%^_`|~]+"

-- A token or a quoted-string at `pos`: its value and the position after
-- it, or nil.
local function read_value(s, pos)
  if s:sub(pos, pos) == '"' then
    local out, i = {}, pos + 1
    while i <= #s do
      local c = s:sub(i, i)
      if c == "\\" then
        out[#out + 1] = s:sub(i + 1, i + 1)
        i = i + 2
      elseif c == '"' then
        return table.concat(out), i + 1
      else
        out[#out + 1] = c
        i = i + 1
      end
    end
    return nil
  end
  local _, e = s:find("^" .. TOKEN, pos)
  if not e then return nil end
  return s:sub(pos, e), e + 1
end

-- The challenges in a WWW-Authenticate value (RFC 9110 11.6.1): a list
-- of { scheme = ..., params = {...} } (or `token68` for a scheme followed
-- by one bare value, as NTLM's), in the server's order; nil when it does
-- not parse. The second value lists each challenge's parameter names in
-- the server's order.
local function parse_challenges(s)
  local list, names, pos, cur = {}, {}, 1, nil
  while true do
    local p = s:find("[^%s,]", pos)
    if not p then break end
    local _, e, name = s:find("^(" .. TOKEN .. ")%s*=%s*", p)
    local nxt = e and s:sub(e + 1, e + 1) or ""
    if cur and e and not cur.token68 and nxt ~= "" and nxt ~= "," and nxt ~= "=" then
      -- An auth-param of the current challenge.
      local v, after = read_value(s, e + 1)
      if not v then return nil end
      if not cur.params then
        cur.params = fero.output_table()
        names[cur] = {}
      end
      if cur.params[name] == nil then table.insert(names[cur], name) end
      cur.params[name] = v
      local q = s:find("%S", after)
      if q and s:sub(q, q) ~= "," then return nil end
      pos = q or #s + 1
    else
      -- A new challenge: its scheme, then maybe a token68.
      local _, se, scheme = s:find("^(" .. TOKEN .. ")", p)
      if not se then return nil end
      cur = fero.output_table()
      cur.scheme = scheme
      list[#list + 1] = cur
      pos = se + 1
      local _, te, t68 = s:find("^ +([%w%-%._~+/]+=*)%s*", pos)
      if te and (te == #s or s:sub(te + 1, te + 1) == ",") then
        cur.token68 = t68
        pos = te + 1
      elseif te then
        -- Parameters follow: read them from here.
        pos = pos + #s:match("^ +", pos)
      end
    end
  end
  if #list == 0 then return nil end
  return list, names
end

action = function(host, port)
  local path = fero.args.get(SCRIPT_NAME .. ".path")
  if type(path) ~= "string" or path == "" then path = "/" end
  local resp, err = fero.http.get(host, port, path, { truncated_ok = true })
  if not resp then
    fero.debug(1, "request failed: " .. tostring(err))
    return nil
  end
  if resp.status ~= 401 then return nil end
  local head = resp["status-line"]:gsub("%s+$", "")
  local lines = {}
  local auth = resp.header["www-authenticate"]
  local challenges, names
  if auth then challenges, names = parse_challenges(auth) end
  if not auth then
    lines[1] = ("Server returned status %d but no WWW-Authenticate header."):format(resp.status)
  elseif not challenges then
    lines[1] = ("Server returned status %d but the WWW-Authenticate header could not be parsed."):format(resp.status)
    lines[2] = "WWW-Authenticate: " .. auth
  else
    for _, c in ipairs(challenges) do
      local line = c.scheme
      if c.token68 then line = line .. " " .. c.token68 end
      for _, name in ipairs(names[c] or {}) do
        line = line .. " " .. name .. "=" .. c.params[name]
      end
      lines[#lines + 1] = line
    end
  end
  local text = "\n" .. head .. "\n  " .. table.concat(lines, "\n  ")
  return challenges, text
end
