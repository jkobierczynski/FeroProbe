-- NSE compatibility layer: the `json` module (RFC 8259).
-- Written for FeroProbe from nmap's public API documentation (not from
-- nselib); GPL-3.0-or-later, like FeroProbe.
local json = {}

-- The JSON null, distinct from a missing value.
json.NULL = setmetatable({}, { __tostring = function() return "null" end })

local ARRAY = { __jsontype = "array" }
local OBJECT = { __jsontype = "object" }

-- Mark a table as a JSON array or object, for generate and typeof.
function json.make_array(t) return setmetatable(t or {}, ARRAY) end
function json.make_object(t) return setmetatable(t or {}, OBJECT) end

-- "array", "object", "null", or Lua's type name.
function json.typeof(v)
  if v == json.NULL then return "null" end
  local mt = type(v) == "table" and getmetatable(v)
  if mt == ARRAY or mt == OBJECT then return mt.__jsontype end
  return type(v)
end

local ESCAPES = { ['"'] = '"', ["\\"] = "\\", ["/"] = "/", b = "\b", f = "\f",
  n = "\n", r = "\r", t = "\t" }

local Parser = {}
Parser.__index = Parser

function Parser:fail(what)
  error({ json_error = what .. " at position " .. self.pos }, 0)
end

function Parser:space()
  self.pos = self.text:find("[^ \t\r\n]", self.pos) or #self.text + 1
end

function Parser:utf8_char(cp)
  if cp < 0 or cp > 0x10FFFF then self:fail("bad \\u escape") end
  return utf8.char(cp)
end

function Parser:string()
  local s, out = self.text, {}
  local i = self.pos + 1
  while true do
    local j = s:find('["\\%c]', i)
    if not j then self:fail("unterminated string") end
    out[#out + 1] = s:sub(i, j - 1)
    local c = s:sub(j, j)
    if c == '"' then
      self.pos = j + 1
      return table.concat(out)
    elseif c == "\\" then
      local e = s:sub(j + 1, j + 1)
      if ESCAPES[e] then
        out[#out + 1] = ESCAPES[e]
        i = j + 2
      elseif e == "u" then
        local hex = s:match("^%x%x%x%x", j + 2)
        if not hex then self:fail("bad \\u escape") end
        local cp = tonumber(hex, 16)
        i = j + 6
        if cp >= 0xD800 and cp <= 0xDBFF then
          local lo = s:match("^\\u(%x%x%x%x)", i)
          lo = lo and tonumber(lo, 16)
          if lo and lo >= 0xDC00 and lo <= 0xDFFF then
            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)
            i = i + 6
          end
        end
        out[#out + 1] = self:utf8_char(cp)
      else
        self:fail("bad escape")
      end
    else
      self:fail("control character in string")
    end
  end
end

function Parser:value(depth)
  if depth > 500 then self:fail("nested too deeply") end
  self:space()
  local s, i = self.text, self.pos
  local c = s:sub(i, i)
  if c == "{" then
    local obj = json.make_object({})
    self.pos = i + 1
    self:space()
    if s:sub(self.pos, self.pos) == "}" then self.pos = self.pos + 1 return obj end
    while true do
      self:space()
      if s:sub(self.pos, self.pos) ~= '"' then self:fail("expected a name") end
      local k = self:string()
      self:space()
      if s:sub(self.pos, self.pos) ~= ":" then self:fail("expected ':'") end
      self.pos = self.pos + 1
      obj[k] = self:value(depth + 1)
      self:space()
      local d = s:sub(self.pos, self.pos)
      self.pos = self.pos + 1
      if d == "}" then return obj end
      if d ~= "," then self:fail("expected ',' or '}'") end
    end
  elseif c == "[" then
    local arr = json.make_array({})
    self.pos = i + 1
    self:space()
    if s:sub(self.pos, self.pos) == "]" then self.pos = self.pos + 1 return arr end
    while true do
      arr[#arr + 1] = self:value(depth + 1)
      self:space()
      local d = s:sub(self.pos, self.pos)
      self.pos = self.pos + 1
      if d == "]" then return arr end
      if d ~= "," then self:fail("expected ',' or ']'") end
    end
  elseif c == '"' then
    return self:string()
  elseif s:sub(i, i + 3) == "true" then
    self.pos = i + 4 return true
  elseif s:sub(i, i + 4) == "false" then
    self.pos = i + 5 return false
  elseif s:sub(i, i + 3) == "null" then
    self.pos = i + 4 return json.NULL
  else
    local num = s:match("^-?%d+%.?%d*[eE]?[-+]?%d*", i)
    if not num or num == "" or num == "-" then self:fail("unexpected input") end
    local n = math.tointeger(tonumber(num)) or tonumber(num)
    if not n then self:fail("bad number") end
    self.pos = i + #num
    return n
  end
end

-- Parse JSON text: true and the value, or false and a message.
function json.parse(text)
  if type(text) ~= "string" then return false, "not a string" end
  local p = setmetatable({ text = text, pos = 1 }, Parser)
  local ok, v = pcall(function()
    local v = p:value(0)
    p:space()
    if p.pos <= #text then p:fail("trailing input") end
    return v
  end)
  if ok then return true, v end
  if type(v) == "table" and v.json_error then return false, v.json_error end
  error(v, 0)
end

local function quote(s)
  return '"' .. s:gsub('[%c"\\]', function(c)
    local named = { ['"'] = '\\"', ["\\"] = "\\\\", ["\b"] = "\\b", ["\f"] = "\\f",
      ["\n"] = "\\n", ["\r"] = "\\r", ["\t"] = "\\t" }
    return named[c] or string.format("\\u%04x", c:byte())
  end) .. '"'
end

local function is_array(t)
  local mt = getmetatable(t)
  if mt == ARRAY then return true end
  if mt == OBJECT then return false end
  local n = 0
  for _ in pairs(t) do n = n + 1 end
  if n == 0 then return false end
  for i = 1, n do
    if t[i] == nil then return false end
  end
  return true
end

local function gen(v, out, seen)
  local kind = type(v)
  if v == json.NULL or v == nil then
    out[#out + 1] = "null"
  elseif kind == "boolean" then
    out[#out + 1] = tostring(v)
  elseif kind == "number" then
    if v ~= v or v == math.huge or v == -math.huge then error("json.generate: number cannot be JSON", 0) end
    out[#out + 1] = math.type(v) == "integer" and tostring(v) or string.format("%.14g", v)
  elseif kind == "string" then
    out[#out + 1] = quote(v)
  elseif kind == "table" then
    if seen[v] then error("json.generate: a table contains itself", 0) end
    seen[v] = true
    if is_array(v) then
      out[#out + 1] = "["
      for i = 1, #v do
        if i > 1 then out[#out + 1] = "," end
        gen(v[i], out, seen)
      end
      out[#out + 1] = "]"
    else
      local keys = {}
      for k in pairs(v) do keys[#keys + 1] = tostring(k) end
      table.sort(keys)
      out[#out + 1] = "{"
      for i, k in ipairs(keys) do
        if i > 1 then out[#out + 1] = "," end
        out[#out + 1] = quote(k) .. ":"
        local x = v[k]
        if x == nil then x = v[tonumber(k)] end
        gen(x, out, seen)
      end
      out[#out + 1] = "}"
    end
    seen[v] = nil
  else
    error("json.generate: a " .. kind .. " cannot be JSON", 0)
  end
end

-- The value as JSON text. A table is an array when json.make_array marked
-- it or its keys are exactly 1..n; otherwise an object (keys sorted).
function json.generate(v)
  local out = {}
  gen(v, out, {})
  return table.concat(out)
end

return json
