-- NSE compatibility layer: Lua's `io` library, read-only. Scripts read
-- the files nmap.fetchfile finds and files named in --script-args (word
-- lists, data files); they cannot write, create or run anything. Written
-- for FeroProbe from the Lua 5.4 reference manual; GPL-3.0-or-later,
-- like FeroProbe.
local fero = ...
local io = {}

local READONLY = "FeroProbe scripts cannot write files"

-- An open file: its whole content, read once, and a position.
local File = {}
File.__index = File
File.__name = "FILE*"
File.__tostring = function(f)
  if f.closed then return "file (closed)" end
  return "file (" .. tostring(f.path) .. ")"
end

local function check(f)
  if getmetatable(f) ~= File then error("bad argument #1 (FILE* expected)", 3) end
  if f.closed then error("attempt to use a closed file", 3) end
  return f
end

-- One item for read/lines, at the file's position.
local function read_one(f, fmt)
  local data, pos = f.data, f.pos
  if math.type(fmt) == "integer" or (type(fmt) == "number" and fmt == math.floor(fmt)) then
    local n = math.tointeger(fmt)
    if n < 0 then error("bad argument to 'read' (invalid format)", 3) end
    if pos > #data then return nil end
    if n == 0 then return "" end
    f.pos = pos + n
    return data:sub(pos, pos + n - 1)
  end
  if type(fmt) ~= "string" then error("bad argument to 'read' (invalid format)", 3) end
  local c = fmt:gsub("^%*", ""):sub(1, 1)
  if c == "l" or c == "L" then
    if pos > #data then return nil end
    local nl = data:find("\n", pos, true)
    if not nl then
      f.pos = #data + 1
      return data:sub(pos)
    end
    f.pos = nl + 1
    return data:sub(pos, c == "L" and nl or nl - 1)
  elseif c == "a" then
    f.pos = #data + 1
    return data:sub(pos)
  elseif c == "n" then
    -- A numeral, as Lua reads one: white space, then the longest prefix
    -- that is a number.
    local s, e = data:find("^%s*", pos)
    local start = e + 1
    local text = data:sub(start, start + 199):match("^[%+%-]?0[xX][%x%.]*[pP]?[%+%-]?%d*")
      or data:sub(start, start + 199):match("^[%+%-]?%d*%.?%d*[eE]?[%+%-]?%d*")
    -- Shorten to the longest prefix that converts.
    while text and #text > 0 and tonumber(text) == nil do text = text:sub(1, -2) end
    if not text or #text == 0 then
      f.pos = start
      return nil
    end
    f.pos = start + #text
    return tonumber(text)
  end
  error("bad argument to 'read' (invalid format)", 3)
end

local function read_all(f, ...)
  local n = select("#", ...)
  if n == 0 then return read_one(f, "l") end
  local out = {}
  for i = 1, n do
    out[i] = read_one(f, (select(i, ...)))
    if out[i] == nil then return table.unpack(out, 1, i) end
  end
  return table.unpack(out, 1, n)
end

function File:read(...) return read_all(check(self), ...) end

function File:lines(...)
  check(self)
  local fmts = table.pack(...)
  return function()
    if self.closed then error("file is already closed", 2) end
    return read_all(self, table.unpack(fmts, 1, fmts.n))
  end
end

function File:seek(whence, offset)
  check(self)
  whence = whence or "cur"
  offset = offset or 0
  local base
  if whence == "set" then base = 0
  elseif whence == "cur" then base = self.pos - 1
  elseif whence == "end" then base = #self.data
  else error("bad argument #1 to 'seek' (invalid option '" .. tostring(whence) .. "')", 2) end
  local p = base + math.tointeger(offset)
  if p < 0 then return nil, "Invalid argument", 22 end
  self.pos = p + 1
  return p
end

function File:close()
  check(self)
  self.closed = true
  self.data = ""
  return true
end

function File:write() check(self); return nil, READONLY, 9 end
function File:flush() check(self); return self end
function File:setvbuf() check(self); return true end

local function open(path, mode)
  mode = mode or "r"
  if type(path) ~= "string" then error("bad argument #1 to 'open' (string expected)", 3) end
  if type(mode) ~= "string" or not mode:match("^[rwa]%+?b?$") then
    error("bad argument #2 to 'open' (invalid mode)", 3)
  end
  if mode:sub(1, 1) ~= "r" or mode:find("+", 1, true) then
    return nil, path .. ": " .. READONLY, 13
  end
  local data, err, code = fero.__read_file(path)
  if not data then return nil, err, code end
  return setmetatable({ data = data, pos = 1, path = path }, File)
end

io.open = function(path, mode) return open(path, mode) end

io.lines = function(path, ...)
  if path == nil then
    return function() return nil end
  end
  local f, err = open(path, "r")
  if not f then error(err, 2) end
  local fmts = table.pack(...)
  return function()
    if f.closed then return nil end
    local v = table.pack(read_all(f, table.unpack(fmts, 1, fmts.n)))
    if v[1] == nil then f:close() end
    return table.unpack(v, 1, v.n)
  end
end

io.close = function(f)
  if f == nil then return true end
  return File.close(f)
end

io.type = function(v)
  if getmetatable(v) == File then return v.closed and "closed file" or "file" end
  -- io.stdout and io.stderr are files too.
  if type(v) == "table" and v.__std then return "file" end
  return nil
end

-- Standard output and error go to the debugging output, as print() does
-- (-d shows them). There is no standard input.
local function std(name)
  local s = { __std = name }
  function s:write(...)
    local parts = {}
    for i = 1, select("#", ...) do
      local v = select(i, ...)
      if type(v) ~= "string" and type(v) ~= "number" then
        error("bad argument #" .. i .. " to 'write' (string expected, got " .. type(v) .. ")", 2)
      end
      parts[#parts + 1] = tostring(v)
    end
    local text = table.concat(parts):gsub("\n$", "")
    if #text > 0 then fero.debug(1, text) end
    return self
  end
  function s:read() return nil end
  function s:lines() return function() return nil end end
  function s:close() return nil, "cannot close standard file" end
  function s:flush() return self end
  function s:setvbuf() return true end
  function s:seek() return nil, "Illegal seek", 29 end
  return s
end
io.stdout = std("stdout")
io.stderr = std("stderr")
io.stdin = std("stdin")

io.write = function(...) return io.stdout:write(...) end
io.output = function(f)
  if f ~= nil and f ~= io.stdout and f ~= io.stderr then
    return nil, READONLY
  end
  return io.stdout
end
io.input = function(f)
  if type(f) == "string" then
    local h, err = open(f, "r")
    if not h then error(err, 2) end
    io.__input = h
  elseif getmetatable(f) == File then
    io.__input = f
  end
  return io.__input or io.stdin
end
io.read = function(...)
  local h = io.__input
  if h and not h.closed then return h:read(...) end
  return nil
end

for _, name in ipairs({ "popen", "tmpfile" }) do
  io[name] = function()
    error("io." .. name .. " is not available in FeroProbe", 2)
  end
end

return io
