-- NSE compatibility layer: the `strbuf` module, a string buffer.
-- Written for FeroProbe from nmap's public API documentation (not from
-- nselib); GPL-3.0-or-later, like FeroProbe.
local strbuf = {}

local Buffer = {}
Buffer.__index = Buffer

-- buf .. "text" appends and gives the buffer back; buf .. other_buffer
-- appends the other buffer's pieces.
Buffer.__concat = function(a, b)
  if getmetatable(a) ~= Buffer then
    error("a string buffer must come first in a concatenation", 2)
  end
  if getmetatable(b) == Buffer then
    for _, piece in ipairs(b) do a[#a + 1] = piece end
  else
    a[#a + 1] = tostring(b)
  end
  return a
end

Buffer.__eq = function(a, b)
  return strbuf.dump(a) == strbuf.dump(b)
end

Buffer.__tostring = function(b) return strbuf.dump(b) end

-- A new buffer holding the given strings.
function strbuf.new(...)
  local b = setmetatable({}, Buffer)
  for i = 1, select("#", ...) do b[#b + 1] = tostring((select(i, ...))) end
  return b
end

-- The buffer's pieces joined, with `delimiter` between them (none by
-- default).
function strbuf.dump(b, delimiter)
  return table.concat(b, delimiter or "")
end

-- Empty the buffer.
function strbuf.clear(b)
  for i = #b, 1, -1 do b[i] = nil end
end

return strbuf
