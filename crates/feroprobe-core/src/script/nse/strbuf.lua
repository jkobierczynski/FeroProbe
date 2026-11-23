-- NSE compatibility layer: the `strbuf` module, a string buffer.
-- Written for FeroProbe from nmap's public API documentation (not from
-- nselib); GPL-3.0-or-later, like FeroProbe.
local strbuf = {}

local Buffer = {}
Buffer.__index = Buffer

-- buf .. "text" appends and gives the buffer back; buf .. other_buffer
-- appends the other buffer's pieces (as many as it had, so b .. b ends).
function strbuf.concatbuf(a, b)
  if getmetatable(a) ~= Buffer then
    error("a string buffer must come first in a concatenation", 2)
  end
  if getmetatable(b) == Buffer then
    local n = #b
    for i = 1, n do a[#a + 1] = b[i] end
  else
    a[#a + 1] = tostring(b)
  end
  return a
end

-- Whether two buffers hold the same text.
function strbuf.eqbuf(a, b)
  return strbuf.dump(a) == strbuf.dump(b)
end

-- The buffer's pieces, one per line.
function strbuf.tostring(b)
  return strbuf.dump(b, "\n")
end

Buffer.__concat = strbuf.concatbuf
Buffer.__eq = strbuf.eqbuf
Buffer.__tostring = strbuf.tostring

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
