-- NSE compatibility layer: the `tab` module, text tables for output.
-- Written for FeroProbe from nmap's public API documentation (not from
-- nselib); GPL-3.0-or-later, like FeroProbe.
local tab = {}

-- A new, empty table; row 1 is the current row.
tab.new = function()
  return { rows = {}, current = 1 }
end

-- v (made a string) at column c of the current row.
tab.add = function(t, c, v)
  local row = t.rows[t.current]
  if not row then
    row = {}
    t.rows[t.current] = row
  end
  row[c] = tostring(v)
end

-- Each argument after t in its own column, then on to the next row.
tab.addrow = function(t, ...)
  local n = select("#", ...)
  for i = 1, n do tab.add(t, i, (select(i, ...))) end
  tab.nextrow(t)
end

-- Later adds go to a new row.
tab.nextrow = function(t)
  t.current = t.current + 1
end

-- The table as text: each column as wide as its widest cell plus two
-- spaces, one line per row (trailing spaces left off), each line ending
-- in a newline.
tab.dump = function(t)
  local widths, last = {}, 0
  for r = 1, t.current do
    local row = t.rows[r]
    if row then
      for c, v in pairs(row) do
        if #v > (widths[c] or 0) then widths[c] = #v end
        if c > last then last = c end
      end
    end
  end
  local out = {}
  for r = 1, t.current do
    local row = t.rows[r]
    if row then
      local cells = {}
      for c = 1, last do
        local v = row[c] or ""
        cells[c] = v .. string.rep(" ", (widths[c] or 0) + 2 - #v)
      end
      out[#out + 1] = (table.concat(cells):gsub("%s+$", "")) .. "\n"
    end
  end
  return table.concat(out)
end

return tab
