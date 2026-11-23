-- NSE compatibility layer: the `outlib` module.
-- Written for FeroProbe from nmap's public API documentation (not from
-- nselib); GPL-3.0-or-later, like FeroProbe.
local fero = ...
local outlib = {}

-- An output table with t's entries in the order of their keys.
outlib.sorted_by_key = function(t)
  local keys = {}
  for k in pairs(t) do keys[#keys + 1] = k end
  table.sort(keys, function(a, b) return tostring(a) < tostring(b) end)
  local out = fero.output_table()
  for _, k in ipairs(keys) do out[k] = t[k] end
  return out
end

-- A list shown as one line, its entries joined by ", " (or sep).
outlib.list_sep = function(list, sep)
  local text = {}
  for i, v in ipairs(list) do text[i] = tostring(v) end
  return setmetatable(list, {
    __tostring = function() return table.concat(text, sep or ", ") end,
  })
end

return outlib
