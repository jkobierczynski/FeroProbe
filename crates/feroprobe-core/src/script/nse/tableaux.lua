-- NSE compatibility layer: the `tableaux` module.
-- Written for FeroProbe from nmap's public API documentation (not from
-- nselib); GPL-3.0-or-later, like FeroProbe.
local tableaux = {}

local function copy(t, seen)
  if type(t) ~= "table" then return t end
  if seen[t] then return seen[t] end
  local c = {}
  seen[t] = c
  for k, v in pairs(t) do c[copy(k, seen)] = copy(v, seen) end
  return setmetatable(c, getmetatable(t))
end

tableaux.tcopy = function(t) return copy(t, {}) end

tableaux.shallow_tcopy = function(t)
  local c = {}
  for k, v in pairs(t) do c[k] = v end
  return c
end

tableaux.keys = function(t)
  local list = {}
  for k in pairs(t) do list[#list + 1] = k end
  return list
end

-- true and the key when value is in t (only its list part with array).
tableaux.contains = function(t, value, array)
  local iter = array and ipairs or pairs
  for k, v in iter(t) do
    if v == value then return true, k end
  end
  return false, nil
end

tableaux.invert = function(t)
  local r = {}
  for k, v in pairs(t) do r[v] = k end
  return r
end

return tableaux
