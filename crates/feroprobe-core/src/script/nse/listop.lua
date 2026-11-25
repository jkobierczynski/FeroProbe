-- NSE compatibility layer: the `listop` module, list operations on Lua
-- tables.
-- Written for FeroProbe from nmap's public API documentation (not from
-- nselib); GPL-3.0-or-later, like FeroProbe.
local listop = {}

listop.is_list = function(l) return type(l) == "table" end
listop.is_empty = function(l) return next(l) == nil end

listop.map = function(f, l)
  local out = {}
  for i, v in ipairs(l) do out[i] = f(v) end
  return out
end

listop.apply = function(f, l) return f(table.unpack(l)) end

listop.filter = function(f, l)
  local out = {}
  for _, v in ipairs(l) do
    if f(v) then out[#out + 1] = v end
  end
  return out
end

listop.car = function(l) return l[1] end

listop.cdr = function(l) return listop.ncdr(l, 1) end

listop.ncar = function(l, x) return l[x or 1] end

listop.ncdr = function(l, x)
  local out = {}
  for i = (x or 1) + 1, #l do out[#out + 1] = l[i] end
  return out
end

local function as_list(v)
  if type(v) == "table" then return v end
  return { v }
end

listop.cons = function(v1, v2)
  return listop.append(as_list(v1), as_list(v2))
end

listop.append = function(l1, l2)
  local out = {}
  for _, v in ipairs(l1) do out[#out + 1] = v end
  for _, v in ipairs(l2) do out[#out + 1] = v end
  return out
end

listop.reverse = function(l)
  local out = {}
  for i = #l, 1, -1 do out[#out + 1] = l[i] end
  return out
end

listop.flatten = function(l)
  local out = {}
  local function walk(t)
    for _, v in ipairs(t) do
      if type(v) == "table" then walk(v) else out[#out + 1] = v end
    end
  end
  walk(l)
  return out
end

return listop
