-- NSE compatibility layer: the `bits` module, bit operations.
-- Written for FeroProbe from nmap's public API documentation (not from
-- nselib); GPL-3.0-or-later, like FeroProbe.
local bits = {}

-- a shifted right by b places, keeping its sign.
bits.arshift = function(a, b)
  a = math.tointeger(a) or math.floor(a)
  if a >= 0 then return a >> b end
  return ~((~a) >> b)
end

-- The lowest `size` bits of n (default 8) in reverse order.
bits.reverse = function(n, size)
  size = size or 8
  local r = 0
  for _ = 1, size do
    r = (r << 1) | (n & 1)
    n = n >> 1
  end
  return r
end

return bits
