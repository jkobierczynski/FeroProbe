-- NSE compatibility layer: the `rand` module.
-- Written for FeroProbe from nmap's public API documentation (not from
-- nselib); GPL-3.0-or-later, like FeroProbe.
local rand = {}

-- The characters from left to right (one-character strings), as a list.
rand.charset = function(left, right, charset)
  charset = charset or {}
  for b = left:byte(), right:byte() do charset[#charset + 1] = string.char(b) end
  return charset
end

local alpha = rand.charset("a", "z")
rand.charset("A", "Z", alpha)

-- len characters, each taken at random from charset (a string or a
-- list of strings); random bytes when there is none.
rand.random_string = function(len, charset)
  local out = {}
  if charset == nil then
    for i = 1, len do out[i] = string.char(math.random(0, 255)) end
  elseif type(charset) == "string" then
    for i = 1, len do
      local n = math.random(1, #charset)
      out[i] = charset:sub(n, n)
    end
  else
    for i = 1, len do out[i] = charset[math.random(1, #charset)] end
  end
  return table.concat(out)
end

rand.random_alpha = function(len) return rand.random_string(len, alpha) end

return rand
