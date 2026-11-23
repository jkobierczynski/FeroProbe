-- NSE compatibility layer: the `stringaux` module.
-- Written for FeroProbe from nmap's public API documentation (not from
-- nselib); GPL-3.0-or-later, like FeroProbe.
local stringaux = {}

-- The pieces of text between matches of the separator pattern.
stringaux.strsplit = function(pattern, text)
  local list, pos = {}, 1
  text = tostring(text)
  if pattern == "" then error("stringaux.strsplit: empty separator", 2) end
  while true do
    local s, e = text:find(pattern, pos)
    if not s or e < s then
      list[#list + 1] = text:sub(pos)
      return list
    end
    list[#list + 1] = text:sub(pos, s - 1)
    pos = e + 1
  end
end

-- A string made safe as a file name: every byte but letters, digits,
-- "-", "_" and "." as %XX, and "." and ".." escaped in full.
stringaux.filename_escape = function(s)
  if s == "." then return "%2e" end
  if s == ".." then return "%2e%2e" end
  return (tostring(s):gsub("[^%w%-_.]", function(c)
    return string.format("%%%02x", c:byte())
  end))
end

-- A pattern that matches pattern's letters in either case.
stringaux.ipattern = function(pattern)
  local out, i, in_set = {}, 1, false
  while i <= #pattern do
    local c = pattern:sub(i, i)
    if c == "%" then
      out[#out + 1] = pattern:sub(i, i + 1)
      i = i + 2
    else
      if c == "[" then in_set = true elseif c == "]" then in_set = false end
      if c:find("%a") then
        local pair = c:lower() .. c:upper()
        out[#out + 1] = in_set and pair or ("[" .. pair .. "]")
      else
        out[#out + 1] = c
      end
      i = i + 1
    end
  end
  return table.concat(out)
end

return stringaux
