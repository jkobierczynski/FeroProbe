-- NSE compatibility layer: the `formulas` module, small statistics.
-- Written for FeroProbe from nmap's public API documentation (not from
-- nselib); GPL-3.0-or-later, like FeroProbe.
local formulas = {}

-- Bits of entropy of a password: its length times log2 of the size of
-- the character classes it uses (lower case, upper case, digits, other
-- printable characters).
formulas.calcPwdEntropy = function(value)
  local n = 0
  if value:find("%l") then n = n + 26 end
  if value:find("%u") then n = n + 26 end
  if value:find("%d") then n = n + 10 end
  if value:find("[^%w]") then n = n + 32 end
  if n == 0 then return 0 end
  return #value * math.log(n) / math.log(2)
end

-- Upper critical value of the chi-square distribution with df degrees of
-- freedom at a 1% significance level (Wilson-Hilferty approximation).
local function chi2_critical(df)
  local z = 2.326
  local a = 2 / (9 * df)
  return df * (1 - a + z * math.sqrt(a)) ^ 3
end

-- Whether data looks random: a chi-square goodness-of-fit test of the
-- counts of its 2-, 4- and 8-bit groups against a uniform spread; all
-- three must pass.
formulas.looksRandom = function(data)
  if #data == 0 then return false end
  for _, w in ipairs({ 2, 4, 8 }) do
    local bins, counts, n = 1 << w, {}, 0
    for i = 1, #data do
      local b = data:byte(i)
      for s = 8 - w, 0, -w do
        local v = (b >> s) & (bins - 1)
        counts[v] = (counts[v] or 0) + 1
        n = n + 1
      end
    end
    local e = n / bins
    local chi = 0
    for v = 0, bins - 1 do
      local d = (counts[v] or 0) - e
      chi = chi + d * d / e
    end
    if chi > chi2_critical(bins - 1) then return false end
  end
  return true
end

-- The mean and the sample standard deviation of a list of numbers.
formulas.mean_stddev = function(t)
  local n, mean, m2 = 0, 0, 0
  for _, x in ipairs(t) do
    n = n + 1
    local d = x - mean
    mean = mean + d / n
    m2 = m2 + d * (x - mean)
  end
  if n == 0 then return nil end
  if n == 1 then return mean, 0 end
  return mean, math.sqrt(m2 / (n - 1))
end

local function sorted(t)
  local s = {}
  for i, v in ipairs(t) do s[i] = v end
  table.sort(s)
  return s
end

-- The k-th largest element of a list.
formulas.quickselect = function(t, k)
  local s = sorted(t)
  return s[#s - k + 1]
end

-- The median of a list (the mean of the middle two for an even count).
formulas.median = function(t)
  local s = sorted(t)
  local n = #s
  if n == 0 then return nil end
  if n % 2 == 1 then return s[(n + 1) // 2] end
  return (s[n // 2] + s[n // 2 + 1]) / 2
end

return formulas
