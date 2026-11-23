-- NSE compatibility layer: the `match` module, delimiter functions
-- for sock:receive_buf.
-- Written for FeroProbe from nmap's public API documentation (not from
-- nselib); GPL-3.0-or-later, like FeroProbe.
local match = {}

-- Ends once n bytes have come.
match.numbytes = function(n)
  return function(buf)
    if #buf >= n then return n, n end
    return nil
  end
end

-- Finds pattern within the first `within` bytes; with more than that
-- and no match, ends there.
match.pattern_limit = function(pattern, within)
  return function(buf)
    local s, e = buf:find(pattern)
    if s and e <= within then return s, e end
    if #buf >= within then return within, within end
    return nil
  end
end

-- Never matches: read until the connection ends or times out.
match.dontmatch = function()
  return function() return nil end
end

match.regex = function()
  error("match.regex is not available in FeroProbe (no PCRE); use a Lua pattern", 2)
end

return match
