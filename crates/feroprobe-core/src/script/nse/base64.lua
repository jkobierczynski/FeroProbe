-- NSE compatibility layer: the `base64` module.
-- Written for FeroProbe from nmap's public API documentation (not from
-- nselib); GPL-3.0-or-later, like FeroProbe.
local fero = ...
return {
  enc = function(s) return fero.base64.encode(tostring(s)) end,
  dec = function(s) return fero.base64.decode(tostring(s)) end,
}
