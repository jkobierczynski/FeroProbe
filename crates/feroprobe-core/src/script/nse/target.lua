-- NSE compatibility layer: the `target` module. FeroProbe does not scan
-- hosts that scripts discover: ALLOW_NEW_TARGETS is always false and
-- add() refuses them, whatever newtargets says, so a scan never reaches
-- beyond the targets the user gave. Scripts still report what they found.
-- Written for FeroProbe from nmap's public API documentation (not from
-- nselib); GPL-3.0-or-later, like FeroProbe.
local target = {}

target.ALLOW_NEW_TARGETS = false

local REFUSED = "FeroProbe does not scan hosts that scripts add"

-- With no arguments: true and the number of queued targets (always 0).
-- With targets: false and why none was added.
target.add = function(...)
  if select("#", ...) == 0 then return true, 0 end
  return false, REFUSED
end

return target
