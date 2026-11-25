-- NSE compatibility layer: the `target` module, hosts that scripts add to
-- the scan. As in nmap, adding works only with the `newtargets` script
-- argument (and up to `max-newtargets` hosts, 0 for no limit); the CLI
-- scans the added hosts after the ones on the command line. Postrule
-- scripts cannot add.
-- Written for FeroProbe from nmap's public API documentation (not from
-- nselib); GPL-3.0-or-later, like FeroProbe.
local nmap = require "nmap"
local stdnse = require "stdnse"
local target = {}

local function flag(v)
  return v ~= nil and v ~= false and v ~= "false" and v ~= "0"
end

target.ALLOW_NEW_TARGETS = flag(stdnse.get_script_args("newtargets"))

local function max_new()
  local n = tonumber(stdnse.get_script_args("max-newtargets"))
  if not n or n <= 0 then return nil end
  return math.floor(n)
end

-- target.add(t1, t2, ...): true and how many were added, or false and
-- why. With no arguments: true and the number of targets still queued.
target.add = function(...)
  local n = select("#", ...)
  if n == 0 then return true, nmap.add_targets() end
  if not target.ALLOW_NEW_TARGETS then
    return false, "to add targets run with --script-args=newtargets"
  end
  local list = { ... }
  local max = max_new()
  if max then
    local room = max - nmap.new_targets_num()
    if room <= 0 then return false, "the maximum of new targets (max-newtargets) is reached" end
    if room < n then
      for i = n, room + 1, -1 do list[i] = nil end
      n = room
    end
  end
  local count, err = nmap.add_targets(table.unpack(list, 1, n))
  if count and count > 0 then return true, count end
  return false, err or "failed to add new targets"
end

return target
