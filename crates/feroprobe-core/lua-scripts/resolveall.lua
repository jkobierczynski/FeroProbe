-- FeroProbe script: resolveall
-- Written for FeroProbe from scratch, from the documented behaviour of
-- nmap's resolveall (its description, arguments and example output);
-- GPL-3.0-or-later.

description = [[
Resolves host names to every address they have, and with the
newtargets script argument adds those addresses to the scan. A normal
scan of a name scans only its first address.

Before the scan it resolves the names given in resolveall.hosts. On a
target given by name, it lists the name's other addresses. Only
addresses of the scan's family are used (IPv4, or IPv6 with -6). The
addresses it adds are scanned after the command line's targets; they
are addresses, not names, so the script does not run again for them.

Without newtargets the script only lists the addresses. max-newtargets
limits how many hosts scripts may add in all.
]]

---
-- @usage
-- feroprobe --script resolveall --script-args 'newtargets,resolveall.hosts={example.com,example.org}' -sn 192.0.2.1
-- feroprobe --script resolveall --script-args newtargets example.com
--
-- @args resolveall.hosts A name, or a list of names, to resolve before
--       the scan.
-- @args newtargets Add the addresses found to the scan.
-- @args max-newtargets The most hosts scripts may add (default 0: no
--       limit).
--
-- @output
-- Pre-scan script results:
-- | resolveall:
-- |   Host 'example.com' resolves to:
-- |     192.0.2.10
-- |     192.0.2.11
-- |_  Successfully added 2 new targets

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "discovery", "safe" }

local function names()
  local v = fero.args.get(SCRIPT_NAME .. ".hosts")
  if v == nil or v == true then return {} end
  if type(v) ~= "table" then v = { v } end
  local out = {}
  for _, n in ipairs(v) do
    if type(n) == "string" and n ~= "" then out[#out + 1] = n end
  end
  return out
end

local function adding()
  local v = fero.args.get("newtargets")
  return v ~= nil and v ~= false and v ~= "false" and v ~= "0"
end

-- Adds addrs to the scan, within max-newtargets; how many were added.
local function add(addrs)
  local list = {}
  for i, a in ipairs(addrs) do list[i] = a end
  local max = math.tointeger(tonumber(fero.args.get("max-newtargets")) or 0) or 0
  if max > 0 then
    local room = max - fero.new_targets_num()
    for i = #list, math.max(room, 0) + 1, -1 do list[i] = nil end
  end
  if #list == 0 then return 0 end
  return fero.add_targets(table.unpack(list)) or 0
end

local function is_address(s)
  return s:match("^%d+%.%d+%.%d+%.%d+$") ~= nil or s:find(":", 1, true) ~= nil
end

prerule = function()
  return #names() > 0
end

hostrule = function(host)
  return host.targetname ~= nil and not is_address(host.targetname)
end

-- Resolves each name; returns the structured and the text output.
local function report(list, also, skip)
  local out = fero.output_table()
  local hosts = fero.output_table()
  local lines, found = {}, {}
  for _, name in ipairs(list) do
    local ok, addrs = fero.resolve(name, fero.address_family)
    if ok then
      local keep = {}
      for _, a in ipairs(addrs) do
        if a ~= skip then keep[#keep + 1] = a end
      end
      if #keep > 0 then
        hosts[name] = keep
        lines[#lines + 1] = "  Host '" .. name .. "'" .. (also and " also" or "") .. " resolves to:"
        for _, a in ipairs(keep) do
          lines[#lines + 1] = "    " .. a
          found[#found + 1] = a
        end
      end
    else
      lines[#lines + 1] = "  Host '" .. name .. "' could not be resolved"
    end
  end
  if #found == 0 and also then return nil end
  if adding() then
    local n = add(found)
    out.newtargets = n
    lines[#lines + 1] = "  Successfully added " .. n .. " new targets"
  else
    lines[#lines + 1] = "  Use the 'newtargets' script-arg to add the results as targets"
  end
  out.hosts = hosts
  return out, "\n" .. table.concat(lines, "\n")
end

action = function(host)
  if SCRIPT_TYPE == "prerule" then return report(names(), false) end
  return report({ host.targetname }, true, host.ip)
end
