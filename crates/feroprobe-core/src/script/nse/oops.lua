-- NSE compatibility layer: the `oops` module, stacks of error messages.
-- Written for FeroProbe from nmap's public API documentation (not from
-- nselib); GPL-3.0-or-later, like FeroProbe.
local stdnse = require "stdnse"
local oops = {}

local Oops = {}
Oops.__index = Oops
-- Newest message first: "outer: inner: cause".
Oops.__tostring = function(o) return table.concat(o.errors, ": ") end

-- An error stack with message on top of previous (an Oops object, a
-- message, or nothing).
oops.err = function(message, previous)
  local o = setmetatable({ errors = { tostring(message) } }, Oops)
  if getmetatable(previous) == Oops then
    for _, e in ipairs(previous.errors) do o.errors[#o.errors + 1] = e end
  elseif previous ~= nil then
    o.errors[#o.errors + 1] = tostring(previous)
  end
  return o
end

-- Passes a status-first result through; on failure the error becomes an
-- Oops stack with message on top.
oops.raise = function(message, status, previous, ...)
  if status then return status, previous, ... end
  return status, oops.err(message, previous)
end

-- A script's return value: message when status is true; otherwise the
-- error, which (as for stdnse.format_output) shows only with -d.
oops.output = function(status, message)
  if status then return message end
  if getmetatable(message) ~= Oops then message = oops.err(message) end
  return stdnse.format_output(false, tostring(message))
end

return oops
