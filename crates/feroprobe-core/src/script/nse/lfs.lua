-- NSE compatibility layer: the `lfs` module. FeroProbe scripts cannot
-- list, create or remove directories or make links (see the read-only
-- `io`), so those calls report a failure; only the path separator is
-- given.
-- Written for FeroProbe from nmap's public API documentation (not from
-- nselib); GPL-3.0-or-later, like FeroProbe.
local fero = ...
local lfs = {}

local REFUSED = "FeroProbe scripts cannot change the file system"

lfs.get_path_separator = function()
  return fero.path_separator or "/"
end

lfs.mkdir = function() return false, REFUSED end
lfs.rmdir = function() return false, REFUSED end
lfs.link = function() return false, REFUSED end

lfs.dir = function(path)
  error("FeroProbe scripts cannot list directories (" .. tostring(path) .. ")", 2)
end

return lfs
