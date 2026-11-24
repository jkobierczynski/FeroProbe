-- NSE compatibility layer: the `unpwdb` module, user name and password
-- lists for the brute-force scripts.
-- Written for FeroProbe from nmap's public API documentation (not from
-- nselib); GPL-3.0-or-later, like FeroProbe.
--
-- FeroProbe ships none of nmap's word lists. A list is read only from a
-- file the user names in --script-args (userdb / passdb) or, failing
-- that, from an installed nmap's own list found by nmap.fetchfile
-- (nselib/data/usernames.lst, nselib/data/passwords.lst). With neither,
-- the list is empty, so a brute-force script that relies on it does
-- nothing -- the safe default. This is a documented difference from
-- nmap, which carries both lists built in.
local stdnse = require "stdnse"
local nmap = require "nmap"
local io = require "io"
local unpwdb = {}

-- nmap's default budget for the whole brute-force phase.
local DEFAULT_TIMELIMIT = 600

-- The time budget in seconds from the unpwdb.timelimit argument, or the
-- default; 0 (or "0", "unlimited") means no limit, returned as nil.
function unpwdb.timelimit()
  local spec = stdnse.get_script_args("unpwdb.timelimit")
  if spec == nil then return DEFAULT_TIMELIMIT end
  if spec == "0" or spec == 0 or spec == "unlimited" then return nil end
  local secs = stdnse.parse_timespec(spec)
  if not secs then return DEFAULT_TIMELIMIT end
  if secs <= 0 then return nil end
  return secs
end

-- Read a list file into an array of non-empty lines, comments (#...) and
-- surrounding white space dropped. `path` is a user-named file or a name
-- for nmap.fetchfile; returns nil and a message when it cannot be read.
local function load_list(path, fetch_name)
  local file = path
  if file == nil and fetch_name then file = nmap.fetchfile(fetch_name) end
  if file == nil then
    return nil, "no list file (set the script argument, or install nmap's lists)"
  end
  local f, err = io.open(file, "r")
  if not f then return nil, err end
  local words = {}
  for line in f:lines() do
    local w = line:gsub("^%s+", ""):gsub("%s+$", "")
    if w ~= "" and w:sub(1, 1) ~= "#" then words[#words + 1] = w end
  end
  f:close()
  return words
end

-- An iterator over an array that answers "reset" by starting over, as
-- nmap's list iterators do.
local function array_iterator(words)
  local i = 0
  return function(cmd)
    if cmd == "reset" then i = 0; return end
    i = i + 1
    return words[i]
  end
end

-- unpwdb.usernames([time_limit]) and unpwdb.passwords([time_limit]):
-- status and an iterator closure. The iterator returns the next entry,
-- or nil at the end; call it with "reset" to start over. A count limit
-- (unpwdb.userlimit / unpwdb.passlimit) and the time limit are applied.
local function list_loader(arg, fetch_name, limit_arg)
  local cache
  return function(time_limit)
    if cache == nil then
      local words, err = load_list(stdnse.get_script_args(arg), fetch_name)
      if not words then
        stdnse.debug1("unpwdb: %s", err)
        words = {}
      end
      cache = words
    end
    local iter = array_iterator(cache)
    local count = tonumber(stdnse.get_script_args(limit_arg))
    if count then iter = unpwdb.limited_iterator(iter, count, nil) end
    if time_limit == nil then time_limit = unpwdb.timelimit() end
    if time_limit then iter = unpwdb.limited_iterator(iter, nil, time_limit) end
    return true, iter
  end
end

unpwdb.usernames = list_loader("userdb", "nselib/data/usernames.lst", "unpwdb.userlimit")
unpwdb.passwords = list_loader("passdb", "nselib/data/passwords.lst", "unpwdb.passlimit")

-- Yield every entry of the first iterator, then of the second; "reset"
-- resets both and starts from the first again.
function unpwdb.concat_iterators(iter1, iter2)
  local on_first = true
  return function(cmd)
    if cmd == "reset" then
      iter1("reset"); iter2("reset"); on_first = true
      return
    end
    if on_first then
      local v = iter1()
      if v ~= nil then return v end
      on_first = false
    end
    return iter2()
  end
end

-- Yield only the entries for which filter(entry) is true.
function unpwdb.filter_iterator(iterator, filter)
  return function(cmd)
    if cmd == "reset" then return iterator("reset") end
    while true do
      local v = iterator()
      if v == nil then return nil end
      if filter(v) then return v end
    end
  end
end

-- Stop after `count` entries or `time` seconds (either may be nil).
-- "reset" restores both budgets and resets the wrapped iterator.
function unpwdb.limited_iterator(iterator, count, time)
  local left = count
  local deadline = time and (nmap.clock() + time) or nil
  return function(cmd)
    if cmd == "reset" then
      left = count
      deadline = time and (nmap.clock() + time) or nil
      return iterator("reset")
    end
    if left ~= nil and left <= 0 then return nil end
    if deadline and nmap.clock() > deadline then return nil end
    local v = iterator()
    if v ~= nil and left ~= nil then left = left - 1 end
    return v
  end
end

return unpwdb
