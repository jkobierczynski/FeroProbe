-- NSE compatibility layer: the `brute` module, the framework the
-- brute-force scripts build on.
-- Written for FeroProbe from nmap's public API documentation (not from
-- nselib); GPL-3.0-or-later, like FeroProbe.
--
-- A brute-force script gives the framework a Driver (connect, login,
-- disconnect) and an Engine runs it against a credential stream built
-- from unpwdb's lists. FeroProbe differs from nmap in two documented
-- ways: it ships no word lists (see unpwdb), and it makes its guesses
-- one at a time -- setMaxThreads and the brute.threads argument are
-- accepted but have no effect, because the engine does not run guesses
-- in parallel. A brute-force script is run only when it is chosen by its
-- exact name, by a file, or by the `brute` category word; never through
-- `all`, another category, a wildcard, -sC or -A.
local stdnse = require "stdnse"
local nmap = require "nmap"
local creds = require "creds"
local unpwdb = require "unpwdb"
local brute = {}

-- An account the driver's login returns on success. Same shape as
-- creds.Account, so scripts may use either name.
brute.Account = creds.Account

-- creds.State, for a driver that wants to report a non-default state.
brute.State = creds.State

-- An error a driver's login returns on failure. It carries a message
-- and flags that tell the engine what to do next.
brute.Error = {}
brute.Error.__index = brute.Error

function brute.Error:new(msg)
  return setmetatable({ msg = msg, retry = false, abort = false,
    reduce = false, done = false, invalid = false }, self)
end

function brute.Error:getMessage() return self.msg end
function brute.Error:setRetry(v) self.retry = (v ~= false) end
function brute.Error:isRetry() return self.retry end
function brute.Error:setAbort(v) self.abort = (v ~= false) end
function brute.Error:isAbort() return self.abort end
function brute.Error:setReduce(v) self.reduce = (v ~= false) end
function brute.Error:isReduce() return self.reduce end
function brute.Error:setDone(v) self.done = (v ~= false) end
function brute.Error:isDone() return self.done end
-- An invalid account is one the service says does not exist; the engine
-- stops guessing passwords for it.
function brute.Error:setInvalidAccount(account) self.invalid = account or true end
function brute.Error:isInvalidAccount() return self.invalid ~= false end

-- "true"/"false"/nil from a script argument, with a default.
function brute.checkBoolArg(arg, default)
  local v = stdnse.get_script_args(arg)
  if v == nil then return default end
  if v == true or v == "true" or v == "1" then return true end
  if v == false or v == "false" or v == "0" then return false end
  return default
end

-- A socket for a driver; it is an ordinary nmap socket in FeroProbe.
function brute.new_socket(proto)
  return nmap.new_socket(proto)
end

-- The run's options, filled from the brute.* script arguments. A script
-- may change them through engine:setOption / engine.options.
brute.Options = {}
brute.Options.__index = brute.Options

function brute.Options:new()
  local o = setmetatable({}, self)
  o.mode = stdnse.get_script_args("brute.mode")
  o.firstonly = brute.checkBoolArg("brute.firstonly", false)
  o.passonly = brute.checkBoolArg("brute.passonly", false)
  o.useraspass = brute.checkBoolArg("brute.useraspass", true)
  o.emptypass = brute.checkBoolArg("brute.emptypass", false)
  o.nostore = false
  o.max_retries = tonumber(stdnse.get_script_args("brute.retries")) or 2
  o.max_guesses = tonumber(stdnse.get_script_args("brute.guesses")) or 0
  o.delay = stdnse.parse_timespec(stdnse.get_script_args("brute.delay") or 0) or 0
  o.credfile = stdnse.get_script_args("brute.credfile")
  o.title = nil
  return o
end

function brute.Options:setOption(name, value) self[name] = value end

-- Iterators ---------------------------------------------------------------

-- Pair up usernames and passwords. mode "pass" (the default) tries every
-- password for each username; mode "user" tries every username for each
-- password. Each returns user, pass pairs and resets on "reset".
function brute.account_iterator(usernames, passwords, mode)
  local outer, inner = usernames, passwords
  local pass_mode = mode ~= "user"
  if not pass_mode then outer, inner = passwords, usernames end
  local cur_outer
  local started = false
  local function next_pair()
    while true do
      if cur_outer == nil then
        cur_outer = outer()
        if cur_outer == nil then return nil end
        inner("reset")
      end
      local v = inner()
      if v ~= nil then
        if pass_mode then return cur_outer, v else return v, cur_outer end
      end
      cur_outer = nil
    end
  end
  return function(cmd)
    if cmd == "reset" then
      outer("reset"); inner("reset"); cur_outer = nil; started = false
      return
    end
    started = true
    return next_pair()
  end
end

-- Read user:pass pairs from a credential file (one per line, split at the
-- first colon). Yields user, pass pairs.
function brute.credential_iterator(path)
  local io = require "io"
  local lines = {}
  if path then
    local f = io.open(path, "r")
    if f then
      for line in f:lines() do
        line = line:gsub("[\r\n]+$", "")
        if line ~= "" and line:sub(1, 1) ~= "#" then lines[#lines + 1] = line end
      end
      f:close()
    else
      stdnse.debug1("brute: cannot read credfile %s", tostring(path))
    end
  end
  local i = 0
  return function(cmd)
    if cmd == "reset" then i = 0; return end
    i = i + 1
    local line = lines[i]
    if line == nil then return nil end
    local user, pass = line:match("^(.-):(.*)$")
    if not user then user, pass = line, "" end
    return user, pass
  end
end

-- Try the user name as the password too.
function brute.pw_same_as_user_iterator(usernames, case)
  return function(cmd)
    if cmd == "reset" then return usernames("reset") end
    local u = usernames()
    if u == nil then return nil end
    if case == "upper" then return u, u:upper() end
    if case == "lower" then return u, u:lower() end
    return u, u
  end
end

-- Upper-case every password an iterator yields.
function brute.pw_ucase_iterator(pw_iterator)
  return function(cmd)
    if cmd == "reset" then return pw_iterator("reset") end
    local p = pw_iterator()
    if p == nil then return nil end
    return p:upper()
  end
end

-- The Engine --------------------------------------------------------------

brute.Engine = {}
brute.Engine.__index = brute.Engine

function brute.Engine:new(driver, host, port, options)
  local e = setmetatable({}, self)
  e.driver = driver
  e.host = host
  e.port = port
  e.options = options or brute.Options:new()
  e.max_threads = 1
  e.found = {}
  e.invalid = {}
  e.guesses = 0
  return e
end

-- Accepted for compatibility; FeroProbe guesses sequentially, so the
-- thread count has no effect.
function brute.Engine:setMaxThreads(n) self.max_threads = n end
function brute.Engine:setPasswordIterator(iter) self.pw_iterator = iter end
function brute.Engine:setUsernameIterator(iter) self.user_iterator = iter end
function brute.Engine:setMode(mode) self.options.mode = mode end
function brute.Engine:setOption(name, value) self.options[name] = value end
function brute.Engine:setTitle(title) self.options.title = title end

-- A safety cap on how large a word list the engine reads into memory.
local MAX_LIST = 2000000

-- Drain an iterator into an array, so the list can be walked more than
-- once without disturbing the source iterator.
local function materialize(iter)
  local out = {}
  if iter == nil then return out end
  iter("reset")
  while #out < MAX_LIST do
    local v = iter()
    if v == nil then break end
    out[#out + 1] = v
  end
  return out
end

-- Build the credential stream: a function returning the next user, pass
-- pair, or nil at the end. The extra guesses nmap makes first
-- (useraspass, emptypass) come before the main cross-product of the user
-- and password lists, in the order the mode sets.
function brute.Engine:credentials()
  local o = self.options
  if o.credfile or o.mode == "creds" then
    return brute.credential_iterator(o.credfile)
  end
  local passwords = materialize(self.pw_iterator or select(2, unpwdb.passwords()))
  if o.passonly then
    -- Guess passwords only, with an empty user name.
    local j = 0
    return function()
      j = j + 1
      local p = passwords[j]
      if p == nil then return nil end
      return "", p
    end
  end
  local users = materialize(self.user_iterator or select(2, unpwdb.usernames()))
  -- A list of generators, each returning its next pair or nil, run in
  -- order. The first ones are the extra guesses; the last is the main
  -- cross product.
  local gens = {}
  if o.useraspass then
    local i = 0
    gens[#gens + 1] = function()
      i = i + 1
      local u = users[i]
      if u == nil then return nil end
      return u, u
    end
  end
  if o.emptypass then
    local i = 0
    gens[#gens + 1] = function()
      i = i + 1
      local u = users[i]
      if u == nil then return nil end
      return u, ""
    end
  end
  if o.mode == "user" then
    -- Outer password, inner user: every user for a password in turn.
    local pi, uj = 1, 0
    gens[#gens + 1] = function()
      while passwords[pi] ~= nil do
        uj = uj + 1
        local u = users[uj]
        if u ~= nil then return u, passwords[pi] end
        uj = 0
        pi = pi + 1
      end
      return nil
    end
  else
    -- Outer user, inner password (nmap's default): every password for a
    -- user in turn.
    local ui, pj = 1, 0
    gens[#gens + 1] = function()
      while users[ui] ~= nil do
        pj = pj + 1
        local p = passwords[pj]
        if p ~= nil then return users[ui], p end
        pj = 0
        ui = ui + 1
      end
      return nil
    end
  end
  local g = 1
  return function()
    while g <= #gens do
      local u, p = gens[g]()
      if u ~= nil then return u, p end
      g = g + 1
    end
    return nil
  end
end

-- One login attempt, with retries. Returns "found" (and stores the
-- account), "next" to go on, "skip-user" to drop this user, or "abort".
function brute.Engine:try(user, pass)
  local o = self.options
  local tries = 0
  while true do
    tries = tries + 1
    self.guesses = self.guesses + 1
    local driver = self.driver:new(self.host, self.port, o)
    local ok = driver:connect()
    local status, resp
    if ok then
      status, resp = driver:login(user, pass)
    else
      status = false
      resp = brute.Error:new("Failed to connect")
      resp:setRetry(true)
    end
    pcall(function() driver:disconnect() end)
    if status then
      local account = resp
      if getmetatable(account) ~= creds.Account then
        account = creds.Account:new(user, pass, creds.State.VALID)
      end
      if not o.nostore then
        creds.Credentials:new(self.title or SCRIPT_NAME, self.host, self.port)
          :add(account.username or user, account.password or pass,
            account.state or creds.State.VALID)
      end
      self.found[#self.found + 1] = tostring(account)
      return "found"
    end
    -- A failure: act on the error's flags.
    if type(resp) == "table" and resp.isAbort and resp:isAbort() then return "abort" end
    if type(resp) == "table" and resp.isInvalidAccount and resp.invalid ~= false
        and resp:isInvalidAccount() then
      return "skip-user"
    end
    if type(resp) == "table" and resp.isDone and resp:isDone() then return "abort" end
    if type(resp) == "table" and resp.isRetry and resp:isRetry()
        and tries <= o.max_retries then
      stdnse.debug2("brute: retry %d:%d (%s)", tries, o.max_retries,
        resp.getMessage and resp:getMessage() or "")
      if o.delay and o.delay > 0 then stdnse.sleep(o.delay) end
    else
      return "next"
    end
  end
end

-- Run the brute force. Returns true and the formatted result, or false
-- and a message. SCRIPT_NAME is the script's name for the credentials
-- store (set by the engine from setTitle, else the running script).
function brute.Engine:start()
  self.title = self.options.title
  local o = self.options
  local iterator = self:credentials()
  local start = nmap.clock()
  local counts = { skip = {} }
  local aborted = false
  while true do
    local user, pass = iterator()
    if user == nil then break end
    if counts.skip[user] then
      -- user marked invalid; skip
    elseif o.max_guesses > 0 and self.guesses >= o.max_guesses then
      break
    else
      local r = self:try(user, pass)
      if r == "abort" then aborted = true; break end
      if r == "skip-user" then counts.skip[user] = true end
      if r == "found" and o.firstonly then break end
      if o.delay and o.delay > 0 then stdnse.sleep(o.delay) end
    end
  end
  local elapsed = nmap.clock() - start
  local out = stdnse.output_table()
  if #self.found > 0 then
    out["Accounts"] = self.found
  else
    out["Accounts"] = "No valid accounts found"
  end
  out["Statistics"] = string.format(
    "Performed %d guesses in %.0f seconds, average tps: %.1f",
    self.guesses, elapsed, elapsed > 0 and self.guesses / elapsed or self.guesses)
  if aborted then out["Status"] = "aborted by the service" end
  return true, out
end

return brute
