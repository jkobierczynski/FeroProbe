-- FeroProbe script: http-git
-- Written for FeroProbe from scratch, from Git's documented repository
-- layout (gitrepository-layout(5)); GPL-3.0-or-later.

description = [[
Checks whether a web site serves a Git repository's .git directory
from its document root, which can expose the site's source code. Asks
for .git/HEAD; when that holds a Git reference, reads a few small,
uncompressed files: .gitignore, .git/COMMIT_EDITMSG, .git/config,
.git/description and .git/info/exclude. Shows the repository's
description, its last commit message, its remotes, the kind of project
its ignore files suggest, and which files mention words such as "passw",
"key" or "secret". Plain GETs with FeroProbe's User-Agent, six at most
per root; no Git object is downloaded.

Script arguments:
  http-git.root  The path that holds the .git directory (default "/");
                 a list of paths ({/,/app/}) tries each.
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "default", "safe", "vuln" }

portrule = fero.portrule.http

-- Small, common files that are read without decompressing anything.
local FILES = {
  ".gitignore",
  ".git/COMMIT_EDITMSG",
  ".git/config",
  ".git/description",
  ".git/info/exclude",
}

-- Words worth a second look when a file contains them.
local INTERESTING = { "bug", "key", "passw", "pw", "user", "secret", "uid" }

-- What an ignore file's entries suggest about the project; the more
-- specific first.
local PROJECT_TYPES = {
  { "%.scala_dependencies", "Scala application" },
  { "npm%-debug%.log", "node.js application" },
  { "joomla%.xml", "Joomla! site" },
  { "jboss/server", "JBoss Java web application" },
  { "wp%-%*%.php", "WordPress site" },
  { "app/config/database%.php", "CakePHP web application" },
  { "sites/default/settings%.php", "Drupal site" },
  { "local_settings%.py", "Django web application" },
  { "/%.bundle", "Ruby on Rails web application" },
  { "%.py[dco]", "Python application" },
  { "%.jsp", "JSP web application" },
  { "%.bundle", "Ruby application" },
  { "%.class", "Java application" },
  { "%.php", "PHP application" },
}

local IGNORE_FILES = { ".gitignore", ".git/info/exclude" }

-- Long texts are cut to this many characters in the normal report.
local SHORT = 60

local function summarize(s)
  if s == nil or s == "" then return "<unknown>" end
  local cut = s:sub(1, SHORT):gsub("%c", " ")
  if #s > SHORT then cut = cut .. "..." end
  return cut
end

local function roots()
  local arg = fero.args.get(SCRIPT_NAME .. ".root")
  local list = {}
  if type(arg) == "table" then
    for _, r in ipairs(arg) do list[#list + 1] = tostring(r) end
  elseif type(arg) == "string" or type(arg) == "number" then
    list[1] = tostring(arg)
  end
  if #list == 0 then list[1] = "/" end
  for i, r in ipairs(list) do
    if r:sub(-1) ~= "/" then r = r .. "/" end
    if r:sub(1, 1) ~= "/" then r = "/" .. r end
    list[i] = r
  end
  return list
end

local function get(host, port, path)
  local resp, err = fero.http.get(host, port, path, { truncated_ok = true })
  if not resp then
    fero.debug(1, path .. ": " .. tostring(err))
    return nil
  end
  if resp.status ~= 200 then return nil end
  return resp.body
end

-- What one root holds: the structured table and the report's lines; nil
-- when its .git/HEAD is not a Git reference.
local function check_root(host, port, root)
  local head = get(host, port, root .. ".git/HEAD")
  if not head or not (head:find("^ref: ") or head:find("^" .. ("%x"):rep(40))) then
    return nil
  end
  local bodies, found, ok = {}, fero.output_table(), 0
  for _, name in ipairs(FILES) do
    bodies[name] = get(host, port, root .. name)
    found[name] = bodies[name] ~= nil
    if bodies[name] then ok = ok + 1 end
  end

  local info = fero.output_table()
  info["files-found"] = found
  local lines = {}
  -- .git/HEAD counts as found too.
  if #FILES - ok <= 2 then
    lines[1] = "Git repository found!"
  else
    lines[1] = ("Potential Git repository found (found %d/%d expected files)"):format(ok + 1, #FILES + 1)
  end

  local matches = fero.output_table()
  for _, name in ipairs(FILES) do
    local body = bodies[name]
    if body then
      local words = {}
      for _, w in ipairs(INTERESTING) do
        if body:find(w, 1, true) then words[#words + 1] = w end
      end
      if #words > 0 then
        matches[name] = words
        lines[#lines + 1] = ("%s matched patterns '%s'"):format(name, table.concat(words, "' '"))
      end
    end
  end
  if next(matches) then info["interesting-matches"] = matches end

  local desc = bodies[".git/description"]
  if desc then
    info["repository-description"] = desc
    lines[#lines + 1] = "Repository description: " .. summarize(desc)
  end
  local msg = bodies[".git/COMMIT_EDITMSG"]
  if msg then
    info["last-commit-message"] = msg
    lines[#lines + 1] = "Last commit message: " .. summarize(msg)
  end

  local config = bodies[".git/config"]
  if config then
    local remotes = {}
    for url in ("\n" .. config):gmatch("\n%s*url%s*=%s*(%S*/%S*)") do
      remotes[#remotes + 1] = url
    end
    if #remotes > 0 then
      info.remotes = remotes
      lines[#lines + 1] = "Remotes:"
      for _, url in ipairs(remotes) do lines[#lines + 1] = "  " .. url end
    end
  end

  local types = fero.output_table()
  for _, file in ipairs(IGNORE_FILES) do
    local body = bodies[file]
    if body then
      local guessed = {}
      for _, t in ipairs(PROJECT_TYPES) do
        if body:find(t[1]) then guessed[#guessed + 1] = t[2] end
      end
      if #guessed > 0 then
        types[file] = guessed
        lines[#lines + 1] = ("Project type: %s (guessed from %s)"):format(guessed[1], file)
      end
    end
  end
  if next(types) then info["project-type"] = types end
  return info, lines
end

action = function(host, port)
  local out = fero.output_table()
  local text = {}
  for _, root in ipairs(roots()) do
    local info, lines = check_root(host, port, root)
    if info then
      local where = host.ip .. ":" .. port.number .. root .. ".git/"
      out[where] = info
      text[#text + 1] = "  " .. where
      for _, l in ipairs(lines) do text[#text + 1] = "    " .. l end
    end
  end
  if #text == 0 then return nil end
  return out, "\n" .. table.concat(text, "\n")
end
