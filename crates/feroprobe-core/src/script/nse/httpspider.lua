-- NSE compatibility layer: the `httpspider` module, a small web crawler.
-- Written for FeroProbe from nmap's public API documentation (not from
-- nselib); GPL-3.0-or-later, like FeroProbe. Every page is fetched with
-- the `http` module, so requests go only to the scanned host and the
-- ports the scan probed there, whatever the scope options say.
local fero = ...
local http = require "http"
local url = require "url"
local stdnse = require "stdnse"
local httpspider = {}

-- Extensions of files that are web pages (links are read from them, and
-- they are fetched with GET even with useheadfornonwebfiles).
local WEB_FILES = {}
for _, e in ipairs({ "", "htm", "html", "xhtml", "shtml", "php", "php3", "php4", "php5", "phtml",
  "asp", "aspx", "ashx", "jsp", "jspx", "do", "action", "cgi", "pl", "py", "rb", "cfm", "nsf",
  "txt", "xml", "json", "js", "css" }) do
  WEB_FILES[e] = true
end

-- Extensions the default blacklist skips: images, media, archives and
-- documents, whose links are not crawled and which are rarely of use.
local BINARY = {}
for _, e in ipairs({ "png", "jpg", "jpeg", "gif", "bmp", "ico", "svg", "webp", "tif", "tiff",
  "mp3", "mp4", "avi", "mov", "mkv", "wav", "ogg", "flac", "webm", "wmv", "flv", "swf",
  "zip", "gz", "tgz", "bz2", "xz", "7z", "rar", "tar", "iso", "dmg", "exe", "msi", "bin", "deb", "rpm",
  "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods",
  "woff", "woff2", "ttf", "otf", "eot" }) do
  BINARY[e] = true
end

local function extension(path)
  local file = (path or ""):match("([^/]*)$") or ""
  return (file:match("%.([%w]+)$") or ""):lower()
end

---------------------------------------------------------------------------
-- URL: one parsed URL.
local URL = {}
URL.__index = URL
URL.__tostring = function(u) return u.raw end
URL.__eq = function(a, b) return a.raw == b.raw end

function URL:new(u)
  local p = url.parse(tostring(u))
  local o = setmetatable({ raw = tostring(u) }, self)
  o.proto = p.scheme and p.scheme:lower() or nil
  o.host = p.host
  o.port = tonumber(p.port) or (o.proto and url.get_default_port(o.proto)) or nil
  o.path = p.path or "/"
  if o.path == "" then o.path = "/" end
  o.querystring = p.query
  o.dir = o.path:match("^(.*/)") or "/"
  o.file = o.path:match("([^/]*)$") or ""
  return o
end

function URL:getRaw() return self.raw end
function URL:getHost() return self.host end
function URL:getPort() return self.port end
function URL:getProto() return self.proto end
function URL:getPath() return self.path end
function URL:getDir() return self.dir end
function URL:getFile() return self.file end
function URL:getQuery() return self.querystring end
-- The directory depth of the path: "/" is 0, "/a/" and "/a/b.html" 1.
function URL:getDirDepth()
  local n = 0
  for _ in self.dir:gmatch("[^/]+/") do n = n + 1 end
  return n
end

httpspider.URL = URL

---------------------------------------------------------------------------
-- LinkExtractor: the links of a page, as absolute URLs.
local LinkExtractor = {}
LinkExtractor.__index = LinkExtractor

function LinkExtractor:new(base, html, options)
  return setmetatable({ url = base, html = html or "", options = options or {} }, self)
end

-- True for a URL with a scheme ("http://h/") or a protocol-relative one.
LinkExtractor.isAbsolute = function(u)
  return u:match("^%a[%w+.-]*:") ~= nil or u:match("^//") ~= nil
end

-- The value of each href, src or action attribute (and CSS url()).
local function raw_links(html)
  local out = {}
  for attr, q, v in html:gmatch("[%s\"'](%a+)%s*=%s*([\"']?)([^\"'%s>]*)") do
    local a = attr:lower()
    if (a == "href" or a == "src" or a == "action") and v ~= "" then out[#out + 1] = v end
  end
  -- Quoted values with spaces.
  for attr, v in html:gmatch("[%s\"'](%a+)%s*=%s*\"([^\"]*)\"") do
    local a = attr:lower()
    if (a == "href" or a == "src" or a == "action") and v:find("%s") then out[#out + 1] = v end
  end
  for v in html:gmatch("url%(%s*[\"']?([^\"')%s]+)") do out[#out + 1] = v end
  return out
end

-- The page's <base href>, if any.
local function base_of(html)
  local tag = html:match("<[Bb][Aa][Ss][Ee][%s>][^>]*>")
  if not tag then return nil end
  return tag:match("[Hh][Rr][Ee][Ff]%s*=%s*[\"']?([^\"'%s>]+)")
end

function LinkExtractor:getLinks()
  local base = tostring(self.url)
  local b = base_of(self.html)
  if b then base = url.absolute(base, b) end
  local seen, out = {}, {}
  -- The <base> tag's own href is not a link.
  local html = self.html:gsub("<[Bb][Aa][Ss][Ee][%s>][^>]*>", "")
  for _, v in ipairs(raw_links(html)) do
    v = v:gsub("&amp;", "&"):gsub("#.*$", "")
    local scheme = v:match("^(%a[%w+.-]*):")
    if v ~= "" and (not scheme or scheme:lower() == "http" or scheme:lower() == "https") then
      local abs = LinkExtractor.isAbsolute(v) and v or url.absolute(base, v)
      if abs:match("^//") then abs = (self.url.proto or "http") .. ":" .. abs end
      if not seen[abs] then
        seen[abs] = true
        out[#out + 1] = abs
      end
    end
  end
  return out
end

httpspider.LinkExtractor = LinkExtractor

---------------------------------------------------------------------------
-- UrlQueue: the URLs still to visit, first in first out.
local UrlQueue = {}
UrlQueue.__index = UrlQueue

function UrlQueue:new(options)
  return setmetatable({ items = {}, head = 1, tail = 0, options = options or {} }, self)
end
function UrlQueue:add(u)
  if type(u) == "table" and getmetatable(u) ~= URL then
    for _, x in ipairs(u) do self:add(x) end
    return
  end
  self.tail = self.tail + 1
  self.items[self.tail] = u
end
function UrlQueue:getNext()
  local u = self.items[self.head]
  if u == nil then return nil end
  self.items[self.head] = nil
  self.head = self.head + 1
  return u
end
function UrlQueue:empty() return self.items[self.head] == nil end

httpspider.UrlQueue = UrlQueue

---------------------------------------------------------------------------
-- Options: the crawler's settings, from the script's own arguments
-- (`<scriptname>.maxpagecount`), then httpspider's (`httpspider.maxpagecount`),
-- then the options given to Crawler:new, then the defaults.
local Options = {}
Options.__index = Options

local function arg(scriptname, name)
  local v
  if scriptname then v = stdnse.get_script_args(scriptname .. "." .. name) end
  if v == nil then v = stdnse.get_script_args("httpspider." .. name) end
  return v
end

local function truthy(v)
  return v ~= nil and v ~= false and v ~= "false" and v ~= "0"
end

function Options:new(options)
  options = options or {}
  local o = setmetatable({}, self)
  for k, v in pairs(options) do o[k] = v end
  local s = options.scriptname
  local n = tonumber(arg(s, "maxpagecount"))
  o.maxpagecount = n or tonumber(options.maxpagecount) or 20
  n = tonumber(arg(s, "maxdepth"))
  o.maxdepth = n or tonumber(options.maxdepth) or 3
  local wh, wd = arg(s, "withinhost"), arg(s, "withindomain")
  if wh ~= nil then o.withinhost = truthy(wh) end
  if wd ~= nil then o.withindomain = truthy(wd) end
  if o.withinhost == nil and o.withindomain == nil then o.withinhost = true end
  if truthy(arg(s, "noblacklist")) then o.noblacklist = true end
  if truthy(arg(s, "useheadfornonwebfiles")) then o.useheadfornonwebfiles = true end
  o.whitelist = o.whitelist or {}
  o.blacklist = o.blacklist or {}
  return o
end

httpspider.Options = Options

---------------------------------------------------------------------------
-- Crawler.
local Crawler = {}
Crawler.__index = Crawler

local function is_ssl(port)
  if port.version and port.version.service_tunnel == "ssl" then return true end
  local s = port.service or (port.version and port.version.name) or ""
  return s == "https" or s == "ssl/http" or port.number == 443 or port.number == 8443
end

-- A crawler of host:port, starting at start (default "/", or the
-- httpspider.url argument).
function Crawler:new(host, port, start, options)
  local o = setmetatable({}, self)
  o.host, o.port = host, port
  o.options = Options:new(options)
  local scheme = is_ssl(port) and "https" or "http"
  local hostname = stdnse.get_hostname(host)
  if hostname:find(":", 1, true) then hostname = "[" .. hostname .. "]" end
  o.base = scheme .. "://" .. hostname .. ":" .. port.number
  start = arg(o.options.scriptname, "url") or start or "/"
  if not LinkExtractor.isAbsolute(start) then
    if start:sub(1, 1) ~= "/" then start = "/" .. start end
    start = o.base .. start
  end
  o.start = URL:new(start)
  o.queue = UrlQueue:new()
  o.queue:add(o.start)
  o.seen = { [tostring(o.start)] = true }
  o.pages = 0
  o.timeout = nil
  o.stopped = false
  o.started = nil
  -- Scope functions the options may replace (booleans keep the default).
  if type(o.options.withinhost) ~= "function" then
    local on = o.options.withinhost
    o.options.withinhost = function(u) return not on or o:iswithinhost(u) end
    o.withinhost_set = on
  end
  if type(o.options.withindomain) ~= "function" then
    local on = o.options.withindomain
    o.options.withindomain = function(u) return not on or o:iswithindomain(u) end
  end
  if type(o.options.doscraping) ~= "function" then
    o.options.doscraping = function(u) return true end
  end
  return o
end

-- The whole crawl's time limit in milliseconds (nmap's set_timeout).
function Crawler:set_timeout(ms) self.timeout = tonumber(ms) end

function Crawler:stop() self.stopped = true end

local function as_url(u)
  if getmetatable(u) == URL then return u end
  return URL:new(tostring(u))
end

function Crawler:iswithinhost(u)
  u = as_url(u)
  if not u.host then return true end
  return u.host:lower() == self.start.host:lower() and u.port == self.start.port
end

-- The last two labels of a name (example.com for www.example.com).
local function domain(h)
  if not h then return nil end
  h = h:lower()
  if h:match("^[%d.]+$") or h:find(":", 1, true) then return h end
  return h:match("([^.]+%.[^.]+)$") or h
end

function Crawler:iswithindomain(u)
  u = as_url(u)
  if not u.host then return true end
  return domain(u.host) == domain(self.start.host)
end

-- Whether u's file has the extension ext, possibly followed by one of
-- the characters in signs (default "#" and "?").
function Crawler:isresource(u, ext, signs)
  local raw = tostring(as_url(u))
  signs = signs or { "#", "?" }
  if type(signs) == "string" then signs = { signs } end
  ext = ext:lower():gsub("^%.", "")
  local path = raw:lower()
  local cut = #path + 1
  for _, s in ipairs(signs) do
    local i = path:find(s, 1, true)
    if i and i < cut then cut = i end
  end
  path = path:sub(1, cut - 1)
  return path:sub(-(#ext + 1)) == "." .. ext
end

-- The crawl's limits, as nmap's scripts show them under their output.
function Crawler:getLimitations()
  local o = self.options
  local parts = {}
  if o.maxdepth and o.maxdepth >= 0 then
    parts[#parts + 1] = ("maxdepth=%d"):format(o.maxdepth)
  end
  if o.maxpagecount and o.maxpagecount >= 0 then
    parts[#parts + 1] = ("maxpagecount=%d"):format(o.maxpagecount)
  end
  if self.withinhost_set then
    parts[#parts + 1] = "withinhost=" .. (self.start.host or "")
  end
  if #parts == 0 then return nil end
  return "Spidering limited to: " .. table.concat(parts, "; ")
end

-- Whether the crawler may visit u at all.
function Crawler:allowed(u)
  local o = self.options
  if u.proto ~= "http" and u.proto ~= "https" then return false end
  if not o.withinhost(u) or not o.withindomain(u) then return false end
  if o.maxdepth and o.maxdepth >= 0 then
    if u:getDirDepth() - self.start:getDirDepth() > o.maxdepth then return false end
  end
  if not o.noblacklist and BINARY[extension(u.path)] then return false end
  for _, f in ipairs(o.blacklist) do
    if f(u) then return false end
  end
  if #o.whitelist > 0 then
    local any = false
    for _, f in ipairs(o.whitelist) do
      if f(u) then any = true break end
    end
    if not any then return false end
  end
  return true
end

-- The next page: true and { url = URL, response = response }, or false
-- and { err = true, reason = ... } on an error, or false and
-- { msg = ... } when the crawl is done (no more pages, a limit reached,
-- stopped).
function Crawler:crawl()
  self.started = self.started or stdnse.clock_ms()
  while true do
    if self.stopped then return false, { msg = "Crawler stopped" } end
    local o = self.options
    if o.maxpagecount and o.maxpagecount >= 0 and self.pages >= o.maxpagecount then
      return false, { msg = "Reached the maximum page count" }
    end
    if self.timeout and stdnse.clock_ms() - self.started > self.timeout then
      return false, { msg = "Crawler timed out" }
    end
    local u = self.queue:getNext()
    if not u then return false, { msg = "No more URLs" } end
    if self:allowed(u) then
      local path = u.path .. (u.querystring and ("?" .. u.querystring) or "")
      local opts = { no_cache = o.no_cache, redirect_ok = o.redirect_ok }
      if u.proto == "https" then opts.scheme = "https" elseif u.proto == "http" then opts.scheme = "http" end
      local resp
      if o.useheadfornonwebfiles and not WEB_FILES[extension(u.path)] then
        resp = http.head(self.host, u.port or self.port, path, opts)
      else
        resp = http.get(self.host, u.port or self.port, path, opts)
      end
      self.pages = self.pages + 1
      if resp and resp.status then
        local ctype = resp.header and resp.header["content-type"] or ""
        if resp.body and o.doscraping(u)
          and (ctype == "" or ctype:find("html", 1, true) or ctype:find("xml", 1, true)) then
          for _, link in ipairs(LinkExtractor:new(u, resp.body, o):getLinks()) do
            if not self.seen[link] then
              self.seen[link] = true
              local lu = URL:new(link)
              if self:allowed(lu) then self.queue:add(lu) end
            end
          end
        end
        return true, { url = u, response = resp }
      end
      -- A page that gave no answer is skipped, as a crawl goes on.
    end
  end
end

httpspider.Crawler = Crawler

return httpspider
