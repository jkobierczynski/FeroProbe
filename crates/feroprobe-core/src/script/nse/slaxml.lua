-- NSE compatibility layer: the `slaxml` module, a SAX-like XML parser
-- and a DOM builder over it. Written for FeroProbe from nmap's public API
-- documentation (not from nselib or SLAXML's code); GPL-3.0-or-later,
-- like FeroProbe.
--
-- Like the original, it is lenient rather than validating: it reports
-- what it reads in order and does not check that elements nest, so a
-- script may feed a document in pieces that each end after a ">".
local fero = ...
local slaxml = {}

local ENTITIES = { lt = "<", gt = ">", amp = "&", quot = '"', apos = "'" }

local utf8_char = utf8.char
local function utf8(cp)
  if cp < 0 or cp > 0x10ffff then return nil end
  return utf8_char(cp)
end

-- Entity and character references replaced; unknown ones left as they are.
local function unescape(s)
  return (s:gsub("&(#?[%w]+);", function(e)
    if e:sub(1, 2) == "#x" or e:sub(1, 2) == "#X" then
      local n = tonumber(e:sub(3), 16)
      return n and utf8(n)
    elseif e:sub(1, 1) == "#" then
      local n = tonumber(e:sub(2))
      return n and utf8(n)
    end
    return ENTITIES[e]
  end))
end

local function debug_level()
  local d = fero.args and fero.args.get("slaxml.debug")
  return tonumber(d) or 3
end

-- Default callbacks: print what is parsed at the slaxml.debug level.
local function default_calls()
  local lvl = debug_level()
  local function say(...) fero.debug(lvl, table.concat({ ... }, " ")) end
  return {
    startElement = function(name, nsURI, nsPrefix)
      say("startElement", tostring(name), tostring(nsURI), tostring(nsPrefix))
    end,
    attribute = function(name, value, nsURI, nsPrefix)
      say("attribute", tostring(name), tostring(value), tostring(nsURI), tostring(nsPrefix))
    end,
    closeElement = function(name, nsURI) say("closeElement", tostring(name), tostring(nsURI)) end,
    text = function(text) say("text", tostring(text)) end,
    comment = function(content) say("comment", tostring(content)) end,
    pi = function(target, content) say("pi", tostring(target), tostring(content)) end,
  }
end

slaxml.parser = { unescape = unescape }
slaxml.parser.__index = slaxml.parser

---
-- slaxml.parser:new(callbacks): a parser calling callbacks (kept as
-- parser._call, which a script may change while parsing).
function slaxml.parser:new(callbacks)
  local o = setmetatable({}, self)
  o._call = callbacks or default_calls()
  return o
end

local function call(self, name, ...)
  local f = self._call and self._call[name]
  if f then return f(...) end
end

-- "prefix:local" as local and prefix.
local function split(qname)
  local p, l = qname:match("^([^:]+):(.+)$")
  if p then return l, p end
  return qname, nil
end

local function lookup(stack, prefix)
  for i = #stack, 1, -1 do
    local uri = stack[i][prefix or ""]
    if uri ~= nil then return uri end
  end
  return nil
end

---
-- parser:parseSAX(xml, options): parses xml, calling the callbacks;
-- options.stripWhitespace trims text and skips text that is only white
-- space.
function slaxml.parser:parseSAX(xml, options)
  xml = tostring(xml or "")
  options = options or {}
  local strip = options.stripWhitespace or options.stripWhitespaces
  local ns = { { xml = "http://www.w3.org/XML/1998/namespace" } }
  local open = {}
  local pos, n = 1, #xml

  local function emit_text(t, raw)
    if strip then
      t = t:match("^%s*(.-)%s*$")
      if t == "" then return end
    end
    call(self, "text", raw and t or unescape(t))
  end

  while pos <= n do
    local lt = xml:find("<", pos, true)
    if not lt then
      emit_text(xml:sub(pos))
      break
    end
    if lt > pos then emit_text(xml:sub(pos, lt - 1)) end
    if xml:sub(lt, lt + 3) == "<!--" then
      local e = xml:find("-->", lt + 4, true)
      call(self, "comment", xml:sub(lt + 4, (e or n + 1) - 1))
      pos = e and e + 3 or n + 1
    elseif xml:sub(lt, lt + 8) == "<![CDATA[" then
      local e = xml:find("]]>", lt + 9, true)
      call(self, "text", xml:sub(lt + 9, (e or n + 1) - 1))
      pos = e and e + 3 or n + 1
    elseif xml:sub(lt, lt + 1) == "<?" then
      local e = xml:find("?>", lt + 2, true)
      local body = xml:sub(lt + 2, (e or n + 1) - 1)
      local target, content = body:match("^(%S+)%s*(.-)$")
      if target then call(self, "pi", target, content) end
      pos = e and e + 2 or n + 1
    elseif xml:sub(lt, lt + 1) == "<!" then
      -- A DOCTYPE or other declaration, with an internal subset in [...].
      local e = lt + 2
      local depth = 0
      while e <= n do
        local c = xml:sub(e, e)
        if c == "[" then depth = depth + 1
        elseif c == "]" then depth = depth - 1
        elseif c == ">" and depth <= 0 then break end
        e = e + 1
      end
      pos = e + 1
    elseif xml:sub(lt, lt + 1) == "</" then
      local name, e = xml:match("^%s*([^%s>]+)%s*>()", lt + 2)
      if not name then
        emit_text(xml:sub(lt))
        break
      end
      local localname, prefix = split(name)
      call(self, "closeElement", localname, lookup(ns, prefix), prefix)
      if #ns > 1 and open[#open] == name then
        ns[#ns] = nil
        open[#open] = nil
      end
      pos = e
    else
      local name, rest = xml:match("^([^%s/>]+)()", lt + 1)
      if not name then
        emit_text("<")
        pos = lt + 1
      else
        -- The attributes up to the tag's end (">" outside quotes).
        local attrs = {}
        local p = rest
        local closed, selfclose = false, false
        while p <= n do
          local s, e2 = xml:find("^%s*", p)
          p = e2 + 1
          local c = xml:sub(p, p)
          if c == ">" then closed = true; p = p + 1; break end
          if xml:sub(p, p + 1) == "/>" then closed, selfclose = true, true; p = p + 2; break end
          if c == "" then break end
          local an, after = xml:match("^([^%s=/>]+)%s*=%s*()", p)
          if not an then
            -- An attribute without a value, or junk: skip a word.
            local skip = xml:match("^[^%s/>]+()", p)
            p = skip or p + 1
          else
            local q = xml:sub(after, after)
            local val, nxt
            if q == '"' or q == "'" then
              local e3 = xml:find(q, after + 1, true)
              val = xml:sub(after + 1, (e3 or n + 1) - 1)
              nxt = e3 and e3 + 1 or n + 1
            else
              val, nxt = xml:match("^([^%s>]*)()", after)
            end
            attrs[#attrs + 1] = { an, unescape(val) }
            p = nxt
          end
        end
        -- Namespace declarations of this element.
        local scope = {}
        for _, a in ipairs(attrs) do
          if a[1] == "xmlns" then scope[""] = a[2]
          else
            local pfx = a[1]:match("^xmlns:(.+)$")
            if pfx then scope[pfx] = a[2] end
          end
        end
        ns[#ns + 1] = scope
        open[#open + 1] = name
        local localname, prefix = split(name)
        call(self, "startElement", localname, lookup(ns, prefix), prefix)
        for _, a in ipairs(attrs) do
          local aname, apfx = split(a[1])
          local auri = apfx and apfx ~= "xmlns" and lookup(ns, apfx) or nil
          call(self, "attribute", aname, a[2], auri, apfx)
        end
        if selfclose then
          call(self, "closeElement", localname, lookup(ns, prefix), prefix)
          ns[#ns] = nil
          open[#open] = nil
        end
        pos = closed and p or n + 1
      end
    end
  end
end

---
-- slaxml.parseDOM(xml, options): the document as a table: { type =
-- "document", name = "#doc", kids, root }; elements { type = "element",
-- name, nsURI, attr (by index and by name), kids, el, parent }; text,
-- comment and pi nodes { type, name, value, parent }.
function slaxml.parseDOM(xml, options)
  local doc = { type = "document", name = "#doc", kids = {} }
  local current = doc
  local function push(node)
    node.parent = current
    current.kids[#current.kids + 1] = node
  end
  local builder = slaxml.parser:new({
    startElement = function(name, nsURI)
      local el = { type = "element", name = name, nsURI = nsURI, attr = {}, kids = {}, el = {} }
      push(el)
      if current.el then current.el[#current.el + 1] = el end
      if current == doc and not doc.root then doc.root = el end
      current = el
    end,
    attribute = function(name, value, nsURI)
      if current.type ~= "element" then return end
      local a = { type = "attribute", name = name, value = value, nsURI = nsURI, parent = current }
      current.attr[#current.attr + 1] = a
      current.attr[name] = value
    end,
    closeElement = function()
      if current ~= doc then current = current.parent end
    end,
    text = function(text) push({ type = "text", name = "#text", value = text }) end,
    comment = function(c) push({ type = "comment", name = "#comment", value = c }) end,
    pi = function(target, content) push({ type = "pi", name = target, value = content }) end,
  })
  builder:parseSAX(xml, options)
  return doc
end

return slaxml
