-- NSE compatibility layer: the `vulns` module, reports of what a
-- vulnerability check found.
-- Written for FeroProbe from nmap's public API documentation (not from
-- nselib); GPL-3.0-or-later, like FeroProbe.
local fero = ...
local stdnse = require "stdnse"
local vulns = {}

vulns.STATE = {
  NOT_VULN = 1,
  LIKELY_VULN = 2,
  VULN = 4,
  DoS = 8,
  EXPLOIT = 16,
  UNKNOWN = 32,
}

vulns.STATE_MSG = {
  [vulns.STATE.NOT_VULN] = "NOT VULNERABLE",
  [vulns.STATE.LIKELY_VULN] = "LIKELY VULNERABLE",
  [vulns.STATE.VULN] = "VULNERABLE",
  [vulns.STATE.DoS] = "VULNERABLE (DoS)",
  [vulns.STATE.EXPLOIT] = "VULNERABLE (Exploitable)",
  [vulns.STATE.DoS | vulns.STATE.VULN] = "VULNERABLE (DoS)",
  [vulns.STATE.EXPLOIT | vulns.STATE.VULN] = "VULNERABLE (Exploitable)",
  [vulns.STATE.UNKNOWN] = "UNKNOWN (unable to test)",
}

local function vulnerable(state)
  return state ~= nil and state ~= vulns.STATE.NOT_VULN and state ~= vulns.STATE.UNKNOWN
end

local function state_text(state)
  return vulns.STATE_MSG[state] or tostring(state)
end

local function date_text(d)
  if type(d) ~= "table" then return tostring(d) end
  if d.year then
    return string.format("%04d-%02d-%02d", d.year, d.month or 1, d.day or 1)
  end
  return nil
end

local function add_list(lines, label, list, indent)
  if type(list) == "string" then list = { list } end
  if type(list) ~= "table" or #list == 0 then return end
  lines[#lines + 1] = indent .. label .. ":"
  for _, v in ipairs(list) do lines[#lines + 1] = indent .. "  " .. tostring(v) end
end

-- One vulnerability table as output lines.
local function format(v)
  local lines = {}
  lines[#lines + 1] = tostring(v.title or "(untitled)")
  local ind = "  "
  lines[#lines + 1] = ind .. "State: " .. state_text(v.state)
  if type(v.IDS) == "table" then
    local ids = {}
    for k, id in pairs(v.IDS) do ids[#ids + 1] = k .. ":" .. tostring(id) end
    table.sort(ids)
    if #ids > 0 then lines[#lines + 1] = ind .. "IDs:  " .. table.concat(ids, "  ") end
  end
  if v.risk_factor then
    local r = ind .. "Risk factor: " .. tostring(v.risk_factor)
    if type(v.scores) == "table" then
      local s = {}
      for k, x in pairs(v.scores) do s[#s + 1] = k .. ": " .. tostring(x) end
      table.sort(s)
      if #s > 0 then r = r .. "  " .. table.concat(s, "  ") end
    end
    lines[#lines + 1] = r
  end
  if v.description then
    for l in tostring(v.description):gmatch("[^\n]+") do
      local t = l:match("^%s*(.-)%s*$")
      if t ~= "" then lines[#lines + 1] = ind .. "  " .. t end
    end
  end
  if type(v.dates) == "table" and v.dates.disclosure then
    local d = date_text(v.dates.disclosure)
    if d then lines[#lines + 1] = ind .. "Disclosure date: " .. d end
  end
  add_list(lines, "Check results", v.check_results, ind)
  add_list(lines, "Extra information", v.extra_info, ind)
  add_list(lines, "Exploit results", v.exploit_results, ind)
  local refs = {}
  if type(v.references) == "table" then
    for _, r in ipairs(v.references) do refs[#refs + 1] = r end
  end
  if type(v.IDS) == "table" and v.IDS.CVE then
    refs[#refs + 1] = "https://cve.mitre.org/cgi-bin/cvename.cgi?name=" .. tostring(v.IDS.CVE)
  end
  add_list(lines, "References", refs, ind)
  return lines
end

-- A report for a script on a host (and port).
vulns.Report = {}
vulns.Report.__index = vulns.Report

function vulns.Report:new(script_name, host, port)
  return setmetatable({ script_name = script_name, host = host, port = port, list = {} }, self)
end

-- Add vulnerability tables to the report.
function vulns.Report:add_vulns(...)
  for i = 1, select("#", ...) do
    local v = select(i, ...)
    if type(v) == "table" then self.list[#self.list + 1] = v end
  end
  return true
end

-- The output for the given vulnerability tables (and any added before):
-- the vulnerable ones, under "VULNERABLE:"; with the script argument
-- vulns.showall, also those found not vulnerable. nil when nothing is
-- shown, as nmap shows nothing for a host that is not vulnerable.
function vulns.Report:make_output(...)
  self:add_vulns(...)
  local showall = stdnse.get_script_args("vulns.showall") and true or false
  local lines, shown = {}, 0
  local function section(header, filter)
    local any = false
    for _, v in ipairs(self.list) do
      if filter(v.state) then
        if not any then lines[#lines + 1] = header any = true end
        for _, l in ipairs(format(v)) do lines[#lines + 1] = "  " .. l end
        shown = shown + 1
      end
    end
  end
  section("VULNERABLE:", vulnerable)
  if showall then
    section("NOT VULNERABLE:", function(s) return not vulnerable(s) end)
  end
  if shown == 0 then return nil end
  return "\n  " .. table.concat(lines, "\n  ")
end

return vulns
