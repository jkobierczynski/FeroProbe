-- NSE compatibility layer: the `ls` module, the shared output of scripts
-- that list files (nfs-ls, smb-ls, ftp and http listings). Written for
-- FeroProbe from nmap's public API documentation (not from nselib);
-- GPL-3.0-or-later, like FeroProbe. The text layout (a "Volume" line,
-- info lines, then aligned columns) follows nmap's documented nfs-ls
-- output; the structured form is FeroProbe's own.
local fero = ...
local stdnse = require "stdnse"
local tab = require "tab"
local ls = {}

local DEFAULTS = {
  errors = false, human = false, empty = false, checksum = false,
  maxdepth = 0, maxfiles = 10,
}

local function as_bool(v)
  if type(v) == "boolean" then return v end
  if v == nil then return false end
  v = tostring(v):lower()
  return not (v == "false" or v == "0" or v == "no" or v == "")
end

---
-- ls.config(argname): the <script>.argname argument, else ls.argname,
-- else the default (maxfiles 10, maxdepth 0, the flags false).
function ls.config(argname)
  local v
  if SCRIPT_NAME then v = stdnse.get_script_args(SCRIPT_NAME .. "." .. argname) end
  if v == nil then v = stdnse.get_script_args("ls." .. argname) end
  local default = DEFAULTS[argname]
  if v == nil then return default end
  if type(default) == "boolean" then return as_bool(v) end
  if type(default) == "number" then return tonumber(v) or default end
  return v
end

---
-- ls.new_listing(): an empty listing.
function ls.new_listing()
  return {
    volumes = {}, errors = {}, info = {},
    maxfiles = ls.config("maxfiles"), showerrors = ls.config("errors"),
    showempty = ls.config("empty"), total = { files = 0, bytes = 0 },
  }
end

---
-- ls.new_vol(output, name, hasperms): starts a volume; hasperms adds the
-- permission, owner and group columns.
function ls.new_vol(output, name, hasperms)
  output.cur = { name = name, hasperms = hasperms, files = {}, info = {}, errors = {}, count = 0 }
end

---
-- ls.add_file(output, file): adds a file to the volume: an array
-- { permission, uid, gid, size, time, filename } (with permissions) or
-- { size, time, filename }, or a table with those names. False once
-- maxfiles files are listed.
function ls.add_file(output, file)
  local vol = output.cur
  if not vol then return false end
  if output.maxfiles and output.maxfiles > 0 and vol.count >= output.maxfiles then
    vol.truncated = true
    return false
  end
  local f
  if vol.hasperms then
    f = { permission = file.permission or file[1], uid = file.uid or file[2], gid = file.gid or file[3],
      size = file.size or file[4], time = file.time or file[5], filename = file.filename or file[6] }
  else
    f = { size = file.size or file[1], time = file.time or file[2], filename = file.filename or file[3] }
  end
  if file.checksum then f.checksum = file.checksum end
  vol.files[#vol.files + 1] = f
  vol.count = vol.count + 1
  output.total.files = output.total.files + 1
  local n = tonumber(f.size)
  if n then output.total.bytes = output.total.bytes + n end
  if output.maxfiles and output.maxfiles > 0 and vol.count >= output.maxfiles then
    vol.truncated = true
    return false
  end
  return true
end

---
-- ls.end_vol(output): ends the volume.
function ls.end_vol(output)
  local vol = output.cur
  if not vol then return end
  if #vol.files > 0 or #vol.info > 0 or #vol.errors > 0 or output.showempty then
    output.volumes[#output.volumes + 1] = vol
  end
  output.cur = nil
end

---
-- ls.report_error(output, err, level): a debug message at level (1),
-- and a line of the output when the errors argument is set.
function ls.report_error(output, err, level)
  stdnse.debug(level or 1, "%s", tostring(err))
  if output.showerrors then
    local t = output.cur and output.cur.errors or output.errors
    t[#t + 1] = tostring(err)
  end
end

---
-- ls.report_info(output, info, level): a debug message at level (1) and
-- a line of the output.
function ls.report_info(output, info, level)
  stdnse.debug(level or 1, "%s", tostring(info))
  local t = output.cur and output.cur.info or output.info
  t[#t + 1] = tostring(info)
end

local function vol_text(vol, lines)
  lines[#lines + 1] = "Volume " .. tostring(vol.name)
  for _, s in ipairs(vol.info) do lines[#lines + 1] = s end
  for _, s in ipairs(vol.errors) do lines[#lines + 1] = "ERROR: " .. s end
  if #vol.files > 0 then
    local t = tab.new()
    local checksum = vol.files[1].checksum ~= nil
    local head = vol.hasperms and { "PERMISSION", "UID", "GID", "SIZE", "TIME", "FILENAME" }
      or { "SIZE", "TIME", "FILENAME" }
    if checksum then head[#head + 1] = "CHECKSUM" end
    tab.addrow(t, table.unpack(head))
    for _, f in ipairs(vol.files) do
      local row = vol.hasperms and { f.permission, f.uid, f.gid, f.size, f.time, f.filename }
        or { f.size, f.time, f.filename }
      if checksum then row[#row + 1] = f.checksum or "" end
      for i = 1, #head do row[i] = tostring(row[i] == nil and "" or row[i]) end
      tab.addrow(t, table.unpack(row, 1, #head))
    end
    for line in tab.dump(t):gmatch("[^\n]+") do lines[#lines + 1] = line end
  end
  if vol.truncated then lines[#lines + 1] = "(only the first " .. tostring(vol.count) .. " files are listed)" end
  lines[#lines + 1] = ""
end

---
-- ls.end_listing(output): the structured output (volumes with their
-- files, info and errors, and the totals) and the text.
function ls.end_listing(output)
  if output.cur then ls.end_vol(output) end
  local lines = {}
  for _, s in ipairs(output.info) do lines[#lines + 1] = s end
  for _, s in ipairs(output.errors) do lines[#lines + 1] = "ERROR: " .. s end
  local structured = { volumes = {}, total = output.total }
  for _, vol in ipairs(output.volumes) do
    vol_text(vol, lines)
    structured.volumes[#structured.volumes + 1] = {
      volume = vol.name, files = vol.files, info = vol.info, errors = vol.errors,
    }
  end
  if #output.info > 0 then structured.info = output.info end
  if #output.errors > 0 then structured.errors = output.errors end
  if #lines == 0 then return nil end
  while lines[#lines] == "" do lines[#lines] = nil end
  for i, l in ipairs(lines) do lines[i] = l == "" and "" or ("  " .. l) end
  return structured, "\n" .. table.concat(lines, "\n")
end

return ls
