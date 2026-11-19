-- FeroProbe script: ntp-info
-- Written for FeroProbe from scratch (RFC 5905 NTPv4, RFC 9327 NTP
-- control messages); GPL-3.0-or-later.

description = [[
Asks an NTP server for its time, with an ordinary client request, and
for its system variables (version, operating system, stratum, reference
clock and others) with a control-message READVAR request, which many
servers refuse. Shows the server's receive time and the variables it
gave. Each request is a single small datagram; READVAR is not the
"monlist" request known for traffic amplification.

Script arguments:
  ntp-info.timeout  How long to wait for each answer, in milliseconds
                    (default 5000).
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "default", "discovery", "safe" }

portrule = fero.portrule.match({ 123 }, { "ntp" }, "udp")

-- Seconds from the NTP era (1900) to the Unix epoch (1970).
local NTP_EPOCH = 2208988800

-- The variables shown, in this order; others the server gives are kept
-- in the structured output only.
local SHOWN = {
  "version", "processor", "system", "leap", "stratum", "precision",
  "rootdelay", "rootdisp", "refid", "reftime", "clock", "peer", "tc",
  "mintc", "offset", "frequency", "sys_jitter", "clk_jitter", "clk_wander",
}

local function parse_vars(text)
  local vars = {}
  local pos = 1
  for _ = 1, 200 do
    local s, e, name = text:find("^%s*([%w_%.%-]+)", pos)
    if not s then break end
    pos = e + 1
    local value = ""
    if text:sub(pos, pos) == "=" then
      pos = pos + 1
      if text:sub(pos, pos) == '"' then
        local close = text:find('"', pos + 1, true) or #text + 1
        value = text:sub(pos + 1, close - 1)
        pos = close + 1
      else
        local v = text:match("^[^,\r\n]*", pos)
        value = v
        pos = pos + #v
      end
    end
    vars[name] = (value:gsub("[^\32-\126]", "?"))
    local sep = text:find("^%s*,", pos)
    if not sep then break end
    pos = text:find(",", pos, true) + 1
  end
  return vars
end

action = function(host, port)
  local timeout = tonumber(fero.args.get(SCRIPT_NAME .. ".timeout")) or 5000
  local data, lines = {}, {}

  -- A client request: LI 0, version 4, mode 3, the rest zero.
  local sock = fero.socket.new()
  sock:set_timeout(timeout)
  if sock:connect(host, port, "udp") then
    sock:send(string.char(0x23) .. string.rep("\0", 47))
    local ok, reply = sock:receive()
    if ok and #reply >= 48 and reply:byte(1) & 7 == 4 then
      local secs = string.unpack(">I4", reply, 33)
      if secs ~= 0 then
        fero.record_skew(secs - NTP_EPOCH)
        local when = os.date("!%Y-%m-%dT%H:%M:%S", secs - NTP_EPOCH)
        data["receive time stamp"] = when
        lines[#lines + 1] = "receive time stamp: " .. when
      end
    end
    sock:close()
  end

  -- READVAR (opcode 2) for the system variables (association 0).
  sock = fero.socket.new()
  sock:set_timeout(timeout)
  if sock:connect(host, port, "udp") then
    sock:send(string.pack(">BBI2I2I2I2I2", 0x16, 2, 1, 0, 0, 0, 0))
    -- Fragments may arrive in any order: the one without the "more" bit
    -- gives the end, and the reply is whole once the fragments cover every
    -- byte from 0 to that end (RFC 9327 section 2.4).
    local parts, seen, last_end, complete = {}, {}, nil, false
    local function covered()
      table.sort(parts, function(a, b) return a[1] < b[1] end)
      local at = 0
      -- Back to back: a gap waits for more, an overlap never completes.
      for _, p in ipairs(parts) do
        if p[1] ~= at then return false end
        at = at + #p[2]
      end
      return at >= last_end
    end
    for _ = 1, 16 do
      local ok, reply = sock:receive()
      if not ok or #reply < 12 then break end
      local _, op, _, _, _, offset, count = string.unpack(">BBI2I2I2I2I2", reply)
      if op & 0x80 == 0 or op & 0x40 ~= 0 or op & 0x1f ~= 2 then break end
      if count > #reply - 12 then break end
      if not seen[offset] then
        seen[offset] = true
        parts[#parts + 1] = { offset, reply:sub(13, 12 + count) }
      end
      if op & 0x20 == 0 then last_end = offset + count end
      if last_end and covered() then
        complete = true
        break
      end
    end
    sock:close()
    if complete then
      local text = {}
      for i, p in ipairs(parts) do text[i] = p[2] end
      local vars = parse_vars(table.concat(text))
      for k, v in pairs(vars) do data[k] = v end
      for _, k in ipairs(SHOWN) do
        if vars[k] then lines[#lines + 1] = k .. ": " .. vars[k] end
      end
    end
  end
  if #lines == 0 then return nil end
  return data, "\n  " .. table.concat(lines, "\n  ")
end
