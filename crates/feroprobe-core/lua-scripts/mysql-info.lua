-- FeroProbe script: mysql-info
-- Written for FeroProbe from scratch, from the MySQL client/server
-- protocol documentation (Protocol::Handshake); GPL-3.0-or-later.

description = [[
Reads the greeting a MySQL or MariaDB server sends when a connection
opens: protocol and server version, connection (thread) ID, capability
flags, status and the authentication plugin. Sends nothing and logs in
to nothing. A server that refuses the connection says why, and that is
shown.

Script arguments:
  mysql-info.timeout  How long to wait for the greeting, in milliseconds
                      (default 8000).
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "default", "discovery", "safe" }

portrule = fero.portrule.match({ 3306 }, { "mysql" })

-- Capability flags, by bit, with the names the protocol documentation
-- gives them (CLIENT_...).
local CAPABILITIES = {
  [0] = "LONG_PASSWORD", "FOUND_ROWS", "LONG_FLAG", "CONNECT_WITH_DB",
  "NO_SCHEMA", "COMPRESS", "ODBC", "LOCAL_FILES", "IGNORE_SPACE",
  "PROTOCOL_41", "INTERACTIVE", "SSL", "IGNORE_SIGPIPE", "TRANSACTIONS",
  "RESERVED", "SECURE_CONNECTION", "MULTI_STATEMENTS", "MULTI_RESULTS",
  "PS_MULTI_RESULTS", "PLUGIN_AUTH", "CONNECT_ATTRS",
  "PLUGIN_AUTH_LENENC_CLIENT_DATA", "CAN_HANDLE_EXPIRED_PASSWORDS",
  "SESSION_TRACK", "DEPRECATE_EOF",
}

local function printable(s)
  return (s:gsub("[^\32-\126]", function(c) return string.format("\\x%02x", c:byte()) end))
end

action = function(host, port)
  local timeout = tonumber(fero.args.get(SCRIPT_NAME .. ".timeout")) or 8000
  local sock = fero.socket.new()
  sock:set_timeout(timeout)
  if not sock:connect(host, port) then return nil end
  local r = fero.reader(sock)
  local head = r:bytes(4)
  local payload = head and r:bytes(string.unpack("<I3", head))
  sock:close()
  if not payload or #payload < 1 then return nil end
  local proto = payload:byte(1)
  if proto == 0xff and #payload >= 3 then
    local code = string.unpack("<I2", payload, 2)
    local msg = payload:sub(4):gsub("^#%w%w%w%w%w", "")
    return { error_code = tostring(code), error = printable(msg) },
      "Error " .. code .. ": " .. printable(msg)
  end
  if proto ~= 10 then return nil end
  local ok, version, pos = pcall(string.unpack, "z", payload, 2)
  if not ok or pos + 31 > #payload + 1 then return nil end
  local thread, salt1, caps_lo, _, status, caps_hi, auth_len
  thread, salt1, pos = string.unpack("<I4c8", payload, pos)
  pos = pos + 1 -- filler
  caps_lo, pos = string.unpack("<I2", payload, pos)
  local charset
  if pos <= #payload then
    charset, status, caps_hi, auth_len, pos = string.unpack("<BI2I2B", payload, pos)
  end
  local caps = caps_lo | ((caps_hi or 0) << 16)
  local data = {
    ["Protocol"] = tostring(proto),
    ["Version"] = printable(version),
    ["Thread ID"] = tostring(thread),
    ["Capabilities flags"] = tostring(caps),
  }
  local lines = {
    "Protocol: " .. proto,
    "Version: " .. data["Version"],
    "Thread ID: " .. thread,
    "Capabilities flags: " .. caps,
  }
  local names = {}
  for bit = 0, 31 do
    if caps & (1 << bit) ~= 0 and CAPABILITIES[bit] then
      names[#names + 1] = CAPABILITIES[bit]
    end
  end
  if #names > 0 then
    data["Some Capabilities"] = names
    lines[#lines + 1] = "Some Capabilities: " .. table.concat(names, ", ")
  end
  if status then
    local s = status & 2 ~= 0 and "Autocommit" or tostring(status)
    data["Status"] = s
    lines[#lines + 1] = "Status: " .. s
  end
  local salt = salt1
  if pos and pos + 10 <= #payload then
    pos = pos + 10 -- reserved
    local n = math.max(13, (auth_len or 0) - 8)
    local salt2 = payload:sub(pos, pos + n - 1):gsub("%z$", "")
    salt = salt .. salt2
    pos = pos + n
    if caps & (1 << 19) ~= 0 and pos <= #payload then
      local plugin = payload:sub(pos):match("^[^%z]*")
      if plugin ~= "" then data["Auth Plugin Name"] = printable(plugin) end
    end
  end
  data["Salt"] = printable(salt)
  lines[#lines + 1] = "Salt: " .. data["Salt"]
  if data["Auth Plugin Name"] then
    lines[#lines + 1] = "Auth Plugin Name: " .. data["Auth Plugin Name"]
  end
  return data, "\n  " .. table.concat(lines, "\n  ")
end
