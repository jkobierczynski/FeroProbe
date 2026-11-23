-- NSE compatibility layer: the `ipOps` module, IPv4 and IPv6 addresses.
-- Written for FeroProbe from nmap's public API documentation (not from
-- nselib); GPL-3.0-or-later, like FeroProbe.
local ipOps = {}

local function v4_bytes(ip)
  local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
  if not a then return nil end
  local t = { tonumber(a), tonumber(b), tonumber(c), tonumber(d) }
  for _, n in ipairs(t) do if n > 255 then return nil end end
  return string.char(table.unpack(t))
end

local function v6_bytes(ip)
  ip = ip:gsub("%%.*$", "")
  -- A trailing dotted IPv4 part becomes two groups.
  local head, v4 = ip:match("^(.*:)(%d+%.%d+%.%d+%.%d+)$")
  if head then
    local b = v4_bytes(v4)
    if not b then return nil end
    ip = head .. string.format("%x:%x", b:byte(1) * 256 + b:byte(2), b:byte(3) * 256 + b:byte(4))
  end
  local left, right = ip, nil
  local dc = ip:find("::", 1, true)
  if dc then
    left, right = ip:sub(1, dc - 1), ip:sub(dc + 2)
    if right:find("::", 1, true) then return nil end
  end
  local function groups(s)
    local g = {}
    if s == "" then return g end
    for part in (s .. ":"):gmatch("([^:]*):") do
      if not part:match("^%x%x?%x?%x?$") then return nil end
      g[#g + 1] = tonumber(part, 16)
    end
    return g
  end
  local l, r = groups(left), groups(right or "")
  if not l or not r then return nil end
  local all = {}
  for _, v in ipairs(l) do all[#all + 1] = v end
  if dc then
    if #l + #r > 7 then return nil end
    for _ = 1, 8 - #l - #r do all[#all + 1] = 0 end
  end
  for _, v in ipairs(r) do all[#all + 1] = v end
  if #all ~= 8 then return nil end
  local out = {}
  for i, v in ipairs(all) do out[i] = string.char(v // 256, v % 256) end
  return table.concat(out)
end

-- The address as 4 or 16 bytes (network order); nil and a message when
-- it is not one.
ipOps.ip_to_str = function(ip)
  if type(ip) ~= "string" then return nil, "Error in ip_to_str: not a string" end
  local b = v4_bytes(ip) or (ip:find(":") and v6_bytes(ip))
  if not b then return nil, "Error in ip_to_str: not an IP address: " .. ip end
  return b
end

-- 4 or 16 bytes as an address in text; IPv6 in its shortest form.
ipOps.str_to_ip = function(b)
  if #b == 4 then return string.format("%d.%d.%d.%d", b:byte(1, 4)) end
  if #b ~= 16 then return nil, "Error in str_to_ip: need 4 or 16 bytes" end
  local g = {}
  for i = 1, 16, 2 do g[#g + 1] = b:byte(i) * 256 + b:byte(i + 1) end
  -- The longest run of two or more zero groups becomes "::".
  local best, best_len, run, run_len = nil, 1, nil, 0
  for i = 1, 8 do
    if g[i] == 0 then
      if not run then run, run_len = i, 0 end
      run_len = run_len + 1
      if run_len > best_len then best, best_len = run, run_len end
    else
      run = nil
    end
  end
  local parts = {}
  local i = 1
  while i <= 8 do
    if i == best then
      parts[#parts + 1] = (i == 1) and ":" or ""
      i = i + best_len
      if i > 8 then parts[#parts + 1] = "" end
    else
      parts[#parts + 1] = string.format("%x", g[i])
      i = i + 1
    end
  end
  return table.concat(parts, ":")
end

ipOps.todword = function(ip)
  local b = v4_bytes(tostring(ip))
  if not b then return nil, "Error in todword: not an IPv4 address" end
  return string.unpack(">I4", b)
end

ipOps.fromdword = function(n)
  return ipOps.str_to_ip(string.pack(">I4", n))
end

-- The address as a string of 32 or 128 "0" and "1" characters.
ipOps.ip_to_bin = function(ip)
  local b, err = ipOps.ip_to_str(ip)
  if not b then return nil, err end
  local bits = {}
  for i = 1, #b do
    local v = b:byte(i)
    for j = 7, 0, -1 do bits[#bits + 1] = (v >> j) & 1 == 1 and "1" or "0" end
  end
  return table.concat(bits)
end

ipOps.bin_to_ip = function(bits)
  if #bits ~= 32 and #bits ~= 128 or bits:find("[^01]") then
    return nil, "Error in bin_to_ip: need 32 or 128 bits"
  end
  local bytes = {}
  for i = 1, #bits, 8 do bytes[#bytes + 1] = string.char(tonumber(bits:sub(i, i + 7), 2)) end
  return ipOps.str_to_ip(table.concat(bytes))
end

ipOps.hex_to_bin = function(hex)
  local bits = {}
  for c in tostring(hex):gmatch("%x") do
    local v = tonumber(c, 16)
    for j = 3, 0, -1 do bits[#bits + 1] = (v >> j) & 1 == 1 and "1" or "0" end
  end
  return table.concat(bits)
end

-- The full form: IPv4 as is; IPv6 as eight four-digit groups.
ipOps.expand_ip = function(ip, family)
  local b = ipOps.ip_to_str(ip)
  if not b then return nil, "Error in expand_ip: not an IP address" end
  if #b == 4 then
    if family == "inet6" then
      return "0000:0000:0000:0000:0000:ffff:" .. string.format("%02x%02x:%02x%02x", b:byte(1, 4))
    end
    return ipOps.str_to_ip(b)
  end
  local g = {}
  for i = 1, 16, 2 do g[#g + 1] = string.format("%02x%02x", b:byte(i), b:byte(i + 1)) end
  return table.concat(g, ":")
end

-- compare_ip(left, "eq"|"ge"|"le"|"gt"|"lt"|"ne", right). An IPv4
-- address sorts before every IPv6 one.
ipOps.compare_ip = function(left, op, right)
  local a, err = ipOps.ip_to_str(left)
  if not a then return nil, err end
  local b
  b, err = ipOps.ip_to_str(right)
  if not b then return nil, err end
  local c
  if #a ~= #b then c = #a < #b and -1 or 1
  elseif a == b then c = 0
  else c = a < b and -1 or 1 end
  local r = ({ eq = c == 0, ne = c ~= 0, lt = c < 0, le = c <= 0, gt = c > 0, ge = c >= 0 })[op]
  if r == nil then return nil, "Error in compare_ip: bad operator " .. tostring(op) end
  return r
end

ipOps.ip_sort = function(list)
  table.sort(list, function(a, b) return ipOps.compare_ip(a, "lt", b) end)
  return list
end

-- First and last address of "a.b.c.d/n", "x::/n" or "first-last".
ipOps.get_ips_from_range = function(range)
  range = tostring(range)
  local first, last = range:match("^%s*(.-)%s*%-%s*(.-)%s*$")
  if first and ipOps.ip_to_str(first) and ipOps.ip_to_str(last) then return first, last end
  local ip, bits = range:match("^%s*(.-)%s*/%s*(%d+)%s*$")
  if not ip then return nil, nil, "Error in get_ips_from_range: bad range " .. range end
  local b = ipOps.ip_to_str(ip)
  bits = tonumber(bits)
  if not b or bits > #b * 8 then
    return nil, nil, "Error in get_ips_from_range: bad range " .. range
  end
  local lo, hi = {}, {}
  for i = 1, #b do
    local keep = math.max(0, math.min(8, bits - (i - 1) * 8))
    local mask = (0xff << (8 - keep)) & 0xff
    lo[i] = string.char(b:byte(i) & mask)
    hi[i] = string.char((b:byte(i) & mask) | (~mask & 0xff))
  end
  return ipOps.str_to_ip(table.concat(lo)), ipOps.str_to_ip(table.concat(hi))
end

ipOps.get_last_ip = function(ip, prefix)
  local _, last, err = ipOps.get_ips_from_range(ip .. "/" .. prefix)
  return last, err
end

ipOps.ip_in_range = function(ip, range)
  local first, last, err = ipOps.get_ips_from_range(range)
  if not first then return nil, err end
  return ipOps.compare_ip(ip, "ge", first) and ipOps.compare_ip(ip, "le", last)
end

local PRIVATE = {
  "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
  "169.254.0.0/16", "100.64.0.0/10", "fc00::/7", "fe80::/10", "::1/128",
}

-- Private, loopback and link-local addresses.
ipOps.isPrivate = function(ip)
  local b = ipOps.ip_to_str(ip)
  if not b then return nil, "Error in isPrivate: not an IP address" end
  for _, r in ipairs(PRIVATE) do
    local first = r:match("^[^/]+")
    if (#b == 4) == (not first:find(":")) and ipOps.ip_in_range(ip, r) then return true end
  end
  return false
end

ipOps.subnet_to_cidr = function(mask)
  local bits = ipOps.ip_to_bin(mask)
  if not bits or bits:find("01") then return nil end
  return #(bits:match("^1*"))
end

return ipOps
