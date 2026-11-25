-- NSE compatibility layer: the `dns` module, DNS queries and updates.
-- Written for FeroProbe from nmap's public API documentation and the DNS
-- RFCs (1035, 2136, 3596, 4034, 5155, 5001, 6891, 7871); not from nselib.
-- GPL-3.0-or-later, like FeroProbe.
--
-- Queries go out through nmap.new_socket, so they reach only what the
-- script's scope allows: the scanned host on the ports the scan probed,
-- and the run's DNS servers (--dns-servers, or the system's) on their
-- DNS port. Referrals to other servers are not followed. Every packet
-- carries the transaction ID 0x4650 ("FP") unless the script sets its
-- own, the mark IDS rules 9100032 (UDP) and 9100033 (TCP) look for.
local fero = ...
local nmap = require "nmap"
local ipOps = require "ipOps"
local base32 = require "base32"
local dns = {}

-- The FeroProbe mark: "FP" as the transaction ID.
local ID = 0x4650

-- Record types (IANA DNS parameters).
dns.types = {
  A = 1, NS = 2, MD = 3, MF = 4, CNAME = 5, SOA = 6, MB = 7, MG = 8, MR = 9, NULL = 10,
  WKS = 11, PTR = 12, HINFO = 13, MINFO = 14, MX = 15, TXT = 16, RP = 17, AFSDB = 18,
  X25 = 19, ISDN = 20, RT = 21, NSAP = 22, ["NSAP-PTR"] = 23, SIG = 24, KEY = 25, PX = 26,
  GPOS = 27, AAAA = 28, LOC = 29, NXT = 30, EID = 31, NIMLOC = 32, SRV = 33, ATMA = 34,
  NAPTR = 35, KX = 36, CERT = 37, A6 = 38, DNAME = 39, SINK = 40, OPT = 41, APL = 42,
  DS = 43, SSHFP = 44, IPSECKEY = 45, RRSIG = 46, NSEC = 47, DNSKEY = 48, DHCID = 49,
  NSEC3 = 50, NSEC3PARAM = 51, TLSA = 52, SMIMEA = 53, HIP = 55, CDS = 59, CDNSKEY = 60,
  OPENPGPKEY = 61, CSYNC = 62, ZONEMD = 63, SVCB = 64, HTTPS = 65, SPF = 99, TKEY = 249,
  TSIG = 250, IXFR = 251, AXFR = 252, MAILB = 253, MAILA = 254, ANY = 255, URI = 256,
  CAA = 257,
}

dns.CLASS = { IN = 1, CS = 2, CH = 3, HS = 4, NONE = 254, ANY = 255 }

local TYPE_NAME = {}
for k, v in pairs(dns.types) do TYPE_NAME[v] = k end

local RCODE_NAME = {
  [1] = "Format Error", [2] = "Server Failure", [3] = "No Such Name", [4] = "Not Implemented",
  [5] = "Refused", [6] = "Name Exists", [7] = "RRset Exists", [8] = "RRset Does Not Exist",
  [9] = "Not Authoritative", [10] = "Not in Zone",
}

local function type_number(t)
  if type(t) == "number" then return t end
  if type(t) == "string" then return dns.types[t:upper()] or tonumber(t) end
  return nil
end

-- Header flags, most significant bit first (RFC 1035 4.1.1, RFC 4035).
local FLAGS = { "QR", "OC1", "OC2", "OC3", "OC4", "AA", "TC", "RD", "RA", "Z", "AD", "CD",
  "RC1", "RC2", "RC3", "RC4" }

local function encode_flags(f)
  if type(f) == "number" then return f & 0xffff end
  local v = 0
  for i, name in ipairs(FLAGS) do
    if f and f[name] then v = v | (1 << (16 - i)) end
  end
  return v
end

local function decode_flags(v)
  local f = {}
  for i, name in ipairs(FLAGS) do f[name] = (v >> (16 - i)) & 1 == 1 end
  return f
end

local function rcode(pkt)
  local f = pkt.flags or {}
  return (f.RC1 and 8 or 0) + (f.RC2 and 4 or 0) + (f.RC3 and 2 or 0) + (f.RC4 and 1 or 0)
end

-- A name in wire form (no compression). "" and "." are the root.
local function encode_name(name)
  name = tostring(name or "")
  local out = {}
  for label in name:gmatch("[^%.]+") do
    if #label > 63 then error("DNS label longer than 63 bytes: " .. label, 0) end
    out[#out + 1] = string.pack("s1", label)
  end
  out[#out + 1] = "\0"
  return table.concat(out)
end

---
-- dns.decStr(data, pos): reads the (possibly compressed) name at pos;
-- returns the position after it and the name, labels joined by ".".
function dns.decStr(data, pos)
  pos = pos or 1
  local labels = {}
  local after
  local jumps = 0
  while true do
    local len = data:byte(pos)
    if not len then return nil end
    if len == 0 then
      pos = pos + 1
      break
    elseif len & 0xc0 == 0xc0 then
      local lo = data:byte(pos + 1)
      if not lo then return nil end
      after = after or pos + 2
      jumps = jumps + 1
      if jumps > 64 then return nil end
      pos = ((len & 0x3f) << 8 | lo) + 1
    elseif len & 0xc0 ~= 0 then
      return nil
    else
      if pos + len > #data then return nil end
      labels[#labels + 1] = data:sub(pos + 1, pos + len)
      pos = pos + 1 + len
    end
  end
  return after or pos, table.concat(labels, ".")
end

-- Type numbers in an NSEC/NSEC3 type bitmap (RFC 4034 4.1.2).
local function decode_bitmap(data, pos, stop)
  local types = {}
  while pos + 1 <= stop do
    local window, len = data:byte(pos), data:byte(pos + 1)
    pos = pos + 2
    for i = 0, len - 1 do
      local b = data:byte(pos + i) or 0
      for bit = 0, 7 do
        if b & (0x80 >> bit) ~= 0 then types[#types + 1] = window * 256 + i * 8 + bit end
      end
    end
    pos = pos + len
  end
  return types
end

local function hex(s)
  return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

-- Type-specific fields of a record, read from its rdata at rpos..rend in
-- the whole message (names may point back into it).
local function decode_rdata(rec, data, rpos, rend)
  local t = rec.dtype
  local rd = rec.data
  if t == dns.types.A and #rd == 4 then
    rec.ip = ipOps.str_to_ip(rd)
  elseif t == dns.types.AAAA and #rd == 16 then
    rec.ipv6 = ipOps.str_to_ip(rd)
  elseif t == dns.types.NS or t == dns.types.CNAME or t == dns.types.PTR
    or t == dns.types.DNAME or t == dns.types.MB or t == dns.types.MD
    or t == dns.types.MF or t == dns.types.MG or t == dns.types.MR then
    local _, name = dns.decStr(data, rpos)
    rec.domain = name
  elseif t == dns.types.MX then
    local pref = string.unpack(">I2", data, rpos)
    local _, server = dns.decStr(data, rpos + 2)
    rec.MX = { pref = pref, server = server }
  elseif t == dns.types.SRV then
    local prio, weight, port = string.unpack(">I2I2I2", data, rpos)
    local _, target = dns.decStr(data, rpos + 6)
    rec.SRV = { prio = prio, weight = weight, port = port, target = target }
  elseif t == dns.types.SOA then
    local p, mname = dns.decStr(data, rpos)
    local p2, rname = dns.decStr(data, p)
    local serial, refresh, retry, expire, minimum = string.unpack(">I4I4I4I4I4", data, p2)
    rec.SOA = { mname = mname, rname = rname, serial = serial, refresh = refresh,
      retry = retry, expire = expire, minimum = minimum }
  elseif t == dns.types.TXT or t == dns.types.SPF then
    local text, p = {}, 1
    while p <= #rd do
      local s
      s, p = string.unpack("s1", rd, p)
      text[#text + 1] = s
    end
    rec.TXT = { text = text }
  elseif t == dns.types.HINFO then
    local cpu, p = string.unpack("s1", rd)
    local os_ = string.unpack("s1", rd, p)
    rec.HINFO = { cpu = cpu, os = os_ }
  elseif t == dns.types.NSEC then
    local p, next_dname = dns.decStr(data, rpos)
    rec.NSEC = { dname = rec.dname, next_dname = next_dname,
      types = decode_bitmap(data, p, rend) }
  elseif t == dns.types.NSEC3 then
    local alg, flags, iterations, salt, p = string.unpack(">BBI2s1", rd)
    local nexthash
    nexthash, p = string.unpack("s1", rd, p)
    rec.NSEC3 = {
      dname = rec.dname, flags = flags, iterations = iterations,
      salt = { bin = salt, hex = hex(salt) },
      hash = { alg = alg, bin = nexthash, base32 = base32.enc(nexthash, true):gsub("=", "") },
      types = decode_bitmap(rd, p, #rd),
    }
  elseif t == dns.types.NSEC3PARAM then
    local alg, flags, iterations, salt = string.unpack(">BBI2s1", rd)
    rec.NSEC3PARAM = { alg = alg, flags = flags, iterations = iterations,
      salt = { bin = salt, hex = hex(salt) } }
  elseif t == dns.types.DNSKEY then
    local flags, protocol, algorithm, p = string.unpack(">I2BB", rd)
    rec.DNSKEY = { flags = flags, protocol = protocol, algorithm = algorithm, key = rd:sub(p) }
  elseif t == dns.types.DS then
    local key_tag, algorithm, digest_type, p = string.unpack(">I2BB", rd)
    rec.DS = { key_tag = key_tag, algorithm = algorithm, digest_type = digest_type,
      digest = rd:sub(p) }
  elseif t == dns.types.OPT then
    local options, p = {}, 1
    while p + 3 <= #rd do
      local code, data_
      code, data_, p = string.unpack(">I2s2", rd, p)
      options[#options + 1] = { code = code, data = data_ }
    end
    rec.OPT = { bufsize = rec.class, rcode = (rec.ttl >> 24) & 0xff,
      version = (rec.ttl >> 16) & 0xff, zflags = rec.ttl & 0xffff,
      DO = rec.ttl & 0x8000 ~= 0, options = options }
  end
end

local function decode_rr(data, pos, question)
  local p, name = dns.decStr(data, pos)
  if not p then error("bad name", 0) end
  local dtype, class = string.unpack(">I2I2", data, p)
  if question then
    return { dname = name, dtype = dtype, class = class }, p + 4
  end
  local ttl, rdlen = string.unpack(">I4I2", data, p + 4)
  local rpos = p + 10
  if rpos + rdlen - 1 > #data then error("truncated record", 0) end
  local rec = { dname = name, dtype = dtype, class = class, ttl = ttl,
    data = data:sub(rpos, rpos + rdlen - 1) }
  pcall(decode_rdata, rec, data, rpos, rpos + rdlen - 1)
  return rec, rpos + rdlen
end

---
-- dns.decode(data): the message as a packet table: id, flags (QR, OC1-4,
-- AA, TC, RD, RA, Z, AD, CD, RC1-4), questions, answers, auth, add.
function dns.decode(data)
  if type(data) ~= "string" or #data < 12 then return nil end
  local ok, pkt = pcall(function()
    local id, flags, qd, an, ns, ar, pos = string.unpack(">I2I2I2I2I2I2", data)
    local pkt = { id = id, flags = decode_flags(flags), questions = {}, answers = {},
      auth = {}, add = {} }
    local sections = { { pkt.questions, qd, true }, { pkt.answers, an }, { pkt.auth, ns },
      { pkt.add, ar } }
    for _, s in ipairs(sections) do
      for _ = 1, s[2] do
        local rec
        rec, pos = decode_rr(data, pos, s[3])
        s[1][#s[1] + 1] = rec
      end
    end
    return pkt
  end)
  if ok then return pkt end
  return nil
end

---
-- dns.newPacket(): an empty packet table to fill and encode.
function dns.newPacket()
  return { id = ID, flags = {}, questions = {}, answers = {}, auth = {}, add = {},
    zones = {}, updates = {} }
end

function dns.addQuestion(pkt, dname, dtype, class)
  pkt.questions = pkt.questions or {}
  pkt.questions[#pkt.questions + 1] = { dname = dname, dtype = type_number(dtype) or dtype,
    class = class or dns.CLASS.IN }
  return pkt
end

function dns.addZone(pkt, dname)
  pkt.zones = pkt.zones or {}
  pkt.zones[#pkt.zones + 1] = { dname = dname, dtype = dns.types.SOA, class = dns.CLASS.IN }
  return pkt
end

function dns.addUpdate(pkt, dname, dtype, ttl, data, class)
  pkt.updates = pkt.updates or {}
  pkt.updates[#pkt.updates + 1] = { dname = dname, dtype = type_number(dtype) or dtype,
    ttl = ttl or 0, data = data or "", class = class or dns.CLASS.IN }
  return pkt
end

---
-- dns.addOPT(pkt, Z, opt): adds an EDNS0 OPT record (RFC 6891), or adds
-- to the one there: Z.DO sets the DNSSEC OK bit; opt = { code =, data = }
-- is an option for it.
function dns.addOPT(pkt, Z, opt)
  pkt.add = pkt.add or {}
  local rec
  for _, r in ipairs(pkt.add) do
    if r.dtype == dns.types.OPT then rec = r end
  end
  if not rec then
    rec = { dname = "", dtype = dns.types.OPT, class = 4096, ttl = 0, data = "" }
    pkt.add[#pkt.add + 1] = rec
  end
  if Z and Z.DO then rec.ttl = rec.ttl | 0x8000 end
  if opt and opt.code then
    rec.data = rec.data .. string.pack(">I2s2", opt.code, opt.data or "")
  end
  return pkt
end

-- dns.addNSID(pkt, Z): asks for the server's NSID (RFC 5001).
function dns.addNSID(pkt, Z)
  return dns.addOPT(pkt, Z, { code = 3, data = "" })
end

-- dns.addClientSubnet(pkt, Z, subnet): an EDNS client subnet (RFC 7871);
-- subnet = { family = "inet" | "inet6" | 1 | 2, address =, mask = }.
function dns.addClientSubnet(pkt, Z, subnet)
  subnet = subnet or {}
  local family = subnet.family
  if family == "inet" or family == nil then family = 1
  elseif family == "inet6" then family = 2 end
  local bytes = ipOps.ip_to_str(subnet.address or "") or ""
  if family == 2 and #bytes == 4 then family = 1 end
  if family == 1 and #bytes == 16 then family = 2 end
  local mask = tonumber(subnet.mask) or #bytes * 8
  bytes = bytes:sub(1, (mask + 7) // 8)
  return dns.addOPT(pkt, Z, { code = 8, data = string.pack(">I2BB", family, mask, 0) .. bytes })
end

local function encode_rr(r)
  local data = r.data or ""
  return encode_name(r.dname) .. string.pack(">I2I2I4s2", type_number(r.dtype) or 0,
    r.class or dns.CLASS.IN, r.ttl or 0, data)
end

---
-- dns.encode(pkt): the packet in wire form. A packet with zones is an
-- update (RFC 2136): zones, then updates; otherwise questions. The
-- additional section is written in both (answers and authority are not).
function dns.encode(pkt)
  local out = {}
  local update = pkt.zones and #pkt.zones > 0
  local add = pkt.add or {}
  if update then
    out[1] = string.pack(">I2I2I2I2I2I2", pkt.id or ID, encode_flags(pkt.flags),
      #pkt.zones, 0, #(pkt.updates or {}), #add)
    for _, z in ipairs(pkt.zones) do
      out[#out + 1] = encode_name(z.dname) .. string.pack(">I2I2", dns.types.SOA,
        z.class or dns.CLASS.IN)
    end
    for _, u in ipairs(pkt.updates or {}) do out[#out + 1] = encode_rr(u) end
  else
    local qs = pkt.questions or {}
    out[1] = string.pack(">I2I2I2I2I2I2", pkt.id or ID, encode_flags(pkt.flags), #qs, 0, 0, #add)
    for _, q in ipairs(qs) do
      out[#out + 1] = encode_name(q.dname) .. string.pack(">I2I2",
        type_number(q.dtype) or dns.types.A, q.class or dns.CLASS.IN)
    end
  end
  for _, r in ipairs(add) do out[#out + 1] = encode_rr(r) end
  return table.concat(out)
end

-- Reads one DNS message over TCP (two-byte length first).
local function tcp_receive(s)
  local buf = ""
  while true do
    if #buf >= 2 then
      local len = string.unpack(">I2", buf)
      if #buf >= 2 + len then return true, buf:sub(3, 2 + len) end
    end
    local ok, more = s:receive()
    if not ok then return false, more end
    buf = buf .. more
  end
end

---
-- dns.sendPackets(data, host, port, timeout, cnt, multiple, proto): sends
-- data up to cnt times until a reply comes; true and { { data =, peer = } }
-- (every reply until the timeout with multiple), or false and an error.
function dns.sendPackets(data, host, port, timeout, cnt, multiple, proto)
  if type(host) == "table" then host = host.ip end
  if type(port) == "table" then port = port.number end
  proto = proto or "udp"
  timeout = tonumber(timeout) or 3000
  -- A server given by name is looked up first, as nmap's sockets do; its
  -- address must still be in the script's scope.
  if type(host) == "string" and not ipOps.ip_to_str(host) then
    local ok, addrs = nmap.resolve(host, nmap.address_family())
    if not ok or #addrs == 0 then return false, "Failed to resolve " .. host end
    host = addrs[1]
  end
  local err = "TIMEOUT"
  for _ = 1, math.max(1, tonumber(cnt) or 1) do
    local s = nmap.new_socket(proto)
    s:set_timeout(timeout)
    local ok, e = s:connect(host, port, proto)
    if not ok then
      s:close()
      return false, e
    end
    local reply
    if proto == "tcp" then
      ok, e = s:send(string.pack(">s2", data))
      if ok then ok, reply = tcp_receive(s) end
    else
      ok, e = s:send(data)
      if ok then ok, reply = s:receive() end
    end
    if ok then
      local replies = { { data = reply, peer = host } }
      while multiple do
        local more_ok, more = s:receive()
        if not more_ok then break end
        replies[#replies + 1] = { data = more, peer = host }
      end
      s:close()
      return true, replies
    end
    s:close()
    err = e or reply or err
    if proto == "tcp" then break end
  end
  return false, err
end

-- The nice answer of one record of type dtype, or nil.
local function nice(rec, dtype)
  if dtype == dns.types.A then return rec.ip
  elseif dtype == dns.types.AAAA then return rec.ipv6
  elseif dtype == dns.types.MX and rec.MX then
    return ("%d:%s"):format(rec.MX.pref, rec.MX.server)
  elseif dtype == dns.types.SRV and rec.SRV then
    local s = rec.SRV
    return ("%d:%d:%d:%s"):format(s.prio, s.weight, s.port, s.target)
  elseif rec.domain then return rec.domain
  elseif rec.SOA then return rec.SOA.mname
  end
  return rec.data
end

local function nice_from(section, dtype, pkt, retAll)
  dtype = type_number(dtype)
  if type(pkt) ~= "table" or type(pkt[section]) ~= "table" then
    return false, "Unable to handle response"
  end
  if #pkt[section] == 0 then
    if pkt.flags and rcode(pkt) == 3 then return false, "No Such Name" end
    return false, "No Answers"
  end
  local out = {}
  for _, rec in ipairs(pkt[section]) do
    if rec.dtype == dtype then
      if rec.TXT then
        for _, s in ipairs(rec.TXT.text) do out[#out + 1] = s end
      else
        local v = nice(rec, dtype)
        if v then out[#out + 1] = v end
      end
      if not retAll and #out > 0 then return true, out[1] end
    end
  end
  if #out == 0 then return false, "No Answers" end
  return true, out
end

---
-- dns.findNiceAnswer(dtype, pkt, retAll): the answers of type dtype in
-- pkt, in a simple form (an address, a name, the TXT strings, "pref:server"
-- for MX, "prio:weight:port:target" for SRV); the first, or all with retAll.
function dns.findNiceAnswer(dtype, pkt, retAll)
  return nice_from("answers", dtype, pkt, retAll)
end

-- dns.findNiceAdditional(dtype, pkt, retAll): the same for the additional
-- section.
function dns.findNiceAdditional(dtype, pkt, retAll)
  return nice_from("add", dtype, pkt, retAll)
end

-- The server to use when a script names none: the run's first DNS server.
local function default_server()
  local list = fero.dns_servers and fero.dns_servers() or {}
  if #list == 0 then return nil end
  return list[1].ip, list[1].port
end

-- Sends pkt and decodes the reply; over TCP again when a UDP reply is
-- truncated.
local function exchange(pkt, host, port, proto, timeout, cnt, multiple)
  local data = dns.encode(pkt)
  local ok, replies = dns.sendPackets(data, host, port, timeout, cnt, multiple, proto)
  if not ok then return false, replies end
  local out = {}
  for _, r in ipairs(replies) do
    local d = dns.decode(r.data)
    if d and d.id == (pkt.id or ID) and d.flags.QR then
      if d.flags.TC and proto ~= "tcp" and not multiple then
        return exchange(pkt, host, port, "tcp", timeout, 1, false)
      end
      out[#out + 1] = { pkt = d, peer = r.peer }
    end
  end
  if #out == 0 then return false, "Unable to handle response" end
  return true, out
end

---
-- dns.query(dname, options): looks up dname. Options: dtype (default
-- "A"), host and port (default the run's first DNS server), proto or
-- protocol ("udp" or "tcp"), class, timeout (ms), sendCount or tries,
-- norecurse, dnssec, nsid, subnet, flags, id, retAll, retPkt, multiple.
-- true and the answer (see findNiceAnswer; the decoded packet with
-- retPkt), or false and "No Servers", "No Such Name", "No Answers", ...
function dns.query(dname, options)
  options = options or {}
  local dtype = type_number(options.dtype or "A")
  if not dtype then return false, "Unknown record type" end
  local host, port = options.host, options.port
  if type(host) == "table" then host = host.ip end
  if type(port) == "table" then port = port.number end
  if not host then
    local p
    host, p = default_server()
    if not host then return false, "No Servers" end
    port = port or p
  end
  port = tonumber(port) or 53
  local proto = options.proto or options.protocol or "udp"
  local timeout = tonumber(options.timeout) or 3000
  local cnt = tonumber(options.sendCount) or (options.tries and math.max(1, tonumber(options.tries) or 1)) or 2

  local pkt = dns.newPacket()
  if options.id then pkt.id = options.id end
  if options.flags then
    pkt.flags = options.flags
  else
    pkt.flags.RD = not options.norecurse
  end
  dns.addQuestion(pkt, dname, dtype, options.class or dns.CLASS.IN)
  local Z = options.dnssec and { DO = true } or nil
  if options.dnssec then dns.addOPT(pkt, Z) end
  if options.nsid then dns.addNSID(pkt, Z) end
  if options.subnet then dns.addClientSubnet(pkt, Z, options.subnet) end

  local ok, replies = exchange(pkt, host, port, proto, timeout, cnt, options.multiple)
  if not ok then return false, replies end
  if options.multiple then
    local out = {}
    for _, r in ipairs(replies) do
      if options.retPkt then
        out[#out + 1] = { peer = r.peer, output = r.pkt }
      else
        local s, a = dns.findNiceAnswer(dtype, r.pkt, options.retAll)
        if s then out[#out + 1] = { peer = r.peer, output = a } end
      end
    end
    return #out > 0, #out > 0 and out or "No Answers"
  end
  local reply = replies[1].pkt
  if options.retPkt then return true, reply end
  return dns.findNiceAnswer(dtype, reply, options.retAll)
end

---
-- dns.reverse(ip): the name to look up for ip's PTR record
-- (in-addr.arpa or ip6.arpa).
function dns.reverse(ip)
  local bytes = ipOps.ip_to_str(tostring(ip or ""))
  if not bytes then return ip end
  local parts = {}
  if #bytes == 4 then
    for i = 4, 1, -1 do parts[#parts + 1] = tostring(bytes:byte(i)) end
    return table.concat(parts, ".") .. ".in-addr.arpa"
  end
  for i = #bytes, 1, -1 do
    local b = bytes:byte(i)
    parts[#parts + 1] = string.format("%x", b & 0x0f)
    parts[#parts + 1] = string.format("%x", b >> 4)
  end
  return table.concat(parts, ".") .. ".ip6.arpa"
end

-- The rdata of an update record.
local function update_rdata(dtype, data)
  if type(data) == "table" then
    if dtype == dns.types.MX then
      return string.pack(">I2", tonumber(data.pref) or 0) .. encode_name(data.mx or data.server)
    elseif dtype == dns.types.SRV then
      return string.pack(">I2I2I2", tonumber(data.prio) or 0, tonumber(data.weight) or 0,
        tonumber(data.port) or 0) .. encode_name(data.target)
    end
    return ""
  end
  data = tostring(data or "")
  if dtype == dns.types.A or dtype == dns.types.AAAA then
    return ipOps.ip_to_str(data) or ""
  elseif dtype == dns.types.TXT or dtype == dns.types.SPF then
    return string.pack("s1", data:sub(1, 255))
  elseif dtype == dns.types.CNAME or dtype == dns.types.NS or dtype == dns.types.PTR
    or dtype == dns.types.DNAME then
    return encode_name(data)
  end
  return data
end

---
-- dns.update(dname, options): a dynamic update (RFC 2136) adding a record
-- for dname (options: host, port, dtype, data, ttl, zone, timeout); data
-- "" with ttl 0 deletes the RRset. The zone is options.zone (dname is then
-- relative to it) or dname without its first label. true, or false and
-- the server's error.
function dns.update(dname, options)
  options = options or {}
  local host, port = options.host, options.port
  if type(host) == "table" then host = host.ip end
  if type(port) == "table" then port = port.number end
  if not host then return false, "No Servers" end
  local dtype = type_number(options.dtype or "A")
  if not dtype then return false, "Unknown record type" end
  local zone = options.zone
  if zone then
    if not dname:lower():find("%." .. zone:lower():gsub("%p", "%%%0") .. "$") then
      dname = dname .. "." .. zone
    end
  else
    zone = dname:match("^[^%.]+%.(.+)$") or dname
  end
  local pkt = dns.newPacket()
  pkt.flags = { OC2 = true, OC4 = true } -- opcode 5, UPDATE
  dns.addZone(pkt, zone)
  local ttl = options.ttl or 86400
  if options.data == "" and ttl == 0 then
    dns.addUpdate(pkt, dname, dtype, 0, "", dns.CLASS.ANY)
  else
    dns.addUpdate(pkt, dname, dtype, ttl, update_rdata(dtype, options.data))
  end
  local ok, replies = exchange(pkt, host, tonumber(port) or 53, options.proto or "udp",
    tonumber(options.timeout) or 3000, 2, false)
  if not ok then return false, replies end
  local rc = rcode(replies[1].pkt)
  if rc == 0 then return true end
  return false, RCODE_NAME[rc] or ("Error " .. rc)
end

return dns
