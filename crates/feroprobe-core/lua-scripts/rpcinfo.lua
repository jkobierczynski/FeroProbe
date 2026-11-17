-- FeroProbe script: rpcinfo
-- Written for FeroProbe from scratch (RFC 5531 ONC RPC, RFC 1833
-- portmapper version 2, RFC 4506 XDR); GPL-3.0-or-later.

description = [[
Asks an ONC RPC portmapper (rpcbind, port 111) for the RPC services it
has registered, such as NFS, mountd and the lock manager, with their
versions, protocols and ports: the portmapper's DUMP call, as
"rpcinfo -p" makes it. Over TCP or UDP, as the port was scanned.
The ports it lists are reported, not contacted.

Script arguments:
  rpcinfo.timeout  How long to wait for the answer, in milliseconds
                   (default 10000).
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "default", "discovery", "safe" }

portrule = fero.portrule.match({ 111 }, { "rpcbind", "sunrpc" }, { "tcp", "udp" })

-- Well-known ONC RPC program numbers (from the rpc files of common
-- systems and RFC 5531's registry).
local PROGRAMS = {
  [100000] = "rpcbind", [100001] = "rstatd", [100002] = "rusersd",
  [100003] = "nfs", [100004] = "ypserv", [100005] = "mountd",
  [100007] = "ypbind", [100008] = "walld", [100009] = "yppasswdd",
  [100011] = "rquotad", [100012] = "sprayd", [100021] = "nlockmgr",
  [100024] = "status", [100026] = "bootparam", [100028] = "ypupdated",
  [100069] = "ypxfrd", [100083] = "ttdbserverd", [100099] = "autofs",
  [100133] = "nsm_addrand", [100227] = "nfs_acl", [100232] = "sadmind",
  [100249] = "snmpXdmid", [150001] = "pcnfsd", [300019] = "amd",
  [390113] = "nsrexecd", [391002] = "sgi_fam",
}

local PROTOS = { [6] = "tcp", [17] = "udp" }
local MAX_ENTRIES = 1000

local function call(xid)
  -- xid, CALL, RPC version 2, program 100000 version 2 procedure 4
  -- (DUMP), no credentials, no verifier.
  return string.pack(">I4I4I4I4I4I4I4I4I4I4", xid, 0, 2, 100000, 2, 4, 0, 0, 0, 0)
end

-- The reply body: the record over TCP (its fragments joined), or the
-- datagram over UDP.
local function read_reply(sock, r, udp)
  if udp then
    local ok, data = sock:receive()
    return ok and data or nil
  end
  local out = {}
  for _ = 1, 64 do
    local mark = r:bytes(4)
    if not mark then return nil end
    local n = string.unpack(">I4", mark)
    local frag = r:bytes(n & 0x7fffffff)
    if not frag then return nil end
    out[#out + 1] = frag
    if n & 0x80000000 ~= 0 then return table.concat(out) end
  end
  return nil
end

action = function(host, port)
  local timeout = tonumber(fero.args.get(SCRIPT_NAME .. ".timeout")) or 10000
  local udp = port.protocol == "udp"
  local sock = fero.socket.new()
  sock:set_timeout(timeout)
  if not sock:connect(host, port, port.protocol) then return nil end
  local xid = string.unpack(">I4", fero.crypto.random_bytes(4))
  local msg = call(xid)
  if not udp then msg = string.pack(">I4", 0x80000000 | #msg) .. msg end
  sock:send(msg)
  local body = read_reply(sock, fero.reader(sock), udp)
  sock:close()
  if not body then return nil end
  local ok, rxid, mtype, stat, _, vlen = pcall(string.unpack, ">I4I4I4I4I4", body)
  if not ok or rxid ~= xid or mtype ~= 1 or stat ~= 0 then return nil end
  local pos = 21 + ((vlen + 3) // 4) * 4
  local accept
  ok, accept, pos = pcall(string.unpack, ">I4", body, pos)
  if not ok or accept ~= 0 then return nil end
  -- Group the entries by program, protocol and port, versions joined.
  local groups, order = {}, {}
  for _ = 1, MAX_ENTRIES do
    local more
    ok, more, pos = pcall(string.unpack, ">I4", body, pos)
    if not ok or more == 0 then break end
    local prog, vers, prot, p
    ok, prog, vers, prot, p, pos = pcall(string.unpack, ">I4I4I4I4", body, pos)
    if not ok then break end
    local key = prog .. "/" .. prot .. "/" .. p
    if not groups[key] then
      groups[key] = { prog = prog, proto = PROTOS[prot] or tostring(prot), port = p, versions = {} }
      order[#order + 1] = key
    end
    local g = groups[key]
    g.versions[#g.versions + 1] = vers
  end
  if #order == 0 then return nil end
  table.sort(order, function(a, b)
    local x, y = groups[a], groups[b]
    if x.prog ~= y.prog then return x.prog < y.prog end
    if x.port ~= y.port then return x.port < y.port end
    return x.proto < y.proto -- tcp before udp
  end)
  local data = {}
  local lines = { string.format("%-8s %-12s %-11s %s", "program", "version", "port/proto", "service") }
  for _, key in ipairs(order) do
    local g = groups[key]
    table.sort(g.versions)
    local versions = {}
    for i, v in ipairs(g.versions) do versions[i] = tostring(v) end
    local name = PROGRAMS[g.prog] or ""
    local vtext = table.concat(versions, ",")
    data[#data + 1] = {
      program = tostring(g.prog), version = vtext, port = tostring(g.port),
      protocol = g.proto, service = name,
    }
    lines[#lines + 1] = string.format("%-8d %-12s %5d/%-5s %s", g.prog, vtext, g.port, g.proto, name)
  end
  return data, "\n  " .. table.concat(lines, "\n  ")
end
