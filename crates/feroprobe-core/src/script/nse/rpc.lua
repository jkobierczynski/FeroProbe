-- NSE compatibility layer: the `rpc` module, ONC RPC over TCP and UDP
-- with the portmapper, mountd and NFS versions 2 and 3. Written for
-- FeroProbe from nmap's public API documentation and RFC 5531 (RPC),
-- RFC 4506 (XDR), RFC 1833 (portmapper/rpcbind), RFC 1094 (NFS v2 and
-- mount v1) and RFC 1813 (NFS v3 and mount v3); not from nselib.
-- GPL-3.0-or-later, like FeroProbe.
--
-- A call FeroProbe numbers itself has transaction ID "FP" and 16 random
-- bits (0x4650xxxx, IDS rules 9100036 UDP and 9100037 TCP); a script that
-- passes its own XID sends that one. Portmapper calls carry no
-- credentials (AUTH_NULL); mountd and NFS calls carry AUTH_UNIX as user
-- and group nobody (65534) from machine "feroprobe", never root.
-- Every connection goes through nmap.new_socket, so the mountd and NFS
-- ports the portmapper names are reached only when they were scanned. No
-- reserved source port is bound, so a server that insists on one (the
-- Linux NFS server's `secure` export option) refuses MNT and NFS calls.
local fero = ...
local nmap = require "nmap"
local stdnse = require "stdnse"
local datafiles = require "datafiles"

local rpc = {}

local MAX_RECORD = 4 * 1024 * 1024
local MAX_FRAGMENTS = 1024
local XID_MARK = 0x4650

---------------------------------------------------------------------------
-- Program versions the library speaks (Comm:Connect refuses others while
-- version checks are on). A script may add its own, as rusers does.
rpc.RPC_version = {
  rpcbind = { min = 2, max = 4 },
  portmapper = { min = 2, max = 4 },
  mountd = { min = 1, max = 3 },
  nfs = { min = 2, max = 3 },
}

-- Program numbers known without nmap-rpc (RFC 5531's assigned numbers
-- and those of common systems).
local KNOWN_PROGRAMS = {
  rpcbind = 100000, rstatd = 100001, rusersd = 100002, nfs = 100003,
  ypserv = 100004, mountd = 100005, ypbind = 100007, walld = 100008,
  yppasswdd = 100009, rquotad = 100011, sprayd = 100012, nlockmgr = 100021,
  status = 100024, bootparam = 100026, ypupdated = 100028, ypxfrd = 100069,
  ttdbserverd = 100083, autofs = 100099, nfs_acl = 100227, sadmind = 100232,
  pcnfsd = 150001, amd = 300019, nsrexecd = 390113, nsrd = 390103,
  sgi_fam = 391002, wdb = 0x55555555,
}

---------------------------------------------------------------------------
-- Util: XDR and conversions.
local Util = {}
rpc.Util = Util

local function pad4(n) return (4 - n % 4) % 4 end

function Util.marshall_uint32(n) return string.pack(">I4", math.floor(n) & 0xffffffff) end
function Util.marshall_int32(n) return string.pack(">i4", math.floor(n)) end
function Util.marshall_uint64(n) return string.pack(">I8", math.floor(n)) end
function Util.marshall_int64(n) return string.pack(">i8", math.floor(n)) end
function Util.marshall_boolean(b) return Util.marshall_uint32(b and 1 or 0) end
-- Fixed-length opaque data: the bytes, padded to four.
function Util.marshall_opaque(s) return s .. string.rep("\0", pad4(#s)) end
-- Variable-length opaque data or a string: length, bytes, padding.
function Util.marshall_vopaque(s)
  s = s or ""
  return Util.marshall_uint32(#s) .. Util.marshall_opaque(s)
end

---
-- Util.unmarshall_uint32(data, pos): the position after it and the value
-- (nil when data ends first).
function Util.unmarshall_uint32(data, pos)
  if not data or #data < pos + 3 then return pos, nil end
  return pos + 4, (string.unpack(">I4", data, pos))
end
Util.unmarshall_uint = Util.unmarshall_uint32

function Util.unmarshall_int32(data, pos)
  if not data or #data < pos + 3 then return pos, nil end
  return pos + 4, (string.unpack(">i4", data, pos))
end

-- A 64-bit unsigned value; one above 2^63 comes back as a float.
function Util.unmarshall_uint64(data, pos)
  if not data or #data < pos + 7 then return pos, nil end
  local v = string.unpack(">i8", data, pos)
  if v < 0 then v = v + 18446744073709551616.0 end
  return pos + 8, v
end

function Util.unmarshall_int64(data, pos)
  if not data or #data < pos + 7 then return pos, nil end
  return pos + 8, (string.unpack(">i8", data, pos))
end

---
-- Util.unmarshall_opaque(len, data, pos): the position after len bytes
-- and their padding, and the bytes.
function Util.unmarshall_opaque(len, data, pos)
  len = len or 0
  local s = data:sub(pos, pos + len - 1)
  return pos + len + pad4(len), s
end
Util.unmarshall_vopaque = Util.unmarshall_opaque

-- A length-prefixed string or opaque: position after it and the bytes.
local function vopaque(data, pos)
  local p, len = Util.unmarshall_uint32(data, pos)
  if not len or #data < p + len - 1 then return pos, nil end
  return Util.unmarshall_opaque(len, data, p)
end
Util.unmarshall_string = vopaque

local function boolean(data, pos)
  local p, v = Util.unmarshall_uint32(data, pos)
  if v == nil then return pos, nil end
  return p, v ~= 0
end

local rpc_names -- name -> number, from nmap-rpc and the list above
local rpc_numbers -- number -> name

local function load_programs()
  if rpc_names then return end
  rpc_names, rpc_numbers = {}, {}
  for name, num in pairs(KNOWN_PROGRAMS) do
    rpc_names[name] = num
    rpc_numbers[num] = rpc_numbers[num] or name
  end
  local ok, t = datafiles.parse_rpc()
  if ok and type(t) == "table" then
    for num, name in pairs(t) do
      rpc_numbers[num] = name
      rpc_names[name] = rpc_names[name] or num
    end
  end
  rpc_names.portmapper = rpc_names.portmapper or 100000
  rpc_names.portmap = rpc_names.portmap or 100000
  rpc_names.rpcbind = 100000
end

---
-- Util.ProgNameToNumber(prog_name): the program number, or nil.
function Util.ProgNameToNumber(name)
  load_programs()
  return rpc_names[name]
end

---
-- Util.ProgNumberToName(num): the program's name, or nil.
function Util.ProgNumberToName(num)
  load_programs()
  return rpc_numbers[tonumber(num)]
end

-- File types: XDR ftype numbers (RFC 1813; RFC 1094's agree up to 5)
-- and the mode bits each stands for.
local FTYPE_BITS = { [1] = 0x8000, [2] = 0x4000, [3] = 0x6000, [4] = 0x2000,
  [5] = 0xa000, [6] = 0xc000, [7] = 0x1000, [8] = 0x1000 }
local TYPE_CHAR = { [0x8000] = "-", [0x4000] = "d", [0x6000] = "b", [0x2000] = "c",
  [0xa000] = "l", [0xc000] = "s", [0x1000] = "p" }
local TYPE_NAME = { [0x8000] = "file", [0x4000] = "directory", [0x6000] = "block device",
  [0x2000] = "char device", [0xa000] = "symlink", [0xc000] = "socket", [0x1000] = "fifo" }

---
-- Util.FtypeToChar(mode): the ls type character of a mode ("d", "-",
-- "l", ...; "?" when unknown).
function Util.FtypeToChar(mode)
  return TYPE_CHAR[(tonumber(mode) or 0) & 0xf000] or "?"
end

---
-- Util.FtypeToString(mode): the file type's name ("directory", "file", ...).
function Util.FtypeToString(mode)
  return TYPE_NAME[(tonumber(mode) or 0) & 0xf000] or "unknown"
end

---
-- Util.FpermToString(mode): the permission bits as ls shows them
-- ("rwxr-xr-x", with s/S and t/T for set-ID and sticky bits).
function Util.FpermToString(mode)
  mode = tonumber(mode) or 0
  local out = {}
  local function triple(shift, special, on, off)
    local b = (mode >> shift) & 7
    out[#out + 1] = (b & 4 ~= 0) and "r" or "-"
    out[#out + 1] = (b & 2 ~= 0) and "w" or "-"
    local x = b & 1 ~= 0
    if mode & special ~= 0 then
      out[#out + 1] = x and on or off
    else
      out[#out + 1] = x and "x" or "-"
    end
  end
  triple(6, 0x800, "s", "S")
  triple(3, 0x400, "s", "S")
  triple(0, 0x200, "t", "T")
  return table.concat(out)
end

---
-- Util.FmodeToOctalString(mode): the permission bits in octal ("0755").
function Util.FmodeToOctalString(mode)
  return string.format("%04o", (tonumber(mode) or 0) & 0xfff)
end

local function num2str(n)
  if math.type(n) == "float" then return string.format("%.0f", n) end
  return tostring(n)
end

---
-- Util.SizeToHuman(size, blocksize): a size with a K, M, G, T or P suffix
-- ("883.6M"), in steps of blocksize (1024, or 1000).
function Util.SizeToHuman(size, blocksize)
  local bs = tonumber(blocksize) or 1024
  local s = tonumber(size) or 0
  local units = { "B", "K", "M", "G", "T", "P" }
  local i = 1
  while s > bs and i < #units do
    s = s / bs
    i = i + 1
  end
  return string.format("%.1f%s", s, units[i])
end

---
-- Util.TimeToString(seconds): a file time as nfs-ls shows it
-- ("2026-11-26T13:54:24", UTC, as nmap 7.95's nfs-ls prints it).
function Util.TimeToString(seconds)
  return os.date("!%Y-%m-%dT%H:%M:%S", math.floor(tonumber(seconds) or 0))
end

-- NFSv3 ACCESS bits (RFC 1813 3.3.4).
local ACCESS = { { 0x01, "Read" }, { 0x02, "Lookup" }, { 0x04, "Modify" },
  { 0x08, "Extend" }, { 0x10, "Delete" }, { 0x20, "Execute" } }

---
-- Util.format_access(mask, version): the NFSv3 access rights granted, as
-- "Read Lookup NoModify NoExtend NoDelete NoExecute".
function Util.format_access(mask, version)
  if tonumber(version) ~= 3 then return "" end
  mask = tonumber(mask) or 0
  local out = {}
  for _, a in ipairs(ACCESS) do
    out[#out + 1] = (mask & a[1] ~= 0) and a[2] or ("No" .. a[2])
  end
  return table.concat(out, " ")
end

---
-- Util.format_nfsfattr(attr, mactime): one line about a file:
-- type and permissions, owner, group, size and the chosen time (mtime
-- unless mactime says atime or ctime).
function Util.format_nfsfattr(attr, mactime)
  if type(attr) ~= "table" then return "" end
  local t = attr[mactime or "mtime"] or attr.mtime
  return string.format("%s%s  uid: %s  gid: %s  size: %s  time: %s",
    Util.FtypeToChar(attr.mode), Util.FpermToString(attr.mode), tostring(attr.uid),
    tostring(attr.gid), num2str(attr.size or 0),
    t and Util.TimeToString(t.seconds) or "?")
end

---
-- Util.unmarshall_nfstime(data, pos): position and { seconds, nseconds }
-- (the second field is microseconds in NFSv2; also given as useconds).
function Util.unmarshall_nfstime(data, pos)
  local p, s = Util.unmarshall_uint32(data, pos)
  local p2, n = Util.unmarshall_uint32(data, p)
  if s == nil or n == nil then return pos, nil end
  return p2, { seconds = s, nseconds = n, useconds = n }
end

---
-- Util.unmarshall_nfsfileid3(data, pos): position and the 64-bit file ID.
function Util.unmarshall_nfsfileid3(data, pos)
  return Util.unmarshall_uint64(data, pos)
end

---
-- Util.unmarshall_nfsattr(data, pos, nfsversion): position and the file
-- attributes (type, mode with the file type bits, nlink, uid, gid, size,
-- blocksize and blocks (v2) or used (v3), rdev, fsid, fileid, atime,
-- mtime, ctime); nil when data ends first.
function Util.unmarshall_nfsattr(data, pos, nfsversion)
  local a = {}
  local p = pos
  local function u32(k) local v; p, v = Util.unmarshall_uint32(data, p); a[k] = v; return v ~= nil end
  local function u64(k) local v; p, v = Util.unmarshall_uint64(data, p); a[k] = v; return v ~= nil end
  local function tm(k) local v; p, v = Util.unmarshall_nfstime(data, p); a[k] = v; return v ~= nil end
  if tonumber(nfsversion) == 3 then
    if not (u32("type") and u32("mode") and u32("nlink") and u32("uid") and u32("gid")
      and u64("size") and u64("used")) then return pos, nil end
    local major, minor
    p, major = Util.unmarshall_uint32(data, p)
    p, minor = Util.unmarshall_uint32(data, p)
    a.rdev = { major = major, minor = minor }
    if not (u64("fsid") and u64("fileid") and tm("atime") and tm("mtime") and tm("ctime")) then
      return pos, nil
    end
    a.blocks = a.used
  else
    if not (u32("type") and u32("mode") and u32("nlink") and u32("uid") and u32("gid")
      and u32("size") and u32("blocksize") and u32("rdev") and u32("blocks") and u32("fsid")
      and u32("fileid") and tm("atime") and tm("mtime") and tm("ctime")) then
      return pos, nil
    end
  end
  if a.mode & 0xf000 == 0 and FTYPE_BITS[a.type] then
    a.mode = a.mode | FTYPE_BITS[a.type]
  end
  return p, a
end

-- post_op_attr: a flag, then attributes when it is set.
local function post_op_attr(data, pos)
  local p, follows = boolean(data, pos)
  if follows == nil then return pos, nil end
  if not follows then return p, nil end
  return Util.unmarshall_nfsattr(data, p, 3)
end

local function pct(used, avail)
  local total = used + avail
  if total <= 0 then return "0%" end
  -- The ratio first, in floating point, so huge sizes cannot overflow.
  return string.format("%d%%", math.ceil((used / total) * 100 - 1e-9))
end

---
-- Util.calc_fsstat_table(stats, nfsversion, human): df's columns for a
-- STATFS (v2) or FSSTAT (v3) answer: size, used, available (1K blocks,
-- or with suffixes when human), use ("52%") and, for v2, bsize; nil and
-- an error for other versions.
function Util.calc_fsstat_table(stats, nfsversion, human)
  if type(stats) ~= "table" then return nil, "No file system statistics" end
  local size, used, avail, bsize
  nfsversion = tonumber(nfsversion)
  if nfsversion == 2 then
    bsize = stats.block_size or 0
    size = (stats.total_blocks or 0) * bsize
    used = ((stats.total_blocks or 0) - (stats.free_blocks or 0)) * bsize
    avail = (stats.available_blocks or 0) * bsize
  elseif nfsversion == 3 then
    size = stats.tbytes or 0
    used = (stats.tbytes or 0) - (stats.fbytes or 0)
    avail = stats.abytes or 0
  else
    return nil, "Unsupported NFS version"
  end
  local fs = { use = pct(used, avail) }
  if human then
    fs.size, fs.used, fs.available = Util.SizeToHuman(size), Util.SizeToHuman(used), Util.SizeToHuman(avail)
  else
    fs.size, fs.used, fs.available = num2str(size // 1024), num2str(used // 1024), num2str(avail // 1024)
  end
  if bsize then fs.bsize = num2str(bsize) end
  return fs
end

---
-- Util.calc_fsinfo_table(fsinfo, nfsversion, human): the FSINFO (v3)
-- values as text: rtmax, rtpref, rtmult, wtmax, wtpref, wtmult, dtpref,
-- maxfilesize (always with a suffix), properties.
function Util.calc_fsinfo_table(fsinfo, nfsversion, human)
  if type(fsinfo) ~= "table" then return nil, "No file system information" end
  if tonumber(nfsversion) ~= 3 then return nil, "FSINFO needs NFS version 3" end
  local fs = {}
  for _, k in ipairs({ "rtmax", "rtpref", "rtmult", "wtmax", "wtpref", "wtmult", "dtpref", "properties" }) do
    if fsinfo[k] then fs[k] = num2str(fsinfo[k]) end
  end
  if fsinfo.maxfilesize then
    -- Always with a suffix ("16.0T"), as nmap 7.95's nfs-statfs prints it.
    fs.maxfilesize = Util.SizeToHuman(fsinfo.maxfilesize)
  end
  return fs
end

---
-- Util.calc_pathconf_table(pconf, nfsversion): the PATHCONF (v3) values
-- as text: linkmax, name_max, no_trunc, chown_restricted,
-- case_insensitive, case_preserving.
function Util.calc_pathconf_table(pconf, nfsversion)
  if type(pconf) ~= "table" then return nil, "No path configuration" end
  if tonumber(nfsversion) ~= 3 then return nil, "PATHCONF needs NFS version 3" end
  local fs = {}
  for k, v in pairs(pconf) do
    if k ~= "attributes" then fs[k] = type(v) == "boolean" and tostring(v) or num2str(v) end
  end
  return fs
end

---------------------------------------------------------------------------
-- Portmap: the RPC constants and the portmapper's procedures.
local Portmap = {
  MessageType = { CALL = 0, REPLY = 1 },
  State = { MSG_ACCEPTED = 0, MSG_DENIED = 1 },
  AcceptState = { SUCCESS = 0, PROG_UNAVAIL = 1, PROG_MISMATCH = 2, PROC_UNAVAIL = 3,
    GARBAGE_ARGS = 4, SYSTEM_ERR = 5 },
  RejectState = { RPC_MISMATCH = 0, AUTH_ERROR = 1 },
  AuthType = { NULL = 0, UNIX = 1, SHORT = 2, DES = 3 },
  Procedure = { NULL = 0, SET = 1, UNSET = 2, GETPORT = 3, DUMP = 4, CALLIT = 5 },
  Protocol = { tcp = 6, udp = 17 },
}
Portmap.AcceptMsg = {
  [0] = "RPC executed successfully",
  [1] = "Program unavailable",
  [2] = "Program version mismatch",
  [3] = "Procedure unavailable",
  [4] = "Arguments could not be decoded",
  [5] = "System error",
}
Portmap.RejectMsg = {
  [0] = "RPC version mismatch",
  [1] = "Authentication error",
}
Portmap.__index = Portmap
rpc.Portmap = Portmap

local PROTO_NAME = { [6] = "tcp", [17] = "udp" }

---------------------------------------------------------------------------
-- Comm: one connection to one RPC program.
local Comm = {}
Comm.__index = Comm
rpc.Comm = Comm

---
-- Comm:new(program, version): a connection object for the named program
-- (as nmap-rpc names it) and version.
function Comm:new(program, version)
  local o = setmetatable({}, self)
  o.program = program
  o.program_id = Util.ProgNameToNumber(program)
  o.version = tonumber(version)
  o.checkprogver = true
  o.rbuf = ""
  return o
end

function Comm:SetCheckProgVer(check) self.checkprogver = check end
function Comm:SetProgID(progid) self.program_id = tonumber(progid) end
function Comm:SetVersion(version) self.version = tonumber(version); return true end

function Comm:ChkProgram()
  if not self.program_id then
    return false, string.format("Unknown RPC program: %s", tostring(self.program))
  end
  return true
end

function Comm:ChkVersion()
  local v = rpc.RPC_version[self.program]
  if not v then return true end
  if not self.version or self.version < v.min or self.version > v.max then
    return false, string.format("Version %s of %s is not supported", tostring(self.version), tostring(self.program))
  end
  return true
end

---
-- Comm:Connect(host, port, timeout): connects over the port's protocol.
-- True, or false and an error.
function Comm:Connect(host, port, timeout)
  if self.checkprogver then
    local ok, err = self:ChkProgram()
    if not ok then return false, err end
    ok, err = self:ChkVersion()
    if not ok then return false, err end
  end
  if type(port) ~= "table" then return false, "No port to connect to" end
  local proto = port.protocol or "tcp"
  if proto ~= "tcp" and proto ~= "udp" then return false, "Unsupported protocol: " .. tostring(proto) end
  local sock = nmap.new_socket(proto)
  sock:set_timeout(tonumber(timeout) or tonumber(stdnse.get_script_args("rpc.timeout")) or 10000)
  local ok, err = sock:connect(host, port, proto)
  if not ok then return false, string.format("%s connect error: %s", tostring(self.program), tostring(err)) end
  self.socket, self.proto, self.host, self.port, self.rbuf = sock, proto, host, port, ""
  return true
end

function Comm:Disconnect()
  if self.socket then self.socket:close() end
  self.socket = nil
  return true
end

function Comm:GetSocketInfo()
  if not self.socket then return false, "Not connected" end
  return self.socket:get_info()
end

local function new_xid()
  return (XID_MARK << 16) | (string.unpack(">I2", fero.crypto.random_bytes(2)))
end

-- FeroProbe's AUTH_UNIX machine name, and the user and group it claims
-- by default: nobody (65534), never root.
local UNIX_MACHINE = "feroprobe"
local NOBODY = 65534

-- The credentials: AUTH_NULL, or AUTH_UNIX with uid, gid and gids from
-- auth (nobody by default) and the machine name "feroprobe".
local function credentials(auth)
  local t = auth and auth.type or Portmap.AuthType.NULL
  if t == Portmap.AuthType.NULL then return string.pack(">I4I4", 0, 0) end
  if t ~= Portmap.AuthType.UNIX then return nil, "Only AUTH_NULL and AUTH_UNIX are available in FeroProbe" end
  local gids = type(auth.gids) == "table" and auth.gids or {}
  local body = { string.pack(">I4", os.time() & 0xffffffff), Util.marshall_vopaque(UNIX_MACHINE),
    string.pack(">I4I4", (tonumber(auth.uid) or NOBODY) & 0xffffffff, (tonumber(auth.gid) or NOBODY) & 0xffffffff),
    string.pack(">I4", math.min(#gids, 16)) }
  for i = 1, math.min(#gids, 16) do body[#body + 1] = string.pack(">I4", tonumber(gids[i]) & 0xffffffff) end
  body = table.concat(body)
  return string.pack(">I4I4", t, #body) .. body
end

---
-- Comm:CreateHeader(xid, procedure, auth): true and a CALL header for
-- this program and version, or false and an error. auth.type is
-- AuthType.NULL (the default) or AuthType.UNIX (uid, gid, gids; nobody,
-- 65534, unless given; machine name "feroprobe").
function Comm:CreateHeader(xid, procedure, auth)
  local cred, err = credentials(auth)
  if not cred then return false, err end
  if not self.program_id then return false, "No RPC program number" end
  xid = xid or new_xid()
  return true, string.pack(">I4I4I4I4I4I4", xid & 0xffffffff, Portmap.MessageType.CALL, 2,
    self.program_id & 0xffffffff, (self.version or 0) & 0xffffffff, (procedure or 0) & 0xffffffff)
    .. cred .. string.pack(">I4I4", 0, 0)
end

---
-- Comm:EncodePacket(xid, proc, auth, data): the call as sent: header and
-- data, with the TCP record mark over TCP.
function Comm:EncodePacket(xid, proc, auth, data)
  local ok, header = self:CreateHeader(xid, proc, auth)
  if not ok then return nil, header end
  local packet = header .. (data or "")
  if self.proto ~= "udp" then
    packet = string.pack(">I4", 0x80000000 | #packet) .. packet
  end
  return packet
end

function Comm:SendPacket(packet)
  if not self.socket then return false, "Not connected" end
  if not packet then return false, "No packet" end
  return self.socket:send(packet)
end

-- Exactly n more bytes from a TCP stream.
local function read_exact(self, n)
  while #self.rbuf < n do
    local ok, d = self.socket:receive_bytes(n - #self.rbuf)
    if not ok then return nil, d end
    self.rbuf = self.rbuf .. d
  end
  local out = self.rbuf:sub(1, n)
  self.rbuf = self.rbuf:sub(n + 1)
  return out
end

---
-- Comm:ReceivePacket(): true and one reply (its record's fragments
-- joined over TCP, without the record marks), or false and an error.
function Comm:ReceivePacket()
  if not self.socket then return false, "Not connected" end
  if self.proto == "udp" then
    return self.socket:receive()
  end
  -- A record that breaks off (or is too long) leaves the stream in the
  -- middle of a record, so the connection is closed.
  local function fail(err)
    self:Disconnect()
    return false, err
  end
  local parts, total = {}, 0
  for _ = 1, MAX_FRAGMENTS do
    local mark, err = read_exact(self, 4)
    if not mark then return fail(err) end
    local n = string.unpack(">I4", mark)
    local len = n & 0x7fffffff
    total = total + len
    if total > MAX_RECORD then return fail("RPC record too long") end
    if len > 0 then
      local frag
      frag, err = read_exact(self, len)
      if not frag then return fail(err) end
      parts[#parts + 1] = frag
    end
    if n & 0x80000000 ~= 0 then return true, table.concat(parts) end
  end
  return fail("RPC record in too many fragments")
end

---
-- Comm:GetAdditionalBytes(data, pos, needed): true and data when it holds
-- needed bytes from pos (the whole reply is read at once), else false and
-- an error.
function Comm:GetAdditionalBytes(data, pos, needed)
  if data and #data - pos + 1 >= needed then return true, data end
  return false, "Not enough data in the RPC reply"
end

---
-- Comm:DecodeHeader(data, pos): the position after the reply header and
-- the header: xid, type, state, verifier { flavor, length, data } and
-- accept_state (with low and high for PROG_MISMATCH) or denied_state
-- (with low and high, or auth_state). nil when data is too short.
function Comm:DecodeHeader(data, pos)
  pos = pos or 1
  if type(data) ~= "string" or #data < pos + 7 then return pos, nil end
  local h = {}
  local p
  p, h.xid = Util.unmarshall_uint32(data, pos)
  p, h.type = Util.unmarshall_uint32(data, p)
  if h.type ~= Portmap.MessageType.REPLY then return p, h end
  p, h.state = Util.unmarshall_uint32(data, p)
  if h.state == nil then return pos, nil end
  if h.state == Portmap.State.MSG_ACCEPTED then
    local flavor, len
    p, flavor = Util.unmarshall_uint32(data, p)
    p, len = Util.unmarshall_uint32(data, p)
    if len == nil or #data < p + len - 1 then return pos, nil end
    local vdata
    p, vdata = Util.unmarshall_opaque(len, data, p)
    h.verifier = { flavor = flavor, length = len, data = vdata }
    p, h.accept_state = Util.unmarshall_uint32(data, p)
    if h.accept_state == nil then return pos, nil end
    if h.accept_state == Portmap.AcceptState.PROG_MISMATCH then
      local p2, low = Util.unmarshall_uint32(data, p)
      local p3, high = Util.unmarshall_uint32(data, p2)
      if high then h.low, h.high, p = low, high, p3 end
    end
  elseif h.state == Portmap.State.MSG_DENIED then
    p, h.denied_state = Util.unmarshall_uint32(data, p)
    if h.denied_state == Portmap.RejectState.RPC_MISMATCH then
      p, h.low = Util.unmarshall_uint32(data, p)
      p, h.high = Util.unmarshall_uint32(data, p)
    elseif h.denied_state == Portmap.RejectState.AUTH_ERROR then
      p, h.auth_state = Util.unmarshall_uint32(data, p)
    end
  end
  return p, h
end

-- One call: true, the reply and the position after its header, or false
-- and an error. Replies to other XIDs are skipped; over UDP the call is
-- sent twice at most.
local function call(comm, proc, data)
  local xid = new_xid()
  -- mountd and NFS servers that export with sec=sys refuse AUTH_NULL, so
  -- those calls go as AUTH_UNIX user nobody.
  local auth = { type = Portmap.AuthType.NULL }
  if comm.program == "mountd" or comm.program == "nfs" then auth = { type = Portmap.AuthType.UNIX } end
  local packet, err = comm:EncodePacket(xid, proc, auth, data)
  if not packet then return false, err end
  local tries = comm.proto == "udp" and 2 or 1
  for _ = 1, tries do
    local ok, e = comm:SendPacket(packet)
    if not ok then return false, "RPC send error: " .. tostring(e) end
    for _ = 1, 5 do
      local rok, reply = comm:ReceivePacket()
      if not rok then err = reply; break end
      local pos, h = comm:DecodeHeader(reply, 1)
      if h and h.xid == xid then
        if h.type ~= Portmap.MessageType.REPLY then return false, "Packet was not a reply" end
        if h.state ~= Portmap.State.MSG_ACCEPTED then
          return false, Portmap.RejectMsg[h.denied_state] or "RPC call denied"
        end
        if h.accept_state ~= Portmap.AcceptState.SUCCESS then
          return false, Portmap.AcceptMsg[h.accept_state] or "RPC call failed"
        end
        return true, reply, pos
      end
    end
  end
  return false, "No RPC reply: " .. tostring(err)
end

---------------------------------------------------------------------------
-- Portmap procedures.
function Portmap:new() return setmetatable({}, self) end

-- The port in a universal address ("192.0.2.1.8.1" is port 2049).
local function uaddr_port(addr)
  local hi, lo = tostring(addr):match("%.(%d+)%.(%d+)$")
  if not hi then return nil end
  return tonumber(hi) * 256 + tonumber(lo)
end

---
-- Portmap:Dump(comm): true and the registered programs,
-- t[program][protocol] = { port, version = { ... }, addr (v3 and v4) },
-- or false and an error.
function Portmap:Dump(comm)
  local ok, reply, pos = call(comm, Portmap.Procedure.DUMP)
  if not ok then return false, reply end
  local short = "Short DUMP reply"
  local out, count = {}, 0
  while true do
    local follows
    pos, follows = boolean(reply, pos)
    if follows == nil then return false, short end
    if not follows then break end
    count = count + 1
    if count > 10000 then return false, "Too many DUMP entries" end
    local prog, vers, proto, port, addr
    if (comm.version or 2) >= 3 then
      local netid, owner
      pos, prog = Util.unmarshall_uint32(reply, pos)
      pos, vers = Util.unmarshall_uint32(reply, pos)
      if vers == nil then return false, short end
      pos, netid = vopaque(reply, pos)
      if netid == nil then return false, short end
      pos, addr = vopaque(reply, pos)
      if addr == nil then return false, short end
      pos, owner = vopaque(reply, pos)
      if owner == nil then return false, short end
      proto, port = netid, uaddr_port(addr)
    else
      local prot
      pos, prog = Util.unmarshall_uint32(reply, pos)
      pos, vers = Util.unmarshall_uint32(reply, pos)
      pos, prot = Util.unmarshall_uint32(reply, pos)
      pos, port = Util.unmarshall_uint32(reply, pos)
      if port == nil then return false, short end
      proto = PROTO_NAME[prot] or tostring(prot)
    end
    -- Entries without a port (the "local" netid's socket path) are left out.
    if port ~= nil then
      out[prog] = out[prog] or {}
      local e = out[prog][proto]
      if not e then
        e = { port = port, version = {}, addr = addr, ports = {} }
        out[prog][proto] = e
      end
      -- Each version keeps its own port (they may differ); `port` is the
      -- first one listed.
      if e.ports[vers] == nil then
        e.ports[vers] = port
        e.version[#e.version + 1] = vers
        table.sort(e.version)
      end
    end
  end
  return true, out
end

---
-- Portmap:GetPort(comm, program, protocol, version): the port the
-- portmapper (version 2) gives, 0 when the program is not registered;
-- nil and an error when the call fails.
function Portmap:GetPort(comm, program, protocol, version)
  if (comm.version or 2) ~= 2 then return nil, "GetPort needs portmapper version 2" end
  local prog = Util.ProgNameToNumber(program) or tonumber(program)
  if not prog then return nil, "Unknown RPC program: " .. tostring(program) end
  local prot = Portmap.Protocol[protocol]
  if not prot then return nil, "Unsupported protocol: " .. tostring(protocol) end
  local ok, reply, pos = call(comm, Portmap.Procedure.GETPORT,
    string.pack(">I4I4I4I4", prog, version or 0, prot, 0))
  if not ok then return nil, reply end
  local _, port = Util.unmarshall_uint32(reply, pos)
  if port == nil then return nil, "Short GETPORT reply" end
  return port
end

---
-- Portmap:Callit(comm, program, protocol, version): asks the portmapper
-- to call procedure 0 of the program; true and the raw reply, or false
-- and an error.
function Portmap:Callit(comm, program, protocol, version)
  local prog = Util.ProgNameToNumber(program) or tonumber(program)
  if not prog then return false, "Unknown RPC program: " .. tostring(program) end
  local ok, reply = call(comm, Portmap.Procedure.CALLIT,
    string.pack(">I4I4I4I4", prog, version or 0, 0, 0))
  if not ok then return false, reply end
  return true, reply
end

---------------------------------------------------------------------------
-- Mount.
local Mount = {
  Procedure = { NULL = 0, MOUNT = 1, DUMP = 2, UNMOUNT = 3, UNMOUNTALL = 4, EXPORT = 5 },
  StatMsg = {
    [1] = "Not owner", [2] = "No such file or directory", [5] = "I/O error",
    [13] = "Permission denied", [20] = "Not a directory", [22] = "Invalid argument",
    [63] = "Filename too long", [10004] = "Operation not supported",
    [10006] = "A failure on the server",
  },
}
Mount.__index = Mount
rpc.Mount = Mount

function Mount:new() return setmetatable({}, self) end

---
-- Mount:Export(comm): true and the exports, each { name = path, groups
-- ... } (the groups as the entry's array part), or false and an error.
function Mount:Export(comm)
  local ok, reply, pos = call(comm, Mount.Procedure.EXPORT)
  if not ok then return false, reply end
  local short = "Short EXPORT reply"
  local out = {}
  while true do
    local follows
    pos, follows = boolean(reply, pos)
    if follows == nil then return false, short end
    if not follows then break end
    if #out >= 10000 then return false, "Too many exports" end
    local entry = {}
    pos, entry.name = vopaque(reply, pos)
    if entry.name == nil then return false, short end
    while true do
      local g
      pos, g = boolean(reply, pos)
      if g == nil then return false, short end
      if not g then break end
      if #entry >= 10000 then return false, "Too many export groups" end
      local name
      pos, name = vopaque(reply, pos)
      if name == nil then return false, short end
      entry[#entry + 1] = name
    end
    out[#out + 1] = entry
  end
  return true, out
end

---
-- Mount:Mount(comm, path): true and the export's file handle (32 bytes
-- for mount v1 and v2, up to 64 for v3), or false and an error.
function Mount:Mount(comm, path)
  local ok, reply, pos = call(comm, Mount.Procedure.MOUNT, Util.marshall_vopaque(path))
  if not ok then return false, reply end
  local status
  pos, status = Util.unmarshall_uint32(reply, pos)
  if status == nil then return false, "Short MOUNT reply" end
  if status ~= 0 then
    return false, string.format("Mount failed: %s", Mount.StatMsg[status] or tostring(status))
  end
  local fh
  if (comm.version or 1) >= 3 then
    pos, fh = vopaque(reply, pos)
  else
    if #reply < pos + 31 then return false, "Short MOUNT reply" end
    fh = reply:sub(pos, pos + 31)
  end
  if not fh then return false, "Short MOUNT reply" end
  return true, fh
end

---
-- Mount:Unmount(comm, path): true, or false and an error.
function Mount:Unmount(comm, path)
  local ok, err = call(comm, Mount.Procedure.UNMOUNT, Util.marshall_vopaque(path))
  if not ok then return false, err end
  return true
end

---------------------------------------------------------------------------
-- NFS (versions 2 and 3).
local NFS = {
  Procedure = {
    [2] = { GETATTR = 1, LOOKUP = 4, READDIR = 16, STATFS = 17 },
    [3] = { GETATTR = 1, LOOKUP = 3, ACCESS = 4, READDIR = 16, READDIRPLUS = 17,
      FSSTAT = 18, FSINFO = 19, PATHCONF = 20 },
  },
  StatMsg = {
    [1] = "Not owner", [2] = "No such file or directory", [5] = "I/O error",
    [6] = "No such device or address", [13] = "Permission denied", [17] = "File exists",
    [18] = "Cross-device link", [19] = "No such device", [20] = "Not a directory",
    [21] = "Is a directory", [22] = "Invalid argument", [27] = "File too large",
    [28] = "No space left on device", [30] = "Read-only file system", [31] = "Too many links",
    [63] = "Filename too long", [66] = "Directory not empty", [69] = "Disc quota exceeded",
    [70] = "Stale file handle", [71] = "Too many levels of remote in path",
    [10001] = "Illegal file handle", [10002] = "Update synchronization mismatch",
    [10003] = "Cookie is stale", [10004] = "Operation not supported",
    [10005] = "Buffer or request is too small", [10006] = "A failure on the server",
    [10007] = "Type not supported", [10008] = "Request in progress, try later",
  },
}
NFS.__index = NFS
rpc.NFS = NFS

function NFS:new() return setmetatable({}, self) end

local function proc_of(comm, name)
  local t = NFS.Procedure[comm.version]
  local p = t and t[name]
  if not p then return nil, string.format("%s is not in NFS version %s", name, tostring(comm.version)) end
  return p
end

local function fh_arg(comm, fh)
  fh = fh or ""
  if comm.version == 3 then return Util.marshall_vopaque(fh) end
  return (fh .. string.rep("\0", 32)):sub(1, 32)
end

-- A call whose reply starts with an nfsstat: true, reply, position after
-- the status, or false and an error.
local function nfs_call(comm, name, args)
  local proc, err = proc_of(comm, name)
  if not proc then return false, err end
  local ok, reply, pos = call(comm, proc, args)
  if not ok then return false, reply end
  local status
  pos, status = Util.unmarshall_uint32(reply, pos)
  if status == nil then return false, "Short " .. name .. " reply" end
  if status ~= 0 then
    return false, string.format("%s failed: %s", name, NFS.StatMsg[status] or tostring(status))
  end
  return true, reply, pos
end

---
-- NFS:GetAttrDecode(comm, data, pos): position and the attributes.
function NFS:GetAttrDecode(comm, data, pos)
  return Util.unmarshall_nfsattr(data, pos, comm.version)
end

---
-- NFS:GetAttr(comm, file_handle): true and the file's attributes, or
-- false and an error.
function NFS:GetAttr(comm, file_handle)
  local ok, reply, pos = nfs_call(comm, "GETATTR", fh_arg(comm, file_handle))
  if not ok then return false, reply end
  local _, a = self:GetAttrDecode(comm, reply, pos)
  if not a then return false, "Short GETATTR reply" end
  return true, a
end

---
-- NFS:LookUp(comm, dir_handle, name): true and { fhandle, attributes,
-- dir_attributes (v3) }, or false and an error.
function NFS:LookUp(comm, dir_handle, name)
  local ok, reply, pos = nfs_call(comm, "LOOKUP", fh_arg(comm, dir_handle) .. Util.marshall_vopaque(name))
  if not ok then return false, reply end
  local out = {}
  if comm.version == 3 then
    pos, out.fhandle = vopaque(reply, pos)
    if out.fhandle == nil then return false, "Short LOOKUP reply" end
    pos, out.attributes = post_op_attr(reply, pos)
    pos, out.dir_attributes = post_op_attr(reply, pos)
  else
    if #reply < pos + 31 then return false, "Short LOOKUP reply" end
    out.fhandle = reply:sub(pos, pos + 31)
    pos, out.attributes = Util.unmarshall_nfsattr(reply, pos + 32, 2)
  end
  return true, out
end

---
-- NFS:Access(comm, file_handle, access): true and { mask (the rights
-- granted), attributes } (v3 only), or false and an error.
function NFS:Access(comm, file_handle, access)
  local ok, reply, pos = nfs_call(comm, "ACCESS", fh_arg(comm, file_handle) .. Util.marshall_uint32(access or 0x3f))
  if not ok then return false, reply end
  local out = {}
  pos, out.attributes = post_op_attr(reply, pos)
  pos, out.mask = Util.unmarshall_uint32(reply, pos)
  if out.mask == nil then return false, "Short ACCESS reply" end
  return true, out
end

-- Directory entries of one READDIR or READDIRPLUS reply from pos:
-- position, entries, the last cookie and whether the list ended; or
-- nil and an error when the reply is cut short.
local function dir_entries(comm, data, pos, plus, limit)
  local short = "Short directory reply"
  local entries, cookie = {}, nil
  while #entries < limit do
    local follows
    pos, follows = boolean(data, pos)
    if follows == nil then return nil, short end
    if not follows then break end
    local e = {}
    if comm.version == 3 then
      pos, e.file_id = Util.unmarshall_uint64(data, pos)
      pos, e.name = vopaque(data, pos)
      pos, e.cookie = Util.unmarshall_uint64(data, pos)
      if e.name == nil or e.cookie == nil then return nil, short end
      e.cookie_raw = data:sub(pos - 8, pos - 1)
      if plus then
        local _, flag = boolean(data, pos)
        if flag == nil then return nil, short end
        pos, e.attributes = post_op_attr(data, pos)
        if flag and e.attributes == nil then return nil, short end
        -- An entry the server sends no attributes for (Linux does so for
        -- "..") gets an empty table, so nfs-ls lists it with "?", as nmap.
        e.attributes = e.attributes or {}
        local fh
        pos, fh = boolean(data, pos)
        if fh == nil then return nil, short end
        if fh then
          pos, e.fhandle = vopaque(data, pos)
          if e.fhandle == nil then return nil, short end
        end
      end
    else
      pos, e.file_id = Util.unmarshall_uint32(data, pos)
      pos, e.name = vopaque(data, pos)
      pos, e.cookie = Util.unmarshall_uint32(data, pos)
      if e.name == nil or e.cookie == nil then return nil, short end
      e.cookie_raw = data:sub(pos - 4, pos - 1)
    end
    e.fileid = e.file_id
    entries[#entries + 1] = e
    cookie = e.cookie_raw
  end
  if #entries >= limit then return pos, entries, cookie, false, true end
  local eof
  pos, eof = boolean(data, pos)
  if eof == nil then return nil, short end
  return pos, entries, cookie, eof
end

---
-- NFS:ReadDirDecode(comm, data, pos): position and { attributes (v3),
-- entries = { { file_id, name, cookie } ... }, eof } of a READDIR reply
-- after its status.
function NFS:ReadDirDecode(comm, data, pos)
  local out = {}
  if comm.version == 3 then
    pos, out.attributes = post_op_attr(data, pos)
    out.cookieverf = data:sub(pos, pos + 7)
    pos = pos + 8
  end
  local cookie, entries
  pos, entries, cookie, out.eof = dir_entries(comm, data, pos, false, 100000)
  if not pos then return nil, entries end
  out.entries, out.cookie = entries, cookie
  return pos, out
end

local MAX_ENTRIES, MAX_ROUNDS = 10000, 50

local function read_dir(self, comm, file_handle, plus)
  local name = plus and "READDIRPLUS" or "READDIR"
  local count = comm.proto == "udp" and 8192 or 32768
  local result = { entries = {} }
  local cookie, verf = nil, string.rep("\0", 8)
  for _ = 1, MAX_ROUNDS do
    local args
    if comm.version == 3 then
      args = fh_arg(comm, file_handle) .. (cookie or string.rep("\0", 8)) .. verf
      if plus then
        args = args .. Util.marshall_uint32(count // 4) .. Util.marshall_uint32(count)
      else
        args = args .. Util.marshall_uint32(count)
      end
    else
      args = fh_arg(comm, file_handle) .. (cookie or "\0\0\0\0") .. Util.marshall_uint32(count)
    end
    local ok, reply, pos = nfs_call(comm, name, args)
    if not ok then return false, reply end
    if comm.version == 3 then
      local attrs
      pos, attrs = post_op_attr(reply, pos)
      result.attributes = result.attributes or attrs
      verf = reply:sub(pos, pos + 7)
      pos = pos + 8
    end
    local entries, last, eof
    pos, entries, last, eof = dir_entries(comm, reply, pos, plus, MAX_ENTRIES - #result.entries)
    if not pos then return false, entries end
    for _, e in ipairs(entries) do result.entries[#result.entries + 1] = e end
    if eof then
      result.eof = true
      return true, result
    end
    -- Not at the end, but no cookie to go on from, or the entry cap.
    if not last or #result.entries >= MAX_ENTRIES then break end
    cookie = last
  end
  -- Stopped on the round or entry cap, or without a cookie: the listing
  -- holds what was read and says it is incomplete.
  result.eof = false
  result.incomplete = true
  return true, result
end

---
-- NFS:ReadDir(comm, file_handle): true and { attributes (v3), entries },
-- each entry { file_id, name, cookie }; or false and an error.
function NFS:ReadDir(comm, file_handle) return read_dir(self, comm, file_handle, false) end

---
-- NFS:ReadDirPlus(comm, file_handle): true and { attributes, entries },
-- each entry also with attributes and fhandle (v3 only).
function NFS:ReadDirPlus(comm, file_handle) return read_dir(self, comm, file_handle, true) end

---
-- NFS:StatFsDecode(comm, data, pos): position and { transfer_size,
-- block_size, total_blocks, free_blocks, available_blocks } (v2).
function NFS:StatFsDecode(comm, data, pos)
  local s = {}
  pos, s.transfer_size = Util.unmarshall_uint32(data, pos)
  pos, s.block_size = Util.unmarshall_uint32(data, pos)
  pos, s.total_blocks = Util.unmarshall_uint32(data, pos)
  pos, s.free_blocks = Util.unmarshall_uint32(data, pos)
  pos, s.available_blocks = Util.unmarshall_uint32(data, pos)
  if s.available_blocks == nil then return pos, nil end
  return pos, s
end

---
-- NFS:StatFs(comm, file_handle): true and the STATFS table (v2), or
-- false and an error.
function NFS:StatFs(comm, file_handle)
  local ok, reply, pos = nfs_call(comm, "STATFS", fh_arg(comm, file_handle))
  if not ok then return false, reply end
  local _, s = self:StatFsDecode(comm, reply, pos)
  if not s then return false, "Short STATFS reply" end
  return true, s
end

---
-- NFS:FsStat(comm, file_handle): true and { attributes, tbytes, fbytes,
-- abytes, tfiles, ffiles, afiles, invarsec } (v3), or false and an error.
function NFS:FsStat(comm, file_handle)
  local ok, reply, pos = nfs_call(comm, "FSSTAT", fh_arg(comm, file_handle))
  if not ok then return false, reply end
  local s = {}
  pos, s.attributes = post_op_attr(reply, pos)
  for _, k in ipairs({ "tbytes", "fbytes", "abytes", "tfiles", "ffiles", "afiles" }) do
    pos, s[k] = Util.unmarshall_uint64(reply, pos)
  end
  pos, s.invarsec = Util.unmarshall_uint32(reply, pos)
  if s.invarsec == nil then return false, "Short FSSTAT reply" end
  return true, s
end

---
-- NFS:FsInfo(comm, file_handle): true and { attributes, rtmax, rtpref,
-- rtmult, wtmax, wtpref, wtmult, dtpref, maxfilesize, time_delta,
-- properties } (v3), or false and an error.
function NFS:FsInfo(comm, file_handle)
  local ok, reply, pos = nfs_call(comm, "FSINFO", fh_arg(comm, file_handle))
  if not ok then return false, reply end
  local s = {}
  pos, s.attributes = post_op_attr(reply, pos)
  for _, k in ipairs({ "rtmax", "rtpref", "rtmult", "wtmax", "wtpref", "wtmult", "dtpref" }) do
    pos, s[k] = Util.unmarshall_uint32(reply, pos)
  end
  pos, s.maxfilesize = Util.unmarshall_uint64(reply, pos)
  pos, s.time_delta = Util.unmarshall_nfstime(reply, pos)
  pos, s.properties = Util.unmarshall_uint32(reply, pos)
  if s.properties == nil then return false, "Short FSINFO reply" end
  return true, s
end

---
-- NFS:PathConf(comm, file_handle): true and { attributes, linkmax,
-- name_max, no_trunc, chown_restricted, case_insensitive,
-- case_preserving } (v3), or false and an error.
function NFS:PathConf(comm, file_handle)
  local ok, reply, pos = nfs_call(comm, "PATHCONF", fh_arg(comm, file_handle))
  if not ok then return false, reply end
  local s = {}
  pos, s.attributes = post_op_attr(reply, pos)
  pos, s.linkmax = Util.unmarshall_uint32(reply, pos)
  pos, s.name_max = Util.unmarshall_uint32(reply, pos)
  for _, k in ipairs({ "no_trunc", "chown_restricted", "case_insensitive", "case_preserving" }) do
    pos, s[k] = boolean(reply, pos)
  end
  if s.case_preserving == nil then return false, "Short PATHCONF reply" end
  return true, s
end

---------------------------------------------------------------------------
-- Helper: the portmapper first, then the program it names.
local Helper = {}
rpc.Helper = Helper

-- The protocols to try, in order: the rpc.protocol argument, else TCP
-- then UDP.
local function protocols()
  local p = stdnse.get_script_args("rpc.protocol")
  if type(p) == "string" then return { p } end
  if type(p) == "table" and #p > 0 then return p end
  return { "tcp", "udp" }
end

---
-- Helper.RpcInfo(host, port): true and the portmapper's DUMP table (see
-- Portmap:Dump; rpcbind version 3, else 2), or false and an error. One answer per host and
-- protocol is kept for the run.
function Helper.RpcInfo(host, port)
  local key = "rpcinfo_" .. tostring(type(host) == "table" and host.ip or host) .. "_"
    .. tostring(port and port.number) .. "_" .. tostring(port and port.protocol)
  local cached = nmap.registry[key]
  if type(cached) == "table" then return true, cached end
  -- rpcbind version 3 first, which lists IPv6 (tcp6, udp6) as well, as
  -- nmap 7.95's rpcinfo shows; version 2 when the server has no other.
  local status, result
  for _, v in ipairs({ 3, 2 }) do
    local comm = Comm:new("rpcbind", v)
    local ok, err = comm:Connect(host, port)
    if not ok then return false, err end
    status, result = Portmap:new():Dump(comm)
    comm:Disconnect()
    if status then break end
  end
  if not status then return false, result end
  nmap.registry[key] = result
  return true, result
end

---
-- Helper.GetPortForProgram(host, port, program, protocol): true and the
-- portmapper's entry { port, version } for the program, or false and an
-- error.
function Helper.GetPortForProgram(host, port, program, protocol)
  local ok, info = Helper.RpcInfo(host, port)
  if not ok then return false, info end
  local num = Util.ProgNameToNumber(program) or tonumber(program)
  local e = num and info[num] and info[num][protocol]
  if not e then return false, string.format("No %s over %s registered", tostring(program), tostring(protocol)) end
  return true, e
end

-- Whether host is an IPv6 address.
local function is_ipv6(host)
  local ip = type(host) == "table" and host.ip or host
  return type(ip) == "string" and ip:find(":", 1, true) ~= nil
end

-- The program's usable registrations, best first: { port = { number,
-- protocol }, version } for each protocol in protocols() order, with the
-- highest version from min_version to max_version (the program's range
-- and the <program>.version argument also apply); or nil and an error.
local function candidates(host, port, program, max_version, min_version)
  local ok, info = Helper.RpcInfo(host, port)
  if not ok then return nil, info end
  local num = Util.ProgNameToNumber(program)
  local reg = num and info[num]
  if not reg then return nil, string.format("No %s registered with the portmapper", tostring(program)) end
  local limits = rpc.RPC_version[program]
  local function usable(v)
    return (not limits or (v >= limits.min and v <= limits.max))
      and (not max_version or v <= max_version)
      and (not min_version or v >= min_version)
  end
  local wanted = tonumber(stdnse.get_script_args((program == "mountd" and "mount" or program) .. ".version"))
  if wanted and not usable(wanted) then
    return nil, string.format("Version %d of %s is not supported here", wanted, tostring(program))
  end
  local out = {}
  for _, proto in ipairs(protocols()) do
    -- An IPv6 host is reached over the tcp6/udp6 registration where the
    -- portmapper lists one (rpcbind version 3), else the plain one.
    local e = (is_ipv6(host) and reg[proto .. "6"]) or reg[proto]
    if e then
      local best
      for _, v in ipairs(e.version) do
        if wanted then
          if v == wanted then best = v end
        elseif usable(v) and (not best or v > best) then
          best = v
        end
      end
      if best then
        local number = (e.ports and e.ports[best]) or e.port
        out[#out + 1] = { port = { number = number, protocol = proto }, version = best }
      end
    end
  end
  if #out == 0 then
    if wanted then return nil, string.format("Version %d of %s is not registered", wanted, tostring(program)) end
    return nil, string.format("No supported version of %s registered", tostring(program))
  end
  return out
end

---
-- Helper.GetProgramInfo(host, port, program, max_version): true and
-- { port = { number, protocol }, version } for the program's highest
-- version up to max_version (or the <program>.version argument), on the
-- first protocol it is registered for; or false and an error.
function Helper.GetProgramInfo(host, port, program, max_version)
  local list, err = candidates(host, port, program, max_version)
  if not list then return false, err end
  return true, list[1]
end

-- A connection to the program: each registration in turn until one
-- connects; or nil and the last error.
local function open(host, port, program, max_version, min_version)
  local list, err = candidates(host, port, program, max_version, min_version)
  if not list then return nil, err end
  for _, info in ipairs(list) do
    local comm = Comm:new(program, info.version)
    local status
    status, err = comm:Connect(host, info.port)
    if status then return comm end
    stdnse.debug1("%s over %s: %s", program, info.port.protocol, tostring(err))
  end
  return nil, err
end

---
-- Helper.ShowMounts(host, port): true and mountd's exports (see
-- Mount:Export), or false and an error.
function Helper.ShowMounts(host, port)
  local comm, err = open(host, port, "mountd")
  if not comm then return false, err end
  local ok, mounts = Mount:new():Export(comm)
  comm:Disconnect()
  return ok, mounts
end

---
-- Helper.MountPath(host, port, path): the mountd connection and the
-- export's file handle, or nil and an error. UnmountPath closes it.
function Helper.MountPath(host, port, path, max_version, min_version)
  local comm, err = open(host, port, "mountd", max_version, min_version)
  if not comm then return nil, err end
  local ok, fh = Mount:new():Mount(comm, path)
  if not ok then
    comm:Disconnect()
    return nil, fh
  end
  return comm, fh
end

---
-- Helper.UnmountPath(mnt_comm, path): unmounts and closes; true, or nil
-- and an error.
function Helper.UnmountPath(mnt_comm, path)
  if not mnt_comm then return nil, "Not mounted" end
  local ok, err = Mount:new():Unmount(mnt_comm, path)
  mnt_comm:Disconnect()
  if not ok then return nil, err end
  return true
end

---
-- Helper.NfsOpen(host, port): an NFS connection (version 3 at most), or
-- nil and an error. NfsClose closes it.
function Helper.NfsOpen(host, port)
  return open(host, port, "nfs", 3)
end

---
-- Helper.NfsClose(nfs_comm): true, or nil and an error.
function Helper.NfsClose(nfs_comm)
  if not nfs_comm then return nil, "Not connected" end
  nfs_comm:Disconnect()
  return true
end

-- Mounts path with the mount version that goes with the NFS version
-- (NFS 3 with mount 3, else NFS 2 with mount 1 or 2), runs fn(nfs,
-- nfs_comm, fhandle), unmounts. A server without that pair for version
-- 3 is tried with version 2; a MOUNT or NFS error is returned as it is.
local function with_export(host, port, path, fn)
  local last_err
  for _, plan in ipairs({ { nfs = 3, min = 3, max = 3 }, { nfs = 2, min = 1, max = 2 } }) do
    local nfs_comm, err = open(host, port, "nfs", plan.nfs, plan.nfs)
    local mnt_comm
    if nfs_comm then
      mnt_comm, err = open(host, port, "mountd", plan.max, plan.min)
      if not mnt_comm then Helper.NfsClose(nfs_comm) end
    end
    if mnt_comm then
      local ok, fh = Mount:new():Mount(mnt_comm, path)
      if not ok then
        mnt_comm:Disconnect()
        Helper.NfsClose(nfs_comm)
        return false, fh
      end
      local status, result = fn(NFS:new(), nfs_comm, fh)
      local unmounted, uerr = Helper.UnmountPath(mnt_comm, path)
      Helper.NfsClose(nfs_comm)
      if not unmounted then
        -- The NFS answer (or its error) is what the script asked for;
        -- the UNMOUNT failure is only reported.
        stdnse.debug1("UNMOUNT %s failed: %s", tostring(path), tostring(uerr))
      end
      return status, result
    end
    last_err = err
  end
  return false, last_err
end

---
-- Helper.ExportStats(host, port, path): true and the export's STATFS
-- (v2) or FSSTAT (v3) table, or false and an error.
function Helper.ExportStats(host, port, path)
  return with_export(host, port, path, function(nfs, comm, fh)
    if comm.version == 3 then return nfs:FsStat(comm, fh) end
    return nfs:StatFs(comm, fh)
  end)
end

---
-- Helper.GetAttributes(host, port, path): true and the export's root
-- attributes, or false and an error.
function Helper.GetAttributes(host, port, path)
  return with_export(host, port, path, function(nfs, comm, fh) return nfs:GetAttr(comm, fh) end)
end

---
-- Helper.Dir(host, port, path): true and the export's directory listing
-- (see NFS:ReadDir), or false and an error.
function Helper.Dir(host, port, path)
  return with_export(host, port, path, function(nfs, comm, fh) return nfs:ReadDir(comm, fh) end)
end

return rpc
