-- NSE compatibility layer: the `comm` module.
-- Written for FeroProbe from nmap's public API documentation (not from
-- nselib); GPL-3.0-or-later, like FeroProbe.
local fero = ...
local nmap = require "nmap"
local comm = {}

local DEFAULT_TIMEOUT = 5000

local function proto_of(port, opts)
  if opts.proto then return opts.proto end
  if type(port) == "table" and port.protocol then return port.protocol end
  return "tcp"
end

-- What opts asks to read: lines, bytes, or whatever comes first.
local function read(sock, opts)
  if opts.lines then return sock:receive_lines(opts.lines) end
  if opts.bytes then return sock:receive_bytes(opts.bytes) end
  return sock:receive()
end

-- comm.opencon(host, port, data, opts): a connected socket and the first
-- answer (to data, or the greeting with opts.recv_before); nil and a
-- message when the connection fails.
comm.opencon = function(host, port, data, opts)
  opts = opts or {}
  local sock = nmap.new_socket()
  sock:set_timeout(opts.connect_timeout or opts.timeout or DEFAULT_TIMEOUT)
  local ok, err = sock:connect(host, port, proto_of(port, opts))
  if not ok then return nil, err end
  sock:set_timeout(opts.request_timeout or opts.timeout or DEFAULT_TIMEOUT)
  local early
  if opts.recv_before then
    local s, d = read(sock, opts)
    if s then early = d end
  end
  if data and #data > 0 then
    ok, err = sock:send(data)
    if not ok then sock:close() return nil, err end
    local s, d = read(sock, opts)
    if s then return sock, d, early end
    return sock, nil, early
  end
  return sock, early, early
end

comm.get_banner = function(host, port, opts)
  opts = opts or {}
  local o = {}
  for k, v in pairs(opts) do o[k] = v end
  o.recv_before = true
  local sock, banner = comm.opencon(host, port, nil, o)
  if not sock then return false, banner end
  sock:close()
  if banner == nil then return false, "no banner" end
  return true, banner
end

comm.exchange = function(host, port, data, opts)
  opts = opts or {}
  local sock, resp = comm.opencon(host, port, data, opts)
  if not sock then return false, resp end
  sock:close()
  if resp == nil then return false, "no response" end
  return true, resp
end

-- comm.tryssl: TLS first where the port suggests it, else plain TCP
-- first; the other when the first gets no answer. Returns the socket,
-- the answer, "ssl" or "tcp", and the greeting.
comm.tryssl = function(host, port, data, opts)
  opts = opts or {}
  local first, second = "tcp", "ssl"
  if fero.portrule.ssl(host, type(port) == "table" and port or { number = port,
    protocol = "tcp", state = "open" }) then
    first, second = "ssl", "tcp"
  end
  for _, proto in ipairs({ first, second }) do
    local o = {}
    for k, v in pairs(opts) do o[k] = v end
    o.proto = proto
    local sock, resp, early = comm.opencon(host, port, data, o)
    if sock and (resp or early or not data) then return sock, resp, proto, early end
    if sock then sock:close() end
  end
  return nil, "no answer over TLS or plain TCP"
end

return comm
