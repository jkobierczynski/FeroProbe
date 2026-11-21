-- FeroProbe script: snmp-interfaces
-- Written for FeroProbe from scratch, from RFC 2863 (IF-MIB ifTable),
-- RFC 1213 (ipAddrTable) and the IANA ifType registry (IANAifType-MIB);
-- GPL-3.0-or-later.

description = [[
Lists a device's network interfaces over SNMP: for each interface its
name, IP addresses and netmasks, MAC address with the vendor from the OUI
list, type, speed and the traffic it has sent and received. Without -v
only interfaces that are up are listed; with -v all of them, with their
status.

Reads the interface table (IF-MIB ifTable: the ifDescr, ifType, ifSpeed,
ifPhysAddress, ifOperStatus, ifInOctets and ifOutOctets columns) and the
IP address table (ipAddrTable) one GetNextRequest at a time, as
`snmpwalk` does, with community "public" (creds.snmp sets another). Runs
on UDP 161, or a UDP port -sV named snmp, only when that port was scanned
(-sU -p U:161). Every request has request-id 0x4650 ("FP").

Script arguments (of the SNMP library):
  creds.snmp     The community ("private", or nmap's form ":private").
  snmp.version   v1 (default) or v2c.
  snmp.timeout   How long to wait for each answer (default 5000 ms; a
                 number is milliseconds, or give a unit: 5s).
  snmp.retries   How often a request is sent again (default 1).
]]

author = "FeroProbe contributors"
license = "GPL-3.0-or-later"
categories = { "default", "discovery", "safe" }

portrule = fero.portrule.match({ 161 }, { "snmp" }, "udp")

local IF = "1.3.6.1.2.1.2.2.1"
local IP = "1.3.6.1.2.1.4.20.1"
-- The ifTable columns read, by their number under ifEntry.
local COLUMNS = {
  descr = 2, type = 3, speed = 5, phys = 6, status = 8, rx = 10, tx = 16,
}

-- IANAifType names (the IANA ifType registry).
local IFTYPE = {
  [1] = "other", [2] = "regular1822", [3] = "hdh1822", [4] = "ddnX25",
  [5] = "rfc877x25", [6] = "ethernetCsmacd", [7] = "iso88023Csmacd",
  [8] = "iso88024TokenBus", [9] = "iso88025TokenRing", [10] = "iso88026Man",
  [11] = "starLan", [12] = "proteon10Mbit", [13] = "proteon80Mbit",
  [14] = "hyperchannel", [15] = "fddi", [16] = "lapb", [17] = "sdlc",
  [18] = "ds1", [19] = "e1", [20] = "basicISDN", [21] = "primaryISDN",
  [22] = "propPointToPointSerial", [23] = "ppp", [24] = "softwareLoopback",
  [25] = "eon", [26] = "ethernet3Mbit", [27] = "nsip", [28] = "slip",
  [29] = "ultra", [30] = "ds3", [31] = "sip", [32] = "frameRelay",
  [33] = "rs232", [34] = "para", [35] = "arcnet", [36] = "arcnetPlus",
  [37] = "atm", [38] = "miox25", [39] = "sonet", [40] = "x25ple",
  [41] = "iso88022llc", [42] = "localTalk", [43] = "smdsDxi",
  [44] = "frameRelayService", [45] = "v35", [46] = "hssi", [47] = "hippi",
  [48] = "modem", [49] = "aal5", [50] = "sonetPath", [51] = "sonetVT",
  [52] = "smdsIcip", [53] = "propVirtual", [54] = "propMultiplexor",
  [55] = "ieee80212", [56] = "fibreChannel", [57] = "hippiInterface",
  [58] = "frameRelayInterconnect", [59] = "aflane8023", [60] = "aflane8025",
  [61] = "cctEmul", [62] = "fastEther", [63] = "isdn", [64] = "v11",
  [65] = "v36", [66] = "g703at64k", [67] = "g703at2mb", [68] = "qllc",
  [69] = "fastEtherFX", [70] = "channel", [71] = "ieee80211",
  [72] = "ibm370parChan", [73] = "escon", [74] = "dlsw", [75] = "isdns",
  [76] = "isdnu", [77] = "lapd", [78] = "ipSwitch", [79] = "rsrb",
  [80] = "atmLogical", [81] = "ds0", [82] = "ds0Bundle", [83] = "bsc",
  [84] = "async", [85] = "cnr", [86] = "iso88025Dtr", [87] = "eplrs",
  [88] = "arap", [89] = "propCnls", [90] = "hostPad", [91] = "termPad",
  [92] = "frameRelayMPI", [93] = "x213", [94] = "adsl", [95] = "radsl",
  [96] = "sdsl", [97] = "vdsl", [98] = "iso88025CRFPInt", [99] = "myrinet",
  [100] = "voiceEM", [101] = "voiceFXO", [102] = "voiceFXS",
  [103] = "voiceEncap", [104] = "voiceOverIp", [105] = "atmDxi",
  [106] = "atmFuni", [107] = "atmIma", [108] = "pppMultilinkBundle",
  [109] = "ipOverCdlc", [110] = "ipOverClaw", [111] = "stackToStack",
  [112] = "virtualIpAddress", [113] = "mpc", [114] = "ipOverAtm",
  [115] = "iso88025Fiber", [116] = "tdlc", [117] = "gigabitEthernet",
  [118] = "hdlc", [119] = "lapf", [120] = "v37", [121] = "x25mlp",
  [122] = "x25huntGroup", [123] = "transpHdlc", [124] = "interleave",
  [125] = "fast", [126] = "ip", [127] = "docsCableMaclayer",
  [128] = "docsCableDownstream", [129] = "docsCableUpstream",
  [130] = "a12MppSwitch", [131] = "tunnel", [132] = "coffee", [133] = "ces",
  [134] = "atmSubInterface", [135] = "l2vlan", [136] = "l3ipvlan",
  [137] = "l3ipxvlan", [138] = "digitalPowerline", [139] = "mediaMailOverIp",
  [140] = "dtm", [141] = "dcn", [142] = "ipForward", [143] = "msdsl",
  [144] = "ieee1394", [145] = "if-gsn", [146] = "dvbRccMacLayer",
  [147] = "dvbRccDownstream", [148] = "dvbRccUpstream", [149] = "atmVirtual",
  [150] = "mplsTunnel", [151] = "srp", [152] = "voiceOverAtm",
  [153] = "voiceOverFrameRelay", [154] = "idsl", [155] = "compositeLink",
  [156] = "ss7SigLink", [157] = "propWirelessP2P", [158] = "frForward",
  [159] = "rfc1483", [160] = "usb", [161] = "ieee8023adLag",
  [162] = "bgppolicyaccounting", [163] = "frf16MfrBundle",
  [164] = "h323Gatekeeper", [165] = "h323Proxy", [166] = "mpls",
  [167] = "mfSigLink", [168] = "hdsl2", [169] = "shdsl", [170] = "ds1FDL",
  [171] = "pos", [172] = "dvbAsiIn", [173] = "dvbAsiOut", [174] = "plc",
  [175] = "nfas", [176] = "tr008", [177] = "gr303RDT", [178] = "gr303IDT",
  [179] = "isup", [180] = "propDocsWirelessMaclayer",
  [181] = "propDocsWirelessDownstream", [182] = "propDocsWirelessUpstream",
  [183] = "hiperlan2", [184] = "propBWAp2Mp", [185] = "sonetOverheadChannel",
  [186] = "digitalWrapperOverheadChannel", [187] = "aal2", [188] = "radioMAC",
  [189] = "atmRadio", [190] = "imt", [191] = "mvl", [192] = "reachDSL",
  [193] = "frDlciEndPt", [194] = "atmVciEndPt", [195] = "opticalChannel",
  [196] = "opticalTransport", [197] = "propAtm", [198] = "voiceOverCable",
  [199] = "infiniband", [200] = "teLink", [201] = "q2931",
  [202] = "virtualTg", [203] = "sipTg", [204] = "sipSig",
  [205] = "docsCableUpstreamChannel", [206] = "econet", [207] = "pon155",
  [208] = "pon622", [209] = "bridge", [210] = "linegroup",
  [211] = "voiceEMFGD", [212] = "voiceFGDEANA", [213] = "voiceDID",
  [214] = "mpegTransport", [215] = "sixToFour", [216] = "gtp",
  [217] = "pdnEtherLoop1", [218] = "pdnEtherLoop2",
  [219] = "opticalChannelGroup", [220] = "homepna", [221] = "gfp",
  [222] = "ciscoISLvlan", [223] = "actelisMetaLOOP", [224] = "fcipLink",
  [225] = "rpr", [226] = "qam", [227] = "lmp", [228] = "cblVectaStar",
  [229] = "docsCableMCmtsDownstream", [230] = "adsl2",
  [231] = "macSecControlledIF", [232] = "macSecUncontrolledIF",
  [233] = "aviciOpticalEther", [234] = "atmbond", [235] = "voiceFGDOS",
  [236] = "mocaVersion1", [237] = "ieee80216WMAN", [238] = "adsl2plus",
  [239] = "dvbRcsMacLayer", [240] = "dvbTdm", [241] = "dvbRcsTdma",
  [242] = "x86Laps", [243] = "wwanPP", [244] = "wwanPP2", [245] = "voiceEBS",
  [246] = "ifPwType", [247] = "ilan", [248] = "pip", [249] = "aluELP",
  [250] = "gpon", [251] = "vdsl2", [252] = "capwapDot11Profile",
  [253] = "capwapDot11Bss", [254] = "capwapWtpVirtualRadio", [255] = "bits",
  [256] = "docsCableUpstreamRfPort", [257] = "cableDownstreamRfPort",
  [258] = "vmwareVirtualNic", [259] = "ieee802154", [260] = "otnOdu",
  [261] = "otnOtu", [262] = "ifVfiType", [263] = "g9981", [264] = "g9982",
  [265] = "g9983", [266] = "aluEpon", [267] = "aluEponOnu",
  [268] = "aluEponPhysicalUni", [269] = "aluEponLogicalLink",
  [270] = "aluGponOnu", [271] = "aluGponPhysicalUni", [272] = "vmwareNicTeam",
  [277] = "docsOfdmDownstream", [278] = "docsOfdmaUpstream", [279] = "gfast",
  [280] = "sdci",
  [281] = "xboxWireless", [282] = "fastdsl", [283] = "docsCableScte55d1FwdOob",
  [284] = "docsCableScte55d1RetOob", [285] = "docsCableScte55d2DsOob",
  [286] = "docsCableScte55d2UsOob", [287] = "docsCableNdf", [288] = "docsCableNdr",
  [289] = "ptm", [290] = "ghn",
}

-- ifOperStatus values (RFC 2863).
local OPER_STATUS = {
  "up", "down", "testing", "unknown", "dormant", "notPresent", "lowerLayerDown",
}

-- A speed in bits per second as nmap writes it: "1 Gbps", "100 Mbps",
-- "64 Kbps".
local function speed(v)
  if v >= 1000000000 then return string.format("%.f Gbps", v / 1000000000) end
  if v >= 1000000 then return string.format("%.f Mbps", v / 1000000) end
  return string.format("%.f Kbps", v / 1000)
end

-- A byte count as nmap writes it: "1.27 Mb", "28.43 Kb".
local function traffic(v)
  if v >= 1000000000 then return string.format("%.2f Gb", v / 1000000000) end
  if v >= 1000000 then return string.format("%.2f Mb", v / 1000000) end
  return string.format("%.2f Kb", v / 1000)
end

-- The last arcs of `oid` after `prefix` ("1.3.6...2.5" under "...2" is "5").
local function index_of(oid, prefix)
  return oid:sub(#prefix + 2)
end

-- Walk one column: { [index] = variable }, the indexes in order, or nil
-- and a message when the agent does not answer.
local function column(s, base)
  local vars, err = s:walk(base)
  if not vars then return nil, err end
  local t, order = {}, {}
  for _, v in ipairs(vars) do
    local i = index_of(v.oid, base)
    if t[i] == nil then order[#order + 1] = i end
    t[i] = v
  end
  return t, order
end

local function num(v)
  if v and (math.type(v.value) == "integer" or math.type(v.value) == "float") then
    return v.value
  end
end

action = function(host, port)
  local s = fero.snmp.session(host, port)
  if not s then return nil end
  local cols, order = {}, nil
  for _, name in ipairs({ "descr", "type", "speed", "phys", "status", "rx", "tx" }) do
    local t, o = column(s, IF .. "." .. COLUMNS[name])
    if not t then
      -- No answer at all: nothing more to ask.
      if name == "descr" then
        s:close()
        return nil
      end
      t, o = {}, {}
    end
    cols[name] = t
    if not order or (#order == 0 and #o > 0) then order = o end
  end
  if #order == 0 then
    s:close()
    return nil
  end
  -- ipAddrTable: address (1), interface index (2) and netmask (3), each
  -- indexed by the address.
  local addrs = {}
  local ip_if = column(s, IP .. ".2")
  if ip_if then
    local ip_mask = column(s, IP .. ".3") or {}
    local ip_addr = column(s, IP .. ".1") or {}
    for idx, v in pairs(ip_if) do
      local ifindex = num(v)
      if ifindex then
        local key = tostring(math.tointeger(ifindex) or ifindex)
        local a = ip_addr[idx] and ip_addr[idx].value or idx
        local m = ip_mask[idx] and ip_mask[idx].value
        addrs[key] = addrs[key] or {}
        table.insert(addrs[key], { addr = a, mask = m, key = idx })
      end
    end
  end
  s:close()

  local verbose = fero.verbosity() >= 1
  local data, lines = {}, {}
  for _, i in ipairs(order) do
    local item = fero.output_table()
    local descr = cols.descr[i] and cols.descr[i].value
    if type(descr) == "string" and #descr > 0 then
      item.name = descr
    else
      item.name = "Interface " .. i
    end
    local entry = {}
    local ips = addrs[i] or {}
    table.sort(ips, function(a, b) return fero.snmp.compare(a.key, b.key) < 0 end)
    for _, a in ipairs(ips) do
      if a.mask then
        entry[#entry + 1] = string.format("IP address: %s  Netmask: %s", a.addr, a.mask)
        item.ip_addresses = item.ip_addresses or {}
        table.insert(item.ip_addresses, { address = a.addr, netmask = a.mask })
      end
    end
    local phys = cols.phys[i] and cols.phys[i].value
    if type(phys) == "string" and #phys > 0 then
      if #phys == 6 then
        local mac = fero.hex(phys, ":")
        item.mac = mac
        entry[#entry + 1] = string.format("MAC address: %s (%s)", mac,
          fero.mac_vendor(mac) or "Unknown")
      else
        entry[#entry + 1] = "MAC address: Unknown"
      end
    end
    local itype, ispeed = num(cols.type[i]), num(cols.speed[i])
    if itype then item.type = IFTYPE[itype] or "Unknown" end
    if ispeed then item.speed = speed(ispeed) end
    if itype and ispeed then
      entry[#entry + 1] = string.format("Type: %s  Speed: %s", item.type, item.speed)
    end
    local st = num(cols.status[i])
    local status = st and OPER_STATUS[st]
    item.status = status
    if verbose and status then
      entry[#entry + 1] = "Status: " .. status
    end
    local rx, tx = num(cols.rx[i]), num(cols.tx[i])
    if rx then item.received = traffic(rx) end
    if tx then item.sent = traffic(tx) end
    if rx and tx then
      entry[#entry + 1] = string.format("Traffic stats: %s sent, %s received", item.sent,
        item.received)
    end
    if verbose or status == "up" then
      data[#data + 1] = item
      lines[#lines + 1] = "  " .. item.name
      for _, l in ipairs(entry) do lines[#lines + 1] = "    " .. l end
    end
  end
  if #data == 0 then return nil end
  return data, "\n" .. table.concat(lines, "\n")
end
