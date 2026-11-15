#!/usr/bin/env python3
"""nmap-diff: run nmap and FeroProbe with the same options and diff what they send.

For every case in matrix.txt it

  1. builds (once) a small lab of Linux network namespaces: a scanner, a target
     on the same link, and the same target one router hop away, with real
     open, closed and filtered TCP/UDP ports;
  2. runs nmap, then FeroProbe, with identical options inside the scanner
     namespace, capturing every interface there with tcpdump;
  3. turns each capture into the list of packets the scanner sent, and
     compares the two lists: which destinations (protocol/port) each tool
     touched, what the probes looked like (TCP flags, window, options,
     payload, fragmentation), how many there were, and whether anything went
     outside the ports and protocols that were asked for;
  4. compares the port states the two tools reported (from -oX);
  5. writes a Markdown report and a JSON file with every finding.

Nothing here fixes a difference. Each one is for a person to classify: a
FeroProbe bug, or a deliberate divergence (DEVELOPMENT.md). Findings that
match known-differences.txt are labelled as documented, not hidden.

Needs: Linux, root, iproute2, iptables (and ip6tables), tcpdump, nmap,
python3 (stdlib only). See README.md.
"""

import argparse
import collections
import datetime
import fnmatch
import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))

# --------------------------------------------------------------------------
# Lab layout
# --------------------------------------------------------------------------

NS_SCAN = "fpd-scan"
NS_RTR = "fpd-rtr"
NS_TGT = "fpd-tgt"

# scanner <-> target, same link
LAN_SCAN, LAN_TGT = "10.77.0.1", "10.77.0.2"
LAN6_SCAN, LAN6_TGT = "fd77::1", "fd77::2"
# scanner <-> router <-> target
B_SCAN, B_RTR = "10.79.0.1", "10.79.0.2"
C_RTR, C_TGT = "10.78.0.1", "10.78.0.2"

TARGETS = {
    "lan": LAN_TGT,
    "lan6": LAN6_TGT,
    "routed": C_TGT,
    "local": "127.0.0.1",
}

TCP_OPEN = [22, 80, 8080]
TCP_CLOSED = [443, 3389]
TCP_FILTERED = [8443]
UDP_OPEN = [53]
UDP_CLOSED = [123, 137]
UDP_FILTERED = [161]
TCP_PORTS = sorted(TCP_OPEN + TCP_CLOSED + TCP_FILTERED)
UDP_PORTS = sorted(UDP_OPEN + UDP_CLOSED + UDP_FILTERED)

SCAN_IFACES = ["lo", "fpd-a0", "fpd-b0"]


def sh(cmd, check=True, **kw):
    """Run a command (list or string), return CompletedProcess."""
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    return subprocess.run(cmd, check=check, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, **kw)


def nsx(ns, cmd, check=True):
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    return sh(["ip", "netns", "exec", ns] + cmd, check=check)


class Lab:
    def __init__(self, workdir):
        self.workdir = workdir
        self.procs = []
        self.ipv6 = True

    def down(self):
        for p in self.procs:
            if p.poll() is None:
                p.kill()
        self.procs = []
        for ns in (NS_SCAN, NS_RTR, NS_TGT):
            sh(["ip", "netns", "del", ns], check=False)

    def up(self):
        self.down()
        for ns in (NS_SCAN, NS_RTR, NS_TGT):
            sh(["ip", "netns", "add", ns])
            nsx(ns, "ip link set lo up")
            for knob in ("net.ipv4.icmp_ratelimit=0", "net.ipv6.icmp.ratelimit=0"):
                nsx(ns, ["sysctl", "-qw", knob], check=False)
        # link A: scanner <-> target
        sh(f"ip link add fpd-a0 netns {NS_SCAN} type veth peer name fpd-a1 netns {NS_TGT}")
        # link B: scanner <-> router, link C: router <-> target
        sh(f"ip link add fpd-b0 netns {NS_SCAN} type veth peer name fpd-b1 netns {NS_RTR}")
        sh(f"ip link add fpd-c0 netns {NS_RTR} type veth peer name fpd-c1 netns {NS_TGT}")
        for ns, dev, a4, a6 in (
            (NS_SCAN, "fpd-a0", LAN_SCAN, LAN6_SCAN),
            (NS_TGT, "fpd-a1", LAN_TGT, LAN6_TGT),
            (NS_SCAN, "fpd-b0", B_SCAN, None),
            (NS_RTR, "fpd-b1", B_RTR, None),
            (NS_RTR, "fpd-c0", C_RTR, None),
            (NS_TGT, "fpd-c1", C_TGT, None),
        ):
            nsx(ns, f"ip addr add {a4}/24 dev {dev}")
            if a6 and self.ipv6:
                if nsx(ns, f"ip -6 addr add {a6}/64 dev {dev} nodad", check=False).returncode != 0:
                    self.ipv6 = False
            nsx(ns, f"ip link set {dev} up")
        nsx(NS_SCAN, f"ip route add default via {B_RTR}")
        nsx(NS_TGT, f"ip route add 10.79.0.0/24 via {C_RTR}")
        nsx(NS_RTR, "sysctl -qw net.ipv4.ip_forward=1")
        # Filtered ports: dropped silently on the target and on loopback.
        for ns, iface in ((NS_TGT, None), (NS_SCAN, "lo")):
            for tool in ("iptables", "ip6tables"):
                for proto, ports in (("tcp", TCP_FILTERED), ("udp", UDP_FILTERED)):
                    for port in ports:
                        rule = [tool, "-A", "INPUT", "-p", proto, "--dport", str(port), "-j", "DROP"]
                        if iface:
                            rule[3:3] = ["-i", iface]
                        nsx(ns, rule, check=tool == "iptables")
        listener = os.path.join(HERE, "listeners.py")
        self._spawn(NS_TGT, [sys.executable, "-I", listener, "0.0.0.0"] + (["::"] if self.ipv6 else []))
        self._spawn(NS_SCAN, [sys.executable, "-I", listener, "127.0.0.1"])
        time.sleep(0.5)

    def _spawn(self, ns, cmd):
        p = subprocess.Popen(["ip", "netns", "exec", ns] + cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        line = p.stdout.readline()
        if "ready" not in line:
            raise RuntimeError(f"listeners in {ns} failed to start: {line}")
        self.procs.append(p)

    def scanner_macs(self):
        macs = set()
        for dev in ("fpd-a0", "fpd-b0"):
            out = nsx(NS_SCAN, f"cat /sys/class/net/{dev}/address").stdout.strip()
            macs.add(out.lower())
        return macs

    def flush_neighbours(self):
        for ns in (NS_SCAN, NS_RTR, NS_TGT):
            nsx(ns, "ip neigh flush all", check=False)
            nsx(ns, "ip -6 neigh flush all", check=False)


# --------------------------------------------------------------------------
# Capture
# --------------------------------------------------------------------------


class Capture:
    """tcpdump on every scanner-namespace interface, one pcap per interface."""

    def __init__(self, outdir, tag):
        self.outdir = outdir
        self.tag = tag
        self.procs = []
        self.files = {}

    def start(self):
        for iface in SCAN_IFACES:
            path = os.path.join(self.outdir, f"{self.tag}.{iface}.pcap")
            p = subprocess.Popen(
                ["ip", "netns", "exec", NS_SCAN, "tcpdump", "-i", iface, "-s", "0", "-U", "-n",
                 "--immediate-mode", "-w", path],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            self.procs.append(p)
            self.files[iface] = path
        # wait until every tcpdump says it is listening
        for p in self.procs:
            deadline = time.time() + 10
            while time.time() < deadline:
                line = p.stderr.readline()
                if "listening on" in line or not line:
                    break
        time.sleep(0.3)

    def stop(self):
        time.sleep(1.0)  # let late replies and last probes land
        for p in self.procs:
            p.send_signal(signal.SIGINT)
        for p in self.procs:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
        # tcpdump runs as root but may drop privileges; make sure we can read
        return self.files


# --------------------------------------------------------------------------
# pcap parsing (stdlib only)
# --------------------------------------------------------------------------

TCP_FLAG_NAMES = [(0x01, "F"), (0x02, "S"), (0x04, "R"), (0x08, "P"), (0x10, "A"), (0x20, "U"), (0x40, "E"), (0x80, "C")]

ICMP4_NAMES = {
    (0, None): "echo-reply", (3, None): "unreachable", (8, None): "echo-request",
    (11, None): "time-exceeded", (13, None): "timestamp-request", (14, None): "timestamp-reply",
    (17, None): "mask-request", (18, None): "mask-reply",
}
ICMP4_REPLIES = {0, 3, 4, 5, 11, 12, 14, 16, 18}
ICMP6_NAMES = {
    1: "unreachable", 2: "packet-too-big", 3: "time-exceeded", 4: "param-problem",
    128: "echo-request", 129: "echo-reply", 133: "router-solicit", 134: "router-advert",
    135: "neighbour-solicit", 136: "neighbour-advert", 143: "mld2-report",
}
ICMP6_REPLIES = {1, 2, 3, 4, 129, 136}
# Kernel chatter on interface bring-up, not caused by either scanner.
ICMP6_NOISE = {130, 131, 132, 133, 143}


def tcp_flags(b):
    s = "".join(n for bit, n in TCP_FLAG_NAMES if b & bit)
    return s or "none"


def payload_label(data):
    """A stable, readable name for a payload: size, preview and a short hash."""
    if not data:
        return "-"
    n = len(data)
    h = hashlib.sha1(data).hexdigest()[:6]
    printable = sum(1 for c in data if 32 <= c < 127 or c in (9, 10, 13))
    if printable >= 0.8 * n:
        text = data[:28].decode("ascii", "replace")
        text = text.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
        preview = repr(text)[1:-1]
        if n > 28:
            preview += "..."
        return f"{n}B '{preview}' #{h}"
    if len(set(data)) == 1:
        return f"{n}B x{data[0]:02x} #{h}"
    preview = data[:10].hex()
    return f"{n}B hex:{preview}{'...' if n > 10 else ''} #{h}"


def tcp_options(opts):
    out = []
    i = 0
    while i < len(opts):
        kind = opts[i]
        if kind == 0:
            out.append("EOL")
            break
        if kind == 1:
            out.append("N")
            i += 1
            continue
        if i + 1 >= len(opts):
            break
        ln = opts[i + 1]
        val = opts[i + 2:i + ln] if ln >= 2 else b""
        if kind == 2 and len(val) == 2:
            out.append(f"M{struct.unpack('!H', val)[0]}")
        elif kind == 3 and len(val) == 1:
            out.append(f"W{val[0]}")
        elif kind == 4:
            out.append("S")
        elif kind == 8:
            out.append("T")
        else:
            out.append(f"K{kind}")
        if ln < 2:
            break
        i += ln
    return ",".join(out) or "-"


def read_pcap(path):
    """Yield (ts, linktype, frame bytes) from a classic pcap file."""
    with open(path, "rb") as f:
        hdr = f.read(24)
        if len(hdr) < 24:
            return
        magic = hdr[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            endian = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            endian = ">"
        else:
            raise ValueError(f"{path}: not a pcap file")
        nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        linktype = struct.unpack(endian + "I", hdr[20:24])[0] & 0x0FFFFFFF
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                return
            sec, frac, incl, _ = struct.unpack(endian + "IIII", rec)
            data = f.read(incl)
            yield sec + frac / (1e9 if nano else 1e6), linktype, data


class Packet:
    """One captured frame, decoded far enough to compare probes."""

    __slots__ = ("ts", "iface", "src_mac", "l3", "src", "dst", "proto", "sport", "dport",
                 "kind", "fields", "ttl", "df", "frag", "reply", "noise", "ipid", "fragkey", "raw_l4")

    def __init__(self):
        self.ts = 0.0
        self.iface = ""
        self.src_mac = None
        self.l3 = None
        self.src = self.dst = None
        self.proto = None
        self.sport = self.dport = None
        self.kind = None
        self.fields = {}
        self.ttl = None
        self.df = None
        self.frag = None
        self.reply = False
        self.noise = False
        self.ipid = None
        self.fragkey = None
        self.raw_l4 = None


def decode_l4(p, proto, l4):
    """Fill kind/ports/fields from a transport header + payload."""
    p.proto = proto
    if proto == 6 and len(l4) >= 20:
        sport, dport, _seq, _ack, off, flags, win = struct.unpack("!HHIIBBH", l4[:16])
        hl = (off >> 4) * 4
        p.sport, p.dport = sport, dport
        p.kind = "tcp"
        p.fields = {
            "flags": tcp_flags(flags),
            "win": str(win),
            "opts": tcp_options(l4[20:hl]),
            "payload": payload_label(l4[hl:]),
        }
        # an answer from a port to a scanner, by flags alone, only matters on lo
        return
    if proto == 17 and len(l4) >= 8:
        sport, dport = struct.unpack("!HH", l4[:4])
        p.sport, p.dport = sport, dport
        p.kind = "udp"
        p.fields = {"payload": payload_label(l4[8:])}
        return
    if proto == 132 and len(l4) >= 12:
        sport, dport = struct.unpack("!HH", l4[:4])
        p.sport, p.dport = sport, dport
        p.kind = "sctp"
        chunks = []
        i = 12
        while i + 4 <= len(l4):
            ctype, _cfl, clen = struct.unpack("!BBH", l4[i:i + 4])
            chunks.append({1: "INIT", 2: "INIT-ACK", 6: "ABORT", 10: "COOKIE-ECHO", 11: "COOKIE-ACK"}.get(ctype, f"type{ctype}"))
            if clen < 4:
                break
            i += (clen + 3) & ~3
        p.fields = {"chunks": "+".join(chunks) or "-", "payload": payload_label(l4[12:])}
        return
    if proto == 1 and len(l4) >= 4:
        t, c = l4[0], l4[1]
        p.kind = "icmp"
        p.fields = {"type": ICMP4_NAMES.get((t, None), f"type{t}"), "code": str(c), "payload": payload_label(l4[8:])}
        p.reply = t in ICMP4_REPLIES
        return
    if proto == 58 and len(l4) >= 4:
        t, c = l4[0], l4[1]
        p.kind = "icmp6"
        p.fields = {"type": ICMP6_NAMES.get(t, f"type{t}"), "code": str(c), "payload": payload_label(l4[8:])}
        p.reply = t in ICMP6_REPLIES
        p.noise = t in ICMP6_NOISE
        return
    p.kind = "ip"
    p.fields = {"payload": payload_label(l4)}


def decode_frame(linktype, frame):
    """Return a Packet, or None for frames we do not care about."""
    p = Packet()
    if linktype == 1:  # Ethernet
        if len(frame) < 14:
            return None
        p.src_mac = ":".join(f"{b:02x}" for b in frame[6:12])
        etype = struct.unpack("!H", frame[12:14])[0]
        l3 = frame[14:]
    elif linktype == 0:  # BSD loopback (not used on Linux)
        etype, l3 = 0x0800, frame[4:]
    elif linktype == 113:  # Linux cooked
        etype, l3 = struct.unpack("!H", frame[14:16])[0], frame[16:]
    else:
        return None
    if etype == 0x0806 and len(l3) >= 28:
        op = struct.unpack("!H", l3[6:8])[0]
        p.l3 = "arp"
        p.kind = "arp"
        p.src = socket.inet_ntoa(l3[14:18])
        p.dst = socket.inet_ntoa(l3[24:28])
        p.fields = {"op": {1: "who-has", 2: "is-at"}.get(op, f"op{op}")}
        p.reply = op == 2
        return p
    if etype == 0x0800 and len(l3) >= 20:
        ihl = (l3[0] & 0x0F) * 4
        total = struct.unpack("!H", l3[2:4])[0]
        ipid = struct.unpack("!H", l3[4:6])[0]
        fl_off = struct.unpack("!H", l3[6:8])[0]
        p.l3 = "ip4"
        p.ttl = l3[8]
        p.ipid = ipid
        p.df = bool(fl_off & 0x4000)
        mf = bool(fl_off & 0x2000)
        off = (fl_off & 0x1FFF) * 8
        proto = l3[9]
        p.src = socket.inet_ntoa(l3[12:16])
        p.dst = socket.inet_ntoa(l3[16:20])
        l4 = l3[ihl:total] if total else l3[ihl:]
        if mf or off:
            p.frag = (off, len(l4), mf)
            p.fragkey = (p.src, p.dst, ipid, proto)
            p.proto = proto
            p.raw_l4 = l4
            p.kind = "fragment"
            return p
        decode_l4(p, proto, l4)
        return p
    if etype == 0x86DD and len(l3) >= 40:
        p.l3 = "ip6"
        p.ttl = l3[7]
        nxt = l3[6]
        p.src = socket.inet_ntop(socket.AF_INET6, l3[8:24])
        p.dst = socket.inet_ntop(socket.AF_INET6, l3[24:40])
        rest = l3[40:]
        # walk hop-by-hop / routing / destination / fragment headers
        while nxt in (0, 43, 60, 44) and len(rest) >= 8:
            if nxt == 44:
                fo = struct.unpack("!H", rest[2:4])[0]
                ident = struct.unpack("!I", rest[4:8])[0]
                off, mf = (fo & 0xFFF8), bool(fo & 1)
                p.frag = (off, len(rest) - 8, mf)
                p.fragkey = (p.src, p.dst, ident, rest[0])
                p.proto = rest[0]
                p.raw_l4 = rest[8:]
                p.kind = "fragment"
                return p
            nxt, ln = rest[0], (rest[1] + 1) * 8
            rest = rest[ln:]
        decode_l4(p, nxt, rest)
        return p
    return None


def reassemble(packets):
    """Merge IPv4/IPv6 fragments back into one Packet, noting the fragment sizes."""
    out = []
    groups = []  # lists of fragments, one per datagram
    open_group = {}  # fragkey -> index into groups
    for p in packets:
        if p.kind != "fragment":
            out.append(p)
            continue
        idx = open_group.get(p.fragkey)
        # A repeated offset under the same IP ID is a new datagram (a
        # retransmission that reused the ID), not part of the open one.
        if idx is None or any(f.frag[0] == p.frag[0] for f in groups[idx]):
            groups.append([])
            idx = open_group[p.fragkey] = len(groups) - 1
        groups[idx].append(p)
    for frags in groups:
        frags.sort(key=lambda f: f.frag[0])
        data = b""
        ok = True
        for f in frags:
            off, _ln, _mf = f.frag
            if off != len(data):
                ok = False
                break
            data += f.raw_l4
        first = frags[0]
        q = Packet()
        for attr in ("ts", "iface", "src_mac", "l3", "src", "dst", "ttl", "df", "ipid"):
            setattr(q, attr, getattr(first, attr))
        if ok and not frags[-1].frag[2]:
            decode_l4(q, first.proto, data)
        else:
            q.kind = "ip"
            q.proto = first.proto
            q.fields = {"payload": "incomplete fragments"}
        q.frag = "frags " + "+".join(str(f.frag[1]) for f in frags)
        out.append(q)
    out.sort(key=lambda p: p.ts)
    return out


def load_sent(files, scanner_macs):
    """Packets the scanner sent, from the per-interface captures."""
    packets = []
    for iface, path in files.items():
        if not os.path.exists(path):
            continue
        for ts, lt, frame in read_pcap(path):
            p = decode_frame(lt, frame)
            if p is None:
                continue
            p.ts, p.iface = ts, iface
            packets.append(p)
    packets.sort(key=lambda p: p.ts)
    packets = reassemble(packets)
    sent = []
    initiators = {}  # flow -> direction of its first packet (lo only)
    for p in packets:
        if p.noise:
            continue
        if p.iface == "lo":
            # Both ends live on lo: the side that opened a flow is the scanner.
            if p.kind in ("icmp", "icmp6"):
                if p.reply:
                    continue
            elif p.sport is not None:
                fwd = (p.kind, p.src, p.sport, p.dst, p.dport)
                rev = (p.kind, p.dst, p.dport, p.src, p.sport)
                if rev in initiators:
                    continue
                initiators.setdefault(fwd, True)
            sent.append(p)
        else:
            if p.src_mac in scanner_macs:
                sent.append(p)
    return sent


# --------------------------------------------------------------------------
# Options -> scope
# --------------------------------------------------------------------------


def expand_ports(spec):
    """'22,80-82' -> {22,80,81,82}"""
    out = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            out.update(range(int(a or 1), int(b or 65535) + 1))
        else:
            out.add(int(part))
    return out


def parse_port_spec(spec, default_proto):
    """nmap -p syntax with T:/U:/S:/P: prefixes -> {proto: set(ports)}"""
    res = collections.defaultdict(set)
    proto = None
    for item in spec.split(","):
        item = item.strip()
        m = re.match(r"^([TUSP]):(.*)$", item)
        if m:
            proto = {"T": "tcp", "U": "udp", "S": "sctp", "P": "ip"}[m.group(1)]
            item = m.group(2)
        if not item:
            continue
        targets = [proto] if proto else default_proto
        for t in targets:
            res[t] |= expand_ports(item)
    return res


def expand_macros(opts):
    tcp = ",".join(map(str, TCP_PORTS))
    udp = ",".join(map(str, UDP_PORTS))
    return opts.replace("@ALL", f"T:{tcp},U:{udp}").replace("@TCP", tcp).replace("@UDP", udp)


def scope_of(argv, target_kind, privileged):
    """Which (proto, port) a scan with these options is asked to touch.

    Returns {proto: set(ports)} or None when the port list is not explicit
    (-F, --top-ports, the default 1000) and scope cannot be checked.
    """
    scans = set()
    ports = None
    pn = sn = False
    ping = collections.defaultdict(set)
    explicit_ping = False
    i = 0
    while i < len(argv):
        a = argv[i]
        nxt = argv[i + 1] if i + 1 < len(argv) else ""
        if a in ("-p", "--ports"):
            ports = nxt
            i += 2
            continue
        if a.startswith("-p") and len(a) > 2 and not a.startswith("-P"):
            ports = a[2:]
        if a in ("-F",) or a == "--top-ports":
            return None
        if a.startswith("-s") and len(a) >= 3:
            for ch in a[2:]:
                scans.add(ch)
        if a == "--scanflags":
            scans.add("S")
        if a == "-Pn":
            pn = True
        if a == "-sn":
            sn = True
        m = re.match(r"^-P([SAUY])(.*)$", a)
        if m:
            explicit_ping = True
            proto = {"S": "tcp", "A": "tcp", "U": "udp", "Y": "sctp"}[m.group(1)]
            default = {"S": "80", "A": "80", "U": "40125", "Y": "80"}[m.group(1)]
            ping[proto] |= expand_ports(m.group(2) or default)
        if re.match(r"^-P[EPM]$", a):
            explicit_ping = True
        i += 1
    if "n" in scans:
        sn = True
    scope = collections.defaultdict(set)
    if not sn:
        if ports is None:
            return None
        protos = []
        if scans & set("STAWMFNX") or not scans - {"V", "C", "n"}:
            protos.append("tcp")
        if "U" in scans:
            protos.append("udp")
        if scans & set("YZ"):
            protos.append("sctp")
        if "O" in scans:
            protos = ["ip"]
        for proto, ps in parse_port_spec(ports, protos).items():
            if proto in protos or (proto == "ip" and "O" in scans):
                scope[proto] |= ps
    if not pn:
        for proto, ps in ping.items():
            scope[proto] |= ps
        ip_discovery = target_kind in ("routed", "local") or not privileged or \
            "--send-ip" in argv or "--disable-arp-ping" in argv
        if not explicit_ping and ip_discovery:
            scope["tcp"] |= {80, 443}
    return dict(scope)


# --------------------------------------------------------------------------
# Running the tools
# --------------------------------------------------------------------------


def run_tool(tool, binary, argv, target, privileged, outdir, tag, timeout, unpriv_bin):
    xml = os.path.join(outdir, f"{tag}.xml")
    cmd = [binary] + argv + ["-oX", xml, target]
    if not privileged:
        os.chmod(outdir, 0o777)
        cmd = ["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups", "--inh-caps=-all", "--"] + \
            ([unpriv_bin] if tool == "feroprobe" else [binary]) + argv + ["-oX", xml, target]
    full = ["ip", "netns", "exec", NS_SCAN] + cmd
    t0 = time.time()
    try:
        r = subprocess.run(full, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout,
                           env={**os.environ, "HOME": "/tmp"})
        out, code = r.stdout, r.returncode
    except subprocess.TimeoutExpired as e:
        out, code = (e.stdout or b"").decode() if isinstance(e.stdout, bytes) else (e.stdout or ""), "timeout"
    elapsed = time.time() - t0
    with open(os.path.join(outdir, f"{tag}.out"), "w") as f:
        f.write("$ " + shlex.join(cmd) + "\n" + out)
    return {"cmd": shlex.join([tool] + argv + [target]), "exit": code, "seconds": round(elapsed, 2),
            "output": out, "xml": xml}


def parse_xml_ports(path):
    """{'tcp/22': 'open ssh', ...} plus host state, from nmap-style XML."""
    import xml.etree.ElementTree as ET
    res = {}
    host_state = "no host"
    try:
        root = ET.parse(path).getroot()
    except Exception as e:  # noqa: BLE001
        return {"error": f"unreadable XML: {e}"}, "?"
    for host in root.iter("host"):
        st = host.find("status")
        if st is not None:
            host_state = st.get("state", "?")
        for port in host.iter("port"):
            key = f"{port.get('protocol')}/{port.get('portid')}"
            state = port.find("state")
            svc = port.find("service")
            s = state.get("state") if state is not None else "?"
            if svc is not None and svc.get("name"):
                s += " " + svc.get("name")
            res[key] = s
        for extra in host.iter("extraports"):
            res[f"other {extra.get('state')}"] = extra.get("count")
    return res, host_state


# --------------------------------------------------------------------------
# Comparing
# --------------------------------------------------------------------------


def dest_key(p, target):
    if p.kind == "arp":
        if p.reply:
            return f"arp is-at {p.src} (scanner kernel)"
        return f"arp {p.fields['op']} {p.dst}"
    if p.kind in ("tcp", "udp", "sctp"):
        k = f"{p.kind}/{p.dport}"
    elif p.kind in ("icmp", "icmp6") and p.reply:
        # The scanner host's kernel answering something (e.g. port
        # unreachable for a reply to a raw probe): a side effect, not a probe.
        k = f"{p.kind} {p.fields['type']} (scanner kernel)"
    elif p.kind in ("icmp", "icmp6"):
        k = f"{p.kind} {p.fields['type']}"
    else:
        k = f"ip proto {p.proto}"
    if p.dst and p.dst != target and not (p.kind == "icmp6" and p.fields.get("type") == "neighbour-solicit"):
        k += f" to {p.dst}"
    return k


def summarise(sent, target):
    """dest -> {'count': n, 'fields': {field: Counter(values)}}"""
    dests = collections.OrderedDict()
    ttl = collections.Counter()
    df = collections.Counter()
    for p in sent:
        k = dest_key(p, target)
        d = dests.setdefault(k, {"count": 0, "fields": collections.defaultdict(collections.Counter)})
        d["count"] += 1
        # TCP fields are grouped by flags, so a SYN probe is compared with a
        # SYN probe and not with the RST the kernel sends afterwards.
        pre = f"[{p.fields['flags']}] " if p.kind == "tcp" else ""
        for f, v in p.fields.items():
            if p.kind == "arp" and f == "op":
                continue
            if p.kind in ("icmp", "icmp6") and f == "type":
                continue
            if p.kind == "tcp" and f == "flags":
                d["fields"]["flags"][v] += 1
                continue
            d["fields"][pre + f][v] += 1
        if p.frag:
            d["fields"][pre + "frag"][p.frag] += 1
        if p.l3 in ("ip4", "ip6"):
            d["fields"][pre + "df" if p.l3 == "ip4" else "ip6"][("DF" if p.df else "no DF") if p.l3 == "ip4" else "-"] += 1
            if p.ttl is not None:
                ttl[p.ttl] += 1
            if p.l3 == "ip4":
                df[p.df] += 1
    for d in dests.values():
        d["fields"].pop("ip6", None)
    return dests, ttl


def in_scope(dest, scope):
    """None = cannot tell / not a port; True / False otherwise."""
    if scope is None:
        return None
    m = re.match(r"^(tcp|udp|sctp)/(\d+)$", dest)
    if m:
        return int(m.group(2)) in scope.get(m.group(1), set())
    m = re.match(r"^ip proto (\d+)$", dest)
    if m and "ip" in scope:
        return int(m.group(1)) in scope["ip"]
    return None


def fmt_counter(c):
    return ", ".join(f"{v} x{n}" if n > 1 else str(v) for v, n in sorted(c.items(), key=lambda kv: (-kv[1], str(kv[0]))))


def compare(case, n_sum, f_sum, scope, n_ports, f_ports):
    findings = []

    def add(sev, dest, text, detail=None):
        findings.append({"case": case, "severity": sev, "dest": dest, "text": text, "detail": detail})

    all_dests = list(n_sum.keys()) + [k for k in f_sum.keys() if k not in n_sum]
    for dest in all_dests:
        n, f = n_sum.get(dest), f_sum.get(dest)
        sc = in_scope(dest, scope)
        if sc is False:
            who = "both tools" if n and f else ("nmap only" if n else "FeroProbe only")
            add("out-of-scope", dest, f"{dest} was not asked for, but {who} sent to it "
                f"(nmap {n['count'] if n else 0}, FeroProbe {f['count'] if f else 0} packets)")
        if dest.endswith("(scanner kernel)"):
            if (n["count"] if n else 0) != (f["count"] if f else 0):
                add("side-effect", dest, f"{dest}: nmap run {n['count'] if n else 0}, FeroProbe run {f['count'] if f else 0}")
            continue
        if n and not f:
            add("only-nmap", dest, f"only nmap sent to {dest}: {n['count']} packet(s), "
                + "; ".join(f"{k} {fmt_counter(v)}" for k, v in n["fields"].items()))
            continue
        if f and not n:
            add("only-feroprobe", dest, f"only FeroProbe sent to {dest}: {f['count']} packet(s), "
                + "; ".join(f"{k} {fmt_counter(v)}" for k, v in f["fields"].items()))
            continue
        shape = False
        groups_n = {k.split("] ")[0] + "]" for k in n["fields"] if k.startswith("[")}
        groups_f = {k.split("] ")[0] + "]" for k in f["fields"] if k.startswith("[")}
        for g in sorted(groups_n ^ groups_f):
            side, who = (n, "nmap") if g in groups_n else (f, "FeroProbe")
            cnt = side["fields"]["flags"][g[1:-1]]
            desc = "; ".join(f"{k[len(g) + 1:]} {fmt_counter(v)}" for k, v in side["fields"].items() if k.startswith(g + " "))
            shape = True
            add("shape", dest, f"{dest} {g}: only {who} sent these ({cnt}): {desc}",
                detail=f"{g}: only {who} sent these: " + re.sub(r" x\d+", "", desc))
        for field in sorted(set(n["fields"]) | set(f["fields"])):
            if field == "flags" and (groups_n or groups_f):
                continue
            if field.startswith("[") and field.split("] ")[0] + "]" not in (groups_n & groups_f):
                continue
            nv, fv = n["fields"].get(field, collections.Counter()), f["fields"].get(field, collections.Counter())
            if set(nv) != set(fv):
                shape = True
                add("shape", dest, f"{dest} {field}: nmap [{fmt_counter(nv)}] vs FeroProbe [{fmt_counter(fv)}]",
                    detail=f"{field}: nmap [{', '.join(sorted(map(str, nv)))}] vs FeroProbe [{', '.join(sorted(map(str, fv)))}]")
        if not shape and n["count"] != f["count"]:
            add("count", dest, f"{dest}: nmap sent {n['count']}, FeroProbe {f['count']}")

    # exit status
    if str(n_ports.get("_exit")) != str(f_ports.get("_exit")):
        add("result", "exit", f"exit status: nmap {n_ports.get('_exit')}, FeroProbe {f_ports.get('_exit')}")
    n_ports = {k: v for k, v in n_ports.items() if k != "_exit"}
    f_ports = {k: v for k, v in f_ports.items() if k != "_exit"}
    # results
    for key in sorted(set(n_ports) | set(f_ports)):
        a, b = n_ports.get(key, "(not listed)"), f_ports.get(key, "(not listed)")
        if a != b:
            add("result", key, f"{key}: nmap reports '{a}', FeroProbe '{b}'")
    return findings


def load_known(path):
    known = []
    if not os.path.exists(path):
        return known
    with open(path) as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            parts = [x.strip() for x in line.split("|", 2)]
            if len(parts) != 3:
                continue
            known.append((parts[0], re.compile(parts[1]), parts[2]))
    return known


def annotate(findings, known):
    for f in findings:
        for glob, rx, note in known:
            if fnmatch.fnmatch(f["case"], glob) and rx.search(f["text"]):
                f["known"] = note
                break


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------

SEV_ORDER = ["out-of-scope", "only-nmap", "only-feroprobe", "shape", "result", "count", "side-effect"]
SEV_TITLE = {
    "out-of-scope": "Sent outside the requested ports",
    "only-nmap": "Only nmap sent this",
    "only-feroprobe": "Only FeroProbe sent this",
    "shape": "Different probe contents",
    "result": "Different results",
    "count": "Different packet counts",
    "side-effect": "Different reactions from the scanner host's kernel",
}


def group_findings(items):
    """Fold findings that say the same thing about several ports into one line."""
    out = []
    by_detail = collections.OrderedDict()
    for f in items:
        if f.get("detail"):
            by_detail.setdefault(f["detail"], []).append(f)
        else:
            out.append((f["text"], f.get("known")))
    for detail, fs in by_detail.items():
        known = fs[0].get("known") if all(x.get("known") for x in fs) else None
        if len(fs) == 1:
            out.append((fs[0]["text"], known))
            continue
        dests = sorted({x["dest"] for x in fs}, key=lambda d: (re.sub(r"\d+", "", d), int(re.sub(r"\D", "", d) or 0)))
        shown = ", ".join(dests[:12]) + (f" and {len(dests) - 12} more" if len(dests) > 12 else "")
        out.append((f"{shown} ({len(dests)} destinations) {detail}", known))
    return out


def md_escape(s):
    return s.replace("|", "\\|")


def write_report(path, meta, results):
    L = []
    L.append("# nmap vs FeroProbe: differential report")
    L.append("")
    L.append(f"- Run: {meta['when']}")
    L.append(f"- nmap: {meta['nmap_version']}" + (f" (pinned: {meta['pinned']}" + (", MISMATCH" if meta['pin_mismatch'] else "") + ")" if meta.get('pinned') else ""))
    L.append(f"- FeroProbe: {meta['fero_version']} ({meta['fero_commit']})")
    L.append(f"- Base options for every case: `{meta['base_opts']}`")
    L.append(f"- Lab: TCP open {TCP_OPEN}, closed {TCP_CLOSED}, filtered {TCP_FILTERED}; "
             f"UDP open {UDP_OPEN}, closed {UDP_CLOSED}, filtered {UDP_FILTERED}")
    L.append("")
    L.append("Each case runs both tools with the same options and compares the packets they sent. "
             "The summary counts report lines, after folding identical findings for several ports into one. "
             "Severities: **out-of-scope** (a port nobody asked for), **only-nmap** / **only-feroprobe** "
             "(a destination one tool never touched), **shape** (same destination, different probe "
             "contents), **result** (different exit status, reported port state or service), **count** "
             "(same probes, different number), **side-effect** (ICMP errors the scanner host's own kernel sent, "
             "usually in answer to replies a raw-socket scan did not consume). Findings marked *documented* match "
             "`known-differences.txt`.")
    L.append("")
    L.append("## Summary")
    L.append("")
    L.append("| Case | Options | nmap pkts / s | FeroProbe pkts / s | " + " | ".join(SEV_ORDER) + " |")
    L.append("| --- | --- | --- | --- | " + " | ".join("---" for _ in SEV_ORDER) + " |")
    for r in results:
        if r.get("skipped"):
            L.append(f"| {r['case']} | `{md_escape(r['opts'])}` ({r['target']}, {r['priv']}) | skipped: {r['skipped']} | | "
                     + " | ".join("" for _ in SEV_ORDER) + " |")
            continue
        cnt, kn = collections.Counter(), collections.Counter()
        for sev in SEV_ORDER:
            for _text, known_note in group_findings([f for f in r["findings"] if f["severity"] == sev]):
                (kn if known_note else cnt)[sev] += 1
        cells = []
        for s in SEV_ORDER:
            c = str(cnt.get(s, 0) or "")
            if kn.get(s):
                c += f" (+{kn[s]} doc)" if c else f"({kn[s]} doc)"
            cells.append(c)
        L.append(f"| [{r['case']}](#{r['case']}) | `{md_escape(r['opts'])}` ({r['target']}, {r['priv']}) | "
                 f"{r['nmap']['packets']} / {r['nmap']['seconds']} | {r['fero']['packets']} / {r['fero']['seconds']} | "
                 + " | ".join(cells) + " |")
    L.append("")
    for r in results:
        if r.get("skipped"):
            continue
        L.append(f"## {r['case']}")
        L.append("")
        L.append(f"`{r['nmap']['cmd']}`  ")
        L.append(f"`{r['fero']['cmd']}`  ")
        L.append(f"Target: {r['target']} ({r['target_ip']}), privileges: {r['priv']}. "
                 f"Scope: {r['scope_text']}.")
        for tool in ("nmap", "fero"):
            if r[tool]["exit"] not in (0, "0"):
                name = "nmap" if tool == "nmap" else "FeroProbe"
                tail = "\n".join(r[tool]["output"].strip().splitlines()[-6:])
                L.append("")
                L.append(f"**{name} exited with {r[tool]['exit']}:**")
                L.append("```")
                L.append(tail)
                L.append("```")
        L.append("")
        if not r["findings"]:
            L.append("No differences.")
            L.append("")
            continue
        for sev in SEV_ORDER:
            items = [f for f in r["findings"] if f["severity"] == sev]
            if not items:
                continue
            L.append(f"**{SEV_TITLE[sev]}**")
            L.append("")
            for text, known_note in group_findings(items):
                note = f" — *documented: {known_note}*" if known_note else ""
                L.append(f"- {md_escape(text)}{note}")
            L.append("")
        L.append(f"TTLs used: nmap {r['nmap']['ttl']}; FeroProbe {r['fero']['ttl']}")
        L.append("")
    with open(path, "w") as fh:
        fh.write("\n".join(L) + "\n")


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------


def load_matrix(path):
    cases = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [x.strip() for x in line.split("|", 3)]
            if len(parts) != 4:
                raise SystemExit(f"bad matrix line: {line}")
            name, target, priv, opts = parts
            if target not in TARGETS:
                raise SystemExit(f"{name}: unknown target {target}")
            if priv not in ("root", "user"):
                raise SystemExit(f"{name}: privileges must be root or user")
            cases.append({"case": name, "target": target, "priv": priv, "opts": opts})
    return cases


def ttl_text(c):
    if not c:
        return "-"
    vals = sorted(c)
    if len(vals) <= 4:
        return ", ".join(str(v) for v in vals)
    return f"{vals[0]}-{vals[-1]} ({len(vals)} distinct)"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--feroprobe", default=os.path.join(REPO, "target", "release", "feroprobe"),
                    help="FeroProbe binary (default: target/release/feroprobe)")
    ap.add_argument("--nmap", default=shutil.which("nmap") or "nmap", help="nmap binary")
    ap.add_argument("--matrix", default=os.path.join(HERE, "matrix.txt"))
    ap.add_argument("--known", default=os.path.join(HERE, "known-differences.txt"))
    ap.add_argument("--cases", default="*", help="comma-separated globs of case names to run (default all)")
    ap.add_argument("--base-opts", default="-n -T4", help="options added to every case (default '-n -T4')")
    ap.add_argument("--out", default=os.path.join(REPO, "target", "nmap-diff"), help="output directory")
    ap.add_argument("--timeout", type=int, default=300, help="seconds per tool run (default 300)")
    ap.add_argument("--keep-lab", action="store_true", help="leave the namespaces up afterwards")
    ap.add_argument("--fail-on", default="", help="comma-separated severities that make the exit status 1 "
                    "(e.g. out-of-scope); documented findings never fail")
    args = ap.parse_args()

    if os.geteuid() != 0:
        raise SystemExit("nmap-diff needs root (network namespaces, raw sockets, tcpdump). Run it with sudo.")
    for tool in ("ip", "tcpdump", "iptables", "setpriv"):
        if not shutil.which(tool):
            raise SystemExit(f"missing tool: {tool}")
    if not os.access(args.feroprobe, os.X_OK):
        raise SystemExit(f"FeroProbe binary not found at {args.feroprobe} (cargo build --release)")
    if not shutil.which(args.nmap) and not os.access(args.nmap, os.X_OK):
        raise SystemExit("nmap not found")

    os.makedirs(args.out, exist_ok=True)
    raw = os.path.join(args.out, "raw")
    os.makedirs(raw, exist_ok=True)
    os.chmod(raw, 0o777)

    # an unprivileged user cannot always reach the repo's target dir
    unpriv_dir = tempfile.mkdtemp(prefix="fpd-bin-")
    os.chmod(unpriv_dir, 0o755)
    unpriv_bin = os.path.join(unpriv_dir, "feroprobe")
    shutil.copy2(args.feroprobe, unpriv_bin)
    os.chmod(unpriv_bin, 0o755)

    nmap_version = sh([args.nmap, "--version"]).stdout.splitlines()[0].strip()
    fero_version = sh([args.feroprobe, "--version"]).stdout.splitlines()[0].strip()
    commit = sh(["git", "-C", REPO, "rev-parse", "--short", "HEAD"], check=False).stdout.strip() or "?"
    pinned = None
    pin_file = os.path.join(HERE, "NMAP_VERSION")
    if os.path.exists(pin_file):
        pinned = open(pin_file).read().strip()
    m = re.search(r"Nmap version (\S+)", nmap_version)
    meta = {
        "when": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "nmap_version": m.group(1) if m else nmap_version,
        "pinned": pinned,
        "pin_mismatch": bool(pinned and m and not m.group(1).startswith(pinned)),
        "fero_version": fero_version,
        "fero_commit": commit,
        "base_opts": args.base_opts,
    }
    if meta["pin_mismatch"]:
        print(f"warning: nmap {meta['nmap_version']} is not the pinned {pinned}; differences may come from nmap",
              file=sys.stderr)

    globs = [g.strip() for g in args.cases.split(",") if g.strip()]
    cases = [c for c in load_matrix(args.matrix) if any(fnmatch.fnmatch(c["case"], g) for g in globs)]
    if not cases:
        raise SystemExit("no cases selected")
    known = load_known(args.known)

    lab = Lab(raw)
    results = []
    try:
        lab.up()
        macs = lab.scanner_macs()
        for c in cases:
            opts = expand_macros(c["opts"])
            base = shlex.split(args.base_opts)
            case_argv = shlex.split(opts)
            if any(re.match(r"^-T[0-5a-z]", a) for a in case_argv):
                # the case sets its own timing; do not pass -T twice
                base = [a for a in base if not re.match(r"^-T[0-5a-z]", a)]
            argv = base + case_argv
            target = TARGETS[c["target"]]
            priv = c["priv"] == "root"
            if c["target"] == "lan6" and not lab.ipv6:
                print(f"[{c['case']}] skipped: this host has no IPv6", flush=True)
                results.append({"case": c["case"], "opts": opts, "target": c["target"], "target_ip": target,
                                "priv": c["priv"], "skipped": "this host has no IPv6 stack"})
                continue
            print(f"[{c['case']}] {' '.join(argv)} {target} ({c['priv']})", flush=True)
            r = {"case": c["case"], "opts": opts, "target": c["target"], "target_ip": target, "priv": c["priv"]}
            sums = {}
            for tool, binary in (("nmap", args.nmap), ("fero", args.feroprobe)):
                lab.flush_neighbours()
                time.sleep(0.2)
                tag = f"{c['case']}.{tool}"
                cap = Capture(raw, tag)
                cap.start()
                run = run_tool("nmap" if tool == "nmap" else "feroprobe", binary, argv, target, priv, raw, tag,
                               args.timeout, unpriv_bin)
                files = cap.stop()
                sent = load_sent(files, macs)
                summary, ttl = summarise(sent, target)
                ports, host = parse_xml_ports(run["xml"])
                ports["host"] = host
                ports["_exit"] = run["exit"]
                sums[tool] = (summary, ports)
                r[tool] = {"cmd": run["cmd"], "exit": run["exit"], "seconds": run["seconds"],
                           "output": run["output"], "packets": len(sent), "ttl": ttl_text(ttl),
                           "dests": {k: {"count": v["count"], "fields": {f: dict(x) for f, x in v["fields"].items()}}
                                     for k, v in summary.items()},
                           "ports": ports}
            scope = scope_of(argv, c["target"], priv)
            r["scope_text"] = ("not checked (port list not explicit)" if scope is None else
                               "; ".join(f"{p} {','.join(map(str, sorted(v)))}" for p, v in sorted(scope.items())) or "none")
            r["findings"] = compare(c["case"], sums["nmap"][0], sums["fero"][0], scope, sums["nmap"][1], sums["fero"][1])
            annotate(r["findings"], known)
            results.append(r)
            sev = collections.Counter()
            for sv in SEV_ORDER:
                for _t, known_note in group_findings([f for f in r["findings"] if f["severity"] == sv]):
                    if not known_note:
                        sev[sv] += 1
            print("    " + (", ".join(f"{k} {v}" for k, v in sev.items()) or "no undocumented differences"), flush=True)
    finally:
        if not args.keep_lab:
            lab.down()
        shutil.rmtree(unpriv_dir, ignore_errors=True)

    report = os.path.join(args.out, "report.md")
    write_report(report, meta, results)
    with open(os.path.join(args.out, "report.json"), "w") as fh:
        json.dump({"meta": meta, "results": [{k: v for k, v in r.items()} for r in results]}, fh, indent=1, default=str)
    print(f"report: {report}")

    fail = {s.strip() for s in args.fail_on.split(",") if s.strip()}
    if fail and any(f["severity"] in fail and not f.get("known") for r in results for f in r.get("findings", [])):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
