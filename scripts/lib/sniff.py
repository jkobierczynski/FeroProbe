#!/usr/bin/env python3
"""Minimal packet logger for the scripts/test-*.sh option tests.

Records every IPv4 TCP/UDP/ICMP packet and every ARP packet seen on any
interface of the current network namespace, one line per packet, until it
gets SIGTERM:

    <time> <iface> <in|out> <proto> <src> <sport> <dst> <dport> <flags>

`flags` is the TCP flag string (S, SA, R, RA, ...), the ICMP type, the ARP
opcode, or `-`. Times are seconds (float). It uses an AF_PACKET socket, so
it needs root and Linux, but no tcpdump.

Usage: sniff.py OUTFILE
"""
import signal
import socket
import struct
import sys
import time

PACKET_OUTGOING = 4
ETH_P_ALL = 0x0003


def tcp_flags(b):
    names = [(0x02, "S"), (0x10, "A"), (0x01, "F"), (0x04, "R"), (0x08, "P"), (0x20, "U")]
    return "".join(n for bit, n in names if b & bit) or "-"


def describe(frame):
    if len(frame) < 14:
        return None
    ethertype = struct.unpack("!H", frame[12:14])[0]
    p = frame[14:]
    if ethertype == 0x0806 and len(p) >= 28:
        op = struct.unpack("!H", p[6:8])[0]
        return ("arp", socket.inet_ntoa(p[14:18]), "-", socket.inet_ntoa(p[24:28]), "-",
                "request" if op == 1 else "reply")
    if ethertype != 0x0800 or len(p) < 20:
        return None
    ihl = (p[0] & 0x0F) * 4
    proto = p[9]
    src, dst = socket.inet_ntoa(p[12:16]), socket.inet_ntoa(p[16:20])
    frag = struct.unpack("!H", p[6:8])[0] & 0x1FFF
    l4 = p[ihl:]
    if frag:
        return ("frag", src, "-", dst, "-", "-")
    if proto == 6 and len(l4) >= 14:
        sport, dport = struct.unpack("!HH", l4[0:4])
        return ("tcp", src, sport, dst, dport, tcp_flags(l4[13]))
    if proto == 17 and len(l4) >= 8:
        sport, dport = struct.unpack("!HH", l4[0:4])
        return ("udp", src, sport, dst, dport, "-")
    if proto == 1 and len(l4) >= 1:
        return ("icmp", src, "-", dst, "-", str(l4[0]))
    return ("ip%d" % proto, src, "-", dst, "-", "-")


def main():
    out = open(sys.argv[1], "w", buffering=1)
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.settimeout(0.2)
    stop = []
    signal.signal(signal.SIGTERM, lambda *_: stop.append(1))
    signal.signal(signal.SIGINT, lambda *_: stop.append(1))
    print("ready", flush=True)
    while not stop:
        try:
            frame, addr = s.recvfrom(65535)
        except socket.timeout:
            continue
        except InterruptedError:
            continue
        ifname = addr[0]
        if ifname == "lo":
            continue
        d = describe(frame)
        if d is None:
            continue
        direction = "out" if addr[2] == PACKET_OUTGOING else "in"
        out.write("%.6f %s %s %s %s %s %s %s %s\n" % ((time.time(), ifname, direction) + d))
    out.close()


if __name__ == "__main__":
    main()
