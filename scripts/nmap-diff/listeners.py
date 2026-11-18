#!/usr/bin/env python3
"""Lab services for nmap-diff.py.

Runs inside the target network namespace (and on 127.0.0.1 in the scanner's
namespace for the loopback target). It gives the scanners something real to
talk to, so service and OS detection follow the same paths as they would
against a real host:

  TCP 22    sends an SSH banner, then waits for the client
  TCP 80    answers any request with a small HTTP/1.0 response
  TCP 8080  accepts and stays silent (the "unknown service" path)
  TCP 53    a small DNS server for the script cases: answers CHAOS TXT
            id.server, hostname.bind and version.bind, and the EDNS(0)
            NSID option (not in the @TCP list, so other cases never see it)
  UDP 53    echoes every datagram back (so UDP 53 reads as open)
  UDP 137   answers a NetBIOS NODE STATUS request (RFC 1002) with a fixed
            name table and MAC address, and ignores anything else

Closed and filtered ports are not opened here; nmap-diff.py drops the
filtered ones with iptables. Usage: listeners.py ADDR [ADDR ...]
"""

import socket
import struct
import sys
import threading

SSH_BANNER = b"SSH-2.0-OpenSSH_9.6p1 Debian-4\r\n"
HTTP_REPLY = (
    b"HTTP/1.0 200 OK\r\n"
    b"Server: nginx/1.24.0\r\n"
    b"Content-Type: text/html\r\n"
    b"Content-Length: 13\r\n"
    b"\r\n"
    b"<p>lab</p>\r\n\r\n"
)


# DNS (RFC 1035, RFC 6891 EDNS(0), RFC 5001 NSID)
DNS_TXT, DNS_OPT, DNS_CH, DNS_NSID = 16, 41, 3, 3
DNS_CHAOS = {
    "id.server": b"lab-dns-1",
    "hostname.bind": b"lab-dns-1",
    "version.bind": b"9.18.24-lab",
}
DNS_NSID_VALUE = b"lab-dns-1"

# NetBIOS NODE STATUS (RFC 1002 4.2.17, 4.2.18)
NB_NAMES = (
    (b"FPDLAB", 0x00, 0x0400),  # unique, active
    (b"FPDLAB", 0x20, 0x0400),
    (b"WORKGROUP", 0x00, 0x8400),  # group, active
)
NB_MAC = bytes.fromhex("02000000a10b")


def dns_name(msg, pos):
    """The name at pos (no compression in a question we answer) and the
    position after it; None when it runs out or is compressed."""
    labels = []
    while True:
        if pos >= len(msg):
            return None, pos
        n = msg[pos]
        if n == 0:
            return b".".join(labels).decode("ascii", "replace").lower(), pos + 1
        if n > 63 or pos + 1 + n > len(msg):
            return None, pos
        labels.append(msg[pos + 1:pos + 1 + n])
        pos += 1 + n


def dns_reply(query):
    """The answer to one DNS query, or None for something that is not one.

    A standard query for a CHAOS TXT name in DNS_CHAOS gets that TXT
    record; one carrying an OPT record with the NSID option also gets
    DNS_NSID_VALUE back in an OPT record. Other standard queries get
    REFUSED, other opcodes NOTIMP.
    """
    if len(query) < 12:
        return None
    qid, flags, qd, _an, _ns, ar = struct.unpack(">HHHHHH", query[:12])
    if flags & 0x8000 or qd != 1:
        return None
    name, pos = dns_name(query, 12)
    if name is None or pos + 4 > len(query):
        return None
    qtype, qclass = struct.unpack(">HH", query[pos:pos + 4])
    question = query[12:pos + 4]
    pos += 4
    nsid = False
    for _ in range(ar):
        # the OPT record: root name, type, payload size, ttl, rdlength
        if pos + 11 > len(query) or query[pos] != 0:
            break
        rtype, _size, _ttl, rdlen = struct.unpack(">HHIH", query[pos + 1:pos + 11])
        rdata = query[pos + 11:pos + 11 + rdlen]
        if rtype == DNS_OPT:
            p = 0
            while p + 4 <= len(rdata):
                code, olen = struct.unpack(">HH", rdata[p:p + 4])
                nsid |= code == DNS_NSID
                p += 4 + olen
        pos += 11 + rdlen
    opcode = (flags >> 11) & 0xF
    rcode, answer = 0, b""
    if opcode != 0:
        rcode = 4
    elif qclass == DNS_CH and qtype == DNS_TXT and name in DNS_CHAOS:
        txt = DNS_CHAOS[name]
        rdata = bytes([len(txt)]) + txt
        answer = b"\xc0\x0c" + struct.pack(">HHIH", DNS_TXT, DNS_CH, 0, len(rdata)) + rdata
    else:
        rcode = 5
    out_flags = 0x8400 | (flags & 0x7900) | rcode  # QR, AA, opcode and RD echoed
    additional = b""
    if nsid and rcode != 4:
        opt = struct.pack(">HH", DNS_NSID, len(DNS_NSID_VALUE)) + DNS_NSID_VALUE
        additional = b"\x00" + struct.pack(">HHIH", DNS_OPT, 1232, 0, len(opt)) + opt
    return struct.pack(">HHHHHH", qid, out_flags, 1, 1 if answer else 0, 0,
                       1 if additional else 0) + question + answer + additional


def nbstat_reply(query):
    """The answer to a NetBIOS NODE STATUS request, or None for anything else."""
    if len(query) < 12 + 34 + 4:
        return None
    nid, flags, qd = struct.unpack(">HHH", query[:6])
    # a request (R bit clear), opcode 0 (query), one question
    if flags & 0xF800 or qd != 1 or query[12] != 0x20:
        return None
    name = query[12:12 + 34]
    qtype, qclass = struct.unpack(">HH", query[46:50])
    if name[-1] != 0 or qtype != 0x21 or qclass != 1:
        return None
    table = bytes([len(NB_NAMES)])
    for nb, suffix, nflags in NB_NAMES:
        table += nb.ljust(15, b" ") + bytes([suffix]) + struct.pack(">H", nflags)
    rdata = table + NB_MAC + bytes(40)
    return struct.pack(">HHHHHH", nid, 0x8400, 0, 1, 0, 0) + name + \
        struct.pack(">HHIH", 0x21, 1, 0, len(rdata)) + rdata


def family(addr):
    return socket.AF_INET6 if ":" in addr else socket.AF_INET


def serve_tcp(addr, port, handler):
    s = socket.socket(family(addr), socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family(addr) == socket.AF_INET6:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    s.bind((addr, port))
    s.listen(64)
    while True:
        conn, _ = s.accept()
        threading.Thread(target=handler, args=(conn,), daemon=True).start()


def ssh(conn):
    with conn:
        try:
            conn.sendall(SSH_BANNER)
            conn.settimeout(10)
            conn.recv(4096)
        except OSError:
            pass


def http(conn):
    with conn:
        try:
            conn.settimeout(10)
            if conn.recv(4096):
                conn.sendall(HTTP_REPLY)
        except OSError:
            pass


def silent(conn):
    with conn:
        try:
            conn.settimeout(10)
            while conn.recv(4096):
                pass
        except OSError:
            pass


def dns_tcp(conn):
    """DNS over TCP (RFC 1035 4.2.2): each message has a two-byte length."""
    with conn:
        try:
            conn.settimeout(10)
            buf = b""
            while True:
                while len(buf) >= 2 and len(buf) >= 2 + struct.unpack(">H", buf[:2])[0]:
                    n = struct.unpack(">H", buf[:2])[0]
                    reply = dns_reply(buf[2:2 + n])
                    buf = buf[2 + n:]
                    if reply is None:
                        return
                    conn.sendall(struct.pack(">H", len(reply)) + reply)
                data = conn.recv(4096)
                if not data:
                    return
                buf += data
        except OSError:
            pass


def serve_udp(addr, port, handler):
    s = socket.socket(family(addr), socket.SOCK_DGRAM)
    if family(addr) == socket.AF_INET6:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    s.bind((addr, port))
    while True:
        data, peer = s.recvfrom(65535)
        reply = handler(data)
        if reply is not None:
            s.sendto(reply, peer)


def serve_udp_echo(addr, port):
    s = socket.socket(family(addr), socket.SOCK_DGRAM)
    if family(addr) == socket.AF_INET6:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    s.bind((addr, port))
    while True:
        data, peer = s.recvfrom(65535)
        s.sendto(data or b"\x00", peer)


def main():
    addrs = sys.argv[1:] or ["0.0.0.0"]
    threads = []
    for addr in addrs:
        for port, handler in ((22, ssh), (53, dns_tcp), (80, http), (8080, silent)):
            threads.append(threading.Thread(target=serve_tcp, args=(addr, port, handler), daemon=True))
        threads.append(threading.Thread(target=serve_udp_echo, args=(addr, 53), daemon=True))
        threads.append(threading.Thread(target=serve_udp, args=(addr, 137, nbstat_reply), daemon=True))
    for t in threads:
        t.start()
    print("ready", flush=True)
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
