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
    (b"id", b"server"): b"lab-dns-1",
    (b"hostname", b"bind"): b"lab-dns-1",
    (b"version", b"bind"): b"9.18.24-lab",
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
    """The labels at pos, lower-cased, as a tuple (so "a.b" as one label
    stays apart from "a" and "b"), and the position after them; None when
    the name runs out or is compressed (no question we answer is)."""
    labels = []
    while True:
        if pos >= len(msg):
            return None, pos
        n = msg[pos]
        if n == 0:
            return tuple(labels), pos + 1
        if n > 63 or pos + 1 + n > len(msg):
            return None, pos
        labels.append(msg[pos + 1:pos + 1 + n].lower())
        pos += 1 + n


def dns_additional(query, pos, count):
    """Whether the additional section asks for the NSID; None when it is
    malformed (a record or an EDNS option longer than what is left)."""
    nsid = False
    for _ in range(count):
        owner, pos = dns_name(query, pos)
        if owner is None or pos + 10 > len(query):
            return None
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", query[pos:pos + 10])
        pos += 10
        if pos + rdlen > len(query):
            return None
        if rtype == DNS_OPT:
            if owner != ():
                return None
            rdata, p = query[pos:pos + rdlen], 0
            while p < len(rdata):
                if p + 4 > len(rdata):
                    return None
                code, olen = struct.unpack(">HH", rdata[p:p + 4])
                if p + 4 + olen > len(rdata):
                    return None
                nsid |= code == DNS_NSID
                p += 4 + olen
        pos += rdlen
    return nsid


def dns_reply(query):
    """The answer to one DNS query, or None for something that is not one.

    A standard query for a CHAOS TXT name in DNS_CHAOS gets that TXT
    record; one carrying an OPT record with the NSID option also gets
    DNS_NSID_VALUE back in an OPT record. Other standard queries get
    REFUSED, other opcodes NOTIMP, a malformed additional section FORMERR.
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
    nsid = dns_additional(query, pos + 4, ar)
    opcode = (flags >> 11) & 0xF
    rcode, answer = 0, b""
    if nsid is None:
        rcode, nsid = 1, False
    elif opcode != 0:
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
    # first-level encoding (RFC 1001 14.1): 32 letters A to P
    if name[-1] != 0 or any(not 0x41 <= c <= 0x50 for c in name[1:33]):
        return None
    if qtype != 0x21 or qclass != 1:
        return None
    table = bytes([len(NB_NAMES)])
    for nb, suffix, nflags in NB_NAMES:
        table += nb.ljust(15, b" ") + bytes([suffix]) + struct.pack(">H", nflags)
    rdata = table + NB_MAC + bytes(40)
    return struct.pack(">HHHHHH", nid, 0x8400, 0, 1, 0, 0) + name + \
        struct.pack(">HHIH", 0x21, 1, 0, len(rdata)) + rdata


def family(addr):
    return socket.AF_INET6 if ":" in addr else socket.AF_INET


def bind(addr, port, kind):
    s = socket.socket(family(addr), kind)
    try:
        if kind == socket.SOCK_STREAM:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family(addr) == socket.AF_INET6:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        s.bind((addr, port))
        if kind == socket.SOCK_STREAM:
            s.listen(64)
    except OSError:
        s.close()
        raise
    return s


def serve_tcp(s, handler):
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


def serve_udp(s, handler):
    while True:
        data, peer = s.recvfrom(65535)
        reply = handler(data)
        if reply is not None:
            s.sendto(reply, peer)


def echo(data):
    return data or b"\x00"


def main():
    addrs = sys.argv[1:] or ["0.0.0.0"]
    tcp = ((22, ssh), (53, dns_tcp), (80, http), (8080, silent))
    udp = ((53, echo), (137, nbstat_reply))
    # Bind every socket before saying "ready", so the harness never scans a
    # lab with a service missing; on a failure close them all and exit.
    served = []
    try:
        for addr in addrs:
            for port, handler in tcp:
                served.append((serve_tcp, bind(addr, port, socket.SOCK_STREAM), handler))
            for port, handler in udp:
                served.append((serve_udp, bind(addr, port, socket.SOCK_DGRAM), handler))
    except OSError as e:
        for _, s, _ in served:
            s.close()
        print(f"listener setup failed: {e}", flush=True)
        sys.exit(1)
    threads = [threading.Thread(target=f, args=(s, h), daemon=True) for f, s, h in served]
    for t in threads:
        t.start()
    print("ready", flush=True)
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
