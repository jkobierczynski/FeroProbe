#!/usr/bin/env python3
"""Lab services for nmap-diff.py.

Runs inside the target network namespace (and on 127.0.0.1 in the scanner's
namespace for the loopback target). It gives the scanners something real to
talk to, so service and OS detection follow the same paths as they would
against a real host:

  TCP 22    sends an SSH banner, then waits for the client
  TCP 80    answers any request with a small HTTP/1.0 response
  TCP 8080  accepts and stays silent (the "unknown service" path)
  UDP 53    echoes every datagram back (so UDP 53 reads as open)

Closed and filtered ports are not opened here; nmap-diff.py drops the
filtered ones with iptables. Usage: listeners.py ADDR [ADDR ...]
"""

import socket
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
        for port, handler in ((22, ssh), (80, http), (8080, silent)):
            threads.append(threading.Thread(target=serve_tcp, args=(addr, port, handler), daemon=True))
        threads.append(threading.Thread(target=serve_udp_echo, args=(addr, 53), daemon=True))
    for t in threads:
        t.start()
    print("ready", flush=True)
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
