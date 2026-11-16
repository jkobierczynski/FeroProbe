#!/usr/bin/env bash
#
# test-packet-options.sh: end-to-end check of the small packet options
# (roadmap step 6.7) on the wire.
#
# Builds a private two-namespace lab (see scripts/lib/lab.sh), records every
# IPv4 packet the scanner sends in full, and checks the bytes:
#
#   --data-length 20     every SYN carries 20 bytes of data; results unchanged
#   --data 0xdeadbeef    the ICMP echo request carries exactly de ad be ef
#   --data-string hello  every UDP probe carries "hello"; the echo service
#                        answers it (open)
#   --ttl 7              every SYN leaves with TTL 7
#   --ip-options R       every SYN has a record-route option (IHL 15), and
#                        --packet-trace shows nmap's notation both ways, the
#                        reply's route filled in with the target's address
#   --badsum             every SYN has a wrong TCP checksum, so the target
#                        drops it and the open port reads filtered
#   --defeat-rst-ratelimit  the SYN scan still finds open and closed ports
#   --unprivileged       as root: a connect scan, no ARP request of
#                        FeroProbe's own, the host up from a TCP answer
#   --system-dns         -R with --dns-servers: no DNS query to that server
#   -b                   an FTP bounce scan through a small FTP relay on the
#                        target: open and closed ports read right, the relay
#                        gets PORT/LIST for each port, the -oN report masks
#                        the password, and a public relay is refused
#   --dry-run            with --data-string: describes the payload, sends
#                        nothing
#
# Needs root and Linux. Prints PASS/FAIL per check, exits non-zero on failure.
#
# Usage:   sudo ./scripts/test-packet-options.sh [--bin PATH] [-v]
#
. "$(dirname "$0")/lib/lab.sh"
lab_usage_args "$@"
lab_require
lab_find_bin --data-string
lab_up

TCP_PORTS="$TCP_OPEN,$TCP_CLOSED"

# --- full-packet capture -------------------------------------------------------
# One line per IPv4 packet the scanner namespace sends: "<iface> <hex>".
PKTS=""
_PKT_PID=""
pkt_start() {
    PKTS="$(lab_tmp)/pkts.txt"
    ip netns exec "$NS_SCAN" python3 - "$PKTS" >/dev/null 2>&1 <<'PY' &
import signal, socket, sys
out = open(sys.argv[1], "w", buffering=1)
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.settimeout(0.2)
stop = []
signal.signal(signal.SIGTERM, lambda *_: stop.append(1))
while not stop:
    try:
        frame, addr = s.recvfrom(65535)
    except (socket.timeout, InterruptedError):
        continue
    if addr[0] == "lo" or addr[2] != 4 or frame[12:14] != b"\x08\x00":
        continue
    out.write("%s %s\n" % (addr[0], frame[14:].hex()))
PY
    _PKT_PID=$!
    _PIDS+=("$_PKT_PID")
    local i
    for i in $(seq 50); do [ -e "$PKTS" ] && break; sleep 0.05; done
    sleep 0.2
}
pkt_stop() {
    sleep 0.3
    kill "$_PKT_PID" 2>/dev/null || true
    wait "$_PKT_PID" 2>/dev/null || true
    if [ "$VERBOSE" = 1 ]; then echo "--- packets ---"; cat "$PKTS"; echo "---"; fi
}
fero_pkts() { pkt_start; fero "$@"; pkt_stop; }

# Ask a question of the captured packets to the target. Args: a Python
# expression over `p` (one parsed packet: proto, ttl, ihl, opts, l4, data,
# dport, flags, sum_ok) and a filter expression; prints "count:all-match".
pkts() {
    python3 - "$PKTS" "$TGT_A" "$1" "$2" <<'PY'
import socket, struct, sys
from types import SimpleNamespace as NS

def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s

path, tgt, test, keep = sys.argv[1:5]
n = ok = 0
for line in open(path):
    _, hexpkt = line.split()
    b = bytes.fromhex(hexpkt)
    if len(b) < 20 or socket.inet_ntoa(b[16:20]) != tgt:
        continue
    ihl = (b[0] & 15) * 4
    total = struct.unpack("!H", b[2:4])[0]
    l4 = b[ihl:total]
    p = NS(proto=b[9], ttl=b[8], ihl=ihl, opts=b[20:ihl], l4=l4, dport=None,
           flags=None, data=b"", sum_ok=True)
    if p.proto == 6 and len(l4) >= 20:
        p.dport = struct.unpack("!H", l4[2:4])[0]
        p.flags = l4[13]
        p.data = l4[(l4[12] >> 4) * 4:]
    elif p.proto == 17 and len(l4) >= 8:
        p.dport = struct.unpack("!H", l4[2:4])[0]
        p.data = l4[8:]
    elif p.proto == 1 and len(l4) >= 8:
        p.data = l4[8:]
    if p.proto in (6, 17):
        pseudo = b[12:20] + struct.pack("!BBH", 0, p.proto, len(l4))
        p.sum_ok = csum(pseudo + l4) == 0xFFFF
    if not eval(keep, {"p": p}):
        continue
    n += 1
    ok += bool(eval(test, {"p": p}))
print("%d:%s" % (n, "yes" if n and ok == n else "no"))
PY
}
SYN='p.proto == 6 and p.flags == 0x02'
UDP='p.proto == 17'
ECHO='p.proto == 1 and p.l4[0] == 8'

echo "== --data-length 20 =="
fero_pkts -Pn -sS --data-length 20 -p "$TCP_PORTS" "$TGT_A"
check "exit status" "$RC" 0
check "open port" "$(state_of tcp "$TCP_OPEN")" open
check "closed port" "$(state_of tcp "$TCP_CLOSED")" closed
check "every SYN carries 20 bytes" "$(pkts 'len(p.data) == 20' "$SYN" | cut -d: -f2)" yes

echo "== --data 0xdeadbeef (ping) =="
# --disable-arp-ping, or ARP alone would decide this local host.
fero_pkts -sn -PE --disable-arp-ping --data 0xdeadbeef "$TGT_B"
check "exit status" "$RC" 0
check_true "host up" output_has "Host is up"
PKT_TGT="$TGT_A"; TGT_A="$TGT_B"
check "echo request payload is de ad be ef" "$(pkts 'p.data == bytes.fromhex("deadbeef")' "$ECHO")" "1:yes"
TGT_A="$PKT_TGT"

echo "== --data-string hello (UDP) =="
fero_pkts -Pn -sU --data-string hello -p "$UDP_OPEN" "$TGT_A"
check "exit status" "$RC" 0
check "UDP echo port answers the payload" "$(state_of udp "$UDP_OPEN")" open
check "every UDP probe carries hello" "$(pkts 'p.data == b"hello"' "$UDP" | cut -d: -f2)" yes

echo "== --ttl 7 =="
fero_pkts -Pn -sS --ttl 7 -p "$TCP_PORTS" "$TGT_A"
check "exit status" "$RC" 0
check "open port" "$(state_of tcp "$TCP_OPEN")" open
check "every SYN has TTL 7" "$(pkts 'p.ttl == 7' "$SYN" | cut -d: -f2)" yes

echo "== --ip-options R =="
fero_pkts -Pn -sS --ip-options R --packet-trace -p "$TCP_OPEN" "$TGT_A"
check "exit status" "$RC" 0
check "open port" "$(state_of tcp "$TCP_OPEN")" open
# On the wire the kernel has already recorded the scanner's own address.
check "every SYN has a record route (IHL 60)" \
    "$(pkts 'p.ihl == 60 and p.opts[:3] == bytes([1, 7, 39])' "$SYN" | cut -d: -f2)" yes
check_true "options printed up front" output_has "Parsed ip options to be sent:"
check_true "SENT line in nmap's notation" output_has "ipopts={ NOP RR{#0.0.0.0 0.0.0.0"
check_true "RCVD line shows the recorded route" output_has "ipopts={ RR{ $SCAN_A $TGT_A"

echo "== --badsum =="
fero_pkts -Pn -sS --badsum --max-retries 1 -p "$TCP_OPEN" "$TGT_A"
check "exit status" "$RC" 0
check "every SYN has a wrong checksum" "$(pkts 'not p.sum_ok' "$SYN" | cut -d: -f2)" yes
check "the target drops them: filtered" "$(state_of tcp "$TCP_OPEN")" filtered

echo "== --defeat-rst-ratelimit =="
fero -Pn -sS --defeat-rst-ratelimit -p "$TCP_PORTS" "$TGT_A"
check "exit status" "$RC" 0
check "open port" "$(state_of tcp "$TCP_OPEN")" open
check "closed port" "$(state_of tcp "$TCP_CLOSED")" closed

echo "== --unprivileged (as root) =="
fero_captured --unprivileged -p "$TCP_PORTS" "$TGT_A"
check "exit status" "$RC" 0
check "open port" "$(state_of tcp "$TCP_OPEN")" open
check "closed port" "$(state_of tcp "$TCP_CLOSED")" closed
# The kernel may ARP once for the connects (or have the address cached);
# FeroProbe's own request would be one more.
check "at most one ARP request (the kernel's)" \
    "$(cap_count '$3=="out" && $4=="arp" && $9=="request"' | awk '{print ($1<=1)?"yes":"no"}')" yes
check_true "host up from a TCP answer, not ARP" output_lacks "arp-response"

echo "== --system-dns =="
# Without -n (which lab.sh's fero adds), so reverse DNS runs.
fero_rdns() {
    local d; d="$(lab_tmp)"; OUT="$d/out.txt"; RC=0
    capture_start
    nsx "$NS_SCAN" timeout 30 "$BIN" "$@" >"$OUT" 2>&1 || RC=$?
    capture_stop
    if [ "$VERBOSE" = 1 ]; then echo "--- feroprobe $* (exit $RC) ---"; cat "$OUT"; fi
}
DNS_TO="\$3==\"out\" && \$4==\"udp\" && \$7==\"$TGT_B\" && \$8==53"
fero_rdns -R --system-dns --dns-servers "$TGT_B" -sn "$TGT_A"
check "exit status" "$RC" 0
check "no DNS query to --dns-servers" "$(cap_count "$DNS_TO")" 0
fero_rdns -R --dns-servers "$TGT_B" -sn "$TGT_A"
check "sanity: without it the query goes there" \
    "$(cap_count "$DNS_TO" | awk '{print ($1>0)?"yes":"no"}')" yes

echo "== -b FTP bounce =="
FTP_PORT=2121
FTP_LOG="$(lab_tmp)/ftp.log"
ip netns exec "$NS_TGT" python3 - "$TGT_A" "$FTP_PORT" "$FTP_LOG" >/dev/null 2>&1 <<'PY' &
# A tiny FTP relay: USER/PASS, PORT, LIST (a data connection to the PORT
# address, as a bounce needs), QUIT. Everything it is sent goes to the log.
import socket, sys, threading
addr, port, log = sys.argv[1], int(sys.argv[2]), open(sys.argv[3], "a", buffering=1)
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind((addr, port)); srv.listen(8)
def session(c):
    f = c.makefile("rb")
    say = lambda s: c.sendall(s.encode() + b"\r\n")
    say("220 lab relay ready")
    data_to = None
    for raw in f:
        line = raw.decode(errors="replace").strip()
        log.write(line + "\n")
        cmd = line.split(" ", 1)[0].upper()
        if cmd == "USER":
            say("331 password please")
        elif cmd == "PASS":
            say("230 logged in" if line == "PASS s3cret" else "530 login incorrect")
        elif cmd == "PORT":
            n = [int(x) for x in line.split(" ", 1)[1].split(",")]
            data_to = (".".join(map(str, n[:4])), n[4] * 256 + n[5])
            say("200 PORT command successful")
        elif cmd == "LIST" and data_to:
            try:
                d = socket.create_connection(data_to, timeout=1)
            except OSError:
                say("425 Can't build data connection")
                continue
            say("150 Opening data connection")
            d.close()
            say("226 Transfer complete")
        elif cmd == "QUIT":
            say("221 bye"); break
        else:
            say("502 not implemented")
    c.close()
while True:
    c, _ = srv.accept()
    threading.Thread(target=session, args=(c,), daemon=True).start()
PY
_PIDS+=($!)
sleep 0.5
REPORT="$(lab_tmp)/bounce.nmap"
fero -Pn -b "bob:s3cret@$TGT_A:$FTP_PORT" -p "$TCP_PORTS" -oN "$REPORT" "$TGT_A"
check "exit status" "$RC" 0
check "open port through the relay" "$(state_of tcp "$TCP_OPEN")" open
check "closed port through the relay" "$(state_of tcp "$TCP_CLOSED")" closed
check "relay got a PORT per port" "$(grep -c '^PORT ' "$FTP_LOG")" 2
check "relay got a LIST per port" "$(grep -c '^LIST' "$FTP_LOG")" 2
check_true "report masks the password" grep -qF "bob:****@$TGT_A" "$REPORT"
check_true "  and does not hold it" bash -c "! grep -qF s3cret '$REPORT'"
: >"$FTP_LOG"
fero -Pn -b "bob:s3cret@192.0.2.10" -p "$TCP_OPEN" "$TGT_A"
check_true "public relay refused (exit $RC)" test "$RC" -ne 0
check_true "  naming --allow-public-evasion" output_has "--allow-public-evasion"

echo "== --dry-run with --data-string =="
fero_pkts -Pn -sU --data-string hello --dry-run -p "$UDP_OPEN" "$TGT_A"
check "exit status" "$RC" 0
check_true "describes the payload" output_has "5 bytes of data"
check_true "  and the probe carrying it" output_has "len=5"
check "sends nothing to the target" "$(pkts 'True' 'True' | cut -d: -f1)" 0

lab_finish
