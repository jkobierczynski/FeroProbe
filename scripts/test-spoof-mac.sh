#!/usr/bin/env bash
#
# test-spoof-mac.sh: end-to-end check of --spoof-mac.
#
# Builds a private two-namespace lab (see scripts/lib/lab.sh), records every
# Ethernet frame the scanner sends, and checks the source MAC address:
#
#   -sS --spoof-mac MAC  every frame to the target, ARP included, comes from
#                        MAC (also the ARP sender field); the answers still
#                        arrive, so open and closed ports read right
#   -sU --spoof-mac MAC  the same for UDP probes; the echo service answers
#   -sn --spoof-mac MAC  the ARP ping comes from MAC; the host is up
#   --packet-trace       SENT lines end in ether-src=MAC
#   -e IFACE             the same through the chosen interface: answers
#                        still reach the scan (they come back through lo)
#   -sS                  no reset from this host answers a SYN-ACK
#   silent next hop      --host-timeout still bounds the ARP lookup
#   -sS -sV              the version scan's own connections complete,
#                        though the target now answers the spoofed MAC
#   --spoof-mac 0        a random address: not the interface's, unicast
#   --spoof-mac Apple    a vendor name: Apple's prefix
#   --spoof-mac 02:aa    a prefix: the rest is filled in
#   -sT --spoof-mac      warns that the connect scan keeps the real MAC
#   public target        refused without --allow-public-evasion
#
# Needs root and Linux. Prints PASS/FAIL per check, exits non-zero on failure.
#
# Usage:   sudo ./scripts/test-spoof-mac.sh [--bin PATH] [-v]
#
. "$(dirname "$0")/lib/lab.sh"
lab_usage_args "$@"
lab_require
lab_find_bin --spoof-mac
lab_up

TCP_PORTS="$TCP_OPEN,$TCP_CLOSED"
SPOOF=02:11:22:33:44:55
REAL="$(nsx "$NS_SCAN" cat /sys/class/net/fpt-a0/address)"

# --- frame capture --------------------------------------------------------------
# One line per frame the scanner sends on fpt-a0:
#   <src-mac> <ip|arp> <dst-ip> <arp-sender-mac or -> <tcp-flags or ->
FRAMES=""
_FR_PID=""
frames_start() {
    FRAMES="$(lab_tmp)/frames.txt"
    ip netns exec "$NS_SCAN" python3 - "$FRAMES" >/dev/null 2>&1 <<'PY' &
import signal, socket, sys
out = open(sys.argv[1], "w", buffering=1)
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.bind(("fpt-a0", 0))
s.settimeout(0.2)
stop = []
signal.signal(signal.SIGTERM, lambda *_: stop.append(1))
mac = lambda b: ":".join("%02x" % x for x in b)
while not stop:
    try:
        f, addr = s.recvfrom(65535)
    except (socket.timeout, InterruptedError):
        continue
    if addr[2] != 4:   # outgoing only
        continue
    t = f[12:14]
    if t == b"\x08\x00":
        flags = "-"
        if f[23] == 6:
            b = f[14 + (f[14] & 15) * 4 + 13]
            flags = "".join(c for bit, c in zip((2, 16, 1, 4, 8), "SAFRP") if b & bit) or "."
        out.write("%s ip %s - %s\n" % (mac(f[6:12]), socket.inet_ntoa(f[30:34]), flags))
    elif t == b"\x08\x06":
        out.write("%s arp %s %s -\n" % (mac(f[6:12]), socket.inet_ntoa(f[38:42]), mac(f[22:28])))
PY
    _FR_PID=$!
    _PIDS+=("$_FR_PID")
    local i
    for i in $(seq 50); do [ -e "$FRAMES" ] && break; sleep 0.05; done
    sleep 0.2
}
frames_stop() {
    sleep 0.3
    kill "$_FR_PID" 2>/dev/null || true
    wait "$_FR_PID" 2>/dev/null || true
    if [ "$VERBOSE" = 1 ]; then echo "--- frames ---"; cat "$FRAMES"; echo "---"; fi
}
fero_frames() { frames_start; fero "$@"; frames_stop; }
# Frames to the target: how many, and the distinct source MACs.
to_target() { awk -v t="$TGT_A" '$3 == t' "$FRAMES"; }
count_to_target() { to_target | wc -l | tr -d ' '; }
macs_to_target() { to_target | awk '{print $1}' | sort -u | paste -sd' ' -; }
# TCP frames to the target with exactly these flags, and from which MAC.
tcp_with() { to_target | awk -v f="$1" '$2 == "ip" && $5 == f'; }
arp_senders() { to_target | awk '$2 == "arp" {print $4}' | sort -u | paste -sd' ' -; }

echo "== -sS --spoof-mac $SPOOF =="
fero_frames -Pn -sS --spoof-mac "$SPOOF" --packet-trace -p "$TCP_PORTS" "$TGT_A"
check "exit status" "$RC" 0
check_true "announces the address" output_has "Spoofing MAC address 02:11:22:33:44:55"
check "open port" "$(state_of tcp "$TCP_OPEN")" open
check "closed port" "$(state_of tcp "$TCP_CLOSED")" closed
check_true "frames were sent to the target ($(count_to_target))" test "$(count_to_target)" -gt 0
check "every frame comes from the spoofed MAC" "$(macs_to_target)" "$SPOOF"
check "ARP sender field is the spoofed MAC" "$(arp_senders)" "$SPOOF"
check_true "trace lines show ether-src" output_has "ether-src=02:11:22:33:44:55"
check "no reset answers the SYN-ACK" "$(tcp_with R | wc -l | tr -d ' ')" 0

echo "== -e fpt-a0 --spoof-mac $SPOOF =="
fero_frames -e fpt-a0 -Pn -sS --spoof-mac "$SPOOF" -p "$TCP_PORTS" "$TGT_A"
check "exit status" "$RC" 0
check "open port" "$(state_of tcp "$TCP_OPEN")" open
check "closed port" "$(state_of tcp "$TCP_CLOSED")" closed
check "every frame comes from the spoofed MAC" "$(macs_to_target)" "$SPOOF"
fero -e fpt-a0 -Pn -sU --spoof-mac "$SPOOF" -p "$UDP_OPEN" "$TGT_A"
check "UDP echo port" "$(state_of udp "$UDP_OPEN")" open

echo "== -sU --spoof-mac $SPOOF =="
fero_frames -Pn -sU --spoof-mac "$SPOOF" -p "$UDP_OPEN" "$TGT_A"
check "exit status" "$RC" 0
check "UDP echo port" "$(state_of udp "$UDP_OPEN")" open
check "every frame comes from the spoofed MAC" "$(macs_to_target)" "$SPOOF"

echo "== -sn --spoof-mac $SPOOF (ARP ping) =="
fero_frames -sn --spoof-mac "$SPOOF" "$TGT_A"
check "exit status" "$RC" 0
check_true "host up" output_has "Host is up"
check "ARP request from the spoofed MAC" "$(arp_senders)" "$SPOOF"

echo "== --spoof-mac 0 (random) =="
fero_frames -Pn -sS --spoof-mac 0 -p "$TCP_OPEN" "$TGT_A"
check "exit status" "$RC" 0
check "open port" "$(state_of tcp "$TCP_OPEN")" open
RAND="$(macs_to_target)"
check_true "one address, not the interface's ($RAND)" \
    bash -c "[ -n '$RAND' ] && [ '$RAND' != '$REAL' ] && ! echo '$RAND' | grep -q ' '"
check_true "  and unicast" bash -c "[ \$(( 0x${RAND:0:2} & 1 )) -eq 0 ]"

echo "== --spoof-mac Apple (vendor) =="
fero_frames -Pn -sS --spoof-mac Apple -p "$TCP_OPEN" "$TGT_A"
check "exit status" "$RC" 0
check_true "announces Apple" output_has "(Apple)"
check "frames carry Apple's prefix" "$(macs_to_target | cut -c1-8)" "00:03:93"

echo "== --spoof-mac 02:aa (prefix) =="
fero_frames -Pn -sS --spoof-mac 02:aa -p "$TCP_OPEN" "$TGT_A"
check "exit status" "$RC" 0
check "frames carry the prefix" "$(macs_to_target | cut -c1-5)" "02:aa"

echo "== silent next hop, --host-timeout 300ms =="
# The next hop's ARP lookup must stop at the host timeout too.
T0=$(date +%s%N)
fero -Pn -sS -p 1-20 --host-timeout 300ms --spoof-mac "$SPOOF" 10.66.1.99
T1=$(( ($(date +%s%N) - T0) / 1000000 ))
check "exit status" "$RC" 0
check_true "skipped for the host timeout" output_has "due to host timeout"
check_true "  within 5 s (${T1} ms)" test "$T1" -lt 5000

echo "== -sS -sV --spoof-mac $SPOOF =="
# Last of the captured runs: the system's own connections may still be
# closing, from its real MAC, when the next scan starts.
# No -Pn: the ARP ping from the spoofed MAC teaches the target that
# address, so it answers the version scan's connections there too.
fero_frames -sS -sV --spoof-mac "$SPOOF" -p "$TCP_OPEN" "$TGT_A"
check "exit status" "$RC" 0
check "open port" "$(state_of tcp "$TCP_OPEN")" open
check_true "the version scan's connections complete (ACK from $REAL)" \
    bash -c "[ -n \"\$(awk -v t='$TGT_A' -v m='$REAL' '\$3 == t && \$1 == m && \$5 == \"A\"' '$FRAMES')\" ]"
check "  and the SYN scan draws no reset" "$(tcp_with R | awk -v m="$SPOOF" '$1 != m' | wc -l | tr -d ' ')" 0

echo "== -sT --spoof-mac =="
fero -Pn -sT --spoof-mac "$SPOOF" -p "$TCP_OPEN" "$TGT_A"
check "exit status" "$RC" 0
check_true "warns the connect scan keeps the real MAC" output_has "will not be honored for the TCP connect scan"

echo "== public target =="
fero -Pn -sS --spoof-mac "$SPOOF" -p 80 192.0.2.10
check_true "refused (exit $RC)" test "$RC" -ne 0
check_true "  naming --allow-public-evasion" output_has "--allow-public-evasion"

lab_finish
