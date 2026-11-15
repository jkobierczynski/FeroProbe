# lab.sh: shared setup for the scripts/test-*.sh option tests.
#
# Source it from a test script. It builds a small, private lab out of two
# network namespaces, so nothing touches your own network:
#
#   fpt-scan (scanner)                       fpt-tgt (target)
#   fpt-a0  10.66.1.1/24  <---- link A ---->  fpt-a1  10.66.1.2/24
#   fpt-b0  10.66.2.1/24  <---- link B ---->  fpt-b1  10.66.2.2/24
#
# The scanner's default route goes over link B (via 10.66.2.2), so the
# target's link-A address 10.66.1.2 is reachable directly over A and, when a
# scan is pinned to fpt-b0 with -e, over B as well.
#
# On the target:
#   TCP_OPEN      a TCP listener                     -> open
#   TCP_CLOSED    nothing                            -> closed
#   TCP_DROP      probes dropped by iptables         -> filtered
#   UDP_OPEN      a UDP echo service                 -> open
#   UDP_DROP      probes dropped by iptables         -> open|filtered
#   DROP_RANGE    TCP and UDP probes dropped         -> filtered, open|filtered
#
# Needs root, Linux, iproute2, iptables and python3. Everything is removed
# again when the script exits.

set -euo pipefail

NS_SCAN=fpt-scan
NS_TGT=fpt-tgt
TGT_A=10.66.1.2
TGT_B=10.66.2.2
SCAN_A=10.66.1.1
SCAN_B=10.66.2.1

TCP_OPEN=18080
TCP_CLOSED=18081
TCP_DROP=18082
DROP_RANGE=18100:18199   # extra TCP and UDP ports that drop probes (parallelism tests)
UDP_OPEN=18053
UDP_DROP=18054

LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$LIB_DIR/../.." && pwd)"
VERBOSE=${VERBOSE:-0}
BIN=${BIN:-}

fails=0
_PIDS=()
_TMP=()

lab_usage_args() {   # parse the options every test script takes
    while [ $# -gt 0 ]; do
        case "$1" in
            --bin) BIN="$2"; shift 2 ;;
            -v)    VERBOSE=1; shift ;;
            -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
            *) echo "unknown argument: $1" >&2; exit 2 ;;
        esac
    done
}

lab_require() {
    if [ "$(uname -s)" != Linux ]; then
        echo "These tests build a network-namespace lab and only run on Linux." >&2
        exit 1
    fi
    if [ "$(id -u)" -ne 0 ]; then
        echo "This script needs root (network namespaces, raw sockets). Re-run with sudo." >&2
        exit 1
    fi
    local t
    for t in ip iptables python3; do
        command -v "$t" >/dev/null || { echo "$t is required." >&2; exit 1; }
    done
}

lab_find_bin() {
    if [ -z "$BIN" ]; then
        local cand
        for cand in "$REPO_ROOT/target/release/feroprobe" "$REPO_ROOT/target/debug/feroprobe"; do
            [ -x "$cand" ] && BIN="$cand" && break
        done
    fi
    # Rebuild when the binary is missing or predates the option under test.
    if [ -z "$BIN" ] || ! "$BIN" --help 2>&1 | grep -q -- "$1"; then
        echo "Building FeroProbe (cargo build)..." >&2
        ( cd "$REPO_ROOT" && cargo build >&2 )
        BIN="$REPO_ROOT/target/debug/feroprobe"
    fi
    [ -x "$BIN" ] || { echo "FeroProbe binary not found: $BIN" >&2; exit 1; }
    BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
    echo "FeroProbe: $BIN"
}

nsx() { local ns="$1"; shift; ip netns exec "$ns" "$@"; }

lab_down() {
    local p
    for p in "${_PIDS[@]:-}"; do
        if [ -n "$p" ]; then kill "$p" 2>/dev/null || true; fi
    done
    ip netns del "$NS_SCAN" 2>/dev/null || true
    ip netns del "$NS_TGT" 2>/dev/null || true
    for p in "${_TMP[@]:-}"; do
        if [ -n "$p" ]; then rm -rf "$p"; fi
    done
}

lab_tmp() { local f; f="$(mktemp -d)"; _TMP+=("$f"); echo "$f"; }

lab_up() {
    lab_down
    trap lab_down EXIT
    ip netns add "$NS_SCAN"
    ip netns add "$NS_TGT"
    nsx "$NS_SCAN" ip link set lo up
    nsx "$NS_TGT" ip link set lo up
    ip link add fpt-a0 netns "$NS_SCAN" type veth peer name fpt-a1 netns "$NS_TGT"
    ip link add fpt-b0 netns "$NS_SCAN" type veth peer name fpt-b1 netns "$NS_TGT"
    nsx "$NS_SCAN" ip addr add "$SCAN_A/24" dev fpt-a0
    nsx "$NS_SCAN" ip addr add "$SCAN_B/24" dev fpt-b0
    nsx "$NS_TGT" ip addr add "$TGT_A/24" dev fpt-a1
    nsx "$NS_TGT" ip addr add "$TGT_B/24" dev fpt-b1
    local d
    for d in fpt-a0 fpt-b0; do nsx "$NS_SCAN" ip link set "$d" up; done
    for d in fpt-a1 fpt-b1; do nsx "$NS_TGT" ip link set "$d" up; done
    nsx "$NS_SCAN" ip route add default via "$TGT_B" dev fpt-b0
    # Replies to the scanner's link-B address leave over link B.
    nsx "$NS_TGT" sysctl -qw net.ipv4.conf.all.rp_filter=0
    nsx "$NS_SCAN" sysctl -qw net.ipv4.conf.all.rp_filter=0
    nsx "$NS_SCAN" sysctl -qw net.ipv4.conf.fpt-a0.rp_filter=0
    nsx "$NS_SCAN" sysctl -qw net.ipv4.conf.fpt-b0.rp_filter=0

    # Filtered ports: silently drop the probes on the target.
    nsx "$NS_TGT" iptables -A INPUT -p tcp --dport "$TCP_DROP" -j DROP
    nsx "$NS_TGT" iptables -A INPUT -p tcp --dport "$DROP_RANGE" -j DROP
    nsx "$NS_TGT" iptables -A INPUT -p udp --dport "$DROP_RANGE" -j DROP
    nsx "$NS_TGT" iptables -A INPUT -p udp --dport "$UDP_DROP" -j DROP

    # Services on the target.
    local svc; svc="$(lab_tmp)/svc.py"
    cat >"$svc" <<'PY'
import socket, sys, threading
tcp_port, udp_port = int(sys.argv[1]), int(sys.argv[2])
t = socket.socket(); t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
t.bind(("0.0.0.0", tcp_port)); t.listen(64)
def tcp():
    while True:
        c, _ = t.accept(); c.close()
# One UDP socket per address, so each answer comes from the address the probe
# went to (a socket on 0.0.0.0 would answer a probe for the link-A address
# that came in over link B from the link-B address).
def udp(addr):
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind((addr, udp_port))
    while True:
        data, peer = u.recvfrom(4096)
        u.sendto(data or b"x", peer)
threading.Thread(target=tcp, daemon=True).start()
for a in sys.argv[3:]:
    threading.Thread(target=udp, args=(a,), daemon=True).start()
print("ready", flush=True)
threading.Event().wait()
PY
    nsx "$NS_TGT" python3 "$svc" "$TCP_OPEN" "$UDP_OPEN" "$TGT_A" "$TGT_B" >/dev/null 2>&1 &
    _PIDS+=($!)
    # Wait until the target's listener answers over link A.
    nsx "$NS_SCAN" python3 - "$TGT_A" "$TCP_OPEN" <<'PY' \
        || { echo "lab: the target does not answer over link A" >&2; exit 1; }
import socket, sys, time
for _ in range(50):
    try:
        socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=0.5).close()
        sys.exit(0)
    except OSError:
        time.sleep(0.1)
sys.exit(1)
PY
    echo "Lab:       scanner $SCAN_A (fpt-a0), $SCAN_B (fpt-b0); target $TGT_A, $TGT_B"
    echo
}

# --- capture -----------------------------------------------------------------
_SNIFF_PID=""
CAP=""
capture_start() {   # capture everything in the scanner namespace into $CAP
    CAP="$(lab_tmp)/cap.txt"
    nsx "$NS_SCAN" python3 "$LIB_DIR/sniff.py" "$CAP" >/dev/null 2>&1 &
    _SNIFF_PID=$!
    _PIDS+=("$_SNIFF_PID")
    local i
    for i in $(seq 50); do [ -e "$CAP" ] && break; sleep 0.05; done
    sleep 0.2
}
capture_stop() {
    sleep 0.3
    kill "$_SNIFF_PID" 2>/dev/null || true
    wait "$_SNIFF_PID" 2>/dev/null || true
    if [ "$VERBOSE" = 1 ]; then echo "--- capture ---"; cat "$CAP"; echo "---"; fi
}
# Lines of the capture matching an awk condition on the fields
#   $1 time  $2 iface  $3 in|out  $4 proto  $5 src  $6 sport  $7 dst  $8 dport  $9 flags
cap() { awk "$1" "$CAP"; }
cap_count() { awk "$1" "$CAP" | wc -l | tr -d ' '; }
# The most first probes to distinct ports sent within any WINDOW seconds: a
# measure of how many probes were in flight at once when every probe goes
# unanswered until its timeout. Args: awk-condition window-seconds
cap_burst() {
    awk "$1" "$CAP" | python3 -c '
import sys
w = float(sys.argv[1]); first = {}
for line in sys.stdin:
    f = line.split()
    first.setdefault((f[3], f[7]), float(f[0]))
t = sorted(first.values()); best = 0; j = 0
for i in range(len(t)):
    while t[i] - t[j] > w:
        j += 1
    best = max(best, i - j + 1)
print(best)' "$2"
}

# --- running FeroProbe -------------------------------------------------------
OUT=""      # console output (stdout+stderr) of the last run
JSON=""     # its -oJ file
RC=0        # its exit status
fero() {    # run FeroProbe in the scanner namespace with the given arguments
    local d; d="$(lab_tmp)"
    OUT="$d/out.txt"; JSON="$d/out.json"
    RC=0
    nsx "$NS_SCAN" "$BIN" -n -oJ "$JSON" "$@" >"$OUT" 2>&1 || RC=$?
    if [ "$VERBOSE" = 1 ]; then echo "--- feroprobe $* (exit $RC) ---"; cat "$OUT"; fi
}
fero_captured() { capture_start; fero "$@"; capture_stop; }

state_of() {   # args: protocol port -> the port's state in the last run's JSON
    [ -s "$JSON" ] || { echo "no-json"; return; }
    python3 - "$JSON" "$1" "$2" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
for h in data.get("hosts", []):
    for p in h.get("ports", []):
        if p["protocol"] == sys.argv[2] and p["port"] == int(sys.argv[3]):
            print(p["state"]); sys.exit(0)
print("absent")
PY
}

# --- assertions --------------------------------------------------------------
check() {   # args: label got want
    if [ "$2" = "$3" ]; then
        printf '  PASS  %-46s %s\n' "$1" "$2"
    else
        printf '  FAIL  %-46s got %s, want %s\n' "$1" "$2" "$3"
        fails=$((fails + 1))
    fi
}
check_true() {   # args: label condition-description; uses the exit status of "$@" after --
    local label="$1"; shift
    if "$@"; then
        printf '  PASS  %s\n' "$label"
    else
        printf '  FAIL  %s\n' "$label"
        fails=$((fails + 1))
    fi
}
output_has() { grep -qiF -- "$1" "$OUT"; }
output_lacks() { ! grep -qiF -- "$1" "$OUT"; }

lab_finish() {
    echo
    if [ "$fails" -eq 0 ]; then
        echo "All checks passed."
    else
        echo "$fails check(s) failed. Re-run with -v to see the scans and captures."
    fi
    exit $((fails == 0 ? 0 : 1))
}
