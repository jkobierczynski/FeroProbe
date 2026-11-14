#!/usr/bin/env bash
#
# test-sctp.sh — end-to-end check of FeroProbe's SCTP scans (-sY, -sZ).
#
# SCTP is awkward to test by hand because you need an SCTP stack to probe.
# This script stands one up for you on 127.0.0.1, runs both SCTP scans
# against three ports in known states, and checks FeroProbe reports each
# one correctly. It needs root (raw sockets) and prints PASS/FAIL per case,
# exiting non-zero if anything is wrong.
#
# It picks a backend automatically:
#
#   real       Real kernel SCTP: a listener on the OPEN port, nothing on
#              the CLOSED port (the kernel ABORTs it), and an iptables rule
#              dropping the probe to the FILTERED port. Used when the host
#              has SCTP support (the `sctp` module). This exercises a
#              genuine SCTP stack — the best test.
#
#   synthetic  A small raw-socket responder that answers INIT with INIT-ACK
#              on the OPEN port, ABORT on the CLOSED port, and stays silent
#              on the FILTERED port. Used when the kernel has no SCTP
#              support. Needs no SCTP server and no kernel module; it
#              reproduces exactly the replies the scans key off.
#
# Expected results in both backends:
#
#              -sY (INIT)        -sZ (COOKIE ECHO)
#   OPEN       open              open|filtered   (open ports drop COOKIE ECHO)
#   CLOSED     closed            closed
#   FILTERED   filtered          open|filtered
#
# Usage:   sudo ./scripts/test-sctp.sh [--bin PATH] [--backend auto|real|synthetic]
#                                       [--open N] [--closed N] [--filtered N] [-v]
#
set -euo pipefail

BIN=""
BACKEND="auto"
OPEN=19911
CLOSED=19912
FILTERED=19913
VERBOSE=0

while [ $# -gt 0 ]; do
    case "$1" in
        --bin)      BIN="$2"; shift 2 ;;
        --backend)  BACKEND="$2"; shift 2 ;;
        --open)     OPEN="$2"; shift 2 ;;
        --closed)   CLOSED="$2"; shift 2 ;;
        --filtered) FILTERED="$2"; shift 2 ;;
        -v)         VERBOSE=1; shift ;;
        -h|--help)  sed -n '2,38p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "This script needs root (raw sockets). Re-run with sudo." >&2
    exit 1
fi

command -v python3 >/dev/null || { echo "python3 is required." >&2; exit 1; }

# --- find the FeroProbe binary ------------------------------------------
repo_root="$(cd "$(dirname "$0")/.." && pwd)"
if [ -z "$BIN" ]; then
    for cand in "$repo_root/target/release/feroprobe" "$repo_root/target/debug/feroprobe"; do
        [ -x "$cand" ] && BIN="$cand" && break
    done
fi
if [ -z "$BIN" ]; then
    echo "No built binary found; building (cargo build)..." >&2
    ( cd "$repo_root" && cargo build >&2 )
    BIN="$repo_root/target/debug/feroprobe"
fi
[ -x "$BIN" ] || { echo "FeroProbe binary not found: $BIN" >&2; exit 1; }

# A pre-SCTP binary would fail every check confusingly; rebuild if the one
# we found does not know the SCTP scans.
if ! "$BIN" --help 2>&1 | grep -qi sctp; then
    echo "note: $BIN predates the SCTP scans; rebuilding..." >&2
    ( cd "$repo_root" && cargo build >&2 )
    BIN="$repo_root/target/debug/feroprobe"
fi

# --- choose the backend -------------------------------------------------
kernel_sctp() { python3 -c 'import socket; socket.socket(socket.AF_INET, socket.SOCK_STREAM, 132).close()' 2>/dev/null; }
if [ "$BACKEND" = auto ]; then
    if kernel_sctp; then BACKEND=real; else BACKEND=synthetic; fi
fi
echo "FeroProbe:  $BIN"
echo "Backend:    $BACKEND"
echo "Ports:      open=$OPEN closed=$CLOSED filtered=$FILTERED"
echo

# --- background helpers + cleanup ---------------------------------------
PIDS=()
TMPFILES=()
IPTABLES_RULE=""
cleanup() {
    for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
    [ -n "$IPTABLES_RULE" ] && iptables -D OUTPUT $IPTABLES_RULE 2>/dev/null || true
    for f in "${TMPFILES[@]:-}"; do rm -f "$f"; done
}
trap cleanup EXIT

start_synthetic() {
    # The synthetic responder shares the wire with the kernel: if the host
    # has SCTP, the kernel also ABORTs the unbound open/filtered ports and
    # skews the results. Auto-select routes such hosts to the real backend;
    # refuse only when synthetic was forced here.
    if kernel_sctp; then
        echo "This host has kernel SCTP, which would answer the test ports and" >&2
        echo "skew the synthetic backend. Use --backend real (or auto)." >&2
        exit 1
    fi
    local f; f="$(mktemp)"
    cat >"$f" <<'PY'
import socket, struct, sys
OPEN, CLOSED = int(sys.argv[1]), int(sys.argv[2])
INIT, INIT_ACK, ABORT, COOKIE_ECHO = 1, 2, 6, 10
rx = socket.socket(socket.AF_INET, socket.SOCK_RAW, 132); rx.settimeout(0.5)
tx = socket.socket(socket.AF_INET, socket.SOCK_RAW, 132)
print("ready", flush=True)
while True:
    try:
        data, addr = rx.recvfrom(65535)
    except socket.timeout:
        continue
    except OSError:
        continue
    if len(data) < 20:
        continue
    ihl = (data[0] & 0x0f) * 4
    s = data[ihl:]
    if len(s) < 16:
        continue
    sport, dport, vtag = struct.unpack("!HHI", s[0:8])
    chunk = s[12]
    if chunk not in (INIT, COOKIE_ECHO):   # ignore our own replies
        continue
    if chunk == INIT:
        if len(s) < 20:
            continue
        reply_vtag = struct.unpack("!I", s[16:20])[0]   # the INIT's initiate tag
    else:
        reply_vtag = vtag
    if dport == OPEN:
        if chunk != INIT:
            continue                       # open port silently drops COOKIE ECHO
        reply_chunk = INIT_ACK
    elif dport == CLOSED:
        reply_chunk = ABORT
    else:
        continue                           # filtered: no answer
    # common header (checksum 0; FeroProbe does not verify it) + bare chunk
    reply = struct.pack("!HHII", dport, sport, reply_vtag, 0) + bytes([reply_chunk, 0, 0, 4])
    try:
        tx.sendto(reply, (addr[0], 0))
    except OSError:
        pass
PY
    python3 "$f" "$OPEN" "$CLOSED" >/dev/null &
    PIDS+=($!)
    TMPFILES+=("$f")
    sleep 0.5
}

start_real() {
    # A real SCTP listener on the OPEN port: the kernel answers INIT-ACK.
    local f; f="$(mktemp)"
    cat >"$f" <<'PY'
import socket, sys, time
p = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 132)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", p)); s.listen(5)
print("listening", flush=True)
while True:
    time.sleep(3600)
PY
    python3 "$f" "$OPEN" >/dev/null &
    PIDS+=($!)
    TMPFILES+=("$f")
    # CLOSED needs no listener: the kernel ABORTs an unbound SCTP port.
    # FILTERED: drop the probe so the kernel never answers -> no response.
    local rule="-p sctp -m sctp --dport $FILTERED -d 127.0.0.1 -j DROP"
    if iptables -A OUTPUT $rule 2>/dev/null; then
        IPTABLES_RULE="$rule"
    else
        echo "warning: could not add the iptables SCTP rule (needs the xt_sctp" >&2
        echo "         match); the filtered-port check may report closed instead." >&2
    fi
    sleep 0.5
}

case "$BACKEND" in
    synthetic) start_synthetic ;;
    real)      start_real ;;
    *) echo "unknown backend: $BACKEND" >&2; exit 2 ;;
esac

# --- run a scan and read one port's state from JSON ---------------------
state_of() {   # args: json-file port
    python3 - "$1" "$2" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
port = int(sys.argv[2])
for h in data["hosts"]:
    for p in h["ports"]:
        if p["port"] == port and p["protocol"] == "sctp":
            print(p["state"]); sys.exit(0)
print("absent")
PY
}

run_scan() {   # args: flag out-file
    local rc=0
    "$BIN" "$1" -p "$OPEN,$CLOSED,$FILTERED" -oJ "$2" 127.0.0.1 >/dev/null 2>&1 || rc=$?
    # A nonzero exit is a failure even if the JSON looks right; record it but
    # still run the assertions below for diagnostics.
    if [ "$rc" -ne 0 ]; then
        printf '  FAIL  %-26s scan exited %s\n' "$1 exit status" "$rc"
        fails=$((fails + 1))
    fi
    if [ "$VERBOSE" = 1 ]; then echo "--- $1 JSON ---"; cat "$2"; echo; fi
}

fails=0
check() {   # args: label got want
    if [ "$2" = "$3" ]; then
        printf '  PASS  %-26s %s\n' "$1" "$2"
    else
        printf '  FAIL  %-26s got %s, want %s\n' "$1" "$2" "$3"
        fails=$((fails + 1))
    fi
}

jy="$(mktemp)"; jz="$(mktemp)"
TMPFILES+=("$jy" "$jz")

echo "== -sY (INIT scan) =="
run_scan -sY "$jy"
check "open port"     "$(state_of "$jy" "$OPEN")"     "open"
check "closed port"   "$(state_of "$jy" "$CLOSED")"   "closed"
check "filtered port" "$(state_of "$jy" "$FILTERED")" "filtered"

echo "== -sZ (COOKIE ECHO scan) =="
run_scan -sZ "$jz"
check "open port"     "$(state_of "$jz" "$OPEN")"     "open|filtered"
check "closed port"   "$(state_of "$jz" "$CLOSED")"   "closed"
check "filtered port" "$(state_of "$jz" "$FILTERED")" "open|filtered"

echo
if [ "$fails" -eq 0 ]; then
    echo "All SCTP scan checks passed."
else
    echo "$fails check(s) failed."
fi
exit $((fails == 0 ? 0 : 1))
