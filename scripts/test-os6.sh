#!/usr/bin/env bash
#
# test-os6.sh — end-to-end check of FeroProbe's OS detection over IPv6 (-O).
#
# OS detection is awkward to try by hand over IPv6: you need an open TCP port
# on an IPv6 host and then have to read the guess out of the output. This
# script does it for you on ::1. It stands up a listener, runs -O against it,
# and checks FeroProbe returns an OS guess; it also checks that a port with
# nothing behind it yields no guess. It needs root (raw sockets + packet
# capture) and prints PASS/FAIL per case, exiting non-zero if anything is
# wrong.
#
# Expected results on a Linux host (the only platform -O supports):
#
#   OPEN     an OS guess, family "Linux", distance 0 (::1 is zero hops away)
#   CLOSED   no OS guess (OS detection needs an open TCP port)
#
# IPv6 is read off a packet capture because a raw IPv6 socket hands back only
# the payload, not the header the hop limit lives in; so this exercises the
# same capture path a real IPv6 scan uses. A host with no IPv6 stack (many
# containers and CI runners) can't run the check and is skipped, not failed.
#
# Usage:   sudo ./scripts/test-os6.sh [--bin PATH] [--open N] [--closed N] [-v]
#
set -euo pipefail

BIN=""
OPEN=0        # 0 = pick a free port
CLOSED=0
VERBOSE=0

while [ $# -gt 0 ]; do
    case "$1" in
        --bin)      BIN="$2"; shift 2 ;;
        --open)     OPEN="$2"; shift 2 ;;
        --closed)   CLOSED="$2"; shift 2 ;;
        -v)         VERBOSE=1; shift ;;
        -h|--help)  sed -n '2,24p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "This script needs root (raw sockets + packet capture). Re-run with sudo." >&2
    exit 1
fi

command -v python3 >/dev/null || { echo "python3 is required." >&2; exit 1; }

# --- need an IPv6 stack ---------------------------------------------------
ipv6_ok() {
    python3 -c 'import socket; socket.socket(socket.AF_INET6, socket.SOCK_STREAM).bind(("::1", 0))' 2>/dev/null
}
if ! ipv6_ok; then
    echo "This host has no usable IPv6 loopback (::1), so IPv6 OS detection"
    echo "cannot be exercised here. Run this on an IPv6-capable host. SKIPPED."
    exit 0
fi

# --- find the FeroProbe binary -------------------------------------------
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

# Pick free ports if not given. The OPEN port is reused by the listener
# below; asking the kernel for one here just reserves a currently-free number.
free_port() {
    python3 -c 'import socket; s=socket.socket(socket.AF_INET6); s.bind(("::1",0)); print(s.getsockname()[1]); s.close()'
}
# Pick each automatic port so it differs from the other (which may be an
# explicit value or an already-chosen automatic one): free_port releases its
# socket, so two calls can hand back the same number, and if the two ports
# coincided the closed-port scan would hit the listener still up on the open
# port and wrongly report a guess.
pick_distinct() {   # args: this-value other-value  -> prints a free port != other
    local val="$1" other="$2" tries=0
    [ "$val" -ne 0 ] && { echo "$val"; return; }
    val="$(free_port)"
    while [ "$val" -eq "$other" ] && [ "$tries" -lt 10 ]; do
        val="$(free_port)"; tries=$((tries + 1))
    done
    echo "$val"
}
OPEN="$(pick_distinct "$OPEN" "$CLOSED")"
CLOSED="$(pick_distinct "$CLOSED" "$OPEN")"
if [ "$OPEN" -eq "$CLOSED" ]; then
    echo "open and closed ports must differ (both $OPEN)." >&2
    exit 2
fi

echo "FeroProbe:  $BIN"
echo "Target:     ::1   (open=$OPEN closed=$CLOSED)"
echo

# --- background listener + cleanup ---------------------------------------
PIDS=()
TMPFILES=()
cleanup() {
    for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
    for f in "${TMPFILES[@]:-}"; do rm -f "$f"; done
}
trap cleanup EXIT

start_listener() {   # arg: port
    local f; f="$(mktemp)"
    cat >"$f" <<'PY'
import socket, sys, threading
port = int(sys.argv[1])
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("::1", port)); s.listen(16)
print("listening", flush=True)
while True:
    try:
        c, _ = s.accept(); c.close()
    except OSError:
        break
PY
    python3 "$f" "$1" >/dev/null &
    PIDS+=($!)
    TMPFILES+=("$f")
    sleep 0.5
}

# --- run -O and read one host's OS guess from JSON -----------------------
# Prints "<family>|<distance>" for a guess, or "none" when the host has none.
os_of() {   # args: json-file
    python3 - "$1" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
hosts = data.get("hosts") or []
if not hosts:
    print("none"); sys.exit(0)
os = hosts[0].get("os")
if not os:
    print("none")
else:
    print("%s|%s" % (os.get("family"), os.get("distance")))
PY
}

run_os_scan() {   # args: port out-file
    local port="$1" out="$2" rc=0
    "$BIN" -O -p "$port" -oJ "$out" ::1 >/dev/null 2>&1 || rc=$?
    if [ "$rc" -ne 0 ]; then
        printf '  FAIL  %-26s scan exited %s\n' "port $port scan" "$rc"
        fails=$((fails + 1))
    fi
    if [ "$VERBOSE" = 1 ]; then echo "--- -O -p $port JSON ---"; cat "$out"; echo; fi
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

jo="$(mktemp)"; jc="$(mktemp)"
TMPFILES+=("$jo" "$jc")

echo "== open port (a listener is up) =="
start_listener "$OPEN"
run_os_scan "$OPEN" "$jo"
check "OS guess over IPv6" "$(os_of "$jo")" "Linux|0"

echo "== closed port (nothing listening) =="
run_os_scan "$CLOSED" "$jc"
check "no guess without a port" "$(os_of "$jc")" "none"

echo
if [ "$fails" -eq 0 ]; then
    echo "All IPv6 OS-detection checks passed."
else
    echo "$fails check(s) failed."
    echo "(If the open-port check reports 'none', the binary may predate the"
    echo " IPv6 OS-detection support merged in PR #20 — rebuild from main.)"
fi
exit $((fails == 0 ? 0 : 1))
