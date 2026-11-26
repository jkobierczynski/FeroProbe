#!/usr/bin/env bash
#
# test-nse-scripts.sh: end-to-end check of the NSE compatibility layer's
# io, nmap.fetchfile and openssl.bignum_* support (PR #87).
#
#   bignum       nmap's ssl-dh-params against a local OpenSSL server with a
#                weak 1024-bit DH group reports it VULNERABLE (big numbers
#                parsed and grade-checked); a server with no DH cipher gives
#                no ssl-dh-params output
#   io           a FeroProbe self-test script reads a file named in
#                --script-args, is refused a write, is refused a file it was
#                not given, and nmap.fetchfile refuses a path with ".."
#   load count   every nmap script in the data directory is indexed by
#                --script-updatedb; ssl-dh-params and an io-using script load
#                rather than being skipped for a missing module
#
# All checks run against 127.0.0.1 with a TCP connect scan, so no root is
# needed. The bignum and load-count checks need an installed nmap's scripts
# (for ssl-dh-params.nse and the script corpus) and openssl; when those are
# missing those checks are skipped, not failed, and the io check still runs.
#
# Needs bash. Uses openssl and an nmap scripts directory when present.
# Prints PASS/FAIL (or SKIP) per check, exits non-zero on any failure.
#
# Usage:  ./scripts/test-nse-scripts.sh [--bin-dir DIR] [--nmap-scripts DIR] [-v]
#
#   --bin-dir DIR       use feroprobe from DIR (default: build it with cargo
#                       and use target/debug)
#   --nmap-scripts DIR  nmap's scripts directory (default: search
#                       $NMAPDIR/scripts, /usr/share/nmap/scripts,
#                       /usr/local/share/nmap/scripts,
#                       /opt/homebrew/share/nmap/scripts)
#   -v                  show the output of each failed check in full
#
# With KEEP=1 the temporary directory is kept and its path printed.

set -u

BIN_DIR=""
NMAP_SCRIPTS=""
VERBOSE=0
while [ $# -gt 0 ]; do
    case "$1" in
        --bin-dir) BIN_DIR="$2"; shift 2 ;;
        --nmap-scripts) NMAP_SCRIPTS="$2"; shift 2 ;;
        -v) VERBOSE=1; shift ;;
        -h|--help) sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

ROOT=$(cd "$(dirname "$0")/.." && pwd)
if [ -z "$BIN_DIR" ]; then
    echo "Building feroprobe..."
    (cd "$ROOT" && cargo build -q -p feroprobe --bins) || exit 2
    BIN_DIR="$ROOT/target/debug"
fi
FERO="$BIN_DIR/feroprobe"
[ -x "$FERO" ] || { echo "no feroprobe in $BIN_DIR" >&2; exit 2; }

# Find nmap's scripts directory, for ssl-dh-params.nse and the corpus.
if [ -z "$NMAP_SCRIPTS" ]; then
    for d in "${NMAPDIR:-}/scripts" /usr/share/nmap/scripts \
             /usr/local/share/nmap/scripts /opt/homebrew/share/nmap/scripts; do
        [ -d "$d" ] && NMAP_SCRIPTS="$d" && break
    done
fi

TMP=$(mktemp -d "${TMPDIR:-/tmp}/feroprobe-nse-test.XXXXXX") || exit 2
SERVER_PID=""
cleanup() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
    if [ -n "${KEEP:-}" ]; then echo "kept $TMP"; else rm -rf "$TMP"; fi
}
trap cleanup EXIT

PASS=0
FAIL=0
SKIP=0
OUT=""
pass() { PASS=$((PASS + 1)); echo "  PASS  $1"; }
fail() {
    FAIL=$((FAIL + 1))
    echo "  FAIL  $1"
    [ "$VERBOSE" = 1 ] && printf '%s\n' "--- output ---" "$OUT" "---" | sed 's/^/        /'
    return 0
}
skip() { SKIP=$((SKIP + 1)); echo "  SKIP  $1"; }
# contains NAME TEXT: the last run's output holds TEXT somewhere.
contains() { case "$OUT" in *"$2"*) pass "$1" ;; *) fail "$1 (no '$2')" ;; esac; }
lacks() { case "$OUT" in *"$2"*) fail "$1 (unexpected '$2')" ;; *) pass "$1" ;; esac; }

# A free TCP port, asked of the kernel.
free_port() {
    python3 - <<'PY' 2>/dev/null || echo 14433
import socket
s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()
PY
}

# Wait until 127.0.0.1:$1 accepts a connection (up to ~5 s).
wait_listen() {
    local p="$1" i
    for i in $(seq 50); do
        if command -v python3 >/dev/null; then
            python3 - "$p" <<'PY' && return 0
import socket, sys
try:
    socket.create_connection(("127.0.0.1", int(sys.argv[1])), 0.3).close()
except OSError:
    sys.exit(1)
PY
        else
            (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null && return 0
        fi
        sleep 0.1
    done
    return 1
}

echo "FeroProbe: $FERO"
[ -n "$NMAP_SCRIPTS" ] && echo "nmap scripts: $NMAP_SCRIPTS" || echo "nmap scripts: not found (bignum and load-count checks will be skipped)"
echo

# --- 1. openssl.bignum_* through ssl-dh-params -------------------------------
echo "1. openssl.bignum_* (ssl-dh-params)"
DHPARAMS="$NMAP_SCRIPTS/ssl-dh-params.nse"
if ! command -v openssl >/dev/null; then
    skip "ssl-dh-params: openssl not installed"
elif [ -z "$NMAP_SCRIPTS" ] || [ ! -f "$DHPARAMS" ]; then
    skip "ssl-dh-params: nmap's ssl-dh-params.nse not found"
else
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$TMP/k.pem" -out "$TMP/c.pem" \
        -days 2 -subj /CN=feroprobe-lab >/dev/null 2>&1
    openssl dhparam -out "$TMP/dh.pem" 1024 >/dev/null 2>&1

    # A server offering a weak 1024-bit DH group.
    port=$(free_port)
    openssl s_server -accept "$port" -cert "$TMP/c.pem" -key "$TMP/k.pem" \
        -dhparam "$TMP/dh.pem" -cipher 'DHE-RSA-AES128-SHA:@SECLEVEL=0' \
        -tls1_2 -quiet -naccept 20 >/dev/null 2>&1 &
    SERVER_PID=$!
    if wait_listen "$port"; then
        OUT=$("$FERO" -sT -Pn -p "$port" --script "+$DHPARAMS" 127.0.0.1 2>&1)
        contains "weak 1024-bit DH group is reported VULNERABLE" "Insufficient Group Strength"
        contains "  the 1024-bit modulus length is parsed" "Modulus Length: 1024"
        contains "  the modulus is recognised as a safe prime" "Safe prime"
    else
        fail "ssl-dh-params: the weak-DH test server did not start"
    fi
    kill "$SERVER_PID" 2>/dev/null; SERVER_PID=""

    # A server with no DH cipher: ssl-dh-params must stay silent.
    port=$(free_port)
    openssl s_server -accept "$port" -cert "$TMP/c.pem" -key "$TMP/k.pem" \
        -cipher 'ECDHE-RSA-AES128-GCM-SHA256:@SECLEVEL=0' \
        -tls1_2 -quiet -naccept 20 >/dev/null 2>&1 &
    SERVER_PID=$!
    if wait_listen "$port"; then
        OUT=$("$FERO" -sT -Pn -p "$port" --script "+$DHPARAMS" 127.0.0.1 2>&1)
        lacks "a server with no DH cipher gives no ssl-dh-params output" "ssl-dh-params:"
    else
        skip "ssl-dh-params negative case: the ECDHE test server did not start"
    fi
    kill "$SERVER_PID" 2>/dev/null; SERVER_PID=""
fi
echo

# --- 2. io and nmap.fetchfile ------------------------------------------------
echo "2. io and nmap.fetchfile"
WORD="$TMP/users.txt"
printf 'feroprobe-io-test-line\nadmin\n' >"$WORD"
LUA="$TMP/fp-io-selftest.lua"
cat >"$LUA" <<'LUA'
-- FeroProbe io/fetchfile self-test (GPL-3.0-or-later, like FeroProbe).
description = "FeroProbe io self-test"
categories = { "safe" }
local io = require "io"
local stdnse = require "stdnse"
prerule = function() return true end
action = function()
  local path = stdnse.get_script_args("iofile")
  local f = assert(io.open(path, "r"))
  local first = f:read("l")
  f:close()
  local parts = {
    "read=" .. tostring(first),
    "write=" .. tostring(select(2, io.open(path, "w")) or "allowed!"),
    "denied=" .. tostring(select(2, io.open("/etc/passwd")) or "allowed!"),
    "fetchdotdot=" .. tostring(nmap.fetchfile("../../etc/passwd")),
  }
  return table.concat(parts, " ")
end
LUA
# A prerule runs before discovery and sends nothing to the target; -p 1 just
# gives the scan a (closed) port so it has something to do.
OUT=$("$FERO" -Pn -sT -p 1 --script "$LUA" --script-args "iofile=$WORD" 127.0.0.1 2>&1)
contains "io.open reads a file named in --script-args" "read=feroprobe-io-test-line"
contains "a write is refused" "FeroProbe scripts cannot write files"
contains "a path not given to the script is refused" "read only files named in --script-args"
contains "nmap.fetchfile refuses a path with .." "fetchdotdot=nil"
echo

# --- 3. load count (--script-updatedb) ---------------------------------------
echo "3. load count (--script-updatedb over nmap's scripts)"
if [ -z "$NMAP_SCRIPTS" ]; then
    skip "load count: nmap's scripts directory not found"
else
    XDG="$TMP/xdg"
    mkdir -p "$XDG/feroprobe/scripts"
    # Copy under a prefix so a script that shares a name with one of
    # FeroProbe's own built-in scripts (http-title, ssl-cert, …) is not
    # skipped for the name clash; this measures how many of nmap's scripts
    # the compatibility layer can load, which is the documented figure.
    for f in "$NMAP_SCRIPTS"/*.nse; do
        cp "$f" "$XDG/feroprobe/scripts/nsecompat-$(basename "$f")"
    done
    total=$(ls "$NMAP_SCRIPTS"/*.nse 2>/dev/null | wc -l | tr -d ' ')
    OUT=$(XDG_DATA_HOME="$XDG" "$FERO" --script-updatedb 2>&1)
    loaded=$(printf '%s\n' "$OUT" | sed -n 's/.*Script database updated: \([0-9]*\) scripts.*/\1/p')
    echo "     $loaded of $total nmap scripts load (for reference, 379 of 606 with nmap 7.94)"
    # The real guard: nothing is skipped for a missing io or openssl module,
    # and ssl-dh-params (needs openssl.bignum_*) is one of the loaded scripts.
    if printf '%s\n' "$OUT" | grep -q "module 'io'"; then
        OUT=$(printf '%s\n' "$OUT" | grep "module 'io'" | head -3)
        fail "no script is skipped for a missing 'io' module"
    else
        pass "no script is skipped for a missing 'io' module"
    fi
    if printf '%s\n' "$OUT" | grep -qE "openssl\.bignum|module 'openssl'"; then
        fail "no script is skipped for a missing openssl bignum"
    else
        pass "no script is skipped for a missing openssl bignum"
    fi
    if [ -f "$DHPARAMS" ]; then
        OUT=$(XDG_DATA_HOME="$XDG" "$FERO" --script-updatedb 2>&1)
        if printf '%s\n' "$OUT" | grep -q "ssl-dh-params"; then
            # It only appears in output if it was skipped; absence means loaded.
            fail "ssl-dh-params.nse loads (bignum)"
        else
            pass "ssl-dh-params.nse loads (bignum)"
        fi
    fi
fi

echo
TOTAL=$((PASS + FAIL))
if [ "$FAIL" -eq 0 ]; then
    echo "All $TOTAL checks passed ($SKIP skipped)."
    exit 0
else
    echo "$FAIL of $TOTAL checks failed ($SKIP skipped). Re-run with -v for details."
    exit 1
fi
