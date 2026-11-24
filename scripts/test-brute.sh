#!/usr/bin/env bash
#
# test-brute.sh: end-to-end check of the brute-force support (PR #88): the
# opt-in selection gating and the brute framework running a driver.
#
#   gating       a brute-category script runs only when chosen by its exact
#                name, by a file path, or by the `brute` category word; it is
#                left out (and named in a warning) when only swept up by
#                `all`, a `*-brute` wildcard, or a whole directory
#   framework    the brute Engine drives a login script against a local FTP
#                server, finds the one valid account from the userdb/passdb
#                word lists, and stores no invalid pair; an empty word list
#                finds nothing
#
# Everything runs against 127.0.0.1 with a TCP connect scan, so no root is
# needed. The framework checks need python3 for the throwaway login server;
# when it is missing those checks are skipped, not failed.
#
# Prints PASS/FAIL (or SKIP) per check, exits non-zero on any failure.
#
# Usage:  ./scripts/test-brute.sh [--bin-dir DIR] [-v]
#
#   --bin-dir DIR   use feroprobe from DIR (default: build it with cargo and
#                   use target/debug)
#   -v              show the output of each failed check in full
#
# With KEEP=1 the temporary directory is kept and its path printed.

set -u

BIN_DIR=""
VERBOSE=0
while [ $# -gt 0 ]; do
    case "$1" in
        --bin-dir) BIN_DIR="$2"; shift 2 ;;
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

TMP=$(mktemp -d "${TMPDIR:-/tmp}/feroprobe-brute-test.XXXXXX") || exit 2
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
# contains NAME TEXT / lacks NAME TEXT: the last run's output holds TEXT (or not).
contains() { case "$OUT" in *"$2"*) pass "$1" ;; *) fail "$1 (no '$2')" ;; esac; }
lacks() { case "$OUT" in *"$2"*) fail "$1 (unexpected '$2')" ;; *) pass "$1" ;; esac; }

# A free TCP port, asked of the kernel.
free_port() {
    python3 - <<'PY' 2>/dev/null || echo 12121
import socket
s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()
PY
}

# Wait until 127.0.0.1:$1 accepts a connection (up to ~5 s).
wait_listen() {
    local p="$1" i
    for i in $(seq 50); do
        python3 - "$p" <<'PY' && return 0
import socket, sys
try:
    socket.create_connection(("127.0.0.1", int(sys.argv[1])), 0.3).close()
except OSError:
    sys.exit(1)
PY
        sleep 0.1
    done
    return 1
}

echo "FeroProbe: $FERO"
echo

# A scripts directory indexed by --script-updatedb, so category and name
# selection work; GATE_DIR holds a brute-category marker script and a
# safe one, both with a prerule so they run with no open port.
GATE_DIR="$TMP/gate"
mkdir -p "$GATE_DIR"
cat >"$GATE_DIR/lab-brute.lua" <<'LUA'
-- FeroProbe brute-gating lab marker (GPL-3.0-or-later, like FeroProbe).
description = "brute gate lab"
categories = { "brute" }
prerule = function() return true end
action = function() return "LAB-BRUTE-RAN" end
LUA
cat >"$GATE_DIR/lab-safe.lua" <<'LUA'
-- FeroProbe safe-gating lab marker (GPL-3.0-or-later, like FeroProbe).
description = "safe gate lab"
categories = { "safe" }
prerule = function() return true end
action = function() return "LAB-SAFE-RAN" end
LUA
GX="$TMP/gate-xdg"
mkdir -p "$GX/feroprobe/scripts"
cp "$GATE_DIR"/*.lua "$GX/feroprobe/scripts/"
XDG_DATA_HOME="$GX" "$FERO" --script-updatedb >/dev/null 2>&1

# gate SPEC: run the indexed lab scripts with --script SPEC on one closed
# port (prerules still fire), capturing stdout and the warning on stderr.
gate() { OUT=$(XDG_DATA_HOME="$GX" "$FERO" -Pn -sT -p 1 --script "$1" 127.0.0.1 2>&1); }

echo "1. opt-in gating"
# Swept up by a category: the brute script is left out, the safe one runs.
gate "all"
contains "'all' leaves the brute script out (warning)" "left out"
contains "  the warning names the brute script" "lab-brute"
lacks   "  the brute script does not run" "LAB-BRUTE-RAN"
contains "  a non-brute script still runs" "LAB-SAFE-RAN"
# Chosen by the `brute` word: it runs, with no warning.
gate "brute"
contains "the 'brute' word runs the brute script" "LAB-BRUTE-RAN"
lacks   "  no left-out warning for the 'brute' word" "left out"
# Chosen by exact name: it runs.
gate "lab-brute"
contains "an exact name runs the brute script" "LAB-BRUTE-RAN"
lacks   "  no left-out warning for an exact name" "left out"
# A name pattern is not deliberate enough: left out.
gate "*-brute"
contains "a '*-brute' wildcard leaves it out (warning)" "left out"
lacks   "  the wildcard does not run it" "LAB-BRUTE-RAN"
# A whole directory sweep leaves brute out but runs the safe script.
gate "$GATE_DIR/"
contains "a directory sweep leaves the brute script out" "left out"
lacks   "  the swept brute script does not run" "LAB-BRUTE-RAN"
contains "  a swept non-brute script still runs" "LAB-SAFE-RAN"
# A direct file path is deliberate: it runs.
gate "$GATE_DIR/lab-brute.lua"
contains "a file path runs the brute script" "LAB-BRUTE-RAN"
lacks   "  no left-out warning for a file path" "left out"
echo

echo "2. brute framework (login server)"
if ! command -v python3 >/dev/null; then
    skip "framework: python3 not installed"
else
    # A throwaway FTP control server that accepts only root:secret.
    SRV="$TMP/ftpd.py"
    cat >"$SRV" <<'PY'
import socket, sys, threading
port = int(sys.argv[1])
def handle(c):
    try:
        c.sendall(b"220 Lab FTP ready\r\n")
        user = b""
        buf = b""
        while True:
            d = c.recv(256)
            if not d:
                break
            buf += d
            while b"\r\n" in buf:
                line, buf = buf.split(b"\r\n", 1)
                cmd = line.split(b" ")[0].upper()
                arg = line[len(cmd) + 1:]
                if cmd == b"USER":
                    user = arg
                    c.sendall(b"331 need password\r\n")
                elif cmd == b"PASS":
                    if user == b"root" and arg == b"secret":
                        c.sendall(b"230 Logged in\r\n")
                    else:
                        c.sendall(b"530 Login incorrect\r\n")
                elif cmd == b"QUIT":
                    c.sendall(b"221 bye\r\n"); c.close(); return
                else:
                    c.sendall(b"500 ?\r\n")
    except OSError:
        pass
    finally:
        try:
            c.close()
        except OSError:
            pass
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port)); s.listen(8)
while True:
    conn, _ = s.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
PY
    # A brute script: its Driver logs in over FeroProbe's own ftp module.
    FX="$TMP/fw-xdg"
    mkdir -p "$FX/feroprobe/scripts"
    cat >"$FX/feroprobe/scripts/lab-ftp-brute.lua" <<'LUA'
-- FeroProbe brute-framework lab driver (GPL-3.0-or-later, like FeroProbe).
description = "brute framework lab (FTP)"
categories = { "brute" }
local brute = require "brute"
local creds = require "creds"
local ftp = require "ftp"
Driver = {}
Driver.__index = Driver
function Driver:new(host, port) return setmetatable({ host = host, port = port }, Driver) end
function Driver:connect()
  local sock, code, msg, buf = ftp.connect(self.host, self.port)
  if not sock then return false end
  self.sock, self.buf = sock, buf
  return true
end
function Driver:login(user, pass)
  local ok = ftp.auth(self.sock, self.buf, user, pass)
  if ok then return true, creds.Account:new(user, pass, creds.State.VALID) end
  local e = brute.Error:new("login failed"); e:setRetry(false)
  return false, e
end
function Driver:disconnect()
  if self.sock then ftp.close(self.sock) end
  return true
end
portrule = function(host, port) return true end
action = function(host, port)
  local engine = brute.Engine:new(Driver, host, port)
  engine.options.useraspass = false
  engine.options.emptypass = false
  local ok, result = engine:start()
  return result
end
LUA
    XDG_DATA_HOME="$FX" "$FERO" --script-updatedb >/dev/null 2>&1

    printf 'root\nadmin\n' >"$TMP/users.txt"
    printf 'x\nsecret\n' >"$TMP/pass.txt"
    : >"$TMP/empty.txt"

    port=$(free_port)
    python3 "$SRV" "$port" >/dev/null 2>&1 &
    SERVER_PID=$!
    if wait_listen "$port"; then
        # Chosen by name, so the brute script runs; the word lists come from
        # the userdb/passdb files.
        OUT=$(XDG_DATA_HOME="$FX" "$FERO" -sT -Pn -p "$port" --script lab-ftp-brute \
            --script-args "userdb=$TMP/users.txt,passdb=$TMP/pass.txt" 127.0.0.1 2>&1)
        contains "the one valid account is found" "root:secret"
        contains "  it is reported valid" "Valid credentials"
        lacks   "  no invalid pair is stored" "admin:"
        # An empty word list finds nothing (the safe default without lists).
        OUT=$(XDG_DATA_HOME="$FX" "$FERO" -sT -Pn -p "$port" --script lab-ftp-brute \
            --script-args "userdb=$TMP/empty.txt,passdb=$TMP/empty.txt" 127.0.0.1 2>&1)
        contains "an empty word list finds nothing" "No valid accounts found"
    else
        fail "framework: the test FTP server did not start"
    fi
    kill "$SERVER_PID" 2>/dev/null; SERVER_PID=""
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
