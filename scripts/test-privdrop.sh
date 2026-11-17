#!/usr/bin/env bash
#
# test-privdrop.sh: end-to-end check of how FeroProbe handles root under
# sudo, and of the settings-file checks (security review M1, M2, M3).
#
# It plays "sudo by the user nobody" by setting SUDO_UID, SUDO_GID and
# SUDO_USER, so no second account is needed:
#
#   hand-over        -v says root was given up; a raw SYN scan of 127.0.0.1
#                    still works; the report belongs to nobody
#   capabilities     while a scan runs, its uid is nobody's and it holds
#                    only CAP_NET_RAW, CAP_NET_ADMIN, CAP_NET_BIND_SERVICE
#   files as user    -iL of a root-only file and -oN into a root-only
#                    directory fail; with --keep-root both work, and the
#                    new report is handed to nobody
#   report links     with --keep-root, a link in a shared sticky directory
#                    is refused and its target left alone
#   settings files   a .feroproberc symlink is refused, a FIFO does not
#                    hang, a file owned by another user is skipped, and
#                    ics_protection = false there cannot switch off root's
#                    ics_protection = true
#
# Needs root and Linux; no network namespaces. Prints PASS/FAIL per check,
# exits non-zero on failure.
#
# Usage:   sudo ./scripts/test-privdrop.sh [--bin PATH] [-v]

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN=""
VERBOSE=0
while [ $# -gt 0 ]; do
    case "$1" in
        --bin) BIN="$2"; shift 2 ;;
        -v) VERBOSE=1; shift ;;
        *) echo "usage: $0 [--bin PATH] [-v]" >&2; exit 2 ;;
    esac
done
if [ "$(id -u)" != 0 ]; then echo "needs root" >&2; exit 2; fi
if [ -z "$BIN" ]; then
    for cand in "$REPO_ROOT/target/release/feroprobe" "$REPO_ROOT/target/debug/feroprobe"; do
        [ -x "$cand" ] && BIN="$cand" && break
    done
fi
[ -x "$BIN" ] || { echo "no feroprobe binary; build it or pass --bin" >&2; exit 2; }
# Absolute, since the scans run from other directories.
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"

NOBODY_UID=$(id -u nobody)
NOBODY_GID=$(id -g nobody)
WORK="$(mktemp -d)"
chmod 755 "$WORK"
trap 'rm -rf "$WORK"' EXIT
USERDIR="$WORK/user"; mkdir "$USERDIR"; chown "$NOBODY_UID:$NOBODY_GID" "$USERDIR"
ROOTDIR="$WORK/root"; mkdir -m 700 "$ROOTDIR"
# Root's own settings live under this HOME, so the host's are not touched.
export HOME="$WORK/home"; mkdir -p "$HOME"
unset XDG_CONFIG_HOME

FAILS=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; FAILS=$((FAILS + 1)); }
check_true() { local what="$1"; shift; if "$@"; then pass "$what"; else fail "$what"; fi; }

# Run FeroProbe as "root under sudo by nobody", from directory $DIR.
DIR="$USERDIR"
OUT="$WORK/out.txt"
fero() {
    RC=0
    (cd "$DIR" && SUDO_UID=$NOBODY_UID SUDO_GID=$NOBODY_GID SUDO_USER=nobody \
        timeout 20 "$BIN" "$@") >"$OUT" 2>&1 || RC=$?
    if [ "$VERBOSE" = 1 ]; then echo "--- feroprobe $* (exit $RC) ---"; cat "$OUT"; fi
}
has() { grep -q -- "$1" "$OUT"; }

echo "== hand-over =="
fero -v -n -sS -Pn -p 1 127.0.0.1 -oN "$USERDIR/r.txt"
check_true "scan as nobody exits 0 (exit $RC)" test "$RC" -eq 0
check_true "-v says root was given up" has "Gave up root: running as uid $NOBODY_UID"
check_true "raw SYN scan still reads port 1 closed" has "1/tcp .*closed"
check_true "report belongs to nobody" test "$(stat -c %u "$USERDIR/r.txt")" = "$NOBODY_UID"

echo "== capabilities =="
(cd "$USERDIR" && SUDO_UID=$NOBODY_UID SUDO_GID=$NOBODY_GID SUDO_USER=nobody \
    exec "$BIN" -n -sS -Pn --scan-delay 2s -p 1-3 127.0.0.1) >/dev/null 2>&1 &
PID=$!
sleep 1
STATUS="$(cat "/proc/$PID/status" 2>/dev/null || true)"
wait "$PID" 2>/dev/null
uid_line="$(awk '/^Uid:/ {print $2, $3, $4, $5}' <<<"$STATUS")"
check_true "real, effective, saved uid are nobody's ($uid_line)" \
    test "$uid_line" = "$NOBODY_UID $NOBODY_UID $NOBODY_UID $NOBODY_UID"
caps="$(awk '/^CapEff:/ {print $2}' <<<"$STATUS")"
# Bits 10, 12 and 13: CAP_NET_BIND_SERVICE, CAP_NET_ADMIN, CAP_NET_RAW.
check_true "effective capabilities are the three network ones ($caps)" \
    test "$caps" = "0000000000003400"
prm="$(awk '/^CapPrm:/ {print $2}' <<<"$STATUS")"
check_true "permitted capabilities are the same ($prm)" test "$prm" = "0000000000003400"

echo "== files as the user =="
echo 127.0.0.1 >"$ROOTDIR/targets.txt"; chmod 600 "$ROOTDIR/targets.txt"
fero -n -sn -iL "$ROOTDIR/targets.txt"
check_true "-iL of a root-only file fails (exit $RC)" test "$RC" -ne 0
fero --keep-root -n -sn -iL "$ROOTDIR/targets.txt"
check_true "--keep-root reads it (exit $RC)" test "$RC" -eq 0
fero -n -sn 127.0.0.1 -oN "$ROOTDIR/r.txt"
check_true "-oN into a root-only directory fails (exit $RC)" test "$RC" -ne 0
check_true "because it cannot be opened" has "opening $ROOTDIR/r.txt"
fero --keep-root -n -sn 127.0.0.1 -oN "$ROOTDIR/r.txt"
check_true "--keep-root writes it (exit $RC)" test "$RC" -eq 0
check_true "and hands the new file to nobody" test "$(stat -c %u "$ROOTDIR/r.txt" 2>/dev/null)" = "$NOBODY_UID"

echo "== report links as root =="
SHARED="$WORK/shared"; mkdir -m 1777 "$SHARED"
echo keep >"$ROOTDIR/victim"
ln -s "$ROOTDIR/victim" "$SHARED/scan.txt"
fero --keep-root -n -sn 127.0.0.1 -oN "$SHARED/scan.txt"
check_true "a link in a sticky shared directory is refused (exit $RC)" test "$RC" -ne 0
check_true "its target is untouched" test "$(cat "$ROOTDIR/victim")" = keep

echo "== settings files =="
ln -s /etc/shadow "$USERDIR/.feroproberc"
fero -n -sn 127.0.0.1
check_true "a .feroproberc symlink is refused (exit $RC)" test "$RC" -ne 0
check_true "naming the link as the reason" has "is a symbolic link"
check_true "and nothing of the target is printed" bash -c "! grep -q 'root:' '$OUT'"
rm "$USERDIR/.feroproberc"
mkfifo "$USERDIR/.feroproberc"
fero -n -sn 127.0.0.1
check_true "a FIFO .feroproberc fails at once instead of hanging (exit $RC)" \
    test "$RC" -ne 0 -a "$RC" -ne 124
check_true "naming it as not a regular file" has "not a regular file"
rm "$USERDIR/.feroproberc"
echo "ics_protection = true" >"$USERDIR/.feroproberc"
chown 12345 "$USERDIR/.feroproberc"
fero -n -sV -Pn -p 1 127.0.0.1
check_true "another user's .feroproberc is skipped with a warning" has "belongs to user id 12345"
check_true "so its setting does not apply (exit $RC)" test "$RC" -eq 0
mkdir -p "$HOME/.config/feroprobe"
echo "ics_protection = true" >"$HOME/.config/feroprobe/config.toml"
echo "ics_protection = false" >"$USERDIR/.feroproberc"
chown "$NOBODY_UID" "$USERDIR/.feroproberc"
fero -n -sV -Pn -p 1 127.0.0.1
check_true ".feroproberc cannot switch ICS protection off: -sV refused (exit $RC)" test "$RC" -ne 0
check_true "with a warning naming the directory file" has "can switch ICS protection on but not off"

echo
if [ "$FAILS" -eq 0 ]; then echo "All checks passed."; else echo "$FAILS check(s) failed."; fi
exit $(( FAILS > 0 ))
