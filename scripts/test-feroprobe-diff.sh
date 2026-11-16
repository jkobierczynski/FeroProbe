#!/usr/bin/env bash
#
# test-feroprobe-diff.sh: end-to-end check of every feroprobe-diff feature.
#
# Writes small scan reports in a temporary directory, runs feroprobe-diff on
# pairs of them and checks the output and the exit status:
#
#   options        -h/--help, -V/--version, -v/--verbose, --text, --xml,
#                  --text with --xml, wrong number of files, unknown option
#   exit status    0 same, 1 different, 2 error
#   hosts          added, removed, up/down, renamed (paired by address),
#                  numeric order, IPv4 before IPv6, MAC case, hosts with
#                  only a name
#   ports          state changes, ports moving into and out of "Not shown",
#                  "Not shown" counts, ports both scans fold away
#   services       name, product, version, extra info, SSL tunnel; details
#                  that are not compared (reason, method, conf, CPE)
#   OS matches     changed, added, removed, unchanged context
#   scripts        port, host, pre-scan and post-scan scripts, the
#                  "|  id: ... |_ last" layout, empty output, very long output
#   banner         scanner name, UTC times, command line; does not count
#   input          nmap reports, DOCTYPE and processing instructions,
#                  --append-output files, other documents, broken XML,
#                  warnings for unusable elements
#   XML output     ndiff's layout, checked with Python's XML parser
#   real scans     a local port scanned open, then closed (connect scan,
#                  no root needed)
#
# Needs bash and python3 (for the XML checks and the local listener).
# Prints PASS/FAIL per check, exits non-zero on any failure.
#
# Usage:   ./scripts/test-feroprobe-diff.sh [--bin-dir DIR] [-v]
#
#   --bin-dir DIR   use feroprobe and feroprobe-diff from DIR (default: build
#                   them with cargo and use target/debug)
#   -v              show the output of each failed check in full
#
# With KEEP=1 in the environment the temporary directory with the reports
# is kept and its path printed, to rerun a failed comparison by hand.

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
    echo "Building feroprobe and feroprobe-diff..."
    (cd "$ROOT" && cargo build -q -p feroprobe --bins) || exit 2
    BIN_DIR="$ROOT/target/debug"
fi
DIFF="$BIN_DIR/feroprobe-diff"
FERO="$BIN_DIR/feroprobe"
[ -x "$DIFF" ] || { echo "no feroprobe-diff in $BIN_DIR" >&2; exit 2; }
command -v python3 >/dev/null || { echo "python3 is needed" >&2; exit 2; }

TMP=$(mktemp -d "${TMPDIR:-/tmp}/feroprobe-diff-test.XXXXXX") || exit 2
LISTENER_PID=""
cleanup() {
    [ -n "$LISTENER_PID" ] && kill "$LISTENER_PID" 2>/dev/null
    if [ -n "${KEEP:-}" ]; then echo "kept $TMP"; else rm -rf "$TMP"; fi
}
trap cleanup EXIT

PASS=0
FAIL=0
pass() { PASS=$((PASS + 1)); echo "  PASS  $1"; }
fail() {
    FAIL=$((FAIL + 1))
    echo "  FAIL  $1"
    if [ "$VERBOSE" = 1 ]; then
        printf '%s\n' "--- stdout ---" "$OUT" "--- stderr ---" "$ERR" "--- exit $RC ---" | sed 's/^/        /'
    fi
}

# check NAME GOT WANT
check() {
    if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (got '$2', want '$3')"; fi
}
# has NAME TEXT: the output holds TEXT as a whole line.
has() {
    if printf '%s\n' "$OUT" | grep -qxF -- "$2"; then pass "$1"; else fail "$1 (no line '$2')"; fi
}
# lacks NAME TEXT: the output has no line TEXT.
lacks() {
    if printf '%s\n' "$OUT" | grep -qxF -- "$2"; then fail "$1 (unexpected line '$2')"; else pass "$1"; fi
}
# contains NAME TEXT: the output holds TEXT somewhere.
contains() {
    case "$OUT" in *"$2"*) pass "$1" ;; *) fail "$1 (no '$2')" ;; esac
}
err_contains() {
    case "$ERR" in *"$2"*) pass "$1" ;; *) fail "$1 (stderr has no '$2')" ;; esac
}
# before NAME FIRST SECOND: line FIRST comes before line SECOND.
before() {
    local a b
    a=$(printf '%s\n' "$OUT" | grep -nxF -- "$2" | head -1 | cut -d: -f1)
    b=$(printf '%s\n' "$OUT" | grep -nxF -- "$3" | head -1 | cut -d: -f1)
    if [ -n "$a" ] && [ -n "$b" ] && [ "$a" -lt "$b" ]; then
        pass "$1"
    else
        fail "$1 ('$2' at line ${a:-none}, '$3' at line ${b:-none})"
    fi
}
# same NAME WANT: the whole output is exactly WANT.
same() {
    if [ "$OUT" = "$2" ]; then pass "$1"; else
        fail "$1 (output differs)"
        [ "$VERBOSE" = 1 ] && diff <(printf '%s\n' "$2") <(printf '%s\n' "$OUT") | sed 's/^/        /'
    fi
}

# run [options] FILE1 FILE2: sets OUT, ERR and RC.
run() {
    OUT=$("$DIFF" "$@" 2>"$TMP/stderr")
    RC=$?
    ERR=$(cat "$TMP/stderr")
}

# Report builders. report FILE [nmaprun attributes] < hosts
START_A=1763280000 # Sun Nov 16 08:00:00 2025 UTC
report() {
    local file="$TMP/$1"
    local attrs=${2:-"scanner=\"feroprobe\" args=\"feroprobe -sV 10.0.0.0/28\" start=\"$START_A\" version=\"0.5.0\""}
    {
        echo '<?xml version="1.0" encoding="UTF-8"?>'
        echo "<nmaprun $attrs>"
        cat
        echo '</nmaprun>'
    } >"$file"
}
# host ADDR [STATE] [CONTENT] [ADDRTYPE]
host() {
    printf '<host><status state="%s"/><address addr="%s" addrtype="%s"/>%s</host>\n' \
        "${2:-up}" "$1" "${4:-ipv4}" "${3:-}"
}
# port ID STATE [SERVICE ATTRIBUTES] [PROTO] [EXTRA CONTENT]
port() {
    local svc=""
    [ -n "${3:-}" ] && svc="<service $3/>"
    printf '<port protocol="%s" portid="%s"><state state="%s"/>%s%s</port>' \
        "${4:-tcp}" "$1" "$2" "$svc" "${5:-}"
}
ports() { printf '<ports>%s</ports>' "$*"; }
names() {
    local out="<hostnames>" n
    for n in "$@"; do out="$out<hostname name=\"$n\" type=\"PTR\"/>"; done
    printf '%s</hostnames>' "$out"
}
extra() { printf '<extraports state="%s" count="%s"/>' "$1" "$2"; }
os() {
    local out="<os>" m
    for m in "$@"; do out="$out<osmatch name=\"$m\" accuracy=\"100\"/>"; done
    printf '%s</os>' "$out"
}
script() { printf '<script id="%s" output="%s"/>' "$1" "$2"; }
NL='&#xa;'

# ---------------------------------------------------------------------------
echo "== options =="

host 10.0.0.1 up "$(ports "$(extra closed 999)" "$(port 22 open 'name="ssh"')")" | report base.xml
host 10.0.0.1 up "$(ports "$(extra closed 998)" "$(port 22 open 'name="ssh"')" "$(port 80 open 'name="http"')")" | report base2.xml

run -h
check "-h exits 0" "$RC" 0
contains "-h shows the usage" "Usage: feroprobe-diff [options] FILE1 FILE2"
contains "-h lists --xml" "--xml"
run --help
check "--help exits 0" "$RC" 0
contains "--help shows the usage" "Usage: feroprobe-diff"

run -V
check "-V exits 0" "$RC" 0
contains "-V names the program" "feroprobe-diff"
VERSION=$(grep -m1 '^version' "$ROOT/Cargo.toml" "$ROOT/crates/feroprobe-cli/Cargo.toml" 2>/dev/null | head -1 | sed 's/.*"\(.*\)".*/\1/')
[ -n "$VERSION" ] && contains "-V shows the version ($VERSION)" "$VERSION"
run --version
check "--version exits 0" "$RC" 0

run "$TMP/base.xml" "$TMP/base2.xml"
TEXT_DEFAULT=$OUT
check "two different scans exit 1" "$RC" 1
run --text "$TMP/base.xml" "$TMP/base2.xml"
check "--text exits 1" "$RC" 1
check "--text is the default output" "$OUT" "$TEXT_DEFAULT"
run --text --text "$TMP/base.xml" "$TMP/base2.xml"
check "--text twice is accepted" "$RC" 1

run --text --xml "$TMP/base.xml" "$TMP/base2.xml"
check "--text with --xml exits 2" "$RC" 2
run "$TMP/base.xml"
check "one file exits 2" "$RC" 2
run "$TMP/base.xml" "$TMP/base.xml" "$TMP/base.xml"
check "three files exit 2" "$RC" 2
run
check "no files exits 2" "$RC" 2
run --bogus "$TMP/base.xml" "$TMP/base2.xml"
check "unknown option exits 2" "$RC" 2
run "$TMP/missing.xml" "$TMP/base.xml"
check "missing first file exits 2" "$RC" 2
err_contains "missing file is named" "missing.xml"
run "$TMP/base.xml" "$TMP/missing.xml"
check "missing second file exits 2" "$RC" 2

# ---------------------------------------------------------------------------
echo "== same scans =="

run "$TMP/base.xml" "$TMP/base.xml"
check "same scan exits 0" "$RC" 0
check "same scan prints nothing" "$OUT" ""
for v in -v --verbose; do
    run "$v" "$TMP/base.xml" "$TMP/base.xml"
    check "$v on the same scan exits 0" "$RC" 0
    has "$v shows the banner" " FeroProbe 0.5.0 scan initiated Sun Nov 16 08:00:00 2025 UTC as: feroprobe -sV 10.0.0.0/28"
    has "$v shows the unchanged host" " 10.0.0.1:"
    has "$v shows the host state" " Host is up."
    has "$v shows Not shown" " Not shown: 999 closed ports"
    has "$v shows the port" " 22/tcp open  ssh"
done
run -v "$TMP/base.xml" "$TMP/base2.xml"
check "-v on different scans exits 1" "$RC" 1
has "-v marks unchanged ports with a space" " 22/tcp open  ssh"
has "-v marks the new port" "+80/tcp open  http"

# ---------------------------------------------------------------------------
echo "== hosts =="

{
    host 10.0.0.2 up "$(ports "$(port 53 open 'name="domain"')")"
    host 10.0.0.3 up "$(ports "$(port 53 open 'name="domain"')")"
    host 10.0.0.4 up "$(ports "$(port 53 open 'name="domain"')")"
} | report hosts-a.xml
{
    host 10.0.0.2 up "$(ports "$(port 53 open 'name="domain"')")"
    host 10.0.0.4 down
    host 10.0.0.9 up "$(ports "$(port 25 open 'name="smtp"')")"
} | report hosts-b.xml
run "$TMP/hosts-a.xml" "$TMP/hosts-b.xml"
check "host changes exit 1" "$RC" 1
lacks "unchanged host is not shown" " 10.0.0.2:"
has "removed host" "-10.0.0.3:"
has "removed host's state" "-Host is up."
has "removed host's port" "-53/tcp open  domain"
has "added host" "+10.0.0.9:"
has "added host's port" "+25/tcp open  smtp"
has "host that went down" " 10.0.0.4:"
has "old host state" "-Host is up."
has "new host state" "+Host is down."
same "full text of the host changes" "
-10.0.0.3:
-Host is up.
-PORT   STATE SERVICE VERSION
-53/tcp open  domain

 10.0.0.4:
-Host is up.
+Host is down.
 PORT   STATE SERVICE VERSION
-53/tcp open  domain

+10.0.0.9:
+Host is up.
+PORT   STATE SERVICE VERSION
+25/tcp open  smtp"

# Renamed host: paired by address, shown once with the old and new name.
host 10.0.0.12 up "$(names old-name.lan)" | report rename-a.xml
host 10.0.0.12 up "$(names new-name.lan)" | report rename-b.xml
run "$TMP/rename-a.xml" "$TMP/rename-b.xml"
check "renamed host exits 1" "$RC" 1
same "renamed host is one block" "
-old-name.lan (10.0.0.12):
+new-name.lan (10.0.0.12):"

# Name added to a host that had none.
host 10.0.0.12 up | report noname.xml
run "$TMP/noname.xml" "$TMP/rename-b.xml"
check "host that gained a name exits 1" "$RC" 1
has "old name line" "-10.0.0.12:"
has "new name line" "+new-name.lan (10.0.0.12):"

# Numeric host order: 10.0.0.2 before 10.0.0.10 before 10.0.0.100, IPv4
# before IPv6.
{
    host 10.0.0.100 up
    host 10.0.0.10 up
    host 2001:db8::1 up "" ipv6
    host 10.0.0.2 up
} | report order-a.xml
{
    host 10.0.0.100 down
    host 10.0.0.10 down
    host 2001:db8::1 down "" ipv6
    host 10.0.0.2 down
} | report order-b.xml
run "$TMP/order-a.xml" "$TMP/order-b.xml"
check "order test exits 1" "$RC" 1
before "10.0.0.2 before 10.0.0.10" " 10.0.0.2:" " 10.0.0.10:"
before "10.0.0.10 before 10.0.0.100" " 10.0.0.10:" " 10.0.0.100:"
before "IPv4 before IPv6" " 10.0.0.100:" " 2001:db8::1:"

# MAC addresses: case is no change; a host is paired by its IP, not its MAC.
printf '<host><status state="up"/><address addr="10.0.0.7" addrtype="ipv4"/><address addr="aa:bb:cc:dd:ee:ff" addrtype="mac"/></host>\n' | report mac-a.xml
printf '<host><status state="up"/><address addr="10.0.0.7" addrtype="ipv4"/><address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/></host>\n' | report mac-b.xml
run "$TMP/mac-a.xml" "$TMP/mac-b.xml"
check "MAC address case is no change" "$RC" 0
check "MAC address case prints nothing" "$OUT" ""
printf '<host><status state="up"/><address addr="10.0.0.7" addrtype="ipv4"/><address addr="11:22:33:44:55:66" addrtype="mac"/></host>\n' | report mac-c.xml
run "$TMP/mac-a.xml" "$TMP/mac-c.xml"
check "new MAC address is a change" "$RC" 1
has "old MAC in the name line" "-10.0.0.7, AA:BB:CC:DD:EE:FF:"
has "new MAC in the name line" "+10.0.0.7, 11:22:33:44:55:66:"

# A host with only a name is paired by that name.
printf '<host><status state="up"/>%s%s</host>\n' "$(names only-name.lan)" "$(ports "$(port 22 open 'name="ssh"')")" | report nameonly-a.xml
printf '<host><status state="up"/>%s%s</host>\n' "$(names only-name.lan)" "$(ports "$(port 22 closed 'name="ssh"')")" | report nameonly-b.xml
run "$TMP/nameonly-a.xml" "$TMP/nameonly-b.xml"
check "name-only host change exits 1" "$RC" 1
has "name-only host is paired by name" " only-name.lan:"
has "name-only host's old port" "-22/tcp open   ssh"
has "name-only host's new port" "+22/tcp closed ssh"

# ---------------------------------------------------------------------------
echo "== ports =="

host 10.0.0.5 up "$(ports "$(extra closed 997)" \
    "$(port 22 open 'name="ssh"')" \
    "$(port 25 open 'name="smtp"')" \
    "$(port 161 open 'name="snmp"' udp)")" | report ports-a.xml
host 10.0.0.5 up "$(ports "$(extra closed 996)" \
    "$(port 25 filtered 'name="smtp"')" \
    "$(port 161 open 'name="snmp"' udp)" \
    "$(port 443 open 'name="https"')" \
    "$(port 8080 open 'name="http-proxy"')")" | report ports-b.xml
run "$TMP/ports-a.xml" "$TMP/ports-b.xml"
check "port changes exit 1" "$RC" 1
has "port that fell into Not shown: - only" "-22/tcp   open     ssh"
lacks "port that fell into Not shown: no + line" "+22/tcp   closed   ssh"
has "port state change: old" "-25/tcp   open     smtp"
has "port state change: new" "+25/tcp   filtered smtp"
has "new port" "+443/tcp  open     https"
has "another new port" "+8080/tcp open     http-proxy"
lacks "unchanged UDP port is not shown" " 161/udp  open     snmp"
has "old Not shown count" "-Not shown: 997 closed ports"
has "new Not shown count" "+Not shown: 996 closed ports"
has "host block header" " 10.0.0.5:"
has "port table header" " PORT     STATE    SERVICE    VERSION"

# Same port number, different protocol: two ports.
host 10.0.0.5 up "$(ports "$(port 53 open 'name="domain"')")" | report proto-a.xml
host 10.0.0.5 up "$(ports "$(port 53 open 'name="domain"' udp)")" | report proto-b.xml
run "$TMP/proto-a.xml" "$TMP/proto-b.xml"
check "TCP port replaced by UDP port exits 1" "$RC" 1
has "53/tcp is gone" "-53/tcp open  domain"
has "53/udp is new" "+53/udp open  domain"

# Not shown groups: several states, and a port both scans fold away.
host 10.0.0.5 up "$(ports "$(extra closed 990)" "$(extra filtered 9)" "$(port 22 open)")" | report extra-a.xml
host 10.0.0.5 up "$(ports "$(extra closed 990)" "$(extra filtered 10)")" | report extra-b.xml
run "$TMP/extra-a.xml" "$TMP/extra-b.xml"
check "Not shown with two states exits 1" "$RC" 1
has "two Not shown groups, old" "-Not shown: 990 closed ports, 9 filtered ports"
has "two Not shown groups, new" "+Not shown: 990 closed ports, 10 filtered ports"
host 10.0.0.5 up "$(ports "$(extra closed 999)" "$(port 22 closed)")" | report folded-a.xml
host 10.0.0.5 up "$(ports "$(extra closed 999)")" | report folded-b.xml
run "$TMP/folded-a.xml" "$TMP/folded-b.xml"
lacks "a port both scans fold into Not shown is not listed" "-22/tcp closed"

# ---------------------------------------------------------------------------
echo "== services =="

host 10.0.0.6 up "$(ports \
    "$(port 21 open 'name="ftp"')" \
    "$(port 22 open 'name="ssh" product="OpenSSH" version="9.6p1" extrainfo="protocol 2.0"')" \
    "$(port 80 open 'name="http"')" \
    "$(port 443 open 'name="http"')" \
    "$(port 3306 open 'name="mysql" product="MySQL" version="8.0.1"')" \
    "$(port 8443 open 'name="http" tunnel="ssl"')" \
    "$(port 9000 open 'name="http" product="Go" method="table" conf="3"')")" | report svc-a.xml
host 10.0.0.6 up "$(ports \
    "$(port 21 open 'name="ftp"')" \
    "$(port 22 open 'name="ssh" product="OpenSSH" version="9.6p1" extrainfo="protocol 2.1"')" \
    "$(port 80 open 'name="http" product="nginx" version="1.24.0"')" \
    "$(port 443 open 'name="http" tunnel="ssl"')" \
    "$(port 3306 open 'name="mysql" product="MariaDB" version="8.0.1"')" \
    "$(port 8443 open 'name="https-alt" tunnel="ssl"')" \
    "$(port 9000 open 'name="http" product="Go" method="probed" conf="10"' tcp '<cpe>cpe:/a:golang:go</cpe>')")" | report svc-b.xml
run "$TMP/svc-a.xml" "$TMP/svc-b.xml"
check "service changes exit 1" "$RC" 1
lacks "unchanged service is not shown" " 21/tcp   open  ftp"
has "extra info change: old" "-22/tcp   open  ssh           OpenSSH 9.6p1 (protocol 2.0)"
has "extra info change: new" "+22/tcp   open  ssh           OpenSSH 9.6p1 (protocol 2.1)"
has "version gained: old" "-80/tcp   open  http"
has "version gained: new" "+80/tcp   open  http          nginx 1.24.0"
has "SSL tunnel gained: old" "-443/tcp  open  http"
has "SSL tunnel gained: new" "+443/tcp  open  ssl/http"
has "product change: old" "-3306/tcp open  mysql         MySQL 8.0.1"
has "product change: new" "+3306/tcp open  mysql         MariaDB 8.0.1"
has "service name change: old" "-8443/tcp open  ssl/http"
has "service name change: new" "+8443/tcp open  ssl/https-alt"
lacks "method, conf and CPE are not compared" "-9000/tcp open  http          Go"

# A tunnel change alone counts for the exit status (ndiff ignores it).
host 10.0.0.6 up "$(ports "$(port 443 open 'name="http"')")" | report tunnel-a.xml
host 10.0.0.6 up "$(ports "$(port 443 open 'name="http" tunnel="ssl"')")" | report tunnel-b.xml
run "$TMP/tunnel-a.xml" "$TMP/tunnel-b.xml"
check "SSL tunnel change alone exits 1" "$RC" 1

# Details that are not compared: reason, TTL, method, conf, CPE, times.
printf '<host starttime="1" endtime="2"><status state="up" reason="arp-response"/><address addr="10.0.0.6" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="ssh" method="table" conf="3"/></port></ports><times srtt="100" rttvar="5" to="100000"/></host>\n' | report ignored-a.xml
printf '<host starttime="5" endtime="9"><status state="up" reason="echo-reply"/><address addr="10.0.0.6" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="128"/><service name="ssh" method="probed" conf="10"><cpe>cpe:/a:openbsd:openssh</cpe></service></port></ports><times srtt="900" rttvar="50" to="200000"/></host>\n' | report ignored-b.xml
run "$TMP/ignored-a.xml" "$TMP/ignored-b.xml"
check "reasons, TTLs, method, conf, CPE and times are not compared" "$RC" 0
check "... and print nothing" "$OUT" ""

# ---------------------------------------------------------------------------
echo "== OS matches =="

host 10.0.0.8 up "$(os 'Linux 4.19 - 6.x' 'Linux 3.x' 'FreeBSD 13')" | report os-a.xml
host 10.0.0.8 up "$(os 'Linux 5.x' 'Linux 3.x' 'OpenBSD 7')" | report os-b.xml
run "$TMP/os-a.xml" "$TMP/os-b.xml"
check "OS change exits 1" "$RC" 1
same "OS matches: changed and unchanged context" "
 10.0.0.8:
 OS details:
-  Linux 4.19 - 6.x
+  Linux 5.x
   Linux 3.x
-  FreeBSD 13
+  OpenBSD 7"
host 10.0.0.8 up | report os-none.xml
run "$TMP/os-none.xml" "$TMP/os-b.xml"
check "OS matches added exits 1" "$RC" 1
has "OS details added" "+OS details:"
has "added match" "+  Linux 5.x"
run "$TMP/os-a.xml" "$TMP/os-none.xml"
check "OS matches removed exits 1" "$RC" 1
has "OS details removed" "-OS details:"
has "removed match" "-  FreeBSD 13"
run "$TMP/os-a.xml" "$TMP/os-a.xml"
check "same OS matches exit 0" "$RC" 0
run -v "$TMP/os-a.xml" "$TMP/os-a.xml"
has "-v shows OS details" " OS details:"
has "-v shows unchanged matches" "   Linux 3.x"

# ---------------------------------------------------------------------------
echo "== scripts =="

host 10.0.0.9 up "$(ports "$(port 80 open 'name="http"' tcp "$(script http-title "Welcome")$(script http-headers "Server: a${NL}Date: x${NL}Connection: close")")")<hostscript>$(script smb-os "Windows")</hostscript>" | report scr-a.xml
host 10.0.0.9 up "$(ports "$(port 80 open 'name="http"' tcp "$(script http-title "Hello")$(script http-headers "Server: b${NL}Date: x${NL}Connection: close")")")<hostscript>$(script smb-os "Windows")$(script nbstat "NAME")</hostscript>" | report scr-b.xml
run "$TMP/scr-a.xml" "$TMP/scr-b.xml"
check "script changes exit 1" "$RC" 1
has "port with changed scripts is shown for context" " 80/tcp open  http"
has "one-line script: old" "-|_ http-title: Welcome"
has "one-line script: new" "+|_ http-title: Hello"
has "multi-line script: first line changed, old" "-|  http-headers: Server: a"
has "multi-line script: first line changed, new" "+|  http-headers: Server: b"
has "multi-line script: unchanged middle line" " |  Date: x"
has "multi-line script: unchanged last line" " |_ Connection: close"
has "host script section" " Host script results:"
has "new host script" "+|_ nbstat: NAME"
lacks "unchanged host script is not shown" " |_ smb-os: Windows"
run -v "$TMP/scr-a.xml" "$TMP/scr-a.xml"
has "-v shows unchanged scripts" " |_ smb-os: Windows"

host 10.0.0.9 up | report scr-none.xml
host 10.0.0.9 up "<hostscript>$(script smb-os "Windows")</hostscript>" | report scr-host.xml
run "$TMP/scr-none.xml" "$TMP/scr-host.xml"
check "host scripts added exit 1" "$RC" 1
has "host script section added" "+Host script results:"
run "$TMP/scr-host.xml" "$TMP/scr-none.xml"
has "host script section removed" "-Host script results:"
has "removed host script" "-|_ smb-os: Windows"

# Pre-scan and post-scan scripts count (ndiff prints them but exits 0).
host 10.0.0.9 up | report pre-a.xml
{ echo "<prescript>$(script broadcast-ping "10.0.0.9")</prescript>"; host 10.0.0.9 up; echo "<postscript>$(script summary "1 host")</postscript>"; } | report pre-b.xml
run "$TMP/pre-a.xml" "$TMP/pre-b.xml"
check "pre- and post-scan script changes exit 1" "$RC" 1
has "pre-scan section" "+Pre-scan script results:"
has "pre-scan script" "+|_ broadcast-ping: 10.0.0.9"
has "post-scan section" "+Post-scan script results:"
has "post-scan script" "+|_ summary: 1 host"
before "pre-scan results come before the hosts" "+Pre-scan script results:" "+Post-scan script results:"

# A script with empty output still shows that it ran.
{ echo "<prescript><script id=\"bcast\" output=\"\"/></prescript>"; host 10.0.0.9 up; } | report empty-b.xml
run "$TMP/pre-a.xml" "$TMP/empty-b.xml"
check "empty script output is a change" "$RC" 1
has "empty script output shows the id" "+|_ bcast:"

# Very long script outputs that differ everywhere: shown as the old block
# replaced by the new one, quickly, instead of building a huge table.
python3 - "$TMP" <<'EOF'
import sys
tmp = sys.argv[1]
for name, tag in (("long-a.xml", "a"), ("long-b.xml", "b")):
    lines = "&#xa;".join(f"line {i} {tag}" for i in range(2500))
    with open(f"{tmp}/{name}", "w") as f:
        f.write('<nmaprun scanner="feroprobe"><host><status state="up"/>'
                '<address addr="10.0.0.9" addrtype="ipv4"/><hostscript>'
                f'<script id="big" output="{lines}"/></hostscript></host></nmaprun>')
EOF
SECONDS=0
run "$TMP/long-a.xml" "$TMP/long-b.xml"
check "very long script outputs exit 1" "$RC" 1
check_time=$SECONDS
if [ "$check_time" -le 20 ]; then pass "very long outputs finish quickly (${check_time}s)"; else fail "very long outputs took ${check_time}s"; fi
before "old block comes before the new one" "-|_ line 2499 a" "+|  big: line 0 b"
check "every old and new line is shown" "$(printf '%s\n' "$OUT" | grep -c '^[-+]|')" 5000

# ---------------------------------------------------------------------------
echo "== banner =="

host 10.0.0.1 up | report banner-a.xml
host 10.0.0.1 up | report banner-b.xml "scanner=\"feroprobe\" args=\"feroprobe -sV -O 10.0.0.0/28\" start=\"1763366400\" version=\"0.5.0\""
run "$TMP/banner-a.xml" "$TMP/banner-b.xml"
check "a different command line and time alone exit 0" "$RC" 0
has "old banner, in UTC" "-FeroProbe 0.5.0 scan initiated Sun Nov 16 08:00:00 2025 UTC as: feroprobe -sV 10.0.0.0/28"
has "new banner, in UTC" "+FeroProbe 0.5.0 scan initiated Mon Nov 17 08:00:00 2025 UTC as: feroprobe -sV -O 10.0.0.0/28"
host 10.0.0.1 up | report banner-nmap.xml "scanner=\"nmap\" args=\"nmap -sV 10.0.0.0/28\" start=\"$START_A\" version=\"7.95\""
run "$TMP/banner-a.xml" "$TMP/banner-nmap.xml"
has "nmap's reports show as Nmap" "+Nmap 7.95 scan initiated Sun Nov 16 08:00:00 2025 UTC as: nmap -sV 10.0.0.0/28"
check "a FeroProbe scan and an nmap scan of the same results exit 0" "$RC" 0
host 10.0.0.1 up | report banner-day.xml "scanner=\"feroprobe\" start=\"1772870400\""
run "$TMP/banner-a.xml" "$TMP/banner-day.xml"
has "single-digit days are zero-padded" "+FeroProbe scan initiated Sat Mar 07 08:00:00 2026 UTC"

# ---------------------------------------------------------------------------
echo "== input =="

# An nmap report with a DOCTYPE, a stylesheet, scaninfo, hosthints and
# runstats, compared with a FeroProbe report of the same results.
cat >"$TMP/nmap.xml" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<!-- Nmap 7.95 scan initiated Sun Nov 16 08:00:00 2025 as: nmap -sV 10.0.0.1 -->
<nmaprun scanner="nmap" args="nmap -sV 10.0.0.1" start="1763280000" startstr="Sun Nov 16 08:00:00 2025" version="7.95" xmloutputversion="1.05">
<scaninfo type="syn" protocol="tcp" numservices="1000" services="1-1000"/>
<verbose level="0"/>
<debugging level="0"/>
<hosthint><status state="up" reason="unknown-response" reason_ttl="0"/>
<address addr="10.0.0.1" addrtype="ipv4"/>
<hostnames>
</hostnames>
</hosthint>
<host starttime="1763280000" endtime="1763280010"><status state="up" reason="arp-response" reason_ttl="0"/>
<address addr="10.0.0.1" addrtype="ipv4"/>
<hostnames>
</hostnames>
<ports><extraports state="closed" count="999">
<extrareasons reason="reset" count="999" proto="tcp" ports="1-21,23-1000"/>
</extraports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="ssh" product="OpenSSH" version="9.6p1" method="probed" conf="10"><cpe>cpe:/a:openbsd:openssh:9.6p1</cpe></service></port>
</ports>
<times srtt="100" rttvar="50" to="100000"/>
</host>
<runstats><finished time="1763280010" timestr="Sun Nov 16 08:00:10 2025" summary="" elapsed="10.00" exit="success"/><hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>
EOF
host 10.0.0.1 up "$(ports "$(extra closed 999)" "$(port 22 open 'name="ssh" product="OpenSSH" version="9.6p1"')")" | report fero.xml
run "$TMP/nmap.xml" "$TMP/nmap.xml"
check "an nmap report with DOCTYPE and stylesheet reads" "$RC" 0
check "hosthints are not hosts" "$(run -v "$TMP/nmap.xml" "$TMP/nmap.xml"; printf '%s\n' "$OUT" | grep -c '^ 10.0.0.1:$')" 1
run "$TMP/nmap.xml" "$TMP/fero.xml"
check "nmap report against a FeroProbe report of the same results exits 0" "$RC" 0

cat "$TMP/base.xml" "$TMP/base2.xml" >"$TMP/appended.xml"
run "$TMP/appended.xml" "$TMP/base.xml"
check "an --append-output file exits 2" "$RC" 2
err_contains "... and says why" "more than one scan"
echo '<html><body/></html>' >"$TMP/html.xml"
run "$TMP/html.xml" "$TMP/base.xml"
check "a document that is not a scan report exits 2" "$RC" 2
err_contains "... and says so" "not a scan report"
echo '<nmaprun><host>' >"$TMP/broken.xml"
run "$TMP/broken.xml" "$TMP/base.xml"
check "broken XML exits 2" "$RC" 2
: >"$TMP/empty.xml"
run "$TMP/empty.xml" "$TMP/base.xml"
check "an empty file exits 2" "$RC" 2
echo '<nmaprun start="yesterday"/>' >"$TMP/badtime.xml"
run "$TMP/badtime.xml" "$TMP/base.xml"
check "a bad start time exits 2" "$RC" 2

printf '<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/><address addr="not-an-ip" addrtype="ipv4"/><ports><extraports state="closed"/><port protocol="tcp" portid="22"/><port portid="23"><state state="open"/></port><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port><script/></ports><hostscript><script id="x"/></hostscript></host>\n' | report warn.xml
host 10.0.0.1 up "$(ports "$(extra closed 0)" "$(port 22 open 'name="ssh"')")" | report warn-ok.xml
run "$TMP/warn.xml" "$TMP/warn-ok.xml"
check "unusable elements are skipped, the rest compares" "$RC" 0
err_contains "warning for an unreadable address" 'unreadable address "not-an-ip"'
err_contains "warning for a port without a state" "port 22/tcp of host 10.0.0.1 has no state"
err_contains "warning for a port without a protocol" "without a usable portid or protocol"
err_contains "warning for a Not shown group without a count" "without a usable count"
err_contains "warning for a script without an id or output" "a script element without an id or output"
err_contains "warnings name the file" "warn.xml"

# ---------------------------------------------------------------------------
echo "== XML output =="

# xmlcheck SCRIPT: run a Python check on $OUT; it prints problems, one per line.
xmlcheck() {
    local name=$1 problems
    problems=$(printf '%s' "$OUT" | python3 -c "
import sys, xml.etree.ElementTree as ET
root = ET.fromstring(sys.stdin.read())
problems = []
def need(cond, what):
    if not cond: problems.append(what)
$2
print('\n'.join(problems))
" 2>&1)
    if [ -z "$problems" ]; then pass "$name"; else fail "$name: $problems"; fi
}

run --xml "$TMP/hosts-a.xml" "$TMP/hosts-b.xml"
check "--xml on different scans exits 1" "$RC" 1
contains "XML declaration" '<?xml version="1.0" encoding="UTF-8"?>'
xmlcheck "ndiff's layout: nmapdiff, scandiff, hostdiff, a and b" '
need(root.tag == "nmapdiff", "root is " + root.tag)
need(root.get("version") == "1", "nmapdiff version")
sd = root.findall("scandiff")
need(len(sd) == 1, "one scandiff")
hd = root.findall("scandiff/hostdiff")
need(len(hd) == 3, "%d hostdiffs, want 3" % len(hd))
gone = [h for h in hd if h.find("a/host/address[@addr=\"10.0.0.3\"]") is not None]
need(len(gone) == 1, "removed host in <a>")
new = [h for h in hd if h.find("b/host/address[@addr=\"10.0.0.9\"]") is not None]
need(len(new) == 1, "added host in <b>")
down = [h for h in hd if h.find("host/address[@addr=\"10.0.0.4\"]") is not None]
need(len(down) == 1, "changed host outside a/b")
if down:
    need(down[0].find("host/a/status").get("state") == "up", "old status in <a>")
    need(down[0].find("host/b/status").get("state") == "down", "new status in <b>")
'
run --xml "$TMP/ports-a.xml" "$TMP/ports-b.xml"
xmlcheck "port state changes are portdiffs with the port in a and b" '
pd = root.findall(".//portdiff")
need(len(pd) >= 3, "%d portdiffs" % len(pd))
ids = {(p.find("*/port").get("portid") if p.find("*/port") is not None else None) for p in pd}
need("25" in ids and "443" in ids and "22" in ids, "portdiffs for 22, 25, 443: %s" % ids)
for p in pd:
    port = p.find("a/port")
    if port is None:
        port = p.find("b/port")
    if port is not None and port.get("portid") == "25":
        need(p.find("a/port/state").get("state") == "open", "25 open in <a>")
        need(p.find("b/port/state").get("state") == "filtered", "25 filtered in <b>")
need(root.find(".//extraports") is not None, "Not shown counts as extraports")
'
run --xml "$TMP/svc-a.xml" "$TMP/svc-b.xml"
xmlcheck "a service change has the two services in a and b" '
port443 = [p for p in root.iter("port") if p.get("portid") == "443"]
need(len(port443) == 1, "port 443 listed once")
if port443:
    old = port443[0].find("a/service")
    new = port443[0].find("b/service")
    need(old is not None and old.get("tunnel") is None, "443 without tunnel in <a>")
    need(new is not None and new.get("tunnel") == "ssl", "443 with ssl tunnel in <b>")
for s in root.iter("service"):
    extra = set(s.attrib) - {"name", "product", "version", "extrainfo", "tunnel"}
    need(not extra, "service has only compared attributes: %s" % extra)
need(not list(root.iter("cpe")), "no CPEs")
'
run --xml "$TMP/os-a.xml" "$TMP/os-b.xml"
xmlcheck "OS matches in os, with a and b" '
need(root.find(".//os") is not None, "os element")
names = [m.get("name") for m in root.iter("osmatch")]
need("Linux 5.x" in names and "Linux 4.19 - 6.x" in names, "osmatch names %s" % names)
for m in root.iter("osmatch"):
    need(set(m.attrib) == {"name"}, "osmatch has only name")
'
run --xml "$TMP/pre-a.xml" "$TMP/pre-b.xml"
xmlcheck "pre- and post-scan scripts" '
need(root.find(".//prescript") is not None, "prescript")
need(root.find(".//postscript") is not None, "postscript")
ids = [s.get("id") for s in root.iter("script")]
need("broadcast-ping" in ids and "summary" in ids, "script ids %s" % ids)
'
run --xml "$TMP/scr-a.xml" "$TMP/scr-b.xml"
xmlcheck "host scripts in hostscript" '
need(root.find(".//hostscript") is not None, "hostscript")
'
run --xml "$TMP/banner-a.xml" "$TMP/banner-b.xml"
check "--xml: run changes alone exit 0" "$RC" 0
xmlcheck "different runs: the two nmaprun elements in a and b come first" '
sd = root.find("scandiff")
first = list(sd)[:2]
need([e.tag for e in first] == ["a", "b"], "first children %s" % [e.tag for e in first])
need(first and first[0].find("nmaprun") is not None, "nmaprun in <a>")
need(len(first) > 1 and first[1].find("nmaprun").get("args") == "feroprobe -sV -O 10.0.0.0/28", "new args in <b>")
'
run --xml "$TMP/base.xml" "$TMP/base.xml"
check "--xml on the same scan exits 0" "$RC" 0
xmlcheck "--xml on the same scan has no hostdiff" '
need(root.tag == "nmapdiff", "root")
need(not list(root.iter("hostdiff")), "no hostdiff")
'
run -v --xml "$TMP/base.xml" "$TMP/base2.xml"
xmlcheck "-v --xml also lists unchanged hosts and ports" '
need(len(list(root.iter("port"))) >= 2, "both ports listed")
'
run --xml "$TMP/scr-a.xml" "$TMP/scr-b.xml"
xmlcheck "script output with special characters stays well-formed" 'pass'
host 10.0.0.1 up "$(ports "$(port 80 open 'name="http"' tcp "$(script t "&lt;b&gt; &amp; &quot;x&quot;")")")" | report special.xml
run --xml "$TMP/base.xml" "$TMP/special.xml"
xmlcheck "markup in script output is escaped" '
outs = [s.get("output") for s in root.iter("script")]
need("<b> & \"x\"" in outs, "output round-trips: %s" % outs)
'

# ---------------------------------------------------------------------------
echo "== output to a closed pipe =="

"$DIFF" -v "$TMP/long-a.xml" "$TMP/long-b.xml" 2>"$TMP/stderr" | head -1 >/dev/null
RC=${PIPESTATUS[0]}
check "a closed pipe is not an error (exit 1, not 2)" "$RC" 1
check "... and prints no message" "$(cat "$TMP/stderr")" ""

# ---------------------------------------------------------------------------
echo "== real scans =="

if [ ! -x "$FERO" ]; then
    echo "  SKIP  no feroprobe in $BIN_DIR"
else
    python3 -c '
import socket, sys, time
s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(16)
print(s.getsockname()[1], flush=True)
s.settimeout(1)
while True:
    try: c, _ = s.accept(); c.close()
    except socket.timeout: pass
' >"$TMP/port" &
    LISTENER_PID=$!
    for _ in $(seq 50); do [ -s "$TMP/port" ] && break; sleep 0.1; done
    PORT=$(cat "$TMP/port")
    "$FERO" -sT -Pn -n -p "$PORT" 127.0.0.1 -oX "$TMP/real-a.xml" >/dev/null 2>&1
    check "scan with the port open" "$?" 0
    kill "$LISTENER_PID" 2>/dev/null
    wait "$LISTENER_PID" 2>/dev/null
    LISTENER_PID=""
    "$FERO" -sT -Pn -n -p "$PORT" 127.0.0.1 -oX "$TMP/real-b.xml" >/dev/null 2>&1
    check "scan with the port closed" "$?" 0
    run "$TMP/real-a.xml" "$TMP/real-b.xml"
    check "real scans differ" "$RC" 1
    contains "the open port" "-$PORT/tcp open"
    contains "the closed port" "+$PORT/tcp closed"
    run "$TMP/real-a.xml" "$TMP/real-a.xml"
    check "a real scan against itself exits 0" "$RC" 0
    run --xml "$TMP/real-a.xml" "$TMP/real-b.xml"
    xmlcheck "XML of real scans" 'need(len(list(root.iter("portdiff"))) == 1, "one portdiff")'
    # -oA writes the .xml that feroprobe-diff reads.
    "$FERO" -sT -Pn -n -p "$PORT" 127.0.0.1 -oA "$TMP/real-c" >/dev/null 2>&1
    run "$TMP/real-b.xml" "$TMP/real-c.xml"
    check "the .xml of -oA reads, same results exit 0" "$RC" 0
fi

# ---------------------------------------------------------------------------
echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
