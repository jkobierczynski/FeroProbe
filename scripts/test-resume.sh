#!/usr/bin/env bash
#
# test-resume.sh: end-to-end check of --resume and the host groups it relies
# on (--min-hostgroup, --max-hostgroup).
#
# Builds a private two-namespace lab (see scripts/lib/lab.sh) and gives the
# target 12 more addresses, 10.66.1.10-21, so a scan has hosts to group.
# Each host has one open port and four that silently drop probes, so every
# host takes about one --timeout to scan. Checks:
#
#   host groups   -v shows one TCP scan per group: 12 hosts in groups of 3
#                 is 4 scans; nmap's default for 5 ports (1024/5 = 204) is
#                 one scan of all 12; --min-hostgroup is a floor; min > max
#                 is refused; min above 100 warns, as in nmap
#   abort         a scan in groups of 2, stopped with Ctrl-C (SIGINT) after
#                 its first groups: the -oN, -oG and -oX files already hold
#                 those hosts and no closing line
#   resume        "feroprobe --resume FILE" from each of the three reports
#                 (restored to the aborted state each time): it sends no
#                 probe to a finished host, scans every other one, and
#                 leaves each report listing all 12 hosts exactly once, with
#                 a valid XML document and two "scan initiated" lines
#   refusals      --resume with another option; a file that is no report
#   edge cases    a report without a finished host starts from the
#                 beginning; a last host that is not among the targets
#                 leaves nothing to scan; both with a warning
#
# Needs root and Linux. Prints PASS/FAIL per check, exits non-zero on failure.
#
# Usage:   sudo ./scripts/test-resume.sh [--bin PATH] [-v]
#
set -euo pipefail
. "$(dirname "$0")/lib/lab.sh"
lab_usage_args "$@"
lab_require
lab_find_bin --resume
lab_up

# 12 more addresses on the target's link-A side.
HOSTS=()
for i in $(seq 10 21); do
    nsx "$NS_TGT" ip addr add "10.66.1.$i/24" dev fpt-a1
    HOSTS+=("10.66.1.$i")
done
RANGE=10.66.1.10-21
PORTS="$TCP_OPEN,18100-18103"   # one open port, four dropped
SLOW=(-Pn -sT -p "$PORTS" --timeout 400 --max-retries 0)

# Scans of the lab's hosts per -v run: "Initiating TCP connect scan of N hosts".
scan_sizes() { grep -o 'Initiating TCP connect scan of [0-9]*' "$OUT" | awk '{print $NF}' | paste -sd' ' -; }

echo "== host groups =="
fero "${SLOW[@]}" -v --max-hostgroup 3 "$RANGE"
check "exit status" "$RC" 0
check "groups of 3" "$(scan_sizes)" "3 3 3 3"
fero "${SLOW[@]}" -v "$RANGE"
check "nmap's default size for 5 ports" "$(scan_sizes)" "12"
fero "${SLOW[@]}" -v --min-hostgroup 5 --max-hostgroup 5 "$RANGE"
check "--min-hostgroup 5 --max-hostgroup 5" "$(scan_sizes)" "5 5 2"
fero "${SLOW[@]}" --min-hostgroup 5 --max-hostgroup 2 "$RANGE"
check_true "min above max refused (exit $RC)" test "$RC" -eq 1
check_true "  saying why" output_has "may not be greater than --max-hostgroup"
fero -Pn -sT --min-hostgroup 101 -p "$TCP_OPEN" "$TGT_A"
check_true "min above 100 warns" output_has "highly aggressive --min-hostgroup"

# --- an aborted scan ----------------------------------------------------------
echo "== abort after the first groups =="
WORK="$(lab_tmp)"
SNAP="$(lab_tmp)"
(
    cd "$WORK"
    # A background job starts with SIGINT ignored; give it back its default,
    # so the INT below acts like Ctrl-C.
    exec python3 -c 'import os, signal, sys
signal.signal(signal.SIGINT, signal.SIG_DFL)
os.execvp(sys.argv[1], sys.argv[1:])' \
        ip netns exec "$NS_SCAN" "$BIN" -n "${SLOW[@]}" --max-hostgroup 2 -oA scan "$RANGE" \
        >/dev/null 2>&1
) &
SCAN_PID=$!
_PIDS+=("$SCAN_PID")
# Stop it once two groups (4 hosts) are in the grepable report.
for _ in $(seq 200); do
    n=$(grep -c 'Status: Up' "$WORK/scan.gnmap" 2>/dev/null || true)
    [ "${n:-0}" -ge 4 ] && break
    sleep 0.05
done
# python3 and "ip netns exec" both exec, so this is the scanner itself.
kill -INT "$SCAN_PID" 2>/dev/null || true
wait "$SCAN_PID" 2>/dev/null || true
cp "$WORK"/scan.* "$SNAP/"

done_hosts=$(grep 'Status: Up' "$SNAP/scan.gnmap" | awk '{print $2}')
n_done=$(echo "$done_hosts" | grep -c . || true)
check_true "aborted with some hosts finished ($n_done of 12)" \
    test "$n_done" -ge 4 -a "$n_done" -lt 12
check_true "grepable report has no closing line" \
    sh -c "! grep -q '^# FeroProbe done' '$SNAP/scan.gnmap'"
check_true "XML report not closed yet" sh -c "! grep -q '</nmaprun>' '$SNAP/scan.xml'"
check "normal report lists the same hosts" \
    "$(grep -c '^Scan report for' "$SNAP/scan.nmap")" "$n_done"
if [ "$VERBOSE" = 1 ]; then echo "finished before the abort:"; echo "$done_hosts"; fi

# Each host's appearances in a report: "12 x1" when all 12 appear once.
once_each() {   # args: file pattern-before-address [pattern-after-address]
    local f="$1" pre="$2" post="${3:-}" h c counts=""
    for h in "${HOSTS[@]}"; do
        c=$(grep -cE "${pre}${h//./\\.}([^0-9]|$).*${post}" "$f" || true)
        counts+="$c "
    done
    echo "$counts" | tr ' ' '\n' | grep . | sort | uniq -c | awk '{printf "%s x%s ", $1, $2}' | sed 's/ $//'
}

for ext in gnmap nmap xml; do
    echo "== --resume scan.$ext =="
    rm -f "$WORK"/scan.*
    cp "$SNAP"/scan.* "$WORK/"
    capture_start
    RC=0
    (cd "$WORK" && nsx "$NS_SCAN" "$BIN" --resume "scan.$ext") >"$WORK/out.txt" 2>&1 || RC=$?
    capture_stop
    OUT="$WORK/out.txt"
    if [ "$VERBOSE" = 1 ]; then cat "$OUT"; fi
    check "exit status" "$RC" 0
    check_true "says what it skips" output_has "Resuming the scan in scan.$ext: skipping $n_done targets"
    # No probe to a host the aborted run finished; probes to all the others.
    probed=$(cap "\$3==\"out\" && \$4==\"tcp\" && \$9==\"S\" {print \$7}" | sort -u)
    again=0
    for h in $done_hosts; do echo "$probed" | grep -qx "$h" && again=$((again + 1)); done
    check "finished hosts probed again" "$again" 0
    check "hosts probed" "$(echo "$probed" | grep -c '^10\.66\.1\.' || true)" "$((12 - n_done))"
    check "grepable: each host once" "$(once_each "$WORK/scan.gnmap" 'Host: ' 'Status: Up')" "12 x1"
    check "grepable: scan initiated lines" "$(grep -c 'scan initiated' "$WORK/scan.gnmap")" 2
    check "grepable: closing line" "$(grep -c '^# FeroProbe done' "$WORK/scan.gnmap")" 1
    check "normal: each host once" "$(once_each "$WORK/scan.nmap" 'Scan report for ')" "12 x1"
    check "normal: scan initiated lines" "$(grep -c 'scan initiated' "$WORK/scan.nmap")" 2
    xml_hosts=$(python3 - "$WORK/scan.xml" <<'PY'
import sys, xml.etree.ElementTree as ET
try:
    root = ET.parse(sys.argv[1]).getroot()
except ET.ParseError as e:
    print("invalid:", e); sys.exit()
addrs = [a.get("addr") for a in root.iter("address") if a.get("addrtype") == "ipv4"]
print(len(addrs), "hosts,", len(set(addrs)), "distinct")
PY
)
    check "XML: one valid document" "$xml_hosts" "12 hosts, 12 distinct"
done

# --- refusals and edge cases -------------------------------------------------
echo "== refusals =="
RC=0
nsx "$NS_SCAN" "$BIN" --resume "$SNAP/scan.gnmap" -p 80 >"$WORK/out.txt" 2>&1 || RC=$?
OUT="$WORK/out.txt"
check_true "--resume with another option refused (exit $RC)" test "$RC" -ne 0
check_true "  with nmap's reason" output_has "cannot be combined with other options"
echo "just some text, not a report at all" >"$WORK/notes.txt"
RC=0
nsx "$NS_SCAN" "$BIN" --resume "$WORK/notes.txt" >"$WORK/out.txt" 2>&1 || RC=$?
OUT="$WORK/out.txt"
check_true "a file that is no report refused (exit $RC)" test "$RC" -ne 0

echo "== a report without a finished host =="
rm -f "$WORK"/scan.*
head -n 1 "$SNAP/scan.gnmap" >"$WORK/scan.gnmap"
capture_start
RC=0
(cd "$WORK" && nsx "$NS_SCAN" "$BIN" --resume scan.gnmap) >"$WORK/out.txt" 2>&1 || RC=$?
capture_stop
OUT="$WORK/out.txt"
check "exit status" "$RC" 0
check_true "warns it starts from the beginning" output_has "lists no finished host"
check "hosts probed" "$(cap "\$3==\"out\" && \$4==\"tcp\" && \$9==\"S\" {print \$7}" | sort -u | grep -c '^10\.66\.1\.' || true)" 12

echo "== a last host that is not among the targets =="
rm -f "$WORK"/scan.*
cp "$SNAP"/scan.* "$WORK/"
last=$(echo "$done_hosts" | tail -n 1)
sed -i "s/^Host: ${last//./\\.} /Host: 10.66.9.9 /" "$WORK/scan.gnmap"
capture_start
RC=0
(cd "$WORK" && nsx "$NS_SCAN" "$BIN" --resume scan.gnmap) >"$WORK/out.txt" 2>&1 || RC=$?
capture_stop
OUT="$WORK/out.txt"
check "exit status" "$RC" 0
check_true "warns nothing is left to scan" output_has "is not among the targets"
check "hosts probed" "$(cap_count "\$3==\"out\" && \$4==\"tcp\" && \$9==\"S\"")" 0

lab_finish
