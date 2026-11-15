#!/usr/bin/env bash
#
# test-interface.sh: end-to-end check of -e <interface>.
#
# Builds a private two-namespace lab (see scripts/lib/lab.sh). The scanner
# reaches the target address 10.66.1.2 directly over link A (fpt-a0), and
# over link B (fpt-b0) through its default route. The script scans that one
# address with and without -e and checks on the wire which interface every
# probe left from:
#
#   no -e                  sanity: probes leave on fpt-a0, the direct route
#   -e fpt-a0  -sS/-sT/-sU probes leave on fpt-a0 only
#   -e fpt-b0  -sS/-sT/-sU probes leave on fpt-b0 only, from fpt-b0's address
#                          10.66.2.1, even though the routing table prefers
#                          fpt-a0; results are the same as over link A
#   -e fpt-a0  -sn         host discovery ARPs for the target on fpt-a0
#   -e fpt-b0  -sn         no ARP on fpt-a0 (the target is not on fpt-b0's
#                          network); the host is still found up over link B
#   -e nosuch0             an error, and nothing is sent
#
# Needs root and Linux. Prints PASS/FAIL per check, exits non-zero on failure.
#
# Usage:   sudo ./scripts/test-interface.sh [--bin PATH] [-v]
#
. "$(dirname "$0")/lib/lab.sh"
lab_usage_args "$@"
lab_require
lab_find_bin "-e <"
lab_up

TCP_PORTS="$TCP_OPEN,$TCP_CLOSED,$TCP_DROP"
# Probes the scanner sent to the target, optionally on one interface. A bare
# RST is left out: after a SYN scan finds an open port, the scanner's own
# kernel resets the connection it knows nothing about, and it routes that RST
# by the routing table, not by -e (nmap's scans show the same).
sent() { cap_count "\$3==\"out\" && \$7==\"$TGT_A\" && \$9!=\"R\" $1"; }

scan_checks() {   # args: scan-flag ports expected-iface other-iface expected-src
    local flag="$1" ports="$2" want="$3" other="$4" src="$5"
    check "exit status" "$RC" 0
    if [ "$flag" = -sU ]; then
        check "UDP echo port" "$(state_of udp "$UDP_OPEN")" open
        check "dropped UDP port" "$(state_of udp "$UDP_DROP")" "open|filtered"
    else
        check "open port" "$(state_of tcp "$TCP_OPEN")" open
        check "closed port" "$(state_of tcp "$TCP_CLOSED")" closed
        check "filtered port" "$(state_of tcp "$TCP_DROP")" filtered
    fi
    local n; n=$(sent "&& \$2==\"$want\"")
    check_true "probes sent on $want ($n)" test "$n" -gt 0
    check "probes sent on $other" "$(sent "&& \$2==\"$other\"")" 0
    check "probes from another address than $src" "$(sent "&& \$5!=\"$src\"")" 0
}

echo "== -sS without -e (sanity: the route goes over fpt-a0) =="
fero_captured -Pn -sS -p "$TCP_PORTS" "$TGT_A"
scan_checks -sS "$TCP_PORTS" fpt-a0 fpt-b0 "$SCAN_A"

for iface in fpt-a0 fpt-b0; do
    if [ "$iface" = fpt-a0 ]; then other=fpt-b0; src="$SCAN_A"; else other=fpt-a0; src="$SCAN_B"; fi
    for flag in -sS -sT; do
        echo "== $flag -e $iface =="
        fero_captured -Pn "$flag" -e "$iface" -p "$TCP_PORTS" "$TGT_A"
        scan_checks "$flag" "$TCP_PORTS" "$iface" "$other" "$src"
    done
    echo "== -sU -e $iface =="
    fero_captured -Pn -sU -e "$iface" -p "$UDP_OPEN,$UDP_DROP" "$TGT_A"
    scan_checks -sU "" "$iface" "$other" "$src"
done

echo "== -sn -e fpt-a0 (ARP discovery) =="
fero_captured -sn -e fpt-a0 "$TGT_A"
check "exit status" "$RC" 0
check_true "host reported up" output_has "host is up"
n=$(cap_count "\$4==\"arp\" && \$3==\"out\" && \$2==\"fpt-a0\" && \$7==\"$TGT_A\"")
check_true "ARP request for the target on fpt-a0 ($n)" test "$n" -gt 0

echo "== -sn -e fpt-b0 (routed discovery) =="
fero_captured -sn -e fpt-b0 "$TGT_A"
check "exit status" "$RC" 0
check_true "host reported up" output_has "host is up"
check "packets sent on fpt-a0" "$(cap_count '$3=="out" && $2=="fpt-a0"')" 0

echo "== -e nosuch0 =="
fero_captured -Pn -sS -e nosuch0 -p "$TCP_OPEN" "$TGT_A"
check_true "fails with a non-zero exit ($RC)" test "$RC" -ne 0
check_true "names the unknown interface" output_has "nosuch0"
check "probes sent" "$(sent "")" 0

lab_finish
