#!/usr/bin/env bash
#
# test-source-port.sh: end-to-end check of -g / --source-port.
#
# Builds a private two-namespace lab (see scripts/lib/lab.sh), scans the
# target with -g and checks on the wire which source port the probes used:
#
#   -sS -g 53            every SYN leaves from port 53; results unchanged
#   --source-port 53     the long name does the same
#   -sU -g 53            every UDP probe leaves from port 53; the UDP echo
#                        service still answers (open)
#   -sS (no -g)          sanity: the probes do not use port 53
#   -sT -g 53            warns that the connect scan cannot use -g, and the
#                        SYNs keep the system's ports (as in nmap)
#   -g 0                 warns that port 0 may not work (as in nmap), and
#                        still sends from port 0
#   -g 70000             rejected (not a port number)
#
# Needs root and Linux. Prints PASS/FAIL per check, exits non-zero on failure.
#
# Usage:   sudo ./scripts/test-source-port.sh [--bin PATH] [-v]
#
. "$(dirname "$0")/lib/lab.sh"
lab_usage_args "$@"
lab_require
lab_find_bin --source-port
lab_up

TCP_PORTS="$TCP_OPEN,$TCP_CLOSED,$TCP_DROP"
tcp_probes() { cap_count "\$3==\"out\" && \$4==\"tcp\" && \$7==\"$TGT_A\" && \$9==\"S\" $1"; }
udp_probes() { cap_count "\$3==\"out\" && \$4==\"udp\" && \$7==\"$TGT_A\" $1"; }

for opt in -g --source-port; do
    echo "== -sS $opt 53 =="
    fero_captured -Pn -sS "$opt" 53 -p "$TCP_PORTS" "$TGT_A"
    check "exit status" "$RC" 0
    check "open port" "$(state_of tcp "$TCP_OPEN")" open
    check "closed port" "$(state_of tcp "$TCP_CLOSED")" closed
    check "filtered port" "$(state_of tcp "$TCP_DROP")" filtered
    total=$(tcp_probes "")
    check_true "SYN probes were sent ($total)" test "$total" -gt 0
    check "SYN probes from another port than 53" "$(tcp_probes '&& $6!=53')" 0
done

echo "== -sU -g 53 =="
fero_captured -Pn -sU -g 53 -p "$UDP_OPEN,$UDP_DROP" "$TGT_A"
check "exit status" "$RC" 0
check "UDP echo port" "$(state_of udp "$UDP_OPEN")" open
check "dropped UDP port" "$(state_of udp "$UDP_DROP")" "open|filtered"
total=$(udp_probes "&& (\$8==$UDP_OPEN || \$8==$UDP_DROP)")
check_true "UDP probes were sent ($total)" test "$total" -gt 0
check "UDP probes from another port than 53" "$(udp_probes '&& $6!=53')" 0

echo "== -sS without -g (sanity) =="
fero_captured -Pn -sS -p "$TCP_PORTS" "$TGT_A"
check "exit status" "$RC" 0
total=$(tcp_probes "")
check_true "SYN probes were sent ($total)" test "$total" -gt 0
check "SYN probes from port 53" "$(tcp_probes '&& $6==53')" 0

echo "== -sT -g 53 (connect scan) =="
fero_captured -Pn -sT -g 53 -p "$TCP_OPEN,$TCP_CLOSED" "$TGT_A"
check "exit status" "$RC" 0
check_true "warns that -sT cannot use -g" output_has "incompatible with the connect scan"
check "open port" "$(state_of tcp "$TCP_OPEN")" open
check "SYNs from port 53" "$(tcp_probes '&& $6==53')" 0

echo "== -g 0 =="
fero_captured -Pn -sS -g 0 -p "$TCP_OPEN" "$TGT_A"
check_true "warns that port 0 may not work" output_has "source port of zero may not work"
check "open port" "$(state_of tcp "$TCP_OPEN")" open
check "SYN probes from another port than 0" "$(tcp_probes '&& $6!=0')" 0

echo "== -g 70000 =="
fero -Pn -sS -g 70000 -p "$TCP_OPEN" "$TGT_A"
check_true "rejected with a non-zero exit ($RC)" test "$RC" -ne 0

lab_finish
