#!/usr/bin/env bash
#
# test-max-retries.sh: end-to-end check of --max-retries (and --retries).
#
# Builds a private two-namespace lab (see scripts/lib/lab.sh) whose target
# silently drops probes to some ports, then counts on the wire how often
# FeroProbe probes such a port. As in nmap, --max-retries is a cap: a host
# that loses nothing (the lab target answers every probe it does not drop)
# gets one resend per silent port, and more only once it answers a resent
# probe. A port that answers gets one probe:
#
#   -sS --max-retries 0      1 SYN to the filtered port
#   -sS --max-retries 3      2 SYNs to the filtered port (one resend: no
#                            losses seen), 1 to the open port
#   -sS --retries 3          the same (FeroProbe's own name)
#   -sT --max-retries 2      2 connection attempts to the filtered port
#   -sU --max-retries 2      2 probes to the dropped UDP port, 1 to the
#                            answering one
#   -T5 --max-retries 1      2 SYNs
#   --max-retries -1         rejected
#
# A short --timeout keeps it quick and below the kernel's own SYN
# retransmission time, so every SYN seen is one of FeroProbe's attempts.
#
# Needs root and Linux. Prints PASS/FAIL per check, exits non-zero on failure.
#
# Usage:   sudo ./scripts/test-max-retries.sh [--bin PATH] [-v]
#
. "$(dirname "$0")/lib/lab.sh"
lab_usage_args "$@"
lab_require
lab_find_bin --max-retries
lab_up

T=(--timeout 300)
syns_to() { cap_count "\$3==\"out\" && \$4==\"tcp\" && \$7==\"$TGT_A\" && \$8==$1 && \$9==\"S\""; }
udp_to() { cap_count "\$3==\"out\" && \$4==\"udp\" && \$7==\"$TGT_A\" && \$8==$1"; }

echo "== -sS --max-retries 0 =="
fero_captured -Pn -sS "${T[@]}" --max-retries 0 -p "$TCP_DROP" "$TGT_A"
check "exit status" "$RC" 0
check "filtered port" "$(state_of tcp "$TCP_DROP")" filtered
check "SYNs to the filtered port" "$(syns_to "$TCP_DROP")" 1

for opt in --max-retries --retries; do
    echo "== -sS $opt 3 =="
    fero_captured -Pn -sS "${T[@]}" "$opt" 3 -p "$TCP_OPEN,$TCP_DROP" "$TGT_A"
    check "exit status" "$RC" 0
    check "open port" "$(state_of tcp "$TCP_OPEN")" open
    check "filtered port" "$(state_of tcp "$TCP_DROP")" filtered
    check "SYNs to the filtered port" "$(syns_to "$TCP_DROP")" 2
    check "SYNs to the open port" "$(syns_to "$TCP_OPEN")" 1
done

echo "== -sT --max-retries 2 =="
fero_captured -Pn -sT "${T[@]}" --max-retries 2 -p "$TCP_DROP" "$TGT_A"
check "exit status" "$RC" 0
check "filtered port" "$(state_of tcp "$TCP_DROP")" filtered
check "connection attempts to the filtered port" "$(syns_to "$TCP_DROP")" 2

echo "== -sU --max-retries 2 =="
fero_captured -Pn -sU "${T[@]}" --max-retries 2 -p "$UDP_OPEN,$UDP_DROP" "$TGT_A"
check "exit status" "$RC" 0
check "UDP echo port" "$(state_of udp "$UDP_OPEN")" open
check "dropped UDP port" "$(state_of udp "$UDP_DROP")" "open|filtered"
check "probes to the dropped port" "$(udp_to "$UDP_DROP")" 2
check "probes to the echo port" "$(udp_to "$UDP_OPEN")" 1

echo "== -T5 --max-retries 1 =="
fero_captured -Pn -sS -T5 --max-retries 1 -p "$TCP_DROP" "$TGT_A"
check "exit status" "$RC" 0
check "SYNs to the filtered port" "$(syns_to "$TCP_DROP")" 2

echo "== --max-retries -1 =="
fero -Pn -sS --max-retries -1 -p "$TCP_DROP" "$TGT_A"
check_true "rejected with a non-zero exit ($RC)" test "$RC" -ne 0

lab_finish
