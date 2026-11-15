#!/usr/bin/env bash
#
# test-max-parallelism.sh: end-to-end check of -M / --max-parallelism
# (and FeroProbe's own -c / --concurrency).
#
# Builds a private two-namespace lab (see scripts/lib/lab.sh) whose target
# silently drops probes to 12 ports, so each connect or UDP probe stays in
# flight for the full --timeout. With at most N in flight, the first probes
# then go out in bursts of N, one burst per timeout. The script measures the
# largest burst on the wire (first probes within half a timeout):
#
#   -sT (default)               12: all ports at once (the default is 500)
#   -sT -M 3                    3
#   -sT --max-parallelism 3     3
#   -sT -c 3, --concurrency 3   3 (FeroProbe's names)
#   -sT -M 1                    1, and the probes are a timeout apart
#   -sU -M 2                    2
#   -M 0                        rejected (must be at least 1)
#   -M 1000                     warns that it is above 900
#
# Raw-socket scans (-sS and friends) are paced by --max-rate instead, so
# they are not covered here.
#
# Needs root and Linux. Prints PASS/FAIL per check, exits non-zero on failure.
#
# Usage:   sudo ./scripts/test-max-parallelism.sh [--bin PATH] [-v]
#
. "$(dirname "$0")/lib/lab.sh"
lab_usage_args "$@"
lab_require
lab_find_bin --max-parallelism
lab_up

PORTS=18100-18111   # 12 ports inside the lab's DROP_RANGE
NPORTS=12
TIMEOUT_MS=800
T=(--timeout "$TIMEOUT_MS" --max-retries 0)
WINDOW=0.4          # half the timeout
tcp_burst() { cap_burst "\$3==\"out\" && \$4==\"tcp\" && \$7==\"$TGT_A\" && \$9==\"S\"" "$WINDOW"; }
udp_burst() { cap_burst "\$3==\"out\" && \$4==\"udp\" && \$7==\"$TGT_A\"" "$WINDOW"; }

echo "== -sT without -M (default parallelism) =="
fero_captured -Pn -sT "${T[@]}" -p "$PORTS" "$TGT_A"
check "exit status" "$RC" 0
check "largest burst of probes" "$(tcp_burst)" "$NPORTS"

for opt in -M --max-parallelism -c --concurrency; do
    echo "== -sT $opt 3 =="
    fero_captured -Pn -sT "${T[@]}" "$opt" 3 -p "$PORTS" "$TGT_A"
    check "exit status" "$RC" 0
    check "largest burst of probes" "$(tcp_burst)" 3
    check "a filtered port" "$(state_of tcp 18100)" filtered
done

echo "== -sT -M 1 =="
fero_captured -Pn -sT "${T[@]}" -M 1 -p "$PORTS" "$TGT_A"
check "exit status" "$RC" 0
check "largest burst of probes" "$(tcp_burst)" 1
# 12 probes one at a time take at least 11 timeouts from first to last.
spread=$(cap "\$3==\"out\" && \$4==\"tcp\" && \$7==\"$TGT_A\" && \$9==\"S\"" \
    | awk 'NR==1{a=$1} {b=$1} END{printf "%d", (b-a)*1000}')
min_spread=$(( (NPORTS - 1) * TIMEOUT_MS * 9 / 10 ))
check_true "first to last probe ${spread} ms (at least ${min_spread} ms)" test "$spread" -ge "$min_spread"

echo "== -sU -M 2 =="
fero_captured -Pn -sU "${T[@]}" -M 2 -p "$PORTS" "$TGT_A"
check "exit status" "$RC" 0
check "largest burst of probes" "$(udp_burst)" 2
check "a dropped port" "$(state_of udp 18100)" "open|filtered"

echo "== -M 0 =="
fero -Pn -sT -M 0 -p "$TCP_OPEN" "$TGT_A"
check_true "rejected with a non-zero exit ($RC)" test "$RC" -ne 0

echo "== -M 1000 =="
fero -Pn -sT -M 1000 -p "$TCP_OPEN" "$TGT_A"
check "exit status" "$RC" 0
check_true "warns that it is extraordinarily high" output_has "extraordinarily high"

lab_finish
