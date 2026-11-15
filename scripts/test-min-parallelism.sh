#!/usr/bin/env bash
#
# test-min-parallelism.sh: end-to-end check of --min-parallelism.
#
# Builds a private two-namespace lab (see scripts/lib/lab.sh) whose target
# silently drops probes to 30 ports, so each connect probe stays in flight
# for the full --timeout and the first probes go out in a burst as large as
# the congestion window, which starts at 10, or at --min-parallelism when
# that is higher (nmap's low_cwnd), and never above the parallelism. The
# script measures the largest burst on the wire (first probes within half a
# timeout). -T2 has a parallelism of 10; --scan-delay 0 removes its delay
# between probes so the bursts show:
#
#   -T2                              10 (sanity: the template's value)
#   -T2 --min-parallelism 20         20: the window starts at the minimum
#   --min-parallelism 5              10: a minimum below 10 changes nothing
#   -M 4 --min-parallelism 2         4: nor does it raise an explicit maximum
#   -M 2 --min-parallelism 5         an error, with nmap's message
#   --min-parallelism 0              rejected (must be at least 1)
#   --min-parallelism 200            warns that it is pretty high (above 100)
#
# Needs root and Linux. Prints PASS/FAIL per check, exits non-zero on failure.
#
# Usage:   sudo ./scripts/test-min-parallelism.sh [--bin PATH] [-v]
#
. "$(dirname "$0")/lib/lab.sh"
lab_usage_args "$@"
lab_require
lab_find_bin --min-parallelism
lab_up

PORTS=18100-18129   # 30 ports inside the lab's DROP_RANGE
T=(--timeout 800 --max-retries 0 --scan-delay 0)
burst() { cap_burst "\$3==\"out\" && \$4==\"tcp\" && \$7==\"$TGT_A\" && \$9==\"S\"" 0.4; }

run() {   # args: label expected-burst feroprobe-options...
    local label="$1" want="$2"; shift 2
    echo "== -sT $label =="
    fero_captured -Pn -sT "${T[@]}" "$@" -p "$PORTS" "$TGT_A"
    check "exit status" "$RC" 0
    check "largest burst of probes" "$(burst)" "$want"
    check "a filtered port" "$(state_of tcp 18100)" filtered
}

run "-T2" 10 -T2
run "-T2 --min-parallelism 20" 20 -T2 --min-parallelism 20
run "--min-parallelism 5" 10 --min-parallelism 5
run "-M 4 --min-parallelism 2" 4 -M 4 --min-parallelism 2

echo "== -M 2 --min-parallelism 5 =="
fero -Pn -sT -M 2 --min-parallelism 5 -p "$TCP_OPEN" "$TGT_A"
check_true "rejected with a non-zero exit ($RC)" test "$RC" -ne 0
check_true "gives nmap's message" \
    output_has "--min-parallelism=5 must be less than or equal to --max-parallelism=2"

echo "== --min-parallelism 0 =="
fero -Pn -sT --min-parallelism 0 -p "$TCP_OPEN" "$TGT_A"
check_true "rejected with a non-zero exit ($RC)" test "$RC" -ne 0

echo "== --min-parallelism 200 =="
fero -Pn -sT --min-parallelism 200 -p "$TCP_OPEN" "$TGT_A"
check "exit status" "$RC" 0
check_true "warns that it is pretty high" output_has "--min-parallelism of 200 is pretty high"

lab_finish
