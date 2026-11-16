#!/usr/bin/env bash
#
# test-ping-types.sh: end-to-end check of the list scan and the ping types
# added for v0.5.0.
#
# Builds a private two-namespace lab (see scripts/lib/lab.sh). Both target
# addresses are on a directly connected link, so the ping tests use
# --disable-arp-ping to make the probes go out at all:
#
#   -sn -PY               an SCTP INIT to port 80 proves the host up (an
#                         ABORT from a kernel with SCTP, else the kernel's
#                         ICMP protocol unreachable)
#   -sn -PY2905,3868      one INIT per port, nothing else on the wire
#   -sn -PY, SCTP dropped the host is down
#   -sn -PO               ICMP, IGMP and IP-in-IP probes; the echo reply
#                         proves the host (proto-response)
#   -sn -PO253            protocol 253: the protocol unreachable proves it
#   -sn -PO253, dropped   the host is down
#   -sn -PR               a warning that -PR changes nothing; ARP decides
#   -sL                   lists the targets, sends nothing (not even ARP)
#   --dry-run -PY -PO     lists the INIT and the protocol probes
#
# Needs root and Linux. Prints PASS/FAIL per check, exits non-zero on failure.
#
# Usage:   sudo ./scripts/test-ping-types.sh [--bin PATH] [-v]
#
. "$(dirname "$0")/lib/lab.sh"
lab_usage_args "$@"
lab_require
lab_find_bin -PY
lab_up

host_field() {   # args: field -> the first host's field in the last run's JSON
    [ -s "$JSON" ] || { echo "no-json"; return; }
    python3 - "$JSON" "$1" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
hosts = data.get("hosts", [])
if not hosts:
    print("no-host"); sys.exit(0)
h = hosts[0]
v = h.get(sys.argv[2])
print(str(v).lower() if v is not None else "none")
PY
}
to_target() { cap_count "\$3==\"out\" && \$7==\"$TGT_A\" $1"; }
not_from() { cap_count "\$3==\"out\" && \$7==\"$TGT_A\" && !($1)"; }

echo "== -sn -PY =="
fero_captured -sn -PY --disable-arp-ping "$TGT_A"
check "exit status" "$RC" 0
check "host up" "$(host_field up)" true
why=$(host_field up_reason)
check_true "reason is abort or proto-unreach ($why)" \
    test "$why" = abort -o "$why" = proto-unreach
check_true "an SCTP INIT went to port 80" \
    test "$(to_target '&& $4=="ip132"')" -gt 0
check "probes other than SCTP" "$(not_from '$4=="ip132" || $4=="arp"')" 0

echo "== -sn -PY2905,3868 =="
fero_captured -sn -PY2905,3868 --disable-arp-ping "$TGT_A"
check "exit status" "$RC" 0
check "host up" "$(host_field up)" true
check "probes other than SCTP" "$(not_from '$4=="ip132" || $4=="arp"')" 0

echo "== -sn -PY, SCTP dropped on the target =="
nsx "$NS_TGT" iptables -A INPUT -p sctp -j DROP
fero_captured -sn -PY --max-retries 1 --disable-arp-ping "$TGT_A"
nsx "$NS_TGT" iptables -D INPUT -p sctp -j DROP
check "exit status" "$RC" 0
check "host up" "$(host_field up)" false

echo "== -sn -PO =="
fero_captured -sn -PO --disable-arp-ping "$TGT_A"
check "exit status" "$RC" 0
check "host up" "$(host_field up)" true
check "reason" "$(host_field up_reason)" proto-response
check_true "an ICMP echo request went out" test "$(to_target '&& $4=="icmp" && $9=="8"')" -gt 0
check "probes outside ICMP, IGMP, IP-in-IP" \
    "$(not_from '$4=="icmp" || $4=="ip2" || $4=="ip4" || $4=="arp"')" 0

echo "== -sn -PO253 =="
fero_captured -sn -PO253 --disable-arp-ping "$TGT_A"
check "exit status" "$RC" 0
check "host up" "$(host_field up)" true
check "reason" "$(host_field up_reason)" proto-unreach
check "probes other than protocol 253" "$(not_from '$4=="ip253" || $4=="arp"')" 0

echo "== -sn -PO253, dropped on the target =="
nsx "$NS_TGT" iptables -A INPUT -p 253 -j DROP
fero_captured -sn -PO253 --max-retries 1 --disable-arp-ping "$TGT_A"
nsx "$NS_TGT" iptables -D INPUT -p 253 -j DROP
check "exit status" "$RC" 0
check "host up" "$(host_field up)" false

echo "== -sn -PR =="
fero_captured -sn -PR "$TGT_A"
check "exit status" "$RC" 0
check_true "warns that -PR changes nothing" output_has "-PR changes nothing"
check "host up" "$(host_field up)" true
check "reason" "$(host_field up_reason)" arp-response
check "probes other than ARP" "$(not_from '$4=="arp"')" 0

echo "== -sL =="
fero_captured -sL "$TGT_A" "$TGT_B"
check "exit status" "$RC" 0
check_true "lists the first target" output_has "Scan report for $TGT_A"
check_true "lists the second target" output_has "Scan report for $TGT_B"
check "hosts reported up" "$(host_field up)" false
check "packets to the targets (ARP included)" \
    "$(cap_count "\$3==\"out\" && (\$7==\"$TGT_A\" || \$7==\"$TGT_B\")")" 0

echo "== -sL -PE (ignored, with a warning) =="
fero_captured -sL -PE "$TGT_A"
check "exit status" "$RC" 0
check_true "warns that -PE is ignored" output_has "-PE is ignored"
check "packets to the target" "$(to_target "")" 0

echo "== -sL -Pn -PE (the -P options are not checked against each other) =="
fero_captured -sL -Pn -PE "$TGT_A"
check "exit status" "$RC" 0
check_true "lists the target" output_has "Scan report for $TGT_A"

echo "== -sL -p 80 (refused, as in nmap) =="
fero -sL -p 80 "$TGT_A"
check_true "rejected with a non-zero exit ($RC)" test "$RC" -ne 0

echo "== --dry-run -sn -PY -PO =="
fero_captured --dry-run -sn -PY -PO --disable-arp-ping "$TGT_A"
check "exit status" "$RC" 0
check_true "lists the SCTP INIT" output_has "SCTP $SCAN_A"
check_true "lists the IGMP probe" output_has "IGMP"
check "packets to the target" "$(to_target "")" 0

lab_finish
