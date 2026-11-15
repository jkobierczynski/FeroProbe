#!/usr/bin/env python3
"""Unit tests for nmap_diff.py's parsing, scope and comparison (no root needed).

    python3 -m unittest discover -s scripts/nmap-diff
"""

import os
import socket
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nmap_diff as nd  # noqa: E402

SCAN_MAC = bytes.fromhex("020000000001")
TGT_MAC = bytes.fromhex("020000000002")


def ip4(src, dst, proto, l4, ttl=64, df=False, ipid=1, frag_off=0, mf=False):
    fl = (0x4000 if df else 0) | (0x2000 if mf else 0) | (frag_off // 8)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), ipid, fl, ttl, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    return hdr + l4


def tcp(sport, dport, flags, win=1024, opts=b"", payload=b""):
    off = (20 + len(opts)) // 4
    return struct.pack("!HHIIBBHHH", sport, dport, 1, 0, off << 4, flags, win, 0, 0) + opts + payload


def udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def eth(src_mac, l3, etype=0x0800):
    return TGT_MAC + src_mac + struct.pack("!H", etype) + l3


def write_pcap(path, frames, linktype=1):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack("<IIII", 1000 + i, 0, len(fr), len(fr)))
            f.write(fr)


class Parsing(unittest.TestCase):
    def test_tcp_syn_fields(self):
        opts = bytes([2, 4, 0x05, 0xB4, 1, 3, 3, 7])
        p = nd.decode_frame(1, eth(SCAN_MAC, ip4("10.77.0.1", "10.77.0.2", 6, tcp(40000, 22, 0x02, 1024, opts)), ))
        self.assertEqual(p.kind, "tcp")
        self.assertEqual(p.dport, 22)
        self.assertEqual(p.fields["flags"], "S")
        self.assertEqual(p.fields["win"], "1024")
        self.assertEqual(p.fields["opts"], "M1460,N,W7")
        self.assertEqual(p.fields["payload"], "-")

    def test_payload_labels(self):
        self.assertEqual(nd.payload_label(b""), "-")
        self.assertIn("'FeroProbeScan/1\\\\n'", nd.payload_label(b"FeroProbeScan/1\n"))
        self.assertTrue(nd.payload_label(b"C" * 300).startswith("300B '"))
        self.assertTrue(nd.payload_label(b"\x00" * 20).startswith("20B x00"))
        self.assertTrue(nd.payload_label(bytes(range(40))).startswith("40B hex:00010203"))

    def test_fragments_reassemble(self):
        seg = tcp(40000, 80, 0x02)  # 20 bytes -> 8 + 8 + 4
        frames = []
        for off in (0, 8, 16):
            chunk = seg[off:off + 8]
            frames.append(eth(SCAN_MAC, ip4("10.77.0.1", "10.77.0.2", 6, chunk, ipid=7, frag_off=off,
                                             mf=off + 8 < len(seg))))
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "f.pcap")
            write_pcap(path, frames)
            sent = nd.load_sent({"fpd-a0": path}, {":".join(f"{b:02x}" for b in SCAN_MAC)})
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0].kind, "tcp")
        self.assertEqual(sent[0].dport, 80)
        self.assertEqual(sent[0].frag, "frags 8+8+4")

    def test_direction_by_mac_and_on_loopback(self):
        probe = eth(SCAN_MAC, ip4("10.77.0.1", "10.77.0.2", 6, tcp(40000, 443, 0x02)))
        reply = eth(TGT_MAC, ip4("10.77.0.2", "10.77.0.1", 6, tcp(443, 40000, 0x14)))
        lo_probe = eth(b"\0" * 6, ip4("127.0.0.1", "127.0.0.1", 6, tcp(40001, 1434, 0x02)))
        lo_reply = eth(b"\0" * 6, ip4("127.0.0.1", "127.0.0.1", 6, tcp(1434, 40001, 0x14)))
        lo_unreach = eth(b"\0" * 6, ip4("127.0.0.1", "127.0.0.1", 1, bytes([3, 3, 0, 0, 0, 0, 0, 0])))
        with tempfile.TemporaryDirectory() as d:
            a, lo = os.path.join(d, "a.pcap"), os.path.join(d, "lo.pcap")
            write_pcap(a, [probe, reply])
            write_pcap(lo, [lo_probe, lo_reply, lo_unreach])
            sent = nd.load_sent({"fpd-a0": a, "lo": lo}, {":".join(f"{b:02x}" for b in SCAN_MAC)})
        keys = sorted(nd.dest_key(p, "10.77.0.2") for p in sent)
        self.assertEqual(keys, ["tcp/1434 to 127.0.0.1", "tcp/443"])


class Scope(unittest.TestCase):
    def test_port_spec(self):
        self.assertEqual(dict(nd.parse_port_spec("22,80-82,U:53", ["tcp"])), {"tcp": {22, 80, 81, 82}, "udp": {53}})

    def test_tcp_scan_scope(self):
        argv = ["-sV", "-p", "102,502"]
        self.assertEqual(nd.scope_of(argv, "lan", True), {"tcp": {102, 502}})
        # off-link or unprivileged: nmap's default discovery touches 80 and 443
        self.assertEqual(nd.scope_of(argv, "routed", True), {"tcp": {80, 102, 443, 502}})
        self.assertEqual(nd.scope_of(["-Pn"] + argv, "routed", True), {"tcp": {102, 502}})

    def test_udp_1434_is_out_of_scope(self):
        scope = nd.scope_of(["-A", "-p", "102,502"], "lan", True)
        self.assertFalse(nd.in_scope("udp/1434", scope))
        self.assertTrue(nd.in_scope("tcp/502", scope))

    def test_ping_scope_and_unknown(self):
        self.assertEqual(nd.scope_of(["-sn", "-PS22,80", "-PU"], "routed", True), {"tcp": {22, 80}, "udp": {40125}})
        self.assertIsNone(nd.scope_of(["-F"], "lan", True))
        self.assertIsNone(nd.scope_of(["-sS"], "lan", True))

    def test_ip_protocol_scan_scope(self):
        scope = nd.scope_of(["-sO", "-p", "1,6"], "lan", True)
        self.assertTrue(nd.in_scope("tcp/80", scope))
        self.assertTrue(nd.in_scope("ip proto 1", scope))
        self.assertFalse(nd.in_scope("udp/40125", scope))

    def test_icmp_outside_an_ip_protocol_scan(self):
        echo = nd.decode_frame(1, eth(SCAN_MAC, ip4("10.77.0.1", "10.77.0.2", 1, bytes([8, 0, 0, 0, 0, 1, 0, 1]))))
        dest = nd.dest_key(echo, "10.77.0.2")
        self.assertEqual(dest, "icmp echo-request")
        self.assertFalse(nd.in_scope(dest, nd.scope_of(["-sO", "-p", "6"], "lan", True)))
        self.assertTrue(nd.in_scope(dest, nd.scope_of(["-sO", "-p", "1,6"], "lan", True)))
        # routed: host discovery sends ICMP echo itself
        self.assertIsNone(nd.in_scope(dest, nd.scope_of(["-sO", "-p", "6"], "routed", True)))

    def test_macros(self):
        self.assertEqual(nd.expand_macros("-p @TCP"), "-p " + ",".join(map(str, nd.TCP_PORTS)))


class Compare(unittest.TestCase):
    def summary(self, recs):
        sent = []
        for dport, flags, win in recs:
            p = nd.decode_frame(1, eth(SCAN_MAC, ip4("10.77.0.1", "10.77.0.2", 6, tcp(40000, dport, flags, win))))
            sent.append(p)
        return nd.summarise(sent, "10.77.0.2")[0]

    def test_same_probes_in_different_numbers(self):
        n = self.summary([(22, 0x02, 1024)] * 3 + [(22, 0x04, 1024)])
        f = self.summary([(22, 0x02, 1024)] + [(22, 0x04, 1024)] * 3)
        found = nd.compare("c", n, f, {"tcp": {22}}, {}, {})
        self.assertEqual([x["severity"] for x in found], ["count"])

    def test_signature_note_needs_the_marker_alone(self):
        known = nd.load_known(os.path.join(os.path.dirname(os.path.abspath(__file__)), "known-differences.txt"))
        mark = nd.payload_label(b"FeroProbeScan/1\n")
        alone = [{"case": "c", "text": f"udp/9 payload: nmap [-] vs FeroProbe [{mark}]"}]
        extra = [{"case": "c", "text": f"udp/9 payload: nmap [-] vs FeroProbe [{mark}, 3B 'abc' #a9993e]"}]
        nd.annotate(alone, known)
        nd.annotate(extra, known)
        self.assertIn("known", alone[0])
        self.assertNotIn("known", extra[0])

    def test_findings(self):
        n = self.summary([(22, 0x02, 1024), (443, 0x02, 1024), (443, 0x02, 1024)])
        f = self.summary([(22, 0x02, 65109), (443, 0x02, 1024), (8080, 0x02, 1024)])
        scope = {"tcp": {22, 443}}
        found = nd.compare("c", n, f, scope, {}, {})
        sev = sorted((x["severity"], x["dest"]) for x in found)
        self.assertEqual(sev, [("count", "tcp/443"), ("only-feroprobe", "tcp/8080"),
                               ("out-of-scope", "tcp/8080"), ("shape", "tcp/22")])
        known = [("*", __import__("re").compile(r"^tcp/\d+ \[[A-Z]+\] win: .* vs FeroProbe \[65109"), "sig")]
        nd.annotate(found, known)
        self.assertEqual([x["severity"] for x in found if x.get("known")], ["shape"])


if __name__ == "__main__":
    unittest.main()
