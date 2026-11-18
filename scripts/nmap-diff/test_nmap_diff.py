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
import listeners  # noqa: E402
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

    def test_sctp_init_random_fields_ignored(self):
        def init(tag, tsn, streams):
            chunk = struct.pack("!BBHIIHHI", 1, 0, 20, tag, 106496, streams, streams, tsn)
            l4 = struct.pack("!HHII", 4000, 80, 0, 0) + chunk
            return nd.decode_frame(1, eth(SCAN_MAC, ip4("10.77.0.1", "10.77.0.2", 132, l4)))
        self.assertEqual(init(1, 2, 10).fields, init(3, 4, 10).fields)
        self.assertNotEqual(init(1, 2, 10).fields, init(1, 2, 11).fields)

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

    def test_new_ping_types_and_list_scan_scope(self):
        self.assertEqual(nd.scope_of(["-sn", "-PY80,2905"], "routed", True), {"sctp": {80, 2905}})
        scope = nd.scope_of(["-sn", "-PO6,17"], "routed", True)
        self.assertTrue(nd.in_scope("tcp/80", scope))
        self.assertTrue(nd.in_scope("udp/40125", scope))
        self.assertFalse(nd.in_scope("sctp/80", scope))
        # Open-ended -PO ranges stay within the protocol numbers 0-255.
        self.assertEqual(nd.scope_of(["-sn", "-PO-"], "routed", True)["ip"], set(range(256)))
        self.assertTrue(nd.in_scope("ip proto 0", nd.scope_of(["-sn", "-PO-"], "routed", True)))
        self.assertEqual(nd.scope_of(["-sn", "-PO250-"], "routed", True)["ip"], set(range(250, 256)))
        # -sL may send nothing at all, whatever else is given.
        self.assertEqual(nd.scope_of(["-sL"], "lan", True), {})
        self.assertEqual(nd.scope_of(["-sL", "-PE"], "routed", True), {})

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
        self.assertTrue(nd.in_scope(dest, nd.scope_of(["-sO", "-p", "6"], "routed", True)))
        # ... but not when only TCP discovery was asked for
        self.assertFalse(nd.in_scope(dest, nd.scope_of(["-sO", "-p", "6", "-PS22"], "routed", True)))

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

    def test_echo_marker_documented_alone(self):
        known = nd.load_known(os.path.join(os.path.dirname(os.path.abspath(__file__)), "known-differences.txt"))
        mark = nd.payload_label(b"feroprobe")
        alone = [{"case": "c", "text": f"icmp echo-request payload: nmap [-] vs FeroProbe [{mark}]"}]
        extra = [{"case": "c", "text": f"icmp echo-request payload: nmap [-] vs FeroProbe [{mark}, 3B 'abc' #a9993e]"}]
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


class Xml(unittest.TestCase):
    def test_scripts_with_output_are_listed(self):
        xml = ('<nmaprun><host><status state="up"/><ports>'
               '<port protocol="udp" portid="53"><state state="open"/><service name="domain"/>'
               '<script id="dns-nsid" output="x"/></port></ports>'
               '<hostscript><script id="nbstat" output="y"/></hostscript></host></nmaprun>')
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "a.xml")
            with open(path, "w") as f:
                f.write(xml)
            ports, state = nd.parse_xml_ports(path)
        self.assertEqual(state, "up")
        self.assertEqual(ports, {"udp/53": "open domain", "udp/53 script dns-nsid": "output",
                                 "host script nbstat": "output"})

    def test_empty_script_record_is_no_output(self):
        xml = ('<nmaprun><host><status state="up"/><ports>'
               '<port protocol="tcp" portid="80"><state state="open"/>'
               '<script id="empty" output=""/>'
               '<script id="table" output=""><elem key="k"></elem></script></port></ports></host></nmaprun>')
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "a.xml")
            with open(path, "w") as f:
                f.write(xml)
            ports, _ = nd.parse_xml_ports(path)
        self.assertNotIn("tcp/80 script empty", ports)
        self.assertEqual(ports["tcp/80 script table"], "output")


def dns_query(name, opt=b"", qclass=3, flags=0):
    q = struct.pack(">HHHHHH", 0x4650, flags, 1, 0, 0, 1 if opt else 0)
    q += b"".join(bytes([len(x)]) + x for x in name.encode().split(b".")) + b"\0"
    return q + struct.pack(">HH", 16, qclass) + opt


class Listeners(unittest.TestCase):
    NSID_OPT = b"\0" + struct.pack(">HHIHHH", 41, 1232, 0, 4, 3, 0)

    def test_dns_chaos_txt_and_nsid(self):
        r = listeners.dns_reply(dns_query("id.server", self.NSID_OPT))
        qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", r[:12])
        self.assertEqual((qid, flags & 0x800F, qd, an, ns, ar), (0x4650, 0x8000, 1, 1, 0, 1))
        self.assertIn(b"\x09lab-dns-1", r)
        self.assertTrue(r.endswith(struct.pack(">HH", 3, 9) + b"lab-dns-1"))
        plain = listeners.dns_reply(dns_query("version.bind"))
        self.assertTrue(plain.endswith(b"\x0b9.18.24-lab"))
        self.assertEqual(struct.unpack(">H", plain[10:12])[0], 0)

    def test_dns_label_boundaries_and_opt_position(self):
        # one label "id.server" is not the name id.server
        q = struct.pack(">HHHHHH", 1, 0, 1, 0, 0, 0) + b"\x09id.server\0" + struct.pack(">HH", 16, 3)
        self.assertEqual(listeners.dns_reply(q)[3] & 0xF, 5)
        # an A record before the OPT record: the NSID is still found
        a_rec = b"\x01x\0" + struct.pack(">HHIH", 1, 1, 0, 4) + bytes(4)
        q = dns_query("ID.Server") + a_rec + self.NSID_OPT
        q = q[:10] + struct.pack(">H", 2) + q[12:]
        r = listeners.dns_reply(q)
        self.assertEqual(r[3] & 0xF, 0)
        self.assertTrue(r.endswith(b"lab-dns-1") and struct.unpack(">H", r[10:12])[0] == 1)

    def test_dns_compressed_owner_before_opt(self):
        a_rec = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 0, 4) + bytes(4)
        q = dns_query("id.server") + a_rec + self.NSID_OPT
        q = q[:10] + struct.pack(">H", 2) + q[12:]
        r = listeners.dns_reply(q)
        self.assertEqual(r[3] & 0xF, 0)
        self.assertTrue(r.endswith(b"lab-dns-1"))

    def test_dns_malformed_opt_is_formerr(self):
        # an NSID option claiming 8 bytes with none left
        bad = b"\0" + struct.pack(">HHIHHH", 41, 1232, 0, 4, 3, 8)
        r = listeners.dns_reply(dns_query("id.server", bad))
        self.assertEqual((r[3] & 0xF, struct.unpack(">H", r[6:8])[0], struct.unpack(">H", r[10:12])[0]), (1, 0, 0))

    def test_dns_other_queries(self):
        # IN class: REFUSED; status request (opcode 2): NOTIMP; a reply: ignored
        self.assertEqual(listeners.dns_reply(dns_query("id.server", qclass=1))[3] & 0xF, 5)
        self.assertEqual(listeners.dns_reply(dns_query("id.server", flags=0x1000))[3] & 0xF, 4)
        self.assertIsNone(listeners.dns_reply(dns_query("id.server", flags=0x8000)))
        self.assertIsNone(listeners.dns_reply(b"hello"))

    def test_nbstat(self):
        name = b"\x20" + b"CK" + b"A" * 30 + b"\0"
        q = struct.pack(">HHHHHH", 0x4650, 0, 1, 0, 0, 0) + name + struct.pack(">HH", 0x21, 1)
        r = listeners.nbstat_reply(q)
        self.assertEqual(struct.unpack(">HHHH", r[:8]), (0x4650, 0x8400, 0, 1))
        self.assertEqual(r[12:46], name)
        rdlen = struct.unpack(">H", r[54:56])[0]
        self.assertEqual(len(r), 56 + rdlen)
        self.assertEqual(r[56], 3)
        self.assertEqual(r[57:72], b"FPDLAB         ")
        self.assertEqual(r[56 + 1 + 3 * 18:56 + 1 + 3 * 18 + 6], listeners.NB_MAC)
        # a name outside the first-level alphabet A to P, a name query (type
        # NB) and garbage get no answer
        self.assertIsNone(listeners.nbstat_reply(q[:13] + b"Z" + q[14:]))
        self.assertIsNone(listeners.nbstat_reply(q[:-4] + struct.pack(">HH", 0x20, 1)))
        self.assertIsNone(listeners.nbstat_reply(b"hello" * 20))


if __name__ == "__main__":
    unittest.main()
