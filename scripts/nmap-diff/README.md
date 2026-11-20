# nmap-diff: does FeroProbe send what nmap sends?

FeroProbe should behave like nmap unless nmap is clearly wrong. This harness
checks that on the wire. For each case in [`matrix.txt`](matrix.txt) it runs
nmap and FeroProbe with the same options against the same lab target,
captures everything the scanner sends, and reports the differences:

| Severity | Meaning |
| --- | --- |
| out-of-scope | A packet to a port nobody asked for (like nmap `-sV` sending UDP/1434 when only TCP ports were requested). Reported for either tool |
| only-nmap, only-feroprobe | A destination (protocol and port, ICMP type, ARP) only one tool sent to |
| shape | Same destination, different probe contents: TCP flags, window, options, payload, DF bit, fragmentation |
| result | The tools report a different port state or service name, or a script gave output in only one of them (from `-oX`; the script output itself is not compared) |
| count | Same probes, different number of them (retries, retransmissions) |
| side-effect | ICMP errors the scanner host's own kernel sent, usually because a raw-socket scan did not consume a reply |

It only reports. Each difference is for a person to sort into a FeroProbe
fix or a deliberate divergence (the "Deliberate differences from nmap"
section of `DEVELOPMENT.md`). Once a divergence is documented, add it to
[`known-differences.txt`](known-differences.txt): the report keeps showing
it, marked *documented*, so nothing is hidden.

## Running it

On Debian or Ubuntu, as root:

```sh
sudo apt-get install nmap tcpdump iproute2 iptables python3
cargo build --release
sudo python3 scripts/nmap-diff/nmap_diff.py                  # every case
sudo python3 scripts/nmap-diff/nmap_diff.py --cases 'version*,aggressive*'
```

The report lands in `target/nmap-diff/report.md` (and `report.json`). The
raw material for every case is in `target/nmap-diff/raw/`: one pcap per
interface per tool (`<case>.<nmap|fero>.<iface>.pcap`, open them in
Wireshark), each tool's console output (`.out`) and XML (`.xml`).

Options:

| Option | Default | |
| --- | --- | --- |
| `--cases` | `*` | Comma-separated globs of case names |
| `--base-opts` | `-n -T4` | Added in front of every case. `-n` keeps DNS out of the captures; `-T4` keeps the run short. Pass `--base-opts ''` to compare default timing |
| `--feroprobe` | `target/release/feroprobe` | Binary to test |
| `--nmap` | `nmap` on the `PATH` | nmap binary |
| `--timeout` | 300 | Seconds per tool run |
| `--fail-on` | none | Severities that make the exit status 1, e.g. `out-of-scope`. Documented findings never fail |
| `--from-json` | | Rebuild `report.md` from an earlier `report.json` without scanning (no root needed), e.g. after adding a line to `known-differences.txt` |
| `--keep-lab` | off | Leave the namespaces up for poking around (`ip netns exec fpd-scan ...`) |

The unit tests need no root: `python3 -m unittest discover -s scripts/nmap-diff`.

## The lab

Three network namespaces, created at the start and removed at the end. Your
own network is not touched and nothing leaves the machine.

```
  fpd-scan (scanner)                         fpd-tgt (target)
  10.77.0.1 fd77::1 ---------- link A ------ 10.77.0.2 fd77::2     "lan", "lan6"
  10.79.0.1 -- link B -- fpd-rtr -- link C - 10.78.0.2             "routed"
  127.0.0.1 (own listeners)                                         "local"
```

Both tools run inside `fpd-scan`, and tcpdump captures all three of its
interfaces (`lo`, `fpd-a0`, `fpd-b0`), so any packet either tool sends, to
any address, is seen. `fpd-scan` has a default route through the router,
so a stray packet to some other address is captured too.

Lab ports (the same on the target and on 127.0.0.1):

| | open | closed | filtered (dropped) |
| --- | --- | --- | --- |
| TCP | 22 (SSH banner, then a KEXINIT), 80 (HTTP; also a `.git` directory, a favicon, `/private/` (401), `/login` (session cookie), `/cms` (generator tag), WebDAV at `/dav/` and CORS preflights for the HTTP default scripts), 8080 (silent) | 443, 3389 | 8443 |
| UDP | 53 (echo), 137 (NetBIOS NODE STATUS) | 123 | 161 |

In `matrix.txt`, `@TCP` and `@UDP` expand to these lists. TCP 53 also has a
small DNS server for the script cases (CHAOS TXT `id.server`,
`hostname.bind`, `version.bind` and the EDNS NSID option). It is not in
`@TCP`, so a case reaches it only by naming port 53 or through a port list
that holds 53 (`fast`, with `-F`, finds it open). The same goes for the
NTLM responders of the `script-ntlm` case: telnet on 23, SMTP on 25, POP3
on 110, NNTP on 119, IMAP on 143 and MS-SQL (TDS) on 1433 each answer an
NTLM NEGOTIATE with a fixed CHALLENGE, and port 80 does so for a request
with `Authorization: NTLM`. TCP 445 has a small SMB server for the
`script-smb` case: NT LM 0.12 (with and without extended security, a
session setup answered with the NTLM challenge and Windows Server 2003 OS
strings) and SMB 2.0.2 to 3.1.1 NEGOTIATE; cases scanning the default or
`-F` port lists find it open too. ICMP rate limits
are off in every namespace, and the neighbour caches are flushed before each
run, so both tools start from the same state.

How "sent by the scanner" is decided: on the veth links, by the scanner's
MAC address (so decoys and spoofed sources still count). On `lo`, where both
ends are local, the side that opened a flow is the scanner, and ICMP
answers (echo reply, unreachable, ...) are not probes. IPv4 and IPv6
fragments are reassembled, and the fragment sizes are kept as a field.

## Pinned nmap version

nmap changes its probes between releases, so a report only means something
with the nmap version next to it. [`NMAP_VERSION`](NMAP_VERSION) holds the
version the known differences were checked against; the report shows it and
warns when the nmap you run is a different one. CI uses the nmap from the
Ubuntu 24.04 archive, which is 7.94 (Jurgen's Debian box has 7.95).

## Limits

- Linux only, and root only (namespaces, raw sockets, tcpdump).
- Timing is not compared beyond the run time in the summary; differences in
  pacing, retry counts and ordering show up only as `count` findings.
- When there is no explicit `-p` (`-F`, `--top-ports`, the default 1000),
  scope is not checked; the port lists themselves are still diffed.
- TTL is not compared per probe (nmap picks a random TTL for raw probes);
  the TTLs each tool used are listed under every case.
- IPv6 cases are skipped on a host without an IPv6 stack.
- It cannot promise to find every nmap behaviour: only those the matrix
  exercises. Add a line to `matrix.txt` for each new option or combination
  worth watching.
