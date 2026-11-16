# OS fingerprints

FeroProbe's OS detection (`-O`) matches what a host's TCP/IP stack sends
back against its own signature database,
[`crates/feroprobe-core/data/os-fingerprints.txt`](../crates/feroprobe-core/data/os-fingerprints.txt),
which is compiled into the binary. This page describes the probes, the
fingerprint, the database format, and how to add a signature.

nmap's database (`nmap-os-db`) is not used, read or copied: its license
does not allow redistribution. Every signature here is written from how a
stack is documented to behave (kernel sources, vendor documentation, RFCs)
or from a capture of a machine we run ourselves. Signatures marked
`# unverified` in the file have not yet been checked against a capture.

## The probes

One try sends a host at most 9 probes, only to ports and protocols the
command already probes (see the manual's `-O` section for when):

| Probe | Sent to | Packet |
| --- | --- | --- |
| `s1` | open TCP port | SYN, options MSS 1460, SACK permitted, timestamps, NOP, window scale 7 |
| `s2` | open TCP port | SYN without options |
| `s3` | open TCP port | SYN, options MSS 1460, NOP, NOP, SACK permitted |
| `s4` | open TCP port | SYN, options MSS 1460, NOP, window scale 7, NOP, NOP, timestamps |
| `e` | open TCP port | SYN with ECE and CWR, options MSS 1460, NOP, NOP, SACK permitted, NOP, window scale 7 |
| `a` | open TCP port | ACK |
| `c1` | closed TCP port | SYN, the options of `s1` |
| `c2` | closed TCP port | ACK |
| `ie` | the host | ICMP or ICMPv6 echo request, payload `feroprobe` |

`s1` to `s4` go 100 ms apart, so the IP IDs and TCP timestamps of their
answers form a sequence. Every TCP probe uses window 64240; the TCP
probes carry no FeroProbe marker, since they must look like a client's.

## The fingerprint

`feroprobe -O -v` (or `-vv` for a host that matched) prints the
fingerprint as `test=value` pairs on lines starting with `OS:`; the XML
report has it in `<osfingerprint>`, the JSON report under
`os.fingerprint`.

| Test | Value |
| --- | --- |
| `ttl` | The initial TTL (IPv6: hop limit) the answers suggest: 32, 64, 128 or 255 |
| `<p>` | `Y` if probe `<p>` was answered, `N` if not. Only for probes sent |
| `<p>.f` | The answer's TCP flags, in the order `S A F R P U E C` (`SA`, `SAE`, `AR`, `R`) |
| `<p>.w` | Its TCP window (`s1`, `s2`, `s3`, `e`, `a`, `c1`, `c2`) |
| `<p>.m` | Its MSS option. Not matched by itself: `m*N` windows are measured in it |
| `<p>.o` | Its TCP option layout: `M` MSS, `S` SACK permitted, `T` timestamps, `N` no-op, `W` window scale, `E` end of list, else the option number; `-` for none |
| `<p>.df` | `Y` if the "don't fragment" bit was set. IPv4 only |
| `<p>.ack` | A reset answering a SYN: `S+` if it acknowledges our sequence number plus one, `Z` if zero, `O` otherwise |
| `<p>.seq` | A reset answering an ACK: `A` if its sequence number is our acknowledgment number, `Z` if zero, `O` otherwise |
| `ws` | The window scale in the answer to `s1`, `-` for none |
| `ipid` | The IP ID sequence of the answers to `s1`-`s4` (IPv4, at least 3): `Z` all zero, `C` constant, `I` incremental, `BI` incremental in steps of 256, `RI` random increments, `RD` random |
| `ipid.rst` | The same for the resets (`a`, `c1`, `c2`) |
| `ipid.shared` | `Y` if SYN-ACKs and resets take their IP IDs from one counter |
| `ts` | The TCP timestamp clock from `s1` and `s4`: `U` no timestamps, `Z` zero, `R` a random offset per connection (the values jump), else the rate in Hz (`2`, `100`, `250`, `1000`) or `O` for another rate |

## Matching

Each test has a weight (in `os/db.rs`): `ttl` 30, `s1.o` 25, `s1.w` 20,
`ipid` and `ts` 15, `ws`, `ipid.rst`, `e.f` and `s1.df` 10, other option
layouts 10, `.ack` and `.seq` 3, the rest 5. A signature's accuracy is the
weight of its tests that match the fingerprint, over the weight of its
tests the fingerprint has; tests the fingerprint lacks (no closed port, no
echo, IPv6 without DF and IP ID) do not count. 100% is a perfect match and
names the OS. 85% and above are near matches, shown with `--osscan-guess`.
A fingerprint without an answer to `s1` matches nothing.

## The database format

Plain text. `#` starts a comment line. A signature is a block:

```text
Fingerprint Linux 4.19 - 6.x
Like Linux common
Class Linux, Linux, 4.X|5.X|6.X, general purpose
CPE cpe:/o:linux:linux_kernel:5
s1.w = m*max
ts = 1000|R
```

| Line | Meaning |
| --- | --- |
| `Fingerprint <name>` | Starts a signature; the name is what the report shows |
| `Template <name>` | Starts a block that is only copied by others, never reported |
| `Like <name>` | Copies an earlier block's tests, class and CPEs; the lines after it override them |
| `Class <vendor>, <family>, <generation>, <device type>` | What the report's `Running` and `Device type` lines and the XML `<osclass>` show. The generation may be empty |
| `CPE <cpe>` | One per line |
| `<test> = <values>` | What the test must show |

Values list alternatives separated by `|`. An alternative is compared as
is, or is `*` (anything), a number range `a-b`, or for a window `m*N` (N
times the answer's MSS, or N times the MSS less the 12 bytes of
timestamps) or `m*max` (the largest such multiple up to 65535). The
`m*` forms let one signature fit every link MTU.

Every signature gives at least `ttl`, `s1`, `s1.o`, `s1.w`, `s2.o`,
`s3.o`, `s4.o` and `e.o`, and one CPE; a test
(`built_in_database_parses_and_is_complete`) checks it.

## Adding a signature

1. Scan a machine you know, from a host on the same network, with an open
   and a closed TCP port in the scan:
   `sudo feroprobe -O -vv -p 22,1 <address>`.
2. Copy the `OS:` lines. Over IPv4 and IPv6 if you can.
3. Add a block to `os-fingerprints.txt`: start from the closest existing
   signature with `Like`, set what differs, and loosen tests that vary
   between installs (window scale, timestamps) with alternatives.
4. Add a unit test in `crates/feroprobe-core/src/os/tests.rs` that builds
   the answers and checks the name, and run `cargo test`.
5. Mention the OS version and how it was configured in the pull request.

Two signatures may both match perfectly when the probes cannot tell them
apart; the report then lists both, as nmap does.
