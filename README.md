# FeroProbe

A fast, nmap-style network scanner written natively in Rust: no nmap, no libpcap,
no external binaries.

> Only scan networks and hosts you own or have explicit permission to test.

## Status

| Feature | State |
| --- | --- |
| TCP connect scan, `-sT` (no root needed) | ✅ |
| TCP SYN scan, `-sS`, IPv4 and IPv6 (raw sockets, Linux, root or `CAP_NET_RAW`) | ✅ |
| FIN, NULL, Xmas, ACK, Window and Maimon scans (`-sF`, `-sN`, `-sX`, `-sA`, `-sW`, `-sM`) and custom flags with `--scanflags`, IPv4 and IPv6 (raw sockets, Linux, root) | ✅ |
| UDP scan, `-sU`, with DNS, NTP, SNMP and SSDP payloads | ✅ |
| Host discovery: ICMP/ICMPv6 echo + TCP 443/80 probes, `-sn`, `-Pn` | ✅ |
| ARP (IPv4) and neighbour discovery (IPv6) on the local network, with MAC address and vendor (Linux, root; `--disable-arp-ping` to turn off) | ✅ |
| MAC vendor names from the full IEEE OUI list (system `oui.txt` or `--oui-file`) | ✅ |
| Timing templates `-T0`…`-T5` and `--scan-delay` | ✅ |
| Targets: IPv4 and IPv6 addresses, CIDR, `a.b.c.X-Y` ranges, `fe80::1%eth0`, hostnames (`-6` for their IPv6 address) | ✅ |
| nmap-style `-p` port specs and top ports | ✅ |
| Table, JSON and nmap-style XML output, `--reason`, `--open` | ✅ |
| Service and version detection, `-sV`, with our own probes and rules | ✅ |
| OS detection, `-O`, from SYN-ACK traits with our own signatures (Linux, root; IPv4 only) | ✅ |
| Traceroute, `--traceroute`, IPv4 and IPv6 (Linux, root), and `-A` (`-sV -O --traceroute`) | ✅ |

## Install

Download a binary for Linux (x86_64, static musl, or arm64), macOS (Apple
silicon or Intel) or Windows (x86_64) from the
[releases page](https://github.com/jkobierczynski/FeroProbe/releases), or build
it:

```sh
cargo install --git https://github.com/jkobierczynski/FeroProbe feroprobe
```

## Usage

```sh
cargo build --release

# Discover hosts, then scan the top 100 ports (SYN scan when root on Linux,
# connect scan otherwise)
./target/release/feroprobe 192.168.1.0/24

# Ping sweep only (as root on Linux, hosts on the local network are found
# with ARP, which also shows their MAC address and vendor)
./target/release/feroprobe -sn 192.168.1.0/24

# Full SYN scan of one host, showing why each port got its state
sudo ./target/release/feroprobe -sS -p - --reason 10.0.0.5

# TCP and UDP together, skipping discovery
./target/release/feroprobe -Pn -sT -sU -p 53,123,161 scanme.example.org

# Which software runs on the open ports
./target/release/feroprobe -sV -p 22,80,443,6379 10.0.0.5

# Guess the operating system (raw sockets, so root)
sudo ./target/release/feroprobe -O 10.0.0.5

# IPv6: a prefix on the local link (found with neighbour discovery as root,
# with MAC addresses), a link-local host on a given interface, and the IPv6
# address of a hostname
sudo ./target/release/feroprobe -sn 2001:db8::/120 fe80::1%eth0
./target/release/feroprobe -6 -p 22,443 scanme.example.org

# Only open ports, as JSON
./target/release/feroprobe --top-ports 1000 --open -o json 10.0.0.1-50

# nmap-style XML, for tools that read nmap's -oX reports
./target/release/feroprobe -sV -o xml 10.0.0.0/24 > scan.xml
# The report says scanner="feroprobe". Add --nmap-label for importers
# that only accept scanner="nmap"; a comment still names FeroProbe.
```

Run `feroprobe --help` for all options (timeout, concurrency, packet rate, retries).

Example output:

```
Starting FeroProbe 0.2.0

Scan report for 127.0.0.1
Host is up, echo-reply (0.06 ms latency).
Not shown: 9998 closed ports
PORT       STATE          SERVICE        REASON
2024/tcp   open           unknown        syn-ack
8000/tcp   open           unknown        syn-ack

FeroProbe done: 1 host(s), 1 up, 10000 port(s) each, in 2.11s
```

With `-sV`:

```
PORT       STATE          SERVICE        VERSION
22/tcp     open           ssh            OpenSSH 9.6p1 (Ubuntu-3ubuntu13.5; protocol 2.0)
443/tcp    open           ssl/http       nginx 1.25.3 (cert CN: example.org)
6379/tcp   open           redis          Redis key-value store 7.0.15
```

### Version detection

`-sV` connects to each open port and works out what is running:

1. On usual TLS ports (443, 993, 8443, ...) it tries TLS first and probes
   the service inside the tunnel. The certificate's subject name is shown.
2. It sends the probes meant for that port: HTTP, Redis, memcached,
   PostgreSQL, AMQP, MQTT, RDP (with its security mode), Microsoft SQL Server
   (with its release, such as 2019), SMB (dialect and signing), LDAP (vendor,
   host and naming context), MongoDB, ZooKeeper, RTSP and SIP.
3. It listens, since SSH, FTP, SMTP, POP3, IMAP, MySQL, VNC, rsync, NNTP and
   IRC talk first.
4. If the service is still silent, it tries HTTP and then TLS.

Replies are matched against FeroProbe's own rules in
`crates/feroprobe-core/src/service/rules.rs`. nmap's probe database is not used,
because its license does not allow redistributing it. Replies that no rule
recognizes are printed under "Unrecognized service replies", which is the
starting point for a new rule. Open UDP ports get a DNS `version.bind`, NTP or
SNMP query. `--version-timeout` sets how long to wait for each reply (default
3000 ms).

### OS detection

`-O` sends one SYN that offers every common TCP option to an open port and
reads the SYN-ACK. The initial TTL (64, 128 or 255), the order of the TCP
options that come back and the "don't fragment" bit tell operating system
families apart, and the TTL also gives the number of hops:

```
OS guess: Linux 3.x - 6.x (90%), from 22/tcp
OS fingerprint: ttl=64 df=1 win=65483 opts=M,S,T,N,W mss=65495 ws=7
Network distance: 1 hop
```

The signatures are FeroProbe's own (in `crates/feroprobe-core/src/os.rs`), not
nmap's database, so the guess is per family (Linux, Windows, macOS, FreeBSD,
OpenBSD, network devices) rather than an exact version. Linux is still
recognized when SACK, timestamps or window scaling are turned off. The fingerprint line
shows the raw traits, which is what a new signature is written from. It needs
raw sockets, so Linux with root or `CAP_NET_RAW`, and at least one open TCP port.
IPv6 hosts are skipped for now: the signatures rely on IPv4 header fields.

### Traceroute and -A

`--traceroute` finds the routers between you and each host that is up. It
sends TCP SYN probes with TTL (IPv6: hop limit) 1 to 30 all at once, to a
port the scan found open, else one it found closed, else 80. Routers answer
the probes that expire with ICMP "time exceeded", and the host answers the
first probe that reaches it, which ends the route:

```text
TRACEROUTE (using port 443/tcp)
HOP RTT        ADDRESS
1   0.29 ms    192.168.1.1
2   ...
3   9.84 ms    203.0.113.5
```

A hop that never answers shows `...`. The route is in the JSON output under
`trace`, and in the XML as nmap's `<trace>` element. It needs raw sockets:
Linux, root or `CAP_NET_RAW`. It also works with `-sn`, probing port 80.

`-A` turns on `-sV`, `-O` and `--traceroute` together. Without raw-socket
privileges it runs only `-sV` and prints a warning.

### FIN, NULL, Xmas, ACK, Window and Maimon scans

These send TCP segments with other flags than SYN and read the answers the
way nmap does. They need the same raw-socket privileges as `-sS`, and one TCP
scan type can run at a time (it can be combined with `-sU`).

| Scan | Flags sent | Reset | No answer |
| --- | --- | --- | --- |
| `-sF` FIN, `-sN` NULL, `-sX` Xmas | FIN / none / FIN+PSH+URG | closed | open\|filtered |
| `-sM` Maimon | FIN+ACK | closed | open\|filtered |
| `-sA` ACK | ACK | unfiltered | filtered |
| `-sW` Window | ACK | open if the reset has a non-zero window, else closed | filtered |

An ICMP unreachable error marks the port filtered in all of them, with the
error as the reason (`host-unreach`, `admin-prohibited`, ...). FIN, NULL and
Xmas rely on RFC 793 behaviour: Windows and some network devices reset every
port, so every port looks closed. Most systems, Linux included, reset Maimon
probes to open ports too, so `-sM` shows them closed. Only some systems put a
non-zero window in the reset for `-sW`; Linux always sends zero, so `-sW`
shows every port on Linux as closed. `-sA` is for mapping
firewalls: "unfiltered" says a probe got through, not whether the port is open.

`--scanflags` sends any flag combination instead, given as names run together
(`SYNFIN`, `URGPSHFIN`; also `ECE`, `CWR`, `RST`) or a number. The answers are
read like those of the scan type given with it, or a SYN scan's without one:

```sh
sudo feroprobe --scanflags SYNFIN -p 80,443 10.0.0.5
sudo feroprobe -sA --scanflags ACKPSH -p 1-1024 10.0.0.5
```

### Privileges

The SYN scan and the other raw TCP scans send hand-built packets over raw
sockets, which needs root. On
Linux you can instead grant the binary just that capability:

```sh
sudo setcap cap_net_raw+ep ./target/release/feroprobe
```

Without it, a scan with no `-s` option uses a connect scan instead, and
discovery uses TCP probes (plus unprivileged ping sockets where the OS allows
them). An explicit `-sS` still needs the privileges; use `-sT` to ask for an
unprivileged TCP scan. With IPv6 targets on a system without IPv6, the default
is also a connect scan.

### IPv6

Every scan type takes IPv6 targets, and IPv4 and IPv6 targets can be mixed in
one scan. Hostnames resolve to their IPv4 address, like nmap; `-6` picks the
IPv6 address instead.

- Discovery pings with ICMPv6 echo. As root on Linux, targets on a directly
  connected link are asked with neighbour discovery (NDP) instead, which, like
  ARP for IPv4, also gives their MAC address and vendor.
- A link-local address (`fe80::/10`) needs the interface it is on:
  `fe80::1%eth0` (or `%2`, by index). Without one, the only interface that has
  a link-local address is used.
- A CIDR block may hold at most 2^20 addresses (a `/108`), so a whole `/64`
  cannot be swept; give the part you want, e.g. `2001:db8::/120`.

### Timing templates

`-T0` to `-T5` (or `-T paranoid` … `-T insane`) work like nmap's: each bundles
a timeout, retries, parallelism, packet rate and delay between probes.

| Template | Timeout | Retries | Parallel | Max rate (pps) | Scan delay |
| --- | --- | --- | --- | --- | --- |
| `-T0` paranoid | 5 s | 2 | 1 | 1 | 5 min |
| `-T1` sneaky | 5 s | 2 | 1 | 1 | 15 s |
| `-T2` polite | 3 s | 2 | 10 | 100 | 0.4 s |
| `-T3` normal (default) | 1.5 s | 1 | 500 | 5000 | none |
| `-T4` aggressive | 1 s | 1 | 1000 | 10000 | none |
| `-T5` insane | 0.3 s | 0 | 2000 | 50000 | none |

On Windows no template goes below a 3 s timeout, since Windows reports a
refused connection only about 2 s after the reset. `--timeout`, `--retries`,
`-c/--concurrency`, `--max-rate` and `--scan-delay` override the template's
value, so `-T4 --max-rate 2000` is aggressive with a lower packet rate.

### MAC vendor names

ARP discovery shows each local host's MAC address and its maker. FeroProbe does
not ship the IEEE OUI registry; it reads it at run time from the first of
`/usr/share/hwdata/oui.txt`, `/usr/share/ieee-data/oui.txt` and similar system
locations (installed by the `hwdata` or `ieee-data` packages, or by Wireshark).
Point it at another copy with `--oui-file`, for example the IEEE's own
[oui.csv](https://standards-oui.ieee.org/oui/oui.csv) or
[oui.txt](https://standards-oui.ieee.org/oui/oui.txt). Without any list, a
small built-in table of common vendors is used.

```sh
curl -o oui.csv https://standards-oui.ieee.org/oui/oui.csv
sudo ./target/release/feroprobe -sn --oui-file oui.csv 192.168.1.0/24
```

## Benchmarks

```sh
cargo bench -p feroprobe-core
```

measures packet building and parsing, port-spec parsing, and a connect scan of
1000 closed localhost ports. On a cloud VM: a SYN packet builds in about 10 ns,
a SYN-ACK parses in about 3.5 ns, the checksum runs at about 11 GiB/s, and the
connect scan takes about 18 ms (about 55,000 ports per second).

## Releases

Pushing a tag such as `v0.2.0` runs `.github/workflows/release.yml`, which
builds the binaries above, smoke-tests each one (the Intel macOS build, which
is cross-compiled, gets an architecture check instead), and publishes them with
SHA-256 checksums as a GitHub release.

## Layout

- `crates/feroprobe-core`: the scanning engine as a library: target and port
  parsing, connect/SYN/UDP scans, host discovery, and a small packet module
  (TCP, IPv4, ICMP, ICMPv6 and NDP) with no external packet crate.
- `crates/feroprobe-cli`: the `feroprobe` command-line tool.

## Port states

| State | Meaning |
| --- | --- |
| open | TCP: SYN-ACK or completed handshake. UDP: the service replied |
| closed | TCP: the host replied with a reset. UDP: ICMP port unreachable |
| filtered | No reply (TCP) or an ICMP unreachable error from a filter |
| open\|filtered | No reply where an open port stays silent too (UDP, FIN, NULL, Xmas, Maimon): a silent service or a firewall |
| unfiltered | ACK scan: the host reset the probe, so no filter dropped it; open or closed is unknown |

UDP note: hosts rate-limit ICMP errors, so scanning many closed UDP ports fast
can report some as open|filtered. Lower `--concurrency` for more accuracy.

**Windows note:** Windows waits about 2 seconds after a reset before it reports
"connection refused", so the default timeout there is 3000 ms instead of 1500 ms.
With a lower `--timeout`, closed ports show as filtered on Windows. The SYN scan
(Linux only for now) does not have this limitation.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
