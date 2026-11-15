# FeroProbe reference manual

This is the complete reference for the `feroprobe` command. It follows the
layout of nmap's reference guide: each section covers one group of options,
and every option is listed with its syntax, what it does, its default and
how it interacts with other options.

FeroProbe aims to behave like nmap. Where it deliberately does not, this
manual says so, and [Differences from nmap](#differences-from-nmap) lists
every such case in one place.

> Only scan networks and hosts you own or have explicit permission to test.
> See [docs/responsible-use.md](responsible-use.md).

## Contents

- [Synopsis](#synopsis)
- [Description](#description)
- [Options summary](#options-summary)
- [Target specification](#target-specification)
- [Host discovery](#host-discovery)
- [Reverse DNS](#reverse-dns)
- [Port scanning basics](#port-scanning-basics)
- [Scan techniques](#scan-techniques)
- [Port specification and scan order](#port-specification-and-scan-order)
- [Service and version detection](#service-and-version-detection)
- [OS detection](#os-detection)
- [Traceroute and aggressive mode](#traceroute-and-aggressive-mode)
- [Timing and performance](#timing-and-performance)
- [Firewall/IDS evasion](#firewallids-evasion)
- [Output](#output)
- [Checking a scan before and while it runs](#checking-a-scan-before-and-while-it-runs)
- [Miscellaneous options](#miscellaneous-options)
- [Settings files and ICS protection](#settings-files-and-ics-protection)
- [Privileges and platforms](#privileges-and-platforms)
- [Probe signature](#probe-signature)
- [Differences from nmap](#differences-from-nmap)
- [nmap options FeroProbe does not have](#nmap-options-feroprobe-does-not-have)
- [Exit status](#exit-status)
- [Files](#files)
- [Examples](#examples)
- [See also](#see-also)

## Synopsis

```
feroprobe [Scan Type(s)] [Options] {target specification}
```

## Description

FeroProbe is a network scanner written natively in Rust. It finds which
hosts on a network are up, which TCP, UDP and SCTP ports and which IP
protocols they answer on, which services and versions run there, which
operating system family they run, and the route to them. It builds and reads
its own packets: it does not use nmap, libpcap or any external binary, and
it ships its own service and OS signatures rather than nmap's databases.

The command line follows nmap's. Most nmap commands that use only options
FeroProbe has run unchanged, with the same defaults.

A scan runs in this order:

1. Targets are read, resolved and filtered by the exclusions.
2. Host discovery finds the targets that are up (skipped with `-Pn`).
3. Reverse DNS names the hosts (`-n` turns it off).
4. The port scans run on the hosts that are up: one TCP scan, plus UDP,
   SCTP and IP protocol scans if asked for.
5. Version detection (`-sV`) and OS detection (`-O`) run on what the port
   scans found.
6. Traceroute (`--traceroute`) traces the route to each host.
7. The reports are written.

## Options summary

`feroprobe --help` (or `feroprobe` with no arguments) prints a one-page
summary of every option, laid out like nmap's. `feroprobe -V` prints the
version.

Options can come in any order, before or after the targets. Single-letter
options that take a value accept it with or without a space (`-p22` or
`-p 22`), except the `-P` ping options and `-s` scan types, whose value is
always run on (`-PS22`, `-sS`). nmap's two-letter options `-iL`, `-oN`,
`-oX`, `-oG`, `-oA` (and FeroProbe's `-oJ`) are written exactly as in nmap,
as a separate word followed by their value.

Durations (`<time>`) are in seconds unless they end in `ms`, `s`, `m` or
`h`: `500ms`, `30s`, `5m`, `1.5h`. A bare number means seconds, as in nmap.
Options documented as taking milliseconds (`--timeout`, `--version-timeout`)
take a plain number of milliseconds instead.

## Target specification

Everything on the command line that is not an option is a target. Targets
can be mixed freely, IPv4 and IPv6 together.

| Form | Example | Notes |
| --- | --- | --- |
| IPv4 address | `192.168.1.10` | Four decimal parts |
| IPv6 address | `2001:db8::1`, `::1` | |
| Link-local IPv6 address with interface | `fe80::1%eth0`, `fe80::1%2` | Interface by name or index. Without one, the only interface that has a link-local address is used |
| CIDR block | `10.0.0.0/24`, `2001:db8::/120` | At most 2^20 (1,048,576) addresses per block, so an IPv6 block can be no larger than a `/108` |
| Last-octet range | `10.0.0.1-20` | IPv4 only |
| Hostname | `scanme.example.org` | Resolved with the system resolver. Its IPv4 address is scanned, or its IPv6 address with `-6` |

A target the system resolver would read as an old-style IPv4 number is
refused rather than scanned: a bare number (`2222` would mean 0.0.8.174),
fewer than four parts (`10.1.2`), octal (`010.0.0.1`) or hexadecimal
(`0x7f000001`). A bare number usually means a port was given to the wrong
option, and the error says so (`-PS22`, not `-PS 22`).

A hostname that does not resolve is skipped with `Failed to resolve "name".`
and the other targets are still scanned, as in nmap. A hostname without an
address of the wanted family is skipped with a hint to add (or drop) `-6`.
If no target is left, FeroProbe warns that 0 hosts were scanned.

A single run expands to at most 2^20 hosts.

#### `-iL <inputfile>` (long form `--input-file`)

Read more targets from a file. Targets are separated by spaces, tabs or
newlines, and `#` starts a comment that runs to the end of the line. Any
target form above works. `-` reads standard input. Targets from the file
are added to those on the command line.

#### `--exclude <host1[,host2],...>`

Leave these hosts out of the scan. Takes a comma-separated list of
addresses, CIDR blocks (of any size), ranges or hostnames. Hostnames are
resolved, and every address they resolve to is excluded.

#### `--excludefile <file>`

Leave out the hosts listed in a file, written like an `-iL` file.
`-iL -` and `--excludefile -` cannot both read standard input.

#### `-6`

Scan the IPv6 address of each hostname target instead of its IPv4
address. Address targets are always scanned as given, so `-6` is not
needed for IPv6 addresses.

#### `--randomize-hosts`

Scan the targets in random order instead of the order given.

## Host discovery

Before port scanning, FeroProbe finds out which targets are up and scans
only those. A host is up as soon as any probe draws an answer; a host that
answers none is reported as down and is not scanned. The probes are nmap's.

### Default probes

| Situation | Probes sent to each target |
| --- | --- |
| Raw sockets available (root or `CAP_NET_RAW` on Linux) | ICMP echo request, TCP SYN to port 443, TCP ACK to port 80, ICMP timestamp request (IPv4 only). For IPv6 targets the echo is ICMPv6 |
| No raw sockets | TCP connects to ports 80 and 443, plus an ICMP echo request through an unprivileged ping socket where the operating system offers one (not on Windows) |

A TCP connect that completes, or is refused with a reset, proves the host
exists. nmap without privileges sends no ICMP at all; FeroProbe uses the
unprivileged ping socket that Linux and macOS offer.

### Local network: ARP and neighbour discovery

As root on Linux, targets on a directly connected Ethernet network are asked
for their MAC address with ARP (IPv4) or neighbour discovery (IPv6) first,
as nmap does. Their answer, or its absence, decides them alone, and the ping
probes go only to the other targets. The answer also gives the host's MAC
address and its vendor (see `--oui-file` under
[Miscellaneous options](#miscellaneous-options)). The reason shown is
`arp-response` or `nd-response`.

### This machine

As root, a target that is this machine (a loopback address, or on Linux one
of its own addresses) is marked up without any probe, with the reason
`localhost-response`, as nmap does. Without raw sockets it is probed like any
other target. Traffic to your own address goes over the loopback interface,
so a capture on the Ethernet interface does not show it.

### Discovery options

Giving any `-P` option other than `-Pn` replaces the default probes: only
the probes you ask for are sent. The options can be repeated and combined,
for example `-PE -PP -PS22,443 -PA80`. Port lists are written like `-p`
lists and run on without a space; `-PS 22` is an error because `22` would be
read as a target. A probe type the process cannot send (for example `-PP`
without raw sockets) is skipped, and the other probes decide.

#### `-sn` (no port scan)

Only find out which hosts are up, then report them; no port scan.
Cannot be combined with other `-s` scan types, `--scanflags`, `-O` or
`-A`. It can be combined with `--traceroute`.

#### `-Pn` (no ping)

Skip host discovery and treat every target as up: every target is port
scanned, and every target is reverse-resolved. `-P0` is accepted as an
old spelling. Cannot be combined with other `-P` options. `-sn -Pn` would
do nothing and is refused unless `--traceroute` is given (trace only).

#### `-PS[portlist]` (TCP SYN ping)

Send a TCP SYN to each port (default port 80). A SYN-ACK or a reset proves
the host is up. With raw sockets on Linux the SYN is a bare raw packet;
otherwise it is a full TCP connect, as in nmap.

#### `-PA[portlist]` (TCP ACK ping)

Send a bare TCP ACK to each port (default port 80). A live host answers
with a reset. Needs raw sockets on Linux; otherwise the ports get a TCP
connect instead, as in nmap.

#### `-PU[portlist]` (UDP ping)

Send a UDP datagram to each port (default port 40125, which is unlikely
to be open). A reply, or an ICMP port unreachable, proves the host is up.
Datagrams to well-known ports carry that service's probe payload (see
[UDP scan](#udp-scan--su)).

#### `-PE` (ICMP echo)

Send an ICMP echo request (ICMPv6 for IPv6 targets). Needs raw sockets,
or an unprivileged ping socket where the OS has one.

#### `-PP` (ICMP timestamp)

Send an ICMP timestamp request. IPv4 only, needs raw sockets.

#### `-PM` (ICMP address mask)

Send an ICMP address mask request. IPv4 only, needs raw sockets. Few
hosts answer it today.

#### `--disable-arp-ping`, `--send-ip`

Do not use ARP or neighbour discovery: local targets get the ping probes
like remote ones. The two names do the same thing; `--send-ip` is nmap's.

nmap's `-PO` (IP protocol ping), `-PY` (SCTP ping) and `-PR` (ARP ping
only) are not supported and are refused with an error. ARP happens on its
own as described above.

`--exclude-ports` also removes its ports from the `-PS`, `-PA` and `-PU`
probes and from the default TCP probes, as nmap does. If that leaves a TCP
or UDP ping type with no ports, it is skipped with a warning.

## Reverse DNS

By default FeroProbe looks up the name of every host that is up (of every
target with `-Pn`). The name is shown as `Scan report for name (address)`,
written as a `type="PTR"` hostname in XML, and included in grepable and JSON
output. When a target was given by hostname, that name is shown, and a
different reverse name is printed as `rDNS record for <address>: <name>`.

#### `-n`

Never do reverse DNS lookups. Cannot be combined with `-R`.

#### `-R`

Look up the names of all targets, including those that are down.

#### `--dns-servers <serv1[,serv2],...>`

Ask these DNS servers directly instead of using the system resolver. Each
is an IP address, optionally with a port (`192.0.2.53:5353`,
`[2001:db8::53]:53`); the default port is 53. FeroProbe uses its own
resolver for these queries. Target hostnames are still resolved by the
system resolver.

## Port scanning basics

### Port states

| State | Meaning |
| --- | --- |
| `open` | A service accepts connections or datagrams there. TCP: a SYN-ACK or a completed handshake. UDP: the service replied. SCTP: an INIT-ACK. IP protocol scan: an answer in that protocol |
| `closed` | The port is reachable but nothing listens. TCP: a reset. UDP: ICMP port unreachable. SCTP: an ABORT. IP protocol scan: ICMP protocol unreachable |
| `filtered` | A firewall or filter is in the way: no answer where a closed port would have answered, or an ICMP unreachable error from a filter |
| `unfiltered` | ACK scan only: the probe got through (the host reset it), but open or closed is unknown |
| `open\|filtered` | No answer, where an open port also stays silent (UDP, FIN, NULL, Xmas, Maimon, SCTP COOKIE ECHO, IP protocol scans) |
| `closed\|filtered` | Used only by nmap's idle scan, which FeroProbe does not have; listed for completeness of the output formats |

### Reasons

`--reason` shows why each port, and each host, got its state. The reasons
are nmap's:

| Reason | Meaning |
| --- | --- |
| `syn-ack` | A SYN-ACK came back |
| `reset` | A TCP reset came back |
| `conn-refused` | The connection was refused (connect scan) |
| `no-response` | Nothing came back |
| `udp-response` | A UDP reply came back |
| `port-unreach`, `proto-unreach`, `host-unreach`, `net-unreach`, `admin-prohibited`, `unreachable` | An ICMP destination unreachable error of that kind |
| `init-ack`, `abort` | SCTP answers |
| `proto-response` | IP protocol scan: an answer in the probed protocol |
| `echo-reply`, `timestamp-reply`, `addressmask-reply` | ICMP answers to discovery probes |
| `arp-response`, `nd-response` | The host answered ARP or neighbour discovery |
| `localhost-response` | The target is this machine (see [Host discovery](#host-discovery)) |
| `user-set` | `-Pn`: the host was assumed up |
| `time-exceeded`, `param-problem` | Other ICMP errors |

## Scan techniques

One TCP scan type can run at a time. It can be combined with `-sU`, one of
`-sY`/`-sZ`, `-sO` and `-sV` in a single run, for example `-sS -sU -sV`.

With no `-s` option, FeroProbe runs a SYN scan when it may use raw sockets
(root or `CAP_NET_RAW` on Linux) and a connect scan otherwise, as nmap does.
It also falls back to a connect scan when an IPv6 target is given on a
system without IPv6 raw sockets. An explicit scan type (`-sU`, `-sY`, `-sZ`,
`-sO`) runs on its own and does not add the default TCP scan; `-sV` alone
keeps it.

The raw-socket scans need Linux with root or `CAP_NET_RAW`; see
[Privileges and platforms](#privileges-and-platforms). All scan types
support IPv4 and IPv6.

### TCP SYN scan (`-sS`)

Sends a SYN and reads the answer without completing the handshake: a
SYN-ACK means `open`, a reset `closed`, and no answer or an ICMP unreachable
error `filtered`. Unanswered probes are retried (`--retries`). This is the
default scan as root.

### TCP connect scan (`-sT`)

Asks the operating system to connect to each port, so it needs no
privileges and works on Linux, macOS and Windows. A completed connection
means `open`, a refused one `closed`, and a timeout `filtered`. This is the
default scan without raw sockets. It carries no FeroProbe signature, since
it is an ordinary connection. On Windows, a refused connection is reported
only about 2 seconds after the reset arrives, which is why the default
timeout there is 3000 ms; with a lower `--timeout`, closed ports show as
filtered.

### FIN, NULL, Xmas and Maimon scans (`-sF`, `-sN`, `-sX`, `-sM`)

| Scan | Flags sent | Reset | No answer | ICMP unreachable |
| --- | --- | --- | --- | --- |
| `-sF` FIN | FIN | closed | open\|filtered | filtered |
| `-sN` NULL | none | closed | open\|filtered | filtered |
| `-sX` Xmas | FIN, PSH, URG | closed | open\|filtered | filtered |
| `-sM` Maimon | FIN, ACK | closed | open\|filtered | filtered |

They rely on RFC 793 behaviour. Windows and some network devices reset
every such probe, so every port looks closed. Most systems, Linux included,
also reset Maimon probes to open ports, so `-sM` shows them closed.

### ACK scan (`-sA`)

Sends a bare ACK. A reset means `unfiltered` (the probe got through a
filter), no answer or an ICMP error means `filtered`. It maps firewall
rules; it cannot tell open from closed.

### Window scan (`-sW`)

Sends an ACK like `-sA`, and reads the TCP window of the reset: non-zero
means `open`, zero means `closed`; no answer means `filtered`. Only some
systems put a non-zero window in such resets. Linux always sends zero, so
`-sW` shows every port of a Linux host as closed.

### Custom TCP flags (`--scanflags <flags>`)

Sends any combination of TCP flags instead of the scan's own. Flags are
given as names run together, in any order (`SYNFIN`, `URGPSHFIN`; the names
are `URG`, `ACK`, `PSH`, `RST`, `SYN`, `FIN`, `ECE`, `CWR`), or as a number
(`--scanflags 3`). The answers are read as the scan type given with it reads
them (`-sA --scanflags ACKPSH` is read like an ACK scan), or as a SYN scan's
when no TCP scan type is given. It needs raw sockets, so it cannot be
combined with `-sT` or `-sn`.

### UDP scan (`-sU`)

Sends a datagram to each port. A UDP reply means `open`, an ICMP port
unreachable `closed`, another ICMP unreachable error `filtered`, and no
answer `open|filtered`. Works without privileges.

Well-known ports get a payload their service answers: DNS (53, 5353), NTP
(123), SNMP (161) and SSDP (1900). Every other port gets the payload
`FeroProbeScan/1\n` (see [Probe signature](#probe-signature)).

Hosts rate-limit their ICMP errors, so a fast scan of many closed UDP ports
can show some of them as `open|filtered`. Lower `--concurrency` or add a
`--scan-delay` for more accurate results (`--max-rate` does not pace UDP
probes).

### SCTP INIT scan (`-sY`)

SCTP carries telephone- and mobile-network signalling (SIGTRAN, Diameter,
S1AP/NGAP). `-sY` sends an INIT chunk, the first step of SCTP's handshake,
and never completes it: an INIT-ACK means `open`, an ABORT `closed`, and no
answer or an ICMP unreachable error `filtered`. Name SCTP ports with `S:` in
`-p`; without `-p` a built-in list of common SCTP ports is scanned. FeroProbe
does not check the CRC32c checksum of SCTP replies.

### SCTP COOKIE ECHO scan (`-sZ`)

Sends a COOKIE ECHO chunk out of the blue. An open port drops it silently
(`open|filtered`), and a closed one answers with an ABORT (`closed`). It
gets past some firewalls that block INIT chunks, but cannot tell open from
filtered. `-sY` and `-sZ` cannot run together.

### IP protocol scan (`-sO`)

Finds which IP protocols (ICMP, IGMP, TCP, UDP, GRE, ESP, SCTP, ...) a host
supports. Its "ports" are protocol numbers 0 to 255, named with `P:` in `-p`
(`-sO -p P:1,6,17,47`); without `-p` all 256 are tried. ICMP, IGMP, TCP,
UDP and SCTP get a real probe (an echo request, a membership query, an ACK,
a datagram, an INIT); every other protocol is sent as a bare IP header.

| Answer | State |
| --- | --- |
| Any answer in the probed protocol, or an ICMP port unreachable (the protocol is there, the port is not) | `open` |
| ICMP protocol unreachable | `closed` |
| Another ICMP unreachable error | `filtered` |
| No answer | `open\|filtered` |

`-sO` can run together with a TCP, UDP or SCTP scan.

### Version detection (`-sV`)

Listed with the scan types because it is given as `-s` option; see
[Service and version detection](#service-and-version-detection).

## Port specification and scan order

Without `-p`, `-F` or `--top-ports`, FeroProbe scans the 100 most common TCP
ports, the 20 most common UDP ports, the 50 most common SCTP ports (from
its own list), and, with `-sO`, all 256 IP protocols. These lists are
FeroProbe's own rankings.

#### `-p <port ranges>`, `--ports <port ranges>`

Scan only these ports. A comma-separated list of single ports (`22`),
ranges (`1-1024`), open-ended ranges (`-1024`, `60000-`) and `-` for all
of 1-65535 (`-p-`). Port 0 cannot be scanned. A protocol prefix applies to
the ports after it, up to the next prefix:

| Prefix | Applies to |
| --- | --- |
| `T:` | TCP ports |
| `U:` | UDP ports |
| `S:` | SCTP ports |
| `P:` | IP protocol numbers (0-255) for `-sO` |

Values before any prefix apply to every scan that runs: `-sS -sU -p
22,U:53,T:80` scans TCP 22 and 80 and UDP 22 and 53. FeroProbe warns, like
nmap, when the prefixes do not match the scans (`-sS -p U:53` warns that
`U:` needs `-sU`), and a scan type left with no ports is skipped with a
warning rather than failing. Cannot be combined with `--top-ports` or
`-F`.

#### `--top-ports <n>`

Scan the `n` most common ports of each protocol scanned. Without it the
defaults above apply.

#### `-F` (fast mode)

Scan the 100 most common ports of each protocol scanned. Cannot be
combined with `-p` or `--top-ports`.

#### `--exclude-ports <port ranges>`

Leave these ports out of the scan. Written like `-p`, prefixes included;
with `-sO`, `P:` numbers are left out of the protocol list. As in nmap,
the excluded ports are also removed from the discovery probes (see
[Host discovery](#host-discovery)).

#### `-r` (don't randomize ports)

Probe ports in numerical order. By default the order is shuffled, as in
nmap. Reports are always sorted.

## Service and version detection

#### `-sV`

After the port scan, find out which service and version run on each open
port. It runs on the hosts found up, together with any TCP scan (the
default one if none was given) and `-sU`. Cannot be combined with `-sn`.
It works without privileges.

For each open TCP port, FeroProbe:

1. Tries TLS first on the usual TLS ports (443, 993, 8443 and similar), and
   probes the service inside the tunnel. The certificate's subject name is
   shown with the version (`cert CN: example.org`).
2. Sends the probes meant for that port: HTTP, Redis, memcached, PostgreSQL,
   AMQP, MQTT, RDP (with its security mode), Microsoft SQL Server (with its
   release), SMB (dialect and signing), LDAP (vendor, host and naming
   context), MongoDB, ZooKeeper, RTSP and SIP.
3. Listens, since SSH, FTP, SMTP, POP3, IMAP, MySQL, VNC, rsync, NNTP and IRC
   speak first.
4. If the service stays silent, tries HTTP and then TLS.

Open UDP ports get a DNS `version.bind` query, an NTP query or an SNMP query
where they fit.

Replies are matched against FeroProbe's own rules, in
`crates/feroprobe-core/src/service/rules.rs`; nmap's probe database is not
used, because its licence does not allow redistributing it. The SERVICE
column then shows the service (`ssl/http` for HTTP inside TLS) and a VERSION
column is added. A reply no rule recognizes is printed under "Unrecognized
service replies" in normal output, which is the starting point for writing a
new rule.

#### `--version-timeout <ms>`

How long to wait for each service reply, in milliseconds. Default 3000.
The timing templates do not change it.

## OS detection

#### `-O`

Guess each host's operating system family. FeroProbe sends one TCP SYN
that offers every common TCP option to an open port, and reads the
SYN-ACK: the initial TTL (64, 128 or 255; for IPv6 the hop limit), the
order of the TCP options that come back, the "don't fragment" bit and the
window. The TTL also gives the network distance in hops.

```
OS guess: Linux 3.x - 6.x (90%), from 22/tcp
OS fingerprint: ttl=64 df=1 win=65483 opts=M,S,T,N,W mss=65495 ws=7
Network distance: 1 hop
```

The signatures are FeroProbe's own, in `crates/feroprobe-core/src/os.rs`,
not nmap's database, so the guess names a family (Linux, Windows, macOS,
FreeBSD, OpenBSD, network devices) rather than an exact version. The
fingerprint line shows the raw traits, from which new signatures are
written. IPv4 and IPv6 hosts are both covered; IPv6 replies are read from a
packet capture so that the hop limit is visible.

`-O` needs raw sockets (Linux, root or `CAP_NET_RAW`) and a port scan that
finds at least one open TCP port; it is an error without raw sockets and
cannot be combined with `-sn`. If no port scan is left to run (every scan
type lost its ports), OS detection is skipped with a warning. Its probes
deliberately carry no FeroProbe signature, since they must look like a real
operating system's.

## Traceroute and aggressive mode

#### `--traceroute`

After the port scan, trace the route to each host that is up. FeroProbe
sends TCP SYN probes with TTL (IPv6: hop limit) 1 to 30 all at once, to a
TCP port the scan found open on that host, else one it found closed, else
a fallback port the command names: the first port of the TCP
scan; with `-sn`, the first TCP port given with `-p`; else the first TCP
port of host discovery (`-PS`, `-PA`, or the default 443 as root). Traceroute
never probes a port outside the scan: when the command probes no TCP port
at all (for example `-sU -Pn`), hosts without an open or closed TCP port
are not traced and a warning says why, and `-sn -Pn --traceroute` without
`-p` is refused. Routers answer the
probes that expire with ICMP time exceeded, and the first probe that
reaches the host ends the route. A hop that never answers is shown as
`...`. Needs raw sockets. With `-Pn` every target is traced, even one that
never answered. Hosts given up on by `--host-timeout` are not traced.

```
TRACEROUTE (using port 443/tcp)
HOP RTT        ADDRESS
1   0.29 ms    192.168.1.1
2   ...
3   9.84 ms    203.0.113.5
```

To trace without a port scan, combine it with `-sn`, and with `-sn -Pn` to
skip host discovery too:

```sh
sudo feroprobe -sn --traceroute example.org
sudo feroprobe -sn -Pn --traceroute -p 443 example.org
```

#### `-A` (aggressive detection)

The same as `-sV -O --traceroute`. Without raw sockets only `-sV` runs,
rather than failing, as in nmap. Unlike nmap, which drops the other parts
silently, FeroProbe prints a warning naming them:

```
Warning: -A without root or CAP_NET_RAW skips OS detection (-O) and traceroute (--traceroute), which send raw packets; only version detection (-sV) runs. Run as root, or grant CAP_NET_RAW, to include them
```

nmap's `-A` also runs its default scripts (`-sC`); FeroProbe has no
scripts. Cannot be combined with `-sn`.

## Timing and performance

### Timing templates (`-T<0-5>`)

`-T0` to `-T5`, or `-T` with a name (`-T paranoid` ... `-T insane`), pick a
bundle of timing settings, as in nmap. `-T3` (normal) is the default. Any of
`--timeout`, `--retries`, `-c`/`--concurrency`, `--max-rate` and
`--scan-delay` given explicitly overrides the template's value for that
setting, so `-T4 --max-rate 2000` is aggressive with a lower packet rate.

| Template | Timeout | Retries | Parallel connect/UDP probes | Max rate (packets/s) | Scan delay |
| --- | --- | --- | --- | --- | --- |
| `-T0` paranoid | 5 s | 2 | 1 | 1 | 5 min |
| `-T1` sneaky | 5 s | 2 | 1 | 1 | 15 s |
| `-T2` polite | 3 s | 2 | 10 | 100 | 0.4 s |
| `-T3` normal (default) | 1.5 s | 1 | 500 | 5000 | none |
| `-T4` aggressive | 1 s | 1 | 1000 | 10000 | none |
| `-T5` insane | 0.3 s | 0 | 2000 | 50000 | none |

On Windows no template goes below a 3 s timeout (see the connect scan).

### Timing options

#### `--timeout <ms>`

How long to wait for an answer to each probe, in milliseconds. Default
from the template: 1500 (3000 on Windows). nmap adapts its timeouts to
measured round-trip times (`--min-rtt-timeout` and friends); FeroProbe
uses this fixed value. Below 20 ms it warns that accuracy may suffer.

#### `--retries <tries>`

How many more times to send a probe that got no answer. Default from the
template: 1. This is nmap's `--max-retries` under FeroProbe's own name.

#### `-c <number>`, `--concurrency <number>`

The most connect and UDP probes in flight at once. Default from the
template: 500. It warns above 900, and when the number is above the
system's open-file limit (`ulimit -n`). Raw-socket probes are paced by
`--max-rate` instead.

#### `--max-rate <number>`

Send at most this many raw-socket packets per second (SYN and other raw
TCP probes, SCTP, IP protocol, ICMP, ARP and NDP). Default from the
template: 5000. One rate holds for the whole run, across all scans and
hosts. Connect and UDP probes are bounded by `--concurrency` and
`--scan-delay` instead.

#### `--min-rate <number>`

Send at least this many probes per second. It raises `--max-rate` to at
least this number, shortens a template's scan delay to fit, and lets
enough connect and UDP probes be in flight to keep up the rate even when
every probe waits out its timeout (up to the open-file limit, with a
warning when that limit, or an explicit `--concurrency`, may hold the rate
down). It is an error when it is 0, above an explicit `--max-rate`, or
when an explicit `--scan-delay` is too long for it.

#### `--scan-delay <time>`

Wait at least this long between probes, across all scan techniques
(`500ms`, `2s`, `5m`; a bare number is seconds). Default from the
template: none for `-T3` and up.

#### `--host-timeout <time>`

Give up on a host whose port scans and detection take longer than this
(`30s`, `5m`). Hosts then run on their own clocks, up to 32 at once,
sharing `--concurrency` and the packet rate. A timed-out host is reported
without port or OS results: `Skipping host <addr> due to host timeout` in
normal output, `Status: Timeout` in grepable output and `timedout="true"`
in XML. It is not traced. `0` means no limit, as in nmap.

nmap's `--max-scan-delay`, `--min-rtt-timeout`, `--max-rtt-timeout`,
`--initial-rtt-timeout`, `--min-hostgroup`, `--max-hostgroup`,
`--min-parallelism` and `--max-parallelism` are not available.

## Firewall/IDS evasion

FeroProbe has nmap's fragmentation, decoy and spoofed-source options for
testing your own firewalls and intrusion detection, and for authorized
penetration tests. Unlike nmap, they are gated by an authorization model.

### Authorization model

- The options work only with a raw TCP scan (`-sS`, `-sF`, `-sN`, `-sX`,
  `-sA`, `-sW`, `-sM`, or `--scanflags`), on IPv4 targets. Anything else is
  refused with an error, with or without the flag below.
- Every target, every decoy and the spoofed source must be in a private
  range: RFC 1918 (10/8, 172.16/12, 192.168/16), carrier-grade NAT
  (100.64/10, RFC 6598), loopback (127/8) or link-local (169.254/16).
  (FeroProbe also treats IPv6 loopback, unique-local `fc00::/7` and
  link-local `fe80::/10` as private, though the options are IPv4 only.)
- A public address anywhere among them is refused, with a message naming
  it, unless you pass **`--allow-public-evasion`**. That flag is the
  deliberate opt-in that says you have permission to test those networks.
  Private ranges never need it.
- The address check runs before the privilege check, so a public address
  is refused whether or not raw sockets are available. A real run then
  needs raw sockets; `--dry-run` needs none and applies the same address
  check.

The reasons are in [docs/responsible-use.md](responsible-use.md).

### Options

#### `-f` (fragment packets)

Split each raw IPv4 probe into IP fragments that carry 8 bytes of payload
each, so a TCP header spans three fragments. Cannot be combined with
`--mtu`.

#### `--mtu <n>`

Fragment raw IPv4 probes with `n` bytes of payload per fragment. `n` must
be a positive multiple of 8.

#### `-D <decoy1[,decoy2][,ME],...>`, `--decoys`

Send each probe from every decoy source address as well, so the target
sees the scan coming from several hosts. Decoys are IPv4 addresses. nmap
uses the token `ME` to place the real scanner in the list; FeroProbe
accepts `ME` anywhere but always sends the decoy copies first and the real
probe last. Answers to the decoys go to the decoy addresses.

#### `-S <IP_Address>`, `--source`

Send the raw IPv4 probes from this forged source address. Answers go to
that address, not to FeroProbe, so the scan is blind unless FeroProbe sits
on the return path; it is mainly for watching what your IDS makes of the
traffic, as in nmap.

#### `--allow-public-evasion`

Authorize the options above against public targets, decoys and spoofed
sources you have permission to test.

With `--packet-trace` (and `--dry-run`), each fragment gets its own line,
so you see exactly what goes on the wire: the first fragment as `TCP
src:sport > dst:dport (frag)`, the later ones as `IP src > dst proto 6 frag
offset=N`, with a trailing `+` while more fragments follow. nmap shows only
the unfragmented probe there; see [Differences from nmap](#differences-from-nmap).

## Output

### Normal output

The default report on standard output is nmap's "normal" layout:

```
Starting FeroProbe 0.3.0

Scan report for example.org (203.0.113.5)
Host is up, syn-ack (0.85 ms latency).
Not shown: 96 closed ports
PORT       STATE          SERVICE        REASON
22/tcp     open           ssh            syn-ack
80/tcp     open           http           syn-ack
443/tcp    open           https          syn-ack
8080/tcp   filtered       http-proxy     no-response

FeroProbe done: 1 host(s), 1 up, 100 port(s) each, in 1.62s
```

Each host that is up gets a "Scan report" with the reason it is up and its
latency, its MAC address and vendor when ARP or neighbour discovery found
it, the port table, and the OS guess and route when asked for. Hosts that
are down are not listed (with `-Pn` every target is). When a single target
seems down, a note suggests `-Pn`.

**Not shown rule.** As in nmap, a non-open state is folded into a single
`Not shown: 96 closed ports` line (states with the most ports first) only
when a host has more than 25 ports in it; smaller groups are listed port by
port. So `-p 80` on a closed port shows `80/tcp closed`. Each `-v` raises
the limit by another 25 (50 with `-v`, 75 with `-vv`), and from `-vvv` on,
`open|filtered` ports are never folded, since they may be open. When every
port is folded, the line reads `All 1000 scanned ports are closed` (or
`... are in ignored states.` followed by the `Not shown` line). Open ports
are never folded.

### Output options

#### `-o <format>`, `--output <format>`

The format of the report on standard output: `table` (normal output,
the default), `xml`, `grepable` or `json`.

#### `-oN <file>`

Also write the normal report to a file.

#### `-oX <file>`

Also write the XML report to a file, in nmap's `-oX` layout (including
`<trace>` for traceroute), so tools that import nmap XML can read it. The
root element says `scanner="feroprobe"`; see `--nmap-label`.

#### `-oG <file>`

Also write the grepable report to a file: one line per host, like nmap's
`-oG`, for `grep` and `awk`.

#### `-oJ <file>`

Also write the JSON report to a file. JSON is FeroProbe's own format: a
top-level object with `scanner`, `version`, `scan_types`, `elapsed_secs`
and a `hosts` array, each host with its address, names, up reason, ports
(number, protocol, state, reason, round-trip time, service and version),
MAC address, OS guess and trace where present.

#### `-oA <basename>`

Write `<basename>.nmap`, `<basename>.xml` and `<basename>.gnmap` (normal,
XML and grepable) at once.

A file name of `-` sends that report to standard output in place of the
usual report there; only one report can go to standard output. Two reports
cannot share a file (FeroProbe checks the real files, so links and other
spellings of the same path are caught), and `-oA -` is refused. All report
files are opened (created, not truncated) before the scan starts, so an
unwritable path fails at once, as in nmap. A `--dry-run` writes no reports
and creates no files.

#### `--nmap-label`

Write `scanner="nmap"` in the XML report instead of
`scanner="feroprobe"`, for importers that accept only nmap's reports. A
comment in the file still names FeroProbe.

#### `--open`

Show only ports that are open or possibly open: `open`, `open|filtered`
and `unfiltered`, as in nmap. No `Not shown` line is printed; a host with
none of these shows `No open ports found`. Applies to every output
format.

#### `--reason`

Add a REASON column with the reason each port got its state (see
[Reasons](#reasons)). XML and JSON always carry the reasons.

#### `-v`, `-vv`

Report progress on standard error: each phase as it starts and ends with
its time (`Initiating TCP SYN scan of 4 hosts`, `Completed TCP SYN scan in
1.21s`), how many hosts are up, excluded hosts, and each open port as a
scan finds it (`Discovered open port 22/tcp on 10.0.0.5`). `-vv` adds
more notes, such as resolver hints. Each `-v` also raises the
[Not shown](#normal-output) limit.

#### `--stats-every <time>`

Print a progress line to standard error at this interval, for example
`Stats: 0:01:05 elapsed; TCP SYN scan: 45.20% done (4520 of 10000
probes)`. `0` turns it off.

## Checking a scan before and while it runs

These options show what FeroProbe will do or is doing. `--explain` and
`--dry-run` are FeroProbe's own; nmap has nothing like them.

#### `--explain`

Before anything is sent, print the plan made from the command line to
standard error, step by step, with the reason for each choice: the
targets, which hosts get ARP and which get ping probes (and which
probes), whether names are looked up, which scan type was picked and why,
where the ports came from, the timing settings, and what runs after the
port scan. The scan then runs as usual. Combined with `--dry-run` it
explains the plan and lists the probes without sending anything.

#### `--packet-trace`

Print every probe sent and every answer received on standard output, as
nmap does: `SENT` for packets sent, `RCVD` for packets received, and
`CONN` for connect attempts and their result.

```
SENT (0.0005s) ICMP [10.0.0.2 > 10.0.0.5 Echo request (type=8/code=0) id=7996 seq=0]
RCVD (0.0007s) ICMP [10.0.0.5 > 10.0.0.2 Echo reply (type=0/code=0) id=7996 seq=0] ttl=64
CONN (0.0006s) TCP localhost > 10.0.0.5:443 => Connection refused
SENT (0.0543s) TCP 10.0.0.2:48100 > 10.0.0.5:22 S seq=2448842408 win=65109
RCVD (0.0545s) TCP 10.0.0.5:22 > 10.0.0.2:48100 SA seq=1290442 win=64240 ttl=64
```

With `-f`/`--mtu` every fragment gets its own line (see
[Firewall/IDS evasion](#firewallids-evasion)).

#### `--dry-run`

Send nothing. Print the host-discovery and port-scan probes the scan would
send, one line per probe in the `--packet-trace` layout with the prefix
`NOT SENT (dry run)`, then stop. It covers host discovery and every port scan, with `-f`/`--mtu`,
`-D` and `-S` applied, so the lines show the real flags, sequence
numbers, window, payload sizes, fragments and source addresses. Comment
lines starting with `#` group the probes by target and phase and end with
a count.

```
# Dry run (--dry-run): these are the probes the scan would send. Nothing is sent.
# Target 10.0.0.5 from 10.0.0.2
# Host discovery
NOT SENT (dry run) ICMP [10.0.0.2 > 10.0.0.5 Echo request (type=8/code=0) id=14847 seq=0]
...
# TCP scan with raw packets, flags S
NOT SENT (dry run) TCP 10.0.0.2:43970 > 10.0.0.5:22 S seq=1654920040 win=65109
# Dry run done: 4 discovery and 1 port-scan probe for 1 host listed, nothing sent; ...
```

Because nothing is sent, nothing comes back: there are no `RCVD` lines and
no port states. A dry run therefore assumes every target is up and lists
the port-scan probes for all of them (a real run scans only the hosts
discovery finds), lists only the first attempt of each probe (a real run
resends unanswered ones up to `--retries` times), and only names the
steps that depend on answers (`-sV`, `-O`, `--traceroute`, reverse DNS)
instead of listing their probes. Target hostnames are still resolved
through the system resolver, even with `-n` (give numeric addresses when no
DNS traffic is allowed), so the addresses shown are the real ones,
and the routing table is consulted (without sending) for the source
address. No reverse DNS query is made. With `--traceroute`, a note names
the TCP port traceroute would fall back to (or says hosts would not be
traced).

**A dry run is not a preview of nmap.** It lists FeroProbe's probes. nmap
run with the same options sends different packets, and some of its
features probe outside `-p`, so a dry run must not be used to check an
nmap command before running it. What nmap sends in addition or instead,
per option:

| Options | What nmap does differently |
| --- | --- |
| `-A` | Also runs its default scripts (`-sC`). Some probe outside `-p`: `ms-sql-info` sends a 1-byte UDP datagram to port 1434 of every host; others connect to the open ports and talk to the services |
| `-A` without root | Silently skips OS detection and traceroute (FeroProbe skips them with a warning) |
| `-sV` | Sends probes from its own database (dozens to an unrecognized port), also probes UDP ports left `open\|filtered`, and runs its version scripts on open ports |
| `-O`, IPv4 | Sends 16 probes per host to an open TCP port, a closed TCP port and a closed UDP port. A closed port is one the scan found closed, else unfiltered; without one it picks a random TCP or UDP port between 30000 and 44780, outside `-p` |
| `-O`, IPv6 | Sends up to 17 probes per host, including a neighbour solicitation to on-link targets. Without a closed (or unfiltered) TCP port it skips the closed-port TCP probes; without a closed (or unfiltered) UDP port it picks a random one between 30000 and 44780, outside `-p` |
| `--traceroute` | Traces with the probe that got the best answer (TCP, UDP, SCTP or ICMP), else an ICMP echo |
| Raw TCP scans | TCP window 1024 instead of FeroProbe's signature 65109 |
| `-sU` | Payloads for many more ports, empty datagrams elsewhere (FeroProbe: `FeroProbeScan/1`) |
| `-f`, `--mtu` | Sends fragments too, but its `--packet-trace` shows the unfragmented packet |
| `-D` with `ME` | Sends the real probe at `ME`'s place, not last |
| Default discovery without root | Only TCP connects to 80 and 443, no ICMP echo |
| Any scan | Adaptive timeouts and up to 10 resends, instead of a fixed `--timeout` and `--retries` |

These come from nmap 7.99's source.

A dry run needs no root, writes no report files (it warns if `-oN`,
`-oX`, `-oG`, `-oJ` or `-oA` were given), and notes when a real run of the
same command would need raw-socket privileges. The evasion address check
still applies: a public address with `-f`, `--mtu`, `-D` or `-S` is
refused unless `--allow-public-evasion` is given.

This matters most on operational-technology and industrial-control
(OT/ICS) networks, where an unexpected packet can hang or reset a fragile
device such as a PLC or RTU. With `--dry-run`, an operator can check
every target, port, flag and fragment a command would send, and confirm it
stays within the approved scope, before any scan probe is sent.
Then run the same command without `--dry-run`, ideally with a gentle
timing template (`-T0` or `-T1`), a low `--max-rate` and a short, explicit
port list, with FeroProbe: the same command run with nmap sends other
probes. The closest nmap option, the list scan `-sL`, only lists the
targets.

## Miscellaneous options

#### `-6`

Use the IPv6 address of hostname targets; see
[Target specification](#target-specification).

#### `-A`

Version detection, OS detection and traceroute; see
[Traceroute and aggressive mode](#traceroute-and-aggressive-mode).

#### `--override-ics-protection`

Run once despite ICS protection, allowing `-sV`, `-O` and `-A`, with a
prominent warning naming what it allowed. Changes no settings file. See
[Settings files and ICS protection](#settings-files-and-ics-protection).

#### `--oui-file <file>`

The IEEE OUI list used to name the vendor of MAC addresses found by ARP
or neighbour discovery. FeroProbe reads `oui.txt`, `oui.csv` and
Wireshark `manuf` files. Without this option it uses the first of
`/usr/share/hwdata/oui.txt`, `/usr/share/ieee-data/oui.txt` and similar
system locations that exists (installed by the `hwdata` or `ieee-data`
packages, or by Wireshark), and otherwise a small built-in table of
common vendors. The IEEE publishes the list at
`https://standards-oui.ieee.org/oui/oui.csv`.

#### `-V`, `--version`

Print the version and exit.

#### `-h`, `--help`

Print the help page and exit. Running `feroprobe` with no arguments does
the same.

## Settings files and ICS protection

FeroProbe reads optional settings from TOML files when it starts, lowest
precedence first:

1. `$XDG_CONFIG_HOME/feroprobe/config.toml` (`~/.config/feroprobe/config.toml`
   when `XDG_CONFIG_HOME` is unset or not absolute; `%APPDATA%\feroprobe\config.toml`
   on Windows without `HOME`);
2. under `sudo`, the same file in the invoking user's home (from
   `SUDO_USER`), since sudo points `HOME` at root's (skipped when sudo kept
   an absolute `XDG_CONFIG_HOME`, which already names your file);
3. `.feroproberc` in the current directory.

A key in a later file replaces the same key from an earlier one, and
command-line options win over all of them. A missing file is skipped; one
that cannot be read, is not valid TOML or gives a value of the wrong type
stops the run. Unknown keys only warn. `-v` prints which files were read
and whether ICS protection is on. nmap has no such files.

The one setting is `ics_protection`, **off by default**: FeroProbe is a
general scanner and behaves like nmap unless you ask otherwise.

```toml
ics_protection = true
```

With it on:

- `-sV`, `-O` and `-A` are refused before any name is resolved or packet
  sent, with a message naming the option and where protection was turned
  on. Version detection sends application-protocol probes (HTTP, TLS, ...)
  to every open port, and fragile PLCs and RTUs can fault or hang when,
  for example, their Modbus handler on port 502 receives an HTTP request.
- `--override-ics-protection` lets a single run through with a warning.
- `--dry-run` is not refused, since it sends no probes, but warns that the
  real run would be.
- A scan that includes a well-known OT port (102/tcp S7comm, 502/tcp
  Modbus, 20000/tcp+udp DNP3, 44818/tcp+udp EtherNet/IP, 47808/udp BACnet)
  prints a warning. Ports are never refused.

### Hardened build

Building with the `ics-protection-default` Cargo feature makes protection
always on in that binary: settings files cannot switch it off (a
`ics_protection = false` is ignored with a warning), and only
`--override-ics-protection` allows a single run. For teams that hand out
a FeroProbe binary for use on control networks:

```sh
cargo build --release -p feroprobe --features ics-protection-default
```

See [docs/ics-protection.md](ics-protection.md) for the full rationale.

## Privileges and platforms

| Needs raw sockets (Linux, root or `CAP_NET_RAW`) | Works without |
| --- | --- |
| `-sS`, `-sF`, `-sN`, `-sX`, `-sA`, `-sW`, `-sM`, `--scanflags`, `-sY`, `-sZ`, `-sO`, `-O`, `--traceroute`, `-f`, `--mtu`, `-D`, `-S`, ARP and neighbour discovery, raw `-PS`/`-PA` pings, `-PP`, `-PM` | `-sT`, `-sU`, `-sV`, `-sn`, `-Pn`, `-PS` and `-PA` (as connects), `-PU`, `-PE` (where an unprivileged ping socket exists), all output options, `--explain`, `--dry-run` |

Instead of running as root on Linux, you can grant the binary just the
capability it needs:

```sh
sudo setcap cap_net_raw+ep /path/to/feroprobe
```

Without raw sockets, a scan with no `-s` option runs a connect scan, and
discovery uses its unprivileged probes; an explicit raw scan type, `-O` or
`--traceroute` is an error that says what is needed. `-A` degrades to `-sV`
with a warning naming what it skipped (nmap degrades silently).

Linux has every feature. On macOS and Windows FeroProbe runs the connect and
UDP scans, discovery with its unprivileged probes, `-sV`, and every output
format; the raw-socket features are Linux only.

## Probe signature

FeroProbe's probes carry a stable, documented signature so that network
owners can recognize them:

- Raw TCP scans (`-sS`, `-sF`, `-sN`, `-sX`, `-sA`, `-sW`, `-sM`,
  `--scanflags`) set the TCP window to 65109 (`0xFE55`).
- UDP probes to ports without a service payload carry `FeroProbeScan/1\n`.

The connect scan and OS detection probes carry no mark, by design. Suricata
and Snort rules matching the signature are in the repository's `rules/`
directory. Details are in [docs/responsible-use.md](responsible-use.md).

## Differences from nmap

FeroProbe follows nmap unless nmap's behaviour is clearly wrong or a
safeguard calls for a difference. The deliberate differences are:

| Behaviour | nmap | FeroProbe |
| --- | --- | --- |
| `--packet-trace` with `-f`/`--mtu` | Prints one `SENT` line for the unfragmented probe, although fragments are what goes on the wire | Prints one line per fragment actually sent. nmap's display is treated as a bug |
| Evasion options (`-f`, `--mtu`, `-D`, `-S`) | Allowed against any address | Raw IPv4 TCP scans only; public targets, decoys or spoofed sources need `--allow-public-evasion` |
| Decoy order (`-D ...,ME,...`) | `ME` places the real probe | `ME` is accepted, but the real probe always goes last |
| Probe signature | None | Raw TCP probes use window 65109; generic UDP probes carry `FeroProbeScan/1\n` |
| Unprivileged discovery | TCP connects to 80 and 443 only | The same, plus an ICMP echo through an unprivileged ping socket where the OS offers one |
| `--explain`, `--dry-run` | No equivalent | FeroProbe's own planning and checking options |
| Settings files, `ics_protection`, `--override-ics-protection` | No equivalent | FeroProbe's own; off by default, so default behaviour is unchanged |
| JSON output (`-oJ`) | No equivalent | FeroProbe's own format |
| XML `scanner` attribute | `nmap` | `feroprobe`, unless `--nmap-label` |
| Service and OS signatures | nmap's databases | FeroProbe's own (nmap's cannot be redistributed); OS detection names the family, not the version |
| Timeouts | Adapt to measured round-trip times | A fixed `--timeout` per probe, set by the template |
| Old-style IPv4 numbers as targets (`2222`, `10.1.2`, `010.0.0.1`) | Passed to the resolver | Refused with an explanation |
| Probes outside the requested ports | `-A`'s scripts can probe other ports (`ms-sql-info`: UDP 1434 on every host); `-O` picks a random closed UDP port (and for IPv4 also TCP) when the scan found none | Never beyond the command's own ports (`-p` plus the host-discovery ports): `-sV` and `-O` probe only open ports the scan found, traceroute only a scanned port, a discovery port, or (with `-sn`) the `-p` port, and FeroProbe has no scripts |
| Traceroute port | The probe that got the best answer during discovery or the scan, else ICMP echo | TCP SYNs to an open or closed scanned port, else a TCP port the command names (`-p` with `-sn`, or a discovery port), else the host is not traced (FeroProbe used to fall back to port 80) |
| `-A` without root | Silently drops `-O` and traceroute | Drops them with a warning naming them |

Behaviour that looks unusual but matches nmap includes: skipping discovery
for this machine as root (`localhost-response`), ARP or neighbour discovery
deciding local hosts alone, the default discovery probes, the 25-port
`Not shown` rule, `--exclude-ports` thinning the ping probes, shuffled port
order, and skipping (rather than failing) a scan type left without ports.

## nmap options FeroProbe does not have

These nmap options are refused as unknown, or (for `-PO`, `-PY`, `-PR`)
with an error naming the supported alternatives:

- Scans and discovery: `-sL` (list scan), `-sI` (idle scan, not planned),
  `-b` (FTP bounce), `-PO`, `-PY`, `-PR`, `-iR`, `--system-dns`,
  `--resolve-all`.
- Scripting: `-sC`, `--script` and related options (nmap's scripts cannot
  be shipped under their licence).
- Version and OS detection tuning: `--version-intensity`,
  `--version-light`, `--version-all`, `--version-trace`, `--osscan-limit`,
  `--osscan-guess`, `--max-os-tries`.
- Timing: `--min-rtt-timeout`, `--max-rtt-timeout`, `--initial-rtt-timeout`,
  `--max-retries` (use `--retries`), `--min-hostgroup`, `--max-hostgroup`,
  `--min-parallelism`, `--max-parallelism` (use `-c`), `--max-scan-delay`,
  `--defeat-rst-ratelimit`.
- Evasion and packet options: `--spoof-mac`, `-g`/`--source-port`, `-e`,
  `--data`, `--data-string`, `--data-length`, `--ip-options`, `--ttl`,
  `--badsum`.
- Output and misc: `-oS`, `--append-output`, `--resume`, `--stylesheet`,
  `--webxml`, `--no-stylesheet`, `-d`, `--iflist`, `--privileged`,
  `--unprivileged`, `--port-ratio`, and the interactive keys during a scan.

[DEVELOPMENT.md](../DEVELOPMENT.md) tracks which of these are planned.

## Exit status

| Status | Meaning |
| --- | --- |
| 0 | The scan (or dry run) completed. Hosts being down or ports closed is not an error |
| 1 | FeroProbe refused the command or the scan failed; the reason is printed to standard error after `Error:` |
| 2 | The command line could not be parsed (an unknown option or an invalid value) |

Warnings, progress (`-v`, `--stats-every`) and `--explain` go to standard
error; reports, `--packet-trace` and `--dry-run` output go to standard
output.

## Files

| Path | Use |
| --- | --- |
| `/usr/share/hwdata/oui.txt`, `/usr/share/ieee-data/oui.txt` and similar | MAC vendor names, unless `--oui-file` is given |
| `~/.config/feroprobe/config.toml` (`$XDG_CONFIG_HOME`), the invoking user's under `sudo`, and `./.feroproberc` | Settings; see [Settings files and ICS protection](#settings-files-and-ics-protection) |
| The system resolver's configuration (`/etc/resolv.conf` on Unix) | Resolving target hostnames, and reverse DNS without `--dns-servers` |

FeroProbe needs no other data files: its port rankings, service rules and
OS signatures are built into the binary.

## Examples

```sh
# Discover hosts on a network, then scan their 100 most common TCP ports
feroprobe 192.168.1.0/24

# Ping sweep only
sudo feroprobe -sn 192.168.1.0/24

# Every TCP port of one host, with the reason for each state
sudo feroprobe -sS -p- --reason 10.0.0.5

# TCP and UDP together, skipping discovery
feroprobe -Pn -sT -sU -p 53,123,161 scanme.example.org

# Services and versions, OS and route in one go
sudo feroprobe -A -p 22,80,443 10.0.0.5

# Custom discovery probes
sudo feroprobe -sn -PE -PP -PS22,443 -PA80 10.0.0.0/24

# SCTP signalling ports, and which IP protocols a host speaks
sudo feroprobe -sY -p S:2905,3868 10.0.0.5
sudo feroprobe -sO -p P:1,6,17,47,50,132 10.0.0.5

# IPv6: a local prefix, a link-local host, and the IPv6 address of a name
sudo feroprobe -sn 2001:db8::/120 fe80::1%eth0
feroprobe -6 -p 22,443 scanme.example.org

# Gentle scan of a fragile network: check the probes first, then run it
# (same privileges for both, since root changes the default scan type)
sudo feroprobe --dry-run -T1 --max-rate 10 -p 502,102 10.10.0.0/28
sudo feroprobe -T1 --max-rate 10 -p 502,102 10.10.0.0/28

# Test your own IDS with fragments and decoys (private range)
sudo feroprobe -sS -f -D 10.0.0.7,ME,10.0.0.8 -p 80 --packet-trace 10.0.0.5

# Read targets from a file, write all report formats
feroprobe -iL hosts.txt --exclude 10.0.0.1 -oA weekly

# Grep open ports from grepable output on standard output
feroprobe -oG - 192.168.1.0/24 | grep '/open/'
```

## See also

- [README.md](../README.md): overview, installation and quick start
- [DEVELOPMENT.md](../DEVELOPMENT.md): implemented features and the gap to
  nmap parity
- [docs/responsible-use.md](responsible-use.md): the safeguards and why
  they exist
- `rules/`: Suricata and Snort rules that detect FeroProbe's probes
- nmap(1)
