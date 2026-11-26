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
- [Script scanning](#script-scanning)
- [Timing and performance](#timing-and-performance)
- [Firewall/IDS evasion and spoofing](#firewallids-evasion-and-spoofing)
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
2. Host discovery finds the targets that are up (skipped with `-Pn`). A
   list scan (`-sL`) stops after the next step and sends the targets
   nothing.
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
`-oX`, `-oS`, `-oG`, `-oA` (and FeroProbe's `-oJ`) are written exactly as in nmap,
as a separate word followed by their value.

Durations (`<time>`) are in seconds unless they end in `ms`, `s`, `m` or
`h`: `500ms`, `30s`, `5m`, `1.5h`. A bare number means seconds, as in nmap.
Options documented as taking milliseconds (`--timeout`, `--version-timeout`)
take a plain number of milliseconds instead. For the RTT timeout options a
bare number of 50000 or more is refused with a hint, as in nmap, since it
was almost surely meant as milliseconds.

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
without raw sockets) is skipped, and the other probes decide. The exceptions
are `-PY` and `-PO`, which have no fallback: without raw sockets on Linux
FeroProbe refuses them, as nmap does without root, rather than leaving them
out. `--dry-run` still lists them.

#### `-sL` (list scan)

List the targets and send them nothing: no ping, no ARP or neighbour
discovery, no port scan. Each target is reported with its reverse DNS name
(unless `-n`), so it is a quick way to see what a target specification
expands to, and what the addresses are called, before scanning anything.
The only traffic is the DNS queries for those names, which go to the
resolver, not to the targets. The report lists every target with no host
status (XML `state="unknown"`, grepable `Status: Unknown`, JSON
`"up": false`), and the totals count no host as up, as in nmap.

`-sL` cannot be combined with port scan types, `-sV`, `--scanflags`,
`-p`, `-F`, `--top-ports`, `-O`, `-A` or `--traceroute`. `-sn` may come
along and changes nothing. `-P` options are ignored, with a warning for
each (nmap ignores them silently). `--dry-run -sL` lists the targets and
says nothing would be sent. `-sL` is not `--dry-run`: a dry run lists the
probes a scan would send, a list scan only the targets.

#### `-sn` (no port scan)

Only find out which hosts are up, then report them; no port scan.
Cannot be combined with other `-s` scan types, `--scanflags`, `-O` or
`-A`. It can be combined with `--traceroute`.

#### `-Pn` (no ping)

Skip host discovery and treat every target as up: every target is port
scanned, and every target is reverse-resolved. `-P0` is accepted as an
old spelling. Cannot be combined with other `-P` options. `-sn -Pn` would
do nothing and is refused unless `--traceroute` is given (trace only).

As in nmap, targets on a local Ethernet network still get one ARP (IPv4)
or neighbour discovery (IPv6) request when FeroProbe runs with raw
sockets, unless `--disable-arp-ping` is given: the answer gives the
report's MAC address and latency and times the port scan's first probes.
Targets that do not answer are scanned all the same. Other targets show
the latency the port scan measured.

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

#### `-PY[portlist]` (SCTP INIT ping)

Send an SCTP INIT chunk to each port (default port 80), the same packet as
the `-sY` scan's. An INIT-ACK (the port is open) or an ABORT (closed)
proves the host is up, and so does an ICMP port or protocol unreachable
that the target sends itself; the same error from a router on the way
proves nothing. Needs raw sockets on Linux (refused otherwise). Hosts
whose kernel has no SCTP support usually answer with a protocol
unreachable, which counts.

#### `-PO[protocol list]` (IP protocol ping)

Send one IP packet of each protocol in the list (default `1,2,4`: ICMP,
IGMP and IP-in-IP), built as the `-sO` scan builds them: an ICMP echo
request for 1, an IGMP membership query for 2, a TCP ACK to port 80 for 6,
a UDP datagram to port 40125 for 17, an SCTP INIT to port 80 for 132, and
a bare IP header for the others. Any answer from the target in a probed
protocol proves it up (`proto-response`), and so does an ICMP protocol or
port unreachable from the target itself. Protocol numbers run from 0 to
255 and run on without a space: `-PO1,6,17`. Needs raw sockets on Linux
(refused otherwise). The echo request carries FeroProbe's `feroprobe`
payload like every discovery echo request; `-sO`'s stays empty, as in nmap.

#### `-PR` (ARP ping)

Accepted, and changes nothing, as in nmap (whose current versions call it
deprecated): targets on a local Ethernet network always get an ARP or
neighbour discovery request when FeroProbe has raw sockets, unless
`--disable-arp-ping` is given, and other targets get the usual probes. In
particular `-PR` does not stop the ping probes to remote targets. A warning
says so on every run (nmap prints its note only with `-v`).

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

`--exclude-ports` also removes its ports from the `-PS`, `-PA`, `-PU` and
`-PY` probes (`S:` ports for `-PY`), its `P:` protocols from `-PO`, and its
ports from the default TCP probes, as nmap does. If that leaves a ping type
with no ports, it is skipped with a warning.

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

#### `--system-dns`

Use the system resolver for reverse DNS. That is already FeroProbe's
default (nmap's default is its own parallel resolver), so the option only
matters together with `--dns-servers`, which it overrides, with a warning.

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
| `proto-response` | IP protocol scan or ping (`-PO`): an answer in the probed protocol |
| `echo-reply`, `timestamp-reply`, `addressmask-reply` | ICMP answers to discovery probes |
| `arp-response`, `nd-response` | The host answered ARP or neighbour discovery |
| `localhost-response` | The target is this machine (see [Host discovery](#host-discovery)) |
| `user-set` | `-Pn`: the host was assumed up; with `-sL`, the host was only listed |
| `time-exceeded`, `param-problem` | Other ICMP errors |

## Scan techniques

One TCP scan type can run at a time. It can be combined with `-sU`, one of
`-sY`/`-sZ`, `-sO`, `-sV` and `-sC` in a single run, for example `-sS -sU -sV`.
As in nmap, the letters can be run together after one `-s`: `-sCV` is
`-sC -sV`, and `-sSU` is `-sS -sU`.

With no `-s` option, FeroProbe runs a SYN scan when it may use raw sockets
(root or `CAP_NET_RAW` on Linux) and a connect scan otherwise, as nmap does.
It also falls back to a connect scan when an IPv6 target is given on a
system without IPv6 raw sockets. An explicit scan type (`-sU`, `-sY`, `-sZ`,
`-sO`) runs on its own and does not add the default TCP scan; `-sV` alone
keeps it.

The raw-socket scans need Linux with root or `CAP_NET_RAW`; see
[Privileges and platforms](#privileges-and-platforms). All scan types
support IPv4 and IPv6.

Like nmap's, the probes of the raw-socket scans, of host discovery and of
the UDP scan go out without the "don't fragment" bit and with a random TTL
(IPv6: hop limit) from 37 to 59, picked again for every probe. Traceroute
sets its own TTLs.

### TCP SYN scan (`-sS`)

Sends a SYN and reads the answer without completing the handshake: a
SYN-ACK means `open`, a reset `closed`, and no answer or an ICMP unreachable
error `filtered`. Unanswered probes are resent as the host's losses call for, up to
`--retries` times (see [Resends and delays](#resends-and-delays)). This is the
default scan as root.

### TCP connect scan (`-sT`)

Asks the operating system to connect to each port, so it needs no
privileges and works on Linux, macOS and Windows. A completed connection
means `open`, a refused one `closed`, and a timeout `filtered`. An open
port's connection is closed at once with a reset, as nmap does, rather
than with a FIN. This is the
default scan without raw sockets. It carries no FeroProbe signature, since
it is an ordinary connection. On Windows, a refused connection is reported
only about 2 seconds after the reset arrives, so there a connect try never
waits less than 3 s, whatever the timeout options say.

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

Well-known ports get a payload their service answers: DNS (53, 5353),
NetBIOS name service (137, a NODE STATUS request with transaction ID
`0x4650` "FP"), NTP (123), SNMP (161) and SSDP (1900). Every other port gets the payload
`FeroProbeScan/1\n` (see [Probe signature](#probe-signature)).

Hosts rate-limit their ICMP errors, so many closed UDP ports only answer
a resent probe. As in nmap, the scan then resends more often and raises its
delay between probes to that host (see [Resends and delays](#resends-and-delays)),
which makes UDP scans of closed ports slow but accurate. A scan that gives
up early (`--max-retries`, or a low `--max-scan-delay`) can show some
closed ports as `open|filtered` (`--max-rate` does not pace UDP probes).

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

### FTP bounce scan (`-b <FTP relay host>`)

Asks an FTP server (the relay) to open a data connection to each target
port, as nmap's `-b` does: after logging in, FeroProbe sends one `PORT`
command naming the target address and port, then `LIST`, over a single
control connection. The relay, not this machine, connects to the targets,
so the result shows what the targets look like from the relay's network.

The argument is `[user[:pass]@]server[:port]`; the defaults are user
`anonymous`, password `-wwwuser@` and port 21, like nmap's. The last `@`
ends the login, so a password may contain `@`. Plain FTP sends the login
in cleartext, so anyone on the path to the relay can read a password given
here; reports show the command line with it masked (`user:****@server`),
so `--resume` refuses such a report: run the bounce scan again instead.

| Relay's answer to `LIST` | State |
| --- | --- |
| `150`/`125` then `226` (the data connection opened), or a `2xx` | `open` |
| `425` (can't open data connection), `150` then `426`, anything else | `closed` |
| Nothing within 12 seconds, or a `150` that never completes (FeroProbe sends `ABOR`) | `filtered` |

After a reply that did not come in time, or an `ABOR`, FeroProbe logs in
again before the next port, so a late reply cannot be read as the answer
about another port. `--scan-delay` (and the timing templates' delay) waits
between ports.

If the relay refuses a `PORT` command for a port below 1024 before any
privileged port went through, FeroProbe warns and skips the privileged
ports, as nmap does; if it refuses an unprivileged one, the relay cannot
bounce at all and the scan stops with an error. The reason shown with
`--reason` is `ftp-bounce` (or `no-response` for `filtered`).

`-b` is a TCP scan of its own: it replaces the default TCP scan and cannot
be combined with `-sS`, `-sT` or the other TCP scans. It is IPv4 only,
because `PORT` carries an IPv4 address, and it needs no privileges. Host
discovery still runs from this machine, so FeroProbe prints nmap's hint to
add `-Pn` when the targets are only reachable from the relay. The FTP
commands and answers show in `--packet-trace` as `SENT ... FTP` and `RCVD
... FTP` lines (the password as `****`), and `--dry-run` lists one line per
port.

Like the evasion options, the bounce scan is refused when any target or
the relay has a public address, unless `--allow-public-evasion` is given;
see [the authorization model](#authorization-model). Few FTP servers still
allow it (RFC 2577 asks them not to).

### Version detection (`-sV`)

Listed with the scan types because it is given as `-s` option; see
[Service and version detection](#service-and-version-detection).

## Port specification and scan order

Without `-p`, `-F` or `--top-ports`, FeroProbe scans the 1000 most common
TCP ports and the 1000 most common UDP ports, as nmap does, the 50 most
common SCTP ports, and, with `-sO`, all 256 IP protocols.

The TCP and UDP lists are nmap's: the same ports in the same order as
nmap's `--top-ports`, ranked by the frequencies in nmap's `nmap-services`
(nmap 7.94). The default scan, `-F` (the first 100) and `--top-ports N`
(the first `N`) cover the same ports as nmap's. Only the port numbers and
their order are taken; the names FeroProbe prints come from the IANA
registry.

`-p-` scans all 65535.

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

Scan the `n` most common ports of each protocol scanned, from the ranked
lists above. Past the end of a list (1000 TCP, 1000 UDP, 52 SCTP ports)
the remaining ports are added in ascending order. Without it the defaults
above apply.

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

The probes and the rules that read the replies come from FeroProbe's
[service rules file](#service-rules-file). nmap's probe database is not
used, because its licence does not allow redistributing it. Each probe has
a rarity from 0 to 9: the higher, the less likely it is to help. For each
open TCP port, FeroProbe tries, until a rule matches:

1. On the TLS probe's ports (443, 993, 8443 and similar), a TLS handshake
   first, then the probes inside the tunnel. The certificate's subject
   name is shown with the version (`cert CN: example.org`).
2. The probes meant for that port, whatever the intensity: HTTP on 80 and
   8080, Redis on 6379, SMB on 445, and so on.
3. The `null` probe: connect and listen, since SSH, FTP, SMTP, POP3, IMAP,
   MySQL, VNC and others speak first.
4. Every other probe whose rarity is at most the
   [intensity](#--version-intensity-level), the most common first, as nmap
   does.
5. A TLS handshake, when the port stayed silent or answered with a TLS
   alert.

A **soft match** names the service but not the product (a `+OK` greeting
is POP3, but whose?). Probing then goes on only with the probes that can
tell more about that service, as in nmap (with every probe at intensity
9). Open UDP ports get the UDP probes the same way, without the listen and
TLS steps. Like nmap, UDP ports the scan left `open|filtered` are probed
too, and one that answers becomes `open` (reason `udp-response`).

A reply that is exactly the probe sent is an `echo` service (RFC 862), as
nmap reports it. nmap recognizes the echo from one probe (`help`); FeroProbe
from whichever probe comes back unchanged, so an echo also never passes for
the service whose request it reflects (an echoed SNMP GetRequest used to be
reported as `snmp`).

Each probe opens a new connection and waits up to `--version-timeout` for
a reply, so a silent port costs one wait per probe tried: at the default
intensity about 15 probes. `--version-light` makes such ports much quicker.

Protocols with their own probes: HTTP, RTSP, SIP, SMB, RDP, Redis, LDAP,
ONC RPC, DNS (TCP and UDP), Microsoft SQL Server, PostgreSQL, SOCKS5,
memcached (TCP and UDP), AMQP, MQTT, MongoDB, ZooKeeper, X11, Java RMI,
AJP, XMPP, PPTP, Erlang Port Mapper, Cassandra, beanstalkd, git, SNMP,
NetBIOS name service, NTP, SSDP, IPMI and OpenVPN. Services recognized from
what they send first: SSH, FTP, SMTP, POP3, IMAP, MySQL and MariaDB, VNC,
telnet, rsync, NNTP, IRC, NATS, ActiveMQ, Subversion, dictd and ident.
FeroProbe sends no probes for industrial protocols (Modbus, S7 and the
like): a version probe is a request the device has to parse.

The SERVICE column shows the service (`ssl/http` for HTTP inside TLS) and
a VERSION column is added. Below the ports, a `Service Info` line collects
what the services gave away about the host, as in nmap: host names, the
operating system, the device type and operating-system CPEs
(`Service Info: Host: mail.example.org; OS: Linux; CPE: cpe:/o:linux:linux_kernel`).
The XML report carries every CPE as `<cpe>` elements of `<service>` and the
`hostname`, `ostype` and `devicetype` attributes; the JSON report has the
same fields.

A port that takes the connections but answers no probe gets the usual
service name for the port with a `?` (`jetdirect?`; a port with no usual
name stays `unknown`), as in nmap. A reply no rule recognizes is shown with
a `?` after the usual service name for the port and, at intensity 7 or more (as in nmap), printed under
"Unrecognized service replies" in normal output and as `servicefp` in XML:
the starting point for writing a new rule.

#### `--version-intensity <level>`

How many probes to try, from 0 to 9; default 7, as in nmap. A probe is
sent when its rarity is at most the level, or when it is meant for the
port. At 0, an open port only gets the probes meant for it and the `null`
probe. At 9 every probe is tried, and soft matches no longer narrow the
probes. The last of `--version-intensity`, `--version-light` and
`--version-all` wins, as in nmap. Without `-sV` (or `-A`) the option does
nothing, and FeroProbe warns.

#### `--version-light`

`--version-intensity 2`: the probes meant for the port, the `null` probe,
HTTP, the generic line probe and TLS.

#### `--version-all`

`--version-intensity 9`: every probe.

#### `--version-trace`

Print what version detection does to standard output: each probe sent,
each reply (escaped, up to 120 bytes), and each match with the rule that
made it, in the layout of nmap's version trace. When a JSON, XML or
grepable report goes to standard output (`-o json`, `-oX -`, ...), the
trace goes to standard error instead, so the report stays readable:

```
Service scan sending probe null to 10.0.0.5:22 (tcp)
Service scan got 32 bytes in reply to probe null from 10.0.0.5:22 (tcp): "SSH-2.0-OpenSSH_9.6p1 Debian-4\r\n"
Service scan hard match (Probe null matched with built-in rules line 332): 10.0.0.5:22 is ssh.  Version: |OpenSSH|9.6p1|Debian-4; protocol 2.0|
```

The rule is named by its line in the rules file (or as a built-in parser,
the built-in echo check or the built-in HTTP header reader), which makes the trace the tool for
writing and debugging rules. nmap's version trace also prints its network
library's debug lines; FeroProbe prints only the lines above.

#### `--service-rules <file>`

Read the probes and rules from `<file>` instead of the built-in ones. The
file replaces the built-in rules completely, so start from a copy of
[`crates/feroprobe-core/data/service-rules.txt`](../crates/feroprobe-core/data/service-rules.txt).
A mistake in the file stops the scan before anything is sent, naming the
line. nmap's `--versiondb` takes nmap's own format; FeroProbe does not read
that format and says so if given an `nmap-service-probes` file.

#### `--allports`

Probe every open port with `-sV`, including the ones the rules file
excludes. The built-in rules exclude TCP 9100-9107, the raw printing ports
of network printers (JetDirect, AppSocket): a printer prints whatever
reaches them, so each probe would come out as a page of garbage. Without
`--allports` version detection sends those ports no probe (the port scan
itself still reaches them, as in nmap: a TCP connect scan opens and closes
a connection, which prints nothing) and they show the name their number
suggests with a `?` (`jetdirect?`), as in nmap, which excludes the same
ports. `--dry-run` lists the ports it would skip.

#### `--version-timeout <ms>`

How long to wait for each service reply, in milliseconds. Default 3000.
The timing templates do not change it.

### Service rules file

The rules file is plain text in FeroProbe's own format. It starts with the
line `feroprobe-service-rules 1`. `#` starts a comment line. Directives
start at the beginning of a line; their attributes follow on indented
lines.

```
feroprobe-service-rules 1

probe null tcp
  rarity 0

probe redis tcp
  rarity 6
  ports 6379,6380
  send "*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n"

match redis ^\$\d+\r\n.*?redis_version:([\d.]+)
  product Redis key-value store
  version ${1}
  cpe cpe:/a:redis:redis:${1}

softmatch pop3 ^\+OK\x20
  probe null
```

`probe NAME tcp|udp` defines a probe:

| Attribute | Meaning |
| --- | --- |
| `rarity N` | 0 to 9 (default 5). Sent at an intensity of at least `N`, and always to its own ports. 0 means always |
| `ports LIST` | The ports the probe is meant for, such as `80,8000-8010` |
| `send "TEXT"` | The bytes to send. `\r`, `\n`, `\t`, `\0`, `\\`, `\"` and `\xHH` are understood; several `send` lines are joined |
| `pad N` | Append `N` zero bytes |
| `tls` | A TLS handshake instead of a payload (the `tls` probe) |
| `listen-ports LIST` | For the TLS probe: inside TLS, listen first on these ports |

`exclude tcp|udp LIST` names ports `-sV` leaves alone unless
`--allports` is given, like nmap's `Exclude` directive. The built-in file
has `exclude tcp 9100-9107` (printers).

A probe with no payload, like `null`, connects and listens. The built-in
parsers for binary replies (SQL Server, SMB, RDP, LDAP, DNS, NTP, SNMP,
SSDP and NetBIOS) run on the replies to the probes of those names.

`match SERVICE REGEX` and `softmatch SERVICE REGEX` define a rule. The
regular expression is the rest of the line, run on the raw reply with
`.` matching any byte, newlines included, and `\xNN` matching byte `NN`
(Rust regex syntax, flags `(?s-u)`); write `\x20` for a space at either end.
Rules are tried in file order, hard matches before soft ones, and the
first match wins. A soft match takes only `probe` and `ports`. Attributes:

| Attribute | Meaning |
| --- | --- |
| `probe NAME` | Only read replies to this probe |
| `ports LIST` | Only read replies from these ports, for a reply that means different services on different ports (Dovecot greets LMTP on 24 and mail submission on 587 the same way) |
| `product`, `version` | The product and version; `${1}`, `${2}`, ... are the regex's groups |
| `info TEXT` | Extra information; may be repeated, joined with `; ` |
| `host`, `os`, `device` | What goes in the `Service Info` line |
| `cpe TEXT` | A CPE name such as `cpe:/a:openbsd:openssh:${2}`; may be repeated |

## OS detection

#### `-O`

Enable OS detection. For every host where the port scan found an open TCP
port, FeroProbe sends a small set of probes, reads how the host's TCP/IP
stack answers, and matches that fingerprint against its own OS database,
which names OS versions where the probes can tell them apart (for example
Linux 4.19 - 6.x against Linux 3.x - 4.18, or Windows 10 - 11 against
Windows 7).

One try sends a host at most 9 probes, all to ports and protocols the
command already probes:

| Probe | Sent to | What it is |
| --- | --- | --- |
| `s1`-`s4` | the open TCP port | four SYNs with different TCP option sets, 100 ms apart |
| `e` | the open TCP port | a SYN with ECE and CWR (asks for ECN) |
| `a` | the open TCP port | an ACK outside any connection |
| `c1`, `c2` | a closed TCP port, if the scan found one | a SYN and an ACK |
| `ie` | the host, only if the command's host discovery sends ICMP echo requests (the default as root, or `-PE`) | an ICMP or ICMPv6 echo request with the `feroprobe` payload |

The fingerprint records, per probe, whether it was answered, the TCP
flags, window, option layout and "don't fragment" bit of the answer, and
across probes the initial TTL (IPv6: hop limit), the window scale, the IP
ID sequence (IPv4), how the TCP timestamp clock runs, and whether the
host answers ECN. Each signature in the database lists the values it
expects; its accuracy is the share of its tests (weighted) that match. A
signature that matches every test the fingerprint has is a perfect match,
reported as the OS:

```
Device type: general purpose
Running: Linux 4.X|5.X|6.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:linux:linux_kernel:6
OS details: Linux 4.19 - 6.x
Network Distance: 1 hop
```

Without a perfect match FeroProbe prints `No exact OS matches for host`
and the fingerprint (lines starting with `OS:`), so it can be added to the
database, see [docs/os-fingerprints.md](os-fingerprints.md). Signatures
that match at 85% or better are shown as `Aggressive OS guesses` with
`--osscan-guess`, or when the conditions were not ideal (for example no
closed port), as in nmap. With `-v` the IP ID sequence class is shown
(`IP ID Sequence Generation: All zeros`); with `-vv` the fingerprint is
shown even for a perfect match. The network distance is 0 for this
machine, 1 for a host whose MAC address discovery found, and otherwise
counted from the TTL.

As in nmap, a host without a perfect match is tried again, up to
`--max-os-tries` times (default 5), or at most twice when the conditions
make a match unlikely: no closed TCP port, a host more than five hops
away, or a `--scan-delay` above 500 ms. A host with an open but no closed
TCP port gets the warning `OSScan results may be unreliable because we
could not find at least 1 open and 1 closed port`. A host without an open
TCP port gets no OS probes at all (nmap would probe its closed port and
random closed ports outside the scan, see [Differences from
nmap](#differences-from-nmap)).

The XML report has nmap's `<os>` element (`<portused>`, `<osmatch>` with
`<osclass>` and `<cpe>`, `<osfingerprint>`), then `<distance>` and
`<ipidsequence>`; the grepable report lists perfect matches after `OS:`;
the JSON report has the full result under `os`.

`-O` needs raw sockets (Linux, root or `CAP_NET_RAW`) and a port scan; it
is an error without raw sockets and cannot be combined with `-sn`. If no
port scan is left to run (every scan type lost its ports), OS detection is
skipped with a warning. IPv4 and IPv6 hosts are both covered; the answers
are read from a packet capture, which shows the IP header of both. The TCP
probes deliberately carry no FeroProbe window marker, since they must
look like a real client's SYNs; the echo request carries the usual
`feroprobe` payload. `--packet-trace` and `--dry-run` show each probe's
TCP options (`<mss 1460,sackOK,timestamp ...>`). With `ics_protection`
on, `-O` is refused (see [ICS protection](#settings-files-and-ics-protection)).

#### `--osscan-limit`

Only run OS detection against hosts where the scan found at least one open
and one closed (or unfiltered) TCP port, as in nmap. Other hosts are
skipped (with `-v`, a line says so), which saves time on many hosts. No
effect without `-O` or `-A` (a warning says so).

#### `--osscan-guess`, `--fuzzy`

When no signature matches perfectly, also print the near matches (85% or
better) as `Aggressive OS guesses: Linux 4.19 - 6.x (93%), ...` and the
`Running (JUST GUESSING)` line, as in nmap. No effect without `-O` or `-A`.

#### `--max-os-tries <tries>`

How many tries a host without a perfect match gets (default 5, at least
1). Each try sends the probe set again. A lower value is faster and
gentler on hosts the database does not know; it does not raise the limit
of two tries for hosts without a closed port. No effect without `-O` or
`-A`.

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
are not traced and a warning says why (with `-sn`, name the port with
`-p`). A directly connected host needs no port, since it gets no probes
(see below). Routers answer the
probes that expire with ICMP time exceeded, and the first probe that
reaches the host ends the route. A hop that never answers is shown as
`...`. Needs raw sockets. With `-Pn` every target is traced, even one that
never answered. Hosts given up on by `--host-timeout` are not traced.

As in nmap, this machine itself (a loopback address or one of its own) is
not traced at all, and a host on a directly connected network gets no
probes: its route is the host alone, at hop 1, with the latency the scan
measured, under a plain `TRACEROUTE` header (in XML, a `<trace>` element
without a port).

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

The same as `-sV -O -sC --traceroute`, as in nmap: version detection, OS
detection, the default scripts (see [`-sC`](#-sc-default-scripts)) and
traceroute. Without raw sockets only `-sV` and `-sC` run, rather than
failing, as in nmap. Unlike nmap, which drops the other parts silently,
FeroProbe prints a warning naming them:

```
Warning: -A without root or CAP_NET_RAW skips OS detection (-O) and traceroute (--traceroute), which send raw packets; only version detection (-sV) and the default scripts (-sC) run. Run as root, or grant CAP_NET_RAW, to include them
```

`--script` given with `-A` adds to the default scripts. Cannot be combined
with `-sn` or `-sL`. With ICS protection on, `-A` is refused as a whole.

## Script scanning

After the scan, FeroProbe can run scripts against the hosts and ports it
found, like nmap's scripting engine. Scripts are written in Lua 5.4, which
is built into FeroProbe. Each script decides from what the scan found
whether it runs on a host or a port (its *rule*), then its *action* talks
to the service and returns a result, which the report shows under the port
or the host.

The scripts are FeroProbe's own, with FeroProbe's own script library
(`fero`). nmap's libraries (`stdnse`, `shortport`, `nmap.new_socket` and
the rest) cannot be shipped under their licence, so nmap's scripts run
only when they use the parts of those libraries that FeroProbe's own
[NSE compatibility layer](#nse-compatibility-layer) offers. FeroProbe
ships its own scripts, written from the protocols' specifications (see
[Built-in scripts](#built-in-scripts)): `-sC` runs the ones in the
`default` category, and more come in later releases. You can run your
own: see [Writing scripts](#writing-scripts).

Scripts run in a sandbox and can only reach the host they run against, and
only the ports the scan probed there: see
[Script sandbox and scope](#script-sandbox-and-scope).

Scripts run last for each host group, after version and OS detection and
traceroute, on the hosts found up (every host with `-Pn`) that were not
given up on by `--host-timeout`, as in nmap. Scripts with a `prerule` run
once before host discovery, and scripts with a `postrule` once after the
last host. With `-sn`, scripts with a `hostrule` still run, but no port is
probed, so they can open no socket. A list scan (`-sL`) refuses `--script`
and `-sC`, since it sends the targets nothing. With ICS protection on,
`--script`, `-sC` and `-A` are refused (see
[Settings files and ICS protection](#settings-files-and-ics-protection)).

```
$ feroprobe -p 22,25 --script banner 192.0.2.10
PORT       STATE          SERVICE
22/tcp     open           ssh
|_banner: SSH-2.0-OpenSSH_9.6
25/tcp     open           smtp
|_banner: 220 mail.example ESMTP Postfix
```

#### `-sC` (default scripts)

Run the scripts in the `default` category, the same as `--script
default`, as in nmap. `-A` includes it. Given with `--script`, the
default scripts run as well as the ones `--script` names. Like nmap's
default set, these scripts are chosen to be quick, to say something
useful about common services, and to be safe: they read greetings,
capabilities and keys, never try passwords other than an anonymous login
where the protocol defines one (FTP), and change nothing on the target.
They run on a port only when the port is open and its number or service
(from the port number, or from `-sV`) is theirs; see
[Built-in scripts](#built-in-scripts) for the list. As every script, they
reach only the ports the scan probed: `ftp-anon` therefore lists no
files (a listing would come over a second connection to a port the
server picks), and nothing is sent to a port outside `-p`.

```
$ feroprobe -sCV -p 21,22,80 192.0.2.10
PORT       STATE          SERVICE        VERSION
21/tcp     open           ftp            vsftpd 3.0.5
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
22/tcp     open           ssh            OpenSSH 9.6p1 Ubuntu 3ubuntu13
| ssh-hostkey: 
|   256 4f:0a:...:91 (ECDSA)
|_  256 c2:7e:...:3b (ED25519)
80/tcp     open           http           nginx 1.24.0
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 1 disallowed entry
|_/admin
|_http-title: Welcome
```

With ICS protection on, `-sC` is refused like `--script`.

#### `--script <scripts>`

Choose the scripts to run: a comma-separated list where each item is

- a script name, such as `banner`, with `*` matching any run of characters
  (`http-*`); a trailing `.lua` or `.nse` is allowed;
- a category, such as `safe` or `discovery`, or `all` for every script;
- a boolean expression of names and categories with `and`, `or`, `not` and
  parentheses, such as `"safe and not intrusive"`. As in nmap, `and` and
  `or` bind equally and group from the right (`a and b or c` is
  `a and (b or c)`), so use parentheses when mixing them;
- a script file, given by its path, with or without `.lua` (or `.nse`,
  for scripts written for nmap: see [NSE compatibility
  layer](#nse-compatibility-layer));
- a directory, given by its path with a trailing `/`, for every `.lua`
  and `.nse` file in it. Without the slash it is refused, as in nmap, so that a
  directory named like a category is never picked by mistake.

Names, categories and expressions choose among the scripts built into
FeroProbe and the scripts installed in your
[scripts directory](#--script-updatedb) that its index lists. An item that
matches none of them is tried as a file, then as a directory, then as the
name of a script in the scripts directory (`--script my-check` finds
`my-check.lua` there even before it is indexed, as nmap does); one that
matches nothing at all stops the run before anything is sent, as does a script that fails to load, or two scripts with the same
name. A `+` before an item runs its scripts on every host and port whatever
their rules say (scripts with a `portrule` still only see the ports that
may be open). `--script` may be given more than once; the lists add up.
`-v` prints how many scripts were loaded.

As in nmap, a script chosen by its name (or a name pattern such as
`http-*`, also inside an expression) or by its file path runs as if `-v`
had been given once more, so it shows the detail it was asked for:
`--script snmp-interfaces` lists interfaces that are down, which `-sC` or
`--script default` shows only with `-v`. Scripts chosen by category or
directory see the verbosity as set. As in nmap, the first item that
matches a script decides: `--script snmp-interfaces,default` gives the
boost, `--script default,snmp-interfaces` does not.

Each script is loaded (its file run in the sandbox to read its fields)
when FeroProbe starts. Its rules are checked in one sandbox per host (the
hostrule and the portrules of that host's ports), and its action runs in
a fresh sandbox for every host or port, so actions share nothing with
each other, with the rules or between runs.

#### Brute-force scripts

A script in the `brute` category tries to log in to a service by guessing
user names and passwords, so running one sends real login attempts to the
target. FeroProbe runs a brute-force script only when you choose it
deliberately:

- by its exact name, such as `--script ftp-brute`;
- by a file path, such as `--script ./ftp-brute.lua`; or
- by the `brute` category word, such as `--script brute` or
  `--script "brute and safe"`.

It is never run when it is only swept up by `all`, by another category
such as `intrusive`, by a name pattern such as `*-brute`, by a whole
directory, or by `-sC` or `-A`. A brute-force script left out this way is
named in a warning, so you know it was skipped and how to run it. This is
a FeroProbe safeguard; nmap runs brute-force scripts from any matching
selection. (With [ICS protection](#settings-files-and-ics-protection) on,
`--script` is refused altogether unless you pass
`--override-ics-protection`.)

Brute-force scripts take their user names and passwords from word lists.
FeroProbe ships none of nmap's lists, so a list is read only from a file
you name in `--script-args` or from an installed nmap's own lists:

- `userdb=<file>` and `passdb=<file>` give the user-name and password
  files (one entry per line; `#` comments and blank lines are skipped);
- `brute.credfile=<file>` gives a file of `user:pass` pairs, one per line;
- without any of these, FeroProbe looks for nmap's `usernames.lst` and
  `passwords.lst` in its data directories (`$NMAPDIR` and the usual
  installed-nmap locations). If none is found the list is empty and the
  script finds nothing.

Other `brute.*` and `unpwdb.*` arguments nmap takes are accepted too, for
example `brute.mode` (`user`, `pass` or `creds`), `brute.firstonly`,
`brute.useraspass`, `brute.emptypass`, `brute.guesses`, `brute.delay`,
`unpwdb.userlimit`, `unpwdb.passlimit` and `unpwdb.timelimit`. FeroProbe
makes its guesses one at a time, so `brute.threads` and the scripts'
thread settings are accepted but have no effect — another documented
difference from nmap, which guesses in parallel.

#### `--script-args <args>`

Arguments for the scripts, in nmap's syntax: comma-separated `name=value`
pairs and bare names (flags), where a value is a word, a quoted string
(`"a,b"` or `'a,b'`, with `\` escaping the next character) or a `{...}`
table of the same:

```sh
feroprobe --script banner --script-args 'banner.timeout=2000,banner.length=80' 192.0.2.10
feroprobe --script mine.lua --script-args 'paths={/,/admin},user=admin,unsafe' 192.0.2.10
```

Names are usually prefixed with the script's name, as above. A later name
replaces an earlier one. Arguments that do not parse stop the run. A
script reads them with `fero.args.get` (see [Writing scripts](#writing-scripts)).

#### `--script-args-file <file>`

Read script arguments from a file, in the same syntax, where newlines
separate arguments as commas do. Trailing commas are ignored. Arguments
given with `--script-args` are added after the file's, so they win.

#### `--script-help <scripts>`

Print each chosen script's name, categories, origin (built into FeroProbe,
or the file it came from) and description, then stop. `<scripts>` is read
as for `--script`. It needs no target, sends nothing and is never refused
by ICS protection.

```
$ feroprobe --script-help banner

banner
Categories: discovery safe
Built into FeroProbe
  Shows the first line of text a TCP service sends when a connection
  opens, ...
```

#### `--script-trace`

Print everything the scripts' connections do on standard output, one line
each, in nmap's script-trace layout: the protocol, the local and remote
ends, `>` towards the target or `<` from it, and after the `|` either an
event (`CONNECT`, `CLOSE`, `EOF`, `TIMEOUT` or the error) or the data
sent or received.

```
LUA: TCP 192.0.2.1:40312 > 192.0.2.10:21 | CONNECT
LUA: TCP 192.0.2.1:40312 < 192.0.2.10:21 | 220 (vsFTPd 3.0.5)\r\n
LUA: TCP 192.0.2.1:40312 > 192.0.2.10:21 | USER anonymous\r\n
LUA: TCP 192.0.2.1:40312 > 192.0.2.10:21 | CLOSE
```

Data that is mostly text (at most 5% of its bytes unprintable, as nmap
decides) is shown on one line, with line ends and tabs as `\r`, `\n`,
`\t`, a backslash as `\\` and other bytes as `\xHH`. Other data is shown
as a hex dump, sixteen bytes a line with their printable characters.
Connections that speak TLS show the data inside the TLS, as nmap's do.
The HTTP library's connections are traced too. The prefix is `LUA:`
(nmap's is `NSE:`, the name of its engine); the rest of the line is in
nmap's layout.

[`--packet-trace`](#--packet-trace) turns the script trace on as well, as
in nmap (and the `p` key while a scan runs turns both on and off).
Without `--script` or `-sC` the option does nothing, and a warning says
so.

#### `--script-updatedb`

Index the scripts in your scripts directory by category, then stop. It
needs no target and sends nothing.

The scripts directory is `$XDG_DATA_HOME/feroprobe/scripts`, which is
`~/.local/share/feroprobe/scripts` when `XDG_DATA_HOME` is not set (on
Windows, `%APPDATA%\feroprobe\scripts`). Put your own `.lua` scripts
(and `.nse` scripts written for nmap) there, then run:

```
$ feroprobe --script-updatedb
Updating the script database in /home/me/.local/share/feroprobe/scripts.
Script database updated: 2 scripts.
```

Each script is loaded in the sandbox (as when it runs, with no network)
to read its categories, and the result is written to `script.db` in that
directory, one line per script, in nmap's layout:

```
Entry { filename = "my-check.lua", categories = { "discovery", "safe", } }
```

From then on `--script` and `-sC` choose those scripts by category and
expression as well as by name: a script of yours in `default` runs with
`-sC`, as in nmap. A script added or whose categories changed is chosen by
category only after the next `--script-updatedb`; by name it is found at
once. A script that does not load, or that has a built-in script's name,
is left out of the index with a warning (give its path to `--script` to
run it anyway). A `script.db` that FeroProbe cannot read stops the run
with a message naming the fix, and one that lists a script that has gone
does too. FeroProbe reads the index as data and never runs it.

Under `sudo`, FeroProbe gives up root for the user who ran `sudo` (see
[Privileges and platforms](#privileges-and-platforms)), and uses that user's scripts directory, so
`sudo feroprobe --script-updatedb` and `sudo feroprobe -sC ...` see your
own scripts. With `--keep-root`, or as root without `sudo`, it is root's.
nmap uses the `~/.nmap` of whoever it runs as.

#### `--script-timeout <time>`

The longest one script may run against one host or port, counted from its
start. A script that runs longer is stopped, and gives no output, as in
nmap; `-d` names it. `0` means no limit. By default the limit is ten
minutes at every timing. nmap has none by default and sets ten minutes only
with `-T5`; FeroProbe always sets one, so a server that answers very slowly
(a byte at a time, say) cannot hold a script for hours.

### Script sandbox and scope

Every script runs in its own Lua state with:

- Lua's `string`, `table`, `math`, `utf8` and `coroutine` libraries, the
  basic functions, `os.time`, `os.clock`, `os.date` and `os.difftime`, and
  FeroProbe's `fero` library;
- no `io`, no other `os` functions (no commands, environment, files or
  exit), no `package`, `debug`, `dofile`, `loadfile` or
  `collectgarbage`, no `string.dump`, and `load` for source text only,
  never precompiled bytecode;
- `require` only for the modules of the [NSE compatibility
  layer](#nse-compatibility-layer) and Lua's own libraries by name (an
  NSE script also gets the layer's read-only `io`, which reads only
  data files and files named in `--script-args`);
- 64 MB of memory, and about a billion Lua instructions (some seconds of
  pure computation; time spent waiting on the network does not count);
- for rules, ten seconds (or `--script-timeout`, if shorter); for loading a
  script, two seconds;
- at most 32 sockets open at once.

When a limit is reached the script is stopped, and `pcall`, `xpcall` and
`coroutine.resume` pass that error on rather than catching it, so a
script cannot carry on past it.

Lua's pattern functions (`string.find`, `string.match`, `string.gmatch`
and `string.gsub`) are FeroProbe's own, not Lua's: Lua runs each of them
as a single step that no limit can interrupt, so a pattern that
backtracks heavily over a long text could hold a script far past its
timeout. FeroProbe's versions count every matching step against the
instruction limit and check the deadline as they go, and the result of
`string.gsub` may grow no larger than the memory limit. They take the
same arguments, give the same results and raise the same errors as
Lua 5.4's, with the same limits (32 captures, nesting 200 deep).

**Scope.** The engine checks every connection, rather than trusting the
script. A script running against a host may connect only to that host
(its address, the name it was given on the command line or its reverse
DNS name; no name is looked up) and only to a port of the same protocol
that the scan probed on it, in any state. Only TCP sockets (plain or
TLS) and UDP sockets exist. The HTTP library goes through the same check,
and follows a redirect only when it points inside the scope; one that
points elsewhere is not followed and is returned to the script as it
came. Scripts with a `prerule` or `postrule`, which run without a host,
have no other network access, so nothing broadcasts. Every script may
also reach the run's DNS servers on their DNS port (TCP and UDP): the
`--dns-servers` you gave (unless `--system-dns`), else the `nameserver`
lines of /etc/resolv.conf. `nmap.get_dns_servers()` lists them, and
the `dns` module asks the first when a script names no server. A DNS
server the script finds by itself (a zone's name servers, say) is
refused unless it is the scanned host. A connection the
script asks for outside the scope fails, quietly by default: the refusal
is the scope working as meant. With `-v`, FeroProbe counts the refusals
and, when the scripts of a phase are done, prints one warning per script
and reason, with how many connections were refused, on which host and
which ports the script tried:

```
Warning: script ntp-info: 28 connections refused on 192.168.1.159, UDP not scanned (it tried 14 udp ports: 21, 22, 110, 143, 465, 587, 993, 995, 6 more); -vv shows each
```

This matters most for scripts forced with `+`, which run on every port
whatever their rule says: a UDP script forced onto a TCP-only scan tries
(and is refused) on each open TCP port. With `-vv` or `-d` each refusal
is also printed as it happens, naming the address and port. A wider scope may
come later as an explicit option.

### Writing scripts

A script is a `.lua` file that sets these globals (the names are nmap's,
so the shape is familiar):

| Field | |
| --- | --- |
| `description` | What the script does; `--script-help` prints it |
| `categories` | A list of categories, such as `{"discovery", "safe"}` (required) |
| `author`, `license` | Optional: a string or list of strings, and a string |
| `dependencies` | Optional: names of scripts that must finish first when they are chosen too |
| `prerule()` | Runs the script once before the scan if it returns true |
| `hostrule(host)` | Runs the script against `host` if it returns true |
| `portrule(host, port)` | Runs the script against `port` if it returns true; asked for every port that is `open`, `open\|filtered` or `unfiltered` |
| `postrule()` | Runs the script once after the scan if it returns true |
| `action(host, port)` | The work; `host` and `port` as for its rule (none for pre- and postrule) |

At least one rule and `action` are required. Rules cannot use sockets.
While a script runs, `SCRIPT_NAME` holds its name and `SCRIPT_TYPE` the
rule it runs under (`"prerule"`, `"hostrule"`, `"portrule"`, `"postrule"`).

**The host table:** `ip` (the address as text), `name` (its reverse DNS
name, or `""`), `targetname` (the name given on the command line, if
any), `mac_addr` (if known) and `os` (the names of the OS matches, best
first, with `-O`).

**The port table:** `number`, `protocol` (`"tcp"`, `"udp"`, ...), `state`
(`"open"`, ...), `reason`, `service` (the service name) and `version`, a
table with `name`, `product`, `version`, `extrainfo`, `hostname`, `ostype`,
`devicetype`, `service_tunnel` (`"ssl"` or `"none"`) and `cpe` (a list), as
far as `-sV` found them.

**The `fero` library:**

| Call | |
| --- | --- |
| `fero.socket.new()` | A new socket |
| `sock:connect(host, port [, proto])` | Connect to `host` (a host table or an address) on `port` (a port table or a number), over `"tcp"` (default, or the port table's protocol), `"udp"`, or `"ssl"` for TLS over TCP. Returns `true`, or `false` and a message |
| `sock:reconnect_ssl()` | Start TLS on a connected TCP socket, as after a STARTTLS exchange. Returns `true`, or `false` and a message |
| `sock:get_ssl_certificate()` | The server's certificate as a table (see [TLS](#script-tls-and-http)), or `false` and a message |
| `sock:get_tls_info()` | The session's `version` (`"TLSv1.2"`, `"TLSv1.3"`), `cipher` (its IANA name) and `alpn` |
| `sock:get_info()` | `true`, the local address and port, and the remote address and port |
| `sock:send(data)` | Send. Returns `true`, or `false` and a message |
| `sock:receive()` | Whatever arrives next. Returns `true` and the data, or `false` and `"TIMEOUT"`, `"EOF"` or another message |
| `sock:receive_bytes(n)`, `sock:receive_lines(n)` | Wait for at least `n` bytes or `n` lines; returns all data read. What arrived before a timeout or the end of the connection is returned too |
| `sock:receive_buf(delimiter, keep)` | The data up to the first match of `delimiter`, a Lua pattern (such as `"\r?\n"`) or a function that is given the buffered data and returns where its delimiter starts and ends, as `string.find` does; with the delimiter when `keep` is true. What follows stays buffered for the next receive call. Without a match before a timeout, the end of the connection or 16 MiB, returns `false` and the message, and keeps what arrived for the next call |
| `sock:set_timeout(ms)` | How long each call waits (default 30 seconds) |
| `sock:close()` | Close the socket (also done when the script ends) |
| `fero.args.get(name, ...)` | The `--script-args` values of the given names, one per name; an item may be a list of names, the first found wins. A name given as a bare flag returns `true`; `"script.arg"` falls back to `"arg"`, as in nmap |
| `fero.args.table` | All the arguments, as a table |
| `fero.http.get(host, port, path [, options])` | An HTTP GET; returns the response table, or `nil` and a message (see [HTTP](#script-tls-and-http)) |
| `fero.http.head(host, port, path [, options])` | The same with HEAD |
| `fero.http.post(host, port, path, options, content)` | A POST of `content`: a string, or a table sent form-encoded |
| `fero.http.request(method, host, port, path [, options])` | Any method |
| `fero.http.USER_AGENT` | The `User-Agent` requests send by default |
| `fero.portrule.match(ports, services [, protos [, states]])` | A port rule: true for a port whose number is in `ports` or whose service is in `services` (a value or a list each), of a protocol in `protos` (default `"tcp"`) and a state in `states` (default `open` and `open\|filtered`) |
| `fero.portrule.http`, `fero.portrule.ssl` | Ready-made port rules for web ports and for TLS ports (TLS found by `-sV`, or a TLS service name or port number) |
| `fero.base64.encode(s)`, `fero.base64.decode(s)` | Base64 (decode gives `nil` for text that is not base64) |
| `fero.get_port_state(host, port)` | The port table of a scanned port that may be open (`port` gives `number`, and `protocol`, default `"tcp"`), else `nil`; for a hostrule script to find its service. Closed and filtered ports are `nil` |
| `fero.smb.port(host)` | The port to reach SMB on. With `--script-args smbport=N`, that port only (`nil` when it is not open; 445 and 139 are not tried). Without it, 445 if open, else 139, else `nil` |
| `fero.smb.negotiate(host, port [, timeout [, dialects]])` | One SMB2 NEGOTIATE exchange (the `dialects` given, default all of `fero.smb.dialects()`, 2.0.2 to 3.1.1; on 139 or a `netbios-ssn` port after a NetBIOS session request): a table with `dialect` (`0x0311`...), `security_mode`, `capabilities`, `server_guid`, `time` and `start_time` (Unix seconds, `start_time` `nil` when not given), or `nil` and a message. Logs in to nothing; `fero.smb.dialect_name(d)` writes a dialect as nmap does (`3:1:1`, `2:1:0`, `3:0:0`) |
| `fero.smb.negotiate_v1(host, port [, timeout [, extended]])` | One SMB1 NEGOTIATE offering only `NT LM 0.12` (as nmap does), with extended security when `extended` is true: a table with `dialect`, `security_mode` (1 user level, 2 challenge/response, 4 signing enabled, 8 signing required), `capabilities`, `time` (Unix seconds, `nil` when not given), `timezone` (seconds east of UTC), `extended`, and without extended security `domain` and `server`; or `nil` and a message (`SMB1 not supported` when the server answers in SMB2 or takes no dialect). Logs in to nothing |
| `fero.smb.os_info(host, port [, timeout])` | What an SMB1 server says about itself, as nmap's `smb.get_os` gathers it, over two connections: a plain NEGOTIATE (clock, time zone, domain or workgroup, name), then one with extended security and the first leg of a session setup carrying FeroProbe's NTLM NEGOTIATE (the server's NativeOS and NativeLanMan, and the names in its NTLM challenge). The challenge is never answered, so nothing logs in. A table with `os`, `lanmanager`, `server`, `domain`, `workgroup` (set, and `domain` `nil`, for a workgroup host), `fqdn`, `domain_dns`, `forest_dns`, `time` and `timezone`, each when known; `nil` and a message when the server gives no OS details |
| `fero.smb.list_dialects(host, port [, timeout])` | The dialects the server takes, as nmap's `smb-protocols` tries them (NT LM 0.12 alone, all SMB2/SMB3 dialects together, then each older one alone, one connection each): a list of names (`"NT LM 0.12"`, `"2:0:2"` ... `"3:1:1"`), empty when it takes none |
| `fero.ntlm.negotiate_message()`, `fero.ntlm.negotiate_base64()` | An NTLM NEGOTIATE message, raw or in base64, for a script to wrap in its protocol: no domain, the workstation `FEROPROBE` (FeroProbe's mark, IDS rules 9100016 and 9100017), the same 49 bytes every time |
| `fero.ntlm.info(data [, opts])` | What an NTLM CHALLENGE found in `data` says, as the `*-ntlm-info` scripts show it: an ordered table with `Target_Name`, `NetBIOS_Domain_Name`, `NetBIOS_Computer_Name`, `DNS_Domain_Name`, `DNS_Computer_Name`, `DNS_Tree_Name` and `Product_Version` (each when given and not empty), and `System_Time` with `opts.system_time`. Notes the server's clock for `clock-skew`. `nil` when there is no challenge |
| `fero.ntlm.parse_challenge(data)` | Finds the NTLM CHALLENGE in `data` (it may be wrapped, as in CredSSP or SPNEGO) and reads it: `target_name`, `netbios_computer`, `netbios_domain`, `dns_computer`, `dns_domain`, `dns_tree`, `timestamp` (Unix seconds), `version` (`"10.0.14393"`) and `flags`, each when the server gives it; or `nil` and a message |
| `fero.ssh.connect(host, port [, timeout])` | Connects, reads the server's version line (lines before it are skipped) and sends FeroProbe's, `SSH-2.0-FeroProbe_Scripting_Engine` (IDS rule 9100007). Returns the socket, a `fero.reader` on it and the server's version line; or `nil` and a message when the server is not SSH 2.0 or 1.99. `timeout` in ms, default 10000 |
| `fero.ssh.kexinit(lists)`, `fero.ssh.packet(payload)` | A KEXINIT payload from `lists` (a name-list, as an array or a comma-separated string, under each RFC 4253 name in `fero.ssh.KEXINIT_LISTS`; a missing one is empty; random cookie), and an unencrypted SSH packet around a payload |
| `fero.ssh.read_kexinit(reader)`, `fero.ssh.parse_kexinit(payload)` | Reads packets until the server's KEXINIT (skipping IGNORE, DEBUG and UNIMPLEMENTED) and parses it: a table with each name-list as an array under its RFC 4253 name (`kex_algorithms`, `server_host_key_algorithms`, `encryption_algorithms_client_to_server`, ...) and `first_kex_packet_follows`; or `nil` and a message. `fero.ssh.read_packet(reader)` reads one packet's payload |
| `fero.ssh.host_key(host, port, algs [, timeout])`, `fero.ssh.key_bits(blob)` | Connects and reads the server's host key for the first of the host key algorithms `algs` it offers, from its key exchange reply (curve25519 or finite-field Diffie-Hellman; nothing logs in): the key blob; or `nil` and the server's host key algorithms when it offers none of `algs`; or `nil`, `nil` and a message. `key_bits` gives a key blob's size in bits and its type (`ssh-rsa`, `ssh-dss`, `ecdsa-sha2-*`, `ssh-ed25519`) |
| `fero.starttls.protocol(port)` | The protocol a TCP port switches to TLS with: by its service name, else its number, as nmap's table: `smtp` (25, `submission` 587), `lmtp`, `imap` (143), `pop3` (110), `nntp` (119), `ftp` (21, AUTH TLS), `ldap` (389, the StartTLS extended operation), `postgresql` (5432, SSLRequest), `xmpp` (5222, and `xmpp-server` 5269); `nil` for others |
| `fero.starttls.connect(host, port [, opts])` | Connects, asks the server to switch to TLS as its protocol does, and returns the socket speaking TLS (an SMTP server then wants EHLO again), or `nil` and a message (the connection closed). SMTP and LMTP say `EHLO`/`LHLO feroprobe.invalid` first (`opts.domain`, else `smtp.domain`, replaces the name); IMAP asks for CAPABILITY and switches only when STARTTLS is listed; XMPP opens a stream to the target's name. `opts.timeout` (ms, default 10000) bounds each wait, `opts.protocol` names the protocol instead of the port, `opts.plain` returns the socket once the server agreed, before any TLS (for a script that sends its own hello, as `fero.tls` does). Only the port asked for is contacted |
| `fero.tls.hello(host, port [, opts])` | Connects (after the protocol's STARTTLS request when `opts.starttls` names one, see `fero.starttls.protocol`), sends one ClientHello built by `fero.tls.client_hello(opts)` and reads the server's first flight with `fero.tls.read_answer`; closes and returns the answer, or `nil` and a message. Nothing is ever encrypted or finished: the scripts that use it only ask what the server would choose |
| `fero.tls.client_hello(opts)` | A ClientHello in one record: `version` (`0x0300` SSLv3 to `0x0304` TLS 1.3, default `0x0303`; TLS 1.3 is asked through `supported_versions`, with a random x25519 key share when x25519 is among the groups, else none), `ciphers` (codes or names; default the TLS 1.3 suites for TLS 1.3, every other suite otherwise), `compressors` (default `{0}`), `server_name` (SNI; `fero.tls.hello` uses the host's name, never an address), `alpn` (protocol names), `npn` (`true`), `groups`, `extensions` (`{type, data}` pairs). SSLv3 hellos carry no extensions. Its random holds `FeroProbeTLSScan` after the four time bytes (IDS rule 9100019) |
| `fero.tls.read_answer(sock [, opts])` | Reads a server's answer to a ClientHello until ServerHelloDone, an alert, a TLS 1.3 ServerHello or, with `opts.hello_only`, the ServerHello, all within `opts.timeout` ms (default 5000) however slowly the bytes come, and at most 256 KiB: `server_hello` (`version`, `cipher`, `compressor`, `extensions` by type, `hrr`, `group`, `alpn`, `npn`), `certificates` (DER, the server's first), `server_key_exchange`, `done`, `alert` (`level`, `code`, `name`) |
| `fero.tls.cipher_name(code)`, `fero.tls.cipher_code(name)`, `fero.tls.cipher_info(name)` | The IANA cipher suites (`fero.tls.CIPHERS`; TLS 1.3 ones named as nmap does, `TLS_AKE_WITH_AES_128_GCM_SHA256`), and what a name says: `kex`, `cipher`, `size`, `mode`, `block`, `hash`, `export`, `anon`, `forward_secrecy`, `tls12`, `tls13` |
| `fero.tls.group_name(code)`, `fero.tls.group_strength(name)`, `fero.tls.ec_strength(bits)`, `fero.tls.parse_server_key_exchange(msg, info)` | Named groups as nmap names them (`secp256r1`, `ecdh_x25519`, `ffdhe2048`), their strength in RSA bits (NIST SP 800-57), and what a ServerKeyExchange says (`{type = "ec", group = ...}`, `{type = "dh", bits = ...}`, `{type = "rsa", bits = ...}`) |
| `fero.tls.parse_certificate(der)` | A certificate as `sock:get_ssl_certificate()` gives it (see [Script TLS and HTTP](#script-tls-and-http)), or `nil` |
| `fero.tls.sslv2_client_hello()`, `fero.tls.sslv2_read_server_hello(sock [, timeout])` | An SSLv2 CLIENT-HELLO offering every SSLv2 cipher kind, with `FeroProbeTLSScan` as its challenge (IDS rule 9100020), and the SERVER-HELLO read: `version`, `certificate`, `ciphers` (nmap's names, `SSL2_RC4_128_WITH_MD5`...) |
| `fero.snmp.session(host, port [, opts])` | An SNMP session over UDP with a scanned port: `s:get(oid, ...)` (GetRequest), `s:getnext(oid)` (GetNextRequest), `s:walk(base [, max])` (the variables under `base`, one GetNextRequest at a time, at most 65,536), `s:discover()` (the SNMPv3 engine discovery request: `engine_id`, `boots`, `time`), `s:close()`. Answers are tables (`version`, `community`, `request_id`, `error_status`, `error_index`, `varbinds`, each with `oid`, `tag`, `value` and `exception`); an answer counts only when it carries FeroProbe's request-id `0x4650` ("FP", IDS rule 9100021), the version and community asked with and, for GetRequest, the variables asked for, for GetNextRequest one that comes after the one asked (so a late answer to an earlier step of a walk is skipped). Options from `--script-args`, as nmap's SNMP library takes them: `creds.snmp` (the community, or nmap's `user:pass` form; default `public`), `snmp.version` (`v1`, the default, or `v2c`), `snmp.timeout` (ms, or with a unit such as `5s`; default 5000), `snmp.retries` (default 1). `fero.snmp.parse(msg)`, `fero.snmp.parse_v3(msg)`, `fero.snmp.compare(a, b)` (OID order), `fero.snmp.format_ticks(t)` (TimeTicks as nmap writes an uptime) |
| `fero.output_table()` | A table for output that keeps its names in the order they are first set (one removed and set again goes last), and `#t` counts its entries, as nmap's `stdnse.output_table`; see Output below |
| `fero.registry.get(name)`, `.set(name, value)`, `.append(name, value)` | Values shared by every script of the run, as nmap's `nmap.registry`; see [The registry](#the-registry) |
| `fero.host_registry.get(name)`, `.set(...)`, `.append(...)` | The same for the host the script runs against, as nmap's `host.registry`; `nil` in prerule and postrule scripts |
| `fero.record_skew(remote [, scanner])` | Notes how far a service's clock (`remote`, Unix seconds) is from the scanner's (`scanner`, default `os.time()`) for `clock-skew`, as nmap's `datetime.record_skew` |
| `fero.format_time(seconds)` | A time span as nmap writes one: `0s`, `5s`, `-1m05s`, `2h03m04s`, `1d02h03m04s` |
| `fero.reader(sock)` | A buffered reader over a connected socket: `r:line()` (one line, without its CR LF), `r:bytes(n)` (exactly `n` bytes) and `r:reply()` (an FTP or SMTP style reply: its code as a number and its lines, following `250-` continuation lines up to `250 `). Each returns `nil` and a message on a timeout, the end of the connection or a line over 64 KiB |
| `fero.crypto.digest(name, data)` | The digest of `data` as raw bytes: `md5`, `sha1`, `sha256`, `sha384` or `sha512` (MD5 and SHA-1 only for fingerprints, as tools still print them) |
| `fero.crypto.random_bytes(n)` | `n` random bytes from the system (at most 65536) |
| `fero.clock_ms()` | Milliseconds on a monotonic clock (from the script's start), for deadlines finer than `os.time()` |
| `fero.mac_vendor(mac)` | The vendor the OUI list (`--oui-file`, else the system's) gives for a MAC address such as `00:0c:29:01:02:03`, or `nil` |
| `fero.sleep(seconds)` | Waits (fractions allowed, at most 600 per call) without holding up other scripts; nmap's `stdnse.sleep` |
| `fero.hex(s [, sep])` | `s` in lower-case hex, with `sep` between bytes if given (`fero.hex(d, ":")`) |
| `fero.verbosity()`, `fero.debugging()` | The `-v` and `-d` levels; `fero.verbosity()` is one higher for a script chosen by name or file path, as `nmap.verbosity()` is |
| `fero.debug(level, message)` | Print `message` with `-d` at `level` or more; `print(...)` prints at level 1 |

**Output.** `action` returns a string, which is the output as it is; a
table, which the report lays out as indented lines (its numbered entries
first, as their value alone, then its named entries as `name: value`, in
name order, or for a table from `fero.output_table()` in the order they
were set) and which XML and JSON keep as structured data; or a table
and a string, the string being the text shown. Returning nothing gives no
output. An error in a rule or action gives no output either; `-d` shows it.

```lua
description = [[Says whether a TCP service greets first.]]
categories = {"safe"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end

action = function(host, port)
  local sock = fero.socket.new()
  sock:set_timeout(tonumber(fero.args.get(SCRIPT_NAME .. ".timeout")) or 3000)
  if not sock:connect(host, port) then return nil end
  local ok, data = sock:receive()
  sock:close()
  return { greets = tostring(ok), bytes = ok and #data or 0 }
end
```

### The registry

Each script run has a Lua state of its own, so scripts leave values for
each other in the registry, which lives outside them all: `set(name,
value)` stores a copy (`nil` removes it), `get(name)` returns a copy (or
`nil`), and `append(name, value)` adds a copy to the end of the list under
`name`, starting the list when there is none, in one step, so scripts that
run at the same time never lose each other's entries. Changing a table
after `set` or `get` changes only the script's own copy; store it again to
share the change. Only plain data is kept: `nil`, booleans, numbers,
strings, and tables of them (keys: numbers, strings or booleans) up to 32
levels deep. A function, a socket or another userdata is refused with an
error, so nothing in the registry can run in another script. All values
together may take 16 MiB.

`fero.registry` is the run's, shared by every script, the prerule and
postrule ones included; `fero.host_registry` is the host's, shared by the
scripts that run against that host. A script that reads what another one
leaves names it in `dependencies`, so that it runs after it when both are
chosen. In nmap the registry is a plain table that scripts change in
place; FeroProbe's is called through these functions, as values are
copied between states. The [NSE compatibility
layer](#nse-compatibility-layer) offers nmap's form on top.

### Script TLS and HTTP

**TLS.** Script TLS (`"ssl"` sockets, `reconnect_ssl`, the HTTP library)
speaks TLS 1.2 and 1.3. It accepts any certificate without checking it,
offers no client certificate, and sends the host's name as SNI when it has
one (the name given on the command line, else its reverse DNS name; never
an address). nmap, through OpenSSL, can also speak older versions, so a
device that only knows SSLv3 to TLS 1.1 answers nmap's scripts but not
FeroProbe's. The scripts built on `fero.tls` (`ssl-enum-ciphers`,
`sslv2`, `tls-alpn`, `tls-nextprotoneg`) are the exception: they send
their own hellos, from SSLv2 and SSLv3 up to TLS 1.3, and read the answer
without finishing a handshake.

`sock:get_ssl_certificate()` returns `subject` and `issuer` (tables of
attribute names such as `commonName`, `organizationName` and
`countryName` to their values), `subject_text` and `issuer_text` (every
attribute in the certificate's order, as `name=value/name=value`),
`serial` (hex), `version`, `sig_algorithm` (such as
`sha256WithRSAEncryption`), `pubkey` (`type`: `rsa`, `ec`, `dsa`,
`ed25519`...; `bits`; `curve` for EC keys), `validity` (`notBefore` and
`notAfter`, as `YYYY-MM-DDTHH:MM:SS` in UTC), `san` (the subject
alternative names, as `DNS:name`, `IP:address`, `email:...`, `URI:...`),
`sha1` and `sha256` (fingerprints in hex), `pem` and `der`.

**HTTP.** `fero.http` speaks HTTP/1.1, one request per connection
(`Connection: close`), and sends a `Host` header (the host's name, else
its address, with the port unless it is 80, or 443 over TLS) and a
`User-Agent` that names FeroProbe:

```
Mozilla/5.0 (compatible; FeroProbe Scripting Engine; https://github.com/jkobierczynski/FeroProbe)
```

This is the script engine's signature (see `docs/responsible-use.md`).
A request goes over TLS or not as the port suggests: TLS when `-sV` found
it, or the service name or port number is a TLS one; if that attempt gets
no HTTP answer, the other is tried, as nmap does. A request carrying
credentials (`Authorization`, `Proxy-Authorization` or `Cookie`) that
started over TLS never falls back to plain text, and a redirect that
leaves TLS for plain text, or goes to another port, drops those headers.
The options table takes:

| Option | |
| --- | --- |
| `header` | A table of extra headers, name to value; a `Host` or `User-Agent` here replaces FeroProbe's |
| `content` | The request body |
| `timeout` | Milliseconds for the whole request, both attempts included; a first attempt gets at most half while a second may follow (default 30000) |
| `ssl` | `true` or `false` to use TLS or not, with no second attempt |
| `redirect_ok` | `false` to follow no redirect, or how many to follow (default 3) |
| `max_body_size` | The most body bytes kept (default 2 MiB, at most 16 MiB) |
| `truncated_ok` | Return a body cut at `max_body_size`; without it a longer body is an error, as in nmap |
| `auth` | `{username = ..., password = ...}` for basic authentication |
| `cookies` | A `Cookie` header, as a string or a table of names to values |
| `user_agent` | Another `User-Agent` |

The response table has `status` (a number), `status-line`, `version`
(`"1.1"`), `header` (names in lower case; a repeated header's values
joined with `, `), `rawheader` (every header line as sent), `cookies`
(one table per `Set-Cookie`, with `name`, `value` and its attributes in
lower case, flags such as `httponly` as `true`), `body`, `ssl` (whether TLS
was used), `truncated`, and `location` (the URLs of the redirects
followed, in order; the response is the last one's). A request that fails
returns `nil` and a message, such as `"TIMEOUT"` or a scope refusal; in
nmap the response table comes back with no `status`. Bodies are not
decompressed; FeroProbe sends no `Accept-Encoding`, so servers send them
plain. A method, path or header value holding a control character (such
as CR or LF) is refused.

Script arguments that apply to every HTTP request, as in nmap:
`http.useragent` (another `User-Agent`), `http.host` (another `Host`
header), `http.max-body-size` and `http.truncated-ok`. A `User-Agent` set
this way, or by the script, replaces the FeroProbe signature: like
`--data`, it is a deliberate choice, and the request carries exactly
what was asked for.

### Script output

In the normal report each script's output follows its port, or comes under
`Host script results:` after the host's other results, `Pre-scan script
results:` before the first host and `Post-scan script results:` after the
last, in nmap's layout: `|_name: output` for one line, and `| ` before
every line but the last for more. Control characters other than tab and
newline are shown as `\xHH`, so a service cannot send terminal escape
sequences through a script. Results are listed by script name. In the
names of a returned table, a backslash is doubled, so a name holding the
byte 0xFF (`\xFF`) stays apart from one holding the text `\xFF`
(`\\xFF`).

The XML report has nmap's elements: `<script id="..." output="...">` in
`<port>`, `<hostscript>` in `<host>`, and `<prescript>` and `<postscript>`
in `<nmaprun>`, with a returned table as nested `<elem key="...">` and
`<table key="...">` elements. The JSON report has a `scripts` list in each
port and host, and `prescript` and `postscript` lists at the top, each
entry with `id`, `output` and, for a table, `data` (an array for a table
with only numbered entries, else an object with the numbered entries under
`"1"`, `"2"`, .... Lua lets `t["1"]` and `t[1]` both exist, so a name made
only of digits and not starting with `0`, or a name that starts with a
double quote, is written in an added pair of double quotes: `t["1"]` as
`"\"1\""`. A bare whole number is then always a numbered entry, a quoted
key a name with the outer quotes removed, and any other key a name as it
is).
At most 100,000 values and 16 MiB of text are kept from one result; the
rest is shown as `...`. The grepable report has no script results, as in
nmap.

A port whose state is folded into the `Not shown` line still gets its own
row when a script gave output for it, in every report, so the output is
not lost; the `Not shown` count leaves it out. nmap drops such output.

### Hosts that scripts add

Some scripts find other hosts: `resolveall` the other addresses of a
name, nmap's `targets-*` and `broadcast-*` scripts the hosts on a link,
traceroute hops or DNS answers. As in nmap, such a script adds them to
the scan only when you ask for it with the `newtargets` script argument:

```
feroprobe -sn --script resolveall --script-args 'newtargets,resolveall.hosts=example.com' 192.0.2.1
```

Without `newtargets` the script only reports what it found. With it, the
added hosts are scanned like the command line's, with the same options,
after them, and scripts that run on them may add more. Each target is
added once per run; `max-newtargets=<n>` caps how many hosts scripts add
in all. Postrule scripts cannot add hosts. An added host that
`--exclude` names is left out, and so is one of an address family the
scan was not planned for (an IPv6 address in a scan of IPv4 targets, or
the other way round), with a warning. NSE scripts use `target.add`
(and `nmap.add_targets`), FeroProbe's own `fero.add_targets`.

### Built-in scripts

The scripts in the `default` category are the ones `-sC` and `-A` run.
Every one is also in `safe`. Each was written for FeroProbe from the
protocol's specification; where one of nmap's scripts has the same name,
FeroProbe's does the same job and lays out its output alike, so reports
compare, with the differences named below.

| Script | Categories | Runs on | What it does |
| --- | --- | --- | --- |
| `banner` | discovery, safe | open TCP ports | Shows the first line the service sends, without sending anything. Arguments: `banner.timeout` (ms, default 5000), `banner.length` (characters, default 200) |
| `clock-skew` | default, safe | hosts where another script noted a clock | Sums up how far the host's clocks are from the scanner's, from what `http-date`, `ntp-info`, the `*-ntlm-info` scripts, `smb-os-discovery`, `smb-security-mode`, `smb2-time` and `ssl-date` saw (it runs after them and sends nothing): the one value when there is one (`5s`), else `mean: ..., deviation: ..., median: ...` (the population standard deviation); XML and JSON have `mean`, `stddev`, `median` and `count` in seconds. After the scan, when two or more hosts had a value, it lists the hosts grouped by their median (`Post-scan script results`). The differences include the time an answer took and the rounding to whole seconds, so `-1s` or `1s` usually means the clocks agree. nmap's also counts services FeroProbe has no scripts for yet (SMB1 and others) |
| `dns-nsid` | default, discovery, safe | 53, `domain` (TCP or UDP) | Asks a DNS server who it is: the name server identifier (NSID, RFC 5001) from an EDNS(0) query for `id.server`, and the CHAOS TXT records `id.server` and `version.bind` (RFC 4892), shown as `NSID: <id> (<hex>)`, `id.server:` and `bind.version:`; only the ones the server gives. At most three small queries to the scanned port, with the recursion-desired (RD) flag set as in nmap's queries: a server that rejects EDNS (FORMERR or NOTIMP) is asked for `id.server` again without it. A reply that carries a question counts only when it is the one asked, and only the TXT record for that name is read; an error reply without a question (FORMERR or NOTIMP) only triggers the retry without EDNS. Over UDP each query is sent twice at most; over TCP with the two-byte length in front, read in two reads at most within the timeout each. The NSID and `id.server` come from the same reply (unless the retry without EDNS was needed); `version.bind` comes from its own query (and, over TCP, its own connection), so behind a load balancer or anycast address it can come from a different server. The transaction ID is `0x4650` ("FP"). Argument: `dns-nsid.timeout` (ms, default 5000) |
| `ftp-anon` | default, auth, safe | 21, `ftp` | Logs in as `anonymous` with the password `feroprobe@` and says whether that is allowed, then quits. Lists no files (nmap's does): a listing needs a data connection to a port the server picks, outside the scan's scope. Argument: `ftp-anon.timeout` (ms, default 8000) |
| `ftp-syst` | default, discovery, safe | 21, `ftp` | Sends SYST and STAT without logging in and shows the answers (many servers answer STAT only after a login; then only SYST is shown). Argument: `ftp-syst.timeout` |
| `http-auth` | default, auth, safe | web ports | One GET; when the page answers 401 Unauthorized, shows the status line and each challenge in its `WWW-Authenticate` header (every header of that name, read as RFC 9110 lays them out): the scheme with its parameters (`Basic realm=Lab`, `Digest realm=lab qop=auth nonce=...`) or its bare token (`Negotiate YIIB...`). XML and JSON: one table per challenge, with `scheme`, and `params` or `token68`. Sends no credentials. Argument: `http-auth.path` (default `/`) |
| `http-cookie-flags` | default, safe, vuln | web ports | One GET without following a redirect, and when the answer is a redirect a second GET that follows it (within scope), so a cookie set by the redirect itself is checked too (nmap's sees only the final page's); for each session cookie set (named as sessions commonly are: `PHPSESSID`, `JSESSIONID`, `ASP.NET_SessionId`, `session`, any `session...id`, ...), says `httponly flag not set` when it lacks HttpOnly and, when the answer came over TLS, `secure flag not set and HTTPS in use` when it lacks Secure. nmap's checks Secure only when the port's service is named `https`, so it misses TLS found by `-sV` (`ssl/http`); FeroProbe's goes by the connection. nmap's also checks the pages `http-enum` found; FeroProbe has no `http-enum`. Arguments: `http-cookie-flags.path` (default `/`), `http-cookie-flags.cookie` (check only this cookie name) |
| `http-cors` | default, discovery, safe | web ports | Sends one CORS preflight (OPTIONS with `Origin` and `Access-Control-Request-Method`) for each of HEAD, GET, POST, PUT, DELETE, TRACE, OPTIONS, CONNECT and PATCH, and lists the methods whose successful (2xx) answer allows both the origin (`*` or exactly the origin named) and the method (by name or `*`), as the Fetch standard's CORS check does. Tries no method. nmap's counts an origin as allowed only when the answer says `*` (it compares the answer with the wrong value) and asks about `/` whatever `http-cors.path` says; FeroProbe's also counts the origin named, and asks about the path given. Arguments: `http-cors.path` (default `/`), `http-cors.origin` (default `example.com`, as nmap's) |
| `http-date` | discovery, safe | web ports | One GET of the front page; shows its `Date` header and how far it is from the scanner's clock, as `Wed, 19 Nov 2026 03:00:05 GMT; +5s from local time.` (XML and JSON: `date` in ISO form and `delta` in seconds), and notes the difference for `clock-skew`. Reads all three HTTP-date forms. Follows no redirect. Not in `default`, as in nmap |
| `http-favicon` | default, discovery, safe | web ports | Fetches the icon the front page names in a `<link rel="icon">` (only when it is on the scanned host and port), else `/favicon.ico`, and shows `Unknown favicon MD5: ...` with `-v` (or when chosen by name, which counts as one `-v`, as in nmap). nmap names the application from its icon database and shows the MD5 of an unknown icon only with `-v`; FeroProbe has no icon database (nmap's cannot be redistributed), so every icon is unknown and nothing is shown without `-v` unless the script was chosen by name. Three GETs at most. Arguments (nmap's names): `favicon.uri` (the icon's path, no search), `favicon.root` (a path before the others) |
| `http-generator` | default, discovery, safe | web ports | One GET (following up to 3 redirects within scope); shows the `content` of the page's `<meta name="generator">` tag, where content management systems name themselves and often their version. Reads the tag's attributes in any order and quoting; nmap's matches only `name` before `content`. Arguments: `http-generator.path` (default `/`), `http-generator.redirects` (default 3) |
| `http-git` | default, safe, vuln | web ports | Asks for `/.git/HEAD`; when that holds a Git reference, reads `.gitignore`, `.git/COMMIT_EDITMSG`, `.git/config`, `.git/description` and `.git/info/exclude` (seven GETs at most per root, no Git object; a redirect or an HTML page is not counted as the file, nor a `.git/config` without a `[section]` line, and when the site answers `.git/feroprobe-no-such-file` (asked for once) with a 200 only `.git/config` is counted, so a site that answers every path with its own page is not taken for a repository, and HEAD must be a whole `ref: refs/...` line or object name) and shows `Git repository found!` (or `Potential Git repository found` when three or more are missing), which files contain the words `bug`, `key`, `passw`, `pw`, `user`, `secret` or `uid`, the description and last commit message (60 characters), the remote URLs from the `[remote]` sections of `.git/config` (with any user name and password in them left out of the report; nmap's shows them as found and also lists submodule URLs), and the kind of project the ignore files suggest, as nmap's. One request at a time (nmap pipelines them). Argument: `http-git.root` (default `/`; a list `{/,/app/}` tries each) |
| `http-headers` | discovery, safe | web ports | Lists the headers of the front page's answer as they came, then the request used: HEAD, or GET when HEAD gets an error status or no answer. Follows no redirect. Not in `default`, as in nmap. Arguments: `http-headers.path` (default `/`), `http-headers.useget` (GET straight away) |
| `http-methods` | default, safe | web ports | Sends one OPTIONS request and lists the methods in the `Allow` header, repeating those beyond GET, HEAD, POST and OPTIONS as potentially risky. Tries no method. Argument: `http-methods.url-path` (default `/`) |
| `http-ntlm-info` | default, discovery, safe | web ports | One GET with `Authorization: NTLM` and the NEGOTIATE in base64; reads the challenge from the `WWW-Authenticate` header of the 401 answer. Shows what the server's NTLM CHALLENGE says: target name, NetBIOS and DNS domain and computer names, DNS tree name and product version, in nmap's order and labels (see `fero.ntlm.info`); the server's clock is noted for `clock-skew`. The NTLM NEGOTIATE names no user and the workstation `FEROPROBE`; nothing logs in. A server that offers no NTLM gives no output. Argument: `http-ntlm-info.root` (default `/`, a path that asks for authentication) |
| `http-robots.txt` | default, discovery, safe | web ports | Fetches `/robots.txt` and lists its `Disallow` paths (at most 100) |
| `http-server-header` | discovery, safe, version | web ports | One GET of the front page; shows each different `Server` header value (the software the server names), or nothing when there is none. Follows no redirect. nmap runs its `version` scripts with every `-sV` and lets this one fill in an empty version column; FeroProbe runs it only when chosen (`--script http-server-header` or `--script version`) and leaves the version column to `-sV` |
| `http-title` | default, discovery, safe | web ports | Fetches a web server's front page and shows its title, following redirects within scope (and saying where the page came from), or where a redirect it did not follow points. Argument: `http-title.path` (default `/`) |
| `http-webdav-scan` | default, discovery, safe | web ports | One OPTIONS: a successful (2xx) answer whose `DAV` header lists class 1 marks WebDAV, and the allowed methods (`Allow`, `Public`), `Server`, `Date` and the WebDAV type (Apache DAV, SharePoint DAV or unknown) are shown. Then one PROPFIND (`Depth: 1`, no body); a 207 Multi-Status document in the `DAV:` namespace also marks WebDAV, and the resource each response names (100 at most; not hrefs inside properties, such as a lock root) and any private IPv4 addresses in it are listed. Nothing is created or changed. nmap's accepts the Multi-Status only with the `D:` prefix and a literal `HTTP/1.1 200 OK` property status, lists every href, and never sees SharePoint's `X-MSDAVEXT` header (it looks for it in upper case); FeroProbe's takes any prefix and finds the header. Argument: `http-webdav-scan.path` (default `/`) |
| `imap-ntlm-info` | default, discovery, safe | 143, 993, `imap`, `imaps` | Switches to TLS with STARTTLS when the server lists it (else starts again in plain text), sends `AUTHENTICATE NTLM` and the NEGOTIATE, then cancels the exchange (`*`) and logs out. Shows what the server's NTLM CHALLENGE says: target name, NetBIOS and DNS domain and computer names, DNS tree name and product version, in nmap's order and labels (see `fero.ntlm.info`); the server's clock is noted for `clock-skew`. The NTLM NEGOTIATE names no user and the workstation `FEROPROBE`; nothing logs in. Over TLS from the start on 993 and when `-sV` found TLS. Argument: `imap-ntlm-info.timeout` (ms, default 10000) |
| `imap-capabilities` | default, safe | 143, 993, `imap`, `imaps` | Sends CAPABILITY and lists the answer; logs in to nothing. Over TLS on 993 and when `-sV` found TLS |
| `ms-sql-ntlm-info` | default, discovery, safe | 1433, `ms-sql-s` | Sends one TDS 7.1 LOGIN7 packet asking for Windows (integrated) authentication, with the NEGOTIATE as its security data, host name `FEROPROBE` and application name `FeroProbe Scripting Engine`, and reads the SSPI answer. Shows what the server's NTLM CHALLENGE says: target name, NetBIOS and DNS domain and computer names, DNS tree name and product version, in nmap's order and labels (see `fero.ntlm.info`); the server's clock is noted for `clock-skew`. The NTLM NEGOTIATE names no user and the workstation `FEROPROBE`; nothing logs in. The output is listed under the instance, `address:port`, as nmap's. nmap's first asks the SQL Server Browser on UDP 1434 for other instances, even when 1434 was not scanned; FeroProbe's asks only the TCP port the scan found. Argument: `ms-sql-ntlm-info.timeout` (ms, default 10000) |
| `mysql-info` | default, discovery, safe | 3306, `mysql` | Reads the server's greeting: protocol, version, thread ID, capability flags and names, status, salt and authentication plugin, or the error a server that refuses the connection gives. Sends nothing |
| `nbstat` | default, discovery, safe | hosts where UDP 137 (or the `nbstat.port` port) was scanned and is open, open\|filtered or unfiltered | One NetBIOS NODE STATUS request (as `nbtstat -A`, RFC 1002), sent twice at most: the host's NetBIOS name, the logged-in user when the name table has one, and the MAC address the host reports with its vendor from the OUI list (`<unknown>`, and no `mac` in XML/JSON, for the all-zero MAC Samba gives); a `<03>` name the machine also holds as a unique `<00>` or `<20>` name (its own name or an alias) is not taken for a user; with `-v` the whole name table and its flags. The transaction ID is `0x4650` ("FP"). nmap's also runs when only TCP 139 or 445 is open and then sends to UDP 137 anyway; FeroProbe's runs only when its port (UDP 137, or `nbstat.port`) was scanned (`-sU -p U:137`), as nothing goes to ports outside the scan. nmap's shows the name table's statistics with `-vv`; FeroProbe's does not. Arguments: `nbstat.port` (default 137, must be scanned), `nbstat.timeout` (ms, default 5000) |
| `nntp-ntlm-info` | default, discovery, safe | 119, 433, 563, `nntp`, `snews` | Switches to TLS with STARTTLS where the server allows it (else starts again in plain text), sends `AUTHINFO GENERIC NTLM` and then the NEGOTIATE, and says QUIT. Shows what the server's NTLM CHALLENGE says: target name, NetBIOS and DNS domain and computer names, DNS tree name and product version, in nmap's order and labels (see `fero.ntlm.info`); the server's clock is noted for `clock-skew`. The NTLM NEGOTIATE names no user and the workstation `FEROPROBE`; nothing logs in. Over TLS from the start on 563 and when `-sV` found TLS. Argument: `nntp-ntlm-info.timeout` (ms, default 10000) |
| `ntp-info` | default, discovery, safe | 123/udp, `ntp` | One NTP client request (the server's receive time) and one control-message READVAR request (version, system, stratum, reference ID and the other system variables, which many servers refuse). The receive time is noted for `clock-skew`. Not the `monlist` request used for amplification |
| `pop3-capabilities` | default, discovery, safe | 110, 995, `pop3`, `pop3s` | Sends CAPA and lists the capabilities, with their arguments in parentheses, plus APOP when the greeting offers it; logs in to nothing |
| `pop3-ntlm-info` | default, discovery, safe | 110, 995, `pop3`, `pop3s` | Switches to TLS with STLS where the server allows it (else starts again in plain text), sends `AUTH NTLM` and the NEGOTIATE, then cancels the exchange (`*`) and says QUIT. Shows what the server's NTLM CHALLENGE says: target name, NetBIOS and DNS domain and computer names, DNS tree name and product version, in nmap's order and labels (see `fero.ntlm.info`); the server's clock is noted for `clock-skew`. The NTLM NEGOTIATE names no user and the workstation `FEROPROBE`; nothing logs in. Over TLS from the start on 995 and when `-sV` found TLS. Argument: `pop3-ntlm-info.timeout` (ms, default 10000) |
| `resolveall` | discovery, safe | before the scan, the names in `resolveall.hosts`; each target given by name | Resolves names to all their addresses of the scan's family (IPv4, or IPv6 with `-6`) and lists them (`Host 'example.com' resolves to:`); on a target given by name, the addresses other than the one scanned (`also resolves to`). With `newtargets` it adds them to the scan (`Successfully added 2 new targets`), else says `Use the 'newtargets' script-arg to add the results as targets`. It connects to no host; it only asks the resolver. XML and JSON: `hosts` (a list per name) and `newtargets`. nmap's also suggests its `--resolve-all` option, which FeroProbe does not have. Arguments: `resolveall.hosts` (a name or `{name,...}`), `newtargets`, `max-newtargets` |
| `rdp-ntlm-info` | default, discovery, safe | 3389, `ms-wbt-server` | Asks for TLS and CredSSP (Network Level Authentication) in the connection request, sends an NTLM NEGOTIATE (see `fero.ntlm.negotiate_message`) inside a CredSSP message over TLS and shows what the server's NTLM CHALLENGE says: target name, NetBIOS and DNS domain and computer names, DNS tree name, product version and system time (UTC), in that order, as nmap's; the system time is noted for `clock-skew`. No credentials are sent. A server that does not offer CredSSP gives no output. The connection request carries the routing cookie `Cookie: mstshash=FeroProbe`. TLS 1.2 and 1.3 only, as for all FeroProbe TLS, so old servers with TLS 1.0 only give no output. Argument: `rdp-ntlm-info.timeout` (ms, default 8000) |
| `rpcinfo` | default, discovery, safe | 111/tcp and udp, `rpcbind` | Asks the portmapper for its registered RPC programs (DUMP, as `rpcinfo -p`) and lists program, versions, port and protocol, and service name. The ports it lists are not contacted |
| `smb-os-discovery` | default, discovery, safe | hosts with 445 or 139 open | What an SMB1 server says about itself (see `fero.smb.os_info`): OS and LAN manager, OS CPE (for the Windows versions nmap knows), computer name, NetBIOS computer name, then for a domain member the domain, forest, FQDN and NetBIOS domain names, else the workgroup, and the system time in the server's time zone (`2026-01-02T04:04:05+01:00`), noted for `clock-skew`. Two connections; the NTLM challenge is never answered, so nothing logs in. No output from servers without SMB1 (Windows 10 and Server 2016 on, by default). Arguments: `smbport`, `smb-os-discovery.timeout` (ms, default 8000) |
| `smb-protocols` | discovery, safe | hosts with 445 or 139 open | Lists the SMB dialects the server takes (see `fero.smb.list_dialects`), NT LM 0.12 marked `(SMBv1) [dangerous, but default]`. One NEGOTIATE per connection, up to seven. Not in `default`, as in nmap. Arguments: `smbport`, `smb-protocols.timeout` |
| `smb-security-mode` | default, discovery, safe | hosts with 445 or 139 open | One SMB1 NEGOTIATE (NT LM 0.12, extended security) and the security the server asks for: `authentication_level` (user, or share: dangerous), `challenge_response` (supported, or plaintext-only: dangerous) and `message_signing` (required, supported, or disabled: dangerous, but default); the clock is noted for `clock-skew`. No output from servers without SMB1. Arguments: `smbport`, `smb-security-mode.timeout` |
| `smb2-capabilities` | discovery, safe | hosts with 445 or 139 open | One SMB2 NEGOTIATE offering every dialect finds the newest the server speaks; then one NEGOTIATE per dialect from 2.0.2 up to it lists the capabilities given for each (Distributed File System, Leasing, Multi-credit operations, Multiple Channel support, Persistent handles, Directory Leasing, Encryption; `All capabilities are disabled` for none). Not in `default`, as in nmap. Arguments: `smbport`, `smb2-capabilities.timeout` |
| `smb2-security-mode` | default, discovery, safe | hosts with 445 or 139 open | One SMB2 NEGOTIATE (see `fero.smb.negotiate`) and whether the server signs messages: enabled and required, enabled but not required, or disabled, under the dialect it chose (`3:1:1`). Arguments: `smbport`, `smb2-security-mode.timeout` (ms, default 8000) |
| `smb2-time` | default, discovery, safe | hosts with 445 or 139 open | The server's clock and start time from its NEGOTIATE answer (`N/A` when it gives none, as current Windows does), in UTC; the clock is noted for `clock-skew`. Arguments: `smbport`, `smb2-time.timeout` |
| `smtp-commands` | default, discovery, safe | 25, 465, 587, `smtp`, `submission` | Sends `EHLO feroprobe.invalid` and lists the server's name and extensions; QUIT. Over TLS on 465. `smtp.domain` (nmap's name) sends another name instead. nmap's also sends HELP, and by default the target's own name; FeroProbe's sends no HELP |
| `smtp-ntlm-info` | default, discovery, safe | 25, 465, 587, `smtp`, `smtps`, `submission` | Says `EHLO feroprobe.invalid`, switches to TLS with STARTTLS where the server allows it (some servers take AUTH only then; else it starts again in plain text) and says EHLO again, sends `AUTH NTLM` and the NEGOTIATE, then cancels the exchange (`*`) and says QUIT. Shows what the server's NTLM CHALLENGE says: target name, NetBIOS and DNS domain and computer names, DNS tree name and product version, in nmap's order and labels (see `fero.ntlm.info`); the server's clock is noted for `clock-skew`. The NTLM NEGOTIATE names no user and the workstation `FEROPROBE`; nothing logs in. Over TLS from the start on 465 and when `-sV` found TLS. Arguments: `smtp-ntlm-info.domain` or `smtp.domain` (the EHLO name), `smtp-ntlm-info.timeout` (ms, default 10000) |
| `snmp-info` | default, version, safe | UDP 161, `snmp` (UDP), open or open\|filtered, when scanned (`-sU -p U:161`) | Sends the SNMPv3 engine discovery request (no user, no credentials, sent twice at most) and shows what the agent's Report gives: `enterprise` (the vendor's IANA Private Enterprise Number, by name for some 40 common vendors, else the number), `engineIDFormat` (`ipv4`, `ipv6`, `mac`, `text`, `octets` or `unknown`) and `engineIDData`, `snmpEngineBoots` and `snmpEngineTime`. msgID and request-id `0x4650` ("FP"). nmap's names every registered enterprise from its copy of the IANA list, and its result also sets the port's version (`<enterprise> SNMPv3 server`); FeroProbe's does not change `-sV`'s result. Arguments: `snmp.timeout`, `snmp.retries` |
| `snmp-interfaces` | default, discovery, safe | UDP 161, `snmp` (UDP), open or open\|filtered, when scanned | Walks IF-MIB's `ifTable` (the `ifDescr`, `ifType`, `ifSpeed`, `ifPhysAddress`, `ifOperStatus`, `ifInOctets` and `ifOutOctets` columns, one GetNextRequest at a time) and `ipAddrTable`, and lists each interface as nmap does: its name, `IP address: ...  Netmask: ...` (every address it has; nmap's shows only the last), `MAC address:` with the vendor from the OUI list, `Type:` (the IANA ifType name) and `Speed:`, and `Traffic stats: ... sent, ... received`. Interfaces that are not up, and every `Status:` line (any RFC 2863 state: `up`, `down`, `testing`, `unknown`, `dormant`, `notPresent`, `lowerLayerDown`; nmap's names only the first two), only with `-v` (or when chosen by name, which counts as one `-v`, as in nmap). Reads only the columns it shows, about half the requests nmap's walk of the whole table sends. nmap's can also run before the scan against a host named in `snmp-interfaces.host` and add its addresses as targets; FeroProbe's runs only against scanned ports. Arguments: `creds.snmp`, `snmp.version`, `snmp.timeout`, `snmp.retries` |
| `snmp-sysdescr` | default, discovery, safe | UDP 161, `snmp` (UDP), open or open\|filtered, when scanned | Asks for `sysDescr.0` (the device, its operating system and often its version) and `sysUpTime.0`, two GetRequests, and shows the description and `System uptime: 28d17h18m59.00s (248153900 timeticks)`, as nmap's. A description with CR LF line ends keeps its lines. nmap's sets the port `open` when the agent answers; FeroProbe's leaves the state to the scan (an agent that answers the `-sU` probe is already `open`). Arguments: `creds.snmp`, `snmp.version`, `snmp.timeout`, `snmp.retries` |
| `ssh-hostkey` | default, discovery, safe | 22, `ssh` | Shows each host key's size, MD5 fingerprint and type, as nmap's does, and with `-vv` the key. `ssh-hostkey.format` (or nmap's `ssh_hostkey`) picks `md5`, `sha256` (as `ssh-keygen -l` prints it), `full` or `all`; nmap's `visual` and `bubble` forms are not offered. One connection per key type the server offers; each stops at the server's key exchange reply, before any login. The client announces itself as `SSH-2.0-FeroProbe_Scripting_Engine`. Key exchange: curve25519 or the Diffie-Hellman groups 14, 16, 18 and 1. Argument: `ssh-hostkey.timeout` (ms, default 10000) |
| `ssh2-enum-algos` | discovery, safe | 22, `ssh` | Lists what the server offers in its KEXINIT: `kex_algorithms`, `server_host_key_algorithms`, `encryption_algorithms`, `mac_algorithms` and `compression_algorithms`, with the number of each; with `-v` also each algorithm, in the server's order of preference. Same rule as nmap's: `--script ssh2-enum-algos` lists them without `-v`, `--script discovery` only with it. A group the server offers differently in each direction is shown twice, under the RFC 4253 names (`encryption_algorithms_client_to_server`, `..._server_to_client`). The XML and JSON reports always hold the full lists. One connection: the version lines (FeroProbe's is `SSH-2.0-FeroProbe_Scripting_Engine`), FeroProbe's KEXINIT, the server's KEXINIT, then it closes; no key exchange, nothing logs in. Not in `default`, as in nmap. Argument: `ssh2-enum-algos.timeout` (ms, default 10000) |
| `ssl-cert` | default, discovery, safe | TLS ports, and ports that switch to TLS on request (see `fero.starttls.protocol`) | Shows the certificate of a TLS port: subject, alternative names, issuer, key type and size, signature algorithm, validity dates, SHA-1 and SHA-256 fingerprints, and with `-v` the PEM. On an SMTP, LMTP, IMAP, POP3, NNTP, FTP, LDAP, PostgreSQL or XMPP port that `-sV` did not find speaking TLS straight away, it first asks for TLS the protocol's way (`fero.starttls.connect`), and when that fails tries a TLS handshake straight away, as nmap's does. nmap's also covers MySQL, VNC and MS-SQL (TDS), which FeroProbe's does not yet; nmap's also shows MD5, FeroProbe's SHA-256 instead |
| `ssl-date` | default, discovery, safe | TLS ports | Sends a TLS 1.2 ClientHello and reads the time the server puts in the first four bytes of its ServerHello random, as `2026-11-18T10:00:00+00:00; +5s from scanner time.` No handshake is finished. A second hello checks that the value moves with the clock (and when both answers came within one second, a third one two seconds later, so that a field that never changes is not taken for a clock); most current servers fill it with random bytes, and then the script says `TLS randomness does not represent time`. A ServerHello split across several records is read; only its first 10 bytes are read, within one timeout. The hello's random carries `FeroProbeSSLDate` after the time field. The server's clock is noted for `clock-skew`. Direct TLS only (no STARTTLS, which nmap's also tries). Argument: `ssl-date.timeout` (ms, default 8000) |
| `ssl-enum-ciphers` | discovery, intrusive | TLS ports, and ports that switch to TLS on request (see `fero.starttls.protocol`) | Lists, for each protocol version from SSLv3 to TLS 1.3 the server speaks, the cipher suites it takes, with what the key exchange used (`rsa 2048`, `dh 2048`, `secp256r1`, `ecdh_x25519`) and a grade from A to F, the compression methods (none for TLS 1.3), whether the server picks by its own order (`server`, the suites then listed in that order) or the client's (`client`, listed by name), and warnings; then `least strength`, the weakest grade. Layout, names and warning texts as nmap's. Finds the suites with ClientHellos offering 64 at a time, asking again without each one the server picks; the order as nmap decides it: the first two suites found are offered alone, in both orders, and a different pick each time means `client` (`indeterminate` with `cipher preference error: Too few ciphers supported` for one suite; no `cipher preference` line, only the error, when a comparison gets no answer). Grades (from the Qualys SSL Labs rating guide, without its protocol part, as nmap's): 3 parts key exchange strength (in RSA bits, elliptic curves converted by NIST SP 800-57) and 4 parts cipher key size, capped at F for anonymous or export key exchange, a NULL cipher or a certificate signed with MD5 or SHA-1, and at C for RC4, 64-bit block ciphers (SWEET32) and CBC in SSLv3 (POODLE). No handshake is finished: each connection ends at the server's first flight. Makes many connections (often over a hundred), hence intrusive, as nmap's; not in `default`. nmap 7.94 misses TLS 1.3 on some servers whose certificate key is ECDSA P-384 (seen with OpenSSL 3); FeroProbe's finds it. It runs on ports in FeroProbe's TLS port and service list (`fero.portrule.ssl`) and on ports that switch to TLS on request; only on a port that is neither does it need `-sV` to find TLS (or `+ssl-enum-ciphers`); nmap's also runs on some other ports without `-sV`. Argument: `ssl-enum-ciphers.timeout` (ms per answer, default 5000) |
| `sshv1` | default, safe | 22, `ssh` | Says whether the server still accepts the obsolete SSH protocol 1, from the version in its greeting; sends nothing. nmap's also reads the version 1 keys and ciphers |
| `sslv2` | default, safe | TLS ports | Sends one SSLv2 CLIENT-HELLO offering every SSLv2 cipher kind and, when the server answers with an SSLv2 SERVER-HELLO, shows `SSLv2 supported` and the ciphers it lists (nmap's names, `SSL2_DES_192_EDE3_CBC_WITH_MD5`...; `none` when it lists none). No handshake is finished. The challenge is `FeroProbeTLSScan`. Argument: `sslv2.timeout` (ms, default 5000) |
| `telnet-ntlm-info` | default, discovery, safe | 23, `telnet` | Sends one telnet AUTHENTICATION IS NTLM sub-negotiation ([MS-TNAP]) with the NEGOTIATE and reads the server's REPLY (doubled 0xff bytes undone), skipping the server's own option negotiation. Shows what the server's NTLM CHALLENGE says: target name, NetBIOS and DNS domain and computer names, DNS tree name and product version, in nmap's order and labels (see `fero.ntlm.info`); the server's clock is noted for `clock-skew`. The NTLM NEGOTIATE names no user and the workstation `FEROPROBE`; nothing logs in. Answers only Microsoft's telnet server. Argument: `telnet-ntlm-info.timeout` (ms, default 10000) |
| `tls-alpn` | default, discovery, safe | TLS ports | Lists the protocols the server takes through ALPN, in the order it picks them: a TLS 1.2 ClientHello offers the IANA registry's protocol IDs (`h2`, `http/1.1`, `spdy/3`, `h3`, `xmpp-client`... but not `acme-tls/1`, which asks an ACME client for a validation certificate), and is sent again without each one picked until the server picks none. TLS 1.3 servers answer ALPN inside encryption, so a TLS 1.3-only server gives no output (as with nmap's). nmap 7.94's gets no answer from some servers that require TLS 1.2 (seen with Python's `ssl` module); FeroProbe's asks with TLS 1.2 straight away. Argument: `tls-alpn.timeout` (ms, default 5000) |
| `tls-nextprotoneg` | default, discovery, safe | TLS ports | One TLS 1.2 ClientHello with an empty NPN (Next Protocol Negotiation) extension; lists the protocols the server advertises, in its order. Both this script and `tls-alpn` send the target's name (SNI) like `ssl-enum-ciphers`; nmap 7.95's print nothing for some name-based hosts (seen on a Cloudflare site). Argument: `tls-nextprotoneg.timeout` (ms, default 5000) |
| `vnc-info` | default, discovery, safe | 5900-5910, `vnc` | Answers the RFB version handshake and lists the security types offered, with a warning when "None" (no authentication) is one; chooses none, so nothing logs in |
| `x11-access` | default, auth, safe | 6000-6009, `X11` | Sends an X11 connection setup without credentials and says whether the server lets anyone connect; closes at once |

"Web ports" are the usual HTTP and HTTPS ports (80, 443, 8080, 8443 and
others) and ports whose service is `http`, `https` or similar; "TLS
ports" are ports where `-sV` found TLS, or whose number or service is a
TLS one. A script whose rule needs a service name sees the one `-sV`
found, or without `-sV` the name of the port number, as in nmap.

nmap's `default` category has more scripts (other SMB ones, DNS and others);
FeroProbe's grows release by release. Scripts of nmap's that would reach
beyond the scanned host, such as `http-open-proxy` or `socks-open-proxy`,
which ask the target to fetch an outside site, are not planned for the
default set.

```
$ feroprobe -sV -p 80,443 --script http-title,ssl-cert 192.0.2.10
PORT       STATE          SERVICE        VERSION
80/tcp     open           http           nginx 1.24.0
|_http-title: Did not follow redirect to https://www.example.test/
443/tcp    open           ssl/http       nginx 1.24.0
| http-title: Example
|_Requested resource was https://192.0.2.10/start
| ssl-cert: Subject: commonName=www.example.test/organizationName=Example
| Subject Alternative Name: DNS:www.example.test, DNS:example.test
| Issuer: countryName=US/organizationName=Example CA/commonName=Example CA R1
| Public Key type: ec
| Public Key bits: 256
| Signature Algorithm: ecdsa-with-SHA384
| Not valid before: 2026-09-01T00:00:00
| Not valid after:  2026-11-30T23:59:59
| SHA-1:   3c1f...
|_SHA-256: 9a07...
```

### NSE compatibility layer

Scripts written for nmap's scripting engine (NSE) can run in FeroProbe
when they use only the parts of nmap's libraries that FeroProbe offers.
`--script` takes `.nse` files as it takes `.lua` ones: by path, by name
in the scripts directory (`name.lua` first, then `name.nse`), from a
directory, and in the index `--script-updatedb` writes. A script becomes
an NSE script the moment it calls `require`; FeroProbe's own scripts do
not. As in nmap, such a script also has `nmap` and Lua's `io` (FeroProbe's
read-only one) available as globals, without requiring them.

`require` gives these modules, written for FeroProbe on top of `fero`
from nmap's public API documentation (nmap's own libraries are under the
NPSL and are not used or shipped). The same sandbox and scope rules
apply: every connection still goes only to the scanned host and to ports
the scan probed there.

| Module | What it has |
| --- | --- |
| `nmap` | `new_socket` (`connect`, `send`, `sendto`, `receive`, `receive_bytes`, `receive_lines`, `receive_buf`, `set_timeout`, `close`, `get_info`, `reconnect_ssl`, `get_ssl_certificate`), `new_try`, `registry`, `verbosity`, `debugging`, `clock_ms`, `clock`, `address_family`, `get_port_state`, `get_ports`, `resolve`, `add_targets`, `new_targets_num`, `have_ssl`, `is_privileged`, `timing_level`, `version_intensity`, `mutex`, `condvar`, `log_write`; `set_port_state` and `set_port_version` are accepted and do nothing |
| `stdnse` | `debug`, `debug0`-`debug9`, `print_debug`, `verbose`, `verbose0`-`verbose9`, `get_script_args`, `format_output`, `output_table`, `tohex`, `fromhex`, `parse_timespec`, `sleep`, `clock_ms`, `get_hostname`, `format_mac`, `get_timeout`, `new_thread`, `string_or_blank`, `make_buffer`, `registry_get`, `registry_add_table`, `registry_add_array`, `in_port_range`, `generate_random_string`, `silent_require`, and the old names `strsplit`, `keys`, `contains`, `format_time`, `format_timestamp` |
| `shortport` | `portnumber`, `service`, `port_or_service`, `version_port_or_service`, `port_range`, `http`, `ssl`, `ssh`, `LIKELY_HTTP_PORTS`, `LIKELY_HTTP_SERVICES` (`http` and `ssl` are FeroProbe's own port rules) |
| `comm` | `opencon`, `get_banner`, `exchange`, `tryssl` |
| `http` | `get`, `head`, `post`, `put`, `generic_request`, `get_url`, `pipeline_add`, `pipeline_go`, `response_contains`, `parse_www_authenticate`, `identify_404`, `page_exists`, `can_use_head`, `get_status_string`, `USER_AGENT`; on top of FeroProbe's HTTP library, so its redirect rule, signature User-Agent and limits apply |
| `url` | `parse`, `build`, `absolute`, `escape`, `unescape`, `parse_query`, `build_query`, `parse_path`, `build_path`, `get_default_port` |
| `ipOps` | `ip_to_str`, `str_to_ip`, `compare_ip`, `isPrivate`, `todword`, `fromdword`, `ip_to_bin`, `bin_to_ip`, `hex_to_bin`, `expand_ip`, `ip_in_range`, `get_ips_from_range`, `get_last_ip`, `ip_sort`, `subnet_to_cidr` |
| `stringaux`, `tableaux` | `strsplit`, `filename_escape`, `ipattern`; `tcopy`, `shallow_tcopy`, `keys`, `contains`, `invert` |
| `datetime` | `format_timestamp`, `format_time`, `format_difftime`, `date_to_timestamp`, `record_skew` (feeds `clock-skew`) |
| `openssl` | `md5`, `sha1`, `digest` (MD5, SHA-1, SHA-256, SHA-384, SHA-512), `hmac`, `rand_bytes`, `rand_pseudo_bytes`, `supported_digests`; big numbers: `bignum_bin2bn`, `bignum_dec2bn`, `bignum_hex2bn`, `bignum_bn2bin`, `bignum_bn2dec`, `bignum_bn2hex`, `bignum_add`, `bignum_div`, `bignum_mod_exp`, `bignum_num_bits`, `bignum_num_bytes`, `bignum_is_bit_set`, `bignum_set_bit`, `bignum_clear_bit`, `bignum_is_prime`, `bignum_is_safe_prime`, `bignum_rand`, `bignum_pseudo_rand`; no ciphers |
| `io` | Lua's `io`, read-only: `open` (read modes), `lines`, `close`, `type`, `read`, `input`, and files' `read` (`l`, `L`, `n`, `a`, byte counts), `lines`, `seek`, `close`; `write` and `io.stdout:write` go to the debugging output, as `print` does |
| `base64`, `rand`, `match`, `outlib` | `enc`, `dec`; `random_string`, `random_alpha`, `charset`; `numbytes`, `pattern_limit`, `dontmatch`; `sorted_by_key`, `list_sep` |
| `strbuf`, `json` | `new`, `dump`, `clear`, `concatbuf`, `eqbuf`, `tostring` (one piece per line) and `..`, `==` on buffers; `parse` (to `true` and the value, or `false` and a message), `generate`, `NULL`, `make_array`, `make_object`, `typeof` |
| `creds` | `State`, `StateMsg`, `ALL_DATA`, `Account`, `Credentials` (`new` with a script name or a list of tags, `add`, `getCredentials`, `getTable`); kept in `nmap.registry.creds` for the run; asking for `State.PARAM` also gives the accounts in `creds.<service>` and `creds.global` (`user:pass`) |
| `vulns` | `STATE`, `STATE_MSG`, `Report` (`new`, `add_vulns`, `make_output`); `vulns.showall` lists what is not vulnerable too |
| `ftp` | `connect`, `read_reply`, `auth`, `pasv`, `close` |
| `httpspider` | `Crawler` (`new`, `crawl`, `set_timeout`, `stop`, `iswithinhost`, `iswithindomain`, `isresource`, `getLimitations`), `URL`, `LinkExtractor`, `UrlQueue`, `Options`. Crawls breadth-first from `httpspider.url` (default `/`): at most `httpspider.maxpagecount` pages (20) and `httpspider.maxdepth` directories below the start (3), negative for no limit; links from `href`, `src`, `action` and CSS `url()`. Images, media, archives, documents and fonts are skipped unless `httpspider.noblacklist`; `httpspider.useheadfornonwebfiles` asks for files that are not web pages with HEAD. `httpspider.withinhost=false` or `httpspider.withindomain` widen the crawl's own scope, but every page is still fetched only from the scanned host and its scanned ports. Each argument can also be given under the script's name (`http-grep.maxpagecount=50`) |
| `sslcert` | `getCertificate`, `parse_ssl_certificate`, `isPortSupported`, `getPrepareTLSWithoutReconnect`, over FeroProbe's STARTTLS helper (SMTP, LMTP, IMAP, POP3, NNTP, FTP, LDAP, PostgreSQL, XMPP); an RSA key's `modulus` and `exponent` are `openssl` bignums, as nmap's `ssl-cert` reads them |
| `tls` | `client_hello`, `record_read`, `record_write`, `record_buffer`, `handshake_parse`, `record_version_ok`, `cipher_info`, `servername`, `rsa_equiv`, `KEX_ALGORITHMS` (with `server_key_exchange` readers), `EXTENSION_HELPERS`, `PROTOCOLS`, `CIPHERS`, `COMPRESSORS`, `ELLIPTIC_CURVES`, `DEFAULT_ELLIPTIC_CURVES`, `EXTENSIONS`, `TLS_ALERT_REGISTRY` and the other registries |
| `ssh2` | `fetch_host_key`, `check_packet_length`, `transport` (`build`, `payload`, `receive_packet`, `kex_init`, `parse_kex_init`, `kexdh_init`, `kexdh_gex_init`) |
| `smb` | `get_port`, `get_os`, `get_windows_version`, `list_dialects`, `start`, `start_ex`, `negotiate_protocol`, `stop`, `get_uniqueish_name`, `get_overrides` |
| `snmp` | `Helper` (`new`, `connect`, `get`, `getnext`, `walk`, `close`), `str2oid`, `oid2str` |
| `unpwdb` | `usernames`, `passwords`, `timelimit`, `concat_iterators`, `filter_iterator`, `limited_iterator`; reads only a file named in `--script-args` (`userdb`/`passdb`) or an installed nmap's `usernames.lst`/`passwords.lst` found by `nmap.fetchfile`, since FeroProbe ships no word lists |
| `brute` | `Engine` (`new`, `start`, `setMaxThreads`, `setUsernameIterator`, `setPasswordIterator`, `setMode`, `setOption`, `setTitle`), `Driver` interface (`new`, `connect`, `login`, `disconnect`), `Error` (`new`, `getMessage`, `setRetry`/`isRetry`, `setAbort`/`isAbort`, `setReduce`/`isReduce`, `setDone`/`isDone`, `setInvalidAccount`/`isInvalidAccount`), `Options`, `Account`, `account_iterator`, `credential_iterator`, `pw_same_as_user_iterator`, `pw_ucase_iterator`, `checkBoolArg`, `new_socket`; guesses one at a time, so `setMaxThreads` and `brute.threads` have no effect |
| `tab`, `listop`, `bits` | `new`, `add`, `addrow`, `nextrow`, `dump`; `map`, `filter`, `apply`, `append`, `cons`, `car`, `cdr`, `ncar`, `ncdr`, `reverse`, `flatten`, `is_empty`, `is_list`; `arshift`, `reverse` |
| `oops`, `formulas` | `err`, `raise`, `output` (an error shows only with `-d`, as with `stdnse.format_output`); `mean_stddev`, `median`, `quickselect`, `calcPwdEntropy`, `looksRandom` |
| `geoip` | `add`, `empty`, `get_all_by_ip`, `get_all_by_gps`; kept in `nmap.registry` for the run |
| `irc`, `knx` | `portrule`; `parseHeader`, `parseKnxAddress`, `query`, and the KNXnet/IP service family, medium and DIB type tables |
| `lfs` | `get_path_separator`; `mkdir`, `rmdir` and `link` return false and a message, and `dir` raises an error, since scripts cannot touch the file system |
| `dns`, `base32` | `query`, `update`, `reverse`, `encode`, `decode`, `decStr`, `newPacket`, `addQuestion`, `addZone`, `addUpdate`, `addOPT`, `addNSID`, `addClientSubnet`, `findNiceAnswer`, `findNiceAdditional`, `sendPackets`, `types`, `CLASS`; `enc`, `dec` (with the extended hex alphabet as the second argument). Queries go to the run's DNS servers unless the script names a server, and only where the scope allows (see below); referrals to other servers are not followed |
| `mysql` | `receiveGreeting`, `loginRequest` (mysql_native_password; a server that asks for another plugin, such as MySQL 8's default caching_sha2_password, refuses the login), `sqlQuery`, `formatResultset`, `decodeQueryResponse`, `decodeField`, `decodeFieldPackets`, `decodeDataPackets`, `Capabilities`, `ExtCapabilities` (under the names nmap's mysql-info prints); the login names FeroProbe in its connection attributes |
| `slaxml` | `parser:new` (callbacks `startElement`, `attribute`, `closeElement`, `text`, `comment`, `pi`, kept in `parser._call`), `parseSAX` (option `stripWhitespace`), `parser.unescape`, `parseDOM`; lenient like nmap's: it reports what it reads and does not check that elements nest |
| `unicode` | `utf8_enc`, `utf8_dec`, `utf16_enc`, `utf16_dec`, `cp437_enc`, `cp437_dec`, `decode`, `encode`, `transcode`, `utf16to8`, `utf8to16`, `chardet` |
| `smbauth` | `get_host_info_from_security_blob` (what a server's NTLM challenge says about it: names, domain, clock and Windows version) and `get_security_blob` for the first message only, which is always FeroProbe's own NTLM NEGOTIATE naming workstation FEROPROBE; the login functions raise an error, as FeroProbe's NSE layer does not log in over NTLM |
| `datafiles` | `parse_services`, `parse_protocols`, `parse_rpc`, `parse_mac_prefixes` (a whole MAC works as a key too), `parse_file`, `parse_lines`, `read_from_file`, `get_array`, `get_assoc_array`; the files are found as `nmap.fetchfile` finds them, so an installed nmap's `nmap-services`, `nmap-protocols`, `nmap-rpc`, `nmap-mac-prefixes` and word lists are used. Without them, `parse_services` and `parse_protocols` give FeroProbe's own port and protocol names (the ones its reports show), `parse_mac_prefixes` the OUI list FeroProbe reports vendors from, and `parse_rpc` and other files an error |
| `smb2` | `negotiate_v2` (a NEGOTIATE carrying FeroProbe's client GUID; it fills the state from `smb.start` with the dialect, security mode, capabilities, server GUID and the server's clock and start time), `dialects`, `dialect_name` (nmap's `3:1:1` form); `smb2_encode_header_sync`, `smb2_send` and `smb2_read` raise an error, as FeroProbe does not keep an SMB connection open between calls |
| `netbios` | `name_encode`, `name_decode`, `flags_to_string`, `do_nbstat` (the same NODE STATUS request as the `nbstat` script, asked once per host), `get_server_name`, `get_workstation_name`, `get_user_name`, `get_names`, and `nbquery` (a NAME QUERY with transaction ID `FP`, IDS rule 9100035); both go to UDP 137, only when it was scanned |
| `rpc` | ONC RPC over TCP and UDP: `Comm` (connections, packets, reply headers), `Portmap` (`Dump`, `GetPort`, `Callit` and the RPC constants), `Mount` (`Export`, `Mount`, `Unmount`, versions 1 to 3), `NFS` versions 2 and 3 (`GetAttr`, `LookUp`, `Access`, `ReadDir`, `ReadDirPlus`, `StatFs`, `FsStat`, `FsInfo`, `PathConf`), `Helper` (`RpcInfo`, `GetProgramInfo`, `ShowMounts`, `MountPath`, `UnmountPath`, `NfsOpen`, `NfsClose`, `ExportStats`, `GetAttributes`, `Dir`) and `Util`; arguments `rpc.protocol`, `mount.version`, `nfs.version`. Calls carry transaction ID `FP` (IDS rules 9100036 and 9100037) unless the script picks its own, use no credentials (AUTH_NULL), and reach mountd and NFS only on ports you scanned: scan them too (for example `-p 111,2049,<mountd port>`; `rpcinfo` lists them). FeroProbe does not bind a reserved source port, so a server exporting with the Linux `secure` option refuses to mount |
| `ls` | `new_listing`, `new_vol`, `add_file`, `end_vol`, `end_listing`, `report_error`, `report_info`, `config`; arguments `ls.maxfiles` (10), `ls.maxdepth` (0), `ls.human`, `ls.errors`, `ls.empty`, `ls.checksum`, each also under the script's name |
| `target` | `ALLOW_NEW_TARGETS`, `add`: as in nmap, a script adds hosts to the scan only when you pass the `newtargets` script argument, and at most `max-newtargets` of them (0, the default, for no limit); see [Hosts that scripts add](#hosts-that-scripts-add) |
| Lua's own | `string`, `table`, `math`, `coroutine`, `utf8`, `os` (the sandbox's), `_G` |

Any other module (`packet`, `msrpc`, `mssql`, ...)
stops the script from loading with an error that names it; a function
FeroProbe does not have in a module it offers (`nmap.new_dnet`,
`openssl.encrypt`, ...) raises an error naming it when called. Of nmap
7.94's 606 scripts, 372 load as they are. See
[Brute-force scripts](#brute-force-scripts) for how a `brute` script must
be chosen before it will run.

What NSE scripts see differently:

- **The host table** has nmap's form for them: `bin_ip`, `mac_addr` as
  six bytes, `os` as a list of `{ name = ... }` tables, and `registry`.
- **The registries.** `nmap.registry` and `host.registry` look like plain
  tables changed in place. Each top-level entry is copied out of
  FeroProbe's registry the first time the script touches it, and what the
  script changed is written back after each rule and action, merged with
  what other scripts did meanwhile: values it set or removed are applied,
  and entries it added at the end of a list go after that list's end as
  it is now, so scripts that run at once and add to the same list (or
  start it with `nmap.registry.x = nmap.registry.x or {}`) all keep their
  entries. After each write-back the script sees the merged value, other
  scripts' additions included, in the same tables it already holds. A
  plain value two scripts set at once keeps the last write. Only
  plain data is kept (see [The registry](#the-registry)); top-level names
  must be strings, and `pairs(nmap.registry)` lists only the entries the
  script has touched. A script stopped by its timeout leaves no changes.
  `nmap.registry.args` holds the script arguments, as in nmap (a copy:
  changing it changes nothing for other scripts).
- **Threads.** `stdnse.new_thread` runs the function to completion
  before it returns (FeroProbe already runs many scripts at once), and
  returns a finished coroutine, so the usual wait loops end at once;
  `nmap.mutex` and `nmap.condvar` never wait.
- **No raw packets or privileges.** `nmap.is_privileged()` is `false`, so
  scripts take their unprivileged path; `new_dnet`, `pcap_open` and the
  interface functions are not available.
- **Ports.** A port table's `version.name_confidence` is 10 when version
  detection named the service and 3 when the name comes from the port
  number, nmap's scale. `nmap.get_port_state` and `nmap.get_ports` know
  only the ports that may be open (open, open|filtered, unfiltered), the
  ones a portrule is asked about. A script's portrule or hostrule runs
  again in the action's own state just before the action, so what the
  rule keeps in the script's variables is there for the action, as in
  nmap, where rule and action share one instance.
- **Scripts do not change results.** `nmap.set_port_state` and
  `nmap.set_port_version` are accepted and ignored (shown with `-d2`).
- **Files are read-only, and only some.** FeroProbe ships none of nmap's
  data files. `nmap.fetchfile(name)` looks for `name` (a relative path
  without `..`) in FeroProbe's data directory (the folder above the
  scripts directory, such as `~/.local/share/feroprobe/`), then in
  `$NMAPDIR`, `/usr/local/share/nmap`, `/usr/share/nmap`,
  `/opt/homebrew/share/nmap` and `/opt/local/share/nmap`, so the word
  lists and data files of an nmap you installed are found as nmap finds
  them. `io.open` reads only a file inside those directories (after
  following links) or a path you gave in `--script-args` exactly as
  written (such as `userdb=users.txt`); any other path, and every write
  mode, gives `nil` and a message. Files are read whole, at most 16 MiB.
  `io.popen` and `io.tmpfile` raise an error. nmap's scripts can read and
  write any file the user can.
- **Name lookups.** `nmap.resolve(name [, family])` asks the system resolver, as nmap's does, and gives each address once (nmap's can repeat one, as the resolver lists it once per socket type).
- **Big numbers** (`openssl.bignum_*`) are FeroProbe's own, with limits
  so one call stays short: numbers up to 65,536 bits; `bignum_mod_exp`
  and the prime tests up to 16,384 bits. Prime tests use Miller-Rabin with
  random bases, false positives below 2^-80 as documented for nmap's.
- **Fixed values.** `nmap.timing_level()` is 3 and
  `nmap.version_intensity()` 7 whatever the scan's options;
  `stdnse.get_timeout` is 5 seconds within the range asked for, as
  FeroProbe gives scripts no round-trip times.
- **Errors.** `stdnse.format_output(false, msg)` gives `ERROR: msg` only
  with `-d`, as in nmap; a failed `nmap.new_try` ends the script without
  output, as any script error does in FeroProbe.
- **Messages** from `stdnse.debug`, `verbose` and `nmap.log_write` go to
  standard error, as FeroProbe's other messages do.
- **HTTP.** `redirect_ok` functions cannot run inside FeroProbe's HTTP
  client: `false` and numbers are honoured, a function means FeroProbe's
  own rule. Pipelined requests go one after another. A failure gives
  nmap's form, a response with `status` `nil` and the reason in
  `status-line`.
- **Certificates** (`sslcert`, a socket's `get_ssl_certificate`) have
  `subject`, `issuer`, `pubkey` (`type`, `bits`, and for an EC key its
  curve, also as `ecdhparams`), `validity` (date tables), `sig_algorithm`,
  `version`, `serial`, `pem`, `der` and `digest`, but no key modulus or
  exponent, and of the extensions only the
  subject alternative names. TLS is 1.2 and 1.3, as for every FeroProbe
  connection.
- **TLS hellos** built with `tls.client_hello` carry FeroProbe's mark in
  their random, as `fero.tls` hellos do (IDS rule 9100019). A TLS 1.3
  hello gets `supported_versions` and an x25519 key share unless the
  script gives them. A hello that leaves them out also offers the common
  curves and point formats and, from TLS 1.2 on, signature algorithms,
  since servers such as OpenSSL 3 refuse a hello that gives them no way
  to sign their key exchange. `tls.KEX_ALGORITHMS` reads the server's
  key exchange parameters (DH, elliptic curve, export RSA, and the TLS
  1.3 key share), and `tls.rsa_equiv` maps key sizes with NIST SP 800-57's
  table.
- **No logins over SMB.** `smb` reads what a server says before any
  login (the NEGOTIATE, the OS details, the dialects), as FeroProbe's own
  SMB scripts do; `start_session`, trees, files, shares and accounts
  return `false` and "FeroProbe does not log in to SMB servers".
  `get_os` gives `timezone` in hours, as nmap does.
- **No writes to devices.** The `snmp` helper reads (Get, GetNext,
  walks) over SNMPv1 and v2c; `set` returns `false` and a message, and
  the raw BER encoders are not available.
- **SSH.** `ssh2.fetch_host_key` reads the key from the key exchange
  reply without logging in, sending FeroProbe's SSH version line (IDS
  rule 9100007); an RSA key is asked for with the SHA-2 signature names
  too, so servers that turned `ssh-rsa` off still give it.
  `ssh2.transport` builds and reads unencrypted packets and KEXINITs,
  enough to list what a server offers; nothing goes past the key
  exchange. A script that writes its own version line on the socket
  (nmap's `ssh2-enum-algos` sends `SSH-2.0-Nmap_SSH2_Enum_Algos`) is not
  marked by FeroProbe, as with a script's own `User-Agent`.
- **FTP data connections** (`ftp.pasv`) go to the scanned host, never
  to the address in the server's reply, and only to a port the scan
  probed there; any other port is refused by the scope rule, so they
  usually fail.
- **The signature.** The HTTP library sends FeroProbe's User-Agent
  unless the script sets one, as for FeroProbe's own scripts; what a
  script sends on its own sockets is its own and carries no FeroProbe
  mark.

A script written for FeroProbe should use `fero` directly; the
compatibility layer is for running scripts written for nmap.

## Timing and performance

### Timing templates (`-T<0-5>`)

`-T0` to `-T5`, or `-T` with a name (`-T paranoid` ... `-T insane`), pick a
bundle of timing settings, as in nmap. `-T3` (normal) is the default. Any of
`--timeout`, the RTT timeout options, `--retries`, `-c`/`--concurrency`,
`--min-parallelism`, `--max-rate`, `--scan-delay` and `--max-scan-delay`
given explicitly
overrides the template's value for that setting, so `-T4 --max-rate 2000`
is aggressive with a lower packet rate. Given more than once, the last
`-T` wins, as in nmap.

| Template | RTT timeouts (initial / min / max) | Most retries | Most probes waiting at once | Max rate (packets/s) | Scan delay | Max scan delay (TCP, SCTP, IP / UDP) |
| --- | --- | --- | --- | --- | --- | --- |
| `-T0` paranoid | 5 min / 100 ms / 5 min | 10 | 1 | none | 5 min | 5 min / 5 min |
| `-T1` sneaky | 15 s / 100 ms / 15 s | 10 | 1 | none | 15 s | 15 s / 15 s |
| `-T2` polite | 1 s / 100 ms / 10 s | 10 | 10 | none | 0.4 s | 1 s / 1 s |
| `-T3` normal (default) | 1 s / 100 ms / 10 s | 10 | 500 | none | none | 1 s / 1 s |
| `-T4` aggressive | 500 ms / 100 ms / 1.25 s | 6 | 1000 | none | none | 10 ms / 1 s |
| `-T5` insane | 250 ms / 50 ms / 300 ms | 2 | 2000 | none | none | 5 ms / 1 s |

The RTT timeouts, retries and maximum scan delays are nmap's for each
template. As in nmap, no template limits the packet rate: only an explicit
`--max-rate` does. Most retries is a cap: a probe is resent once unless its host
shows losses (see [Resends and delays](#resends-and-delays)). The scan delay also sets a
floor under every measured timeout, so `-T0` and `-T1` probes wait at least
their delay.

### How long a probe waits

Like nmap, FeroProbe adapts its timeouts to the network. Every answer
(a SYN-ACK, a reset, an ICMP error, a UDP reply, an echo reply, an ARP
or neighbor discovery reply) gives a
round-trip time, and each host keeps a smoothed round-trip time and its
variance, the way TCP does (RFC 6298). A probe to that host waits the
smoothed time plus four times the variance, kept between
`--min-rtt-timeout` and `--max-rtt-timeout` and never below the scan delay.
A host that has not answered yet waits as long as the scan's hosts do
together, and before any answer at all a probe waits
`--initial-rtt-timeout`. The estimates carry over from host discovery to
the port scan, OS detection, version detection's connections and
traceroute. Round trips far outside the estimate (over 8 s, or a sudden
jump of more than 1.5 s) are ignored, as in nmap.

So on a fast local network a closed or filtered port costs about 100 ms
instead of a second, and on a slow link the timeout grows to fit.
`--timeout` turns this off: it fixes all three limits to one value.

ARP and neighbour discovery answers come from the link, not the host, so
they do not feed the estimates; their sweep waits as long as a host that
has not answered yet. Reverse DNS through `--dns-servers` waits the initial
timeout, at most 5 s, since the name servers are not scan targets; the
system resolver keeps its own timeouts.

### Congestion control

Also like nmap, the scans hold back how many probes may wait for an answer
at once, with congestion windows like TCP's: one per host and one for all
hosts together. Each starts at 10 probes. Every answer widens it (by one
probe per answer up to 75, then about one probe per window's worth of
answers; faster when many probes go unanswered, and with `-T4` and `-T5`).
An answer to a resent probe means the first one was lost: the host's
window then drops to one probe (or `--min-parallelism`) and the group's
halves, but no lower. A probe that only
times out moves no window. ICMP errors to resent probes are left out in the
scans where silence means `filtered`, since routers rate-limit them. The
group window only applies while two or more hosts are still being scanned.

`-c`/`--concurrency` caps both windows, and `--min-parallelism` is their
floor. The windows only ever hold probes
back: `--max-rate` and `--scan-delay` still apply on top, so gentle timing
stays gentle. Only `--min-rate` lets a probe through a full window, to keep
up its rate, as in nmap.

This applies to the raw TCP, SCTP, IP protocol, connect and UDP scans,
including the TCP and UDP probes of host discovery. Because only answers
widen the windows, a host that answers nothing is scanned slowly: about 10
probes per timeout. A thousand filtered ports with one retry take a few
minutes at the defaults, as with nmap; `-T4`, `--min-rate`, or `-Pn`
avoided on dead hosts speed this up.

### Resends and delays

As in nmap, how often a probe without an answer is sent again depends on
its host. At first a probe is resent once. When a host answers a resent
probe, the first copy or its answer was lost, so that host's probes may be
resent one time more than the highest resend it answered, up to
`--max-retries` (10 by default). Probes still waiting for an answer at that
point are sent again too. A host that loses nothing costs one resend per
silent port, and a host that drops packets, or rate-limits its resets or
ICMP errors, is probed until it answers.

Resends go before new probes. The first time a host has a probe due for a
higher try than any it was sent before (its first resend, its first second
resend, and so on), the scan sends that host nothing for one second, as
nmap does to detect rate limiting: a host that limits how fast it answers
gets to recover, and answers that were only slow come in before anything
is resent. A scan of a single probe skips the pause.

A lossy host also gets a delay between its probes. When more than 10 of
its answers since the delay last changed came only after a resend, and they
are more than 30 % of its answers (40 % with `-T4` and `-T5`), or when it
answers only after more than 3 resends (4 with `-T4` and `-T5`), the delay
goes up: to 5 ms at first (50 ms for UDP), then doubling, up to 1 s and no
more than `--max-scan-delay`. It never drops below `--scan-delay`. Routers
and firewalls that rate-limit their resets (closed TCP ports) or ICMP
errors (closed UDP ports) then get their answers counted instead of being
reported `filtered` or `open|filtered`, at the price of a slower scan.

This applies to the raw TCP, SCTP, IP protocol, connect and UDP scans and
their host discovery probes. ARP, ICMP echo, OS detection, traceroute and
reverse DNS resend once (none with `--max-retries 0`).

### Timing options

#### `--initial-rtt-timeout <time>`

How long a probe waits before any round trip has been measured (`500ms`,
`2s`; a bare number is seconds). Default from the template: 1 s. Must be
positive. If it is above the maximum, the maximum rises to it; below the
minimum, the minimum falls to it, as in nmap.

#### `--min-rtt-timeout <time>`

The shortest a probe's adaptive timeout may get. Default from the
template: 100 ms (50 ms with `-T5`). The maximum and the initial timeout
rise to it where they are lower. Raise it on a network that drops answers
under load, where short timeouts lose them.

#### `--max-rtt-timeout <time>`

The longest a probe's adaptive timeout may get. Default from the template:
10 s. The minimum and the initial timeout fall to it where they are higher.
It must be at least 5 ms, and below 20 ms it warns that accuracy may
suffer, as in nmap.

When more than one of the three is given, they are applied in nmap's order:
initial, then minimum, then maximum.

#### `--timeout <ms>`

A fixed timeout for every probe, in milliseconds: it sets the minimum,
maximum and initial RTT timeouts all to this value, so measured round
trips no longer change it. FeroProbe's own option, kept from before the
timeouts adapted; the RTT options given with it still apply on top. Below
20 ms it warns that accuracy may suffer.

#### `--retries <tries>`, `--max-retries <tries>`

The most times a probe that got no answer is sent again. Default from the
template: 10 (6 with `-T4`, 2 with `-T5`). `--max-retries` is nmap's name
for it and works the same. As in nmap it is a cap: a probe is resent once,
and more often only to hosts that lose probes (see
[Resends and delays](#resends-and-delays)). `0` turns resends off.

#### `-c <number>`, `--concurrency <number>`

The most probes waiting for an answer at once: the cap on the congestion
windows (see [Congestion control](#congestion-control)), and for connect
and UDP scans also the number of sockets open at once. Default from the
template: 500. nmap's names `--max-parallelism <number>` and `-M <number>`
work too. It must be at least 1, warns above 900, and warns when the number
is above the system's open-file limit (`ulimit -n`).

#### `--min-parallelism <number>`

Keep at least this many probes waiting at once: the congestion windows
never shrink below it, as in nmap, and it raises the template's `-c` (or
the one `--min-rate` picked) to this number if that is lower. It must be
at least 1, warns above 100, and is an error above an explicit
`-c`/`--max-parallelism`, with nmap's message.

#### `--max-rate <number>`

Send at most this many raw-socket packets per second (SYN and other raw
TCP probes, SCTP, IP protocol, ICMP, ARP and NDP). By default there is
no limit, as in nmap: the congestion windows and the scan delay pace the
probes. One rate holds for the whole run, across all scans and
hosts. Connect and UDP probes are bounded by the congestion windows,
`--concurrency` and `--scan-delay` instead.

#### `--min-rate <number>`

Send at least this many probes per second. It raises `--max-rate` to at
least this number, shortens a template's scan delay to fit, lets probes
through a full congestion window whenever the scan falls behind the rate,
and lets enough connect and UDP probes be in flight to keep up the rate
even when every probe waits out its initial timeout (up to the open-file limit, with a
warning when that limit, or an explicit `--concurrency`, may hold the rate
down). It is an error when it is 0, above an explicit `--max-rate`, or
when an explicit `--scan-delay` is too long for it.

#### `--scan-delay <time>`

Wait at least this long between probes, across all scan techniques
(`500ms`, `2s`, `5m`; a bare number is seconds). Default from the
template: none for `-T3` and up. The scan may raise the delay for a host
that loses probes (see [Resends and delays](#resends-and-delays)), but
never lowers it.

#### `--max-scan-delay <time>`

The longest delay between probes the scan may set on its own for a host
that loses probes (`100ms`, `1s`; a bare number is seconds). Default from
the template: 1 s, or for TCP, SCTP and IP protocol probes 10 ms with `-T4`
and 5 ms with `-T5`. An explicit `--scan-delay` above it raises it, as in
nmap; `--max-scan-delay` given explicitly applies to every scan type. It
never takes the delay below `--scan-delay`.

#### `--defeat-rst-ratelimit`

In a SYN scan, a reset that answers a resent probe no longer slows the
scan down. Many hosts rate-limit the resets they send for closed ports,
and the scan otherwise reads the missing ones as losses and backs off.
The price, as in nmap: a closed port whose reset was held back may be
reported `filtered`, and the port table then says `Some closed ports may be
reported as filtered due to --defeat-rst-ratelimit`. It is refused with
any other TCP scan type unless `--open` is given. `--open` turns it on by
itself, as in nmap, since closed and filtered ports are not shown then.

#### `--host-timeout <time>`

Give up on a host whose port scans and detection take longer than this
(`30s`, `5m`). Hosts then run on their own clocks, up to 32 at once,
sharing `--concurrency` and the packet rate. A timed-out host is reported
without port or OS results: `Skipping host <addr> due to host timeout` in
normal output, `Status: Timeout` in grepable output and `timedout="true"`
in XML. It is not traced. `0` means no limit, as in nmap.

The host timeout does not yet cover scripts (`--script`): a host that
finished its scans in time runs its scripts with their own limit,
`--script-timeout` (ten minutes by default), per script. Use that option to bound the script
phase.

#### `--min-hostgroup <size>`, `--max-hostgroup <size>`

As in nmap, hosts are pinged in batches of up to 4096 targets, then
port-scanned, traced and reported a group at a time; each group's results
are printed and written to the report files as soon as it finishes. The
group size is nmap's: 128 hosts for UDP or SCTP scans, 1024 divided by the
TCP port count (at least 64) for TCP scans, and 16 otherwise. A TCP scan of
more than 1000 ports at `-T4` or slower starts with a quick group of 4 hosts
(8 at `-T4`) to show results early. These two options hold the size
between `--min-hostgroup` (default 1) and `--max-hostgroup` (default
100000). A larger group can be faster; a smaller one reports sooner.
`--min-hostgroup` above `--max-hostgroup` is an error, and above 100 it
warns, as in nmap. A minimum above 4096 also raises the discovery batch to
it.

## Firewall/IDS evasion and spoofing

### Interface and source port

These two work against any target, like in nmap; they do not need
`--allow-public-evasion`.

#### `-e <interface>`

Send and receive on this network interface (`eth0`, `wlan0`, `tun0`, as
`ip link` names them), as nmap's `-e` does. Every socket of the scan is
bound to it: raw probes, the packet capture of IPv6 OS detection, ARP and
neighbour discovery, connect scans, UDP probes, version detection and the
reverse DNS queries of `--dns-servers`. The interface's own address is the
source of the probes (unless `-S` gives another), and only its networks
count as local for ARP and neighbour discovery: a target on another
interface's network is reached through `-e`'s interface, as if it were on
that link. Forward lookups of target names use the system resolver, which
is not bound.

It is an error when there is no such interface. Linux and macOS only.
Binding a socket to an interface needs root (or `CAP_NET_RAW`) on Linux
kernels older than 5.7; newer kernels allow it to any user. With `-v`,
FeroProbe prints the interface it uses.

#### `-g <portnum>`, `--source-port <portnum>`

Send probes from this source port, as nmap's `-g` does: some firewalls let
in anything from port 53 (DNS) or 20 (FTP data). It applies to:

- the raw TCP scans (`-sS`, `-sA`, `-sF`, ..., `--scanflags`), SCTP scans
  (`-sY`, `-sZ`) and the TCP, UDP and SCTP probes of the IP protocol scan
  (`-sO`);
- the raw TCP pings (`-PS`, `-PA` as root) and UDP pings (`-PU`);
- the UDP scan (`-sU`);
- OS detection (`-O`).

As in nmap, it does not apply to the connect scan (`-sT`; FeroProbe warns,
with nmap's message, and keeps the system's ports), to unprivileged TCP
pings (connects), to version detection, to traceroute (whose source port
tells its probes apart) or to DNS. `-g 0` warns that port 0 may not work;
the UDP probes, which go through the system's sockets, cannot be sent from
port 0 and keep a random port (the warning says so).

FeroProbe already sends every raw probe of a scan from one source port
(random, from 40000-59999), so `-g` only fixes which one; the probe
signature (`docs/responsible-use.md`) is unchanged. UDP probes from a fixed
port share it between sockets (`SO_REUSEADDR`), each connected to a
different target port. If another program holds the port, the UDP scan
fails with an error naming it. On Windows, sockets cannot share a UDP port
that way, so `-g` does not apply to UDP probes there (FeroProbe warns).

### Fragmentation, decoys and spoofed source

FeroProbe has nmap's fragmentation, decoy and spoofed-source options for
testing your own firewalls and intrusion detection, and for authorized
penetration tests. Unlike nmap, they are gated by an authorization model.

#### Authorization model

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

#### `--spoof-mac <MAC address, prefix, or vendor name>`

Send IPv4 probes and ARP requests in Ethernet frames from this hardware
address instead of the card's own, as nmap does. The argument is read as
nmap reads it:

- `0`: a random address (FeroProbe clears the multicast bit, which a
  source address must not have),
- hex digits, optionally separated by `:` (also `-` or `.`): a whole
  address, or its first bytes with the rest random (`00:0C:29` looks like
  VMware),
- anything else: a vendor name, matched without regard to case against the
  built-in vendor table, then against the installed IEEE list (see
  `--oui-file`), whose prefix is used with three random bytes
  (`--spoof-mac Raspberry`).

FeroProbe prints the address it chose (`Spoofing MAC address
00:0C:29:5A:11:03 (VMware)`). The next hop's address comes from the
kernel's neighbour table, or else from an ARP request sent from the spoofed
address. Answers to the spoofed address are picked up off the card (which
is told to accept that address, or put in promiscuous mode) and handed to
FeroProbe through the loopback interface, with any checksum the card left
unfinished filled in. TCP answers go with a deliberately wrong checksum:
FeroProbe's raw sockets read them first, and this host's TCP then drops
them instead of resetting each SYN-ACK from the real MAC address (nmap,
reading answers with pcap, draws no reset either). Packets of a connection
the system itself holds (version detection's, once the target has learnt
the spoofed address from the ARP requests) are passed on intact. With `-e`,
the probes leave through that interface, and the sockets that read IPv4
answers are not bound to it, since the answers come in through loopback. A
strict reverse-path filter
(`net.ipv4.conf.all.rp_filter=1`) drops those; FeroProbe warns, and only
answers sent to the card's own address are then seen.

Linux only, needs raw sockets. It covers raw IPv4 probes of every kind (the
port scans, host discovery, OS detection, traceroute), UDP scan probes
(which then go out on a raw socket) and ARP discovery. It does not cover
IPv6 probes, the TCP connect scan, version detection or DNS, whose packets
the system sends; FeroProbe warns when the scan includes any of them.
`--packet-trace` adds `ether-src=<MAC>` to each probe sent in a spoofed
frame. Like every SENT line it is printed just before the send, so it shows
a frame FeroProbe attempted to send, not proof that the frame left. Like
the other evasion options, public targets need `--allow-public-evasion`.

#### `--allow-public-evasion`

Authorize the options above against public targets, decoys and spoofed
sources you have permission to test.

With `--packet-trace` (and `--dry-run`), each fragment gets its own line,
so you see exactly what goes on the wire: the first fragment as `TCP
src:sport > dst:dport (frag)`, the later ones as `IP src > dst proto 6 frag
offset=N`, with a trailing `+` while more fragments follow. nmap shows only
the unfragmented probe there; see [Differences from nmap](#differences-from-nmap).

### Packet contents

These options change what goes into the probes. Unlike the options above
they need no authorization; `--badsum` needs raw sockets.

They apply, as in nmap, to the raw TCP scans, the UDP scan, the SCTP
scans, the IP protocol scan, the discovery pings and (all but
`--ip-options`) traceroute. OS detection keeps its own packets: it takes
`--ttl` but no payload, options or bad checksum. The connect scan and
version detection use the system's TCP stack, so none of them apply;
FeroProbe warns when the TCP scan is `-sT`. `--packet-trace` and
`--dry-run` show what was added: `len=N` for TCP data, `ttl=N`,
`ipopts={...}`, `badsum`, and `via <hop>` for a source route. The
options read as in nmap, such as `ipopts={ NOP RR{#0.0.0.0 0.0.0.0}}`,
with `#` before the slot the pointer names; received packets show their
options too, so a record route comes back filled in. Like nmap,
`--packet-trace` and `-d` also print the options once before the scan,
as bytes and as text.

#### `--data <hex string>`

Add these bytes after the header of each probe, written `0xdeadbeef`,
`\xde\xad\xbe\xef` or `deadbeef`. They replace the payload of ICMP echo
requests and of UDP probes (nmap does the same with its UDP payloads), so
those probes no longer carry FeroProbe's `feroprobe` and
`FeroProbeScan/1` markers; the TCP window mark stays (see
[docs/responsible-use.md](responsible-use.md)). Payloads over 1400 bytes
get nmap's warning that they may not be sent successfully. Only one of
`--data`, `--data-string` and `--data-length` may be given.

#### `--data-string <string>`

Like `--data`, with the bytes of this text.

#### `--data-length <number>`

Like `--data`, with this many random bytes (0 to 65435), drawn once for
the whole scan as nmap does.

#### `--ip-options <options>`

Send IPv4 probes with these IP header options, in nmap's notation:

- `R`: record route (room for 9 addresses),
- `T`: internet timestamp; `U`: timestamps with addresses,
- `L <hop> [<hop> ...]`: loose source route; `S <hop> ...`: strict source
  route. Up to 8 hops; the packet goes to the first hop and the target
  takes the last slot,
- raw bytes: `\x01\x07\x04...` in hex, `\1\7` in decimal, and `*N` to
  repeat the last byte (`\x01*4` is four NOPs).

The result is padded to a multiple of 4 bytes and may be at most 40.
IPv4 only: probes to IPv6 targets go without them, with a warning. With
`-f`/`--mtu` every fragment carries the whole header, options included, as
in nmap. Many routers drop packets with source routes. On systems other
than Linux only the probes FeroProbe builds whole (`-sO`, `-f`, `--mtu`,
`-D`, `-S`) carry the options, with a warning.

#### `--ttl <value>`

Send probes with this IP time-to-live (IPv6 hop limit), 0 to 255, instead
of a random one from 37 to 59. The system refuses an IPv4 TTL of 0 on
sockets whose header it writes, so with `--ttl 0` those probes go with TTL 1
(FeroProbe warns); probes it builds whole and IPv6 probes carry 0.

#### `--badsum`

Send TCP, UDP, SCTP, ICMP and IGMP probes with a checksum one less than
the right one, as nmap does. Hosts drop such packets, so an answer usually
comes from a firewall or IDS that did not check the checksum. UDP scan
probes then go out on a raw socket from the probe's port. It needs raw
sockets: without them FeroProbe warns and sends correct checksums. ICMPv6
checksums are always written by the kernel, so IPv6 echo requests keep
theirs.

## Output

### Normal output

The default report on standard output is nmap's "normal" layout:

```
Starting FeroProbe 0.7.0

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

Also write the normal report to a file. As in nmap, the file starts with a
comment line naming the version, the start time and the command line
(`# FeroProbe 0.7.0 scan initiated ... as: feroprobe -oN scan.nmap ...`),
which `--resume` reads, and ends with `# FeroProbe done at ...` instead of
the screen's summary line.

#### `-oX <file>`

Also write the XML report to a file, in nmap's `-oX` layout (including
`<trace>` for traceroute), so tools that import nmap XML can read it. The
root element says `scanner="feroprobe"`; see `--nmap-label`.

#### `-oS <file>`

Also write the normal report to a file in "script kiddie" spelling, as
nmap's `-oS` does: at random, letters become look-alikes (`4` for `A`, `3`
for `e`, `0` for `o`, `$` or `z` for `s`, `!`, `|` or `1` for `i`, and `s`
for `z`) or change case. Fingerprint lines (the `OS:` lines and the
unrecognized service replies) are left as they are, so they can still be
copied. It exists for parity with nmap; `-oA` does not include it.

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
unwritable path fails at once, as in nmap. A file's old content is
replaced when the first part of the new report is written, just before
the first host group is scanned, so a command that fails before scanning
leaves the previous report in place. The normal, XML, grepable and `-oS`
reports are then written a host group at a time as the scan goes (see
`--max-hostgroup`), so an aborted scan leaves reports of the hosts it
finished, which `--resume` can carry on from. The JSON report is a single
document and is written when the scan ends. A `--dry-run` writes no
reports and creates no files.

Report files are written through the handles opened at the start, so the
paths are not looked up again: replacing a report path with a link while
the scan runs does not redirect the report.

Under `sudo`, FeroProbe has already given up root when it opens the
report files (see [Giving up root under sudo](#giving-up-root-under-sudo)),
so it writes them as the user who ran `sudo`: they belong to that user,
and a path that user cannot write to fails as it would for them. When it
does run as root (`--keep-root`, or root without `sudo`), it refuses to
follow a symbolic link anywhere in a report's path, for a directory or the
file itself, unless root owns both the link and the directory holding it
and no other user can write to that directory (so `/dev/stdout` works, but
`sudo feroprobe --keep-root -oN /tmp/scan.txt` is refused when
`/tmp/scan.txt` is a link, whoever made it). The path is opened one
component at a time with `O_NOFOLLOW`, and an allowed link's target is
walked the same way, so a link it leads through is checked too and a link
swapped in at the last moment is refused, and a file root creates under `sudo --keep-root` is handed to
the invoking user. nmap writes its reports as root through any link.

#### `--append-output`

Add the reports to the end of the `-oN`, `-oX`, `-oS`, `-oG`, `-oJ` and
`-oA` files instead of replacing them, as nmap's `--append-output` does.
Each run adds a complete report, so a normal or grepable file collects one
report after another. An XML file then holds several `<nmaprun>`
documents one after another, each with its own `<?xml ...?>` header, which
XML parsers refuse as one document until it is split, just as with nmap;
a JSON file likewise holds one JSON document per run. Reports written to
standard output (`-`) are not affected.

#### `--stylesheet <path or URL>`

Link this XSL stylesheet from the XML report, through an
`<?xml-stylesheet href="..." type="text/xsl"?>` line after the
`<!DOCTYPE>` line, as nmap does. A browser that opens the report applies
the stylesheet and shows the report as a web page. The value is written as
given, so give a URL or a path that is valid where the report will be
opened.

Without `--stylesheet`, `--webxml` or `--no-stylesheet`, the report links
FeroProbe's own stylesheet, `feroprobe.xsl`: the copy installed with
FeroProbe as a `file://` URL (next to the binary, as in the release
archives, then `../share/feroprobe/` from the binary, then
`/usr/local/share/feroprobe/` and `/usr/share/feroprobe/`), or the bare
name `feroprobe.xsl` when no copy is found, as nmap does with `nmap.xsl`.
The stylesheet is `docs/feroprobe.xsl` in the source; it is written for
FeroProbe (nmap's `nmap.xsl` is not reused) and also shows nmap's own XML
reports. Most browsers refuse to apply a stylesheet to a local file or
from another site, so the reliable way to get a web page is to convert the
report:

```sh
xsltproc -o report.html /usr/share/feroprobe/feroprobe.xsl report.xml
```

Of `--stylesheet`, `--webxml` and `--no-stylesheet`, the last one given
wins, as in nmap.

#### `--webxml`

Link the published copy of FeroProbe's stylesheet,
`https://jkobierczynski.github.io/feroprobe/feroprobe.xsl`, instead of the
installed one, so the link works on machines where FeroProbe is not
installed. Short for `--stylesheet` with that URL.

#### `--no-stylesheet`

Leave the `xml-stylesheet` line out of the XML report.

#### `--resume <filename>`

Carry on with a scan that was aborted (with Ctrl-C, a lost connection, a
reboot), given its normal (`-oN`), XML (`-oX`) or grepable (`-oG`) report;
for `-oA`, any of the three files. As in nmap, it takes no other options,
except `--keep-root`, `--allow-public-evasion` and
`--override-ics-protection`. Under `sudo`, root is given up before the
report is read, so a scan whose report or files only root can reach is
resumed with `sudo feroprobe --keep-root --resume FILE` (a `--keep-root`
recorded in the report has no effect on this). The two authorizations are
explained below:

```
feroprobe --resume scan.gnmap
```

The command line is read back from the report, so the resumed scan runs
with the same options, targets and report files. Every target up to and
including the last host the report lists is skipped, and the scan continues
with the next one, appending to the existing reports (the command line is
run with `--append-output` added, as nmap does): the normal and grepable
files get a second `scan initiated` line, and the XML document is
continued rather than started again, so that it ends up complete. Like nmap, the file is searched
for grepable `Host:` lines first, then XML `<address>` elements, then normal
`Scan report for` lines.

Because the reports are written a host group at a time, hosts of the group
that was running when the scan stopped are scanned again. Hosts found down
are not listed in the reports, so those after the last listed host are
probed again too. Other things to know:

- If the report lists no finished host, the scan starts from the
  beginning, with a warning.
- If the last host it lists is not among the targets (the targets were
  given by a name that now resolves differently, for example), nothing is
  left to scan, as in nmap, with a warning.
- With `--randomize-hosts` the targets come in a different order each
  time, so some hosts may be scanned twice and others missed; a warning
  says so, as in nmap.
- The JSON report (`-oJ`) is written only when a scan ends, so the
  aborted run left none, and the one written after resuming lists only
  the hosts scanned since; a warning says so.
- The settings files and ICS protection apply to the resumed scan as they
  would to the command typed again.

A report is a plain text file that anyone can write, and resuming one runs
the command line it records: its targets, its options and its report
files. Treat a report you did not write yourself like a script someone
handed you; FeroProbe prints the command line it resumes on standard error
before anything else happens. Three safeguards, all differences from nmap:

- **Only the scan's own reports are appended to.** Every report file the
  recorded command line names (except `-` and `/dev/null`, `/dev/stdout`,
  `/dev/stderr`) must already exist and hold the report of that same scan:
  for `-oN`, `-oG` and `-oX`, a `scan initiated ... as:` line recording the
  same command line; for `-oS`, the mangled `Starting FeroProbe` line; for
  `-oJ`, nothing yet or a FeroProbe JSON document. Otherwise the resume is
  refused before anything is sent, and a missing report file is not
  created. nmap appends to whatever the recorded command line names, so a
  forged report can make it add text to any file the user can write (as
  root, any file), text the scanned hosts partly choose (a service's
  version string, for example).
- **Authorizations are given again.** If the recorded command line has
  `--allow-public-evasion` or `--override-ics-protection`, the resume is
  refused unless the same option is given beside `--resume`
  (`feroprobe --allow-public-evasion --resume scan.nmap`). A deliberate
  opt-in is not taken from a file. Given beside `--resume`, either option
  applies to the resumed scan, as it would to the command typed again.
- **Root is not kept for it.** Under `sudo`, the resumed scan runs as the
  user who ran `sudo` like any other (see
  [Giving up root under sudo](#giving-up-root-under-sudo)); with
  `--keep-root` or a root shell, the checks above still apply.

Files the command line reads (`-iL`, `--excludefile`, `--service-rules`,
`--oui-file`) are read as they would be for the command typed again, so
under `sudo` with root given up, only files the user could read anyway.

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
[Not shown](#normal-output) limit. When a host loses so many probes that
FeroProbe slows down for it, `-v` says so, as nmap does (`Increasing send
delay for 10.0.0.5 from 0 to 5 due to 11 out of 30 dropped probes since
last increase.`). The verbosity can be changed while the scan runs; see
[Runtime interaction](#runtime-interaction).

#### `-d`, `-dd`, `-d<level>`, `--debug[=<level>]`

Raise the debugging level, as nmap's `-d` does: each `-d` (or each extra
`d`, as in `-ddd`) raises the debugging level and the verbosity by one;
`-d<level>` (or `--debug=<level>`) sets both to `<level>`, from 0 to 10.
Options apply in command-line order, so `-v -d` gives verbosity 2 and
debugging 1, while `-vv -d1` gives 1 and 1. The level must be attached:
`-d 3` is `-d` followed by the target `3`. Like nmap's, `-d` also turns
on [`--reason`](#--reason). The output goes to standard error, with the
`-v` progress:

- `-d`: a timing report before the scan (`--------------- Timing report
  ---------------`, with the host group size, the RTT timeouts in
  milliseconds, `--max-scan-delay` for TCP, UDP and SCTP,
  `--min-parallelism` and the parallelism cap, `--max-retries`,
  `--host-timeout`, `--min-rate` and `--max-rate`; 0 means not set),
  `Increased max_successful_tryno for <host> to <n> (packet drop)` each
  time a host answers only a resent probe, which lets its probes be sent
  once more, and after the port scan `Final times for host <address>:
  srtt: <us> rttvar: <us>  to: <us>` with the host's smoothed round-trip
  time, its variance and its probe timeout in microseconds.
- `-d2`: `Discovered <state> port <port>/<protocol> on <host>` for ports
  in every state, not only open ones.
- With [`--iflist`](#--iflist), the reason a table could not be read.

nmap prints much more at high debugging levels (its scan engine's
internal state); FeroProbe prints the messages above and adds more where
they help.

#### `--stats-every <time>`

Print a progress line to standard error at this interval, for example
`Stats: 0:01:05 elapsed; TCP SYN scan: 45.20% done (4520 of 10000
probes)`. `0` turns it off. Pressing a key during the scan prints the same
line once; see [Runtime interaction](#runtime-interaction).

#### `--iflist`

Print the host's network interfaces and routes, then stop, in nmap's
layout. The interface table has one row per address of each interface
(an interface without addresses shows `(none)/0`), with its type
(`ethernet`, `loopback`, `point2point` or `other`), whether it is up, its
MTU and, for Ethernet, its MAC address. The route table lists each route
that goes through a listed interface, IPv4 first, then the longest
prefixes first, with its metric and gateway.

```
************************INTERFACES************************
DEV  (SHORT) IP/MASK        TYPE     UP MTU   MAC
lo   (lo)    127.0.0.1/8    loopback up 65536
eth0 (eth0)  192.168.0.5/24 ethernet up 1500  00:1A:2B:3C:4D:5E
eth0 (eth0)  fe80::5/64     ethernet up 1500  00:1A:2B:3C:4D:5E

**************************ROUTES**************************
DST/MASK       DEV  METRIC GATEWAY
192.168.0.0/24 eth0 100
0.0.0.0/0      eth0 100    192.168.0.1
fe80::/64      eth0 256
```

Needs no root and no target. The routes are read on Linux only for now;
elsewhere the route table shows `ROUTES: NONE FOUND(!)` (with `-d`, the
reason). On Windows neither table is available yet.

#### `--noninteractive`

Do not read keys from the terminal during the scan; see
[Runtime interaction](#runtime-interaction).

### Runtime interaction

While a scan runs in a terminal, FeroProbe reads single keys from it, as
nmap does:

| Key | Effect |
| --- | --- |
| `v` / `V` | Raise / lower the verbosity by one (`Verbosity Increased to 2.`) |
| `d` / `D` | Raise / lower the debugging level by one (`Debugging Increased to 1.`) |
| `p` / `P` | Turn the [packet trace](#--packet-trace) on / off (`Packet Tracing enabled.`) |
| `?` | List these keys |
| any other key | Print a status line, as [`--stats-every`](#--stats-every-time) does |

The keys take effect at once: a higher verbosity also lists more ports in
the final report. Their messages go to standard error, like the rest of
the progress output (nmap writes them to standard output). Keys are read
from the controlling terminal (`/dev/tty`), not standard input, so they
work with `-iL -`; only while FeroProbe is the terminal's foreground job,
so a scan started in the background with `&` reads nothing; and only
during the scan itself, not during `--dry-run` or after the scan. Line
editing and echo are turned off on the terminal while keys are read and
are restored when the scan ends, when FeroProbe exits, and on Ctrl-C.
Keys are not read when FeroProbe was started with SIGTTOU ignored or
blocked: the terminal could then not keep a scan that was moved to the
background from changing another job's settings.
`--noninteractive` turns key reading off. Not available on Windows yet.

### Comparing two scans

`feroprobe-diff FILE1 FILE2` compares two XML reports (`-oX`) and shows
what changed between them: hosts that came up or went away, ports that
opened or closed, and changed services, versions, OS matches and script
output. It is FeroProbe's counterpart of nmap's `ndiff`, with the same
options (`-v`, `--text`, `--xml`), output and exit status (0 same, 1
different, 2 error), and reads nmap's reports too. It is a separate program,
installed next to `feroprobe`; see feroprobe-diff(1) or
[docs/feroprobe-diff.md](feroprobe-diff.md).

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

With `--script`, `-sC` or `-A` the plan ends with a **Script scan** step
that says where scripts may run, before anything is sent:

- the **scope**: the hosts and ports every script connection is held to.
  A script may connect only to the host it runs against, and only on the
  TCP and UDP ports this scan probes there; FeroProbe refuses anything
  else. This is a hard ceiling, whatever the script is.
- the chosen scripts **by phase**: prerule (before the scan) and postrule
  (after it) scripts are named, and send nothing to the targets, as they
  get no network access; hostrule and portrule scripts are listed with
  what their rule keys on. For FeroProbe's built-in scripts that is the
  ports and service names the rule wants (`ssh-hostkey: TCP 22, or a TCP
  port named ssh`), scripts with the same rule on one line. A script from
  a file, an nmap `.nse` script above all, is named only: its rule is its
  own Lua code and declares no ports, so FeroProbe does not guess which
  ports it will pick. It runs inside the scope above. Scripts forced with
  `+` are named as running on every host or port.
- a **note** when a built-in script forced with `+` connects only over a
  protocol the scan does not probe, such as `ntp-info` or the `snmp-*`
  scripts (UDP) on a TCP-only scan: forced, they still run, but every
  connection they try is refused (quietly unless `-v`), so the note says
  so before the scan and names the option that would scan that protocol
  (`-sU`).

The connections scripts actually make show up afterwards with
[`--script-trace`](#--script-trace), and `-d2` logs each script run with
the host and port it ran against.

```
6. Script scan
   - 3 scripts: the scripts chosen by --script ssh-hostkey,clock-skew,/x/mine.nse
   - scope: a script may connect only to the host it runs against, on the ports this scan probes there; FeroProbe refuses any other connection. Here that is whichever of the 2 targets are found up, on 1 TCP port: 22
   - once per host that is up (hostrule), when the rule says yes:
     * clock-skew: a host other scripts noted a clock for; it sends nothing itself
   - once per port found open, open|filtered or unfiltered (portrule), when the rule says yes:
     * ssh-hostkey: TCP 22, or a TCP port named ssh
     * mine: the portrule is the script's own code and names no ports; it is asked about each port, inside the scope above
   - after the scan (postrule), sending nothing to the targets: clock-skew
   - to see the connections scripts actually make: --script-trace, or -d2 for each script run and the host and port it ran against
```

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
[Firewall/IDS evasion and spoofing](#firewallids-evasion-and-spoofing)).
As in nmap, `--packet-trace` also turns on the
[script trace](#--script-trace).

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
resends unanswered ones as its hosts' losses call for, up to `--retries`
times), and only names the
steps that depend on answers (`-sV`, `--traceroute`, reverse DNS)
instead of listing their probes. OS detection (`-O`) is listed probe by
probe for one try, with `<open>` and `<closed>` in place of the ports the
scan would find, and a count of its own in the last line. When the scan
covers a single TCP port it cannot find both an open and a closed one, so
the `<closed>` probes are left out (and with `--osscan-limit` no OS probes
are listed at all). Target hostnames are still resolved
through the system resolver, even with `-n` (give numeric addresses when no
DNS traffic is allowed), so the addresses shown are the real ones,
and the routing table is consulted (without sending) for the source
address. No reverse DNS query is made. With `--traceroute`, a note names
the TCP port traceroute would fall back to (or says hosts would not be
traced). With `-sV`, the notes describe its probes instead of listing them,
since they go only to the TCP ports found open and the UDP ports found
`open` or `open|filtered`: at the intensity in use, the
TLS-first ports, the probes meant for each scanned port, the listen probe,
then the other probes in the order they would be tried, for TCP and UDP.
With `--script`, the scripts are loaded (so a bad one fails the dry run)
and a note names each with its rules and the scope its sockets would have;
what scripts send is not listed, since their rules depend on what the scan
finds and what they send on the replies they get.

**A dry run is not a preview of nmap.** It lists FeroProbe's probes. nmap
run with the same options sends different packets, and some of its
features probe outside `-p`, so a dry run must not be used to check an
nmap command before running it. What nmap sends in addition or instead,
per option:

| Options | What nmap does differently |
| --- | --- |
| `-A` | Also runs its default scripts (`-sC`). Some probe outside `-p`: `ms-sql-info` sends a 1-byte UDP datagram to port 1434 of every host; others connect to the open ports and talk to the services |
| `-A` without root | Silently skips OS detection and traceroute (FeroProbe skips them with a warning) |
| `-sV` | Sends probes from its own database (dozens to an unrecognized port), first the `NULL` probe (listen) on every port, and runs its version scripts on open ports |
| `-O`, IPv4 | Sends 16 probes per host to an open TCP port, a closed TCP port and a closed UDP port. A closed port is one the scan found closed, else unfiltered; without one it picks a random TCP or UDP port between 30000 and 44780, regardless of `-p`. It also probes hosts without an open TCP port, and sends 2 ICMP echo requests even when discovery sends none. FeroProbe sends at most 9 probes per try, to scanned ports only |
| `-O`, IPv6 | Sends up to 17 probes per host, including a neighbour solicitation to on-link targets. Without a closed (or unfiltered) TCP port it skips the closed-port TCP probes; without a closed (or unfiltered) UDP port it picks a random one between 30000 and 44780, regardless of `-p` |
| `--traceroute` | Traces with the probe that got the best answer (TCP, UDP, SCTP or ICMP), else an ICMP echo |
| Raw TCP scans | TCP window 1024 instead of FeroProbe's signature 65109 |
| `-sU` | Payloads for many more ports, empty datagrams elsewhere (FeroProbe: `FeroProbeScan/1`) |
| `-f`, `--mtu` | Sends fragments too, but its `--packet-trace` shows the unfragmented packet |
| `-D` with `ME` | Sends the real probe at `ME`'s place, not last |
| `-g` with `-O` | Sends its OS detection probes from a run of source ports starting at the `-g` port, not all from it |
| `-g 0` with `-sU` or `-PU` | Sends the UDP probes from port 0 (FeroProbe cannot, and uses a random port, with a warning) |
| Default discovery without root | Only TCP connects to 80 and 443, no ICMP echo |
| `-PO` with protocol 1 | Its ICMP echo request is empty (FeroProbe's carries `feroprobe`) |
| `--script` | Its scripts may connect to any host and port they choose, beyond the scan's ports, and some prerule scripts broadcast on the local network (FeroProbe's scripts may reach only the host they run against, on ports the scan probed) |
| `-sL` with `-sV` or `--traceroute`, as root | Drops them, but the route lookup they cause can send ARP requests to local targets (FeroProbe refuses the combination) |

These come from nmap 7.99's source.

A dry run needs no root, writes no report files (it warns if `-oN`,
`-oX`, `-oS`, `-oG`, `-oJ` or `-oA` were given), and notes when a real run of the
same command would need raw-socket privileges. The evasion address check
still applies: a public address with `-f`, `--mtu`, `-D` or `-S` is
refused unless `--allow-public-evasion` is given.

This matters most on operational-technology and industrial-control
(OT/ICS) networks, where an unexpected packet can hang or reset a fragile
device such as a PLC or RTU. With `--dry-run`, an operator can check
every target, port, flag and fragment a command would send, and confirm it
stays within the approved scope, before any scan probe is sent. This does
not hold for `--script`: a dry run names each script and the ports its
sockets could reach, but not what it would send, so it cannot alone
approve script traffic on such a network (ICS protection refuses
`--script` for this reason).
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

Version detection, OS detection, the default scripts and traceroute; see
[Traceroute and aggressive mode](#traceroute-and-aggressive-mode).

#### `--override-ics-protection`

Run once despite ICS protection, allowing `-sV`, `-O`, `-A`, `-sC` and `--script`, with a
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

#### `--privileged`

Assume raw sockets work, for a process that has `CAP_NET_RAW` in a way
FeroProbe's check (opening a raw socket) does not see. A raw socket that
then cannot be opened fails the scan with an error.

#### `--unprivileged`

Act as an ordinary user: no raw sockets, so the connect scan and connect
pings by default, as without root. The last of `--privileged` and
`--unprivileged` wins.

#### `--keep-root`

Under `sudo`, stay root for the whole run. Without it, FeroProbe reads
its settings files as root and then becomes the user who ran `sudo`,
keeping only the network capabilities a scan needs; see
[Giving up root under sudo](#giving-up-root-under-sudo). Use it only when
the run must read or write a file that only root can reach (for example
`-oN /root/scan.txt`). nmap has no such option, since it always stays root.

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
command-line options win over all of them, with one exception: the
directory's `.feroproberc` may switch `ics_protection` on but not off. A
`ics_protection = false` there, when an earlier file switched it on, is
ignored with a warning naming both files (a working directory may be
shared, unpacked from an archive or cloned, and must not quietly undo your
own setting). A missing file is skipped; one that cannot be read, is not
valid TOML or gives a value of the wrong type stops the run. Unknown keys
only warn.

Since root reads these files under `sudo` from places an ordinary user
controls, each file is checked first: as root, a symbolic link is refused;
the file must be a regular file (not a pipe or device) of at most 64 KB,
not writable by every user; and a file owned by anyone other than root or
you (the user who ran `sudo`) is skipped with a warning. A TOML error
names the line and column, and repeats the parser's message only for your
own file. `-v` prints which files were read
and whether ICS protection is on. nmap has no such files.

The one setting is `ics_protection`, **off by default**: FeroProbe is a
general scanner and behaves like nmap unless you ask otherwise.

```toml
ics_protection = true
```

With it on:

- `-sV`, `-O`, `-A`, `-sC` and `--script` are refused before any name is
  resolved or packet sent, with a message naming the option and where
  protection was turned on. Version detection sends application-protocol
  probes (HTTP, TLS, ...) to every open port, and fragile PLCs and RTUs can
  fault or hang when, for example, their Modbus handler on port 502
  receives an HTTP request; scripts talk to services in whatever way they
  are written to. `--script-help` sends nothing and is never refused.
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
| `-sS`, `-sF`, `-sN`, `-sX`, `-sA`, `-sW`, `-sM`, `--scanflags`, `-sY`, `-sZ`, `-sO`, `-O`, `--traceroute`, `-f`, `--mtu`, `-D`, `-S`, `--badsum`, ARP and neighbour discovery, raw `-PS`/`-PA` pings, `-PP`, `-PM` | `-sT`, `-sU`, `-sV`, `-b`, `-sn`, `-Pn`, `-PS` and `-PA` (as connects), `-PU`, `-PE` (where an unprivileged ping socket exists), all output options, `--explain`, `--dry-run` |

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

### Giving up root under sudo

Only raw sockets need root. So when root runs FeroProbe under `sudo`, it
reads its settings files first and then becomes the user who ran `sudo`
(`SUDO_UID`, `SUDO_GID` and that user's groups) before it opens any other
file or starts a thread. On Linux it keeps just `CAP_NET_RAW`,
`CAP_NET_ADMIN` and `CAP_NET_BIND_SERVICE` (for `-g` below 1024), so every
raw-socket feature still works; on other systems, where raw scans are not
supported, it gives root up entirely. Everything else in the run (service
and banner parsing, TLS, `-iL`, `--excludefile`, `--service-rules`,
`--resume` and the report files) then happens as that user. `-v` prints a
line saying so.

This means a `sudo feroprobe` run reads and writes files with your own
permissions: `-iL /root/targets.txt` or `-oN /root/scan.txt` fail unless
you can reach them yourself. `--keep-root` stays root for such a run.
Root without `sudo` (a root shell with no `SUDO_UID`) keeps root, as there
is no other user to become.

nmap stays root for the whole run, which is why a sudoers entry that allows
only `nmap` is a well-known way to become root. Do not rely on a
restricted sudoers entry for FeroProbe either: `--keep-root`, and options
that read files, still put root's privileges in the hands of whoever runs
it. Grant the capability with `setcap` instead (above), or give such users
full `sudo`.

## Probe signature

FeroProbe's probes carry a stable, documented signature so that network
owners can recognize them:

- Raw TCP scans (`-sS`, `-sF`, `-sN`, `-sX`, `-sA`, `-sW`, `-sM`,
  `--scanflags`) set the TCP window to 65109 (`0xFE55`).
- UDP probes to ports without a service payload carry `FeroProbeScan/1\n`.
- ICMP and ICMPv6 echo requests (host discovery) carry the 9-byte payload
  `feroprobe`, where nmap's are empty.

A payload given with `--data`, `--data-string` or `--data-length` replaces
the UDP and ICMP echo markers (the TCP window mark stays), and the FTP
bounce scan (`-b`) sends only ordinary FTP commands to the relay.

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
| Probe signature | None (empty ICMP echo payload) | Raw TCP probes use window 65109; generic UDP probes carry `FeroProbeScan/1\n`; ICMP echo requests carry `feroprobe`. A `--data`, `--data-string` or `--data-length` payload replaces the UDP and echo markers, as nmap's replaces its payloads |
| FTP bounce scan (`-b`) | Allowed against any target through any relay | Public targets or a public relay need `--allow-public-evasion` |
| `--spoof-mac` | Allowed against any address; IPv6 frames spoofed too; `0` may pick a multicast address | Public targets need `--allow-public-evasion`; IPv4 and ARP only (IPv6 probes keep the real address, with a warning); `0` always picks a unicast address |
| `--badsum` with `-O` | Also spoils the OS-detection probes (nmap's checksum routine applies it to every packet), which makes their answers meaningless | OS-detection probes keep correct checksums |
| Unprivileged discovery | TCP connects to 80 and 443 only | The same, plus an ICMP echo through an unprivileged ping socket where the OS offers one |
| `--explain`, `--dry-run` | No equivalent | FeroProbe's own planning and checking options |
| Settings files, `ics_protection`, `--override-ics-protection` | No equivalent | FeroProbe's own; off by default, so default behaviour is unchanged. A `.feroproberc` in the working directory can switch protection on but not off |
| JSON output (`-oJ`) | No equivalent | FeroProbe's own format |
| XML `scanner` attribute | `nmap` | `feroprobe`, unless `--nmap-label` |
| XML stylesheet | Links `nmap.xsl`; `--webxml` links nmap.org's copy | Links FeroProbe's own `feroprobe.xsl`; `--webxml` links FeroProbe's published copy |
| Privileges under `sudo` | Stays root for the whole run | Becomes the user who ran `sudo` once the settings files are read, keeping only the network capabilities on Linux, so reports, `-iL` and other files are read and written as that user; `--keep-root` stays root (see [Giving up root under sudo](#giving-up-root-under-sudo)) |
| Report files as root | Written through any symbolic link | With `--keep-root` or without `sudo`: a link is refused unless root owns it and its directory and no other user can write there (`/dev/stdout` works); a new file under `sudo` belongs to the invoking user (see `-oA` under Output options) |
| NSE scripts | nmap's libraries | The NSE compatibility layer: FeroProbe's own modules under nmap's names, a subset of nmap's (see [NSE compatibility layer](#nse-compatibility-layer)); registries copied and merged rather than shared in place, threads run to completion when started, no raw packets, scripts cannot change port results |
| Service and OS signatures | nmap's databases | FeroProbe's own (nmap's cannot be redistributed); the OS database is much smaller than nmap's, so fewer hosts get a perfect match |
| UDP service payloads (`-sU`) | nmap's payload database: several probes per port (two DNS queries to 53, two NTP versions to 123, SNMPv1 and v3 to 161, three NetBIOS queries to 137), up to dozens with `-sV` | FeroProbe's own, one per port: DNS (53, 5353), NetBIOS NODE STATUS (137, transaction ID `0x4650` "FP", the request `nbstat` sends), NTP (123), SNMP (161) and SSDP (1900); every other port gets `FeroProbeScan/1\n`. nmap's payloads cannot be redistributed; one payload per service is enough to make it answer |
| OS detection probes (`-O`) | About 16 probes per try (6 SYNs with varied options, ECN, T2-T7 to open and closed ports, 2 ICMP echoes, a UDP probe to a closed port), with closed ports picked at random outside the scan when none was found, and hosts without an open port probed too | At most 9 probes per try (4 SYNs, ECN and an ACK to the open port; a SYN and an ACK to a closed port the scan found; an ICMP echo only if discovery sends echo requests). No UDP probe, no T3/T5-T7-style odd flag combinations, no random ports, and hosts without an open TCP port are not probed. The price: fewer tests, so some systems nmap tells apart look alike |
| OS uptime and TCP sequence lines (`-O -v`) | `Uptime guess` from the TCP timestamps, `TCP Sequence Prediction` difficulty | Not printed. Most current systems give each connection its own random timestamp offset, so the uptime nmap prints for them is wrong; sequence predictability is left out with it |
| Port names | nmap-services | The same names for the common ports, from the IANA registry, and `unknown` for the rest. nmap-services cannot be redistributed |
| Timeouts | Adapt to measured round-trip times | The same (nmap's formula, limits and template values); `--timeout` fixes them, an option nmap does not have |
| Congestion control, `--max-retries`, `--max-scan-delay` | Windows per host and group between `--min-parallelism` and `--max-parallelism`; resends as losses show up, up to `--max-retries`; raises a lossy host's scan delay, saying so with `-v` | The same, except: a connect or UDP probe that already gave up is not sent again when its host's resends go up later; no timing pings to detect losses; the raised delays are not reported |
| `-g` with UDP scans | Raw UDP packets from the port, any port including 0 | UDP probes go through the system's sockets, which share the port between them; port 0 cannot be used and falls back to a random port, with a warning |
| Old-style IPv4 numbers as targets (`2222`, `10.1.2`, `010.0.0.1`) | Passed to the resolver | Refused with an explanation |
| Probes outside the requested ports | `-A`'s scripts can probe other ports (`ms-sql-info`: UDP 1434 on every host); `-O` picks a random UDP port (and for IPv4 also TCP), regardless of `-p`, when the scan found no closed or unfiltered one | Never beyond the command's own ports (`-p` plus the host-discovery ports): `-sV` probes only open ports the scan found, `-O` an open TCP port the scan found and, when it found one, a closed one (and ICMP echo only when discovery sends it), traceroute only a scanned port, a discovery port, or (with `-sn`) the `-p` port, and scripts only the ports the scan probed on the host they run against |
| Traceroute port | The probe that got the best answer during discovery or the scan, else ICMP echo | TCP SYNs to an open or closed scanned port, else a TCP port the command names (`-p` with `-sn`, or a discovery port), else the host is not traced (FeroProbe used to fall back to port 80) |
| `-A` without root | Silently drops `-O` and traceroute | Drops them with a warning naming them |
| `-sL` with `-P` options | Ignores them silently | Ignores them with a warning per option |
| `-sL` with `-sV` or `--traceroute` | Silently drops them (and as root still looks up routes, so local targets can get ARP requests) | Refuses the combination; a list scan sends the targets nothing at all |
| `-PR` | A no-op; says so only with `-v` | A no-op; says so on every run |
| Script library | nmap's NSE libraries (`stdnse`, `shortport`, `nmap.new_socket`, ...) and its own scripts | FeroProbe's own `fero` library and scripts (nmap's cannot be shipped under their licence); nmap's scripts run only when they use the modules of the [NSE compatibility layer](#nse-compatibility-layer) |
| Script sockets | A script may connect anywhere; prerule scripts may broadcast | Only to the host the script runs against, on ports the scan probed there; prerule and postrule scripts get no network access. A refused connection prints a warning |
| Script sandbox | Scripts may read and write files and run commands (`io`, `os`) | No files, commands or environment; memory and instruction limits per run |
| Script output text | Every byte outside printable ASCII shown as `\xHH` | UTF-8 text kept; control characters and invalid bytes shown as `\xHH` |
| Script table output | Named entries in Lua's traversal order (unpredictable) unless the script orders them | Named entries sorted by name |
| Script output on folded ports | Not shown when the port's state is folded into `Not shown` | The port is listed with its output |
| `fero.args.get` of a bare flag | `stdnse.get_script_args` returns `1` | Returns `true` |
| `--script-help` | Prints a link to nmap.org's documentation of each script, and writes `-oX` XML | Prints where the script came from (built in, or its file); no XML |
| Default scripts (`-sC`) | nmap's own set of over a hundred scripts, some reaching other ports (`ms-sql-info`: UDP 1434) or outside hosts (`http-open-proxy`) | FeroProbe's own, smaller set (see [Built-in scripts](#built-in-scripts)), within the scan's scope. `ftp-anon` lists no files, `sshv1` reads the greeting only, `smtp-commands` sends no HELP, `ssh-hostkey` has no `visual` or `bubble` form and offers no ECDH key exchange on NIST curves |
| Script traffic signature | `SSH-2.0-Nmap-SSH2-Hostkey`; EHLO with the target's own name, else `nmap.scanme.org`; FTP password `IEUser@` | `SSH-2.0-FeroProbe_Scripting_Engine`, `EHLO feroprobe.invalid`, FTP password `feroprobe@` (see `docs/responsible-use.md`) |
| `*-ntlm-info` scripts | NTLM NEGOTIATE with no workstation; `ms-sql-ntlm-info` first asks UDP 1434 for instances; SMTP, IMAP, POP3 and NNTP leave the AUTH exchange open when they close; `telnet-ntlm-info` reads the challenge with any doubled 0xff bytes left in | NEGOTIATE naming the workstation `FEROPROBE` (rules 9100016, 9100017); `ms-sql-ntlm-info` asks only the scanned TCP port; the AUTH exchange is cancelled (`*`) before QUIT (NNTP has no cancel); doubled 0xff bytes are undone. A failed STARTTLS costs POP3 and NNTP a second connection (nmap's carry on in plain text on the first) |
| `smb-os-discovery` | Logs in (anonymously, then as guest) on its two connections to read the OS strings; keeps the NUL that ends the workgroup or domain name (`Workgroup: WORKGROUP\x00`), so a domain member's `NetBIOS domain name` line is left out; notes the clock for `clock-skew` with the time zone taken off a time that is already UTC (a skew the size of the zone); prints `OS: Unknown` when the server gives a NativeOS but no NativeLanMan; can fill in the `-sV` version column | Logs in to nothing: the OS strings and names come from the answer to the first leg of a session setup, and the NTLM challenge is never answered; names without the NUL; the clock noted as the UTC time it is; a NativeOS alone is shown; the `-sV` columns are left alone, as by every script |
| `smb-security-mode` | Names the account it would log in with (`account_used: guest`), although it logs in to nothing | No `account_used` line: no account is used |
| SNMP scripts | `snmp-info` names every registered enterprise from nmap's copy of the IANA list and sets the port's version; `snmp-sysdescr` and `snmp-interfaces` set the port `open` when the agent answers; `snmp-interfaces` walks the whole `ifTable`, shows one address per interface, and can run before the scan against `snmp-interfaces.host`, adding its addresses as targets | `snmp-info` names some 40 common vendors and shows other enterprise numbers as numbers, and leaves `-sV`'s result alone; the port state is the scan's; `snmp-interfaces` reads only the columns it shows (about half the requests), shows every address, and runs only against scanned ports. Every SNMP request has request-id `0x4650` ("FP") |
| SMB2 NEGOTIATE client capabilities (`smb2-capabilities` and the other `smb2-*` scripts) | 0, so servers leave out the SMB3 capabilities they grant only to clients that have them (multi-channel, persistent handles, directory leasing, 3.0 encryption) | DFS, leasing, large MTU, multi-channel, persistent handles, directory leasing and encryption whenever an SMB 3.x dialect is offered (0 for 2.0.2 and 2.1 alone), so `smb2-capabilities` lists what the server supports. Neither reads 3.1.1's encryption context, so 3.1.1 never lists Encryption |
| SMB script signature | Session setup NativeOS `Nmap`, NativeLanMan `Native Lanman`; a random SMB1 process ID; SMB2 client GUID `1234567890123456` | SMB1 process ID `0x5046` ("FP"), SMB1 NativeOS and NativeLanMan `FeroProbe`, SMB2 client GUID `FeroProbeSMBScan`, NTLM workstation `FEROPROBE` (see `docs/responsible-use.md`) |
| `--resume` | Runs the recorded command line as it is, creating or appending to any report file it names | Prints the command line first; appends only to existing files that hold that scan's report (creates none); a recorded `--allow-public-evasion` or `--override-ics-protection` must be given again beside `--resume` |

Behaviour that looks unusual but matches nmap includes: skipping discovery
for this machine as root (`localhost-response`), ARP or neighbour discovery
deciding local hosts alone, the default discovery probes, the 25-port
`Not shown` rule, `--exclude-ports` thinning the ping probes, shuffled port
order, and skipping (rather than failing) a scan type left without ports.

## nmap options FeroProbe does not have

These nmap options are refused as unknown:

- Scans and discovery: `-sI` (idle scan, not planned), `-iR`,
  `--resolve-all`.
- Output and misc: `--port-ratio`.

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

FeroProbe needs no other data files: its port rankings, service rules,
OS signatures and scripts are built into the binary. Scripts of your own
are read from the files and directories `--script` names.

## Examples

```sh
# Discover hosts on a network, then scan their 1000 most common TCP ports
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
- feroprobe-diff(1), [docs/feroprobe-diff.md](feroprobe-diff.md): compare
  two scan reports
- `rules/`: Suricata and Snort rules that detect FeroProbe's probes
- nmap(1)
