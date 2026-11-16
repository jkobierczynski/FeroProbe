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

Well-known ports get a payload their service answers: DNS (53, 5353), NTP
(123), SNMP (161) and SSDP (1900). Every other port gets the payload
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

A reply no rule recognizes is shown with a `?` after the usual service
name for the port and, at intensity 7 or more (as in nmap), printed under
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

The rule is named by its line in the rules file (or as a built-in parser
or the built-in HTTP header reader), which makes the trace the tool for
writing and debugging rules. nmap's version trace also prints its network
library's debug lines; FeroProbe prints only the lines above.

#### `--service-rules <file>`

Read the probes and rules from `<file>` instead of the built-in ones. The
file replaces the built-in rules completely, so start from a copy of
[`crates/feroprobe-core/data/service-rules.txt`](../crates/feroprobe-core/data/service-rules.txt).
A mistake in the file stops the scan before anything is sent, naming the
line. nmap's `--versiondb` takes nmap's own format; FeroProbe does not read
that format and says so if given an `nmap-service-probes` file.

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

A probe with no payload, like `null`, connects and listens. The built-in
parsers for binary replies (SQL Server, SMB, RDP, LDAP, DNS, NTP, SNMP,
SSDP and NetBIOS) run on the replies to the probes of those names.

`match SERVICE REGEX` and `softmatch SERVICE REGEX` define a rule. The
regular expression is the rest of the line, run on the raw reply with
`.` matching any byte, newlines included, and `\xNN` matching byte `NN`
(Rust regex syntax, flags `(?s-u)`); write `\x20` for a space at either end.
Rules are tried in file order, hard matches before soft ones, and the
first match wins. A soft match takes only `probe`. Attributes:

| Attribute | Meaning |
| --- | --- |
| `probe NAME` | Only read replies to this probe |
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

#### `--host-timeout <time>`

Give up on a host whose port scans and detection take longer than this
(`30s`, `5m`). Hosts then run on their own clocks, up to 32 at once,
sharing `--concurrency` and the packet rate. A timed-out host is reported
without port or OS results: `Skipping host <addr> due to host timeout` in
normal output, `Status: Timeout` in grepable output and `timedout="true"`
in XML. It is not traced. `0` means no limit, as in nmap.

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
Starting FeroProbe 0.4.0

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
(`# FeroProbe 0.5.0 scan initiated ... as: feroprobe -oN scan.nmap ...`),
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
the scan runs does not redirect the report. When FeroProbe runs as root
(for example under `sudo`), it also refuses to write a report through a
symbolic link that another user owns in a shared directory with the sticky
bit, such as `/tmp` (for example `sudo feroprobe -oN /tmp/scan.txt` when
someone else has made `/tmp/scan.txt` a link to a system file). Linux
refuses this too when `fs.protected_symlinks` is on; FeroProbe checks it
on every system. The files are created with the usual permissions from the
umask and owned by root, as with nmap.

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
for `-oA`, any of the three files. As in nmap, it takes no other options:

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
[Firewall/IDS evasion and spoofing](#firewallids-evasion-and-spoofing)).

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
- ICMP and ICMPv6 echo requests (host discovery) carry the 9-byte payload
  `feroprobe`, where nmap's are empty.

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
| Probe signature | None (empty ICMP echo payload) | Raw TCP probes use window 65109; generic UDP probes carry `FeroProbeScan/1\n`; ICMP echo requests carry `feroprobe` |
| Unprivileged discovery | TCP connects to 80 and 443 only | The same, plus an ICMP echo through an unprivileged ping socket where the OS offers one |
| `--explain`, `--dry-run` | No equivalent | FeroProbe's own planning and checking options |
| Settings files, `ics_protection`, `--override-ics-protection` | No equivalent | FeroProbe's own; off by default, so default behaviour is unchanged |
| JSON output (`-oJ`) | No equivalent | FeroProbe's own format |
| XML `scanner` attribute | `nmap` | `feroprobe`, unless `--nmap-label` |
| XML stylesheet | Links `nmap.xsl`; `--webxml` links nmap.org's copy | Links FeroProbe's own `feroprobe.xsl`; `--webxml` links FeroProbe's published copy |
| Report files as root | Written through any symbolic link | A link another user owns in a sticky shared directory such as `/tmp` is refused (see `-oA` under Output options) |
| Service and OS signatures | nmap's databases | FeroProbe's own (nmap's cannot be redistributed); the OS database is much smaller than nmap's, so fewer hosts get a perfect match |
| UDP service payloads (`-sU`) | nmap's payload database: several probes per port (two DNS queries to 53, two NTP versions to 123, SNMPv1 and v3 to 161, three NetBIOS queries to 137), up to dozens with `-sV` | FeroProbe's own, one per port: DNS (53, 5353), NTP (123), SNMP (161) and SSDP (1900); every other port gets `FeroProbeScan/1\n`. nmap's payloads cannot be redistributed; one payload per service is enough to make it answer |
| OS detection probes (`-O`) | About 16 probes per try (6 SYNs with varied options, ECN, T2-T7 to open and closed ports, 2 ICMP echoes, a UDP probe to a closed port), with closed ports picked at random outside the scan when none was found, and hosts without an open port probed too | At most 9 probes per try (4 SYNs, ECN and an ACK to the open port; a SYN and an ACK to a closed port the scan found; an ICMP echo only if discovery sends echo requests). No UDP probe, no T3/T5-T7-style odd flag combinations, no random ports, and hosts without an open TCP port are not probed. The price: fewer tests, so some systems nmap tells apart look alike |
| OS uptime and TCP sequence lines (`-O -v`) | `Uptime guess` from the TCP timestamps, `TCP Sequence Prediction` difficulty | Not printed. Most current systems give each connection its own random timestamp offset, so the uptime nmap prints for them is wrong; sequence predictability is left out with it |
| Port names | nmap-services | The same names for the common ports, from the IANA registry, and `unknown` for the rest. nmap-services cannot be redistributed |
| Timeouts | Adapt to measured round-trip times | The same (nmap's formula, limits and template values); `--timeout` fixes them, an option nmap does not have |
| Congestion control, `--max-retries`, `--max-scan-delay` | Windows per host and group between `--min-parallelism` and `--max-parallelism`; resends as losses show up, up to `--max-retries`; raises a lossy host's scan delay, saying so with `-v` | The same, except: a connect or UDP probe that already gave up is not sent again when its host's resends go up later; no timing pings to detect losses; the raised delays are not reported |
| `-g` with UDP scans | Raw UDP packets from the port, any port including 0 | UDP probes go through the system's sockets, which share the port between them; port 0 cannot be used and falls back to a random port, with a warning |
| Old-style IPv4 numbers as targets (`2222`, `10.1.2`, `010.0.0.1`) | Passed to the resolver | Refused with an explanation |
| Probes outside the requested ports | `-A`'s scripts can probe other ports (`ms-sql-info`: UDP 1434 on every host); `-O` picks a random UDP port (and for IPv4 also TCP), regardless of `-p`, when the scan found no closed or unfiltered one | Never beyond the command's own ports (`-p` plus the host-discovery ports): `-sV` probes only open ports the scan found, `-O` an open TCP port the scan found and, when it found one, a closed one (and ICMP echo only when discovery sends it), traceroute only a scanned port, a discovery port, or (with `-sn`) the `-p` port, and FeroProbe has no scripts |
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
- Timing: `--defeat-rst-ratelimit`.
- Evasion and packet options: `--spoof-mac`, `--data`, `--data-string`, `--data-length`, `--ip-options`, `--ttl`,
  `--badsum`.
- Output and misc: `-oS`, `--append-output`, `--stylesheet`,
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
- `rules/`: Suricata and Snort rules that detect FeroProbe's probes
- nmap(1)
