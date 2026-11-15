# Development status

This file tracks what FeroProbe implements and what is still missing compared
with nmap. **Update it in the same pull request that adds, changes or drops a
feature**, so it stays the one place to see where the project stands.

The goal is nmap parity: FeroProbe behaves like nmap unless nmap's behaviour is
clearly wrong. Two deliberate exceptions are listed under
[Not planned](#not-planned) and [Anti-abuse safeguards](#anti-abuse-safeguards).

Last audited against the source: 2026-11-15 (main at `34559fb`, v0.2.0 plus
the SCTP, IP protocol, IPv6 OS detection and probe-signature work).

## Implemented

### Scan types

| Feature | Options | Notes |
| --- | --- | --- |
| TCP connect scan | `-sT` | No privileges needed; default when not root |
| TCP SYN scan | `-sS` | Raw sockets (Linux, root or `CAP_NET_RAW`); default when root. IPv4 and IPv6 |
| FIN, NULL, Xmas scans | `-sF`, `-sN`, `-sX` | Raw sockets, IPv4 and IPv6 |
| ACK, Window, Maimon scans | `-sA`, `-sW`, `-sM` | Raw sockets, IPv4 and IPv6 |
| Custom TCP flags | `--scanflags` | Names (`SYNFIN`) or a number; answers read like the chosen scan type |
| UDP scan | `-sU` | Service payloads for DNS, NTP, SNMP, SSDP; generic probes carry the FeroProbe marker |
| SCTP INIT and COOKIE ECHO scans | `-sY`, `-sZ` | Raw sockets, IPv4 and IPv6 (`crates/feroprobe-core/src/sctp.rs`) |
| IP protocol scan | `-sO` | Protocol numbers via `-p P:...`, real probes for ICMP/IGMP/TCP/UDP/SCTP (`ipproto.rs`) |
| Ping scan only | `-sn` | Host discovery without a port scan |

### Host discovery and names

| Feature | Options | Notes |
| --- | --- | --- |
| Default discovery | (none) | ICMP/ICMPv6 echo plus TCP 443 and 80 |
| Skip discovery | `-Pn` | |
| Ping probe types | `-PS`, `-PA`, `-PU`, `-PE`, `-PP`, `-PM` | With port lists, repeatable |
| ARP on the local network (IPv4) | default as root, `--disable-arp-ping` / `--send-ip` | MAC address and vendor |
| Neighbour discovery (IPv6) | default as root | MAC address and vendor (`ndp.rs`) |
| MAC vendor names | `--oui-file` | Full IEEE OUI list from the system or a file, small built-in fallback |
| Reverse DNS | `-n`, `-R`, `--dns-servers` | Own resolver for `--dns-servers` (`dns.rs`) |
| Random host order | `--randomize-hosts` | |
| Traceroute | `--traceroute` | TCP SYN probes, IPv4 and IPv6 (`trace.rs`) |

### Targets and ports

| Feature | Options | Notes |
| --- | --- | --- |
| Target forms | positional | IPv4/IPv6 addresses, CIDR, `a.b.c.X-Y` ranges, `fe80::1%eth0`, hostnames; old-style IPv4 numbers refused |
| IPv6 address of hostnames | `-6` | |
| Target lists | `-iL` | `-` for standard input |
| Exclusions | `--exclude`, `--excludefile` | |
| Port specs | `-p` | Ranges, `-p-`, `T:`/`U:`/`S:`/`P:` prefixes, mismatch warnings like nmap's |
| Common ports | `--top-ports`, `-F` | |
| Port exclusions | `--exclude-ports` | Also removed from the ping probes, like nmap |
| Port order | `-r` | Shuffled by default, like nmap |

### Service and version detection

| Feature | Options | Notes |
| --- | --- | --- |
| Version detection | `-sV`, `--version-timeout` | Our own probes and rules (`service/rules.rs`), not nmap's licensed database. TLS first on TLS ports (rustls), shows the certificate name |
| Probed protocols | | HTTP, Redis, memcached, PostgreSQL, AMQP, MQTT, RDP, MS SQL, SMB, LDAP, MongoDB, ZooKeeper, RTSP, SIP |
| Banner protocols | | SSH, FTP, SMTP, POP3, IMAP, MySQL, VNC, rsync, NNTP, IRC |
| UDP version probes | | DNS `version.bind`, NTP, SNMP (`service/udp_info.rs`) |
| Unrecognized replies | | Printed so new rules can be written from them |

### OS detection

| Feature | Options | Notes |
| --- | --- | --- |
| OS guess | `-O` | One SYN to an open port; TTL / hop limit, TCP option order, DF bit, window. Our own family-level signatures (`os.rs`). IPv4 and IPv6 (IPv6 read off an `AF_PACKET` capture) |
| Network distance | | From the TTL |
| Aggressive mode | `-A` | `-sV -O --traceroute`; only `-sV` without raw-socket privileges |

### Timing and performance

| Feature | Options | Notes |
| --- | --- | --- |
| Timing templates | `-T0` … `-T5` (or names `paranoid` … `insane`) | Set timeout, retries, parallelism, rate and scan delay (`timing.rs`); explicit flags override |
| Probe timeout and retries | `--timeout`, `--retries` | |
| Parallelism | `-c`, `--concurrency` | Connect and UDP probes in flight |
| Packet rate | `--min-rate`, `--max-rate` | One shared rate schedule for the whole run |
| Delay between probes | `--scan-delay` | |
| Per-host time limit | `--host-timeout` | |
| Progress | `--stats-every`, `-v`, `-vv` | |
| Benchmarks | | criterion benches in `crates/feroprobe-core/benches` |

### Output

| Feature | Options | Notes |
| --- | --- | --- |
| Normal (table) output | default, `-oN` | |
| nmap-style XML | `-o xml`, `-oX`, `--nmap-label` | nmap's `-oX` layout incl. `<trace>`; `scanner="feroprobe"` unless `--nmap-label` (`xml.rs`) |
| Grepable output | `-o grepable`, `-oG` | One line per host, like nmap's (`grep.rs`) |
| JSON output | `-o json`, `-oJ` | FeroProbe's own format |
| All formats at once | `-oA` | `.nmap`, `.xml`, `.gnmap` |
| Port state reasons | `--reason` | |
| Open ports only | `--open` | |
| Packet trace | `--packet-trace` | `SENT`/`RCVD`/`CONN` lines like nmap's |
| Plan explanation | `--explain` | FeroProbe's own: the plan with a reason for each step |
| nmap-style help and warnings | `-h`, `--help` | Help page laid out like nmap's; nmap's warnings for names, down hosts, option values |

### Anti-abuse safeguards

| Feature | Notes |
| --- | --- |
| Recognizable probe signature | Raw TCP scans use window 65109 (`0xFE55`); generic UDP probes carry `FeroProbeScan/1\n`. Documented in `docs/responsible-use.md` |
| IDS rules | Suricata (`rules/feroprobe.rules`) and Snort (`rules/feroprobe.snort.rules`) |

### Platform and project

| Feature | Notes |
| --- | --- |
| Linux | Everything; raw-socket features need root or `CAP_NET_RAW` |
| macOS, Windows | Connect scan, UDP, discovery, `-sV`, all output formats |
| CI | ubuntu, macOS, Windows, plus a root job for raw sockets |
| Releases | `release.yml` builds binaries on `v*` tags |
| Live test scripts | `scripts/test-sctp.sh`, `scripts/test-os6.sh` |

## In review

| Feature | Options | Pull request |
| --- | --- | --- |
| Fragmentation, decoys, spoofed source | `-f`, `--mtu`, `-D`, `-S` | #23. Refused unless every target is in a private range (RFC 1918, loopback, link-local, CGNAT, IPv6 ULA) and the scan is a raw IPv4 TCP scan |

Move these to [Implemented](#implemented) when the pull request merges.

## Remaining gap to nmap parity

### Large

| Feature | nmap options | Notes |
| --- | --- | --- |
| Scripting engine | `-sC`, `--script`, `--script-args` | NSE scripts can't be shipped (licence) and an embedded language would not run them. Skipped for now, see below |
| Deeper version detection | `--version-intensity`, `--version-light`, `--version-all`, `--version-trace` | Our rule set covers about 25 protocols; nmap's database has thousands of signatures |
| Full OS fingerprinting | `--osscan-limit`, `--osscan-guess`, `--max-os-tries` | We send one probe and guess the family; nmap sends 16 probes and names versions |

### Medium

| Feature | nmap options | Notes |
| --- | --- | --- |
| Resume an aborted scan | `--resume` | Planned (phase 4, step 6) |
| Compare two reports | `ndiff` | Planned (phase 4, step 7) |
| List scan | `-sL` | List targets (and names) without sending probes |
| More ping types | `-PR`, `-PO`, `-PY` | ARP happens automatically, but can't be asked for alone; IP protocol and SCTP ping are missing |
| RTT-based timeouts | `--min-rtt-timeout`, `--max-rtt-timeout`, `--initial-rtt-timeout` | We use a fixed `--timeout` |
| Host groups and parallelism | `--min-hostgroup`, `--max-hostgroup`, `--min-parallelism`, `--max-parallelism`, `--max-retries` | We have `-c` and `--retries` under our own names |
| Interface and source port | `-e`, `-g` / `--source-port` | |
| Interactive keys during a scan | `v`, `d`, `p`, ... | |
| Debug output | `-d`, `--iflist` | |
| Output extras | `--append-output`, `-oS`, `--stylesheet`, `--webxml`, `--no-stylesheet` | |

### Small

| Feature | nmap options | Notes |
| --- | --- | --- |
| Spoofed MAC | `--spoof-mac` | Would fall under the private-range gate |
| Padding and payloads | `--data-length`, `--data`, `--data-string` | |
| IP header options | `--ttl`, `--ip-options` | |
| Bad checksums | `--badsum` | |
| FTP bounce scan | `-b` | |
| Random targets | `-iR` | Would conflict with the anti-abuse stance |
| Misc | `--privileged`, `--unprivileged`, `--system-dns`, `--port-ratio`, `--defeat-rst-ratelimit` | |

### Not planned

| Feature | Why |
| --- | --- |
| Idle scan `-sI` | Dropped: little use beyond teaching, and nmap already covers that |
| nmap's probe, service and OS databases | Their licence does not allow redistributing them; FeroProbe writes its own |
