# Development status

This file tracks what FeroProbe implements and what is still missing compared
with nmap. **Update it in the same pull request that adds, changes or drops a
feature**, so it stays the one place to see where the project stands.

The goal is nmap parity: FeroProbe behaves like nmap unless nmap's behaviour is
clearly wrong. The deliberate exceptions are listed under
[Not planned](#not-planned), [Anti-abuse safeguards](#anti-abuse-safeguards)
and [Deliberate differences from nmap](#deliberate-differences-from-nmap).

Last audited against the source: 2026-11-15 (main at `34559fb`, v0.2.0 plus
the SCTP, IP protocol, IPv6 OS detection and probe-signature work).

## Documentation

| Document | What it covers | Keep it current |
| --- | --- | --- |
| [README.md](README.md) | Overview, install, quick start and examples | When a headline feature changes |
| [docs/manual.md](docs/manual.md) | The reference manual: every option with its syntax, default and interactions, nmap-style sections, the differences from nmap | In the same pull request as any option or behaviour change. A test (`every_option_is_in_the_manual` in `crates/feroprobe-cli/src/help.rs`) fails when an option has no heading there |
| [docs/feroprobe.1](docs/feroprobe.1) | The man page, generated from `docs/manual.md` | Rebuild with `scripts/build-manpage.sh` (needs pandoc) whenever the manual changes, and commit both |
| `--help` (`crates/feroprobe-cli/src/help.rs`) | One-page option summary, laid out like nmap's | A test fails when an option is missing |
| [docs/responsible-use.md](docs/responsible-use.md) | The anti-abuse safeguards and why they exist | When a safeguard changes |
| [rules/README.md](rules/README.md) | The Suricata and Snort rules for the probe signature | When the signature changes |
| This file | Implemented features and the gap to nmap | With every feature change |

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
| Default discovery | (none) | nmap's defaults: as root, raw ICMP echo, SYN to 443, ACK to 80 and ICMP timestamp (IPv4); unprivileged, TCP connects to 80 and 443 (plus an ICMP echo over an unprivileged ping socket where the OS has one, which nmap lacks) |
| Localhost shortcut | default as root | This machine (loopback or one of its own addresses) is up without a probe, reason `localhost-response`, like nmap |
| Skip discovery | `-Pn` | |
| Ping probe types | `-PS`, `-PA`, `-PU`, `-PE`, `-PP`, `-PM` | With port lists, repeatable. `-PS`/`-PA` are raw SYN/ACK as root on Linux, connects otherwise |
| ARP on the local network (IPv4) | default as root, `--disable-arp-ping` / `--send-ip` | MAC address and vendor |
| Neighbour discovery (IPv6) | default as root | MAC address and vendor (`ndp.rs`) |
| MAC vendor names | `--oui-file` | Full IEEE OUI list from the system or a file, small built-in fallback |
| Reverse DNS | `-n`, `-R`, `--dns-servers` | Own resolver for `--dns-servers` (`dns.rs`) |
| Random host order | `--randomize-hosts` | |
| Traceroute | `--traceroute` | TCP SYN probes, IPv4 and IPv6 (`trace.rs`); only through a TCP port the command already probes (see [Deliberate differences](#deliberate-differences-from-nmap)) |

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
| Aggressive mode | `-A` | `-sV -O --traceroute`; only `-sV` without raw-socket privileges, with a warning naming what was skipped |

### Timing and performance

| Feature | Options | Notes |
| --- | --- | --- |
| Timing templates | `-T0` … `-T5` (or names `paranoid` … `insane`) | Set timeout, retries, parallelism, rate and scan delay (`timing.rs`); explicit flags override |
| Probe timeout and retries | `--timeout`, `--retries` | |
| Parallelism | `-c`, `--concurrency` | Connect and UDP probes in flight |
| Packet rate | `--min-rate`, `--max-rate` | `--max-rate` caps raw-socket probes (SYN, ICMP, ARP, NDP) on one schedule shared across the run; connect and UDP probes are paced by `--scan-delay` and bounded by `--concurrency`. `--min-rate` raises `--max-rate` and the connect/UDP parallelism, and shortens a template's scan delay |
| Delay between probes | `--scan-delay` | |
| Per-host time limit | `--host-timeout` | |
| Progress | `--stats-every`, `-v`, `-vv` | |
| Benchmarks | | criterion benches in `crates/feroprobe-core/benches` |

### Output

| Feature | Options | Notes |
| --- | --- | --- |
| Normal (table) output | default, `-oN` | Like nmap, a non-open state is folded into "Not shown" only above 25 ports (×(1 + `-v` count); `open\|filtered` never above `-vv`); smaller groups are listed |
| nmap-style XML | `-o xml`, `-oX`, `--nmap-label` | nmap's `-oX` layout incl. `<trace>`; `scanner="feroprobe"` unless `--nmap-label` (`xml.rs`) |
| Grepable output | `-o grepable`, `-oG` | One line per host, like nmap's (`grep.rs`) |
| JSON output | `-o json`, `-oJ` | FeroProbe's own format |
| All formats at once | `-oA` | `.nmap`, `.xml`, `.gnmap` |
| Port state reasons | `--reason` | |
| Open ports only | `--open` | Keeps `open`, `open\|filtered` and `unfiltered` ports, like nmap |
| Packet trace | `--packet-trace` | `SENT`/`RCVD`/`CONN` lines like nmap's; with `-f`/`--mtu` it shows each fragment actually sent (see [Deliberate differences](#deliberate-differences-from-nmap)) |
| Plan explanation | `--explain` | FeroProbe's own: the plan with a reason for each step |
| Dry run | `--dry-run` | FeroProbe's own: prints every probe the scan would send (discovery and port scan, with `-f`/`--mtu`, `-D`, `-S` expanded) as `NOT SENT (dry run)` lines in the `--packet-trace` layout, then stops. Sends nothing, needs no root, writes no report (`dryrun.rs`) |
| nmap-style help and warnings | `-h`, `--help` | Help page laid out like nmap's; nmap's warnings for names, down hosts, option values |

### Anti-abuse safeguards

| Feature | Notes |
| --- | --- |
| Recognizable probe signature | Raw TCP scans use window 65109 (`0xFE55`); generic UDP probes carry `FeroProbeScan/1\n`. Documented in `docs/responsible-use.md` |
| IDS rules | Suricata (`rules/feroprobe.rules`) and Snort (`rules/feroprobe.snort.rules`) |
| Settings files | `~/.config/feroprobe/config.toml` (XDG), under sudo also the invoking user's (`SUDO_USER`), then `./.feroproberc`; CLI wins; `-v` shows what was read. FeroProbe's own, nmap has none. `crates/feroprobe-cli/src/config.rs` |
| ICS protection | `ics_protection = true` refuses `-sV`, `-O`, `-A` (future script scanning too); `--override-ics-protection` allows one run with a warning; `--dry-run` is not refused but warns; warns on OT ports 102, 502, 20000, 44818, 47808. Off by default, so nmap behaviour is unchanged; Cargo feature `ics-protection-default` builds it always on (files cannot switch it off). `docs/ics-protection.md` |
| Evasion options behind an authorization flag | `-f`, `--mtu`, `-D`, `-S` (raw IPv4 TCP scans). Private ranges (RFC 1918, loopback, link-local, CGNAT, IPv6 ULA) work as is; a public target, decoy or spoofed source needs `--allow-public-evasion` (`scope.rs`, `evasion.rs`) |

### Platform and project

| Feature | Notes |
| --- | --- |
| Linux | Everything; raw-socket features need root or `CAP_NET_RAW` |
| macOS, Windows | Connect scan, UDP, discovery, `-sV`, all output formats |
| CI | ubuntu, macOS, Windows, plus a root job for raw sockets |
| Releases | `release.yml` builds binaries on `v*` tags |
| Live test scripts | `scripts/test-sctp.sh`, `scripts/test-os6.sh` |

## Deliberate differences from nmap

| Behaviour | nmap | FeroProbe | Why |
| --- | --- | --- | --- |
| `--packet-trace` with `-f`/`--mtu` | Prints one `SENT` line for the whole, unfragmented probe, although the fragments are what goes on the wire | Prints one `SENT` line per fragment actually sent (`TCP ... (frag)`, then `IP ... frag offset=N`) | The trace should show what is sent; nmap's display is treated as a bug and not copied (Jurgen, 2026-11-15). `--dry-run` shows fragments the same way |
| Evasion against public addresses | Allowed | Needs `--allow-public-evasion` | Anti-abuse safeguard, see `docs/responsible-use.md` |
| Probes outside the requested ports | `-A`'s scripts probe other ports (`ms-sql-info` sends a 1-byte UDP datagram to 1434 on every host, seen in Jurgen's tcpdump of `nmap -A -p 502,102`); `-O` picks a random closed UDP port, and for IPv4 also TCP (30000-44780), when the scan found none | Never. `-sV` and `-O` probe only open ports the scan found; there are no scripts. Traceroute falls back to a TCP port the command already probes (scan, `-p` with `-sn`, or a discovery port), else skips the host with a warning (it used to fall back to port 80) | An OT operator must be able to rely on `-p` being the scope (Jurgen, 2026-11-15). When script scanning is added, scripts must default to the scanned ports (like nmap's `mssql.scanned-ports-only`) |
| `-A` without root | Silently drops `-O` and traceroute | Drops them too, with a warning naming them and why | No silent downgrade (Jurgen, 2026-11-15) |
| Dry run | No equivalent. The closest is the list scan `-sL`, which only lists (and reverse-resolves) the targets | `--dry-run` lists every probe, per target and port, without sending any, and does no reverse DNS | A safe way to check exactly what a command would put on the wire. Every dry run opens with a "NOT A PREVIEW OF NMAP" box listing what nmap would send differently with the options given (`nmap_differences` in `main.rs`), and ends with the same reminder, because people may use it to check a command before running nmap (Jurgen, 2026-11-15) |

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
| List scan | `-sL` | List targets (and names) without sending probes. `--dry-run` covers the "send nothing" part and lists the probes too, but is not nmap's option and does no reverse DNS |
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

## Development notes

- 2026-11-15: while this project was being built with an AI coding
  assistant, one of the assistant's status updates about the evasion
  options (`-f`, `--mtu`, `-D`, `-S`; branch `claude/project-thread-qatskg`,
  PR #23) was incorrectly flagged by the assistant's safety safeguards, and
  the session was switched to another model to continue. The work itself
  was the authorization-gated evasion feature described above.
