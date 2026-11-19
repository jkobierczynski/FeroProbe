# Responsible use

FeroProbe is a network scanner. Scan only networks you own or have written
permission to test. Unauthorised scanning is illegal in many countries and
against the terms of most hosting providers.

## Why another scanner

nmap is excellent and FeroProbe follows its behaviour and options closely.
People still have good reasons to want an alternative:

- **Memory safety.** FeroProbe is written in Rust. Packet parsing, which
  handles untrusted input from the network, runs in memory-safe code.
- **One static binary.** Releases are single files with no runtime data
  files to install, which helps on locked-down or minimal systems.
- **A library as well as a tool.** `feroprobe-core` can be embedded in
  other Rust programs, such as inventory or monitoring tools.
- **Automation.** Clean JSON output next to nmap-compatible XML and
  grepable formats.

FeroProbe is meant for asset discovery, inventory, and checking your own
firewalls and exposure. It is not meant for hiding a scan from the people
who run the network being scanned.

## Where FeroProbe differs from nmap on purpose

FeroProbe aims to behave like nmap. The safeguards below are the
deliberate exceptions.

### Evasion options gated behind an authorization flag

nmap has options whose main use is getting past intrusion detection or
hiding who is scanning: packet fragmentation (`-f`, `--mtu`), decoys
(`-D`), and spoofed source addresses (`-S`). These are useful when you test
your own firewall or IDS, or when you run an authorized penetration test,
and those are the uses FeroProbe supports.

By default FeroProbe only allows them against private address ranges
(RFC 1918, carrier-grade NAT per RFC 6598, loopback, link-local, and IPv6
loopback, unique-local and link-local addresses). For a public target,
decoy, or spoofed source it refuses them with a message naming the address
that is out of scope, unless you pass `--allow-public-evasion`. That flag is
a deliberate, explicit opt-in: it says you have permission to test the
network in question. Without it, a public address is always refused, so the
abuse-resistant behaviour is the default and reaching past it takes a
conscious step. Private ranges never need the flag.

The options also need a raw TCP scan (`-sS`, `-sF`, `-sN`, `-sX`, `-sA`,
`-sW` or `-sM`) on IPv4 targets, since that is the only path they are wired
into. That requirement holds with or without `--allow-public-evasion`.

- `-f` fragments raw IPv4 probes into 8-byte pieces; `--mtu <n>` sets the
  fragment payload size (a multiple of 8).
- `-D <a,b,ME,c>` sends the probe from each decoy source address as well as
  the real one, so the real scanner is harder to pick out. `ME` marks the
  real scanner's slot and is accepted for nmap compatibility; FeroProbe
  sends the real probe last.
- `-S <addr>` forges the source address of the probes. Replies go to that
  address, not to FeroProbe, so the scan is blind unless FeroProbe sits on
  the path back — this matches nmap and is mainly for watching what your IDS
  makes of the traffic.

With `--packet-trace`, every fragment that `-f`/`--mtu` produces gets its
own `SENT` line, so you see exactly what went on the wire. nmap prints only
the unfragmented probe there; FeroProbe does not copy that.

The FTP bounce scan (`-b`) is gated the same way. It asks someone else's
FTP server to connect to the targets for you, so both the targets and the
FTP relay must be private addresses unless you pass
`--allow-public-evasion`. Bouncing through a public FTP server into the
network behind it is exactly the abuse RFC 2577 warns about.

`--spoof-mac` is gated the same way too: it hides which machine on the
local network sent the probes, so public targets need
`--allow-public-evasion`.

The packet options `--data`, `--data-string`, `--data-length`, `--ttl`,
`--ip-options` and `--badsum` are not gated: they change what a probe
carries, not who appears to send it or where it goes, and nmap users rely
on them for ordinary firewall and path testing. Source routing through
`--ip-options L`/`S` reaches only hops you name, and most routers drop it.

The idle scan (`-sI`), which bounces probes off a third "zombie" host, is
**not** implemented: its only real use is educational, and nmap already
serves that.

### Opt-in ICS protection

Version detection (`-sV`), OS detection (`-O`), `-A` and scripts
(`--script`, `-sC`) send probes that can hang or crash fragile industrial devices: a PLC whose Modbus handler on
port 502 receives an HTTP request may fault or stop until it is
power-cycled. Reports on penetration testing of control systems have
described routine scans that upset production equipment for twenty years.

Setting `ics_protection = true` in a settings file
(`~/.config/feroprobe/config.toml`, or `.feroproberc` in the working
directory) makes FeroProbe refuse those options, before it resolves or
sends anything, with a message naming the option.
`--override-ics-protection` lets one run through with a prominent warning.
A `--dry-run` is not refused, since it sends nothing, but warns that the
real run would be.
With protection on, scanning a well-known OT port (Modbus 502, S7comm 102,
EtherNet/IP 44818, DNP3 20000, BACnet 47808) also prints a warning.

This one is **off by default**, unlike the safeguards around it, and that
is deliberate. FeroProbe is a general scanner that behaves like nmap; it is
not an ICS tool. People who scan control networks must know these risks
without leaning on a default, and the setting is there for those who want
a safety catch on the machines they use for that work. With it off,
FeroProbe behaves exactly like nmap. See
[ics-protection.md](ics-protection.md) for the settings files, their
precedence and the full rationale.

### Recognizable traffic

FeroProbe's probes carry a stable, documented signature, so a network owner
can tell FeroProbe traffic apart from other traffic. The marks are:

- **Raw-socket TCP scans** (SYN, FIN, NULL, Xmas, ACK, Window and Maimon)
  set the TCP window to `65109` (`0xFE55`). The window of a scan probe is
  otherwise meaningless, because the scan never completes a handshake, so
  the fixed value is a reliable marker that does not change how the probe
  behaves or how the target answers it.
- **UDP scans** to ports with no service-specific probe carry the ASCII
  payload `FeroProbeScan/1` instead of an empty datagram. Service probes
  (DNS, NTP, SNMP, SSDP and so on) keep their own payloads, which are
  already identifiable as the standard probe for that service. The
  NetBIOS probe to UDP 137 carries transaction ID `0x4650` ("FP"), the
  same request as the `nbstat` script, so rule 9100013 matches both.
- **ICMP and ICMPv6 echo requests** sent for host discovery carry the
  9-byte ASCII payload `feroprobe` (nmap's echo requests are empty). Echo
  replies copy the payload back, so the marker shows in both directions.
  This includes the echo request of the IP protocol ping (`-PO`); the
  `-sO` scan's stays empty, as in nmap. The TCP ACK that `-sO`/`-PO` send
  for protocol 6 carries the window marker like the other raw TCP probes.

SCTP probes (`-sY`, `-sZ`, `-PY`) and the other IP protocol probes
(`-sO`, `-PO`: IGMP, IP-in-IP, bare headers, and their UDP datagram) carry
no FeroProbe mark yet; they are the same packets nmap sends.

A payload you give with `--data`, `--data-string` or `--data-length`
replaces the UDP and ICMP echo markers, as nmap's replaces its own
payloads: a payload typed on the command line is a deliberate choice, and
the probe carries exactly those bytes. The TCP window marker is not part of
the payload and stays.

Two scans carry no marker, on purpose:

- The TCP **connect** scan (`-sT`) completes a normal handshake through the
  operating system's own TCP stack, so it is indistinguishable from an
  ordinary connection.
- **OS-detection** TCP probes (`-O`) deliberately mimic a real client's
  SYNs so the target's response can be read, so they do not carry the
  window marker. The OS-detection echo request, sent only when host
  discovery sends echo requests too, carries the usual `feroprobe` payload.

**Script traffic** (`--script`, `-sC`, `-A`) is ordinary application traffic over the
operating system's own TCP and UDP sockets, like the connect scan, so the
raw-probe markers cannot apply to it. What it looks like depends on the
script: the built-in `banner` script only opens a TCP connection and
reads, sending nothing. Script traffic is bounded instead: a script can
connect only to the host it runs against, and only to ports the scan
probed there, and scripts that run before or after the scan get no network
access at all, so no script broadcasts or wanders to other hosts. HTTP
redirects are followed only within the same bounds.

Where a protocol has a place to name the client, script traffic names
FeroProbe. Every request of the script HTTP library (`fero.http`, used by
the built-in `http-title` script) carries

```
User-Agent: Mozilla/5.0 (compatible; FeroProbe Scripting Engine; https://github.com/jkobierczynski/FeroProbe)
```

the counterpart of nmap's `Nmap Scripting Engine` agent. Over HTTPS the
header is encrypted, so a network sensor sees it only in plain HTTP; the
web server's own logs show it either way. As with `--data`, a
`User-Agent` the user chooses replaces it (`--script-args
http.useragent=...`, or a script that sets the header), as in nmap: a
value typed on purpose is sent exactly as given. TLS handshakes (the
`ssl-cert` script, `fero.socket` with `"ssl"`) carry no marker: a TLS
ClientHello has no field for one. They offer no client certificate and
check nothing about the server's.

The default scripts (`-sC`, also run by `-A`) name FeroProbe wherever
their protocol lets a client name itself, so the target's own logs show
who asked:

| Script | What the target sees | nmap's counterpart |
| --- | --- | --- |
| `ssh-hostkey` (and `ssh2-enum-algos` when chosen) | The client version line `SSH-2.0-FeroProbe_Scripting_Engine` (in clear text, before encryption starts) | `SSH-2.0-Nmap-SSH2-Hostkey`, `SSH-2.0-Nmap-SSH2-Enum-Algos` |
| `smtp-commands` | `EHLO feroprobe.invalid` (`.invalid` is a reserved name, RFC 2606) | the target's name, or `nmap.scanme.org` |
| `ftp-anon` | `USER anonymous`, `PASS feroprobe@` | `PASS IEUser@` |
| `smb2-security-mode`, `smb2-time` | The SMB2 NEGOTIATE client GUID `FeroProbeSMBScan` (16 bytes of ASCII); on port 139 the NetBIOS calling name `FEROPROBE` | — |
| `rdp-ntlm-info` | The RDP routing cookie `Cookie: mstshash=FeroProbe` in the connection request (clear text, before TLS); then the NTLM NEGOTIATE below, inside TLS | — |
| `http-ntlm-info`, `smtp-ntlm-info`, `imap-ntlm-info`, `pop3-ntlm-info`, `nntp-ntlm-info`, `telnet-ntlm-info`, `ms-sql-ntlm-info` | An NTLM NEGOTIATE that names the workstation `FEROPROBE` and no user or domain, the same 49 bytes every time: in base64 over HTTP (`Authorization: NTLM`, beside the `User-Agent` above), SMTP, IMAP, POP3 and NNTP (rule 9100016), as is over telnet and MS-SQL (rule 9100017). `ms-sql-ntlm-info`'s login also gives the host name `FEROPROBE` and the application name `FeroProbe Scripting Engine`; `smtp-ntlm-info` says `EHLO feroprobe.invalid`. These scripts switch to TLS with STARTTLS where the server allows it, and the NEGOTIATE is then encrypted | NEGOTIATE with no workstation |
| `ssl-date` | `FeroProbeSSLDate` in the TLS ClientHello random, after its four time bytes (clear text, it is the first message of the handshake) | — |
| `nbstat` | The NetBIOS transaction ID `0x4650` ("FP") of its NODE STATUS request to UDP 137 (a weak mark of 2 bytes: rule 9100013 also needs the rest of the request to match, and a tool that picks its IDs at random still matches about once in 65,536 such requests) | — |
| `dns-nsid` | The DNS transaction ID `0x4650` ("FP") of its CHAOS TXT queries for `id.server` and `version.bind` (the first one asking for the NSID too). A weak mark of 2 bytes: rules 9100014 (UDP) and 9100015 (TCP) also need only the RD flag (as in nmap's queries), one question and that question (`id.server` or `version.bind`, CHAOS TXT), which few other clients send; a tool that picks its IDs at random still matches about once in 65,536 such queries | — |
| `http-title`, `http-methods`, `http-robots.txt`, `http-auth`, `http-cookie-flags`, `http-cors`, `http-favicon`, `http-generator`, `http-git`, `http-webdav-scan` (and `http-date`, `http-headers`, `http-server-header` when chosen) | The `User-Agent` above. `http-cors` also sends `Origin: example.com` (nmap's default), `http-webdav-scan` one `PROPFIND` with `Depth: 1`, `http-git` GETs of `/.git/HEAD` and a few small `.git` files | `Nmap Scripting Engine` |

As with the `User-Agent`, `--script-args smtp.domain=...` replaces the
EHLO name with one chosen on purpose. The other default scripts read a
greeting or ask a protocol's standard question (CAPA, CAPABILITY, SYST,
an RPC portmapper dump, an NTP time request, an RFB or X11 handshake),
which has no field for a client name. `clock-skew` sends nothing: it only
sums up what the other scripts saw. None of them logs in with a
password, and each stays within the ports the scan probed.

### Detection rules for defenders

The repository ships Suricata and Snort rules that match the probe
signature, so blue teams can flag FeroProbe scans without writing their
own. Rules 9100006 to 9100017 match the script markers above in clear
text. They are in [`rules/`](../rules/): `rules/feroprobe.rules` for
Suricata and `rules/feroprobe.snort.rules` for Snort 2.9 and
`rules/feroprobe.snort3.rules` for Snort 3, with setup notes in
`rules/README.md`.

## Checking a scan before running it

`--dry-run` prints the host-discovery and port-scan probes a command would
send, one `NOT SENT (dry run)` line per probe in the `--packet-trace` layout,
and sends nothing: no host discovery, no port scan, no reverse DNS. It does
not list the probes of steps that depend on replies: service detection
(`-sV`) and `--traceroute` run on the hosts and open ports a real scan
finds, so the dry run only names them. OS detection (`-O`) is listed probe
by probe for one try, with `<open>` and `<closed>` standing for the ports
the scan would find. Retransmissions of
unanswered probes are not listed either. Since nothing answers, the port-scan
probes are listed for every target as if each were up; a real scan skips the
targets host discovery finds down, so it can send fewer.

It needs no root, so you can review a scan (its targets, ports, flags,
fragments, decoys and spoofed source) before running it for real, or show a
network owner the planned host-discovery and port-scan probes. Only target hostnames are resolved, through the system resolver (even
with `-n`), so the addresses shown are the real ones; give numeric addresses
when no DNS traffic is allowed. The same safeguards apply: evasion
options against a public address are refused in a dry run too, unless
`--allow-public-evasion` is given.

## Limits of these safeguards

FeroProbe is open source under the GPLv3, so anyone can change the code and
remove these checks. With an AI assistant, stripping them out of a fork
takes minutes, so they are a minor nuisance at most for someone set on
abuse. They are not meant as a barrier.

Their value lies elsewhere:

- **No ready-made evasion kit.** The official FeroProbe does not hand out
  tools for hiding a scan from the network's owner.
- **Easy to spot by default.** Its traffic is easy for defenders to
  recognize, which matters most for the many people who run it unchanged.
- **Help for defenders.** The detection rules help blue teams spot scans
  whoever wrote the scanner.

Taken together, they are a statement of intent: FeroProbe is built for the
people who defend networks.
