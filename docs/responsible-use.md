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

### Evasion options only on private networks

nmap has options whose main use is getting past intrusion detection or
hiding who is scanning: packet fragmentation (`-f`, `--mtu`), decoys
(`-D`), and spoofed source addresses (`-S`). These are useful when you test
your own firewall or IDS, and that is the only use FeroProbe supports.

FeroProbe only allows them against private address ranges (RFC 1918,
carrier-grade NAT per RFC 6598, loopback, link-local, and IPv6 loopback,
unique-local and link-local addresses) and refuses them for any public
target, with a message naming the address that is out of scope. They also
need a raw TCP scan (`-sS`, `-sF`, `-sN`, `-sX`, `-sA`, `-sW` or `-sM`) on
IPv4 targets, since that is the only path they are wired into.

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

The idle scan (`-sI`), which bounces probes off a third "zombie" host, is
**not** implemented: its only real use is educational, and nmap already
serves that.

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
  already identifiable as the standard probe for that service.

Two scans carry no marker, on purpose:

- The TCP **connect** scan (`-sT`) completes a normal handshake through the
  operating system's own TCP stack, so it is indistinguishable from an
  ordinary connection.
- **OS-detection** probes (`-O`) deliberately mimic a real OS stack so the
  target's response can be read, so they do not carry the window marker.

### Detection rules for defenders

The repository ships Suricata and Snort rules that match the probe
signature, so blue teams can flag FeroProbe scans without writing their
own. They are in [`rules/`](../rules/): `rules/feroprobe.rules` for
Suricata and `rules/feroprobe.snort.rules` for Snort, with setup notes in
`rules/README.md`.

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
