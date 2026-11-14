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
deliberate exceptions. They are being built as part of the current
development phase; this page says what is in place and what is planned.

### Evasion options only on private networks (planned)

nmap has options whose main use is getting past intrusion detection or
hiding who is scanning: packet fragmentation (`-f`, `--mtu`), decoys
(`-D`), spoofed source addresses (`-S`), the idle scan (`-sI`), which
bounces probes off a third "zombie" host, and similar. These are useful when
you test your own firewall or IDS, and that is the only use FeroProbe
supports. When they are added, FeroProbe will only allow them against
private address ranges (RFC 1918, carrier-grade NAT, loopback, link-local
and IPv6 unique-local addresses) and will refuse them for public targets.

### Recognizable traffic (planned)

FeroProbe's probes will carry a stable, documented signature, so a network
owner can tell FeroProbe traffic apart from other traffic. The exact
signature will be listed here once it is in place.

### Detection rules for defenders (planned)

The repository will ship Suricata and Snort rules that match the probe
signature, so blue teams can flag FeroProbe scans without writing their
own rules.

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
