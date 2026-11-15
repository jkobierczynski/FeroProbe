# Security policy

FeroProbe parses untrusted data from the network (packets, banners, TLS
handshakes, DNS replies) and often runs as root for raw-socket scans, so
bugs in it can matter for security. It also has safeguards (the evasion
authorization gate and ICS protection) whose bypass is a security issue.

## Supported versions

| Version | Supported |
|---|---|
| 0.3.x (latest release) | ✅ |
| `main` | ✅ |
| < 0.3 | ❌ |

Fixes go into `main` and the next release. Older release lines are not
patched; please upgrade to the latest release.

## Reporting a vulnerability

Please do **not** open a public issue. Report it privately through
GitHub: go to the repository's **Security** tab and choose
**Report a vulnerability**.

Useful things to include:

- what an attacker can do and from where (for example a malicious host
  being scanned, or a crafted settings file),
- a packet capture, banner, target list or command line that reproduces it,
- the FeroProbe version (`feroprobe --version`) or commit, and your OS.

You should get a reply within a week. Once a fix is out, the report will be
published as a GitHub security advisory, with credit if you want it.

## Examples of what counts

- A response from a scanned host (packet, service banner, TLS certificate,
  DNS answer) that causes a crash, hang, unbounded memory use, or memory
  unsafety, or that injects misleading content into the XML, JSON,
  grepable or normal reports.
- Privilege problems when running as root or under `sudo`, such as report
  files (`-oN`, `-oX`, `-oA`, ...) written or overwritten where they should
  not be, or settings files read from the wrong user.
- A way to bypass the evasion authorization gate
  ([docs/responsible-use.md](docs/responsible-use.md)) or ICS protection
  ([docs/ics-protection.md](docs/ics-protection.md)) without the intended
  flag or setting.
- Vulnerable dependencies that FeroProbe actually exercises.

## Out of scope

FeroProbe is a scanner: scanning a network you are not authorized to scan
is a misuse of the tool, not a vulnerability in it. Detection of FeroProbe
by an IDS (see [rules/](rules/)) is intended behaviour.
