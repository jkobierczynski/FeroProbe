# Settings files and ICS protection

FeroProbe reads persistent settings from TOML files at startup. The only
setting today is `ics_protection`, an opt-in guard that refuses the options
most likely to upset fragile industrial control system (ICS) and
operational technology (OT) devices. The guard is **off by default**.

## Settings files

### Where they are

FeroProbe reads two files, in this order:

| Order | File | Purpose |
| --- | --- | --- |
| 1 | `$XDG_CONFIG_HOME/feroprobe/config.toml` | Your user-wide settings |
| 2 | `.feroproberc` in the current working directory | Per-project or per-engagement settings |

`XDG_CONFIG_HOME` is used only when it is set to an absolute path, as the
XDG base directory specification says; otherwise the user file is
`~/.config/feroprobe/config.toml`. On Windows, where there is usually no
`HOME`, it is `%APPDATA%\feroprobe\config.toml`.

### Precedence

From lowest to highest:

1. built-in defaults (`ics_protection = false`);
2. the user file;
3. `.feroproberc` in the working directory;
4. command-line options, which always win.

A key set in a later file replaces the same key from an earlier file. A key
that a file leaves out keeps whatever the earlier layers said, so a
`.feroproberc` that sets nothing does not switch off a protection from your
user file. A `.feroproberc` that sets `ics_protection = false` does switch it
off for runs started in that directory.

### Format and errors

The files are [TOML](https://toml.io/). A missing file is fine and is
skipped. A file that exists but cannot be read, is not valid TOML, or gives
a setting the wrong type stops the run with an error naming the file: a
protection you set is never dropped silently because of a typo. An unknown
key gets a warning and is otherwise ignored, so a file written for a newer
FeroProbe still works with an older one.

```toml
# ~/.config/feroprobe/config.toml
ics_protection = true
```

nmap has no equivalent settings file; it is a FeroProbe addition. With no
file present, FeroProbe behaves exactly as before.

## ICS protection

### What it does

With `ics_protection = true`, FeroProbe refuses to start when the command
line asks for any of these options:

| Option | What it sends |
| --- | --- |
| `-sV` | Application-protocol probes (HTTP requests, TLS handshakes, banner prompts and more) to every open port |
| `-O` | Deliberately unusual TCP/IP packets (odd flag combinations, options and window sizes) to an open and a closed port |
| `-A` | Both of the above, plus traceroute |

Script scanning will join this list if FeroProbe ever gets it.

The refusal happens before any name is resolved or any packet is sent, and
names the options that caused it (the message is one line; wrapped here):

```text
$ feroprobe -sV 10.20.0.0/24
Error: ICS protection is on (ics_protection = true in /home/me/.config/feroprobe/config.toml),
so -sV is refused: version and OS detection send probes that can hang or crash fragile
OT/ICS devices such as PLCs. Leave out -sV, or pass --override-ics-protection to run this
once anyway
```

Host discovery and plain port scans (`-sS`, `-sT`, `-sU`, `-sn`, and the
rest) are not refused. They are also not harmless on a control network, so
choose gentle timing (`-T2` or slower) there anyway.

### Override for one run

`--override-ics-protection` lets a single run use the refused options. It
prints a prominent warning naming what it let through, and does not change
any settings file:

```text
$ feroprobe -A --override-ics-protection 10.20.0.15
WARNING: ************************************************************
WARNING: --override-ics-protection: running -A although ICS protection is on (ics_protection = true in .feroproberc)
WARNING: these probes can hang or crash fragile OT/ICS devices such as PLCs
WARNING: ************************************************************
```

When protection is off the flag has no effect, and FeroProbe says so.

### OT port warning

With protection on, a port scan that includes a well-known OT port gets a
warning (never a refusal):

| Port | Protocol |
| --- | --- |
| 102/tcp | Siemens S7comm (ISO-TSAP) |
| 502/tcp | Modbus/TCP |
| 20000/tcp, 20000/udp | DNP3 |
| 44818/tcp, 44818/udp | EtherNet/IP (CIP) |
| 47808/udp | BACnet/IP |

```text
Warning: ICS protection: the scan includes well-known OT ports (102/tcp S7comm, 502/tcp Modbus);
keep it gentle on control devices (e.g. -T2, -sT)
```

The block is on the dangerous options, not on ports: plenty of control
devices listen on ordinary ports such as 80 and 443, and a port list says
nothing reliable about what is behind it.

### Why these options

PLCs, RTUs, protocol gateways and building controllers often run small,
old TCP/IP stacks and protocol handlers that were written for the one
protocol the device speaks and tested against nothing else. Version
detection connects to each open port and sends whatever probes might draw
out a banner: an HTTP `GET`, a TLS ClientHello, a SIP `OPTIONS`, and so on.
A Modbus handler on port 502 that receives an HTTP request may read it as
a malformed Modbus frame, and some devices respond by faulting, dropping
into a stop state, or hanging until someone power-cycles them. OS detection
sends packets that are unusual on purpose, which is exactly what such
stacks handle worst.

This is a long-documented class of incident, not a theory: published
reports on penetration testing of control systems (for example Sandia
National Laboratories' 2005 report on the subject, and the NIST SP 800-82
guide to OT security) describe routine scans that stopped or upset
production equipment. On a production network the
cost of a stopped controller is downtime, damaged product or a safety
problem, not a log entry.

### Why it is off by default

FeroProbe is a general network scanner, not an ICS tool, and out of the
box it behaves like nmap. People who scan control networks are expected to
know these risks and plan for them; a tool that switches protections on by
default teaches them to rely on it, and fails them on the first machine
where the default was never set. `ics_protection` is a convenience for
people who already know: put it in the user file on a jump host that
reaches OT networks, or in a `.feroproberc` in an engagement's working
directory, so a habitual `-A` is caught before it reaches a controller.

### Limits

- It is a local setting. Anyone can delete the file, set the key to
  `false` in a `.feroproberc`, or pass `--override-ics-protection`.
- It does not know which hosts are control devices. It guards the
  options, everywhere, while it is on.
- It does not make other scans safe. Fast discovery and port scans can
  still overload weak devices; slow down and scope carefully.
