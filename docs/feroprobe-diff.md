# feroprobe-diff: compare two scans

`feroprobe-diff` compares two saved scan reports and shows what changed
between them: hosts that came up or went away, ports that opened or closed,
and services, versions, OS matches and script output that changed. It is
FeroProbe's counterpart of nmap's `ndiff`, with the same options, output
and exit codes, written from scratch in Rust. It reads XML reports written
by FeroProbe (`-oX`) or by nmap.

## Contents

- [Synopsis](#synopsis)
- [Description](#description)
- [Options](#options)
- [Text output](#text-output)
- [XML output](#xml-output)
- [How scans are compared](#how-scans-are-compared)
- [Differences from ndiff](#differences-from-ndiff)
- [Exit status](#exit-status)
- [Examples](#examples)
- [See also](#see-also)

## Synopsis

```
feroprobe-diff [options] FILE1 FILE2
```

## Description

`FILE1` is the earlier scan and `FILE2` the later one; both must be XML
reports (`-oX`, or the `.xml` file of `-oA`). Like the standard `diff`,
`feroprobe-diff` compares two scans at a time and by default shows only
what differs. Things it compares:

- Host states (up, down) and which hosts are in each scan
- Host addresses and names
- Port states (open, closed, filtered, ...), including the "Not shown"
  counts
- Services and versions (from `-sV`), including the SSL/TLS tunnel
- OS matches (from `-O`)
- Script output (pre-scan, host and port scripts), for nmap reports and
  for FeroProbe's once it has scripts

The command lines and times of the two scans are shown when they differ,
but do not count as a difference for the [exit status](#exit-status).

A file written with `--append-output` holds one XML document per run and
cannot be read as one scan; split it into one file per run first.

## Options

#### `-v`, `--verbose`

Show every host and every port, not only the ones that changed. Unchanged
lines start with a space.

#### `--text`

Write the differences as text (the default). See
[Text output](#text-output).

#### `--xml`

Write the differences as XML. See [XML output](#xml-output). `--text`
and `--xml` cannot be combined.

#### `-h`, `--help`

Print a short help and exit.

#### `-V`, `--version`

Print the version and exit.

## Text output

The text output looks like a unified diff of the normal scan output. Each
line starts with a mark:

- `-`: the line is in the first scan only
- `+`: the line is in the second scan only
- a space: the line is in both (shown for context, and for everything
  with `-v`)

A line that changed is a `-` line followed by a `+` line. Each host that
changed gets a block, after a blank line:

```
-FeroProbe 0.5.0 scan initiated Sun Nov 16 08:00:00 2025 UTC as: feroprobe -sV -O 10.0.0.0/28
+FeroProbe 0.5.0 scan initiated Mon Nov 17 08:00:00 2025 UTC as: feroprobe -sV -O 10.0.0.0/28

 web.lan (10.0.0.5):
 PORT     STATE SERVICE    VERSION
-22/tcp   open  ssh        OpenSSH 9.6p1 (protocol 2.0)
-80/tcp   open  http
+80/tcp   open  http       nginx 1.24.0
-443/tcp  open  http
+443/tcp  open  ssl/http
+8080/tcp open  http-proxy
 OS details:
-  Linux 4.19 - 6.x
+  Linux 3.x - 4.18

-10.0.0.10:
-Host is up.
-Not shown: 1000 filtered ports

+10.0.0.11:
+Host is up.
+Not shown: 999 closed ports
+PORT    STATE SERVICE VERSION
+161/udp open  snmp

-old-name.lan (10.0.0.12):
+new-name.lan (10.0.0.12):
```

Here port 22 on 10.0.0.5 is no longer open (it fell into the second
scan's "Not shown" ports), port 80 gained a version, port 443 now speaks
TLS, port 8080 opened and the OS match changed. 10.0.0.10 was not in the
second scan, 10.0.0.11 was not in the first, and 10.0.0.12 got a new
reverse DNS name.

A host's block has these parts, each only when it changed (or with `-v`):
the host's name line, `Host is <state>.`, `Not shown: <counts>`, the port
table with the changed ports, `OS details:` with the OS matches, and
`Host script results:`. Script output is shown under its port, in the
`|  id: output` / `|_ last line` layout of the normal output. Pre-scan and
post-scan script results come before and after the hosts.

## XML output

`--xml` writes a document in ndiff's layout, so tools that read ndiff's XML
read it too. The root element is `<nmapdiff version="1">`, holding one
`<scandiff>`. Inside it the scan report's own elements are used
(`<nmaprun>`, `<host>`, `<status>`, `<address>`, `<hostnames>`, `<ports>`,
`<extraports>`, `<port>`, `<state>`, `<service>`, `<os>`, `<osmatch>`,
`<script>`, `<prescript>`, `<postscript>`, `<hostscript>`), with these
additions:

- `<hostdiff>` around each host that changed, and `<portdiff>` around each
  port that changed.
- `<a>` around what is in the first scan only, `<b>` around what is in the
  second scan only. A host in one scan only is a `<hostdiff>` holding the
  whole `<host>` in `<a>` or `<b>`. A port whose state changed is a
  `<portdiff>` with the whole `<port>` in `<a>` and in `<b>`; a port whose
  state stayed but whose service changed has the two `<service>` elements
  in `<a>` and `<b>`.
- When the runs differ (scanner, version, command line, start or end
  time), the two `<nmaprun>` elements in `<a>` and `<b>` come first.

Elements carry only the attributes that are compared: `<service>` has
`name`, `product`, `version`, `extrainfo` and `tunnel`; `<osmatch>` has
`name`.

## How scans are compared

**Hosts** are paired by address: a host in both scans is the one with the
same first address (IPv4 before IPv6 before MAC), or the same name for a
host without an address. A host whose addresses or names changed is shown
with its old name line (`-`) and its new one (`+`). Hosts are listed in
address order.

**Ports** are paired by number and protocol. A port that a scan does not
list (because it is in that scan's "Not shown" group, or was not scanned)
counts as not in that scan: it gets a `-` line only, or a `+` line only. A
port that both scans fold into "Not shown" is not compared on its own; the
"Not shown" counts cover it.

**Services** are compared on their name, product, version, extra
information and SSL/TLS tunnel. Other details of the report (reasons,
round-trip times, CPEs, confidence) are not compared.

**OS matches** are compared as a list, best match first: added and removed
matches are marked, unchanged ones in between are shown for context.

**Script results** are paired by script id; their output is compared line
by line.

## Differences from ndiff

`feroprobe-diff` follows ndiff, except where ndiff's behaviour is clearly
wrong:

| Behaviour | ndiff | feroprobe-diff |
| --- | --- | --- |
| Pairing hosts | By first address and first host name together, so a host whose reverse DNS name changed shows as one host gone and another new (ndiff's own manual still shows it as one host with a new name) | By address alone: the host shows once, with its old and new name |
| Host order | Addresses sorted as text (10.0.0.10 before 10.0.0.2) | Numeric address order |
| SSL/TLS tunnel | A service that gains or loses its tunnel (`http` to `ssl/http`) is not counted as a change | Counted and shown |
| Pre- and post-scan script changes | Shown, but not counted for the exit status | Counted |
| Times | Local time | UTC, like the rest of FeroProbe's output |
| Scanner name in the banner | `Nmap`, or the report's `scanner` attribute | The same, with FeroProbe's reports shown as `FeroProbe` |
| Version option | None | `-V`, `--version` |

## Exit status

- `0`: the scans are the same in everything compared
- `1`: the scans differ
- `2`: an error, such as a file that cannot be opened or read, or a wrong
  option

## Examples

Compare yesterday's scan with today's:

```
feroprobe-diff scan-2026-11-15.xml scan-2026-11-16.xml
```

Scan a network every day and mail the changes, from cron:

```
#!/bin/sh
date=$(date +%F)
cd /var/lib/scans
feroprobe -T4 -F -sV 10.0.0.0/24 -oA scan-$date > /dev/null
if [ -e scan-prev.xml ]; then
    feroprobe-diff scan-prev.xml scan-$date.xml > diff-$date
    [ $? -eq 1 ] && mail -s "Network changes $date" admin < diff-$date
fi
ln -sf scan-$date.xml scan-prev.xml
```

Show everything, changed or not, as XML:

```
feroprobe-diff -v --xml before.xml after.xml
```

## See also

- feroprobe(1), and [docs/manual.md](manual.md) for `-oX`
- ndiff(1)
