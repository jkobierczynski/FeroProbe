# Detection rules for FeroProbe

FeroProbe marks its own scan traffic on purpose, so the owner of a scanned
network can tell a FeroProbe scan apart from other traffic. This directory
ships ready-made intrusion-detection rules that match that signature, so blue
teams can flag FeroProbe scans without writing their own.

- `feroprobe.rules` — Suricata format.
- `feroprobe.snort.rules` — Snort format (2.9.x and 3.x).

## The signature

| Probe | Marker |
|-------|--------|
| Raw-socket TCP scans (SYN, FIN, NULL, Xmas, ACK, Window, Maimon) | TCP window `65109` (`0xFE55`) |
| UDP scans to ports with no service-specific probe | payload `FeroProbeScan/1` |
| ICMP / ICMPv6 echo requests (host discovery, `-PE`, `-PO` and the defaults) | payload `feroprobe` (9 bytes) |
| HTTP requests from scripts (`--script`, `fero.http`) | `User-Agent: Mozilla/5.0 (compatible; FeroProbe Scripting Engine; https://github.com/jkobierczynski/FeroProbe)` |
| `ssh-hostkey` (default script) | SSH client version `SSH-2.0-FeroProbe_Scripting_Engine` |
| `smtp-commands` (default script) | `EHLO feroprobe.invalid` |
| `ftp-anon` (default script) | `PASS feroprobe@` |

The TCP window of a scan probe is otherwise meaningless, because the scan
never completes a handshake, so the fixed window does not change how the
probe behaves or how the target answers it.

Two scans carry **no** marker, by design:

- The TCP **connect** scan (`-sT`) completes a normal handshake through the
  operating system's TCP stack, so it looks like an ordinary connection.
- **OS-detection** probes (`-O`) deliberately mimic a real OS stack to read
  the target's response, so they do not carry the window marker.

Script HTTP requests over TLS (HTTPS) carry the same `User-Agent`, but
encrypted, so the rules can match only plain HTTP. A script, or
`--script-args http.useragent=...`, can set another `User-Agent`, as in
nmap; the request then carries only what was asked for. Likewise
`--script-args smtp.domain=...` replaces the EHLO name. SMTP over TLS
(port 465, or after STARTTLS) hides the EHLO from the rules; the SSH
version line and the FTP password are always in clear text. Other script
traffic (TLS handshakes, protocols with no field for a client name)
carries no marker.

A custom payload (`--data`, `--data-string` or `--data-length`) replaces the
UDP and ICMP echo markers, exactly as it replaces nmap's payloads, so those
probes then carry only what the user asked for. The TCP window marker stays.

See [`../docs/responsible-use.md`](../docs/responsible-use.md) for the
rationale.

## Using the rules

### Suricata

Copy `feroprobe.rules` into your rules directory (e.g.
`/etc/suricata/rules/`) and add it to `suricata.yaml`:

```yaml
rule-files:
  - feroprobe.rules
```

Then reload: `suricatasc -c reload-rules`, or restart Suricata.

First copy `feroprobe.snort.rules` to a directory Snort already searches —
usually the one that holds your other rule files — or note its absolute
path, so the include below can find it.

For **Snort 2.9.x**, add it to `snort.conf`, where `$RULE_PATH` is the
rules directory your config already defines:

```
include $RULE_PATH/feroprobe.snort.rules
```

For **Snort 3.x**, add an `include` entry to the `ips` table in
`snort.lua` (the `include` directive above is not valid Lua). Add the entry
**inside your existing `ips` table** — do not paste this as a new `ips = {
... }` assignment, which would replace the table and drop its other
entries, such as the `variables` that define `$HOME_NET`:

```lua
ips =
{
    -- ... your existing entries (variables, policy, …) stay here ...

    -- a path Snort can find: a bare name only if the file is on the
    -- include search path, otherwise an absolute path.
    include = '/etc/snort/rules/feroprobe.snort.rules',
}
```

`ips.include` takes a single file. If your `ips` table already sets it,
load these rules inline through `ips.rules` instead, following your
existing configuration.

The rules use the local SID range `9100000+` and the `attempted-recon`
class. Adjust the SIDs and `$HOME_NET` to fit your deployment.
