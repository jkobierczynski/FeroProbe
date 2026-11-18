# Detection rules for FeroProbe

FeroProbe marks its own scan traffic on purpose, so the owner of a scanned
network can tell a FeroProbe scan apart from other traffic. This directory
ships ready-made intrusion-detection rules that match that signature, so blue
teams can flag FeroProbe scans without writing their own.

- `feroprobe.rules` — Suricata format.
- `feroprobe.snort.rules` — Snort 2.9.x format.
- `feroprobe.snort3.rules` — Snort 3.x format: the same rules, with content
  modifiers (`depth`, `offset`, `distance`, `within`, `nocase`) written after
  their `content` with a comma, as Snort 3 requires.

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
| `smb2-security-mode`, `smb2-time` (default scripts) | SMB2 NEGOTIATE client GUID `FeroProbeSMBScan`; on port 139 the NetBIOS calling name `FEROPROBE` |
| `rdp-ntlm-info` (default script) | RDP connection request cookie `Cookie: mstshash=FeroProbe` |
| `nbstat` (default script), and the `-sU`/`-sV` probe to UDP 137 | NetBIOS NODE STATUS request to UDP 137 with transaction ID `0x4650` ("FP") |
| `ssl-date` (default script) | TLS ClientHello random `FeroProbeSSLDate` (bytes 15-30 of the record) |
| `dns-nsid` (default script) | DNS CHAOS TXT queries (`id.server`, `version.bind`) with transaction ID `0x4650` ("FP") and no flags, over UDP (SID 9100014) or TCP (SID 9100015) |

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

First copy the file for your Snort version (`feroprobe.snort.rules` for
2.9.x, `feroprobe.snort3.rules` for 3.x) to a directory Snort already
searches — usually the one that holds your other rule files — or note its
absolute path, so the include below can find it.

For **Snort 2.9.x**, add `feroprobe.snort.rules` to `snort.conf`, where
`$RULE_PATH` is the rules directory your config already defines:

```
include $RULE_PATH/feroprobe.snort.rules
```

For **Snort 3.x**, use `feroprobe.snort3.rules`: Snort 3 refuses the 2.9
form of the content modifiers. Add an `include` entry to the `ips` table in
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
    include = '/etc/snort/rules/feroprobe.snort3.rules',
}
```

`ips.include` takes a single file. If your `ips` table already includes
`feroprobe.snort.rules` (the earlier instructions used it for Snort 3 too),
change that entry to `feroprobe.snort3.rules`. If it includes an unrelated
rules file, load these rules inline through `ips.rules` instead, following
your existing configuration.

In Snort 3, SID 9100006 reads the parsed `User-Agent` header through
`http_inspect`, so the HTTP inspector must be enabled and the binder must send
HTTP flows to it. Both hold in the default configuration; with custom
`binder` settings, check that HTTP traffic is still bound to `http_inspect`.

The rules use the local SID range `9100000+` and the `attempted-recon`
class. Adjust the SIDs and `$HOME_NET` to fit your deployment.

If you enable SIDs one by one, enable SID 9100013 together with SID 9100003.
The `-sU` probe to UDP 137 used to carry the generic `FeroProbeScan/1`
payload (SID 9100003); it now sends the NetBIOS NODE STATUS request, which
only SID 9100013 matches. The `-sV` NetBIOS probe already sent that
request.
