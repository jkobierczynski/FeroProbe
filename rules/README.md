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

The TCP window of a scan probe is otherwise meaningless, because the scan
never completes a handshake, so the fixed window does not change how the
probe behaves or how the target answers it.

Two scans carry **no** marker, by design:

- The TCP **connect** scan (`-sT`) completes a normal handshake through the
  operating system's TCP stack, so it looks like an ordinary connection.
- **OS-detection** probes (`-O`) deliberately mimic a real OS stack to read
  the target's response, so they do not carry the window marker.

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

### Snort

Include `feroprobe.snort.rules` from your `snort.conf` / `snort.lua`:

```
include $RULE_PATH/feroprobe.snort.rules
```

The rules use the local SID range `9100000+` and the `attempted-recon`
class. Adjust the SIDs and `$HOME_NET` to fit your deployment.
