# FeroProbe

A fast, nmap-style network scanner written natively in Rust: no nmap, no libpcap,
no external binaries.

> Only scan networks and hosts you own or have explicit permission to test.

## Status

| Feature | State |
| --- | --- |
| TCP connect scan (no root needed) | ✅ |
| Targets: IPs, CIDR, `a.b.c.X-Y` ranges, hostnames, IPv6 | ✅ |
| nmap-style `-p` port specs and top-ports | ✅ |
| Table and JSON output | ✅ |
| Host discovery (ICMP / ARP) | planned |
| SYN and UDP scans (raw sockets) | planned |
| Service and version detection | planned |
| OS fingerprinting | planned |

## Usage

```sh
cargo build --release

# Top 100 ports on a /24
./target/release/feroprobe 192.168.1.0/24

# Specific ports and ranges on a host
./target/release/feroprobe -p 22,80,443,8000-8100 scanme.example.org

# Only open ports, as JSON
./target/release/feroprobe --top-ports 1000 --open -o json 10.0.0.1-50
```

Run `feroprobe --help` for all options (timeout, concurrency, retries).

Example output:

```
Starting FeroProbe 0.1.0

Scan report for 127.0.0.1
Not shown: 8998 closed tcp ports
PORT       STATE     SERVICE
2024/tcp   open      unknown
8000/tcp   open      unknown

FeroProbe done: 1 host(s) scanned, 1 up, 9000 port(s) each, in 0.22s
```

## Layout

- `crates/feroprobe-core`: the scanning engine as a library (target and port
  parsing, async connect scan on tokio).
- `crates/feroprobe-cli`: the `feroprobe` command-line tool.

## Port states

| State | Meaning |
| --- | --- |
| open | The TCP handshake completed |
| closed | The host replied with a reset |
| filtered | No reply before the timeout (after retries), or an ICMP unreachable error |

**Windows note:** Windows waits about 2 seconds after a reset before it reports
"connection refused", so the default timeout there is 3000 ms instead of 1500 ms.
With a lower `--timeout`, closed ports show as filtered on Windows. The raw-socket
SYN scan planned next won't have this limitation.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
