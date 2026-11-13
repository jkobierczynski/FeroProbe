# FeroProbe

A fast, nmap-style network scanner written natively in Rust: no nmap, no libpcap,
no external binaries.

> Only scan networks and hosts you own or have explicit permission to test.

## Status

| Feature | State |
| --- | --- |
| TCP connect scan, `-sT` (no root needed) | ✅ |
| TCP SYN scan, `-sS` (raw sockets, Linux, root or `CAP_NET_RAW`) | ✅ |
| UDP scan, `-sU`, with DNS, NTP, SNMP and SSDP payloads | ✅ |
| Host discovery: ICMP echo + TCP 443/80 probes, `-sn`, `-Pn` | ✅ |
| Targets: IPs, CIDR, `a.b.c.X-Y` ranges, hostnames, IPv6 (connect and UDP) | ✅ |
| nmap-style `-p` port specs and top ports | ✅ |
| Table and JSON output, `--reason`, `--open` | ✅ |
| ARP discovery on the local network | planned |
| Service and version detection | planned |
| OS fingerprinting | planned |

## Usage

```sh
cargo build --release

# Discover hosts, then scan the top 100 ports (SYN scan when root on Linux,
# connect scan otherwise)
./target/release/feroprobe 192.168.1.0/24

# Ping sweep only
./target/release/feroprobe -sn 192.168.1.0/24

# Full SYN scan of one host, showing why each port got its state
sudo ./target/release/feroprobe -sS -p - --reason 10.0.0.5

# TCP and UDP together, skipping discovery
./target/release/feroprobe -Pn -sT -sU -p 53,123,161 scanme.example.org

# Only open ports, as JSON
./target/release/feroprobe --top-ports 1000 --open -o json 10.0.0.1-50
```

Run `feroprobe --help` for all options (timeout, concurrency, packet rate, retries).

Example output:

```
Starting FeroProbe 0.1.0

Scan report for 127.0.0.1
Host is up, echo-reply (0.06 ms latency).
Not shown: 9998 closed ports
PORT       STATE          SERVICE        REASON
2024/tcp   open           unknown        syn-ack
8000/tcp   open           unknown        syn-ack

FeroProbe done: 1 host(s), 1 up, 10000 port(s) each, in 2.11s
```

### Privileges

The SYN scan sends hand-built packets over raw sockets, which needs root. On
Linux you can instead grant the binary just that capability:

```sh
sudo setcap cap_net_raw+ep ./target/release/feroprobe
```

Without it, a scan with no `-s` option uses a connect scan instead, and
discovery uses TCP probes (plus unprivileged ping sockets where the OS allows
them). An explicit `-sS` still needs the privileges; use `-sT` to ask for an
unprivileged TCP scan. The default is also a connect scan when any target is
IPv6, since the SYN scan is IPv4 only for now.

## Layout

- `crates/feroprobe-core`: the scanning engine as a library: target and port
  parsing, connect/SYN/UDP scans, host discovery, and a small packet module
  (TCP, IPv4, ICMP) with no external packet crate.
- `crates/feroprobe-cli`: the `feroprobe` command-line tool.

## Port states

| State | Meaning |
| --- | --- |
| open | TCP: SYN-ACK or completed handshake. UDP: the service replied |
| closed | TCP: the host replied with a reset. UDP: ICMP port unreachable |
| filtered | No reply (TCP) or an ICMP unreachable error from a filter |
| open\|filtered | UDP only: no reply, which can mean a silent service or a firewall |

UDP note: hosts rate-limit ICMP errors, so scanning many closed UDP ports fast
can report some as open|filtered. Lower `--concurrency` for more accuracy.

**Windows note:** Windows waits about 2 seconds after a reset before it reports
"connection refused", so the default timeout there is 3000 ms instead of 1500 ms.
With a lower `--timeout`, closed ports show as filtered on Windows. The SYN scan
(Linux only for now) does not have this limitation.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
