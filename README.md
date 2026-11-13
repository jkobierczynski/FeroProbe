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
| Service and version detection, `-sV`, with our own probes and rules | ✅ |
| ARP discovery on the local network | planned |
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

# Which software runs on the open ports
./target/release/feroprobe -sV -p 22,80,443,6379 10.0.0.5

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

With `-sV`:

```
PORT       STATE          SERVICE        VERSION
22/tcp     open           ssh            OpenSSH 9.6p1 (Ubuntu-3ubuntu13.5; protocol 2.0)
443/tcp    open           ssl/http       nginx 1.25.3 (cert CN: example.org)
6379/tcp   open           redis          Redis key-value store 7.0.15
```

### Version detection

`-sV` connects to each open port and works out what is running:

1. On usual TLS ports (443, 993, 8443, ...) it tries TLS first and probes
   the service inside the tunnel. The certificate's subject name is shown.
2. It sends the probes meant for that port, such as HTTP on 80 or Redis on 6379.
3. It listens, since SSH, FTP, SMTP, POP3, IMAP, MySQL and VNC talk first.
4. If the service is still silent, it tries HTTP and then TLS.

Replies are matched against FeroProbe's own rules in
`crates/feroprobe-core/src/service/rules.rs`. nmap's probe database is not used,
because its license does not allow redistributing it. Replies that no rule
recognizes are printed under "Unrecognized service replies", which is the
starting point for a new rule. Open UDP ports get a DNS `version.bind`, NTP or
SNMP query. `--version-timeout` sets how long to wait for each reply (default
3000 ms).

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
