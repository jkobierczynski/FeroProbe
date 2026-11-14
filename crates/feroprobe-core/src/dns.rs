//! Reverse DNS: the name behind each address (its PTR record), like nmap's
//! report lines `Nmap scan report for name (address)`.
//!
//! By default the system resolver answers, so `/etc/hosts`, mDNS and the
//! configured name servers all count. With `--dns-servers` a small built-in
//! client asks the given servers directly over UDP instead.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

use futures::stream::{self, StreamExt};
use tokio::net::UdpSocket;

use crate::model::ScanConfig;

/// Lookups in flight at once.
const PARALLEL: usize = 64;

/// The name to look up for `ip`'s PTR record: `4.3.2.1.in-addr.arpa` for
/// `1.2.3.4`, and one label per nibble under `ip6.arpa` for IPv6.
pub fn ptr_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let mut s = String::with_capacity(72);
            for b in v6.octets().iter().rev() {
                s.push_str(&format!("{:x}.{:x}.", b & 0xf, b >> 4));
            }
            s.push_str("ip6.arpa");
            s
        }
    }
}

/// A DNS query for the PTR record of `name`, asking for recursion.
pub fn ptr_query(id: u16, name: &str) -> Vec<u8> {
    let mut q = Vec::with_capacity(18 + name.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]); // standard query, recursion desired
    q.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // one question
    for label in name.split('.').filter(|l| !l.is_empty()) {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&[0, 12, 0, 1]); // type PTR, class IN
    q
}

/// Read the domain name at `pos`, following compression pointers. Returns
/// the name (without the final dot) and the position after it.
fn read_name(buf: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end = None;
    // Bounds the pointer chain, so a looping message can't hang us.
    for _ in 0..64 {
        let len = *buf.get(pos)? as usize;
        match len {
            0 => {
                let next = end.unwrap_or(pos + 1);
                return Some((labels.join("."), next));
            }
            l if l & 0xc0 == 0xc0 => {
                let target = ((l & 0x3f) << 8) | *buf.get(pos + 1)? as usize;
                end.get_or_insert(pos + 2);
                pos = target;
            }
            l if l < 64 => {
                let raw = buf.get(pos + 1..pos + 1 + l)?;
                // Names end up in reports: keep them printable.
                let label: String = raw
                    .iter()
                    .map(|&c| if c.is_ascii_graphic() { c as char } else { '?' })
                    .collect();
                labels.push(label);
                pos += 1 + l;
            }
            _ => return None,
        }
    }
    None
}

/// The first PTR name in a DNS response to the query with `id`, if the
/// server found one.
pub fn parse_ptr_response(buf: &[u8], id: u16) -> Option<String> {
    if buf.len() < 12 || u16::from_be_bytes([buf[0], buf[1]]) != id {
        return None;
    }
    // A response (QR set) without an error (RCODE 0).
    if buf[2] & 0x80 == 0 || buf[3] & 0x0f != 0 {
        return None;
    }
    let questions = u16::from_be_bytes([buf[4], buf[5]]);
    let answers = u16::from_be_bytes([buf[6], buf[7]]);
    let mut pos = 12;
    for _ in 0..questions {
        pos = read_name(buf, pos)?.1 + 4;
    }
    for _ in 0..answers {
        pos = read_name(buf, pos)?.1;
        let head = buf.get(pos..pos + 10)?;
        let kind = u16::from_be_bytes([head[0], head[1]]);
        let len = u16::from_be_bytes([head[8], head[9]]) as usize;
        let data = pos + 10;
        if kind == 12 {
            let (name, _) = read_name(buf, data)?;
            return (!name.is_empty()).then_some(name);
        }
        pos = data + len;
    }
    None
}

/// Ask `servers` in turn for `ip`'s PTR record, retrying per `cfg`.
async fn query_servers(ip: IpAddr, servers: &[SocketAddr], cfg: &ScanConfig) -> Option<String> {
    let name = ptr_name(ip);
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    for attempt in 0..=cfg.retries as usize {
        let server = servers[attempt % servers.len()];
        let id = (seed as u16) ^ (attempt as u16).wrapping_mul(0x9e37);
        let bind: SocketAddr = if server.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let Ok(sock) = UdpSocket::bind(bind).await else {
            continue;
        };
        if sock.connect(server).await.is_err() || sock.send(&ptr_query(id, &name)).await.is_err() {
            continue;
        }
        let mut buf = [0u8; 1500];
        let deadline = tokio::time::Instant::now() + cfg.timeout;
        // Skip stray datagrams until the matching answer or the timeout.
        while let Ok(Ok(n)) = tokio::time::timeout_at(deadline, sock.recv(&mut buf)).await {
            if n >= 2 && u16::from_be_bytes([buf[0], buf[1]]) == id {
                // An answer without a PTR record is final: the name doesn't exist.
                return parse_ptr_response(&buf[..n], id);
            }
        }
    }
    None
}

/// Ask the system resolver for `ip`'s name.
async fn query_system(ip: IpAddr) -> Option<String> {
    let name = tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip))
        .await
        .ok()?
        .ok()?;
    let name = name.trim_end_matches('.');
    // Some resolvers hand back the address itself when there is no name.
    (!name.is_empty() && name.parse::<IpAddr>().is_err()).then(|| name.to_string())
}

/// Look up the name of every address in `addrs`: with the system resolver,
/// or with the DNS `servers` when any are given. Addresses without a name
/// are left out.
pub async fn reverse_lookup(
    addrs: &[IpAddr],
    servers: &[SocketAddr],
    cfg: &ScanConfig,
) -> io::Result<HashMap<IpAddr, String>> {
    let mut unique = addrs.to_vec();
    unique.sort();
    unique.dedup();
    let names = stream::iter(unique)
        .map(|ip| async move {
            let name = if servers.is_empty() {
                query_system(ip).await
            } else {
                query_servers(ip, servers, cfg).await
            };
            (ip, name)
        })
        .buffer_unordered(PARALLEL.min(cfg.concurrency.max(1)))
        .filter_map(|(ip, name)| std::future::ready(name.map(|n| (ip, n))))
        .collect()
        .await;
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ptr_names() {
        assert_eq!(
            ptr_name("192.0.2.10".parse().unwrap()),
            "10.2.0.192.in-addr.arpa"
        );
        assert_eq!(
            ptr_name("2001:db8::567:89ab".parse().unwrap()),
            "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
    }

    /// A response to `query` carrying `answers` as (type, rdata) records,
    /// each owned by a pointer to the question name.
    fn response(query: &[u8], rcode: u8, answers: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut r = query.to_vec();
        r[2] = 0x81;
        r[3] = 0x80 | rcode;
        r[6..8].copy_from_slice(&(answers.len() as u16).to_be_bytes());
        for (kind, data) in answers {
            r.extend_from_slice(&[0xc0, 12]);
            r.extend_from_slice(&kind.to_be_bytes());
            r.extend_from_slice(&[0, 1, 0, 0, 0x0e, 0x10]);
            r.extend_from_slice(&(data.len() as u16).to_be_bytes());
            r.extend_from_slice(data);
        }
        r
    }

    #[test]
    fn query_and_answer() {
        let q = ptr_query(0xbeef, "10.2.0.192.in-addr.arpa");
        assert_eq!(&q[..4], &[0xbe, 0xef, 0x01, 0x00]);
        assert_eq!(q[12], 2);
        assert_eq!(&q[13..15], b"10");
        assert_eq!(&q[q.len() - 4..], &[0, 12, 0, 1]);

        // A name written out, after a record of another type.
        let web = b"\x03web\x07example\x00".to_vec();
        let r = response(&q, 0, &[(5, b"\x01x\x00".to_vec()), (12, web)]);
        assert_eq!(
            parse_ptr_response(&r, 0xbeef).as_deref(),
            Some("web.example")
        );
        // A label plus a compression pointer back to the question name.
        let r = response(&q, 0, &[(12, vec![4, b'm', b'a', b'i', b'l', 0xc0, 12])]);
        assert_eq!(
            parse_ptr_response(&r, 0xbeef).as_deref(),
            Some("mail.10.2.0.192.in-addr.arpa")
        );

        // Wrong id, NXDOMAIN, no PTR record, truncated: no name.
        let r = response(&q, 0, &[(12, b"\x01a\x00".to_vec())]);
        assert_eq!(parse_ptr_response(&r, 0xbeef).as_deref(), Some("a"));
        assert_eq!(parse_ptr_response(&r, 0x1234), None);
        assert_eq!(parse_ptr_response(&response(&q, 3, &[]), 0xbeef), None);
        assert_eq!(parse_ptr_response(&response(&q, 0, &[]), 0xbeef), None);
        assert_eq!(parse_ptr_response(&r[..r.len() - 2], 0xbeef), None);
    }

    #[test]
    fn compression_loops_end() {
        let q = ptr_query(1, "x");
        let mut r = response(&q, 0, &[(12, vec![0xc0, 0])]);
        // Point the answer's data at itself.
        let at = r.len() - 2;
        r[at + 1] = at as u8;
        assert_eq!(parse_ptr_response(&r, 1), None);
    }

    #[tokio::test]
    async fn servers_answer_ptr_queries() {
        // A one-shot DNS server on localhost that names every address.
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, from) = server.recv_from(&mut buf).await.unwrap();
            let r = response(&buf[..n], 0, &[(12, b"\x04host\x04test\x00".to_vec())]);
            server.send_to(&r, from).await.unwrap();
        });
        let cfg = ScanConfig {
            timeout: std::time::Duration::from_secs(5),
            ..Default::default()
        };
        let ip: IpAddr = "192.0.2.7".parse().unwrap();
        let names = reverse_lookup(&[ip, ip], &[addr], &cfg).await.unwrap();
        assert_eq!(names.get(&ip).map(String::as_str), Some("host.test"));
        task.await.unwrap();
    }
}
