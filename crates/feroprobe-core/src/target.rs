//! Target specification parsing and resolution.
//!
//! Supported forms, mirroring nmap:
//! - single IPv4/IPv6 address: `192.168.1.10`, `::1`
//! - CIDR block: `10.0.0.0/24`, `fe80::/120`
//! - last-octet range: `192.168.1.1-20`
//! - hostname: `scanme.example.org` (resolved via the system resolver)

use std::net::{IpAddr, Ipv4Addr};

use ipnet::IpNet;

use crate::Error;

/// Refuse to expand target specs larger than this many hosts.
pub const MAX_HOSTS: usize = 1 << 20;

/// A host to be scanned: its address and, if given by name, the original name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub addr: IpAddr,
    pub hostname: Option<String>,
}

impl Target {
    pub fn new(addr: IpAddr) -> Self {
        Self {
            addr,
            hostname: None,
        }
    }
}

/// A parsed but not yet resolved target specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetSpec {
    Addrs(Vec<IpAddr>),
    Hostname(String),
}

/// Parse one target specification without doing any DNS lookups.
pub fn parse_target(spec: &str) -> Result<TargetSpec, Error> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Err(Error::InvalidTarget("empty target".into()));
    }

    if let Ok(ip) = spec.parse::<IpAddr>() {
        return Ok(TargetSpec::Addrs(vec![ip]));
    }

    if spec.contains('/') {
        let net: IpNet = spec
            .parse()
            .map_err(|_| Error::InvalidTarget(format!("'{spec}' is not a valid CIDR block")))?;
        return expand_cidr(net).map(TargetSpec::Addrs);
    }

    if let Some(addrs) = parse_octet_range(spec)? {
        return Ok(TargetSpec::Addrs(addrs));
    }

    if is_valid_hostname(spec) {
        return Ok(TargetSpec::Hostname(spec.to_string()));
    }

    Err(Error::InvalidTarget(format!(
        "'{spec}' is not an address, CIDR, range or hostname"
    )))
}

/// Parse and resolve a list of target specifications into concrete hosts.
/// Duplicate addresses are removed while preserving first-seen order.
pub async fn resolve_targets<S: AsRef<str>>(specs: &[S]) -> Result<Vec<Target>, Error> {
    let mut out: Vec<Target> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for spec in specs {
        match parse_target(spec.as_ref())? {
            TargetSpec::Addrs(addrs) => {
                for addr in addrs {
                    if seen.insert(addr) {
                        out.push(Target::new(addr));
                    }
                }
            }
            TargetSpec::Hostname(name) => {
                let addr = resolve_hostname(&name).await?;
                if seen.insert(addr) {
                    out.push(Target {
                        addr,
                        hostname: Some(name),
                    });
                }
            }
        }
        if out.len() > MAX_HOSTS {
            return Err(Error::InvalidTarget(format!(
                "more than {MAX_HOSTS} hosts requested"
            )));
        }
    }
    Ok(out)
}

/// Resolve a hostname to a single address, preferring IPv4 like nmap does.
async fn resolve_hostname(name: &str) -> Result<IpAddr, Error> {
    let addrs: Vec<IpAddr> = tokio::net::lookup_host((name, 0))
        .await
        .map_err(|e| Error::Resolve(name.to_string(), e.to_string()))?
        .map(|sa| sa.ip())
        .collect();
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .copied()
        .ok_or_else(|| Error::Resolve(name.to_string(), "no addresses returned".into()))
}

fn expand_cidr(net: IpNet) -> Result<Vec<IpAddr>, Error> {
    let host_bits = u32::from(net.max_prefix_len() - net.prefix_len());
    if host_bits > 20 {
        return Err(Error::InvalidTarget(format!(
            "{net} is too large (more than {MAX_HOSTS} hosts)"
        )));
    }
    // Like nmap, include every address in the block, network and broadcast too.
    Ok(match net {
        IpNet::V4(n) => (u32::from(n.network())..=u32::from(n.broadcast()))
            .map(|v| IpAddr::V4(Ipv4Addr::from(v)))
            .collect(),
        IpNet::V6(n) => (u128::from(n.network())..=u128::from(n.broadcast()))
            .map(|v| IpAddr::V6(v.into()))
            .collect(),
    })
}

/// Parse `a.b.c.X-Y` style ranges. Returns `Ok(None)` if the spec is not of
/// that shape, so the caller can try other interpretations.
fn parse_octet_range(spec: &str) -> Result<Option<Vec<IpAddr>>, Error> {
    let Some((prefix, end)) = spec.rsplit_once('-') else {
        return Ok(None);
    };
    let Ok(start_ip) = prefix.parse::<Ipv4Addr>() else {
        return Ok(None);
    };
    let Ok(end_octet) = end.parse::<u8>() else {
        return Err(Error::InvalidTarget(format!(
            "'{end}' is not a valid octet in '{spec}'"
        )));
    };
    let [a, b, c, start_octet] = start_ip.octets();
    if start_octet > end_octet {
        return Err(Error::InvalidTarget(format!(
            "range start is greater than end in '{spec}'"
        )));
    }
    Ok(Some(
        (start_octet..=end_octet)
            .map(|d| IpAddr::V4(Ipv4Addr::new(a, b, c, d)))
            .collect(),
    ))
}

fn is_valid_hostname(s: &str) -> bool {
    s.len() <= 253
        && s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addrs(spec: &str) -> Vec<IpAddr> {
        match parse_target(spec).unwrap() {
            TargetSpec::Addrs(a) => a,
            other => panic!("expected addresses, got {other:?}"),
        }
    }

    #[test]
    fn single_addresses() {
        assert_eq!(
            addrs("10.0.0.1"),
            vec!["10.0.0.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(addrs("::1"), vec!["::1".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn cidr_blocks() {
        let a = addrs("192.168.1.0/30");
        assert_eq!(a.len(), 4);
        assert_eq!(a[0].to_string(), "192.168.1.0");
        assert_eq!(a[3].to_string(), "192.168.1.3");
        assert_eq!(addrs("10.0.0.5/32").len(), 1);
        assert_eq!(addrs("fe80::/126").len(), 4);
    }

    #[test]
    fn octet_ranges() {
        let a = addrs("192.168.1.1-3");
        assert_eq!(
            a.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["192.168.1.1", "192.168.1.2", "192.168.1.3"]
        );
    }

    #[test]
    fn hostnames() {
        assert_eq!(
            parse_target("localhost").unwrap(),
            TargetSpec::Hostname("localhost".into())
        );
        assert_eq!(
            parse_target("scan-me.example.org").unwrap(),
            TargetSpec::Hostname("scan-me.example.org".into())
        );
    }

    #[test]
    fn rejects_bad_input() {
        for bad in [
            "",
            "10.0.0.0/8",
            "10.0.0.0/33",
            "10.0.0.5-2",
            "10.0.0.1-300",
            "-bad-",
            "a b",
        ] {
            assert!(parse_target(bad).is_err(), "{bad} should fail");
        }
    }

    #[tokio::test]
    async fn resolve_dedups() {
        let t = resolve_targets(&["127.0.0.1", "127.0.0.0/31", "127.0.0.1"])
            .await
            .unwrap();
        assert_eq!(
            t.iter().map(|t| t.addr.to_string()).collect::<Vec<_>>(),
            ["127.0.0.1", "127.0.0.0"]
        );
    }
}
