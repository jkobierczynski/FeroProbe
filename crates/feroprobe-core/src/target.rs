//! Target specification parsing and resolution.
//!
//! Supported forms, mirroring nmap:
//! - single IPv4/IPv6 address: `192.168.1.10`, `::1`
//! - IPv6 link-local address with its interface: `fe80::1%eth0`, `fe80::1%2`
//! - CIDR block: `10.0.0.0/24`, `fe80::/120`
//! - last-octet range: `192.168.1.1-20`
//! - hostname: `scanme.example.org` (resolved via the system resolver)
//!
//! A link-local IPv6 address (`fe80::/10`) only means something together with
//! the interface it is on. Give it as `fe80::1%eth0`; without one, the only
//! interface that has a link-local address is used. Build socket addresses
//! with [`socket_addr`] so that this scope is applied.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::{OnceLock, RwLock};

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
    /// A link-local IPv6 address and the interface (index) it is on.
    Scoped(Ipv6Addr, u32),
}

/// Which address to use when a hostname has both IPv4 and IPv6 ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IpVersion {
    /// Prefer IPv4, like nmap; fall back to IPv6 if the name has no IPv4.
    #[default]
    PreferV4,
    /// Use IPv6 only (nmap's `-6`).
    V6,
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

    // The resolver would read "2222" as the address 0.0.8.174. A bare
    // number is almost always a port that came loose from its option, as
    // in `-PS 2222`.
    if spec.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::InvalidTarget(format!(
            "'{spec}' is a number, not a host; if it is a port, attach it to its option (-PS{spec}, not -PS {spec})"
        )));
    }

    if let Some((addr, zone)) = spec.split_once('%') {
        let ip: Ipv6Addr = addr
            .parse()
            .map_err(|_| Error::InvalidTarget(format!("'{addr}' is not an IPv6 address")))?;
        if !is_link_local(ip) {
            return Err(Error::InvalidTarget(format!(
                "'{spec}': only link-local (fe80::/10) addresses take an interface"
            )));
        }
        let index = interface_index(zone)
            .ok_or_else(|| Error::InvalidTarget(format!("no network interface '{zone}'")))?;
        return Ok(TargetSpec::Scoped(ip, index));
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
    resolve_targets_with(specs, IpVersion::PreferV4).await
}

/// Like [`resolve_targets`], choosing hostname addresses by `version`.
///
/// The interfaces of link-local targets (`fe80::1%eth0`) are kept in one
/// process-wide table that [`socket_addr`] reads, since hosts are identified
/// by address alone. So a process scans one set of targets at a time, as the
/// CLI does: a later resolution that gives the same link-local address
/// another interface also moves the earlier target to it.
pub async fn resolve_targets_with<S: AsRef<str>>(
    specs: &[S],
    version: IpVersion,
) -> Result<Vec<Target>, Error> {
    let mut out: Vec<Target> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    // Interfaces given for link-local targets in this request. A host is
    // identified by its address alone, so one address cannot be scanned on
    // two interfaces in the same run.
    let mut scopes: HashMap<Ipv6Addr, u32> = HashMap::new();
    let mut add_scope = |ip: Ipv6Addr, index: u32| -> Result<(), Error> {
        match scopes.insert(ip, index) {
            Some(old) if old != index => Err(Error::InvalidTarget(format!(
                "{ip} is given on two interfaces ({old} and {index}); scan each in its own run"
            ))),
            _ => Ok(()),
        }
    };
    for spec in specs {
        match parse_target(spec.as_ref())? {
            TargetSpec::Addrs(addrs) => {
                for addr in addrs {
                    if seen.insert(addr) {
                        out.push(Target::new(addr));
                    }
                }
            }
            TargetSpec::Scoped(ip, index) => {
                add_scope(ip, index)?;
                if seen.insert(IpAddr::V6(ip)) {
                    out.push(Target::new(IpAddr::V6(ip)));
                }
            }
            TargetSpec::Hostname(name) => {
                let (addr, scope) = resolve_hostname(&name, version).await?;
                if let (IpAddr::V6(v6), Some(index)) = (addr, scope) {
                    add_scope(v6, index)?;
                }
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
    for (ip, index) in scopes {
        set_scope(ip, index);
    }
    Ok(out)
}

/// Hosts to leave out of a scan, like nmap's `--exclude`: addresses, CIDR
/// blocks (of any size), `a.b.c.X-Y` ranges and hostnames.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Exclusions {
    nets: Vec<IpNet>,
    /// Hostnames as given, lowercased, to also match targets given by name.
    names: Vec<String>,
}

impl Exclusions {
    /// Parse exclusion specs, resolving hostnames to their addresses (all
    /// of them, so a name excludes the host whichever address a target used).
    pub async fn parse<S: AsRef<str>>(specs: &[S]) -> Result<Self, Error> {
        let mut ex = Self::default();
        for spec in specs {
            let spec = spec.as_ref().trim();
            if spec.is_empty() {
                continue;
            }
            let host = |ip: IpAddr| IpNet::from(ip);
            if let Ok(ip) = spec.parse::<IpAddr>() {
                ex.nets.push(host(ip));
            } else if let Some((addr, _)) = spec.split_once('%') {
                let ip: Ipv6Addr = addr.parse().map_err(|_| {
                    Error::InvalidTarget(format!("'{addr}' is not an IPv6 address"))
                })?;
                ex.nets.push(host(IpAddr::V6(ip)));
            } else if spec.contains('/') {
                let net: IpNet = spec.parse().map_err(|_| {
                    Error::InvalidTarget(format!("'{spec}' is not a valid CIDR block"))
                })?;
                ex.nets.push(net.trunc());
            } else if let Some(addrs) = parse_octet_range(spec)? {
                ex.nets.extend(addrs.into_iter().map(host));
            } else if spec.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Error::InvalidTarget(format!(
                    "exclude '{spec}' is a number, not a host"
                )));
            } else if is_valid_hostname(spec) {
                let found = tokio::net::lookup_host((spec, 0))
                    .await
                    .map_err(|e| Error::Resolve(spec.to_string(), e.to_string()))?;
                ex.nets.extend(found.map(|sa| host(sa.ip())));
                ex.names.push(spec.to_ascii_lowercase());
            } else {
                return Err(Error::InvalidTarget(format!(
                    "exclude '{spec}' is not an address, CIDR, range or hostname"
                )));
            }
        }
        Ok(ex)
    }

    pub fn is_empty(&self) -> bool {
        self.nets.is_empty() && self.names.is_empty()
    }

    /// Whether `target` is excluded, by address or by the name it was given as.
    pub fn excludes(&self, target: &Target) -> bool {
        self.nets.iter().any(|n| n.contains(&target.addr))
            || target
                .hostname
                .as_ref()
                .is_some_and(|h| self.names.contains(&h.to_ascii_lowercase()))
    }
}

/// Resolve a hostname to a single address: IPv4 first like nmap, or only
/// IPv6 with [`IpVersion::V6`]. A link-local answer comes with the
/// interface it was found on.
async fn resolve_hostname(name: &str, version: IpVersion) -> Result<(IpAddr, Option<u32>), Error> {
    let found: Vec<SocketAddr> = tokio::net::lookup_host((name, 0))
        .await
        .map_err(|e| Error::Resolve(name.to_string(), e.to_string()))?
        .collect();
    let pick = match version {
        IpVersion::PreferV4 => found.iter().find(|a| a.is_ipv4()).or_else(|| found.first()),
        IpVersion::V6 => found.iter().find(|a| a.is_ipv6()),
    };
    let Some(sa) = pick else {
        let why = match version {
            IpVersion::V6 if !found.is_empty() => "no IPv6 address",
            _ => "no addresses returned",
        };
        return Err(Error::Resolve(name.to_string(), why.into()));
    };
    let scope = match sa {
        SocketAddr::V6(v6) if is_link_local(*v6.ip()) && v6.scope_id() != 0 => Some(v6.scope_id()),
        _ => None,
    };
    Ok((sa.ip(), scope))
}

/// Whether `ip` is a link-local unicast address (`fe80::/10`).
pub fn is_link_local(ip: Ipv6Addr) -> bool {
    ip.segments()[0] & 0xffc0 == 0xfe80
}

/// Interfaces chosen for link-local targets, by address.
static SCOPES: RwLock<Option<HashMap<Ipv6Addr, u32>>> = RwLock::new(None);

fn set_scope(ip: Ipv6Addr, index: u32) {
    let mut scopes = SCOPES.write().unwrap_or_else(|e| e.into_inner());
    scopes.get_or_insert_with(HashMap::new).insert(ip, index);
}

/// The interface index a link-local address is used on: the one given
/// with the target, or else the only interface with a link-local address.
/// `None` for other addresses, or when it is ambiguous.
pub fn scope_of(ip: Ipv6Addr) -> Option<u32> {
    if !is_link_local(ip) {
        return None;
    }
    let scopes = SCOPES.read().unwrap_or_else(|e| e.into_inner());
    if let Some(&index) = scopes.as_ref().and_then(|s| s.get(&ip)) {
        return Some(index);
    }
    default_scope()
}

/// The only up, non-loopback interface with a link-local IPv6 address.
fn default_scope() -> Option<u32> {
    static DEFAULT: OnceLock<Option<u32>> = OnceLock::new();
    *DEFAULT.get_or_init(|| {
        let mut found = crate::netif::ipv6_addrs()
            .into_iter()
            .filter(|a| is_link_local(a.addr))
            .map(|a| a.index);
        let first = found.next()?;
        found.all(|i| i == first).then_some(first)
    })
}

/// The socket address for `ip` and `port`, with the interface applied to
/// a link-local IPv6 address. Use this instead of `SocketAddr::new`.
pub fn socket_addr(ip: IpAddr, port: u16) -> SocketAddr {
    match ip {
        IpAddr::V6(v6) => SocketAddr::V6(SocketAddrV6::new(v6, port, 0, scope_of(v6).unwrap_or(0))),
        IpAddr::V4(_) => SocketAddr::new(ip, port),
    }
}

/// An interface's index from its name or number (`eth0`, `2`).
fn interface_index(zone: &str) -> Option<u32> {
    if let Ok(n) = zone.parse::<u32>() {
        return (n != 0).then_some(n);
    }
    crate::netif::index_of(zone)
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
            "2222",
            "0",
        ] {
            assert!(parse_target(bad).is_err(), "{bad} should fail");
        }
        // A bare number is most likely a port split from -PS and friends.
        let err = parse_target("2222").unwrap_err().to_string();
        assert!(err.contains("-PS2222"), "{err}");
    }

    #[test]
    fn scoped_link_local() {
        assert_eq!(
            parse_target("fe80::1%7").unwrap(),
            TargetSpec::Scoped("fe80::1".parse().unwrap(), 7)
        );
        assert!(parse_target("fe80::1%no-such-if0").is_err());
        assert!(parse_target("2001:db8::1%7").is_err());
        assert!(parse_target("fe80::1%0").is_err());
        assert!(is_link_local("fe80::1".parse().unwrap()));
        assert!(is_link_local("febf::1".parse().unwrap()));
        assert!(!is_link_local("fec0::1".parse().unwrap()));
    }

    #[tokio::test]
    async fn scope_reaches_socket_addresses() {
        // fe80::99 is only used by this test, since scopes are process-wide.
        // One address on two interfaces cannot be told apart in results.
        assert!(
            resolve_targets(&["fe80::98%3", "fe80::98%4"])
                .await
                .is_err()
        );
        let t = resolve_targets(&["fe80::99%9", "fe80::99%9"])
            .await
            .unwrap();
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].addr.to_string(), "fe80::99");
        match socket_addr(t[0].addr, 80) {
            SocketAddr::V6(a) => assert_eq!((a.port(), a.scope_id()), (80, 9)),
            other => panic!("{other}"),
        }
        let global: IpAddr = "2001:db8::1".parse().unwrap();
        match socket_addr(global, 80) {
            SocketAddr::V6(a) => assert_eq!(a.scope_id(), 0),
            other => panic!("{other}"),
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

    #[tokio::test]
    async fn exclusions_by_address_block_range_and_name() {
        let ex = Exclusions::parse(&[
            "10.0.0.5",
            "10.1.0.0/16",
            "10.2.0.1-3",
            "192.168.0.0/8",
            "localhost",
        ])
        .await
        .unwrap();
        let t = |a: &str| Target::new(a.parse().unwrap());
        assert!(ex.excludes(&t("10.0.0.5")));
        assert!(!ex.excludes(&t("10.0.0.6")));
        assert!(ex.excludes(&t("10.1.255.255")));
        assert!(ex.excludes(&t("10.2.0.3")));
        assert!(!ex.excludes(&t("10.2.0.4")));
        // A /8 written with host bits set still covers the whole block.
        assert!(ex.excludes(&t("192.1.2.3")));
        assert!(ex.excludes(&t("127.0.0.1")));
        let named = Target {
            addr: "203.0.113.9".parse().unwrap(),
            hostname: Some("LocalHost".into()),
        };
        assert!(ex.excludes(&named));
        assert!(Exclusions::parse(&["not a host!"]).await.is_err());
        assert!(Exclusions::parse(&["2222"]).await.is_err());
        assert!(Exclusions::parse(&[" "]).await.unwrap().is_empty());
    }
}
