//! Port specification parsing (nmap-style `-p` syntax).

use crate::Error;
use crate::model::Protocol;

/// A curated list of commonly open TCP ports, ordered roughly by how often
/// they are seen open on the internet. Used when no ports are specified.
pub const TOP_PORTS: &[u16] = &[
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111, 995, 993,
    5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001, 10000, 514, 5060, 179, 1026, 2000,
    8443, 8000, 32768, 554, 26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631,
    631, 49153, 8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156,
    543, 544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009, 7070, 5190, 3000, 5432, 1900, 3986,
    13, 1029, 9, 5051, 6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37, 6379, 27017, 9200,
    11211, 5672, 1883, 8883, 2375, 6443, 9090, 9443, 5985, 5986, 161, 162, 69, 123,
];

/// A curated list of UDP services, ordered roughly by how often they are
/// found answering: network infrastructure first (DNS, NTP, SNMP, NetBIOS,
/// DHCP, IKE, syslog, UPnP, mDNS), then VPN, VoIP, management, industrial
/// and game ports. The first 20 are the default for UDP scans; `-F` takes
/// all 100.
pub const TOP_UDP_PORTS: &[u16] = &[
    53, 123, 161, 137, 67, 68, 69, 500, 514, 520, 1900, 5353, 138, 139, 135, 445, 631, 1434, 4500,
    49152, 162, 111, 88, 389, 2049, 1812, 1813, 1645, 1646, 1701, 1194, 5060, 3478, 443, 5355,
    3702, 5683, 51820, 623, 546, 547, 427, 464, 177, 199, 521, 1719, 3283, 3389, 3544, 4789, 5004,
    5005, 5351, 5632, 7, 9, 13, 17, 19, 37, 49, 513, 517, 518, 1025, 1026, 1027, 1028, 1029, 2123,
    2152, 2427, 2727, 5000, 5093, 9600, 10000, 11211, 17185, 20000, 27015, 30718, 33434, 44818,
    47808, 49153, 49154, 49156, 32768, 32769, 32771, 1718, 1604, 2222, 1985, 3784, 5684, 9987,
    3074,
];

/// The service usually found on a port, for display when version
/// detection did not run or learned nothing. Purely a label from the port
/// number.
pub fn service_name(protocol: Protocol, port: u16) -> &'static str {
    match (protocol, port) {
        (Protocol::Tcp, 21) => "ftp",
        (Protocol::Tcp, 22) => "ssh",
        (Protocol::Tcp, 23) => "telnet",
        (Protocol::Tcp, 25) => "smtp",
        (_, 53) => "domain",
        (Protocol::Udp, 67) => "dhcps",
        (Protocol::Udp, 68) => "dhcpc",
        (Protocol::Udp, 69) => "tftp",
        (Protocol::Tcp, 80) => "http",
        (Protocol::Tcp, 110) => "pop3",
        (_, 111) => "rpcbind",
        (Protocol::Udp, 123) => "ntp",
        (Protocol::Tcp, 135) => "msrpc",
        (Protocol::Udp, 137) => "netbios-ns",
        (Protocol::Udp, 138) => "netbios-dgm",
        (Protocol::Tcp, 139) => "netbios-ssn",
        (Protocol::Tcp, 143) => "imap",
        (Protocol::Udp, 161) => "snmp",
        (Protocol::Udp, 162) => "snmptrap",
        (Protocol::Tcp, 389) => "ldap",
        (Protocol::Tcp, 443) => "https",
        (Protocol::Tcp, 445) => "microsoft-ds",
        (Protocol::Tcp, 465) => "smtps",
        (Protocol::Udp, 500) => "isakmp",
        (Protocol::Udp, 514) => "syslog",
        (Protocol::Tcp, 587) => "submission",
        (Protocol::Tcp, 993) => "imaps",
        (Protocol::Tcp, 995) => "pop3s",
        (Protocol::Tcp, 1433) => "ms-sql-s",
        (Protocol::Tcp, 1883) => "mqtt",
        (Protocol::Udp, 1900) => "upnp",
        (_, 2049) => "nfs",
        (Protocol::Tcp, 2375) => "docker",
        (Protocol::Tcp, 3306) => "mysql",
        (Protocol::Tcp, 3389) => "ms-wbt-server",
        (Protocol::Udp, 4500) => "nat-t-ike",
        (Protocol::Tcp, 5432) => "postgresql",
        (Protocol::Udp, 5353) => "mdns",
        (Protocol::Tcp, 5672) => "amqp",
        (Protocol::Tcp, 5900) => "vnc",
        (Protocol::Tcp, 6379) => "redis",
        (Protocol::Tcp, 6443) => "kubernetes",
        (Protocol::Tcp, 8080) => "http-proxy",
        (Protocol::Tcp, 8443) => "https-alt",
        (Protocol::Tcp, 9200) => "elasticsearch",
        (_, 11211) => "memcache",
        (Protocol::Tcp, 27017) => "mongodb",
        _ => "unknown",
    }
}

/// Parse an nmap-style port specification.
///
/// Accepts a comma-separated list of single ports (`22`), ranges (`1-1024`),
/// open-ended ranges (`-1024`, `60000-`) and `-` for all ports (1-65535).
/// The result is sorted and de-duplicated.
pub fn parse_ports(spec: &str) -> Result<Vec<u16>, Error> {
    let mut ports = Vec::new();
    for part in spec.split(',').map(str::trim) {
        if part.is_empty() {
            return Err(Error::InvalidPorts(format!("empty entry in '{spec}'")));
        }
        if let Some((start, end)) = part.split_once('-') {
            let start = if start.is_empty() {
                1
            } else {
                parse_port(start)?
            };
            let end = if end.is_empty() {
                65535
            } else {
                parse_port(end)?
            };
            if start > end {
                return Err(Error::InvalidPorts(format!(
                    "range start is greater than end in '{part}'"
                )));
            }
            ports.extend(start..=end);
        } else {
            ports.push(parse_port(part)?);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

/// TCP and UDP ports from one nmap-style specification.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortLists {
    pub tcp: Vec<u16>,
    pub udp: Vec<u16>,
}

/// Parse a port specification that may name its protocol, like nmap's
/// `-p 22,T:80,U:53,161`: `T:` and `U:` apply to the ports after them until
/// the next prefix, and ports before any prefix are both TCP and UDP. Each
/// list is sorted and de-duplicated.
pub fn parse_port_lists(spec: &str) -> Result<PortLists, Error> {
    #[derive(Clone, Copy, PartialEq)]
    enum Proto {
        Both,
        Tcp,
        Udp,
    }
    let mut groups: Vec<(Proto, Vec<&str>)> = Vec::new();
    let mut current = Proto::Both;
    for part in spec.split(',').map(str::trim) {
        let lower = part.get(..2).map(str::to_ascii_uppercase);
        let rest = match lower.as_deref() {
            Some("T:") => {
                current = Proto::Tcp;
                &part[2..]
            }
            Some("U:") => {
                current = Proto::Udp;
                &part[2..]
            }
            Some("S:" | "P:") => {
                return Err(Error::InvalidPorts(format!(
                    "'{part}': only T: (TCP) and U: (UDP) ports are supported"
                )));
            }
            _ => part,
        };
        match groups.last_mut() {
            Some((proto, parts)) if *proto == current => parts.push(rest),
            _ => groups.push((current, vec![rest])),
        }
    }
    let mut lists = PortLists::default();
    for (proto, parts) in groups {
        let ports = parse_ports(&parts.join(",")).map_err(|e| match e {
            Error::InvalidPorts(why) => Error::InvalidPorts(format!("{why} (in '{spec}')")),
            other => other,
        })?;
        if proto != Proto::Udp {
            lists.tcp.extend(&ports);
        }
        if proto != Proto::Tcp {
            lists.udp.extend(&ports);
        }
    }
    for list in [&mut lists.tcp, &mut lists.udp] {
        list.sort_unstable();
        list.dedup();
    }
    Ok(lists)
}

/// The `n` most common ports, sorted ascending.
///
/// Takes ports from [`TOP_PORTS`] first; if `n` is larger than that list, the
/// remaining ports are filled in ascending order from 1 up, so the caller always
/// gets `min(n, 65535)` ports.
pub fn top_ports(n: usize) -> Vec<u16> {
    top_from(TOP_PORTS, n)
}

/// Like [`top_ports`], for UDP, starting from [`TOP_UDP_PORTS`].
pub fn top_udp_ports(n: usize) -> Vec<u16> {
    top_from(TOP_UDP_PORTS, n)
}

fn top_from(list: &[u16], n: usize) -> Vec<u16> {
    let n = n.min(65535);
    let mut ports: Vec<u16> = list.iter().copied().take(n).collect();
    if ports.len() < n {
        let known: std::collections::HashSet<u16> = ports.iter().copied().collect();
        let extra = n - ports.len();
        ports.extend((1..=65535).filter(|p| !known.contains(p)).take(extra));
    }
    ports.sort_unstable();
    ports
}

fn parse_port(s: &str) -> Result<u16, Error> {
    match s.trim().parse::<u16>() {
        Ok(0) => Err(Error::InvalidPorts("port 0 is not scannable".into())),
        Ok(p) => Ok(p),
        Err(_) => Err(Error::InvalidPorts(format!("'{s}' is not a valid port"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_and_list() {
        assert_eq!(parse_ports("22").unwrap(), vec![22]);
        assert_eq!(parse_ports("443, 22,80").unwrap(), vec![22, 80, 443]);
    }

    #[test]
    fn ranges() {
        assert_eq!(parse_ports("20-23").unwrap(), vec![20, 21, 22, 23]);
        assert_eq!(parse_ports("-3").unwrap(), vec![1, 2, 3]);
        assert_eq!(parse_ports("65534-").unwrap(), vec![65534, 65535]);
        assert_eq!(parse_ports("-").unwrap().len(), 65535);
    }

    #[test]
    fn dedup_overlapping() {
        assert_eq!(parse_ports("1-3,2,3-4").unwrap(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn protocol_prefixes() {
        let l = parse_port_lists("22,T:80,443,U:53,161").unwrap();
        assert_eq!(l.tcp, vec![22, 80, 443]);
        assert_eq!(l.udp, vec![22, 53, 161]);
        let l = parse_port_lists("U:53,t:1-3").unwrap();
        assert_eq!(l.tcp, vec![1, 2, 3]);
        assert_eq!(l.udp, vec![53]);
        let l = parse_port_lists("U:-").unwrap();
        assert!(l.tcp.is_empty());
        assert_eq!(l.udp.len(), 65535);
        let l = parse_port_lists("80,80,T:80").unwrap();
        assert_eq!((l.tcp, l.udp), (vec![80], vec![80]));
        for bad in ["", "T:", "S:80", "U:0", "T:22,,80", "X:22"] {
            assert!(parse_port_lists(bad).is_err(), "{bad} should fail");
        }
    }

    #[test]
    fn rejects_bad_input() {
        for bad in ["", "0", "70000", "abc", "10-5", "22,,80"] {
            assert!(parse_ports(bad).is_err(), "{bad} should fail");
        }
    }

    #[test]
    fn top_udp_ports_are_all_ranked() {
        assert_eq!(TOP_UDP_PORTS.len(), 100);
        let fast = top_udp_ports(100);
        let mut ranked = TOP_UDP_PORTS.to_vec();
        ranked.sort_unstable();
        assert_eq!(fast, ranked);
        let default = top_udp_ports(20);
        for p in [53, 67, 69, 123, 137, 161, 500, 514, 1900, 5353] {
            assert!(default.contains(&p), "{p}");
        }
        for p in [1194, 1812, 3478, 5060, 51820, 47808] {
            assert!(fast.contains(&p) && !default.contains(&p), "{p}");
        }
    }

    #[test]
    fn top_ports_has_no_duplicates() {
        let mut list = TOP_PORTS.to_vec();
        list.sort_unstable();
        list.dedup();
        assert_eq!(list.len(), TOP_PORTS.len());
        for n in [1, 50, 1000, 70000] {
            let ports = top_ports(n);
            assert_eq!(ports.len(), n.min(65535));
            assert!(ports.windows(2).all(|w| w[0] < w[1]));
        }
        assert_eq!(top_ports(3), vec![23, 80, 443]);
        assert_eq!(top_udp_ports(2), vec![53, 123]);
        assert_eq!(top_udp_ports(500).len(), 500);
    }
}
