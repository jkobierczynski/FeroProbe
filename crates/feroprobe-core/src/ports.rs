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
    match protocol {
        Protocol::Ip => return u8::try_from(port).map_or("unknown", ip_protocol_name),
        Protocol::Sctp => return sctp_service_name(port),
        Protocol::Tcp | Protocol::Udp => {}
    }
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

/// SCTP services by port (IANA's registry), falling back to the TCP name,
/// since many services use the same port over both.
fn sctp_service_name(port: u16) -> &'static str {
    match port {
        9 => "discard",
        179 => "bgp",
        1167 => "cisco-ipsla",
        2225 => "rcip-itu",
        2904 => "m2ua",
        2905 => "m3ua",
        2944 => "megaco-h248",
        2945 => "h248-binary",
        3097 => "itu-bicc-stc",
        3565 => "m2pa",
        3863 => "asap-sctp",
        3864 => "asap-sctp-tls",
        3868 => "diameter",
        5060 => "sip",
        5061 => "sip-tls",
        5090 => "car",
        5091 => "cxtp",
        6704 => "frc-hp",
        6705 => "frc-mp",
        6706 => "frc-lp",
        7626 => "simco",
        9900 => "iua",
        9901 => "enrp-sctp",
        9902 => "enrp-sctp-tls",
        14001 => "sua",
        29118 => "sgsap",
        29168 => "sbcap",
        29169 => "iuhsctpassoc",
        36412 => "s1-control",
        36422 => "x2-control",
        36443 => "m2ap",
        36444 => "m3ap",
        38412 => "ng-control",
        38422 => "xw-control",
        38472 => "f1-control",
        other => service_name(Protocol::Tcp, other),
    }
}

/// The keyword IANA's protocol numbers registry gives IP protocol
/// `proto`, in lower case as `-sO` shows it, or "unknown".
pub fn ip_protocol_name(proto: u8) -> &'static str {
    const NAMES: [&str; 146] = [
        "hopopt",
        "icmp",
        "igmp",
        "ggp",
        "ipv4",
        "st",
        "tcp",
        "cbt",
        "egp",
        "igp",
        "bbn-rcc-mon",
        "nvp-ii",
        "pup",
        "argus",
        "emcon",
        "xnet",
        "chaos",
        "udp",
        "mux",
        "dcn-meas",
        "hmp",
        "prm",
        "xns-idp",
        "trunk-1",
        "trunk-2",
        "leaf-1",
        "leaf-2",
        "rdp",
        "irtp",
        "iso-tp4",
        "netblt",
        "mfe-nsp",
        "merit-inp",
        "dccp",
        "3pc",
        "idpr",
        "xtp",
        "ddp",
        "idpr-cmtp",
        "tp++",
        "il",
        "ipv6",
        "sdrp",
        "ipv6-route",
        "ipv6-frag",
        "idrp",
        "rsvp",
        "gre",
        "dsr",
        "bna",
        "esp",
        "ah",
        "i-nlsp",
        "swipe",
        "narp",
        "mobile",
        "tlsp",
        "skip",
        "ipv6-icmp",
        "ipv6-nonxt",
        "ipv6-opts",
        "unknown",
        "cftp",
        "unknown",
        "sat-expak",
        "kryptolan",
        "rvd",
        "ippc",
        "unknown",
        "sat-mon",
        "visa",
        "ipcv",
        "cpnx",
        "cphb",
        "wsn",
        "pvp",
        "br-sat-mon",
        "sun-nd",
        "wb-mon",
        "wb-expak",
        "iso-ip",
        "vmtp",
        "secure-vmtp",
        "vines",
        "ttp",
        "nsfnet-igp",
        "dgp",
        "tcf",
        "eigrp",
        "ospfigp",
        "sprite-rpc",
        "larp",
        "mtp",
        "ax.25",
        "ipip",
        "micp",
        "scc-sp",
        "etherip",
        "encap",
        "unknown",
        "gmtp",
        "ifmp",
        "pnni",
        "pim",
        "aris",
        "scps",
        "qnx",
        "a/n",
        "ipcomp",
        "snp",
        "compaq-peer",
        "ipx-in-ip",
        "vrrp",
        "pgm",
        "unknown",
        "l2tp",
        "ddx",
        "iatp",
        "stp",
        "srp",
        "uti",
        "smp",
        "sm",
        "ptp",
        "isis",
        "fire",
        "crtp",
        "crudp",
        "sscopmce",
        "iplt",
        "sps",
        "pipe",
        "sctp",
        "fc",
        "rsvp-e2e-ignore",
        "mobility-hdr",
        "udplite",
        "mpls-in-ip",
        "manet",
        "hip",
        "shim6",
        "wesp",
        "rohc",
        "ethernet",
        "aggfrag",
        "nsh",
    ];
    NAMES
        .get(usize::from(proto))
        .copied()
        .unwrap_or(match proto {
            253 | 254 => "experimental",
            255 => "reserved",
            _ => "unknown",
        })
}

/// Common SCTP ports, most used first: signalling for telephone and
/// mobile networks (SIGTRAN, Diameter, S1/NG), and services that also
/// run over SCTP. From IANA's registry and published deployments.
pub const TOP_SCTP_PORTS: &[u16] = &[
    80, 3868, 2905, 36412, 38412, 2904, 5060, 5061, 179, 443, 9, 22, 21, 2944, 2945, 3565, 3863,
    3864, 14001, 29118, 29168, 29169, 36422, 36443, 36444, 38422, 38472, 1167, 2225, 3097, 5090,
    5091, 6704, 6705, 6706, 7626, 9900, 9901, 9902, 1720, 1812, 1813, 4739, 5672, 8282, 20049,
    7701, 8471, 9082, 9084, 25471, 30100,
];

/// Like [`top_ports`], for SCTP, starting from [`TOP_SCTP_PORTS`].
pub fn top_sctp_ports(n: usize) -> Vec<u16> {
    top_from(TOP_SCTP_PORTS, n)
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

/// TCP, UDP and SCTP ports, and IP protocol numbers, from one nmap-style
/// specification.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortLists {
    pub tcp: Vec<u16>,
    pub udp: Vec<u16>,
    pub sctp: Vec<u16>,
    /// IP protocol numbers for `-sO`. They may be out of range (over
    /// 255): the caller decides, as only `-sO` reads them.
    pub protocols: Vec<u16>,
}

/// Parse a port specification that may name its protocol, like nmap's
/// `-p 22,T:80,U:53,S:2905,161`: `T:` (TCP), `U:` (UDP), `S:` (SCTP) and
/// `P:` (IP protocols, for `-sO`) apply to the ports after them until the
/// next prefix, and ports before any prefix go in every list. Each list
/// is sorted and de-duplicated.
pub fn parse_port_lists(spec: &str) -> Result<PortLists, Error> {
    #[derive(Clone, Copy, PartialEq)]
    enum Proto {
        All,
        Tcp,
        Udp,
        Sctp,
        Ip,
    }
    let mut groups: Vec<(Proto, Vec<&str>)> = Vec::new();
    let mut current = Proto::All;
    for part in spec.split(',').map(str::trim) {
        let prefix = part.get(..2).map(str::to_ascii_uppercase);
        let named = match prefix.as_deref() {
            Some("T:") => Some(Proto::Tcp),
            Some("U:") => Some(Proto::Udp),
            Some("S:") => Some(Proto::Sctp),
            Some("P:") => Some(Proto::Ip),
            _ => None,
        };
        let rest = match named {
            Some(p) => {
                current = p;
                &part[2..]
            }
            None => part,
        };
        match groups.last_mut() {
            Some((proto, parts)) if *proto == current => parts.push(rest),
            _ => groups.push((current, vec![rest])),
        }
    }
    let mut lists = PortLists::default();
    for (proto, parts) in groups {
        let joined = parts.join(",");
        // Protocol 0 is valid, and "-" means all of them, 0-255.
        let ports = if proto == Proto::Ip {
            parse_protocols(&joined)
        } else {
            parse_ports(&joined)
        }
        .map_err(|e| match e {
            Error::InvalidPorts(why) => Error::InvalidPorts(format!("{why} (in '{spec}')")),
            other => other,
        })?;
        for (p, list) in [
            (Proto::Tcp, &mut lists.tcp),
            (Proto::Udp, &mut lists.udp),
            (Proto::Sctp, &mut lists.sctp),
            (Proto::Ip, &mut lists.protocols),
        ] {
            if proto == p || proto == Proto::All {
                list.extend(&ports);
            }
        }
    }
    for list in [
        &mut lists.tcp,
        &mut lists.udp,
        &mut lists.sctp,
        &mut lists.protocols,
    ] {
        list.sort_unstable();
        list.dedup();
    }
    Ok(lists)
}

/// Parse IP protocol numbers for `-sO`, like [`parse_ports`] but from 0,
/// with "-" or an open range ending at 255.
pub fn parse_protocols(spec: &str) -> Result<Vec<u16>, Error> {
    let mut protos = Vec::new();
    for part in spec.split(',').map(str::trim) {
        let num = |s: &str, default: u16| -> Result<u16, Error> {
            if s.is_empty() {
                return Ok(default);
            }
            match s.parse::<u16>() {
                Ok(n) if n <= 255 => Ok(n),
                _ => Err(Error::InvalidPorts(format!(
                    "'{s}' is not an IP protocol number (0-255)"
                ))),
            }
        };
        if part.is_empty() {
            return Err(Error::InvalidPorts(format!("empty entry in '{spec}'")));
        }
        let (start, end) = match part.split_once('-') {
            Some((a, b)) => (num(a, 0)?, num(b, 255)?),
            None => {
                let n = num(part, 0)?;
                (n, n)
            }
        };
        if start > end {
            return Err(Error::InvalidPorts(format!(
                "range start is greater than end in '{part}'"
            )));
        }
        protos.extend(start..=end);
    }
    protos.sort_unstable();
    protos.dedup();
    Ok(protos)
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
        for bad in ["", "T:", "S:0", "U:0", "T:22,,80", "X:22", "P:256"] {
            assert!(parse_port_lists(bad).is_err(), "{bad} should fail");
        }
    }

    #[test]
    fn sctp_and_protocol_prefixes() {
        let l = parse_port_lists("22,S:2905,P:1,6,17,0").unwrap();
        assert_eq!(l.tcp, vec![22]);
        assert_eq!(l.sctp, vec![22, 2905]);
        assert_eq!(l.protocols, vec![0, 1, 6, 17, 22]);
        assert_eq!(parse_protocols("-").unwrap().len(), 256);
        assert_eq!(
            parse_protocols("250-").unwrap(),
            vec![250, 251, 252, 253, 254, 255]
        );
        assert!(parse_protocols("300").is_err());
    }

    #[test]
    fn names_for_ip_protocols_and_sctp_ports() {
        assert_eq!(service_name(Protocol::Ip, 1), "icmp");
        assert_eq!(service_name(Protocol::Ip, 47), "gre");
        assert_eq!(service_name(Protocol::Ip, 50), "esp");
        assert_eq!(service_name(Protocol::Ip, 89), "ospfigp");
        assert_eq!(service_name(Protocol::Ip, 112), "vrrp");
        assert_eq!(service_name(Protocol::Ip, 132), "sctp");
        assert_eq!(service_name(Protocol::Ip, 145), "nsh");
        assert_eq!(service_name(Protocol::Ip, 200), "unknown");
        assert_eq!(service_name(Protocol::Ip, 255), "reserved");
        assert_eq!(service_name(Protocol::Sctp, 3868), "diameter");
        assert_eq!(service_name(Protocol::Sctp, 80), "http");
        let top = top_sctp_ports(TOP_SCTP_PORTS.len());
        assert_eq!(top.len(), TOP_SCTP_PORTS.len(), "no duplicates");
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
