//! Port specification parsing (nmap-style `-p` syntax).

use crate::Error;

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

/// Commonly open UDP ports, used for UDP scans when no ports are specified.
pub const TOP_UDP_PORTS: &[u16] = &[
    53, 67, 68, 69, 123, 135, 137, 138, 139, 161, 162, 445, 500, 514, 520, 631, 1434, 1900, 4500,
    5353, 49152,
];

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
    fn rejects_bad_input() {
        for bad in ["", "0", "70000", "abc", "10-5", "22,,80"] {
            assert!(parse_ports(bad).is_err(), "{bad} should fail");
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
        assert_eq!(top_udp_ports(2), vec![53, 67]);
        assert_eq!(top_udp_ports(500).len(), 500);
    }
}
