//! Version information from UDP services: DNS, NTP, SNMP and SSDP.

use super::ServiceInfo;
use super::rules::clean;

/// DNS query for the TXT record `version.bind` in class CHAOS, which many
/// DNS servers answer with their software version.
const DNS_VERSION_BIND: &[u8] = &[
    0x13, 0x38, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'v', b'e', b'r',
    b's', b'i', b'o', b'n', 0x04, b'b', b'i', b'n', b'd', 0x00, 0x00, 0x10, 0x00, 0x03,
];

/// What to send to the UDP service on `port` to learn its version.
pub(super) fn payload(port: u16) -> Option<&'static [u8]> {
    match port {
        53 => Some(DNS_VERSION_BIND),
        123 | 161 | 1900 => Some(crate::udp::payload_for(port)),
        _ => None,
    }
}

/// Parse the reply from the UDP service on `port`.
pub(super) fn parse(port: u16, data: &[u8]) -> Option<ServiceInfo> {
    match port {
        53 => parse_dns(data),
        123 => parse_ntp(data),
        161 => parse_snmp(data),
        1900 => parse_ssdp(data),
        _ => None,
    }
}

fn parse_dns(data: &[u8]) -> Option<ServiceInfo> {
    // Our query id, and the QR bit that marks a response.
    if data.len() < 12 || data[..2] != DNS_VERSION_BIND[..2] || data[2] & 0x80 == 0 {
        return None;
    }
    let mut info = ServiceInfo::named("domain");
    if let Some(txt) = version_bind_txt(data) {
        let (product, version) = split_version(&txt);
        info.product = product;
        info.version = version;
    }
    Some(info)
}

/// The first TXT string in the answer section of a version.bind reply.
fn version_bind_txt(data: &[u8]) -> Option<String> {
    let rcode = data[3] & 0x0f;
    let answers = u16::from_be_bytes([data[6], data[7]]);
    if rcode != 0 || answers == 0 {
        return None;
    }
    // Skip the header and our question (name, type, class).
    let mut pos = skip_name(data, 12)? + 4;
    // Answer: name, type, class, ttl, rdlength, rdata.
    pos = skip_name(data, pos)?;
    let fixed = data.get(pos..pos + 10)?;
    let rtype = u16::from_be_bytes([fixed[0], fixed[1]]);
    let rdlen = usize::from(u16::from_be_bytes([fixed[8], fixed[9]]));
    let rdata = data.get(pos + 10..pos + 10 + rdlen)?;
    if rtype != 16 {
        return None;
    }
    let (&len, rest) = rdata.split_first()?;
    clean(rest.get(..usize::from(len))?)
}

/// Position after the DNS name that starts at `pos`.
fn skip_name(data: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *data.get(pos)?;
        match len {
            0 => return Some(pos + 1),
            l if l & 0xc0 == 0xc0 => return Some(pos + 2), // compression pointer
            l => pos += usize::from(l) + 1,
        }
    }
}

/// Split a version string such as `dnsmasq-2.90` or `9.18.24-1-Debian`.
fn split_version(txt: &str) -> (Option<String>, Option<String>) {
    let starts_with_digit = |s: &str| s.starts_with(|c: char| c.is_ascii_digit());
    if starts_with_digit(txt) {
        return (None, Some(txt.to_string()));
    }
    for sep in ['-', ' ', '/'] {
        if let Some((name, version)) = txt.split_once(sep) {
            let version = version.trim_start_matches('v');
            if starts_with_digit(version) {
                return (Some(name.to_string()), Some(version.to_string()));
            }
        }
    }
    (Some(txt.to_string()), None)
}

fn parse_ntp(data: &[u8]) -> Option<ServiceInfo> {
    // Mode 4 is a server reply.
    if data.len() < 48 || data[0] & 0x07 != 4 {
        return None;
    }
    let version = (data[0] >> 3) & 0x07;
    let stratum = data[1];
    Some(ServiceInfo {
        name: "ntp".into(),
        product: Some("NTP".into()),
        version: Some(format!("v{version}")),
        extra_info: Some(format!("stratum {stratum}")),
        ..Default::default()
    })
}

/// sysDescr.0, the object our SNMP probe asks for.
const SYS_DESCR_OID: &[u8] = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];

fn parse_snmp(data: &[u8]) -> Option<ServiceInfo> {
    if data.first() != Some(&0x30) {
        return None;
    }
    let mut info = ServiceInfo {
        name: "snmp".into(),
        product: Some("SNMPv1 server".into()),
        extra_info: Some("community: public".into()),
        ..Default::default()
    };
    let at = data
        .windows(SYS_DESCR_OID.len())
        .position(|w| w == SYS_DESCR_OID)?
        + SYS_DESCR_OID.len();
    // The value: an OCTET STRING with a short or one/two-byte long length.
    if let [0x04, rest @ ..] = &data[at..] {
        let (len, rest) = match rest {
            [0x81, l, rest @ ..] => (usize::from(*l), rest),
            [0x82, a, b, rest @ ..] => (usize::from(u16::from_be_bytes([*a, *b])), rest),
            [l, rest @ ..] if *l < 0x80 => (usize::from(*l), rest),
            _ => return Some(info),
        };
        if let Some(descr) = rest.get(..len).and_then(clean) {
            info.extra_info = Some(format!("community: public; {descr}"));
        }
    }
    Some(info)
}

fn parse_ssdp(data: &[u8]) -> Option<ServiceInfo> {
    if !data.starts_with(b"HTTP/1.1 200") {
        return None;
    }
    let server = data.split(|&b| b == b'\n').find_map(|line| {
        let colon = line.iter().position(|&b| b == b':')?;
        line[..colon]
            .eq_ignore_ascii_case(b"server")
            .then(|| clean(&line[colon + 1..]))
            .flatten()
    });
    Some(ServiceInfo {
        name: "upnp".into(),
        product: server,
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_version_bind_reply() {
        let mut reply = DNS_VERSION_BIND.to_vec();
        reply[2] = 0x84; // QR, AA
        reply[7] = 1; // one answer
        reply.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x10, 0x00, 0x03, 0, 0, 0, 0, 0x00, 0x0d]);
        reply.push(12);
        reply.extend_from_slice(b"dnsmasq-2.90");
        let i = parse(53, &reply).unwrap();
        assert_eq!(i.name, "domain");
        assert_eq!(i.product.as_deref(), Some("dnsmasq"));
        assert_eq!(i.version.as_deref(), Some("2.90"));
        // Refused: still DNS, just no version.
        let mut refused = DNS_VERSION_BIND.to_vec();
        refused[2] = 0x80;
        refused[3] = 0x05;
        let i = parse(53, &refused).unwrap();
        assert_eq!((i.name.as_str(), i.version), ("domain", None));
        assert_eq!(
            split_version("9.18.24-1-Debian").1.as_deref(),
            Some("9.18.24-1-Debian")
        );
    }

    #[test]
    fn ntp_reply() {
        let mut reply = [0u8; 48];
        reply[0] = 0x24; // version 4, mode 4
        reply[1] = 2;
        let i = parse(123, &reply).unwrap();
        assert_eq!(i.version.as_deref(), Some("v4"));
        assert_eq!(i.extra_info.as_deref(), Some("stratum 2"));
        assert!(parse(123, &[0x23; 48]).is_none());
    }

    #[test]
    fn snmp_reply() {
        let mut reply = vec![0x30, 0x40, 0x02, 0x01, 0x00];
        reply.extend_from_slice(SYS_DESCR_OID);
        reply.extend_from_slice(&[0x04, 0x05]);
        reply.extend_from_slice(b"Linux");
        let i = parse(161, &reply).unwrap();
        assert_eq!(i.extra_info.as_deref(), Some("community: public; Linux"));
    }
}
