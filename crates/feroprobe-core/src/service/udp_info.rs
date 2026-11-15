//! Version information from UDP services: DNS, NTP, SNMP, SSDP and
//! NetBIOS.

use super::ServiceInfo;
use super::rules::clean;

pub(super) fn parse_dns(data: &[u8]) -> Option<ServiceInfo> {
    // The QR bit marks a response; it must carry our one question.
    if data.len() < 12 || data[2] & 0x80 == 0 || data[4..6] != [0, 1] {
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

pub(super) fn parse_ntp(data: &[u8]) -> Option<ServiceInfo> {
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

pub(super) fn parse_snmp(data: &[u8]) -> Option<ServiceInfo> {
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

pub(super) fn parse_ssdp(data: &[u8]) -> Option<ServiceInfo> {
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

/// A NetBIOS node status reply (RFC 1002): the machine's name, its
/// workgroup, and from the MAC address whether Samba answered.
pub(super) fn parse_nbstat(data: &[u8]) -> Option<ServiceInfo> {
    // A response with one answer.
    if data.len() < 12 || data[2] & 0x80 == 0 || data[6..8] != [0, 1] {
        return None;
    }
    let mut pos = skip_name(data, 12)?;
    let fixed = data.get(pos..pos + 10)?;
    if fixed[..2] != [0x00, 0x21] {
        return None;
    }
    pos += 10;
    let count = usize::from(*data.get(pos)?);
    pos += 1;
    let mut host = None;
    let mut group = None;
    for _ in 0..count {
        let entry = data.get(pos..pos + 18)?;
        pos += 18;
        let (name, suffix, flags) = (&entry[..15], entry[15], entry[16]);
        if suffix != 0x00 {
            continue;
        }
        let slot = if flags & 0x80 != 0 {
            &mut group
        } else {
            &mut host
        };
        if slot.is_none() {
            *slot = clean(name);
        }
    }
    let samba = data.get(pos..pos + 6).is_some_and(|mac| mac == [0; 6]);
    let mut info = ServiceInfo::named("netbios-ns");
    info.product = Some(
        if samba {
            "Samba nmbd netbios-ns"
        } else {
            "Microsoft Windows netbios-ns"
        }
        .into(),
    );
    info.extra_info = group.map(|g| format!("workgroup: {g}"));
    info.hostname = host;
    if !samba {
        info.os_type = Some("Windows".into());
        info.cpe = vec!["cpe:/o:microsoft:windows".into()];
    }
    Some(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The dns-version probe's payload.
    const DNS_VERSION_BIND: &[u8] = &[
        0x13, 0x38, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'v', b'e',
        b'r', b's', b'i', b'o', b'n', 0x04, b'b', b'i', b'n', b'd', 0x00, 0x00, 0x10, 0x00, 0x03,
    ];

    #[test]
    fn dns_payload_is_the_probe() {
        let db = super::super::db::ServiceDb::builtin();
        assert_eq!(db.probe("dns-version").unwrap().payload(), DNS_VERSION_BIND);
        assert_eq!(
            &db.probe("dns-tcp").unwrap().payload()[2..],
            DNS_VERSION_BIND
        );
    }

    #[test]
    fn dns_version_bind_reply() {
        let mut reply = DNS_VERSION_BIND.to_vec();
        reply[2] = 0x84; // QR, AA
        reply[7] = 1; // one answer
        reply.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x10, 0x00, 0x03, 0, 0, 0, 0, 0x00, 0x0d]);
        reply.push(12);
        reply.extend_from_slice(b"dnsmasq-2.90");
        let i = parse_dns(&reply).unwrap();
        assert_eq!(i.name, "domain");
        assert_eq!(i.product.as_deref(), Some("dnsmasq"));
        assert_eq!(i.version.as_deref(), Some("2.90"));
        // Refused: still DNS, just no version.
        let mut refused = DNS_VERSION_BIND.to_vec();
        refused[2] = 0x80;
        refused[3] = 0x05;
        let i = parse_dns(&refused).unwrap();
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
        let i = parse_ntp(&reply).unwrap();
        assert_eq!(i.version.as_deref(), Some("v4"));
        assert_eq!(i.extra_info.as_deref(), Some("stratum 2"));
        assert!(parse_ntp(&[0x23; 48]).is_none());
    }

    #[test]
    fn snmp_reply() {
        let mut reply = vec![0x30, 0x40, 0x02, 0x01, 0x00];
        reply.extend_from_slice(SYS_DESCR_OID);
        reply.extend_from_slice(&[0x04, 0x05]);
        reply.extend_from_slice(b"Linux");
        let i = parse_snmp(&reply).unwrap();
        assert_eq!(i.extra_info.as_deref(), Some("community: public; Linux"));
    }
    fn nbstat_reply(mac: [u8; 6]) -> Vec<u8> {
        let mut r = vec![0x46, 0x50, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0, 0x20];
        r.extend_from_slice(b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00");
        r.extend_from_slice(&[0x00, 0x21, 0x00, 0x01, 0, 0, 0, 0, 0x00, 0x41, 3]);
        for (name, suffix, flags) in [
            (b"FILESERVER     ", 0x00, 0x04),
            (b"FILESERVER     ", 0x20, 0x04),
            (b"WORKGROUP      ", 0x00, 0x84),
        ] {
            r.extend_from_slice(name);
            r.extend_from_slice(&[suffix, flags, 0x00]);
        }
        r.extend_from_slice(&mac);
        r
    }

    #[test]
    fn nbstat() {
        let i = parse_nbstat(&nbstat_reply([0x00, 0x15, 0x5d, 1, 2, 3])).unwrap();
        assert_eq!(i.name, "netbios-ns");
        assert_eq!(i.product.as_deref(), Some("Microsoft Windows netbios-ns"));
        assert_eq!(i.hostname.as_deref(), Some("FILESERVER"));
        assert_eq!(i.extra_info.as_deref(), Some("workgroup: WORKGROUP"));
        assert_eq!(i.os_type.as_deref(), Some("Windows"));
        let i = parse_nbstat(&nbstat_reply([0; 6])).unwrap();
        assert_eq!(i.product.as_deref(), Some("Samba nmbd netbios-ns"));
        assert_eq!(i.os_type, None);
        assert!(parse_nbstat(&[0u8; 20]).is_none());
    }
}
