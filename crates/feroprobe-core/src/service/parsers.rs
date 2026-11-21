//! Parsers for binary replies that a regex cannot read well: the fields
//! sit at offsets or carry their own lengths.
//!
//! Like the rules, these are written from the public protocol
//! specifications: MS-TDS (SQL Server), MS-SMB2, MS-RDPBCGR (RDP),
//! RFC 4511 (LDAP), and for UDP the readers in [`super::udp_info`]. Each
//! runs on the replies to the probe of the same name in the rules file.

use super::ServiceInfo;
use super::rules::clean;

/// Identify a binary reply to `probe`, or `None` to fall through to the
/// regex rules.
pub(super) fn parse(probe: &str, data: &[u8]) -> Option<ServiceInfo> {
    match probe {
        "mssql" => mssql(data),
        "smb" => smb(data),
        "netbios-ssn" => netbios_ssn(data),
        "rdp" => rdp(data),
        "ldap" => ldap(data),
        "dns-version" => super::udp_info::parse_dns(data),
        // DNS over TCP: the same reply behind a two-byte length.
        "dns-tcp" => super::udp_info::parse_dns(data.get(2..)?),
        "ntp" => super::udp_info::parse_ntp(data),
        "snmp" => super::udp_info::parse_snmp(data),
        "ssdp" => super::udp_info::parse_ssdp(data),
        "nbstat" => super::udp_info::parse_nbstat(data),
        _ => None,
    }
}

/// The services the built-in parser for `probe` can name, so that a soft
/// match can tell which probes may still say more.
pub(super) fn services(probe: &str) -> &'static [&'static str] {
    match probe {
        "mssql" => &["ms-sql-s"],
        "smb" => &["microsoft-ds"],
        "netbios-ssn" => &["netbios-ssn"],
        "rdp" => &["ms-wbt-server"],
        "ldap" => &["ldap"],
        "dns-version" | "dns-tcp" => &["domain"],
        "ntp" => &["ntp"],
        "snmp" => &["snmp"],
        "ssdp" => &["upnp"],
        "nbstat" => &["netbios-ns"],
        _ => &[],
    }
}

fn u16_be(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(data.get(at..at + 2)?.try_into().ok()?))
}

fn u16_le(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(data.get(at..at + 2)?.try_into().ok()?))
}

/// SQL Server's PRELOGIN reply: a TDS packet of type 4 whose option table
/// points at the server's version.
fn mssql(data: &[u8]) -> Option<ServiceInfo> {
    if data.first() != Some(&0x04) || data.len() < 8 {
        return None;
    }
    let payload = &data[8..];
    let mut info = ServiceInfo::named("ms-sql-s");
    info.product = Some("Microsoft SQL Server".into());
    // Option table: token, offset (u16 BE), length (u16 BE), up to 0xff.
    let mut at = 0;
    while let Some(&token) = payload.get(at) {
        if token == 0xff {
            break;
        }
        let offset = usize::from(u16_be(payload, at + 1)?);
        let len = usize::from(u16_be(payload, at + 3)?);
        if token == 0x00 && len >= 4 {
            let v = payload.get(offset..offset + 4)?;
            let (major, minor) = (v[0], v[1]);
            let build = u16::from_be_bytes([v[2], v[3]]);
            info.version = Some(format!("{major}.{minor}.{build}"));
            if let Some(name) = mssql_release(major, minor) {
                info.product = Some(format!("Microsoft SQL Server {name}"));
                info.cpe = vec![format!(
                    "cpe:/a:microsoft:sql_server:{}",
                    name.to_lowercase().replace(' ', "_")
                )];
            }
        }
        at += 5;
    }
    Some(info)
}

/// The marketing name of a SQL Server major.minor version.
fn mssql_release(major: u8, minor: u8) -> Option<&'static str> {
    Some(match (major, minor) {
        (17, _) => "2025",
        (16, _) => "2022",
        (15, _) => "2019",
        (14, _) => "2017",
        (13, _) => "2016",
        (12, _) => "2014",
        (11, _) => "2012",
        (10, 50) => "2008 R2",
        (10, _) => "2008",
        (9, _) => "2005",
        (8, _) => "2000",
        _ => return None,
    })
}

/// An SMB2 NEGOTIATE reply: the dialect the server picked and whether it
/// requires signing. An SMB1 reply means the server speaks only SMB1.
fn smb(data: &[u8]) -> Option<ServiceInfo> {
    // NetBIOS session header, then the SMB header.
    let smb = data.get(4..)?;
    let mut info = ServiceInfo::named("microsoft-ds");
    if smb.starts_with(b"\xffSMB") {
        info.extra_info = Some("SMBv1 only".into());
        return Some(info);
    }
    if !smb.starts_with(b"\xfeSMB") {
        return None;
    }
    // The negotiate response body follows the 64-byte header.
    let body = smb.get(64..)?;
    if u16_le(body, 0)? != 65 {
        // An error reply: still SMB2, but nothing more to learn.
        return Some(info);
    }
    let security = u16_le(body, 2)?;
    let dialect = match u16_le(body, 4)? {
        0x0202 => "2.0.2",
        0x0210 => "2.1",
        0x0300 => "3.0",
        0x0302 => "3.0.2",
        0x0311 => "3.1.1",
        _ => "unknown",
    };
    let mut extra = vec![format!("SMB dialect {dialect}")];
    // SMB2_NEGOTIATE_SIGNING_REQUIRED
    if security & 0x0002 != 0 {
        extra.push("signing required".into());
    }
    info.extra_info = Some(extra.join("; "));
    Some(info)
}

/// The reply to a NetBIOS session request (RFC 1002): a positive response,
/// then the SMB2 NEGOTIATE reply when the server took the session; or a
/// negative response (the server does not answer to *SMBSERVER).
fn netbios_ssn(data: &[u8]) -> Option<ServiceInfo> {
    match data {
        [0x82, 0, 0, 0, rest @ ..] => {
            let mut info = ServiceInfo::named("netbios-ssn");
            info.extra_info = smb(rest).and_then(|i| i.extra_info);
            Some(info)
        }
        // Windows refuses *SMBSERVER ("called name not present"), while
        // Samba takes it, so a refusal is Windows, as nmap reports it.
        [0x83, 0, 0, 1, _, ..] => {
            let mut info = ServiceInfo::named("netbios-ssn");
            info.product = Some("Microsoft Windows netbios-ssn".into());
            info.os_type = Some("Windows".into());
            info.cpe = vec!["cpe:/o:microsoft:windows".into()];
            Some(info)
        }
        _ => None,
    }
}

/// RDP's X.224 Connection Confirm, with the security protocol the server
/// chose or the reason it refused ours.
fn rdp(data: &[u8]) -> Option<ServiceInfo> {
    // TPKT version 3, then an X.224 Connection Confirm (0xd0).
    if data.len() < 11 || data[0] != 0x03 || data[5] != 0xd0 {
        return None;
    }
    let mut info = ServiceInfo::named("ms-wbt-server");
    // RDP_NEG_RSP (2) or RDP_NEG_FAILURE (3) after the 11-byte header.
    let detail = match (data.get(11), data.get(15..19)) {
        (Some(2), Some(p)) => match u32::from_le_bytes(p.try_into().ok()?) {
            0 => "standard RDP security",
            1 => "TLS security",
            2 | 8 => "NLA (CredSSP)",
            _ => "unknown security",
        },
        (Some(3), _) => "negotiation refused",
        _ => "standard RDP security",
    };
    info.extra_info = Some(detail.into());
    Some(info)
}

/// An LDAP rootDSE search reply: the vendor's own name and version when it
/// sends them, else what the attributes give away.
fn ldap(data: &[u8]) -> Option<ServiceInfo> {
    // LDAPMessage SEQUENCE, message id 1, then a search reply.
    let mut at = 1 + ber_len(data, 1)?.1;
    if data.first() != Some(&0x30) || data.get(at..at + 3)? != [0x02, 0x01, 0x01] {
        return None;
    }
    at += 3;
    if !matches!(data.get(at), Some(0x64 | 0x65)) {
        return None;
    }
    let mut info = ServiceInfo::named("ldap");
    let attr = |name: &str| ldap_attr(data, name);
    if let Some(vendor) = attr("vendorName") {
        info.product = Some(vendor);
        info.version = attr("vendorVersion");
    } else if data.windows(15).any(|w| w == b"OpenLDAProotDSE") {
        info.product = Some("OpenLDAP".into());
        info.cpe = vec!["cpe:/a:openldap:openldap".into()];
    } else if attr("domainFunctionality").is_some() || attr("isGlobalCatalogReady").is_some() {
        info.product = Some("Microsoft Windows Active Directory LDAP".into());
        info.os_type = Some("Windows".into());
        info.cpe = vec!["cpe:/o:microsoft:windows".into()];
    }
    info.hostname = attr("dnsHostName");
    info.extra_info = attr("defaultNamingContext").map(|c| format!("context: {c}"));
    Some(info)
}

/// A BER length at `at`: its value and how many bytes it took.
fn ber_len(data: &[u8], at: usize) -> Option<(usize, usize)> {
    let first = *data.get(at)?;
    if first < 0x80 {
        return Some((usize::from(first), 1));
    }
    let n = usize::from(first & 0x7f);
    if n == 0 || n > 4 {
        return None;
    }
    let len = data
        .get(at + 1..at + 1 + n)?
        .iter()
        .fold(0usize, |acc, &b| acc << 8 | usize::from(b));
    Some((len, 1 + n))
}

/// The first value of attribute `name` in an LDAP search entry. Each
/// attribute is `OCTET STRING name, SET { OCTET STRING value, ... }`.
fn ldap_attr(data: &[u8], name: &str) -> Option<String> {
    let mut key = vec![0x04, u8::try_from(name.len()).ok()?];
    key.extend_from_slice(name.as_bytes());
    let start = data.windows(key.len()).position(|w| w == key)? + key.len();
    if data.get(start) != Some(&0x31) {
        return None;
    }
    let mut at = start + 1 + ber_len(data, start + 1)?.1;
    if data.get(at) != Some(&0x04) {
        return None;
    }
    let (len, used) = ber_len(data, at + 1)?;
    at += 1 + used;
    clean(data.get(at..at + len)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mssql_prelogin() {
        // Header, VERSION and ENCRYPTION options, terminator, then data.
        let mut reply = vec![0x04, 0x01, 0x00, 0x25, 0x00, 0x00, 0x01, 0x00];
        reply.extend_from_slice(&[0x00, 0x00, 0x0b, 0x00, 0x06]);
        reply.extend_from_slice(&[0x01, 0x00, 0x11, 0x00, 0x01, 0xff]);
        reply.extend_from_slice(&[15, 0, 0x07, 0xd0, 0, 0, 0x02]);
        let i = parse("mssql", &reply).unwrap();
        assert_eq!(i.name, "ms-sql-s");
        assert_eq!(i.product.as_deref(), Some("Microsoft SQL Server 2019"));
        assert_eq!(i.version.as_deref(), Some("15.0.2000"));
        assert_eq!(i.cpe, vec!["cpe:/a:microsoft:sql_server:2019"]);
        assert!(parse("mssql", b"HTTP/1.1 400").is_none());
    }

    fn smb2_reply(dialect: u16, security: u16) -> Vec<u8> {
        let mut r = vec![0, 0, 0, 0];
        r.extend_from_slice(b"\xfeSMB");
        r.resize(4 + 64, 0);
        r.extend_from_slice(&65u16.to_le_bytes());
        r.extend_from_slice(&security.to_le_bytes());
        r.extend_from_slice(&dialect.to_le_bytes());
        r.resize(r.len() + 58, 0);
        r
    }

    #[test]
    fn smb_dialects() {
        let i = parse("smb", &smb2_reply(0x0311, 3)).unwrap();
        assert_eq!(i.name, "microsoft-ds");
        assert_eq!(
            i.extra_info.as_deref(),
            Some("SMB dialect 3.1.1; signing required")
        );
        let i = parse("smb", &smb2_reply(0x0210, 1)).unwrap();
        assert_eq!(i.extra_info.as_deref(), Some("SMB dialect 2.1"));
        let i = parse("smb", b"\x00\x00\x00\x55\xffSMBr").unwrap();
        assert_eq!(i.extra_info.as_deref(), Some("SMBv1 only"));
        assert!(parse("smb", b"\x00\x00\x00\x10junk").is_none());
    }

    #[test]
    fn netbios_session() {
        let mut took = vec![0x82, 0, 0, 0];
        took.extend(smb2_reply(0x0302, 3));
        let i = parse("netbios-ssn", &took).unwrap();
        assert_eq!(i.name, "netbios-ssn");
        assert_eq!(
            i.extra_info.as_deref(),
            Some("SMB dialect 3.0.2; signing required")
        );
        let i = parse("netbios-ssn", b"\x82\x00\x00\x00").unwrap();
        assert_eq!((i.name.as_str(), i.extra_info), ("netbios-ssn", None));
        // "Called name not present", as Windows answers.
        let i = parse("netbios-ssn", b"\x83\x00\x00\x01\x82").unwrap();
        assert_eq!(i.name, "netbios-ssn");
        assert_eq!(i.product.as_deref(), Some("Microsoft Windows netbios-ssn"));
        assert_eq!(i.os_type.as_deref(), Some("Windows"));
        assert!(parse("netbios-ssn", b"\x00\x00\x00\x10junk").is_none());
    }

    #[test]
    fn rdp_confirm() {
        let tls = b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x1f\x08\x00\x02\x00\x00\x00";
        let i = parse("rdp", tls).unwrap();
        assert_eq!(i.name, "ms-wbt-server");
        assert_eq!(i.extra_info.as_deref(), Some("NLA (CredSSP)"));
        let failed =
            b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x03\x00\x08\x00\x05\x00\x00\x00";
        let i = parse("rdp", failed).unwrap();
        assert_eq!(i.extra_info.as_deref(), Some("negotiation refused"));
        let old = b"\x03\x00\x00\x0b\x06\xd0\x00\x00\x12\x34\x00";
        assert_eq!(
            parse("rdp", old).unwrap().extra_info.as_deref(),
            Some("standard RDP security")
        );
    }

    fn ldap_entry(attrs: &[(&str, &str)]) -> Vec<u8> {
        let tlv = |t: u8, v: &[u8]| {
            let mut out = vec![t, u8::try_from(v.len()).unwrap()];
            out.extend_from_slice(v);
            out
        };
        let mut list = Vec::new();
        for (k, v) in attrs {
            let mut a = tlv(0x04, k.as_bytes());
            a.extend(tlv(0x31, &tlv(0x04, v.as_bytes())));
            list.extend(tlv(0x30, &a));
        }
        let mut entry = tlv(0x04, b"");
        entry.extend(tlv(0x30, &list));
        let mut msg = vec![0x02, 0x01, 0x01];
        msg.extend(tlv(0x64, &entry));
        tlv(0x30, &msg)
    }

    #[test]
    fn ldap_root_dse() {
        let i = parse(
            "ldap",
            &ldap_entry(&[
                ("vendorName", "389 Project"),
                ("vendorVersion", "389-Directory/2.4.5"),
            ]),
        )
        .unwrap();
        assert_eq!(i.name, "ldap");
        assert_eq!(i.product.as_deref(), Some("389 Project"));
        assert_eq!(i.version.as_deref(), Some("389-Directory/2.4.5"));
        let i = parse(
            "ldap",
            &ldap_entry(&[
                ("domainFunctionality", "7"),
                ("defaultNamingContext", "DC=corp,DC=example"),
                ("dnsHostName", "dc1.corp.example"),
            ]),
        )
        .unwrap();
        assert_eq!(
            i.product.as_deref(),
            Some("Microsoft Windows Active Directory LDAP")
        );
        assert_eq!(i.extra_info.as_deref(), Some("context: DC=corp,DC=example"));
        assert_eq!(i.hostname.as_deref(), Some("dc1.corp.example"));
        let i = parse(
            "ldap",
            &ldap_entry(&[("structuralObjectClass", "OpenLDAProotDSE")]),
        )
        .unwrap();
        assert_eq!(i.product.as_deref(), Some("OpenLDAP"));
        assert!(parse("ldap", b"\x30\x03\x02\x01\x02").is_none());
    }

    #[test]
    fn long_ber_lengths() {
        assert_eq!(ber_len(&[0x05], 0), Some((5, 1)));
        assert_eq!(ber_len(&[0x81, 0xc8], 0), Some((200, 2)));
        assert_eq!(ber_len(&[0x82, 0x01, 0x00], 0), Some((256, 3)));
        assert_eq!(ber_len(&[0x80], 0), None);
    }
}
