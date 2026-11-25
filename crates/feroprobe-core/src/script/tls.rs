//! TLS for scripts: what `sock:get_ssl_certificate()` and
//! `sock:get_tls_info()` return, read from the session a script's socket
//! opened with `"ssl"` or upgraded with `sock:reconnect_ssl()`.
//!
//! Certificates are accepted without any checks, as in service detection:
//! a script wants to see what the service presents, not to trust it.

use mlua::{Lua, Table};
use x509_parser::prelude::*;

/// A certificate as the table scripts get. `None` when it does not parse.
///
/// Fields: `subject` and `issuer` (tables of attribute name to value,
/// such as `commonName`, plus `subject_text`/`issuer_text` with every
/// attribute in the certificate's order as `name=value/...`), `serial`
/// (hex), `version` (1 to 3), `sig_algorithm`, `pubkey` (`type`, `bits`
/// and, for EC keys, `curve`), `validity` (`notBefore`, `notAfter`, as
/// `YYYY-MM-DDTHH:MM:SS` in UTC), `san` (the subject alternative names,
/// as `DNS:name`, `IP:address`, `email:...`, `URI:...`), `sha1` and
/// `sha256` (fingerprints in hex), `pem` and `der`.
pub(crate) fn cert_table(lua: &Lua, der: &[u8]) -> mlua::Result<Option<Table>> {
    let Ok((_, cert)) = X509Certificate::from_der(der) else {
        return Ok(None);
    };
    let t = lua.create_table()?;
    let (subject, subject_text) = name_table(lua, cert.subject())?;
    t.raw_set("subject", subject)?;
    t.raw_set("subject_text", subject_text)?;
    let (issuer, issuer_text) = name_table(lua, cert.issuer())?;
    t.raw_set("issuer", issuer)?;
    t.raw_set("issuer_text", issuer_text)?;
    t.raw_set("serial", hex(cert.raw_serial()))?;
    t.raw_set("version", cert.version().0 + 1)?;
    t.raw_set(
        "sig_algorithm",
        oid_name(&cert.signature_algorithm.algorithm),
    )?;

    let pubkey = lua.create_table()?;
    let spki = cert.public_key();
    match spki.parsed() {
        Ok(x509_parser::public_key::PublicKey::RSA(rsa)) => {
            pubkey.raw_set("type", "rsa")?;
            pubkey.raw_set("bits", int_bits(rsa.modulus))?;
            pubkey.raw_set("modulus", lua.create_string(rsa.modulus)?)?;
            pubkey.raw_set("exponent", lua.create_string(rsa.exponent)?)?;
        }
        Ok(x509_parser::public_key::PublicKey::EC(_)) => {
            pubkey.raw_set("type", "ec")?;
            let curve = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.as_oid().ok())
                .map(|o| oid_name(&o));
            if let Some(c) = &curve {
                pubkey.raw_set("curve", c.as_str())?;
            }
            if let Some(bits) = curve.as_deref().and_then(curve_bits) {
                pubkey.raw_set("bits", bits)?;
            }
        }
        Ok(x509_parser::public_key::PublicKey::DSA(y)) => {
            pubkey.raw_set("type", "dsa")?;
            pubkey.raw_set("bits", int_bits(y))?;
        }
        _ => {
            let alg = oid_name(&spki.algorithm.algorithm);
            let kind = match alg.as_str() {
                "ED25519" | "1.3.101.112" => "ed25519".to_string(),
                "ED448" | "1.3.101.113" => "ed448".to_string(),
                _ => alg,
            };
            pubkey.raw_set("type", kind.as_str())?;
            match kind.as_str() {
                "ed25519" => pubkey.raw_set("bits", 256)?,
                "ed448" => pubkey.raw_set("bits", 456)?,
                _ => {}
            }
        }
    }
    t.raw_set("pubkey", pubkey)?;

    let validity = lua.create_table()?;
    validity.raw_set(
        "notBefore",
        iso_time(cert.validity().not_before.timestamp()),
    )?;
    validity.raw_set("notAfter", iso_time(cert.validity().not_after.timestamp()))?;
    t.raw_set("validity", validity)?;

    let san = lua.create_table()?;
    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        let mut i = 0;
        for name in &ext.value.general_names {
            let text = match name {
                GeneralName::DNSName(n) => format!("DNS:{n}"),
                GeneralName::RFC822Name(n) => format!("email:{n}"),
                GeneralName::URI(n) => format!("URI:{n}"),
                GeneralName::IPAddress(b) => match b.len() {
                    4 => format!(
                        "IP:{}",
                        std::net::Ipv4Addr::from(<[u8; 4]>::try_from(*b).unwrap())
                    ),
                    16 => format!(
                        "IP:{}",
                        std::net::Ipv6Addr::from(<[u8; 16]>::try_from(*b).unwrap())
                    ),
                    _ => format!("IP:{}", hex(b)),
                },
                GeneralName::DirectoryName(n) => format!("DirName:{}", name_text(n)),
                _ => continue,
            };
            i += 1;
            san.raw_set(i, text)?;
        }
    }
    t.raw_set("san", san)?;

    t.raw_set("sha1", digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, der))?;
    t.raw_set("sha256", digest(&ring::digest::SHA256, der))?;
    t.raw_set("pem", pem(der))?;
    t.raw_set("der", lua.create_string(der)?)?;
    Ok(Some(t))
}

/// A distinguished name as a table (attribute name to value; a repeated
/// attribute keeps its first value) and as `name=value/...` text.
fn name_table(lua: &Lua, name: &X509Name<'_>) -> mlua::Result<(Table, String)> {
    let t = lua.create_table()?;
    for attr in name.iter_attributes() {
        let key = oid_name(attr.attr_type());
        if t.raw_get::<mlua::Value>(key.as_str())?.is_nil() {
            t.raw_set(key.as_str(), attr_value(attr))?;
        }
    }
    Ok((t, name_text(name)))
}

fn name_text(name: &X509Name<'_>) -> String {
    name.iter_attributes()
        .map(|a| format!("{}={}", oid_name(a.attr_type()), attr_value(a)))
        .collect::<Vec<_>>()
        .join("/")
}

fn attr_value(a: &AttributeTypeAndValue<'_>) -> String {
    match a.as_str() {
        Ok(s) => s.to_string(),
        Err(_) => String::from_utf8_lossy(a.attr_value().data).into_owned(),
    }
}

/// An OID's short name (`commonName`, `sha256WithRSAEncryption`,
/// `prime256v1`), or its dotted form when it has none.
fn oid_name(oid: &x509_parser::der_parser::oid::Oid<'_>) -> String {
    x509_parser::objects::oid2sn(oid, x509_parser::objects::oid_registry())
        .map(str::to_string)
        .unwrap_or_else(|_| oid.to_id_string())
}

fn curve_bits(curve: &str) -> Option<u32> {
    Some(match curve {
        "prime256v1" | "secp256r1" | "secp256k1" | "brainpoolP256r1" => 256,
        "secp384r1" | "brainpoolP384r1" => 384,
        "secp521r1" => 521,
        "secp224r1" => 224,
        "prime192v1" | "secp192r1" => 192,
        "brainpoolP512r1" => 512,
        _ => return None,
    })
}

/// The bit length of a big-endian unsigned integer.
fn int_bits(n: &[u8]) -> u32 {
    let n = match n.iter().position(|&b| b != 0) {
        Some(i) => &n[i..],
        None => return 0,
    };
    (n.len() as u32 - 1) * 8 + (8 - n[0].leading_zeros())
}

pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn digest(alg: &'static ring::digest::Algorithm, data: &[u8]) -> String {
    hex(ring::digest::digest(alg, data).as_ref())
}

fn pem(der: &[u8]) -> String {
    let b64 = super::base64::encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

/// Seconds since 1970 as `YYYY-MM-DDTHH:MM:SS` (UTC).
pub(crate) fn iso_time(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// What `sock:get_tls_info()` returns: the protocol version (`TLSv1.2`,
/// `TLSv1.3`), the cipher suite (its IANA name) and the ALPN protocol
/// agreed, if any.
pub(crate) fn info_table(lua: &Lua, conn: &rustls::ClientConnection) -> mlua::Result<Table> {
    let t = lua.create_table()?;
    if let Some(v) = conn.protocol_version() {
        let v = match v {
            rustls::ProtocolVersion::TLSv1_2 => "TLSv1.2".to_string(),
            rustls::ProtocolVersion::TLSv1_3 => "TLSv1.3".to_string(),
            other => format!("{other:?}"),
        };
        t.raw_set("version", v)?;
    }
    if let Some(cs) = conn.negotiated_cipher_suite() {
        let name = cs
            .suite()
            .as_str()
            .map_or_else(|| format!("{:?}", cs.suite()), str::to_string);
        t.raw_set("cipher", name)?;
    }
    if let Some(p) = conn.alpn_protocol() {
        t.raw_set("alpn", lua.create_string(p)?)?;
    }
    Ok(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times() {
        assert_eq!(iso_time(0), "1970-01-01T00:00:00");
        assert_eq!(iso_time(951_782_400), "2000-02-29T00:00:00");
        assert_eq!(iso_time(1_795_000_000), "2026-11-18T11:06:40");
        assert_eq!(iso_time(-1), "1969-12-31T23:59:59");
        assert_eq!(iso_time(253_402_300_799), "9999-12-31T23:59:59");
    }

    #[test]
    fn bits() {
        assert_eq!(int_bits(&[0x00, 0x80, 0, 0]), 24);
        assert_eq!(int_bits(&[0x01]), 1);
        assert_eq!(int_bits(&[0, 0]), 0);
    }

    #[test]
    fn a_generated_certificate() {
        let mut params =
            rcgen::CertificateParams::new(vec!["probe.test".into(), "10.0.0.1".into()]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "probe.test");
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "Lab");
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let lua = Lua::new();
        let t = cert_table(&lua, cert.der()).unwrap().unwrap();
        let subject: Table = t.get("subject").unwrap();
        assert_eq!(subject.get::<String>("commonName").unwrap(), "probe.test");
        assert_eq!(
            t.get::<String>("subject_text").unwrap(),
            "commonName=probe.test/organizationName=Lab"
        );
        let pk: Table = t.get("pubkey").unwrap();
        assert_eq!(pk.get::<String>("type").unwrap(), "ec");
        assert_eq!(pk.get::<u32>("bits").unwrap(), 256);
        assert_eq!(pk.get::<String>("curve").unwrap(), "prime256v1");
        let san: Vec<String> = t
            .get::<Table>("san")
            .unwrap()
            .sequence_values()
            .map(|v| v.unwrap())
            .collect();
        assert_eq!(san, ["DNS:probe.test", "IP:10.0.0.1"]);
        assert_eq!(t.get::<String>("sha256").unwrap().len(), 64);
        assert!(
            t.get::<String>("pem")
                .unwrap()
                .starts_with("-----BEGIN CERTIFICATE-----\n")
        );
        assert_eq!(t.get::<u32>("version").unwrap(), 3);
        assert!(cert_table(&lua, b"junk").unwrap().is_none());
    }
}
