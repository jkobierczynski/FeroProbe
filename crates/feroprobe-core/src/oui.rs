//! MAC vendor (OUI) resolution from the full IEEE registry.
//!
//! The IEEE assigns MAC address prefixes to manufacturers and publishes the
//! list. FeroProbe does not ship that list; it reads it at run time from a
//! file, either one given with `--oui-file` or the first of the usual system
//! locations that exists (see [`DEFAULT_PATHS`]). These formats are read,
//! and can even be mixed in one file:
//!
//! - IEEE `oui.txt`, also shipped by the `hwdata` and `ieee-data` packages:
//!   `00-00-0C   (hex)\t\tCisco Systems, Inc`
//! - IEEE CSV exports (`oui.csv`, `mam.csv`, `oui36.csv`):
//!   `MA-L,00000C,"Cisco Systems, Inc",<address>`
//! - Wireshark's `manuf`: `00:00:0C\tCisco\tCisco Systems, Inc`, including
//!   longer `/28` and `/36` blocks
//! - plain `XXXXXX Vendor` lines, as in nmap's `nmap-mac-prefixes`
//!
//! Longer (MA-M /28, MA-S /36) assignments win over the /24 block they sit
//! in. When no file is found, [`crate::arp::vendor`] falls back to its small
//! built-in table.

use std::borrow::Cow;
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::arp::MacAddr;

/// Where Linux distributions and common tools install an OUI list.
pub const DEFAULT_PATHS: &[&str] = &[
    "/usr/share/hwdata/oui.txt",
    "/usr/share/ieee-data/oui.txt",
    "/usr/share/misc/oui.txt",
    "/var/lib/ieee-data/oui.txt",
    "/usr/share/wireshark/manuf",
    "/usr/share/nmap/nmap-mac-prefixes",
    "/usr/local/share/nmap/nmap-mac-prefixes",
    "/opt/homebrew/share/nmap/nmap-mac-prefixes",
];

/// Lists of longer IEEE blocks, read too when found beside the main list.
const COMPANIONS: &[&str] = &["mam.csv", "oui36.csv", "iab.csv"];

/// Prefix lengths in bits, longest (most specific) first.
const PREFIX_BITS: [u8; 3] = [36, 28, 24];

/// A parsed OUI list: prefix length and masked address to vendor name.
#[derive(Debug, Default)]
pub struct OuiDb {
    map: HashMap<(u8, u64), Box<str>>,
    source: Option<PathBuf>,
}

fn mac_bits(mac: MacAddr) -> u64 {
    mac.0.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b))
}

fn mask(value: u64, bits: u8) -> u64 {
    value & (u64::MAX << (48 - u32::from(bits))) & 0xffff_ffff_ffff
}

impl OuiDb {
    /// Parse a list in any of the supported formats. Lines that match none
    /// of them (headers, addresses, comments) are skipped.
    pub fn parse(text: &str) -> Self {
        let mut db = OuiDb::default();
        db.merge_text(text);
        db
    }

    /// Add the entries in `text`; prefixes already known keep their name.
    fn merge_text(&mut self, text: &str) {
        // IEEE's text files give each entry as a "(hex)" line with the /24
        // and the name, then a "(base 16)" line that, for MA-M and MA-S
        // blocks, holds the range inside that /24.
        let mut pending: Option<(u64, &str)> = None;
        for line in text.lines() {
            let t = line.trim();
            if t.is_empty() || t.starts_with('#') {
                continue;
            }
            if let Some((prefix, name)) = parse_ieee_txt(t) {
                if let Some((p, n)) = pending.replace((prefix, name)) {
                    self.insert(24, p, n);
                }
                continue;
            }
            if let Some((range, _)) = t.split_once("(base 16)") {
                if let Some((p, n)) = pending.take() {
                    match block_in(range.trim()) {
                        Some((bits, low)) => self.insert(bits, p | low, n),
                        None => self.insert(24, p, n),
                    }
                }
                continue;
            }
            if let Some((bits, prefix, name)) = parse_ieee_csv(t)
                .or_else(|| parse_manuf(t).map(|(b, p, n)| (b, p, Cow::Borrowed(n))))
                .or_else(|| parse_plain(t).map(|(b, p, n)| (b, p, Cow::Borrowed(n))))
            {
                self.insert(bits, prefix, &name);
            }
        }
        if let Some((p, n)) = pending {
            self.insert(24, p, n);
        }
    }

    fn insert(&mut self, bits: u8, prefix: u64, name: &str) {
        if name.is_empty() {
            return;
        }
        // The first entry for a prefix wins, so a file's own order decides
        // between duplicates.
        self.map
            .entry((bits, mask(prefix, bits)))
            .or_insert_with(|| name.into());
    }

    pub fn load(path: &Path) -> io::Result<Self> {
        let bytes = std::fs::read(path)?;
        let mut db = Self::parse(&String::from_utf8_lossy(&bytes));
        // The IEEE's MA-M and MA-S lists often sit next to the main one.
        if let Some(dir) = path.parent() {
            for extra in COMPANIONS {
                let other = dir.join(extra);
                if other != path
                    && let Ok(bytes) = std::fs::read(&other)
                {
                    db.merge_text(&String::from_utf8_lossy(&bytes));
                }
            }
        }
        if db.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("no OUI entries found in {}", path.display()),
            ));
        }
        db.source = Some(path.to_path_buf());
        Ok(db)
    }

    /// The first default location that holds a usable list, or an empty db.
    pub fn load_default() -> Self {
        DEFAULT_PATHS
            .iter()
            .find_map(|p| Self::load(Path::new(p)).ok())
            .unwrap_or_default()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// The file this list came from, if any.
    pub fn source(&self) -> Option<&Path> {
        self.source.as_deref()
    }

    pub fn lookup(&self, mac: MacAddr) -> Option<&str> {
        let v = mac_bits(mac);
        PREFIX_BITS
            .iter()
            .find_map(|&bits| self.map.get(&(bits, mask(v, bits))))
            .map(|s| &**s)
    }
}

/// `XX` hex digits, all of them, as a number.
fn hex(s: &str) -> Option<u64> {
    (!s.is_empty() && s.len() <= 12 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| u64::from_str_radix(s, 16).ok())
        .flatten()
}

/// A 24-bit prefix from six hex digits, as a 48-bit value.
fn oui24(digits: &str) -> Option<u64> {
    (digits.len() == 6)
        .then(|| hex(digits))
        .flatten()
        .map(|v| v << 24)
}

/// `00-00-0C   (hex)\t\tCisco Systems, Inc`
fn parse_ieee_txt(line: &str) -> Option<(u64, &str)> {
    let (prefix, rest) = line.split_once("(hex)")?;
    let digits: String = prefix.trim().split('-').collect();
    Some((oui24(&digits)?, rest.trim()))
}

/// The block a "(base 16)" range like `F2A000-F2AFFF` names inside its /24:
/// prefix length and the low 24 bits. `None` for a whole /24 (`00000C`).
fn block_in(range: &str) -> Option<(u8, u64)> {
    let (lo, hi) = range.split_once('-')?;
    let (low, high) = (hex(lo.trim())?, hex(hi.trim())?);
    let size = high.checked_sub(low)? + 1;
    let bits = 48 - size.trailing_zeros() as u8;
    (size.is_power_of_two() && matches!(bits, 28 | 36) && low % size == 0).then_some((bits, low))
}

/// `MA-L,00000C,"Cisco Systems, Inc","170 West Tasman Dr. San Jose CA US 95134"`
fn parse_ieee_csv(line: &str) -> Option<(u8, u64, Cow<'_, str>)> {
    let mut parts = line.splitn(3, ',');
    let registry = parts.next()?;
    let assignment = parts.next()?;
    let rest = parts.next()?;
    let bits = match registry {
        "MA-L" => 24,
        "MA-M" => 28,
        // IAB blocks (iab.csv) are /36 like MA-S.
        "MA-S" | "IAB" => 36,
        _ => return None,
    };
    if assignment.len() != usize::from(bits / 4) {
        return None;
    }
    let value = hex(assignment)? << (48 - u32::from(bits));
    let name = match rest.strip_prefix('"') {
        Some(quoted) => Cow::Owned(unquote(quoted)?),
        None => Cow::Borrowed(rest.split(',').next()?),
    };
    Some((bits, value, trim_cow(name)))
}

/// The rest of a quoted CSV field (after its opening quote), with doubled
/// quotes decoded. `None` if the closing quote is missing.
fn unquote(field: &str) -> Option<String> {
    let mut out = String::new();
    let mut chars = field.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '"' {
            out.push(c);
        } else if chars.peek() == Some(&'"') {
            chars.next();
            out.push('"');
        } else {
            return Some(out);
        }
    }
    None
}

fn trim_cow(s: Cow<'_, str>) -> Cow<'_, str> {
    match s {
        Cow::Borrowed(b) => Cow::Borrowed(b.trim()),
        Cow::Owned(o) => Cow::Owned(o.trim().to_string()),
    }
}

/// `00:00:0C\tCisco\tCisco Systems, Inc` or `00:1B:C5:00:00:00/36\tShort\tLong`.
/// Fields may be separated by tabs or spaces; the long name keeps its spaces.
fn parse_manuf(line: &str) -> Option<(u8, u64, &str)> {
    let (addr, rest) = line.split_once([' ', '\t'])?;
    // Plain "XXXXXX Vendor" lines are parse_plain's: manuf separates bytes.
    if !addr.contains([':', '-', '.']) {
        return None;
    }
    let rest = rest.trim_start();
    let (short, long) = match rest.split_once([' ', '\t']) {
        Some((s, l)) => (s, Some(l.trim())),
        None => (rest.trim(), None),
    };
    let (addr, bits) = match addr.split_once('/') {
        Some((a, b)) => (a, b.parse::<u8>().ok()?),
        None => (addr, 24),
    };
    let digits: String = addr.split([':', '-', '.']).collect();
    if !matches!(bits, 24 | 28 | 36) || digits.len() < usize::from(bits / 4) || digits.len() > 12 {
        return None;
    }
    let value = hex(&digits)? << (48 - 4 * digits.len() as u32);
    Some((bits, value, long.filter(|l| !l.is_empty()).unwrap_or(short)))
}

/// `00000C Cisco Systems` (nmap-mac-prefixes)
fn parse_plain(line: &str) -> Option<(u8, u64, &str)> {
    let (digits, name) = line.split_once([' ', '\t'])?;
    Some((24, oui24(digits)?, name.trim()))
}

static DB: OnceLock<OuiDb> = OnceLock::new();

/// Use the list in `path` for all later lookups. Call it before the first
/// lookup; otherwise the default locations have already been read.
pub fn use_file(path: &Path) -> io::Result<&'static OuiDb> {
    let db = OuiDb::load(path)?;
    DB.set(db).map_err(|_| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "the OUI list was already loaded",
        )
    })?;
    Ok(global())
}

/// The list used for lookups, read from the default locations on first use.
pub fn global() -> &'static OuiDb {
    DB.get_or_init(OuiDb::load_default)
}

/// The vendor registered for `mac`'s prefix in the loaded list.
pub fn lookup(mac: MacAddr) -> Option<&'static str> {
    global().lookup(mac)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIXED: &str = "\
OUI/MA-L                                                    Organization
company_id                                                  Organization
                                                            Address

00-00-0C   (hex)\t\tCisco Systems, Inc
00000C     (base 16)\t\tCisco Systems, Inc
\t\t\t\t170 West Tasman Dr.

70-B3-D5   (hex)\t\tTELEPLATFORMS
F2F000-F2FFFF     (base 16)\t\tTELEPLATFORMS
\t\t\t\tPolbina st., 3/1

Registry,Assignment,Organization Name,Organization Address
MA-L,B827EB,Raspberry Pi Foundation,Mitchell Wood House Caldecote GB CB23 7NU
MA-L,000569,\"VMware, Inc.\",\"3401 Hillview Avenue PALO ALTO CA US 94304\"
MA-M,70B3D51,Example Block Owner,Somewhere
MA-S,70B3D5F2A,\"Tiny Block, Ltd\",Elsewhere
IAB,0050C27D5,DEUTA-WERKE GmbH,Paffrather Strasse 140
MA-L,001122,\"\"\"Acme\"\" Ltd\",\"Road \"\"A\"\", Town\"
00:00:0D Fibronics Fibronics Ltd.
# Wireshark manuf
00:50:56\tVMware\tVMware, Inc.
00:1B:C5:00:00:00/36\tConverging\tConverging Systems Inc.
08:00:27\tPCSSystemt
080028 Texas Instruments
";

    fn mac(s: &str) -> MacAddr {
        let b: Vec<u8> = s
            .split(':')
            .map(|p| u8::from_str_radix(p, 16).unwrap())
            .collect();
        MacAddr(b.try_into().unwrap())
    }

    #[test]
    fn reads_every_format() {
        let db = OuiDb::parse(MIXED);
        let l = |m| db.lookup(mac(m));
        assert_eq!(l("00:00:0c:12:34:56"), Some("Cisco Systems, Inc"));
        assert_eq!(l("b8:27:eb:00:00:01"), Some("Raspberry Pi Foundation"));
        assert_eq!(l("00:05:69:aa:bb:cc"), Some("VMware, Inc."));
        assert_eq!(l("00:50:56:aa:bb:cc"), Some("VMware, Inc."));
        assert_eq!(l("08:00:27:00:00:01"), Some("PCSSystemt"));
        assert_eq!(l("08:00:28:00:00:01"), Some("Texas Instruments"));
        assert_eq!(l("00:1b:c5:00:00:07"), Some("Converging Systems Inc."));
        assert_eq!(l("00:1b:c5:00:10:07"), None);
        assert_eq!(l("12:34:56:00:00:00"), None);
        // A /36 from oui36.txt, without claiming the whole /24 it sits in.
        assert_eq!(l("70:b3:d5:f2:f1:23"), Some("TELEPLATFORMS"));
        assert_eq!(l("00:50:c2:7d:5f:00"), Some("DEUTA-WERKE GmbH"));
        assert_eq!(l("00:11:22:00:00:01"), Some("\"Acme\" Ltd"));
        assert_eq!(l("00:00:0d:00:00:01"), Some("Fibronics Ltd."));
        // Header, address and "(base 16)" lines add nothing extra.
        assert_eq!(db.len(), 13);
    }

    #[test]
    fn longest_prefix_wins() {
        let db = OuiDb::parse(MIXED);
        assert_eq!(db.lookup(mac("70:b3:d5:f2:a1:23")), Some("Tiny Block, Ltd"));
        assert_eq!(
            db.lookup(mac("70:b3:d5:1f:ff:ff")),
            Some("Example Block Owner")
        );
        assert_eq!(db.lookup(mac("70:b3:d5:20:00:00")), None);
    }

    #[test]
    fn empty_files_are_an_error() {
        let dir = std::env::temp_dir().join(format!("feroprobe-oui-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let empty = dir.join("empty.txt");
        std::fs::write(&empty, "nothing useful here\n").unwrap();
        assert_eq!(
            OuiDb::load(&empty).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let good = dir.join("oui.txt");
        std::fs::write(&good, MIXED).unwrap();
        let db = OuiDb::load(&good).unwrap();
        assert_eq!(db.source(), Some(good.as_path()));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
