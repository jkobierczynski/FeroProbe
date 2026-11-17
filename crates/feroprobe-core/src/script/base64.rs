//! Base64 (RFC 4648, standard alphabet, with padding) for scripts
//! (`fero.base64`), HTTP basic authentication and PEM.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub(crate) fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Decode, ignoring whitespace; `None` for any other character outside
/// the alphabet, or for anything but whole groups of four characters with
/// at most two `=` of padding at the very end.
pub(crate) fn decode(text: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut acc = 0u32;
    let mut bits = 0;
    let mut pad = 0;
    let mut count = 0usize;
    for &c in text {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => {
                pad += 1;
                count += 1;
                continue;
            }
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            _ => return None,
        };
        if pad > 0 {
            return None;
        }
        count += 1;
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    // Whole quartets only; padding only where data ran short. Leftover
    // bits must be zero, as an encoder leaves them.
    let ok = count.is_multiple_of(4)
        && pad <= 2
        && (pad == 0 || count >= 4)
        && acc & ((1 << bits) - 1) == 0;
    ok.then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        for (plain, coded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(plain.as_bytes()), coded);
            assert_eq!(decode(coded.as_bytes()).unwrap(), plain.as_bytes());
        }
        assert_eq!(decode(b"Zm9v\nYmFy").unwrap(), b"foobar");
        assert!(decode(b"Zm9v!").is_none());
        assert!(decode(b"Zg==Zg").is_none());
        for bad in [&b"="[..], b"Zm9v=", b"A", b"Zg=", b"Zm9vY", b"Z==="] {
            assert!(decode(bad).is_none(), "{:?}", String::from_utf8_lossy(bad));
        }
    }
}
