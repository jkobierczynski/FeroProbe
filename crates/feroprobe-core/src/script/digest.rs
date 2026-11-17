//! Hashes and random bytes for scripts (`fero.crypto`): MD5 (written
//! here from RFC 1321, since `ring` leaves it out), SHA-1 and the SHA-2
//! family through `ring`.

use ring::digest;

/// The digest of `data` with the named algorithm (`md5`, `sha1`,
/// `sha256`, `sha384`, `sha512`, any case), or `None` for another name.
pub(crate) fn digest(name: &str, data: &[u8]) -> Option<Vec<u8>> {
    let alg = match name.to_ascii_lowercase().as_str() {
        "md5" => return Some(md5(data).to_vec()),
        "sha1" => &digest::SHA1_FOR_LEGACY_USE_ONLY,
        "sha256" => &digest::SHA256,
        "sha384" => &digest::SHA384,
        "sha512" => &digest::SHA512,
        _ => return None,
    };
    Some(digest::digest(alg, data).as_ref().to_vec())
}

/// `n` random bytes from the system's generator.
pub(crate) fn random(n: usize) -> Option<Vec<u8>> {
    use ring::rand::SecureRandom;
    let mut out = vec![0u8; n];
    ring::rand::SystemRandom::new().fill(&mut out).ok()?;
    Some(out)
}

/// The per-round shift amounts of RFC 1321.
const SHIFTS: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

/// MD5 (RFC 1321). Only for fingerprints that tools still print in MD5,
/// such as SSH host keys; never for anything that needs to be secure.
pub(crate) fn md5(data: &[u8]) -> [u8; 16] {
    // T[i] = floor(abs(sin(i + 1)) * 2^32), as the RFC defines it.
    let t: [u32; 64] =
        std::array::from_fn(|i| ((i as f64 + 1.0).sin().abs() * 4294967296.0) as u32);
    let mut state: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
    let mut msg = data.to_vec();
    let bits = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bits.to_le_bytes());
    for block in msg.as_chunks::<64>().0 {
        let m: [u32; 16] = std::array::from_fn(|i| {
            u32::from_le_bytes(block[4 * i..4 * i + 4].try_into().unwrap())
        });
        let [mut a, mut b, mut c, mut d] = state;
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let rotated = a
                .wrapping_add(f)
                .wrapping_add(t[i])
                .wrapping_add(m[g])
                .rotate_left(SHIFTS[i]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(rotated);
        }
        for (s, v) in state.iter_mut().zip([a, b, c, d]) {
            *s = s.wrapping_add(v);
        }
    }
    let mut out = [0u8; 16];
    for (i, s) in state.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&s.to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn md5_matches_the_rfc_test_suite() {
        // RFC 1321, appendix A.5.
        for (input, want) in [
            ("", "d41d8cd98f00b204e9800998ecf8427e"),
            ("a", "0cc175b9c0f1b6a831c399e269772661"),
            ("abc", "900150983cd24fb0d6963f7d28e17f72"),
            ("message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
            (
                "abcdefghijklmnopqrstuvwxyz",
                "c3fcd3d76192e4007dfb496cca67e13b",
            ),
            (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "d174ab98d277d9f5a5611c2c9f419d9f",
            ),
            (
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "57edf4a22be3c955ac49da2e2107b67a",
            ),
        ] {
            assert_eq!(hex(&md5(input.as_bytes())), want, "{input:?}");
        }
    }

    #[test]
    fn named_digests() {
        assert_eq!(
            hex(&digest("SHA256", b"abc").unwrap()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&digest("sha1", b"abc").unwrap()),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert!(digest("crc32", b"abc").is_none());
        assert_eq!(random(16).unwrap().len(), 16);
    }
}
