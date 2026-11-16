//! Evasion options — packet fragmentation, decoys and a spoofed source
//! address — for testing your own firewall or intrusion-detection system.
//!
//! These are a deliberate exception to nmap parity: they are only allowed
//! against private address ranges (see [`crate::scope`]). The caller is
//! responsible for that check; this module only builds the packets.
//!
//! The transforms here are pure so they can be unit-tested without raw
//! sockets. They apply to IPv4 only; IPv6 evasion is not supported and the
//! command-line layer refuses it.

use std::net::IpAddr;

use crate::packet;

/// How to fragment outgoing IPv4 probe packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fragment {
    /// nmap's `-f`: 8 bytes of payload per fragment.
    Eight,
    /// nmap's `--mtu <n>`: `n` bytes of payload per fragment. `n` must be a
    /// positive multiple of 8.
    Mtu(u16),
}

impl Fragment {
    /// The payload bytes per fragment, rounded down to a multiple of 8 and
    /// at least 8.
    fn payload_bytes(self) -> usize {
        let n = match self {
            Fragment::Eight => 8,
            Fragment::Mtu(n) => n as usize,
        };
        (n & !7).max(8)
    }
}

/// The evasion options in effect for a scan. Empty by default (no evasion).
#[derive(Debug, Clone, Default)]
pub struct Evasion {
    /// Decoy source addresses. The target sees a probe from each of these,
    /// alongside the real one, so the real scanner is hard to pick out.
    pub decoys: Vec<IpAddr>,
    /// A forged source address for the real probe (nmap's `-S`). Replies go
    /// to this address, so the scan is blind unless FeroProbe sits on the
    /// path back.
    pub spoof_source: Option<IpAddr>,
    /// Fragment outgoing IPv4 probes.
    pub fragment: Option<Fragment>,
}

impl Evasion {
    /// Whether any evasion option is set.
    pub fn is_active(&self) -> bool {
        !self.decoys.is_empty() || self.spoof_source.is_some() || self.fragment.is_some()
    }

    /// Every source address a probe to `real_src` should be sent from: each
    /// decoy, plus the real probe's source (the spoofed address when `-S`
    /// is set, otherwise `real_src`). The real probe's source is last.
    ///
    /// The transport checksum depends on the source address, so the caller
    /// rebuilds the probe for each source rather than reusing one packet.
    pub fn source_addrs(&self, real_src: IpAddr) -> Vec<IpAddr> {
        let effective = self.spoof_source.unwrap_or(real_src);
        let mut addrs = self.decoys.clone();
        addrs.push(effective);
        addrs
    }
}

/// Split a complete IPv4 packet into fragments of at most `frag`'s payload
/// size. Returns the packet unchanged (as a single element) when it is too
/// short or already fits in one fragment. A header with options
/// (`--ip-options`) is copied whole into every fragment, as nmap does.
///
/// `packet` is a whole IPv4 packet: a 20-byte header followed by the
/// transport payload, as [`packet::ipv4_packet`] builds it. The transport
/// checksum covers the whole payload and travels in the first fragment; the
/// receiver restores it on reassembly, so the fragments carry no transport
/// checksum of their own to recompute.
pub fn fragment_ipv4(pkt: &[u8], frag: Fragment) -> Vec<Vec<u8>> {
    // Only fragment a well-formed IPv4 packet.
    let hlen = usize::from(pkt.first().map_or(0, |b| b & 0x0f)) * 4;
    if pkt.len() < 20 || (pkt[0] >> 4) != 4 || hlen < 20 || pkt.len() < hlen {
        return vec![pkt.to_vec()];
    }
    let header = &pkt[..hlen];
    let payload = &pkt[hlen..];
    let size = frag.payload_bytes();
    if payload.len() <= size {
        return vec![pkt.to_vec()];
    }

    let mut frags = Vec::new();
    let mut offset = 0usize; // payload bytes covered so far
    while offset < payload.len() {
        let end = (offset + size).min(payload.len());
        let chunk = &payload[offset..end];
        let more = end < payload.len();

        let mut p = Vec::with_capacity(hlen + chunk.len());
        p.extend_from_slice(header);
        // Total length = header + this fragment's payload.
        let total = (hlen + chunk.len()) as u16;
        p[2..4].copy_from_slice(&total.to_be_bytes());
        // Flags (3 bits) + fragment offset (13 bits, in 8-byte units).
        let mut flags_off = ((offset / 8) as u16) & 0x1fff;
        if more {
            flags_off |= 0x2000; // More Fragments
        }
        p[6..8].copy_from_slice(&flags_off.to_be_bytes());
        // Recompute the header checksum over the changed header.
        p[10..12].copy_from_slice(&[0, 0]);
        let sum = packet::checksum(&p[..hlen]);
        p[10..12].copy_from_slice(&sum.to_be_bytes());
        p.extend_from_slice(chunk);

        frags.push(p);
        offset = end;
    }
    frags
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn inactive_by_default() {
        assert!(!Evasion::default().is_active());
    }

    #[test]
    fn source_list_appends_real_last() {
        let ev = Evasion {
            decoys: vec![ip("10.0.0.5"), ip("10.0.0.6")],
            ..Default::default()
        };
        assert_eq!(
            ev.source_addrs(ip("10.0.0.1")),
            vec![ip("10.0.0.5"), ip("10.0.0.6"), ip("10.0.0.1")]
        );
    }

    #[test]
    fn source_list_uses_spoofed_source() {
        let ev = Evasion {
            spoof_source: Some(ip("10.9.9.9")),
            ..Default::default()
        };
        assert_eq!(ev.source_addrs(ip("10.0.0.1")), vec![ip("10.9.9.9")]);
    }

    /// A 24-byte payload split into 8-byte fragments reassembles to the
    /// original, with correct offsets, MF flags and header checksums.
    #[test]
    fn fragment_round_trips() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let payload: Vec<u8> = (0..24u8).collect();
        let pkt = packet::ipv4_packet(src, dst, packet::IPPROTO_TCP, 64, 0x1234, &payload);

        let frags = fragment_ipv4(&pkt, Fragment::Eight);
        assert_eq!(frags.len(), 3);

        let mut reassembled = Vec::new();
        for (i, f) in frags.iter().enumerate() {
            // Header checksum is valid (sum over the header is zero).
            assert_eq!(packet::checksum(&f[..20]), 0);
            let flags_off = u16::from_be_bytes([f[6], f[7]]);
            let more = flags_off & 0x2000 != 0;
            let off_units = flags_off & 0x1fff;
            assert_eq!(off_units as usize, i); // offset in 8-byte units: 0, 1, 2
            assert_eq!(more, i < 2); // MF set on all but the last
            reassembled.extend_from_slice(&f[20..]);
        }
        assert_eq!(reassembled, payload);
    }

    #[test]
    fn small_packet_not_fragmented() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let pkt = packet::ipv4_packet(src, dst, packet::IPPROTO_TCP, 64, 1, &[1, 2, 3, 4]);
        let frags = fragment_ipv4(&pkt, Fragment::Eight);
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0], pkt);
    }

    /// Header options travel in every fragment.
    #[test]
    fn fragments_keep_ip_options() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let payload: Vec<u8> = (0..16u8).collect();
        let opts = [1, 1, 1, 1];
        let pkt =
            packet::ipv4_packet_with_options(src, dst, packet::IPPROTO_TCP, 64, 3, &opts, &payload);
        let frags = fragment_ipv4(&pkt, Fragment::Eight);
        assert_eq!(frags.len(), 2);
        for f in &frags {
            assert_eq!(f[0], 0x46);
            assert_eq!(&f[20..24], &opts);
            assert_eq!(packet::checksum(&f[..24]), 0);
            assert_eq!(f.len(), 24 + 8);
        }
    }

    #[test]
    fn mtu_rounds_down_to_eight() {
        // --mtu 20 means 16 payload bytes per fragment (rounded to /8).
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let payload: Vec<u8> = (0..40u8).collect();
        let pkt = packet::ipv4_packet(src, dst, packet::IPPROTO_TCP, 64, 7, &payload);
        let frags = fragment_ipv4(&pkt, Fragment::Mtu(20));
        // 40 bytes / 16 = 3 fragments (16, 16, 8).
        assert_eq!(frags.len(), 3);
        assert_eq!(frags[0][20..].len(), 16);
        assert_eq!(frags[2][20..].len(), 8);
    }
}
