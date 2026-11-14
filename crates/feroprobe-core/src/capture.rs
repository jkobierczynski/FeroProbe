//! Reading every IP packet the host receives, on an `AF_PACKET` socket,
//! for the scans whose answers can come in any protocol: the IP protocol
//! scan (`-sO`) and the SCTP scans. A raw IP socket only sees its own
//! protocol, and on Linux merely having one open for a protocol stops the
//! kernel from answering that protocol's probes to this host with
//! "protocol unreachable", so these scans read packets this way instead.
//! Linux only; needs root (or `CAP_NET_RAW`).

#![cfg(target_os = "linux")]

use std::io;
use std::mem;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::time::Instant;

use crate::packet;

/// One received IP packet, its header parsed.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Packet<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    /// The protocol of the payload (after IPv6 extension headers).
    pub protocol: u8,
    /// TTL or hop limit.
    pub ttl: u8,
    /// The IPv4 identification field; `None` for IPv6.
    pub ipid: Option<u16>,
    pub payload: &'a [u8],
}

impl<'a> Packet<'a> {
    /// Parse an IPv4 or IPv6 packet, header included.
    pub(crate) fn parse(data: &'a [u8]) -> Option<Self> {
        match data.first()? >> 4 {
            4 => {
                let ip = packet::parse_ipv4(data)?;
                Some(Packet {
                    src: ip.src.into(),
                    dst: ip.dst.into(),
                    protocol: ip.protocol,
                    ttl: ip.ttl,
                    ipid: Some(ip.id),
                    payload: ip.payload,
                })
            }
            6 => {
                let ip = packet::parse_ipv6(data)?;
                Some(Packet {
                    src: ip.src.into(),
                    dst: ip.dst.into(),
                    protocol: ip.protocol,
                    ttl: ip.hop_limit,
                    ipid: None,
                    payload: ip.payload,
                })
            }
            _ => None,
        }
    }
}

/// Open a socket that sees every IPv4 and IPv6 packet on every interface,
/// without link-layer headers.
pub(crate) fn open() -> io::Result<OwnedFd> {
    let proto = (libc::ETH_P_ALL as u16).to_be();
    // SAFETY: plain socket(2) call; the result is checked below.
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_DGRAM, i32::from(proto)) };
    if fd < 0 {
        let e = io::Error::last_os_error();
        return Err(if e.kind() == io::ErrorKind::PermissionDenied {
            io::Error::new(
                e.kind(),
                "this scan reads packets off the wire and needs root (or CAP_NET_RAW)",
            )
        } else {
            e
        });
    }
    // SAFETY: fd is a freshly created, owned descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 50_000,
    };
    let size = 8i32 << 20;
    // SAFETY: setsockopt with correctly sized option values.
    unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&tv as *const libc::timeval).cast(),
            mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            (&size as *const i32).cast(),
            mem::size_of::<i32>() as libc::socklen_t,
        );
    }
    Ok(fd)
}

/// Read packets until `stop` is set, and send on those `parse` recognises,
/// given the packet and when it arrived. Packets this host sends are
/// skipped: on the loopback interface each also comes back as received,
/// and `parse` must tell those from answers (by direction or content).
pub(crate) fn receive_loop<T>(
    fd: OwnedFd,
    stop: &AtomicBool,
    tx: &SyncSender<T>,
    parse: impl Fn(&Packet<'_>, Instant) -> Option<T>,
) {
    let mut buf = vec![0u8; 65536];
    while !stop.load(Ordering::Relaxed) {
        // SAFETY: sockaddr_ll is plain data; all-zero is a valid value.
        let mut from: libc::sockaddr_ll = unsafe { mem::zeroed() };
        let mut len = mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
        // SAFETY: reads into `buf` and `from`, both of the sizes given.
        let n = unsafe {
            libc::recvfrom(
                fd.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                0,
                (&mut from as *mut libc::sockaddr_ll).cast(),
                &mut len,
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            if crate::raw::is_idle_read(&e) {
                continue;
            }
            return;
        }
        let at = Instant::now();
        if from.sll_pkttype == libc::PACKET_OUTGOING {
            continue;
        }
        let ethertype = u16::from_be(from.sll_protocol);
        if ethertype != libc::ETH_P_IP as u16 && ethertype != libc::ETH_P_IPV6 as u16 {
            continue;
        }
        let Some(pkt) = Packet::parse(&buf[..n as usize]) else {
            continue;
        };
        let Some(answer) = parse(&pkt, at) else {
            continue;
        };
        crate::packet_trace::log("RCVD", || {
            let line = crate::packet_trace::describe(
                pkt.protocol,
                pkt.payload,
                Some(pkt.src),
                Some(pkt.dst),
            );
            format!("{line} ttl={}", pkt.ttl)
        });
        // Drop the answer if the queue is full (an overloaded or hostile
        // responder); stop only once the receiver has gone.
        if let Err(TrySendError::Disconnected(_)) = tx.try_send(answer) {
            return;
        }
    }
}
