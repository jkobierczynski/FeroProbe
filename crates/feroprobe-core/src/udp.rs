//! UDP scanning.
//!
//! Each port gets a datagram from a *connected* UDP socket. Connecting lets
//! the OS hand us the ICMP "port unreachable" a closed port triggers, as a
//! "connection refused" error, so no raw sockets or root are needed:
//!
//! - **open**: the service answered with data
//! - **closed**: ICMP port unreachable came back
//! - **filtered**: another ICMP unreachable error (host, network, prohibited)
//! - **open|filtered**: no answer at all, which is normal for many UDP
//!   services that ignore unexpected packets, but also for firewalled ports
//!
//! For a few well-known services a protocol-specific payload is sent, so that
//! they actually answer and can be reported as open.
//!
//! Note that hosts rate-limit ICMP errors (Linux allows about 1000 per second
//! with small bursts), so scanning many closed ports quickly can turn some of
//! them into open|filtered. Lower `--concurrency` for more accurate results.

use std::io::{self, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Instant;

use futures::stream::{self, StreamExt};
use socket2::{Domain, Protocol as SockProtocol, Socket, Type};
use tokio::net::UdpSocket;

use crate::connect::is_network_error;
use crate::model::{HostResult, PortResult, PortState, Protocol, ScanConfig, elapsed_ms, reason};
use crate::target::Target;
use crate::timing::pace;

/// A payload likely to make the service on `port` reply, or empty.
pub fn payload_for(port: u16) -> &'static [u8] {
    match port {
        // DNS: standard query for the root NS records.
        53 | 5353 => &[
            0x13, 0x37, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x01,
        ],
        // NTP: version 4 client request.
        123 => &NTP_REQUEST,
        // SNMP v1 GetRequest for sysDescr.0 with community "public".
        161 => &[
            0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa0,
            0x19, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x30, 0x0c,
            0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
        ],
        // SSDP (UPnP) discovery.
        1900 => b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n",
        _ => &[],
    }
}

const NTP_REQUEST: [u8; 48] = {
    let mut p = [0u8; 48];
    p[0] = 0x23; // LI 0, version 4, mode 3 (client)
    p
};

/// Whether the error is the OS reporting an ICMP port unreachable.
fn is_port_unreachable(e: &io::Error) -> bool {
    // Windows reports it on connected UDP sockets as a connection reset.
    e.kind() == ErrorKind::ConnectionRefused
        || (cfg!(windows) && e.kind() == ErrorKind::ConnectionReset)
}

/// ICMP errors other than "port unreachable" that mean a filter or router
/// rejected the probe, beyond the ones [`is_network_error`] knows.
fn is_udp_filtered(e: &io::Error) -> bool {
    // Linux maps ICMP "protocol unreachable" (code 2) to ENOPROTOOPT.
    #[cfg(target_os = "linux")]
    if e.raw_os_error() == Some(libc::ENOPROTOOPT) {
        return true;
    }
    is_network_error(e)
}

/// Whether the reply was larger than our buffer. Windows reports this as an
/// error (WSAEMSGSIZE) instead of truncating; either way the port answered.
fn is_truncated_reply(e: &io::Error) -> bool {
    cfg!(windows) && e.raw_os_error() == Some(10040)
}

/// A UDP socket connected to `addr`. On Linux it also asks for all ICMP
/// errors (`IP_RECVERR`): by default Linux drops "soft" ones such as host
/// unreachable on UDP sockets, which would turn filtered ports into
/// open|filtered.
pub(crate) async fn connected_socket(addr: SocketAddr) -> io::Result<UdpSocket> {
    let (domain, bind): (Domain, SocketAddr) = match addr.ip() {
        IpAddr::V4(_) => (Domain::IPV4, (Ipv4Addr::UNSPECIFIED, 0).into()),
        IpAddr::V6(_) => (Domain::IPV6, (Ipv6Addr::UNSPECIFIED, 0).into()),
    };
    let sock = Socket::new(domain, Type::DGRAM, Some(SockProtocol::UDP))?;
    #[cfg(target_os = "linux")]
    enable_recverr(&sock, addr.is_ipv4())?;
    sock.set_nonblocking(true)?;
    sock.bind(&bind.into())?;
    let sock = UdpSocket::from_std(sock.into())?;
    sock.connect(addr).await?;
    Ok(sock)
}

#[cfg(target_os = "linux")]
fn enable_recverr(sock: &Socket, ipv4: bool) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let (level, name) = if ipv4 {
        (libc::IPPROTO_IP, libc::IP_RECVERR)
    } else {
        (libc::IPPROTO_IPV6, libc::IPV6_RECVERR)
    };
    let on: libc::c_int = 1;
    // SAFETY: valid socket fd, and a pointer/length pair for a c_int.
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            level,
            name,
            (&raw const on).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Probe a single UDP port.
pub async fn probe_udp(addr: SocketAddr, cfg: &ScanConfig) -> io::Result<PortResult> {
    let result = |state, reason, rtt_ms| PortResult {
        port: addr.port(),
        protocol: Protocol::Udp,
        state,
        reason,
        rtt_ms,
        service: None,
    };
    let classify = |e: io::Error, rtt| {
        if is_port_unreachable(&e) {
            Ok(result(PortState::Closed, reason::PORT_UNREACH, rtt))
        } else if is_udp_filtered(&e) {
            Ok(result(PortState::Filtered, reason::UNREACHABLE, rtt))
        } else {
            Err(io::Error::new(
                e.kind(),
                format!("udp probe to {addr}: {e}"),
            ))
        }
    };
    // Creating, binding and connecting the socket can already fail for
    // network reasons (no route, IPv6 disabled); classify those too.
    let sock = match connected_socket(addr).await {
        Ok(s) => s,
        Err(e) => return classify(e, None),
    };

    let payload = payload_for(addr.port());
    let mut buf = [0u8; 2048];
    for _ in 0..=cfg.retries {
        pace(cfg.scan_delay).await;
        let start = Instant::now();
        if let Err(e) = sock.send(payload).await {
            return classify(e, None);
        }
        match tokio::time::timeout(cfg.timeout, sock.recv(&mut buf)).await {
            Ok(Ok(_)) => {
                return Ok(result(
                    PortState::Open,
                    reason::UDP_RESPONSE,
                    Some(elapsed_ms(start)),
                ));
            }
            Ok(Err(e)) if is_truncated_reply(&e) => {
                return Ok(result(
                    PortState::Open,
                    reason::UDP_RESPONSE,
                    Some(elapsed_ms(start)),
                ));
            }
            Ok(Err(e)) => return classify(e, Some(elapsed_ms(start))),
            Err(_) => continue,
        }
    }
    Ok(result(PortState::OpenFiltered, reason::NO_RESPONSE, None))
}

/// Scan every UDP port on every target.
pub async fn udp_scan(
    targets: &[Target],
    ports: &[u16],
    cfg: &ScanConfig,
) -> io::Result<Vec<HostResult>> {
    let mut hosts: Vec<HostResult> = targets
        .iter()
        .map(|t| HostResult::new(t.addr, t.hostname.clone()))
        .collect();
    let jobs = ports
        .iter()
        .flat_map(|&port| (0..targets.len()).map(move |h| (h, port)));
    let mut results = stream::iter(jobs)
        .map(|(h, port)| {
            let addr = SocketAddr::new(targets[h].addr, port);
            async move { (h, probe_udp(addr, cfg).await) }
        })
        .buffer_unordered(cfg.concurrency.max(1));
    while let Some((h, r)) = results.next().await {
        hosts[h].ports.push(r?);
    }
    for host in &mut hosts {
        host.sort_ports();
    }
    Ok(hosts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn open_closed_and_silent() {
        // An echo server: answers, so the port is open.
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let open = echo.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((n, from)) = echo.recv_from(&mut buf).await {
                let _ = echo.send_to(&buf[..n.max(1)], from).await;
            }
        });
        // Bound but never reads: silent, so open|filtered.
        let silent_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let silent = silent_sock.local_addr().unwrap().port();
        // Nothing bound: the kernel answers with ICMP port unreachable.
        let closed = {
            let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            s.local_addr().unwrap().port()
        };

        let cfg = ScanConfig {
            timeout: Duration::from_millis(300),
            retries: 0,
            ..Default::default()
        };
        let target = Target::new("127.0.0.1".parse().unwrap());
        let hosts = udp_scan(&[target], &[open, silent, closed], &cfg)
            .await
            .unwrap();
        let state_of = |p| hosts[0].ports.iter().find(|r| r.port == p).unwrap().state;
        assert_eq!(state_of(open), PortState::Open);
        assert_eq!(state_of(silent), PortState::OpenFiltered);
        assert_eq!(state_of(closed), PortState::Closed);
        assert!(hosts[0].ports.iter().all(|p| p.protocol == Protocol::Udp));
        drop(silent_sock);
    }

    #[test]
    fn payloads() {
        assert_eq!(payload_for(123).len(), 48);
        assert!(payload_for(53).len() > 12);
        assert!(payload_for(9999).is_empty());
    }
}
