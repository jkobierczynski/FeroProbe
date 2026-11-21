//! End-to-end tests against small local servers.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::*;
use crate::model::{PortResult, reason};

const WAIT: Duration = Duration::from_millis(400);

fn vs() -> VersionScan {
    VersionScan::new(WAIT)
}

fn cfg() -> ScanConfig {
    ScanConfig {
        rtt: crate::rtt::RttTimeouts::fixed(Duration::from_secs(5)),
        ..Default::default()
    }
}

/// A TCP server that runs `handler` for every connection.
async fn serve<F, Fut>(handler: F) -> SocketAddr
where
    F: Fn(TcpStream) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(handler(stream));
        }
    });
    addr
}

/// Read one request, then send a canned HTTP response.
async fn http_reply(mut s: TcpStream) {
    let mut buf = [0u8; 1024];
    let _ = s.read(&mut buf).await;
    let _ = s
        .write_all(b"HTTP/1.0 200 OK\r\nServer: TestServer/1.2.3 (Test)\r\n\r\nhello")
        .await;
}

#[tokio::test]
async fn banner_service() {
    let addr = serve(|mut s| async move {
        let _ = s.write_all(b"SSH-2.0-OpenSSH_9.6\r\n").await;
        let mut buf = [0u8; 64];
        let _ = s.read(&mut buf).await;
    })
    .await;
    let info = detect_tcp(addr, None, &cfg(), &vs()).await.unwrap();
    assert_eq!(info.name, "ssh");
    assert_eq!(info.version_line(), "OpenSSH 9.6 (protocol 2.0)");
}

#[tokio::test]
async fn silent_until_http() {
    let addr = serve(http_reply).await;
    let info = detect_tcp(addr, None, &cfg(), &vs()).await.unwrap();
    assert_eq!(info.full_name(), "http");
    assert_eq!(info.version_line(), "TestServer 1.2.3 (Test)");
}

#[tokio::test]
async fn unrecognized_banner() {
    let addr = serve(|mut s| async move {
        let _ = s.write_all(b"WELCOME TO THE THING\r\n").await;
    })
    .await;
    let info = detect_tcp(addr, None, &cfg(), &vs()).await.unwrap();
    assert!(info.name.ends_with('?'), "{info:?}");
    assert_eq!(
        info.fingerprint.as_deref(),
        Some("WELCOME TO THE THING\\r\\n")
    );
}

#[tokio::test]
async fn silent_service_gets_a_question_mark() {
    let addr = serve(|mut s| async move {
        let mut buf = [0u8; 1024];
        while matches!(s.read(&mut buf).await, Ok(n) if n > 0) {}
    })
    .await;
    let vs = VersionScan {
        wait: Duration::from_millis(100),
        ..vs()
    };
    // As in nmap: "?" after the port's name, "unknown" when it has none.
    let info = detect_tcp(addr, None, &cfg(), &vs).await.unwrap();
    let expected = match crate::ports::service_name(Protocol::Tcp, addr.port()) {
        "unknown" => "unknown".to_string(),
        name => format!("{name}?"),
    };
    assert_eq!(info.name, expected);
    assert_eq!(info.product, None);
}

/// A server that answers only memcached's "version" command.
async fn memcached_only() -> SocketAddr {
    serve(|mut s| async move {
        let mut buf = [0u8; 1024];
        if let Ok(n) = s.read(&mut buf).await
            && &buf[..n] == b"version\r\n"
        {
            let _ = s.write_all(b"VERSION 1.6.21\r\n").await;
        }
        let _ = s.read(&mut buf).await;
    })
    .await
}

#[tokio::test]
async fn intensity_decides_how_deep_to_probe() {
    let addr = memcached_only().await;
    let fast = |intensity| VersionScan {
        wait: Duration::from_millis(100),
        intensity,
        ..vs()
    };
    // The memcached probe has rarity 7: tried on any port at 7, not at 6.
    let info = detect_tcp(addr, None, &cfg(), &fast(7)).await.unwrap();
    assert_eq!(info.version_line(), "Memcached 1.6.21");
    // At 6 it stays silent to every probe sent: no product.
    let info = detect_tcp(addr, None, &cfg(), &fast(6)).await.unwrap();
    assert_eq!(info.product, None);
}

#[tokio::test]
async fn soft_match_names_the_service() {
    let addr = serve(|mut s| async move {
        let _ = s.write_all(b"+OK hello from somewhere\r\n").await;
        let mut buf = [0u8; 64];
        let _ = s.read(&mut buf).await;
    })
    .await;
    let info = detect_tcp(addr, None, &cfg(), &vs()).await.unwrap();
    assert_eq!(info.name, "pop3");
    assert_eq!(info.product, None);
    assert_eq!(
        info.fingerprint.as_deref(),
        Some("+OK hello from somewhere\\r\\n")
    );
    // Below intensity 7 no fingerprint, like nmap.
    let light = VersionScan {
        intensity: VersionScan::LIGHT,
        ..vs()
    };
    let info = detect_tcp(addr, None, &cfg(), &light).await.unwrap();
    assert_eq!((info.name.as_str(), info.fingerprint), ("pop3", None));
}

#[test]
fn probe_order_follows_rarity() {
    let db = ServiceDb::builtin();
    let names = |port, listen| {
        probe_order(&db, Protocol::Tcp, port, listen)
            .into_iter()
            .map(|(p, hinted)| (p.name.as_str(), hinted))
            .collect::<Vec<_>>()
    };
    let at_80 = names(80, Listen::AfterHinted);
    assert_eq!(at_80[0], ("http", true));
    assert_eq!(at_80[1], ("null", false));
    // Then by rarity, the lowest first; no TLS, no repeat of http.
    let rarities: Vec<u8> = at_80[2..]
        .iter()
        .map(|(n, _)| db.probe(n).unwrap().rarity)
        .collect();
    assert!(rarities.windows(2).all(|w| w[0] <= w[1]), "{rarities:?}");
    assert!(at_80.iter().all(|(n, _)| *n != "tls"));
    assert_eq!(at_80.iter().filter(|(n, _)| *n == "http").count(), 1);
    // Inside TLS on a talk-first port: listen first.
    assert_eq!(names(993, Listen::First)[0].0, "null");
    assert!(names(443, Listen::Never).iter().all(|(n, _)| *n != "null"));
    // UDP probes only for UDP.
    let udp = probe_order(&db, Protocol::Udp, 53, Listen::Never);
    assert_eq!(udp[0].0.name, "dns-version");
    assert!(udp.iter().all(|(p, _)| p.protocol == Protocol::Udp));
}

#[test]
fn soft_matches_narrow_the_probes() {
    let db = ServiceDb::builtin();
    let p = |n| db.probe(n).unwrap();
    // No soft match: rarity against intensity, own port always.
    assert!(allowed(&db, p("memcached"), false, None, 7));
    assert!(!allowed(&db, p("memcached"), false, None, 6));
    assert!(allowed(&db, p("memcached"), true, None, 0));
    // After a soft "ldap", only probes that can say more about LDAP.
    assert!(allowed(&db, p("ldap"), false, Some("ldap"), 0));
    assert!(!allowed(&db, p("http"), true, Some("ldap"), 7));
    assert!(allowed(&db, p("http"), false, Some("ldap"), 9));
    assert!(allowed(&db, p("pgsql"), false, Some("postgresql"), 2));
}

#[tokio::test]
async fn udp_probes_by_rarity() {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            if buf[..n].ends_with(b"version\r\n") {
                let _ = sock
                    .send_to(b"\x00\x01\x00\x00\x00\x01\x00\x00VERSION 1.6.9\r\n", from)
                    .await;
            }
        }
    });
    let vs = VersionScan {
        wait: Duration::from_millis(100),
        intensity: VersionScan::ALL,
        ..vs()
    };
    let cfg = ScanConfig {
        retries: 0,
        ..cfg()
    };
    let info = detect_udp(addr, &cfg, &vs).await.unwrap();
    assert_eq!(info.version_line(), "Memcached 1.6.9");
}

#[tokio::test]
async fn open_filtered_udp_that_answers_becomes_open() {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            if buf[..n].ends_with(b"version\r\n") {
                let _ = sock
                    .send_to(b"\x00\x01\x00\x00\x00\x01\x00\x00VERSION 1.6.9\r\n", from)
                    .await;
            }
        }
    });
    let mut hosts = vec![HostResult::new(addr.ip(), None)];
    hosts[0].ports = vec![PortResult {
        port: addr.port(),
        protocol: Protocol::Udp,
        state: PortState::OpenFiltered,
        reason: reason::NO_RESPONSE,
        rtt_ms: None,
        service: None,
        scripts: Vec::new(),
    }];
    let vs = VersionScan {
        wait: Duration::from_millis(100),
        intensity: VersionScan::ALL,
        ..vs()
    };
    let cfg = ScanConfig {
        retries: 0,
        ..cfg()
    };
    detect_services(&mut hosts, &cfg, &vs).await;
    let p = &hosts[0].ports[0];
    assert_eq!((p.state, p.reason), (PortState::Open, reason::UDP_RESPONSE));
    assert_eq!(p.service.as_ref().unwrap().name, "memcache");
}

#[tokio::test]
async fn empty_udp_datagram_marks_the_port_open() {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((_, from)) = sock.recv_from(&mut buf).await {
            let _ = sock.send_to(b"", from).await;
        }
    });
    let vs = VersionScan {
        wait: Duration::from_millis(100),
        intensity: 0,
        ..vs()
    };
    let cfg = ScanConfig {
        retries: 0,
        ..cfg()
    };
    let info = detect_udp(addr, &cfg, &vs).await;
    // Intensity 0 on an unknown port sends no probe at all.
    assert_eq!(info, None);
    let vs = VersionScan {
        intensity: VersionScan::ALL,
        ..vs
    };
    let info = detect_udp(addr, &cfg, &vs).await.unwrap();
    assert!(info.name.ends_with('?'), "{info:?}");
    assert_eq!(info.fingerprint, None);
}

#[test]
fn dry_run_describes_the_probes() {
    let lines = dry_run_lines(&vs(), &[22, 80, 443], &[53]);
    assert!(lines[0].contains("intensity 7"), "{lines:?}");
    let tcp = &lines[1];
    assert!(tcp.contains("TLS handshake first on 443"), "{tcp}");
    assert!(tcp.contains("http on 80"), "{tcp}");
    assert!(tcp.contains("null (connect and listen)"), "{tcp}");
    assert!(
        tcp.contains("memcached") && !tcp.contains("beanstalkd"),
        "{tcp}"
    );
    assert!(lines[2].contains("dns-version on 53"), "{lines:?}");
    let light = VersionScan {
        intensity: 0,
        ..vs()
    };
    let lines = dry_run_lines(&light, &[8080], &[]);
    assert!(!lines[1].contains("by rarity"), "{lines:?}");
}

#[tokio::test]
async fn http_inside_tls() {
    let cert = rcgen::generate_simple_self_signed(vec!["probe.test".to_string()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert.cert.der().clone()], key)
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let addr = serve(move |s| {
        let acceptor = acceptor.clone();
        async move {
            let Ok(mut tls) = acceptor.accept(s).await else {
                return;
            };
            let mut buf = [0u8; 1024];
            let _ = tls.read(&mut buf).await;
            let _ = tls
                .write_all(b"HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\n\r\n")
                .await;
            let _ = tls.shutdown().await;
        }
    })
    .await;
    let info = detect_tcp(addr, None, &cfg(), &vs()).await.unwrap();
    assert_eq!(info.full_name(), "ssl/http");
    assert_eq!(
        info.version_line(),
        "nginx 1.25.3 (cert CN: rcgen self signed cert)"
    );
}

#[tokio::test]
async fn fills_open_ports_only() {
    let addr = serve(http_reply).await;
    let port = |port, state| PortResult {
        port,
        protocol: Protocol::Tcp,
        state,
        reason: reason::SYN_ACK,
        rtt_ms: None,
        service: None,
        scripts: Vec::new(),
    };
    let mut hosts = vec![HostResult::new(addr.ip(), None)];
    hosts[0].ports = vec![
        port(addr.port(), PortState::Open),
        port(1, PortState::Closed),
    ];
    detect_services(&mut hosts, &cfg(), &vs()).await;
    assert_eq!(hosts[0].ports[0].service.as_ref().unwrap().name, "http");
    assert_eq!(hosts[0].ports[1].service, None);
}

#[tokio::test]
async fn excluded_ports_are_left_alone() {
    // A server that counts connections: an excluded port gets none.
    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    let addr = serve(move |s| {
        counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        http_reply(s)
    })
    .await;
    let mut db = ServiceDb::parse(
        &format!(
            "feroprobe-service-rules 1\nexclude tcp {}\nprobe http tcp\n  rarity 1\n  send \"GET / HTTP/1.0\\r\\n\\r\\n\"\n",
            addr.port()
        ),
        "test",
    )
    .unwrap();
    db.source = "test".into();
    let mut scan = VersionScan {
        db: Arc::new(db),
        ..vs()
    };
    let open = || PortResult {
        port: addr.port(),
        protocol: Protocol::Tcp,
        state: PortState::Open,
        reason: reason::SYN_ACK,
        rtt_ms: None,
        service: None,
        scripts: Vec::new(),
    };
    let mut hosts = vec![HostResult::new(addr.ip(), None)];
    hosts[0].ports = vec![open()];
    detect_services(&mut hosts, &cfg(), &scan).await;
    let name = &hosts[0].ports[0].service.as_ref().unwrap().name;
    assert!(name.ends_with('?'), "{name}");
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0);
    let lines = dry_run_lines(&scan, &[addr.port()], &[]);
    assert!(lines[1].contains("--allports"), "{lines:?}");
    // --allports probes it.
    scan.all_ports = true;
    hosts[0].ports = vec![open()];
    detect_services(&mut hosts, &cfg(), &scan).await;
    assert_eq!(hosts[0].ports[0].service.as_ref().unwrap().name, "http");
    assert!(hits.load(std::sync::atomic::Ordering::SeqCst) > 0);
}

#[test]
fn printable_escapes() {
    assert_eq!(printable(b"a\\b\x00\r\n", 10), "a\\\\b\\x00\\r\\n");
    assert_eq!(printable(b"abcdef", 3), "abc");
}

#[tokio::test]
async fn slow_trickle_is_cut_off() {
    // One byte every 100 ms, forever: the reply must end after `wait`.
    let addr = serve(|mut s| async move {
        let _ = s.write_all(b"SSH-2.0-").await;
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if s.write_all(b"x").await.is_err() {
                break;
            }
        }
    })
    .await;
    let start = std::time::Instant::now();
    let info = detect_tcp(addr, None, &cfg(), &vs()).await.unwrap();
    assert_eq!(info.name, "ssh");
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "{:?}",
        start.elapsed()
    );
}
