//! End-to-end tests against small local servers.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;
use crate::model::{PortResult, reason};

const WAIT: Duration = Duration::from_millis(400);

fn cfg() -> ScanConfig {
    ScanConfig {
        timeout: Duration::from_secs(5),
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
    let info = detect_tcp(addr, None, &cfg(), WAIT).await.unwrap();
    assert_eq!(info.name, "ssh");
    assert_eq!(info.version_line(), "OpenSSH 9.6 (protocol 2.0)");
}

#[tokio::test]
async fn silent_until_http() {
    let addr = serve(http_reply).await;
    let info = detect_tcp(addr, None, &cfg(), WAIT).await.unwrap();
    assert_eq!(info.full_name(), "http");
    assert_eq!(info.version_line(), "TestServer 1.2.3 (Test)");
}

#[tokio::test]
async fn unrecognized_banner() {
    let addr = serve(|mut s| async move {
        let _ = s.write_all(b"WELCOME TO THE THING\r\n").await;
    })
    .await;
    let info = detect_tcp(addr, None, &cfg(), WAIT).await.unwrap();
    assert!(info.name.ends_with('?'), "{info:?}");
    assert_eq!(
        info.fingerprint.as_deref(),
        Some("WELCOME TO THE THING\\r\\n")
    );
}

#[tokio::test]
async fn silent_service_gives_nothing() {
    let addr = serve(|mut s| async move {
        let mut buf = [0u8; 1024];
        while matches!(s.read(&mut buf).await, Ok(n) if n > 0) {}
    })
    .await;
    assert_eq!(detect_tcp(addr, None, &cfg(), WAIT).await, None);
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
    let info = detect_tcp(addr, None, &cfg(), WAIT).await.unwrap();
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
    };
    let mut hosts = vec![HostResult::new(addr.ip(), None)];
    hosts[0].ports = vec![
        port(addr.port(), PortState::Open),
        port(1, PortState::Closed),
    ];
    detect_services(&mut hosts, &cfg(), WAIT).await;
    assert_eq!(hosts[0].ports[0].service.as_ref().unwrap().name, "http");
    assert_eq!(hosts[0].ports[1].service, None);
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
    let info = detect_tcp(addr, None, &cfg(), WAIT).await.unwrap();
    assert_eq!(info.name, "ssh");
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "{:?}",
        start.elapsed()
    );
}
