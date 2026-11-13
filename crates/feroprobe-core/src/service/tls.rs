//! TLS for service detection: wrap a connection so the probes can see the
//! service inside, and read the certificate's subject name.
//!
//! Certificates are accepted without any checks. A scanner wants to know
//! what is listening, not whether to trust it, and nothing sensitive is sent.

use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

#[derive(Debug)]
struct AcceptAnyCert(Vec<SignatureScheme>);

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.clone()
    }
}

static CONNECTOR: LazyLock<TlsConnector> = LazyLock::new(|| {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let schemes = provider
        .signature_verification_algorithms
        .supported_schemes();
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring supports the default TLS versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert(schemes)))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    TlsConnector::from(Arc::new(config))
});

/// Connect to `addr` and complete a TLS handshake. Returns the stream and
/// the certificate's subject common name, or `None` if the port does not
/// speak TLS (1.2 or later). `host` is sent as SNI when known. `timeout`
/// limits the TCP connect, `wait` the handshake.
pub(super) async fn connect(
    addr: SocketAddr,
    host: Option<&str>,
    timeout: Duration,
    wait: Duration,
) -> Option<(TlsStream<TcpStream>, Option<String>)> {
    let tcp = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;
    let name = host
        .and_then(|h| ServerName::try_from(h.to_string()).ok())
        .unwrap_or_else(|| ServerName::IpAddress(addr.ip().into()));
    let tls = tokio::time::timeout(wait, CONNECTOR.connect(name, tcp))
        .await
        .ok()?
        .ok()?;
    let cn = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certs| certs.first())
        .and_then(|cert| subject_cn(cert));
    Some((tls, cn))
}

/// One DER element: tag, contents, and the bytes after it.
fn der(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, mut rest) = rest.split_first()?;
    let len = if first < 0x80 {
        usize::from(first)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let len = rest[..n]
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
        rest = &rest[n..];
        len
    };
    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}

/// The subject common name (OID 2.5.4.3) of a DER X.509 certificate.
pub(super) fn subject_cn(cert: &[u8]) -> Option<String> {
    let (_, cert, _) = der(cert)?; // Certificate
    let (_, mut tbs, _) = der(cert)?; // TBSCertificate
    if tbs.first() == Some(&0xa0) {
        tbs = der(tbs)?.2; // [0] version
    }
    // Skip serial number, signature algorithm, issuer and validity.
    for _ in 0..4 {
        tbs = der(tbs)?.2;
    }
    let (_, mut subject, _) = der(tbs)?;
    while !subject.is_empty() {
        let (_, set, rest) = der(subject)?;
        subject = rest;
        let (_, attr, _) = der(set)?;
        let (tag, oid, value) = der(attr)?;
        if tag == 0x06 && oid == [0x55, 0x04, 0x03] {
            return super::rules::clean(der(value)?.1);
        }
    }
    None
}
