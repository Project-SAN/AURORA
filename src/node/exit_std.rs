use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as FmtWrite;
use core::str;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::Once;
use std::time::Duration;

use crate::routing::IpAddr;
use crate::types::{Error, Result};

use super::ExitTransport;

pub struct TcpExitTransport;

impl TcpExitTransport {
    pub fn new() -> Self {
        Self
    }
}

impl ExitTransport for TcpExitTransport {
    fn send(&mut self, addr: &IpAddr, port: u16, tls: bool, request: &[u8]) -> Result<Vec<u8>> {
        let addr_str = match addr {
            IpAddr::V4(octets) => format!(
                "{}.{}.{}.{}:{}",
                octets[0], octets[1], octets[2], octets[3], port
            ),
            IpAddr::V6(bytes) => {
                let mut buf = String::new();
                buf.push('[');
                for (i, chunk) in bytes.chunks(2).enumerate() {
                    if i > 0 {
                        buf.push(':');
                    }
                    let value = u16::from_be_bytes([chunk[0], chunk[1]]);
                    let _ = FmtWrite::write_fmt(&mut buf, format_args!("{:x}", value));
                }
                buf.push(']');
                let _ = FmtWrite::write_fmt(&mut buf, format_args!(":{}", port));
                buf
            }
        };

        let mut stream = TcpStream::connect(addr_str).map_err(|_| Error::Crypto)?;
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

        if !tls {
            stream.write_all(request).map_err(|_| Error::Crypto)?;
            let mut response = Vec::new();
            let _ = stream.read_to_end(&mut response);
            return Ok(response);
        }

        ensure_rustls_provider_installed();

        let server_name = std::env::var("HORNET_TLS_SERVER_NAME")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| parse_http_host_header(request));
        let Some(server_name) = server_name else {
            return Err(Error::Crypto);
        };

        let insecure = std::env::var("HORNET_TLS_INSECURE").ok().as_deref() == Some("1");
        let config = if insecure {
            tls_config_insecure()
        } else {
            tls_config_webpki_roots()
        };

        let server_name = rustls::pki_types::ServerName::try_from(server_name).map_err(|err| {
            eprintln!("[exit-tls] invalid server name: {err:?}");
            Error::Crypto
        })?;
        let mut conn =
            rustls::ClientConnection::new(Arc::new(config), server_name).map_err(|err| {
                eprintln!("[exit-tls] failed to create client connection: {err:?}");
                Error::Crypto
            })?;
        let mut tls = rustls::Stream::new(&mut conn, &mut stream);
        tls.write_all(request).map_err(|err| {
            eprintln!("[exit-tls] write failed: {err}");
            Error::Crypto
        })?;
        tls.flush().map_err(|err| {
            eprintln!("[exit-tls] flush failed: {err}");
            Error::Crypto
        })?;
        let mut response = Vec::new();
        tls.read_to_end(&mut response).map_err(|err| {
            eprintln!("[exit-tls] read failed: {err}");
            Error::Crypto
        })?;
        Ok(response)
    }
}

fn ensure_rustls_provider_installed() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // rustls 0.23 requires selecting a crypto provider at runtime.
        // Ignore errors here; connection creation will fail and bubble up as Error::Crypto.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn parse_http_host_header(request: &[u8]) -> Option<String> {
    let s = str::from_utf8(request).ok()?;
    for line in s.split('\n') {
        let line = line.trim_end_matches('\r').trim();
        if line.len() < 5 {
            continue;
        }
        if !line.as_bytes()[..5].eq_ignore_ascii_case(b"host:") {
            continue;
        }
        let mut host = line[5..].trim();
        if host.is_empty() {
            return None;
        }
        // Remove optional port.
        if let Some((h, _p)) = host.rsplit_once(':') {
            if !h.contains(':') {
                host = h;
            }
        }
        // Strip brackets for IPv6 literals: [::1]
        if let Some(inner) = host
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            host = inner;
        }
        let host = host.trim();
        if host.is_empty() {
            return None;
        }
        return Some(host.to_string());
    }
    None
}

fn tls_config_webpki_roots() -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();

    // Optional extra roots (DER-encoded certificates).
    //
    // This is mainly for environments with TLS interception or custom CAs, where
    // `webpki-roots` will not validate the proxy-issued chain.
    //
    // Format: a path to a single DER file, or multiple paths separated by `;`.
    if let Ok(paths) = std::env::var("HORNET_TLS_ROOT_DER_PATHS") {
        for path in paths.split(';').map(str::trim).filter(|p| !p.is_empty()) {
            match std::fs::read(path) {
                Ok(bytes) => {
                    let _ = roots.add(rustls::pki_types::CertificateDer::from(bytes));
                }
                Err(err) => {
                    eprintln!("[exit-tls] failed to read root DER {path}: {err}");
                }
            }
        }
    }

    if std::env::var("HORNET_TLS_DISABLE_WEBPKI_ROOTS")
        .ok()
        .as_deref()
        != Some("1")
    {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

fn tls_config_insecure() -> rustls::ClientConfig {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    #[derive(Debug)]
    struct NoVerifier;

    impl ServerCertVerifier for NoVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> core::result::Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> core::result::Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> core::result::Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let mut cfg = config;
    cfg.dangerous()
        .set_certificate_verifier(Arc::new(NoVerifier));
    cfg
}
