pub mod domain;

pub use domain::{
    announcement, fixed_policy_id, publish_directory, sign_directory_json, verify_directory_json,
    AuthorityError, AuthorityKeyPair, PublishedDirectory, SignatureScheme,
};

use aurora::policy::PolicyMetadata;
use aurora::routing::{self, IpAddr, RouteElem};
use aurora::setup::directory::RouteAnnouncement;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, TcpListener, TcpStream};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_BIND_ADDR: &str = "127.0.0.1:8080";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityConfig {
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,
    #[serde(default)]
    pub signature_scheme: SignatureScheme,
    #[serde(default)]
    pub issued_at: Option<u64>,
    pub signing_key_seed_hex: String,
    #[serde(default)]
    pub policies: Vec<PolicyMetadata>,
    #[serde(default)]
    pub routes: Vec<RouteSpec>,
}

impl AuthorityConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, AuthorityError> {
        let body = fs::read_to_string(path)?;
        Ok(serde_json::from_str(&body)?)
    }

    pub fn key_pair(&self) -> Result<AuthorityKeyPair, AuthorityError> {
        match self.signature_scheme {
            SignatureScheme::Ed25519 => AuthorityKeyPair::from_seed_hex(&self.signing_key_seed_hex),
        }
    }

    pub fn issued_at(&self) -> Result<u64, AuthorityError> {
        self.issued_at
            .map(Ok)
            .unwrap_or_else(current_unix_timestamp)
    }

    pub fn announcement(
        &self,
    ) -> Result<aurora::setup::directory::DirectoryAnnouncement, AuthorityError> {
        self.routes
            .iter()
            .map(RouteSpec::to_route_announcement)
            .collect::<Result<Vec<_>, _>>()
            .map(|routes| domain::announcement(self.policies.clone(), routes))
    }

    pub fn publish(&self) -> Result<PublishedDirectory, AuthorityError> {
        let issued_at = self.issued_at()?;
        let announcement = self.announcement()?;
        publish_directory(&announcement, &self.key_pair()?, issued_at)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteSpec {
    pub policy_id: String,
    pub interface: String,
    pub segments: Vec<RouteHopSpec>,
}

impl RouteSpec {
    pub fn to_route_announcement(&self) -> Result<RouteAnnouncement, AuthorityError> {
        self.segments
            .iter()
            .map(RouteHopSpec::to_route_elem)
            .collect::<Result<Vec<_>, _>>()
            .and_then(|elems| {
                Ok(RouteAnnouncement {
                    policy_id: domain::decode_fixed_hex::<32>("policy_id", &self.policy_id)?,
                    segment: routing::segment_from_elems(&elems),
                    interface: self.interface.clone(),
                })
            })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RouteHopSpec {
    NextHop4 { ip: String, port: u16 },
    NextHop6 { ip: String, port: u16 },
    ExitTcp4 { ip: String, port: u16 },
    ExitTcp6 { ip: String, port: u16 },
}

impl RouteHopSpec {
    fn to_route_elem(&self) -> Result<RouteElem, AuthorityError> {
        match self {
            Self::NextHop4 { ip, port } => parse_ipv4(ip).map(|addr| RouteElem::NextHop {
                addr: IpAddr::V4(addr.octets()),
                port: *port,
            }),
            Self::NextHop6 { ip, port } => parse_ipv6(ip).map(|addr| RouteElem::NextHop {
                addr: IpAddr::V6(addr.octets()),
                port: *port,
            }),
            Self::ExitTcp4 { ip, port } => parse_ipv4(ip).map(|addr| RouteElem::ExitTcp {
                addr: IpAddr::V4(addr.octets()),
                port: *port,
            }),
            Self::ExitTcp6 { ip, port } => parse_ipv6(ip).map(|addr| RouteElem::ExitTcp {
                addr: IpAddr::V6(addr.octets()),
                port: *port,
            }),
        }
    }
}

pub fn serve_once(
    listener: &TcpListener,
    published: &PublishedDirectory,
) -> Result<(), AuthorityError> {
    listener
        .accept()
        .map(|(stream, _)| stream)
        .map_err(AuthorityError::from)
        .and_then(|stream| handle_connection(stream, published))
}

pub fn serve_forever(
    listener: &TcpListener,
    published: &PublishedDirectory,
) -> Result<(), AuthorityError> {
    loop {
        let (stream, _) = listener.accept()?;
        if let Err(err) = handle_connection(stream, published) {
            eprintln!("authority: request failed: {err}");
        }
    }
}

fn handle_connection(
    mut stream: TcpStream,
    published: &PublishedDirectory,
) -> Result<(), AuthorityError> {
    let mut buf = [0u8; 4096];
    let size = stream.read(&mut buf)?;
    if size == 0 {
        return Ok(());
    }

    read_request_line(&buf[..size])
        .map(|(method, path)| dispatch_request(&method, &path, published))
        .and_then(|response| {
            write_http_response(
                &mut stream,
                response.status_code,
                response.reason,
                response.body.as_deref(),
            )
        })
}

#[derive(Debug, PartialEq, Eq)]
struct HttpResponse {
    status_code: u16,
    reason: &'static str,
    body: Option<String>,
}

fn read_request_line(buf: &[u8]) -> Result<(String, String), AuthorityError> {
    let request = String::from_utf8_lossy(buf);
    let line = request
        .lines()
        .next()
        .ok_or_else(|| AuthorityError::InvalidRequest("missing request line".into()))?;
    let mut parts = line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| AuthorityError::InvalidRequest("missing method".into()))?;
    let path = parts
        .next()
        .ok_or_else(|| AuthorityError::InvalidRequest("missing path".into()))?;
    Ok((method.into(), path.into()))
}

fn dispatch_request(method: &str, path: &str, published: &PublishedDirectory) -> HttpResponse {
    match (method, path) {
        ("GET", "/") | ("GET", "/directory") => ok_response(Some(published.body.clone())),
        ("HEAD", "/") | ("HEAD", "/directory") => ok_response(None),
        ("GET", other) | ("HEAD", other) => HttpResponse {
            status_code: 404,
            reason: "Not Found",
            body: Some(format!("unsupported path: {other}\n")),
        },
        _ => HttpResponse {
            status_code: 405,
            reason: "Method Not Allowed",
            body: Some("method not allowed\n".into()),
        },
    }
}

fn ok_response(body: Option<String>) -> HttpResponse {
    HttpResponse {
        status_code: 200,
        reason: "OK",
        body,
    }
}

fn write_http_response(
    stream: &mut TcpStream,
    status_code: u16,
    reason: &str,
    body: Option<&str>,
) -> Result<(), AuthorityError> {
    let body_bytes = body.unwrap_or("").as_bytes();
    write!(
        stream,
        "HTTP/1.1 {status_code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body_bytes.len()
    )?;
    if body.is_some() {
        stream.write_all(body_bytes)?;
    }
    stream.flush()?;
    Ok(())
}

fn default_bind_addr() -> String {
    DEFAULT_BIND_ADDR.to_string()
}

fn parse_ipv4(input: &str) -> Result<Ipv4Addr, AuthorityError> {
    input
        .parse()
        .map_err(|_| AuthorityError::InvalidRequest(format!("invalid IPv4 address: {input}")))
}

fn parse_ipv6(input: &str) -> Result<Ipv6Addr, AuthorityError> {
    input
        .parse()
        .map_err(|_| AuthorityError::InvalidRequest(format!("invalid IPv6 address: {input}")))
}

fn current_unix_timestamp() -> Result<u64, AuthorityError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|err| AuthorityError::Time(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aurora::core::policy::ProofKind;
    use aurora::policy::VerifierEntry;
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::thread;

    fn sample_policy() -> PolicyMetadata {
        PolicyMetadata {
            policy_id: fixed_policy_id(0x42),
            version: 1,
            expiry: 600,
            flags: 0,
            verifiers: vec![VerifierEntry {
                kind: ProofKind::Policy as u8,
                min_rounds: 0,
                verifier_blob: vec![0xAA, 0xBB, 0xCC],
            }],
        }
    }

    fn sample_config() -> AuthorityConfig {
        AuthorityConfig {
            bind_addr: "127.0.0.1:18080".into(),
            signature_scheme: SignatureScheme::Ed25519,
            issued_at: Some(1_700_000_000),
            signing_key_seed_hex: "11".repeat(32),
            policies: vec![sample_policy()],
            routes: vec![RouteSpec {
                policy_id: aurora::utils::encode_hex(&fixed_policy_id(0x42)),
                interface: "router-entry".into(),
                segments: vec![RouteHopSpec::ExitTcp4 {
                    ip: "127.0.0.1".into(),
                    port: 7200,
                }],
            }],
        }
    }

    #[test]
    fn config_publish_generates_signed_body() {
        let config = sample_config();
        let published = config.publish().expect("publish");
        assert_eq!(published.signature_scheme, SignatureScheme::Ed25519);
        assert_eq!(published.issued_at, 1_700_000_000);
        assert_eq!(published.public_key_hex.len(), 64);

        let public_key =
            aurora::utils::decode_hex(&published.public_key_hex).expect("public key must be hex");
        let parsed = verify_directory_json(&published.body, &public_key).expect("verify");
        assert_eq!(parsed.policies().len(), 1);
        assert_eq!(parsed.routes().len(), 1);
    }

    #[test]
    fn http_dispatch_serves_directory_body() {
        let published = PublishedDirectory {
            signature_scheme: SignatureScheme::Ed25519,
            issued_at: 1_700_000_000,
            public_key_hex: "22".repeat(32),
            body: "{\"status\":\"ok\"}".into(),
        };
        let response = dispatch_request("GET", "/directory", &published);
        assert_eq!(response.status_code, 200);
        assert_eq!(response.reason, "OK");
        assert_eq!(response.body.as_deref(), Some("{\"status\":\"ok\"}"));
    }

    #[test]
    #[ignore = "requires loopback socket permissions"]
    fn http_server_e2e_fetch_and_verify() {
        let config = AuthorityConfig {
            bind_addr: "127.0.0.1:0".into(),
            routes: vec![RouteSpec {
                policy_id: aurora::utils::encode_hex(&fixed_policy_id(0x42)),
                interface: "router-entry".into(),
                segments: vec![RouteHopSpec::NextHop4 {
                    ip: "127.0.0.1".into(),
                    port: 7102,
                }],
            }],
            ..sample_config()
        };
        let published = config.publish().expect("publish");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let handle = thread::spawn(move || serve_once(&listener, &published));

        let mut stream = TcpStream::connect(addr).expect("connect");
        stream
            .write_all(b"GET /directory HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .expect("write request");
        stream.shutdown(Shutdown::Write).expect("shutdown write");

        let mut response = String::new();
        stream.read_to_string(&mut response).expect("read response");
        let (_, body) = response
            .split_once("\r\n\r\n")
            .expect("HTTP response must contain header separator");

        let public_key =
            aurora::utils::decode_hex(&config.key_pair().expect("key pair").public_key_hex())
                .expect("public key hex");
        let parsed = verify_directory_json(body, &public_key).expect("verify body");
        assert_eq!(parsed.policies().len(), 1);
        assert_eq!(parsed.routes().len(), 1);

        handle.join().expect("join").expect("serve once");
    }
}
