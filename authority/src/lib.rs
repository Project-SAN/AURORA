use aurora::policy::{PolicyId, PolicyMetadata};
use aurora::routing::{self, IpAddr, RouteElem};
use aurora::setup::directory::{
    from_signed_json, public_key_from_seed, to_signed_json, DirectoryAnnouncement,
    RouteAnnouncement,
};
use aurora::types::Error as AuroraError;
use aurora::utils::{decode_hex, encode_hex};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, TcpListener, TcpStream};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_BIND_ADDR: &str = "127.0.0.1:8080";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureScheme {
    #[default]
    Ed25519,
}

impl SignatureScheme {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
        }
    }
}

impl fmt::Display for SignatureScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthorityError {
    Aurora(AuroraError),
    Io(String),
    Json(String),
    InvalidHex(String),
    InvalidLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    InvalidRequest(String),
    Time(String),
}

impl fmt::Display for AuthorityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aurora(err) => write!(f, "aurora error: {err:?}"),
            Self::Io(err) => write!(f, "io error: {err}"),
            Self::Json(err) => write!(f, "json error: {err}"),
            Self::InvalidHex(err) => write!(f, "invalid hex: {err}"),
            Self::InvalidLength {
                field,
                expected,
                actual,
            } => write!(
                f,
                "invalid length for {field}: expected {expected} bytes, got {actual}"
            ),
            Self::InvalidRequest(err) => write!(f, "invalid request: {err}"),
            Self::Time(err) => write!(f, "time error: {err}"),
        }
    }
}

impl std::error::Error for AuthorityError {}

impl From<AuroraError> for AuthorityError {
    fn from(value: AuroraError) -> Self {
        Self::Aurora(value)
    }
}

impl From<std::io::Error> for AuthorityError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

impl From<serde_json::Error> for AuthorityError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value.to_string())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityKeyPair {
    scheme: SignatureScheme,
    seed: [u8; 32],
    public_key: [u8; 32],
}

impl AuthorityKeyPair {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let public_key = public_key_from_seed(&seed);
        Self {
            scheme: SignatureScheme::Ed25519,
            seed,
            public_key,
        }
    }

    pub fn from_seed_hex(seed_hex: &str) -> Result<Self, AuthorityError> {
        let seed = decode_fixed_hex_32("signing_key_seed_hex", seed_hex)?;
        Ok(Self::from_seed(seed))
    }

    pub const fn signature_scheme(&self) -> SignatureScheme {
        self.scheme
    }

    pub const fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    pub fn public_key_hex(&self) -> String {
        encode_hex(&self.public_key)
    }
}

pub struct PolicyAuthority {
    key_pair: AuthorityKeyPair,
    announcement: DirectoryAnnouncement,
}

impl PolicyAuthority {
    pub fn new(key_pair: AuthorityKeyPair) -> Self {
        Self {
            key_pair,
            announcement: DirectoryAnnouncement::new(),
        }
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self::new(AuthorityKeyPair::from_seed(seed))
    }

    pub fn key_pair(&self) -> &AuthorityKeyPair {
        &self.key_pair
    }

    pub fn announcement(&self) -> &DirectoryAnnouncement {
        &self.announcement
    }

    pub fn add_policy(&mut self, policy: PolicyMetadata) {
        self.announcement.push_policy(policy);
    }

    pub fn add_route(&mut self, route: RouteAnnouncement) {
        self.announcement.push_route(route);
    }

    pub fn sign_json(&self, issued_at: u64) -> Result<String, AuthorityError> {
        sign_directory_json(&self.announcement, &self.key_pair, issued_at)
    }

    pub fn verify_json(&self, body: &str) -> Result<DirectoryAnnouncement, AuthorityError> {
        verify_directory_json(body, self.key_pair.public_key())
    }
}

pub fn sign_directory_json(
    announcement: &DirectoryAnnouncement,
    key_pair: &AuthorityKeyPair,
    issued_at: u64,
) -> Result<String, AuthorityError> {
    match key_pair.signature_scheme() {
        SignatureScheme::Ed25519 => Ok(to_signed_json(announcement, key_pair.seed(), issued_at)?),
    }
}

pub fn verify_directory_json(
    body: &str,
    public_key: &[u8],
) -> Result<DirectoryAnnouncement, AuthorityError> {
    Ok(from_signed_json(body, public_key)?)
}

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
        match self.issued_at {
            Some(value) => Ok(value),
            None => current_unix_timestamp(),
        }
    }

    pub fn build_authority(&self) -> Result<PolicyAuthority, AuthorityError> {
        let mut authority = PolicyAuthority::new(self.key_pair()?);
        for policy in &self.policies {
            authority.add_policy(policy.clone());
        }
        for route in &self.routes {
            authority.add_route(route.to_route_announcement()?);
        }
        Ok(authority)
    }

    pub fn publish(&self) -> Result<PublishedDirectory, AuthorityError> {
        let authority = self.build_authority()?;
        let issued_at = self.issued_at()?;
        let body = authority.sign_json(issued_at)?;
        let public_key_hex = authority.key_pair().public_key_hex();
        Ok(PublishedDirectory {
            bind_addr: self.bind_addr.clone(),
            signature_scheme: self.signature_scheme,
            issued_at,
            public_key_hex,
            body,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishedDirectory {
    pub bind_addr: String,
    pub signature_scheme: SignatureScheme,
    pub issued_at: u64,
    pub public_key_hex: String,
    pub body: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteSpec {
    pub policy_id: String,
    #[serde(default)]
    pub interface: Option<String>,
    pub segments: Vec<RouteHopSpec>,
}

impl RouteSpec {
    pub fn to_route_announcement(&self) -> Result<RouteAnnouncement, AuthorityError> {
        let policy_id = decode_fixed_hex_32("policy_id", &self.policy_id)?;
        let elems = self
            .segments
            .iter()
            .map(RouteHopSpec::to_route_elem)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(RouteAnnouncement {
            policy_id,
            segment: routing::segment_from_elems(&elems),
            interface: self.interface.clone(),
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
            Self::NextHop4 { ip, port } => Ok(RouteElem::NextHop {
                addr: IpAddr::V4(parse_ipv4(ip)?.octets()),
                port: *port,
            }),
            Self::NextHop6 { ip, port } => Ok(RouteElem::NextHop {
                addr: IpAddr::V6(parse_ipv6(ip)?.octets()),
                port: *port,
            }),
            Self::ExitTcp4 { ip, port } => Ok(RouteElem::ExitTcp {
                addr: IpAddr::V4(parse_ipv4(ip)?.octets()),
                port: *port,
            }),
            Self::ExitTcp6 { ip, port } => Ok(RouteElem::ExitTcp {
                addr: IpAddr::V6(parse_ipv6(ip)?.octets()),
                port: *port,
            }),
        }
    }
}

pub fn serve_once(
    listener: &TcpListener,
    published: &PublishedDirectory,
) -> Result<(), AuthorityError> {
    let (stream, _) = listener.accept()?;
    handle_connection(stream, published)
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

    let request = String::from_utf8_lossy(&buf[..size]);
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
    let response = dispatch_request(method, path, published);
    write_http_response(
        &mut stream,
        response.status_code,
        response.reason,
        response.body.as_deref(),
    )
}

#[derive(Debug, PartialEq, Eq)]
struct HttpResponse {
    status_code: u16,
    reason: &'static str,
    body: Option<String>,
}

fn dispatch_request(method: &str, path: &str, published: &PublishedDirectory) -> HttpResponse {
    match (method, path) {
        ("GET", "/") | ("GET", "/directory") => HttpResponse {
            status_code: 200,
            reason: "OK",
            body: Some(published.body.clone()),
        },
        ("HEAD", "/") | ("HEAD", "/directory") => HttpResponse {
            status_code: 200,
            reason: "OK",
            body: None,
        },
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

fn write_http_response(
    stream: &mut TcpStream,
    status_code: u16,
    reason: &str,
    body: Option<&str>,
) -> Result<(), AuthorityError> {
    let body_bytes = body.unwrap_or("").as_bytes();
    let content_length = body_bytes.len();
    write!(
        stream,
        "HTTP/1.1 {status_code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {content_length}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"
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

fn decode_fixed_hex_32(field: &'static str, value: &str) -> Result<[u8; 32], AuthorityError> {
    let bytes = decode_hex(value).map_err(|err| AuthorityError::InvalidHex(err.to_string()))?;
    if bytes.len() != 32 {
        return Err(AuthorityError::InvalidLength {
            field,
            expected: 32,
            actual: bytes.len(),
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
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

pub fn fixed_policy_id(byte: u8) -> PolicyId {
    [byte; 32]
}

#[cfg(test)]
mod tests {
    use super::*;
    use aurora::core::policy::ProofKind;
    use aurora::policy::VerifierEntry;

    fn sample_policy() -> PolicyMetadata {
        PolicyMetadata {
            policy_id: fixed_policy_id(0x42),
            version: 1,
            expiry: 600,
            flags: 0,
            verifiers: vec![VerifierEntry {
                kind: ProofKind::Policy as u8,
                verifier_blob: vec![0xAA, 0xBB, 0xCC],
            }],
        }
    }

    #[test]
    fn authority_signs_and_verifies_directory() {
        let mut authority = PolicyAuthority::from_seed([0x11; 32]);
        authority.add_policy(sample_policy());
        authority.add_route(RouteAnnouncement {
            policy_id: fixed_policy_id(0x42),
            segment: routing::segment_from_elems(&[RouteElem::NextHop {
                addr: IpAddr::V4([127, 0, 0, 1]),
                port: 7102,
            }]),
            interface: Some("router-entry".into()),
        });

        let signed = authority.sign_json(1_700_000_000).expect("signed");
        let parsed = authority.verify_json(&signed).expect("verified");
        assert_eq!(parsed.policies().len(), 1);
        assert_eq!(parsed.routes().len(), 1);
        assert_eq!(parsed.policies()[0], sample_policy());
    }

    #[test]
    fn config_publish_generates_signed_body() {
        let config = AuthorityConfig {
            bind_addr: "127.0.0.1:18080".into(),
            signature_scheme: SignatureScheme::Ed25519,
            issued_at: Some(1_700_000_000),
            signing_key_seed_hex: "11".repeat(32),
            policies: vec![sample_policy()],
            routes: vec![RouteSpec {
                policy_id: encode_hex(&fixed_policy_id(0x42)),
                interface: Some("router-entry".into()),
                segments: vec![RouteHopSpec::ExitTcp4 {
                    ip: "127.0.0.1".into(),
                    port: 7200,
                }],
            }],
        };

        let published = config.publish().expect("publish");
        assert_eq!(published.bind_addr, "127.0.0.1:18080");
        assert_eq!(published.signature_scheme, SignatureScheme::Ed25519);
        assert_eq!(published.issued_at, 1_700_000_000);
        assert_eq!(published.public_key_hex.len(), 64);

        let public_key =
            decode_hex(&published.public_key_hex).expect("published public key must be hex");
        let parsed = verify_directory_json(&published.body, &public_key).expect("verify");
        assert_eq!(parsed.policies().len(), 1);
        assert_eq!(parsed.routes().len(), 1);
    }

    #[test]
    fn http_dispatch_serves_directory_body() {
        let published = PublishedDirectory {
            bind_addr: "127.0.0.1:0".into(),
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
}
