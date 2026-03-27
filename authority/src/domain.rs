use aurora::policy::{PolicyId, PolicyMetadata};
use aurora::setup::directory::{
    from_signed_json, public_key_from_seed, to_signed_json, DirectoryAnnouncement,
    RouteAnnouncement,
};
use aurora::types::Error as AuroraError;
use aurora::utils::{decode_hex, encode_hex};
use serde::{Deserialize, Serialize};
use std::fmt;

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
        Self {
            scheme: SignatureScheme::Ed25519,
            public_key: public_key_from_seed(&seed),
            seed,
        }
    }

    pub fn from_seed_hex(seed_hex: &str) -> Result<Self, AuthorityError> {
        decode_fixed_hex::<32>("signing_key_seed_hex", seed_hex).map(Self::from_seed)
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishedDirectory {
    pub signature_scheme: SignatureScheme,
    pub issued_at: u64,
    pub public_key_hex: String,
    pub body: String,
}

pub fn announcement(
    policies: impl IntoIterator<Item = PolicyMetadata>,
    routes: impl IntoIterator<Item = RouteAnnouncement>,
) -> DirectoryAnnouncement {
    let mut announcement = DirectoryAnnouncement::new();
    policies
        .into_iter()
        .for_each(|policy| announcement.push_policy(policy));
    routes
        .into_iter()
        .for_each(|route| announcement.push_route(route));
    announcement
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

pub fn publish_directory(
    announcement: &DirectoryAnnouncement,
    key_pair: &AuthorityKeyPair,
    issued_at: u64,
) -> Result<PublishedDirectory, AuthorityError> {
    Ok(PublishedDirectory {
        signature_scheme: key_pair.signature_scheme(),
        issued_at,
        public_key_hex: key_pair.public_key_hex(),
        body: sign_directory_json(announcement, key_pair, issued_at)?,
    })
}

pub fn decode_fixed_hex<const N: usize>(
    field: &'static str,
    value: &str,
) -> Result<[u8; N], AuthorityError> {
    let bytes = decode_hex(value).map_err(|err| AuthorityError::InvalidHex(err.to_string()))?;
    if bytes.len() != N {
        return Err(AuthorityError::InvalidLength {
            field,
            expected: N,
            actual: bytes.len(),
        });
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn fixed_policy_id(byte: u8) -> PolicyId {
    [byte; 32]
}

#[cfg(test)]
mod tests {
    use super::*;
    use aurora::core::policy::ProofKind;
    use aurora::policy::VerifierEntry;
    use aurora::routing::{self, IpAddr, RouteElem};

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
    fn publishes_and_verifies_directory() {
        let key_pair = AuthorityKeyPair::from_seed([0x11; 32]);
        let announcement = announcement(
            vec![sample_policy()],
            vec![RouteAnnouncement {
                policy_id: fixed_policy_id(0x42),
                segment: routing::segment_from_elems(&[RouteElem::NextHop {
                    addr: IpAddr::V4([127, 0, 0, 1]),
                    port: 7102,
                }]),
                interface: "router-entry".into(),
            }],
        );

        let published = publish_directory(&announcement, &key_pair, 1_700_000_000).expect("sign");
        let parsed = verify_directory_json(&published.body, key_pair.public_key()).expect("verify");
        assert_eq!(published.signature_scheme, SignatureScheme::Ed25519);
        assert_eq!(published.issued_at, 1_700_000_000);
        assert_eq!(parsed.policies().len(), 1);
        assert_eq!(parsed.routes().len(), 1);
        assert_eq!(parsed.policies()[0], sample_policy());
    }
}
