use crate::policy::{PolicyMetadata, decode_metadata_tlv, encode_metadata_tlv};
use crate::types::{Error, Result};
use alloc::string::String;
use alloc::{vec, vec::Vec};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub struct DirectoryAnnouncement {
    policy_entries: Vec<PolicyMetadata>,
}

impl DirectoryAnnouncement {
    pub fn new() -> Self {
        Self {
            policy_entries: Vec::new(),
        }
    }

    pub fn with_policy(meta: PolicyMetadata) -> Self {
        Self {
            policy_entries: vec![meta],
        }
    }

    pub fn push_policy(&mut self, meta: PolicyMetadata) {
        self.policy_entries.push(meta);
    }

    pub fn policies(&self) -> &[PolicyMetadata] {
        &self.policy_entries
    }

    pub fn to_tlvs(&self) -> Vec<Vec<u8>> {
        self.policy_entries
            .iter()
            .map(encode_metadata_tlv)
            .collect()
    }

    pub fn from_tlvs(tlvs: &[Vec<u8>]) -> Result<Self> {
        let mut metas = Vec::new();
        for tlv in tlvs {
            if tlv.first().copied() == Some(crate::policy::POLICY_METADATA_TLV) {
                metas.push(decode_metadata_tlv(tlv)?);
            }
        }
        Ok(Self {
            policy_entries: metas,
        })
    }
}

impl Default for DirectoryAnnouncement {
    fn default() -> Self {
        Self::new()
    }
}

pub fn apply_to_source_state(
    state: &mut crate::setup::SourceSetupState,
    directory: &DirectoryAnnouncement,
) {
    for policy in &directory.policy_entries {
        state.attach_policy_metadata(policy);
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct DirectoryMessage {
    version: u8,
    issued_at: u64,
    policies: Vec<PolicyMetadata>,
    signature: String,
}

pub fn to_signed_json(
    announcement: &DirectoryAnnouncement,
    secret: &[u8],
    issued_at: u64,
) -> Result<String> {
    let unsigned = DirectoryMessage {
        version: 1,
        issued_at,
        policies: announcement.policy_entries.clone(),
        signature: String::new(),
    };
    let serialized = serde_json::to_string(&unsigned).map_err(|_| Error::Crypto)?;
    let signature = hex_encode(&compute_hmac(secret, serialized.as_bytes()));
    let signed = DirectoryMessage {
        signature,
        ..unsigned
    };
    serde_json::to_string(&signed).map_err(|_| Error::Crypto)
}

pub fn from_signed_json(body: &str, secret: &[u8]) -> Result<DirectoryAnnouncement> {
    let signed: DirectoryMessage = serde_json::from_str(body).map_err(|_| Error::Crypto)?;
    let expected_sig = signed.signature.clone();
    let unsigned = DirectoryMessage {
        signature: String::new(),
        ..signed.clone()
    };
    let serialized = serde_json::to_string(&unsigned).map_err(|_| Error::Crypto)?;
    if !verify_hmac(secret, serialized.as_bytes(), &expected_sig) {
        return Err(Error::Crypto);
    }
    Ok(DirectoryAnnouncement {
        policy_entries: signed.policies,
    })
}

fn compute_hmac(secret: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn verify_hmac(secret: &[u8], data: &[u8], signature: &str) -> bool {
    if let Ok(expected) = hex_decode(signature) {
        if let Ok(mut mac) = HmacSha256::new_from_slice(secret) {
            mac.update(data);
            return mac.verify_slice(&expected).is_ok();
        }
    }
    false
}

fn hex_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(TABLE[(b >> 4) as usize] as char);
        out.push(TABLE[(b & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(input: &str) -> Result<Vec<u8>> {
    if input.len() % 2 != 0 {
        return Err(Error::Length);
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    let mut chars = input.chars();
    while let Some(high) = chars.next() {
        let low = chars.next().ok_or(Error::Length)?;
        let h = decode_nibble(high)?;
        let l = decode_nibble(low)?;
        out.push((h << 4) | l);
    }
    Ok(out)
}

fn decode_nibble(c: char) -> Result<u8> {
    match c {
        '0'..='9' => Ok((c as u8) - b'0'),
        'a'..='f' => Ok((c as u8) - b'a' + 10),
        'A'..='F' => Ok((c as u8) - b'A' + 10),
        _ => Err(Error::Crypto),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn roundtrip_directory_tlvs() {
        let meta = PolicyMetadata {
            policy_id: [0xAA; 32],
            version: 1,
            expiry: 123,
            flags: 0,
            verifier_blob: vec![0x10, 0x20],
        };
        let directory = DirectoryAnnouncement::with_policy(meta.clone());
        let tlvs = directory.to_tlvs();
        assert_eq!(tlvs.len(), 1);
        let parsed = DirectoryAnnouncement::from_tlvs(&tlvs).expect("directory");
        assert_eq!(parsed.policies().len(), 1);
        assert_eq!(parsed.policies()[0], meta);
    }

    #[test]
    fn announcement_signed_roundtrip() {
        let meta = PolicyMetadata {
            policy_id: [0x01; 32],
            version: 1,
            expiry: 99,
            flags: 0,
            verifier_blob: vec![0xAA],
        };
        let directory = DirectoryAnnouncement::with_policy(meta.clone());
        let secret = b"directory-shared-secret";
        let body = to_signed_json(&directory, secret, 1234).expect("signed json");
        let parsed = from_signed_json(&body, secret).expect("verify");
        assert_eq!(parsed.policies()[0], meta);
        assert!(from_signed_json(&body, b"wrong").is_err());
    }
}
