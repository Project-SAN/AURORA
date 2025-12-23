use alloc::vec::Vec;

use crate::types::{Error, Result};

use serde::{Deserialize, Serialize};

pub type PolicyId = [u8; 32];
const HEADER_LEN: usize = 32 + 2 + 4 + 2 + 4;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyMetadata {
    pub policy_id: PolicyId,
    pub version: u16,
    pub expiry: u32,
    pub flags: u16,
    pub verifier_blob: Vec<u8>,
}

impl PolicyMetadata {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.verifier_blob.len());
        out.extend_from_slice(&self.policy_id);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.expiry.to_be_bytes());
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&(self.verifier_blob.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.verifier_blob);
        out
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::Length);
        }
        let mut cursor = 0usize;
        let mut policy_id = [0u8; 32];
        policy_id.copy_from_slice(&bytes[cursor..cursor + 32]);
        cursor += 32;

        let version = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]);
        cursor += 2;
        let expiry = u32::from_be_bytes([
            bytes[cursor],
            bytes[cursor + 1],
            bytes[cursor + 2],
            bytes[cursor + 3],
        ]);
        cursor += 4;

        let flags = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]);
        cursor += 2;

        let blob_len = u32::from_be_bytes([
            bytes[cursor],
            bytes[cursor + 1],
            bytes[cursor + 2],
            bytes[cursor + 3],
        ]) as usize;
        cursor += 4;
        if bytes.len() < cursor + blob_len {
            return Err(Error::Length);
        }
        let verifier_blob = bytes[cursor..cursor + blob_len].to_vec();

        Ok(PolicyMetadata {
            policy_id,
            version,
            expiry,
            flags,
            verifier_blob,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn encode_parse_roundtrip() {
        let meta = PolicyMetadata {
            policy_id: [0x44; 32],
            version: 2,
            expiry: 42,
            flags: 0xAA55,
            verifier_blob: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let bytes = meta.encode();
        let parsed = PolicyMetadata::parse(&bytes).expect("parse");
        assert_eq!(parsed, meta);
    }

    #[test]
    fn parse_rejects_short_buffer() {
        assert!(PolicyMetadata::parse(&[0u8; 3]).is_err());
    }
}
