use alloc::vec::Vec;

use crate::types::{Error, Result};

use serde::{Deserialize, Serialize};

pub type PolicyId = [u8; 32];
const HEADER_LEN: usize = 32 + 2 + 4 + 2 + 1;

pub const POLICY_FLAG_ASYNC: u16 = 0x0001;
pub const POLICY_FLAG_BATCH: u16 = 0x0002;
pub const POLICY_FLAG_PRECOMPUTE: u16 = 0x0004;
pub const POLICY_FLAG_REGEX: u16 = 0x0008;
pub const POLICY_FLAG_PCD: u16 = 0x0010;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyMetadata {
    pub policy_id: PolicyId,
    pub version: u16,
    pub expiry: u32,
    pub flags: u16,
    pub verifiers: Vec<VerifierEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierEntry {
    pub kind: u8,
    pub verifier_blob: Vec<u8>,
}

impl PolicyMetadata {
    pub fn supports_async(&self) -> bool {
        (self.flags & POLICY_FLAG_ASYNC) != 0
    }

    pub fn supports_batch(&self) -> bool {
        (self.flags & POLICY_FLAG_BATCH) != 0
    }

    pub fn supports_precompute(&self) -> bool {
        (self.flags & POLICY_FLAG_PRECOMPUTE) != 0
    }

    pub fn supports_regex(&self) -> bool {
        (self.flags & POLICY_FLAG_REGEX) != 0
    }

    pub fn supports_pcd(&self) -> bool {
        (self.flags & POLICY_FLAG_PCD) != 0
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN);
        out.extend_from_slice(&self.policy_id);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.expiry.to_be_bytes());
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.push(self.verifiers.len().min(u8::MAX as usize) as u8);
        for entry in &self.verifiers {
            out.push(entry.kind);
            out.extend_from_slice(&(entry.verifier_blob.len() as u32).to_be_bytes());
            out.extend_from_slice(&entry.verifier_blob);
        }
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

        let count = bytes[cursor] as usize;
        cursor += 1;
        let mut verifiers = Vec::with_capacity(count);
        for _ in 0..count {
            if bytes.len() < cursor + 5 {
                return Err(Error::Length);
            }
            let kind = bytes[cursor];
            let blob_len = u32::from_be_bytes([
                bytes[cursor + 1],
                bytes[cursor + 2],
                bytes[cursor + 3],
                bytes[cursor + 4],
            ]) as usize;
            cursor += 5;
            if bytes.len() < cursor + blob_len {
                return Err(Error::Length);
            }
            let verifier_blob = bytes[cursor..cursor + blob_len].to_vec();
            cursor += blob_len;
            verifiers.push(VerifierEntry {
                kind,
                verifier_blob,
            });
        }

        Ok(PolicyMetadata {
            policy_id,
            version,
            expiry,
            flags,
            verifiers,
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
            verifiers: vec![VerifierEntry {
                kind: 1,
                verifier_blob: vec![0xDE, 0xAD, 0xBE, 0xEF],
            }],
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
