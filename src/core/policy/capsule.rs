use alloc::vec::Vec;

use crate::types::{Error, Result};

use super::metadata::PolicyId;

pub const POLICY_CAPSULE_MAGIC: &[u8; 4] = b"ZKMB";
const HEADER_LEN: usize = 44;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyCapsule {
    pub policy_id: PolicyId,
    pub version: u8,
    pub proof: Vec<u8>,
    pub commitment: Vec<u8>,
    pub aux: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn encode_decode_roundtrip() {
        let capsule = PolicyCapsule {
            policy_id: [0x11; 32],
            version: 3,
            proof: vec![0xAA; 8],
            commitment: vec![0xBB; 4],
            aux: vec![0xCC; 2],
        };
        let encoded = capsule.encode();
        let (decoded, consumed) = PolicyCapsule::decode(&encoded).expect("decode");
        assert_eq!(decoded, capsule);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn peel_from_buffer_strips_prefix() {
        let capsule = PolicyCapsule {
            policy_id: [0x22; 32],
            version: 1,
            proof: vec![1, 2, 3],
            commitment: vec![4, 5, 6, 7],
            aux: vec![8, 9],
        };
        let mut buffer = capsule.encode();
        buffer.extend_from_slice(b"tail");
        let peeled = PolicyCapsule::peel_from(&mut buffer).expect("peel");
        assert_eq!(peeled, capsule);
        assert_eq!(buffer.as_slice(), b"tail");
    }
}

impl PolicyCapsule {
    pub fn decode(payload: &[u8]) -> Result<(Self, usize)> {
        if payload.len() < HEADER_LEN {
            return Err(Error::Length);
        }
        if &payload[..4] != POLICY_CAPSULE_MAGIC {
            return Err(Error::Length);
        }
        let mut policy_id = [0u8; 32];
        policy_id.copy_from_slice(&payload[4..36]);
        let version = payload[36];
        let _reserved = payload[37];
        let proof_len = u16::from_be_bytes([payload[38], payload[39]]) as usize;
        let commit_len = u16::from_be_bytes([payload[40], payload[41]]) as usize;
        let aux_len = u16::from_be_bytes([payload[42], payload[43]]) as usize;
        let total_len = HEADER_LEN + proof_len + commit_len + aux_len;
        if payload.len() < total_len {
            return Err(Error::Length);
        }
        let mut cursor = HEADER_LEN;
        let proof = payload[cursor..cursor + proof_len].to_vec();
        cursor += proof_len;
        let commitment = payload[cursor..cursor + commit_len].to_vec();
        cursor += commit_len;
        let aux = payload[cursor..cursor + aux_len].to_vec();
        cursor += aux_len;
        let capsule = PolicyCapsule {
            policy_id,
            version,
            proof,
            commitment,
            aux,
        };
        Ok((capsule, cursor))
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            HEADER_LEN + self.proof.len() + self.commitment.len() + self.aux.len(),
        );
        out.extend_from_slice(POLICY_CAPSULE_MAGIC);
        out.extend_from_slice(&self.policy_id);
        out.push(self.version);
        out.push(0u8);
        out.extend_from_slice(&(self.proof.len() as u16).to_be_bytes());
        out.extend_from_slice(&(self.commitment.len() as u16).to_be_bytes());
        out.extend_from_slice(&(self.aux.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.proof);
        out.extend_from_slice(&self.commitment);
        out.extend_from_slice(&self.aux);
        out
    }

    pub fn peel_from(buffer: &mut Vec<u8>) -> Result<Self> {
        let (capsule, consumed) = Self::decode(buffer.as_slice())?;
        buffer.drain(0..consumed);
        Ok(capsule)
    }

    pub fn prepend_to(&self, payload: &mut Vec<u8>) {
        let mut encoded = self.encode();
        encoded.extend_from_slice(payload);
        payload.clear();
        payload.extend_from_slice(&encoded);
    }
}
