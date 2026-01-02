use alloc::vec::Vec;

use crate::types::{Error, Result};

use super::extensions::{decode_extensions, CapsuleExtension};
use super::metadata::PolicyId;

pub const POLICY_CAPSULE_MAGIC: &[u8; 4] = b"ZKMB";
const HEADER_LEN: usize = 39;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofKind {
    KeyBinding = 1,
    Consistency = 2,
    Policy = 3,
}

impl ProofKind {
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(ProofKind::KeyBinding),
            2 => Some(ProofKind::Consistency),
            3 => Some(ProofKind::Policy),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofPart {
    pub kind: ProofKind,
    pub proof: Vec<u8>,
    pub commitment: Vec<u8>,
    pub aux: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyCapsule {
    pub policy_id: PolicyId,
    pub version: u8,
    pub parts: Vec<ProofPart>,
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
            parts: vec![
                ProofPart {
                    kind: ProofKind::KeyBinding,
                    proof: vec![0xAA; 8],
                    commitment: vec![0xBB; 4],
                    aux: vec![0xCC; 2],
                },
                ProofPart {
                    kind: ProofKind::Policy,
                    proof: vec![0xDD; 6],
                    commitment: vec![0xEE; 2],
                    aux: vec![],
                },
            ],
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
            parts: vec![ProofPart {
                kind: ProofKind::Policy,
                proof: vec![1, 2, 3],
                commitment: vec![4, 5, 6, 7],
                aux: vec![8, 9],
            }],
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
        let part_count = payload[38] as usize;
        let mut cursor = HEADER_LEN;
        let mut parts = Vec::with_capacity(part_count);
        for _ in 0..part_count {
            if cursor + 7 > payload.len() {
                return Err(Error::Length);
            }
            let kind = ProofKind::from_u8(payload[cursor]).ok_or(Error::Length)?;
            let proof_len =
                u16::from_be_bytes([payload[cursor + 1], payload[cursor + 2]]) as usize;
            let commit_len =
                u16::from_be_bytes([payload[cursor + 3], payload[cursor + 4]]) as usize;
            let aux_len =
                u16::from_be_bytes([payload[cursor + 5], payload[cursor + 6]]) as usize;
            cursor += 7;
            let total_len = cursor + proof_len + commit_len + aux_len;
            if payload.len() < total_len {
                return Err(Error::Length);
            }
            let proof = payload[cursor..cursor + proof_len].to_vec();
            cursor += proof_len;
            let commitment = payload[cursor..cursor + commit_len].to_vec();
            cursor += commit_len;
            let aux = payload[cursor..cursor + aux_len].to_vec();
            cursor += aux_len;
            parts.push(ProofPart {
                kind,
                proof,
                commitment,
                aux,
            });
        }
        let capsule = PolicyCapsule {
            policy_id,
            version,
            parts,
        };
        Ok((capsule, cursor))
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(POLICY_CAPSULE_MAGIC);
        out.extend_from_slice(&self.policy_id);
        out.push(self.version);
        out.push(0u8);
        out.push(self.parts.len().min(u8::MAX as usize) as u8);
        for part in &self.parts {
            out.push(part.kind as u8);
            out.extend_from_slice(&(part.proof.len() as u16).to_be_bytes());
            out.extend_from_slice(&(part.commitment.len() as u16).to_be_bytes());
            out.extend_from_slice(&(part.aux.len() as u16).to_be_bytes());
            out.extend_from_slice(&part.proof);
            out.extend_from_slice(&part.commitment);
            out.extend_from_slice(&part.aux);
        }
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

    pub fn part(&self, kind: ProofKind) -> Option<&ProofPart> {
        self.parts.iter().find(|part| part.kind == kind)
    }

    pub fn extensions_for(&self, kind: ProofKind) -> Result<Option<Vec<CapsuleExtension>>> {
        let Some(part) = self.part(kind) else {
            return Ok(None);
        };
        decode_extensions(&part.aux)
    }
}
