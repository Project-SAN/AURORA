use crate::types::{Error, Result};

use super::metadata::PolicyId;

pub const POLICY_CAPSULE_MAGIC: &[u8; 4] = b"ZKMB";
const HEADER_LEN: usize = 39;
pub const PROOF_LEN: usize = 1040;
pub const COMMIT_LEN: usize = 32;
pub const AUX_MAX: usize = 1024;
pub const MAX_PARTS: usize = 4;
pub const MAX_CAPSULE_LEN: usize =
    HEADER_LEN + MAX_PARTS * (7 + PROOF_LEN + COMMIT_LEN + AUX_MAX);

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofPart {
    pub kind: ProofKind,
    pub proof: [u8; PROOF_LEN],
    pub commitment: [u8; COMMIT_LEN],
    pub aux_len: u16,
    pub aux: [u8; AUX_MAX],
}

impl ProofPart {
    pub fn aux(&self) -> &[u8] {
        &self.aux[..self.aux_len as usize]
    }

    pub fn set_aux(&mut self, aux: &[u8]) -> Result<()> {
        if aux.len() > AUX_MAX {
            return Err(Error::Length);
        }
        self.aux_len = aux.len() as u16;
        self.aux[..aux.len()].copy_from_slice(aux);
        Ok(())
    }
}

impl Default for ProofPart {
    fn default() -> Self {
        ProofPart {
            kind: ProofKind::Policy,
            proof: [0u8; PROOF_LEN],
            commitment: [0u8; COMMIT_LEN],
            aux_len: 0,
            aux: [0u8; AUX_MAX],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyCapsule {
    pub policy_id: PolicyId,
    pub version: u8,
    pub part_count: u8,
    pub parts: [ProofPart; MAX_PARTS],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let mut part0 = ProofPart {
            kind: ProofKind::KeyBinding,
            proof: [0xAA; PROOF_LEN],
            commitment: [0xBB; COMMIT_LEN],
            aux_len: 0,
            aux: [0u8; AUX_MAX],
        };
        part0.set_aux(&[0xCC; 2]).expect("aux");
        let mut part1 = ProofPart {
            kind: ProofKind::Policy,
            proof: [0xDD; PROOF_LEN],
            commitment: [0xEE; COMMIT_LEN],
            aux_len: 0,
            aux: [0u8; AUX_MAX],
        };
        part1.set_aux(&[]).expect("aux");
        let capsule = PolicyCapsule {
            policy_id: [0x11; 32],
            version: 3,
            part_count: 2,
            parts: [part0, part1, ProofPart::default(), ProofPart::default()],
        };
        let mut encoded = [0u8; MAX_CAPSULE_LEN];
        let encoded_len = capsule.encode_into(&mut encoded).expect("encode");
        let (decoded, consumed) =
            PolicyCapsule::decode(&encoded[..encoded_len]).expect("decode");
        assert_eq!(decoded, capsule);
        assert_eq!(consumed, encoded_len);
    }

    #[test]
    fn peel_from_buffer_strips_prefix() {
        let mut part = ProofPart {
            kind: ProofKind::Policy,
            proof: [1u8; PROOF_LEN],
            commitment: [4u8; COMMIT_LEN],
            aux_len: 0,
            aux: [0u8; AUX_MAX],
        };
        part.set_aux(&[8, 9]).expect("aux");
        let capsule = PolicyCapsule {
            policy_id: [0x22; 32],
            version: 1,
            part_count: 1,
            parts: [part, ProofPart::default(), ProofPart::default(), ProofPart::default()],
        };
        let mut buffer = [0u8; MAX_CAPSULE_LEN + 4];
        let cap_len = capsule.encode_into(&mut buffer[..MAX_CAPSULE_LEN]).expect("encode");
        buffer[cap_len..cap_len + 4].copy_from_slice(b"tail");
        let (peeled, consumed) = PolicyCapsule::decode(&buffer[..cap_len + 4]).expect("peel");
        assert_eq!(peeled, capsule);
        assert_eq!(&buffer[consumed..consumed + 4], b"tail");
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
        if part_count > MAX_PARTS {
            return Err(Error::Length);
        }
        let mut cursor = HEADER_LEN;
        let mut parts = [ProofPart::default(), ProofPart::default(), ProofPart::default(), ProofPart::default()];
        for idx in 0..part_count {
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
            if proof_len != PROOF_LEN || commit_len != COMMIT_LEN || aux_len > AUX_MAX {
                return Err(Error::Length);
            }
            let mut part = ProofPart {
                kind,
                proof: [0u8; PROOF_LEN],
                commitment: [0u8; COMMIT_LEN],
                aux_len: aux_len as u16,
                aux: [0u8; AUX_MAX],
            };
            part.proof.copy_from_slice(&payload[cursor..cursor + PROOF_LEN]);
            cursor += PROOF_LEN;
            part.commitment
                .copy_from_slice(&payload[cursor..cursor + COMMIT_LEN]);
            cursor += COMMIT_LEN;
            part.aux[..aux_len].copy_from_slice(&payload[cursor..cursor + aux_len]);
            cursor += aux_len;
            parts[idx] = part;
        }
        let capsule = PolicyCapsule {
            policy_id,
            version,
            part_count: part_count as u8,
            parts,
        };
        Ok((capsule, cursor))
    }

    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize> {
        let part_count = self.part_count.min(MAX_PARTS as u8) as usize;
        let mut cursor = 0usize;
        if out.len() < HEADER_LEN {
            return Err(Error::Length);
        }
        out[cursor..cursor + 4].copy_from_slice(POLICY_CAPSULE_MAGIC);
        cursor += 4;
        out[cursor..cursor + 32].copy_from_slice(&self.policy_id);
        cursor += 32;
        out[cursor] = self.version;
        cursor += 1;
        out[cursor] = 0u8;
        cursor += 1;
        out[cursor] = part_count as u8;
        cursor += 1;
        for part in self.parts[..part_count].iter() {
            let aux_len = part.aux_len as usize;
            if aux_len > AUX_MAX {
                return Err(Error::Length);
            }
            let needed = cursor + 7 + PROOF_LEN + COMMIT_LEN + aux_len;
            if needed > out.len() {
                return Err(Error::Length);
            }
            out[cursor] = part.kind as u8;
            out[cursor + 1..cursor + 3].copy_from_slice(&(PROOF_LEN as u16).to_be_bytes());
            out[cursor + 3..cursor + 5].copy_from_slice(&(COMMIT_LEN as u16).to_be_bytes());
            out[cursor + 5..cursor + 7].copy_from_slice(&(aux_len as u16).to_be_bytes());
            cursor += 7;
            out[cursor..cursor + PROOF_LEN].copy_from_slice(&part.proof);
            cursor += PROOF_LEN;
            out[cursor..cursor + COMMIT_LEN].copy_from_slice(&part.commitment);
            cursor += COMMIT_LEN;
            out[cursor..cursor + aux_len].copy_from_slice(&part.aux[..aux_len]);
            cursor += aux_len;
        }
        Ok(cursor)
    }

    pub fn part(&self, kind: ProofKind) -> Option<&ProofPart> {
        self.parts[..(self.part_count as usize)]
            .iter()
            .find(|part| part.kind == kind)
    }
}
