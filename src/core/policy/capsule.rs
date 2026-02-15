use crate::types::{Error, Result};

use super::metadata::PolicyId;

pub const POLICY_CAPSULE_MAGIC: &[u8; 4] = b"ZKMB";
const HEADER_LEN: usize = 39;
const PART_HEADER_LEN: usize = 1 + 4 + 4;
pub const COMMIT_LEN: usize = 32;
pub const AUX_MAX: usize = 1024;
pub const MAX_PARTS: usize = 4;
pub const MAX_CAPSULE_LEN: usize = 4 * 1024 * 1024;
pub const POLICY_CAPSULE_VERSION: u8 = 1;

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
    pub proof: alloc::vec::Vec<u8>,
    pub commitment: [u8; COMMIT_LEN],
    pub aux: alloc::vec::Vec<u8>,
}

impl ProofPart {
    pub fn aux(&self) -> &[u8] {
        &self.aux
    }

    pub fn set_aux(&mut self, aux: &[u8]) -> Result<()> {
        self.aux.clear();
        self.aux.extend_from_slice(aux);
        Ok(())
    }
}

impl Default for ProofPart {
    fn default() -> Self {
        ProofPart {
            kind: ProofKind::Policy,
            proof: alloc::vec::Vec::new(),
            commitment: [0u8; COMMIT_LEN],
            aux: alloc::vec::Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyCapsule {
    pub policy_id: PolicyId,
    pub version: u8,
    pub part_count: u8,
    pub parts: [ProofPart; MAX_PARTS],
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    #[test]
    fn encode_decode_roundtrip() {
        let mut part0 = ProofPart {
            kind: ProofKind::KeyBinding,
            proof: vec![0xAA; 3],
            commitment: [0xBB; COMMIT_LEN],
            aux: Vec::new(),
        };
        part0.set_aux(&[0xCC; 2]).expect("aux");
        let mut part1 = ProofPart {
            kind: ProofKind::Policy,
            proof: vec![0xDD; 5],
            commitment: [0xEE; COMMIT_LEN],
            aux: Vec::new(),
        };
        part1.set_aux(&[]).expect("aux");
        let capsule = PolicyCapsule {
            policy_id: [0x11; 32],
            version: POLICY_CAPSULE_VERSION,
            part_count: 2,
            parts: [part0, part1, ProofPart::default(), ProofPart::default()],
        };
        let encoded = capsule.encode().expect("encode");
        let (decoded, consumed) = PolicyCapsule::decode(&encoded).expect("decode");
        assert_eq!(decoded, capsule);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn peel_from_buffer_strips_prefix() {
        let mut part = ProofPart {
            kind: ProofKind::Policy,
            proof: vec![1u8; 4],
            commitment: [4u8; COMMIT_LEN],
            aux: Vec::new(),
        };
        part.set_aux(&[8, 9]).expect("aux");
        let capsule = PolicyCapsule {
            policy_id: [0x22; 32],
            version: POLICY_CAPSULE_VERSION,
            part_count: 1,
            parts: [
                part,
                ProofPart::default(),
                ProofPart::default(),
                ProofPart::default(),
            ],
        };
        let mut buffer = capsule.encode().expect("encode");
        buffer.extend_from_slice(b"tail");
        let (peeled, consumed) = PolicyCapsule::decode(&buffer).expect("peel");
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
        if version != POLICY_CAPSULE_VERSION {
            return Err(Error::Length);
        }
        let _reserved = payload[37];
        let part_count = payload[38] as usize;
        if part_count > MAX_PARTS {
            return Err(Error::Length);
        }
        let mut cursor = HEADER_LEN;
        let mut parts = [
            ProofPart::default(),
            ProofPart::default(),
            ProofPart::default(),
            ProofPart::default(),
        ];
        for slot in parts.iter_mut().take(part_count) {
            if cursor + PART_HEADER_LEN > payload.len() {
                return Err(Error::Length);
            }
            let kind = ProofKind::from_u8(payload[cursor]).ok_or(Error::Length)?;
            cursor += 1;
            let proof_len = read_u32(payload, &mut cursor)? as usize;
            let aux_len = read_u32(payload, &mut cursor)? as usize;
            let total_len = cursor
                .checked_add(proof_len)
                .and_then(|v| v.checked_add(COMMIT_LEN))
                .and_then(|v| v.checked_add(aux_len))
                .ok_or(Error::Length)?;
            if total_len > payload.len() || total_len > MAX_CAPSULE_LEN {
                return Err(Error::Length);
            }
            let proof = payload[cursor..cursor + proof_len].to_vec();
            cursor += proof_len;
            let mut commitment = [0u8; COMMIT_LEN];
            commitment.copy_from_slice(&payload[cursor..cursor + COMMIT_LEN]);
            cursor += COMMIT_LEN;
            let aux = payload[cursor..cursor + aux_len].to_vec();
            cursor += aux_len;
            let part = ProofPart {
                kind,
                proof,
                commitment,
                aux,
            };
            *slot = part;
        }
        let capsule = PolicyCapsule {
            policy_id,
            version,
            part_count: part_count as u8,
            parts,
        };
        Ok((capsule, cursor))
    }

    pub fn encoded_len(&self) -> Result<usize> {
        let part_count = self.part_count.min(MAX_PARTS as u8) as usize;
        let mut total = HEADER_LEN;
        for part in self.parts[..part_count].iter() {
            total = total
                .checked_add(PART_HEADER_LEN)
                .and_then(|v| v.checked_add(part.proof.len()))
                .and_then(|v| v.checked_add(COMMIT_LEN))
                .and_then(|v| v.checked_add(part.aux.len()))
                .ok_or(Error::Length)?;
        }
        if total > MAX_CAPSULE_LEN {
            return Err(Error::Length);
        }
        Ok(total)
    }

    pub fn encode(&self) -> Result<alloc::vec::Vec<u8>> {
        let len = self.encoded_len()?;
        let mut out = alloc::vec![0u8; len];
        self.encode_into(&mut out)?;
        Ok(out)
    }

    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize> {
        let part_count = self.part_count.min(MAX_PARTS as u8) as usize;
        let needed = self.encoded_len()?;
        if out.len() < needed {
            return Err(Error::Length);
        }
        if self.version != POLICY_CAPSULE_VERSION {
            return Err(Error::Length);
        }
        let mut cursor = 0usize;
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
            let proof_len: u32 = part.proof.len().try_into().map_err(|_| Error::Length)?;
            let aux_len: u32 = part.aux.len().try_into().map_err(|_| Error::Length)?;
            out[cursor] = part.kind as u8;
            out[cursor + 1..cursor + 5].copy_from_slice(&proof_len.to_be_bytes());
            out[cursor + 5..cursor + 9].copy_from_slice(&aux_len.to_be_bytes());
            cursor += PART_HEADER_LEN;
            out[cursor..cursor + part.proof.len()].copy_from_slice(&part.proof);
            cursor += part.proof.len();
            out[cursor..cursor + COMMIT_LEN].copy_from_slice(&part.commitment);
            cursor += COMMIT_LEN;
            out[cursor..cursor + part.aux.len()].copy_from_slice(&part.aux);
            cursor += part.aux.len();
        }
        Ok(cursor)
    }

    pub fn part(&self, kind: ProofKind) -> Option<&ProofPart> {
        self.parts[..(self.part_count as usize)]
            .iter()
            .find(|part| part.kind == kind)
    }
}

fn read_u32(buf: &[u8], cursor: &mut usize) -> Result<u32> {
    if *cursor + 4 > buf.len() {
        return Err(Error::Length);
    }
    let mut tmp = [0u8; 4];
    tmp.copy_from_slice(&buf[*cursor..*cursor + 4]);
    *cursor += 4;
    Ok(u32::from_be_bytes(tmp))
}
