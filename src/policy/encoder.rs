use alloc::vec::Vec;
use core::convert::TryInto;

use crate::policy::witness::ProofMaterial;

pub const PROOF_LEN: usize = 192;
const POLICY_FIXED_LEN: usize = 1 + 4 + 4 + 1 + 32 + 32 + 32 + PROOF_LEN;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicySection {
    pub proof_type: u8,
    pub policy_id: u32,
    pub epoch: u32,
    pub hop_index: u8,
    pub c_payload: [u8; 32],
    pub c_token: [u8; 32],
    pub c_req: [u8; 32],
    pub proof_bytes: [u8; PROOF_LEN],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EncodeError {
    Length,
    InvalidProofType,
}

impl PolicySection {
    pub fn new(
        proof_type: u8,
        policy_id: u32,
        epoch: u32,
        hop_index: u8,
        c_payload: [u8; 32],
        c_token: [u8; 32],
        c_req: [u8; 32],
        proof_bytes: [u8; PROOF_LEN],
    ) -> Self {
        Self {
            proof_type,
            policy_id,
            epoch,
            hop_index,
            c_payload,
            c_token,
            c_req,
            proof_bytes,
        }
    }

    pub fn from_material(material: &ProofMaterial, proof_bytes: [u8; PROOF_LEN]) -> Self {
        Self {
            proof_type: 0x01,
            policy_id: material.public_inputs.policy_id,
            epoch: material.public_inputs.epoch,
            hop_index: material.public_inputs.hop_index,
            c_payload: material.commitments.c_payload,
            c_token: material.commitments.c_token,
            c_req: material.commitments.c_req,
            proof_bytes,
        }
    }

    pub fn encoded_len(&self) -> usize {
        POLICY_FIXED_LEN + 2 // plus policy_len field
    }
}

pub fn encode(section: &PolicySection) -> Vec<u8> {
    let mut buf = Vec::with_capacity(section.encoded_len());
    buf.extend_from_slice(&(POLICY_FIXED_LEN as u16).to_be_bytes());
    buf.push(section.proof_type);
    buf.extend_from_slice(&section.policy_id.to_be_bytes());
    buf.extend_from_slice(&section.epoch.to_be_bytes());
    buf.push(section.hop_index);
    buf.extend_from_slice(&section.c_payload);
    buf.extend_from_slice(&section.c_token);
    buf.extend_from_slice(&section.c_req);
    buf.extend_from_slice(&section.proof_bytes);
    buf
}

pub fn section_from_proof_slice(
    material: &ProofMaterial,
    proof_bytes: &[u8],
) -> Result<PolicySection, EncodeError> {
    if proof_bytes.len() != PROOF_LEN {
        return Err(EncodeError::Length);
    }
    let mut arr = [0u8; PROOF_LEN];
    arr.copy_from_slice(proof_bytes);
    Ok(PolicySection::from_material(material, arr))
}

pub fn decode(bytes: &[u8]) -> Result<PolicySection, EncodeError> {
    if bytes.len() < 2 {
        return Err(EncodeError::Length);
    }
    let policy_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
    if policy_len + 2 != bytes.len() {
        return Err(EncodeError::Length);
    }
    if policy_len < POLICY_FIXED_LEN {
        return Err(EncodeError::Length);
    }

    let mut offset = 2;
    let proof_type = bytes[offset];
    offset += 1;
    if proof_type != 0x01 {
        return Err(EncodeError::InvalidProofType);
    }

    let policy_id = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap());
    offset += 4;
    let epoch = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap());
    offset += 4;
    let hop_index = bytes[offset];
    offset += 1;

    let mut c_payload = [0u8; 32];
    c_payload.copy_from_slice(&bytes[offset..offset + 32]);
    offset += 32;
    let mut c_token = [0u8; 32];
    c_token.copy_from_slice(&bytes[offset..offset + 32]);
    offset += 32;
    let mut c_req = [0u8; 32];
    c_req.copy_from_slice(&bytes[offset..offset + 32]);
    offset += 32;
    let mut proof_bytes = [0u8; PROOF_LEN];
    proof_bytes.copy_from_slice(&bytes[offset..offset + PROOF_LEN]);
    // skip any extension fields for forward compatibility

    Ok(PolicySection {
        proof_type,
        policy_id,
        epoch,
        hop_index,
        c_payload,
        c_token,
        c_req,
        proof_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use crate::policy::manifest::{build_policy_tree, Rule};
    use crate::policy::witness::{build_proof_material, WitnessBuilderInput};

    #[test]
    fn encode_decode_roundtrip() {
        let rule = Rule {
            prefix: [0u8; 16],
            prefix_len: 0,
            port_start: 80,
            port_end: 80,
            proto_mask: 1,
            classification_tag: 7,
        };
        let tree = build_policy_tree(vec![rule.clone()]).unwrap();
        let rule_package = crate::policy::manifest::export_rule_package(&tree, 0).unwrap();
        let input = WitnessBuilderInput {
            policy_id: 1,
            h_policy: tree.tree.root(),
            dst_ip: [0u8; 16],
            dst_port: 80,
            proto_id: 6,
            epoch: 123,
            hop_index: 0,
            payload_slice: [1u8; 64],
            chdr_nonce: [2u8; 16],
            tau: [3u8; 32],
            client_nonce: [4u8; 16],
            tls_transcript_hash: [5u8; 48],
            rule_package,
        };
        let material = build_proof_material(input).unwrap();
        let proof_bytes = [7u8; PROOF_LEN];
        let section = PolicySection::from_material(&material, proof_bytes);
        let encoded = encode(&section);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.policy_id, section.policy_id);
        assert_eq!(decoded.c_payload, section.c_payload);
        assert_eq!(decoded.c_req, section.c_req);
    }
}
