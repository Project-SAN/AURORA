use alloc::vec::Vec;

use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use sha2::{Digest, Sha256, Sha384};

use crate::policy::encoder::{self, EncodeError, PolicySection};
use crate::policy::manifest::{self, PoseidonMerkleSibling, Rule, RulePackage};

const PAYLOAD_SLICE_LEN: usize = 64;
const COMM_LEN: usize = 32;
const REQ_COMM_LEN: usize = 48;
const NONCE_LEN: usize = 16;
const TAU_LEN: usize = 32;

#[derive(Clone, Debug)]
pub struct PublicInputs {
    pub policy_id: u32,
    pub h_policy: Fr,
    pub dst_ip: [u8; 16],
    pub dst_port: u16,
    pub proto_id: u8,
    pub epoch: u32,
    pub hop_index: u8,
    pub c_payload: [u8; COMM_LEN],
    pub c_token: [u8; COMM_LEN],
}

impl PublicInputs {
    pub fn to_field_elements(&self) -> Vec<Fr> {
        let mut elements = Vec::with_capacity(9);
        elements.push(Fr::from(self.policy_id as u64));
        elements.push(self.h_policy);
        elements.push(fr_from_u128(&self.dst_ip));
        elements.push(Fr::from(self.dst_port as u64));
        elements.push(Fr::from(self.proto_id as u64));
        elements.push(Fr::from(self.epoch as u64));
        elements.push(Fr::from(self.hop_index as u64));
        elements.push(fr_from_u256(&self.c_payload));
        elements.push(fr_from_u256(&self.c_token));
        elements
    }
}

#[derive(Clone, Debug)]
pub struct WitnessInputs {
    pub rid: [u8; COMM_LEN],
    pub client_nonce: [u8; NONCE_LEN],
    pub tau: [u8; TAU_LEN],
    pub payload_slice: [u8; PAYLOAD_SLICE_LEN],
    pub rule: Rule,
    pub descriptor: Fr,
    pub merkle_path: Vec<PoseidonMerkleSibling>,
    pub c_req: [u8; REQ_COMM_LEN],
}

#[derive(Clone, Debug)]
pub struct Commitments {
    pub c_payload: [u8; COMM_LEN],
    pub c_token: [u8; COMM_LEN],
    pub c_req: [u8; REQ_COMM_LEN],
}

#[derive(Clone, Debug)]
pub struct ProofMaterial {
    pub public_inputs: PublicInputs,
    pub witness: WitnessInputs,
    pub commitments: Commitments,
}

impl ProofMaterial {
    pub fn build_policy_section(&self, proof_bytes: &[u8]) -> Result<PolicySection, EncodeError> {
        encoder::section_from_proof_slice(self, proof_bytes)
    }

    pub fn public_inputs_as_fields(&self) -> Vec<Fr> {
        self.public_inputs.to_field_elements()
    }
}

#[derive(Clone, Debug)]
pub enum WitnessError {
    PayloadSliceWrongLen,
    NonceWrongLen,
    TranscriptWrongLen,
    RuleDescriptorMismatch,
}

pub struct WitnessBuilderInput {
    pub policy_id: u32,
    pub h_policy: Fr,
    pub dst_ip: [u8; 16],
    pub dst_port: u16,
    pub proto_id: u8,
    pub epoch: u32,
    pub hop_index: u8,
    pub payload_slice: [u8; PAYLOAD_SLICE_LEN],
    pub chdr_nonce: [u8; NONCE_LEN],
    pub tau: [u8; TAU_LEN],
    pub client_nonce: [u8; NONCE_LEN],
    pub tls_transcript_hash: [u8; REQ_COMM_LEN],
    pub rule_package: RulePackage,
}

pub fn build_proof_material(input: WitnessBuilderInput) -> Result<ProofMaterial, WitnessError> {
    if input.payload_slice.len() != PAYLOAD_SLICE_LEN {
        return Err(WitnessError::PayloadSliceWrongLen);
    }
    if input.chdr_nonce.len() != NONCE_LEN || input.client_nonce.len() != NONCE_LEN {
        return Err(WitnessError::NonceWrongLen);
    }
    if input.tls_transcript_hash.len() != REQ_COMM_LEN {
        return Err(WitnessError::TranscriptWrongLen);
    }

    let expected_descriptor = manifest::rule_descriptor(&input.rule_package.rule);
    if expected_descriptor != input.rule_package.descriptor {
        return Err(WitnessError::RuleDescriptorMismatch);
    }

    let c_payload = sha256_concat(&[
        &input.payload_slice,
        &input.chdr_nonce,
        &[input.hop_index],
    ]);

    let c_token = sha256(&input.tau);

    let rid = sha256_concat(&[
        &input.dst_ip,
        &input.dst_port.to_be_bytes(),
        &[input.proto_id],
        &input.epoch.to_be_bytes(),
        &input.client_nonce,
    ]);

    let c_req = sha384_concat(&[&rid, &input.tls_transcript_hash]);

    let public_inputs = PublicInputs {
        policy_id: input.policy_id,
        h_policy: input.h_policy,
        dst_ip: input.dst_ip,
        dst_port: input.dst_port,
        proto_id: input.proto_id,
        epoch: input.epoch,
        hop_index: input.hop_index,
        c_payload,
        c_token,
    };

    let witness = WitnessInputs {
        rid,
        client_nonce: input.client_nonce,
        tau: input.tau,
        payload_slice: input.payload_slice,
        rule: input.rule_package.rule,
        descriptor: input.rule_package.descriptor,
        merkle_path: input.rule_package.path,
        c_req,
    };

    let commitments = Commitments {
        c_payload,
        c_token,
        c_req,
    };

    Ok(ProofMaterial {
        public_inputs,
        witness,
        commitments,
    })
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn sha256_concat(chunks: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for chunk in chunks {
        hasher.update(chunk);
    }
    hasher.finalize().into()
}

fn sha384_concat(chunks: &[&[u8]]) -> [u8; 48] {
    let mut hasher = Sha384::new();
    for chunk in chunks {
        hasher.update(chunk);
    }
    let mut out = [0u8; 48];
    out.copy_from_slice(&hasher.finalize());
    out
}

fn fr_from_u128(bytes: &[u8; 16]) -> Fr {
    let mut wide = [0u8; 32];
    wide[16..].copy_from_slice(bytes);
    Fr::from_be_bytes_mod_order(&wide)
}

fn fr_from_u256(bytes: &[u8; 32]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::policy::manifest::{build_policy_tree, PolicyTree, RulePackage};

    #[test]
    fn build_proof_material_happy_path() {
        let rule = Rule {
            prefix: [0u8; 16],
            prefix_len: 0,
            port_start: 1000,
            port_end: 2000,
            proto_mask: 1,
            classification_tag: 42,
        };
        let tree = build_policy_tree(vec![rule.clone()]).expect("tree");
        let package = export_package(&tree);

        let input = WitnessBuilderInput {
            policy_id: 7,
            h_policy: tree.tree.root(),
            dst_ip: [1u8; 16],
            dst_port: 443,
            proto_id: 6,
            epoch: 1234,
            hop_index: 2,
            payload_slice: [9u8; PAYLOAD_SLICE_LEN],
            chdr_nonce: [2u8; NONCE_LEN],
            tau: [3u8; TAU_LEN],
            client_nonce: [4u8; NONCE_LEN],
            tls_transcript_hash: [5u8; REQ_COMM_LEN],
            rule_package: package,
        };

        let material = build_proof_material(input).expect("material");
        assert_eq!(material.public_inputs.policy_id, 7);
        assert_eq!(material.witness.rule.port_start, 1000);
        assert_eq!(material.commitments.c_payload.len(), COMM_LEN);

        let proof_bytes = [8u8; crate::policy::encoder::PROOF_LEN];
        let section = material
            .build_policy_section(&proof_bytes)
            .expect("policy section");
        assert_eq!(section.proof_bytes, proof_bytes);
    }

    fn export_package(tree: &PolicyTree) -> RulePackage {
        export_rule(tree, 0)
    }

    fn export_rule(tree: &PolicyTree, idx: usize) -> RulePackage {
        manifest::export_rule_package(tree, idx).expect("package")
    }
}
