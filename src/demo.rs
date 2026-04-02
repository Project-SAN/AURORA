use crate::core::policy::metadata::POLICY_FLAG_ZKBOO;
use crate::core::policy::ProofKind;
use crate::crypto::zkp::ascon_circuit::{
    build_consistency_circuit, build_keybinding_circuit, build_policy_blocklist_host_circuit,
};
use crate::policy::blocklist::{Blocklist, BlocklistEntry};
use crate::policy::zkboo::ZkBooPolicy;
use crate::policy::{PolicyMetadata, VerifierEntry};
use crate::types::Error;
use alloc::vec;
use alloc::vec::Vec;

pub const DEFAULT_DEMO_POLICY_EXPIRY: u32 = 900;
pub const DEFAULT_DEMO_POLICY_PAYLOAD_LEN: usize = 96;
pub const DEFAULT_DEMO_HOST_HEADER_OFFSET: usize = 16;
pub const DEFAULT_DEMO_MIN_ROUNDS: u16 = 8;
pub const DEMO_DIRECTORY_SEED: [u8; 32] = [0x44; 32];

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HttpBlocklistRules {
    pub exact_hosts: Vec<Vec<u8>>,
    pub prefix_hosts: Vec<Vec<u8>>,
}

pub fn http_host_blocklist_rules(
    blocklist: &Blocklist,
) -> core::result::Result<HttpBlocklistRules, Error> {
    let mut rules = HttpBlocklistRules::default();
    for entry in blocklist.entries() {
        match entry {
            BlocklistEntry::Exact(value) => rules.exact_hosts.push(value.as_slice().to_vec()),
            BlocklistEntry::Prefix(value) => rules.prefix_hosts.push(value.as_slice().to_vec()),
            BlocklistEntry::Raw(_) | BlocklistEntry::Cidr(_) | BlocklistEntry::Range { .. } => {
                return Err(Error::NotImplemented)
            }
        }
    }
    Ok(rules)
}

pub fn demo_policy_metadata_for_blocklist(
    blocklist: &Blocklist,
    expiry: u32,
    payload_len: usize,
    host_header_offset: usize,
) -> core::result::Result<PolicyMetadata, Error> {
    let rules = http_host_blocklist_rules(blocklist)?;
    let keybinding = build_keybinding_circuit(32);
    let consistency = build_consistency_circuit(32, payload_len);
    let policy_circuit = build_policy_blocklist_host_circuit(
        payload_len,
        host_header_offset,
        &rules.exact_hosts,
        &rules.prefix_hosts,
    )?;

    let policy = ZkBooPolicy::new(policy_circuit.clone());
    Ok(PolicyMetadata {
        policy_id: *policy.policy_id(),
        version: 1,
        expiry,
        flags: POLICY_FLAG_ZKBOO,
        verifiers: vec![
            VerifierEntry {
                kind: ProofKind::KeyBinding as u8,
                min_rounds: DEFAULT_DEMO_MIN_ROUNDS,
                verifier_blob: keybinding.encode(),
            },
            VerifierEntry {
                kind: ProofKind::Consistency as u8,
                min_rounds: DEFAULT_DEMO_MIN_ROUNDS,
                verifier_blob: consistency.encode(),
            },
            VerifierEntry {
                kind: ProofKind::Policy as u8,
                min_rounds: DEFAULT_DEMO_MIN_ROUNDS,
                verifier_blob: policy_circuit.encode(),
            },
        ],
    })
}

pub fn demo_policy_metadata_from_blocklist_json(
    json: &str,
    expiry: u32,
    payload_len: usize,
    host_header_offset: usize,
) -> core::result::Result<PolicyMetadata, Error> {
    let blocklist = Blocklist::from_json(json)?;
    demo_policy_metadata_for_blocklist(&blocklist, expiry, payload_len, host_header_offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::zkp::Circuit;

    fn build_payload(host: &str) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"GET / HTTP/1.1\r\n");
        out.extend_from_slice(b"Host: ");
        out.extend_from_slice(host.as_bytes());
        out.extend_from_slice(b"\r\nConnection: close\r\nX-Pad: ");
        let pad_len = DEFAULT_DEMO_POLICY_PAYLOAD_LEN - out.len() - 4;
        out.extend(core::iter::repeat_n(b'a', pad_len));
        out.extend_from_slice(b"\r\n\r\n");
        out
    }

    fn bytes_to_bits_lsb(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(bytes.len() * 8);
        for &b in bytes {
            for bit in 0..8u8 {
                out.push(((b >> bit) & 1) as u8);
            }
        }
        out
    }

    #[test]
    fn metadata_from_blocklist_blocks_exact_host() {
        let metadata = demo_policy_metadata_from_blocklist_json(
            r#"{"entries":[{"type":"exact","value":"blocked.example"}]}"#,
            DEFAULT_DEMO_POLICY_EXPIRY,
            DEFAULT_DEMO_POLICY_PAYLOAD_LEN,
            DEFAULT_DEMO_HOST_HEADER_OFFSET,
        )
        .expect("metadata");
        assert_eq!(metadata.verifiers[0].min_rounds, DEFAULT_DEMO_MIN_ROUNDS);
        let policy = metadata
            .verifiers
            .iter()
            .find(|entry| entry.kind == ProofKind::Policy as u8)
            .expect("policy verifier");
        let circuit = Circuit::decode(policy.verifier_blob.as_slice()).expect("decode");
        let payload = build_payload("blocked.example");
        let out = circuit.eval(&bytes_to_bits_lsb(&payload)).expect("eval");
        assert_eq!(out[32 * 8], 0);
    }

    #[test]
    fn metadata_from_blocklist_rejects_unsupported_cidr_rule() {
        let err = demo_policy_metadata_from_blocklist_json(
            r#"{"entries":[{"type":"cidr","value":"192.168.0.0/16"}]}"#,
            DEFAULT_DEMO_POLICY_EXPIRY,
            DEFAULT_DEMO_POLICY_PAYLOAD_LEN,
            DEFAULT_DEMO_HOST_HEADER_OFFSET,
        )
        .expect_err("unsupported");
        assert!(matches!(err, Error::NotImplemented));
    }
}
