pub mod capsule;
pub mod extensions;
pub mod metadata;
pub mod registry;

pub use capsule::{
    PolicyCapsule, ProofKind, ProofPart, AUX_MAX, COMMIT_LEN, MAX_CAPSULE_LEN, MAX_PARTS, PROOF_LEN,
};
pub use extensions::{
    extension_iter, find_extension, encode_extensions_into, CapsuleExtensionRef, ExtensionIter,
    EXT_TAG_BATCH_ID, EXT_TAG_MODE, EXT_TAG_PCD_KEY_HASH, EXT_TAG_PCD_PROOF, EXT_TAG_PCD_ROOT,
    EXT_TAG_PCD_SEQ, EXT_TAG_PCD_STATE, EXT_TAG_PCD_TARGET_HASH, EXT_TAG_PAYLOAD_HASH,
    EXT_TAG_PRECOMPUTE_ID, EXT_TAG_PRECOMPUTE_PROOF, EXT_TAG_ROUTE_ID, EXT_TAG_SEQUENCE,
    EXT_TAG_SESSION_NONCE,
};
pub use metadata::{PolicyId, PolicyMetadata, VerifierEntry};
pub use registry::{CapsuleValidator, PolicyRegistry, PolicyRole};

use crate::types::{Error, Result};
use alloc::vec::Vec;

pub const POLICY_METADATA_TLV: u8 = 0xA1;

pub fn encode_metadata_tlv(meta: &PolicyMetadata) -> Vec<u8> {
    let payload = meta.encode();
    let mut out = Vec::with_capacity(3 + payload.len());
    out.push(POLICY_METADATA_TLV);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(&payload);
    out
}

pub fn decode_metadata_tlv(buf: &[u8]) -> Result<PolicyMetadata> {
    if buf.len() < 3 {
        return Err(Error::Length);
    }
    if buf[0] != POLICY_METADATA_TLV {
        return Err(Error::Length);
    }
    let len = u16::from_be_bytes([buf[1], buf[2]]) as usize;
    if buf.len() < 3 + len {
        return Err(Error::Length);
    }
    PolicyMetadata::parse(&buf[3..3 + len])
}
