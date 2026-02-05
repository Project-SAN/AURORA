use crate::crypto::ascon::AsconHash256;

pub const COMMIT_LEN: usize = 32;
const DOMAIN_SEP: &[u8] = b"AURORA-ZKP-COMMIT-v1";

pub trait CommitmentScheme {
    fn commit(state: &[u8], salt: &[u8], index: u64) -> [u8; COMMIT_LEN];
}

/// Ascon-Hash256-based commitment (NIST SP 800-232).
pub struct AsconCommitment;

impl CommitmentScheme for AsconCommitment {
    fn commit(state: &[u8], salt: &[u8], index: u64) -> [u8; COMMIT_LEN] {
        let mut hasher = AsconHash256::new();
        hasher.update(DOMAIN_SEP);
        hasher.update(&index.to_be_bytes());
        hasher.update(state);
        hasher.update(salt);
        hasher.finalize()
    }
}
