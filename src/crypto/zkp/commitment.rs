use crate::crypto::ascon::Sponge;

pub const COMMIT_LEN: usize = 32;
const DOMAIN_SEP: &[u8] = b"AURORA-ZKP-COMMIT-v1";

pub trait CommitmentScheme {
    fn commit(state: &[u8], salt: &[u8], index: u64) -> [u8; COMMIT_LEN];
}

/// Ascon-p[12]-based sponge commitment (project-local construction).
pub struct AsconCommitment;

impl CommitmentScheme for AsconCommitment {
    fn commit(state: &[u8], salt: &[u8], index: u64) -> [u8; COMMIT_LEN] {
        let mut sponge = Sponge::new();
        sponge.absorb(DOMAIN_SEP);
        sponge.absorb(&index.to_be_bytes());
        sponge.absorb(state);
        sponge.absorb(salt);
        sponge.finalize();
        let mut out = [0u8; COMMIT_LEN];
        sponge.squeeze(&mut out);
        out
    }
}
