//! Concrete parameter sets for salt-PRISM.

use crate::crypto::isogeny::params::{
    SupersingularParameters, NIST_LEVEL1_BASE, NIST_LEVEL3_BASE, NIST_LEVEL5_BASE,
};

use super::hash::HashToPrimeConfig;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SaltPrismParameters {
    pub security_bits: usize,
    pub base: SupersingularParameters,
    /// `a` in the paper, where the challenge prime lies in `(2^(a-1), 2^a)`.
    pub challenge_bits: usize,
    /// `n` bits of hash output before restricting to `Primes_a`.
    pub hash_bits: usize,
    /// `k` salt bits.
    pub salt_bits: usize,
    /// Conservative `log2(Nsign)` bound used by the proof and parameter table.
    pub max_signatures_log2: usize,
}

impl SaltPrismParameters {
    pub const fn hash_to_prime_config(&self, max_retries: usize) -> HashToPrimeConfig {
        HashToPrimeConfig::new(
            self.hash_bits,
            self.challenge_bits,
            self.salt_bits,
            max_retries,
        )
    }
}

pub const SALT_PRISM_LEVEL1: SaltPrismParameters = SaltPrismParameters {
    security_bits: 128,
    base: NIST_LEVEL1_BASE,
    challenge_bits: 192,
    hash_bits: 192,
    salt_bits: 256,
    max_signatures_log2: 64,
};

pub const SALT_PRISM_LEVEL3: SaltPrismParameters = SaltPrismParameters {
    security_bits: 192,
    base: NIST_LEVEL3_BASE,
    challenge_bits: 256,
    hash_bits: 256,
    salt_bits: 384,
    max_signatures_log2: 64,
};

pub const SALT_PRISM_LEVEL5: SaltPrismParameters = SaltPrismParameters {
    security_bits: 256,
    base: NIST_LEVEL5_BASE,
    challenge_bits: 320,
    hash_bits: 320,
    salt_bits: 512,
    max_signatures_log2: 64,
};
