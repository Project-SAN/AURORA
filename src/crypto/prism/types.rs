//! Protocol-facing PRISM types.

use alloc::vec::Vec;

use crate::crypto::isogeny::arith::IsogenyInteger;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Salt(pub Vec<u8>);

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChallengePrime(pub Vec<u8>);

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Signature {
    pub salt: Salt,
    pub body: Vec<u8>,
}

impl Signature {
    pub fn new(salt: Salt, body: Vec<u8>) -> Self {
        Self { salt, body }
    }
}

impl Salt {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl ChallengePrime {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Paper degree `q(2^a - q)` for a challenge prime `q in Primes_a`.
    pub fn paper_degree(&self, challenge_bits: usize) -> Option<IsogenyInteger> {
        let q = IsogenyInteger::from_be_slice(self.as_bytes())?;
        let lower_bound = IsogenyInteger::pow2(challenge_bits.checked_sub(1)?)?;
        let two_a = IsogenyInteger::pow2(challenge_bits)?;
        if q <= lower_bound || q >= two_a {
            return None;
        }
        let complement = two_a.checked_sub(&q)?;
        q.checked_mul(&complement)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use crate::crypto::prism::{
        ChallengePrime, SALT_PRISM_LEVEL1, SALT_PRISM_LEVEL3, SALT_PRISM_LEVEL5,
    };

    #[test]
    fn paper_degree_matches_expected_bit_lengths() {
        let level1 = ChallengePrime::new({
            let mut bytes = vec![0u8; SALT_PRISM_LEVEL1.challenge_bits / 8];
            let last = bytes.len() - 1;
            bytes[0] = 0x80;
            bytes[last] = 0x01;
            bytes
        });
        let level3 = ChallengePrime::new({
            let mut bytes = vec![0u8; SALT_PRISM_LEVEL3.challenge_bits / 8];
            let last = bytes.len() - 1;
            bytes[0] = 0x80;
            bytes[last] = 0x01;
            bytes
        });
        let level5 = ChallengePrime::new({
            let mut bytes = vec![0u8; SALT_PRISM_LEVEL5.challenge_bits / 8];
            let last = bytes.len() - 1;
            bytes[0] = 0x80;
            bytes[last] = 0x01;
            bytes
        });

        assert_eq!(
            level1
                .paper_degree(SALT_PRISM_LEVEL1.challenge_bits)
                .unwrap()
                .bit_len(),
            382
        );
        assert_eq!(
            level3
                .paper_degree(SALT_PRISM_LEVEL3.challenge_bits)
                .unwrap()
                .bit_len(),
            510
        );
        assert_eq!(
            level5
                .paper_degree(SALT_PRISM_LEVEL5.challenge_bits)
                .unwrap()
                .bit_len(),
            638
        );
    }

    #[test]
    fn paper_degree_rejects_out_of_range_challenge() {
        let mut bytes = vec![0u8; SALT_PRISM_LEVEL1.challenge_bits / 8];
        bytes[0] = 0x80;
        let challenge = ChallengePrime::new(bytes);
        assert_eq!(
            challenge.paper_degree(SALT_PRISM_LEVEL1.challenge_bits),
            None
        );
    }
}
