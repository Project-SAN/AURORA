//! Actual salt-PRISM hash-to-prime logic.

use alloc::{vec, vec::Vec};

use rand_core::RngCore;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use crate::crypto::isogeny::field::{Fp, FpModulus, MAX_LIMBS};

use super::types::{ChallengePrime, Salt};

const HASH_DOMAIN_SALT_PRISM: &[u8] = b"AURORA:salt-prism:hash-to-prime:v1";
const MR_BASES: &[u64] = &[2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];

pub type Result<T> = core::result::Result<T, HashToPrimeError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HashToPrimeConfig {
    pub output_bits: usize,
    pub challenge_bits: usize,
    pub salt_bits: usize,
    pub max_retries: usize,
}

impl HashToPrimeConfig {
    pub const fn new(
        output_bits: usize,
        challenge_bits: usize,
        salt_bits: usize,
        max_retries: usize,
    ) -> Self {
        Self {
            output_bits,
            challenge_bits,
            salt_bits,
            max_retries,
        }
    }

    pub const fn output_bytes(&self) -> usize {
        self.output_bits.div_ceil(8)
    }

    pub const fn challenge_bytes(&self) -> usize {
        self.challenge_bits.div_ceil(8)
    }

    pub const fn salt_bytes(&self) -> usize {
        self.salt_bits.div_ceil(8)
    }

    pub fn validate(&self) -> Result<()> {
        if self.output_bits == 0
            || self.challenge_bits <= 1
            || self.salt_bits == 0
            || self.max_retries == 0
            || self.output_bits < self.challenge_bits
            || self.challenge_bits > MAX_LIMBS * 64
        {
            return Err(HashToPrimeError::InvalidConfig);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashToPrimeError {
    InvalidConfig,
    RetryLimitExceeded,
    SaltLengthMismatch,
    NonCanonicalSalt,
}

pub fn hash_to_prime_with_salt(
    config: &HashToPrimeConfig,
    verifying_key: &[u8],
    message: &[u8],
    salt: &Salt,
) -> Result<Option<ChallengePrime>> {
    config.validate()?;
    validate_salt(config, salt)?;

    let digest = hash_output(config, verifying_key, message, salt.as_bytes());
    let (candidate_bytes, in_range) = extract_low_bits_be(&digest, config.challenge_bits);
    if !in_range {
        return Ok(None);
    }
    if !get_be_bit(&candidate_bytes, config.challenge_bits - 1) {
        return Ok(None);
    }
    if !get_be_bit(&candidate_bytes, 0) {
        return Ok(None);
    }
    if !is_probable_prime(&candidate_bytes) {
        return Ok(None);
    }

    Ok(Some(ChallengePrime::new(candidate_bytes)))
}

pub fn sample_salt_and_hash_to_prime<R: RngCore>(
    config: &HashToPrimeConfig,
    verifying_key: &[u8],
    message: &[u8],
    rng: &mut R,
) -> Result<(Salt, ChallengePrime)> {
    config.validate()?;

    let mut salt_bytes = vec![0u8; config.salt_bytes()];
    for _ in 0..config.max_retries {
        rng.fill_bytes(&mut salt_bytes);
        mask_top_bits(&mut salt_bytes, config.salt_bits);
        let salt = Salt::new(salt_bytes.clone());
        if let Some(challenge) = hash_to_prime_with_salt(config, verifying_key, message, &salt)? {
            return Ok((salt, challenge));
        }
    }
    Err(HashToPrimeError::RetryLimitExceeded)
}

pub fn verify_hash_to_prime(
    config: &HashToPrimeConfig,
    verifying_key: &[u8],
    message: &[u8],
    salt: &Salt,
    challenge: &ChallengePrime,
) -> Result<bool> {
    config.validate()?;
    if challenge.as_bytes().len() != config.challenge_bytes() {
        return Ok(false);
    }
    if !unused_top_bits_zero(challenge.as_bytes(), config.challenge_bits) {
        return Ok(false);
    }

    Ok(
        hash_to_prime_with_salt(config, verifying_key, message, salt)?
            .map(|expected| expected == *challenge)
            .unwrap_or(false),
    )
}

fn hash_output(
    config: &HashToPrimeConfig,
    verifying_key: &[u8],
    message: &[u8],
    salt: &[u8],
) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(HASH_DOMAIN_SALT_PRISM);
    absorb_len_prefixed(&mut hasher, &(config.output_bits as u32).to_be_bytes());
    absorb_len_prefixed(&mut hasher, &(config.challenge_bits as u32).to_be_bytes());
    absorb_len_prefixed(&mut hasher, &(config.salt_bits as u32).to_be_bytes());
    absorb_len_prefixed(&mut hasher, verifying_key);
    absorb_len_prefixed(&mut hasher, message);
    absorb_len_prefixed(&mut hasher, salt);

    let mut reader = hasher.finalize_xof();
    let mut out = vec![0u8; config.output_bytes()];
    reader.read(&mut out);
    mask_top_bits(&mut out, config.output_bits);
    out
}

fn absorb_len_prefixed(hasher: &mut Shake256, data: &[u8]) {
    hasher.update(&(data.len() as u32).to_be_bytes());
    hasher.update(data);
}

fn validate_salt(config: &HashToPrimeConfig, salt: &Salt) -> Result<()> {
    if salt.as_bytes().len() != config.salt_bytes() {
        return Err(HashToPrimeError::SaltLengthMismatch);
    }
    if !unused_top_bits_zero(salt.as_bytes(), config.salt_bits) {
        return Err(HashToPrimeError::NonCanonicalSalt);
    }
    Ok(())
}

fn mask_top_bits(bytes: &mut [u8], bits: usize) {
    if bytes.is_empty() {
        return;
    }
    let rem = bits % 8;
    if rem != 0 {
        bytes[0] &= (1u8 << rem) - 1;
    }
}

fn unused_top_bits_zero(bytes: &[u8], bits: usize) -> bool {
    if bytes.is_empty() {
        return bits == 0;
    }
    let rem = bits % 8;
    if rem == 0 {
        true
    } else {
        (bytes[0] >> rem) == 0
    }
}

fn extract_low_bits_be(bytes: &[u8], bits: usize) -> (Vec<u8>, bool) {
    let out_len = bits.div_ceil(8);
    let mut out = vec![0u8; out_len];
    for bit_index in 0..bits {
        if get_be_bit(bytes, bit_index) {
            set_be_bit(&mut out, bit_index);
        }
    }
    let mut in_range = true;
    for bit_index in bits..bytes.len() * 8 {
        if get_be_bit(bytes, bit_index) {
            in_range = false;
            break;
        }
    }
    mask_top_bits(&mut out, bits);
    (out, in_range)
}

fn get_be_bit(bytes: &[u8], bit_index_lsb: usize) -> bool {
    let byte_index = bytes.len() - 1 - bit_index_lsb / 8;
    let bit_offset = bit_index_lsb % 8;
    ((bytes[byte_index] >> bit_offset) & 1) == 1
}

fn set_be_bit(bytes: &mut [u8], bit_index_lsb: usize) {
    let byte_index = bytes.len() - 1 - bit_index_lsb / 8;
    let bit_offset = bit_index_lsb % 8;
    bytes[byte_index] |= 1 << bit_offset;
}

fn is_probable_prime(candidate_be: &[u8]) -> bool {
    let modulus = match FpModulus::from_be_bytes(candidate_be) {
        Ok(modulus) => modulus,
        Err(_) => return false,
    };

    if let Some(n) = modulus.to_u64() {
        if n < 2 {
            return false;
        }
        if n == 2 || n == 3 {
            return true;
        }
        if n & 1 == 0 {
            return false;
        }
    }

    for &prime in MR_BASES {
        if mod_small_be(candidate_be, prime as u32) == 0 {
            return modulus.to_u64() == Some(prime);
        }
    }

    let (n_minus_one, n_minus_one_len) = sub_small_from_limbs(modulus.as_limbs(), 1).unwrap();
    let (d, d_len, s) = factor_twos(&n_minus_one, n_minus_one_len);
    let n_minus_one_fp = Fp::from_limbs(&modulus, &n_minus_one[..n_minus_one_len]);

    'witnesses: for &base in MR_BASES {
        if modulus.to_u64() == Some(base) {
            continue;
        }
        let a = Fp::from_u64(&modulus, base);
        let mut x = a.pow_vartime(&d[..d_len]);
        if x.is_one() || x == n_minus_one_fp {
            continue 'witnesses;
        }

        for _ in 1..s {
            x = x.square();
            if x == n_minus_one_fp {
                continue 'witnesses;
            }
            if x.is_one() {
                return false;
            }
        }
        return false;
    }
    true
}

fn mod_small_be(bytes: &[u8], modulus: u32) -> u32 {
    let mut rem = 0u32;
    for &byte in bytes {
        rem = ((rem << 8) + byte as u32) % modulus;
    }
    rem
}

fn sub_small_from_limbs(limbs: &[u64], small: u64) -> Option<([u64; MAX_LIMBS], usize)> {
    let mut out = [0u64; MAX_LIMBS];
    let len = limbs.len();
    out[..len].copy_from_slice(limbs);
    let (value, mut borrow) = out[0].overflowing_sub(small);
    out[0] = value;
    let mut idx = 1usize;
    while borrow {
        let (next, overflow) = out.get_mut(idx)?.overflowing_sub(1);
        out[idx] = next;
        borrow = overflow;
        idx += 1;
    }
    Some((out, normalize_len(&out, len)))
}

fn factor_twos(limbs: &[u64; MAX_LIMBS], len: usize) -> ([u64; MAX_LIMBS], usize, usize) {
    let mut d = *limbs;
    let mut d_len = len;
    let mut s = 0usize;
    while d[0] & 1 == 0 {
        shr1_assign(&mut d, &mut d_len);
        s += 1;
    }
    (d, d_len, s)
}

fn shr1_assign(limbs: &mut [u64; MAX_LIMBS], len: &mut usize) {
    let mut carry = 0u64;
    for idx in (0..*len).rev() {
        let next = limbs[idx] & 1;
        limbs[idx] = (limbs[idx] >> 1) | (carry << 63);
        carry = next;
    }
    *len = normalize_len(limbs, *len);
}

fn normalize_len(limbs: &[u64; MAX_LIMBS], mut len: usize) -> usize {
    while len > 1 && limbs[len - 1] == 0 {
        len -= 1;
    }
    len
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use rand_chacha::ChaCha20Rng;
    use rand_core::{Error as RandError, RngCore, SeedableRng};

    use super::{
        hash_output, hash_to_prime_with_salt, is_probable_prime, sample_salt_and_hash_to_prime,
        verify_hash_to_prime, HashToPrimeConfig, HashToPrimeError,
    };
    use crate::crypto::prism::{ChallengePrime, Salt};

    struct FixedRng {
        byte: u8,
    }

    impl RngCore for FixedRng {
        fn next_u32(&mut self) -> u32 {
            u32::from_le_bytes([self.byte; 4])
        }

        fn next_u64(&mut self) -> u64 {
            u64::from_le_bytes([self.byte; 8])
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(self.byte);
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), RandError> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    #[test]
    fn invalid_configs_are_rejected() {
        let bad = HashToPrimeConfig::new(0, 16, 16, 8);
        assert_eq!(
            hash_to_prime_with_salt(&bad, b"vk", b"msg", &Salt::new(vec![0, 0])),
            Err(HashToPrimeError::InvalidConfig)
        );

        let bad = HashToPrimeConfig::new(8, 16, 16, 8);
        assert_eq!(
            hash_to_prime_with_salt(&bad, b"vk", b"msg", &Salt::new(vec![0, 0])),
            Err(HashToPrimeError::InvalidConfig)
        );
    }

    #[test]
    fn hash_to_prime_is_deterministic_for_fixed_salt() {
        let cfg = HashToPrimeConfig::new(16, 16, 16, 128);
        let salt = Salt::new(vec![0x12, 0x34]);
        let a = hash_to_prime_with_salt(&cfg, b"vk", b"msg", &salt).unwrap();
        let b = hash_to_prime_with_salt(&cfg, b"vk", b"msg", &salt).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn salt_and_message_are_domain_separated() {
        let cfg = HashToPrimeConfig::new(16, 16, 16, 128);
        let a = hash_output(&cfg, b"vk", b"msg-a", &[0x12, 0x34]);
        let b = hash_output(&cfg, b"vk", b"msg-b", &[0x12, 0x34]);
        let c = hash_output(&cfg, b"vk", b"msg-a", &[0x12, 0x35]);
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn non_canonical_salt_is_rejected() {
        let cfg = HashToPrimeConfig::new(16, 16, 9, 8);
        let salt = Salt::new(vec![0x80, 0x01]);
        assert_eq!(
            hash_to_prime_with_salt(&cfg, b"vk", b"msg", &salt),
            Err(HashToPrimeError::NonCanonicalSalt)
        );
    }

    #[test]
    fn sampler_finds_prime_and_verify_recomputes_it() {
        let cfg = HashToPrimeConfig::new(16, 16, 16, 256);
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let (salt, challenge) =
            sample_salt_and_hash_to_prime(&cfg, b"vk", b"msg", &mut rng).unwrap();
        assert_eq!(salt.as_bytes().len(), 2);
        assert_eq!(challenge.as_bytes().len(), 2);
        assert!(is_probable_prime(challenge.as_bytes()));
        assert!(verify_hash_to_prime(&cfg, b"vk", b"msg", &salt, &challenge).unwrap());

        let wrong = ChallengePrime::new(vec![challenge.as_bytes()[0], challenge.as_bytes()[1] ^ 1]);
        assert!(!verify_hash_to_prime(&cfg, b"vk", b"msg", &salt, &wrong).unwrap());
    }

    #[test]
    fn retry_limit_is_enforced() {
        let cfg = HashToPrimeConfig::new(8, 8, 8, 1);
        let mut chosen = None;
        for byte in 0u8..=u8::MAX {
            let salt = Salt::new(vec![byte]);
            if hash_to_prime_with_salt(&cfg, b"vk", b"msg", &salt)
                .unwrap()
                .is_none()
            {
                chosen = Some(byte);
                break;
            }
        }
        let mut rng = FixedRng {
            byte: chosen.expect("there should be non-prime-producing salts"),
        };
        assert_eq!(
            sample_salt_and_hash_to_prime(&cfg, b"vk", b"msg", &mut rng),
            Err(HashToPrimeError::RetryLimitExceeded)
        );
    }

    #[test]
    fn primality_test_handles_large_known_values() {
        // 2^127 - 1 is prime.
        let prime = [
            0x7fu8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff,
        ];
        assert!(is_probable_prime(&prime));

        let composite = [
            0x00u8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff,
        ];
        assert!(!is_probable_prime(&composite));
    }
}
