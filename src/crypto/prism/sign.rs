//! Signing orchestration for PRISM-family schemes.

use rand_core::RngCore;

use super::backend::{PrismBackend, PrismError, Result};
use super::hash::sample_salt_and_hash_to_prime;
use super::types::Signature;

pub fn sign_with_backend<R: RngCore, B: PrismBackend>(
    backend: &mut B,
    verifying_key: &B::VerifyingKey,
    signing_key: &B::SigningKey,
    message: &[u8],
    rng: &mut R,
    max_retries: usize,
) -> Result<Signature, B::Error> {
    let config = backend.params().hash_to_prime_config(max_retries);
    let verifying_key_bytes = backend.encode_verifying_key(verifying_key);
    let (salt, challenge) =
        sample_salt_and_hash_to_prime(&config, &verifying_key_bytes, message, rng)?;
    let body = backend
        .sign_challenge(verifying_key, signing_key, &challenge)
        .map_err(PrismError::Backend)?;
    let encoded_body = backend.encode_signature_body(&body);
    Ok(Signature::new(salt, encoded_body))
}
