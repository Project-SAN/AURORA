//! Verification orchestration for PRISM-family schemes.

use super::backend::{PrismBackend, PrismError, Result};
use super::hash::{hash_to_prime_with_salt, HashToPrimeError};
use super::types::Signature;

pub fn verify_with_backend<B: PrismBackend>(
    backend: &B,
    verifying_key: &B::VerifyingKey,
    message: &[u8],
    signature: &Signature,
) -> Result<bool, B::Error> {
    let config = backend.params().hash_to_prime_config(1);
    let verifying_key_bytes = backend.encode_verifying_key(verifying_key);
    let challenge =
        match hash_to_prime_with_salt(&config, &verifying_key_bytes, message, &signature.salt) {
            Ok(Some(challenge)) => challenge,
            Ok(None) => return Ok(false),
            Err(HashToPrimeError::SaltLengthMismatch | HashToPrimeError::NonCanonicalSalt) => {
                return Ok(false);
            }
            Err(error) => return Err(error.into()),
        };

    let Some(body) = backend.decode_signature_body(&signature.body) else {
        return Ok(false);
    };

    backend
        .verify_challenge(verifying_key, &challenge, &body)
        .map_err(PrismError::Backend)
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use crate::crypto::isogeny::params::NIST_LEVEL1_BASE;
    use crate::crypto::prism::{
        keygen_with_backend, sign_with_backend, ChallengePrime, PrismBackend, PrismError, Salt,
        SaltPrismParameters, Signature,
    };

    use super::verify_with_backend;

    const TEST_PARAMS: SaltPrismParameters = SaltPrismParameters {
        security_bits: 16,
        base: NIST_LEVEL1_BASE,
        challenge_bits: 16,
        hash_bits: 16,
        salt_bits: 9,
        max_signatures_log2: 8,
    };

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct MockSignatureBody(Vec<u8>);

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum MockError {
        Keygen,
        Sign,
        Verify,
    }

    #[derive(Clone, Debug)]
    struct MockBackend {
        fail_keygen: bool,
        fail_sign: bool,
        fail_verify: bool,
    }

    impl MockBackend {
        fn new() -> Self {
            Self {
                fail_keygen: false,
                fail_sign: false,
                fail_verify: false,
            }
        }
    }

    impl PrismBackend for MockBackend {
        type Error = MockError;
        type VerifyingKey = Vec<u8>;
        type SigningKey = u8;
        type SignatureBody = MockSignatureBody;

        fn params(&self) -> &'static SaltPrismParameters {
            &TEST_PARAMS
        }

        fn keygen(
            &mut self,
        ) -> core::result::Result<(Self::VerifyingKey, Self::SigningKey), Self::Error> {
            if self.fail_keygen {
                return Err(MockError::Keygen);
            }
            Ok((vec![0x42, 0x99], 0x42))
        }

        fn encode_verifying_key(&self, verifying_key: &Self::VerifyingKey) -> Vec<u8> {
            verifying_key.clone()
        }

        fn sign_challenge(
            &mut self,
            _verifying_key: &Self::VerifyingKey,
            signing_key: &Self::SigningKey,
            challenge: &ChallengePrime,
        ) -> core::result::Result<Self::SignatureBody, Self::Error> {
            if self.fail_sign {
                return Err(MockError::Sign);
            }
            let payload = challenge
                .as_bytes()
                .iter()
                .map(|byte| *byte ^ *signing_key)
                .collect();
            Ok(MockSignatureBody(payload))
        }

        fn encode_signature_body(&self, signature: &Self::SignatureBody) -> Vec<u8> {
            let mut out = Vec::with_capacity(signature.0.len() + 1);
            out.push(0xA5);
            out.extend_from_slice(&signature.0);
            out
        }

        fn decode_signature_body(&self, bytes: &[u8]) -> Option<Self::SignatureBody> {
            let (tag, payload) = bytes.split_first()?;
            if *tag != 0xA5 {
                return None;
            }
            Some(MockSignatureBody(payload.to_vec()))
        }

        fn verify_challenge(
            &self,
            verifying_key: &Self::VerifyingKey,
            challenge: &ChallengePrime,
            signature: &Self::SignatureBody,
        ) -> core::result::Result<bool, Self::Error> {
            if self.fail_verify {
                return Err(MockError::Verify);
            }
            let signing_key = *verifying_key.first().unwrap_or(&0);
            let expected: Vec<u8> = challenge
                .as_bytes()
                .iter()
                .map(|byte| *byte ^ signing_key)
                .collect();
            Ok(signature.0 == expected)
        }
    }

    #[test]
    fn protocol_roundtrip_signs_and_verifies() {
        let mut backend = MockBackend::new();
        let (verifying_key, signing_key) = keygen_with_backend(&mut backend).unwrap();
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let signature = sign_with_backend(
            &mut backend,
            &verifying_key,
            &signing_key,
            b"message",
            &mut rng,
            256,
        )
        .unwrap();

        assert!(verify_with_backend(&backend, &verifying_key, b"message", &signature).unwrap());
        assert!(!verify_with_backend(&backend, &verifying_key, b"tampered", &signature).unwrap());
    }

    #[test]
    fn verify_rejects_non_canonical_salt_and_malformed_body() {
        let mut backend = MockBackend::new();
        let (verifying_key, signing_key) = keygen_with_backend(&mut backend).unwrap();
        let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
        let signature = sign_with_backend(
            &mut backend,
            &verifying_key,
            &signing_key,
            b"message",
            &mut rng,
            256,
        )
        .unwrap();

        let bad_salt = Signature::new(Salt::new(vec![0x80, 0x01]), signature.body.clone());
        assert!(!verify_with_backend(&backend, &verifying_key, b"message", &bad_salt).unwrap());

        let malformed_body = Signature::new(signature.salt.clone(), vec![0x00, 0x12, 0x34]);
        assert!(
            !verify_with_backend(&backend, &verifying_key, b"message", &malformed_body).unwrap()
        );
    }

    #[test]
    fn backend_errors_are_propagated_from_keygen_sign_and_verify() {
        let mut keygen_backend = MockBackend::new();
        keygen_backend.fail_keygen = true;
        assert_eq!(
            keygen_with_backend(&mut keygen_backend),
            Err(PrismError::Backend(MockError::Keygen))
        );

        let mut sign_backend = MockBackend::new();
        sign_backend.fail_sign = true;
        let verifying_key = vec![0x42, 0x99];
        let signing_key = 0x42;
        let mut rng = ChaCha20Rng::from_seed([11u8; 32]);
        assert_eq!(
            sign_with_backend(
                &mut sign_backend,
                &verifying_key,
                &signing_key,
                b"message",
                &mut rng,
                256,
            ),
            Err(PrismError::Backend(MockError::Sign))
        );

        let mut verify_backend = MockBackend::new();
        let mut rng = ChaCha20Rng::from_seed([13u8; 32]);
        let signature = sign_with_backend(
            &mut verify_backend,
            &verifying_key,
            &signing_key,
            b"message",
            &mut rng,
            256,
        )
        .unwrap();
        verify_backend.fail_verify = true;
        assert_eq!(
            verify_with_backend(&verify_backend, &verifying_key, b"message", &signature),
            Err(PrismError::Backend(MockError::Verify))
        );
    }

    #[test]
    fn sign_rejects_invalid_retry_budget() {
        let mut backend = MockBackend::new();
        let (verifying_key, signing_key) = keygen_with_backend(&mut backend).unwrap();
        let mut rng = ChaCha20Rng::from_seed([15u8; 32]);
        assert_eq!(
            sign_with_backend(
                &mut backend,
                &verifying_key,
                &signing_key,
                b"message",
                &mut rng,
                0,
            ),
            Err(PrismError::HashToPrime(
                crate::crypto::prism::HashToPrimeError::InvalidConfig
            ))
        );
    }
}
