//! Backend contract between the PRISM protocol layer and the isogeny engine.

use alloc::vec::Vec;

use super::hash::HashToPrimeError;
use super::params::SaltPrismParameters;
use super::types::ChallengePrime;

pub type Result<T, E> = core::result::Result<T, PrismError<E>>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrismError<E> {
    HashToPrime(HashToPrimeError),
    Backend(E),
}

impl<E> From<HashToPrimeError> for PrismError<E> {
    fn from(error: HashToPrimeError) -> Self {
        Self::HashToPrime(error)
    }
}

pub trait PrismBackend {
    type Error;
    type VerifyingKey;
    type SigningKey;
    type SignatureBody;

    fn params(&self) -> &'static SaltPrismParameters;

    fn keygen(
        &mut self,
    ) -> core::result::Result<(Self::VerifyingKey, Self::SigningKey), Self::Error>;

    fn encode_verifying_key(&self, verifying_key: &Self::VerifyingKey) -> Vec<u8>;

    fn sign_challenge(
        &mut self,
        verifying_key: &Self::VerifyingKey,
        signing_key: &Self::SigningKey,
        challenge: &ChallengePrime,
    ) -> core::result::Result<Self::SignatureBody, Self::Error>;

    fn encode_signature_body(&self, signature: &Self::SignatureBody) -> Vec<u8>;

    fn decode_signature_body(&self, bytes: &[u8]) -> Option<Self::SignatureBody>;

    fn verify_challenge(
        &self,
        verifying_key: &Self::VerifyingKey,
        challenge: &ChallengePrime,
        signature: &Self::SignatureBody,
    ) -> core::result::Result<bool, Self::Error>;
}
