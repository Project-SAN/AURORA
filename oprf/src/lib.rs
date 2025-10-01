#![no_std]

extern crate alloc;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};
use zeroize::Zeroize;

/// Length in bytes of encoded group elements.
pub const ELEMENT_LEN: usize = 32;
/// Length in bytes of resulting OPRF output (τ).
pub const OUTPUT_LEN: usize = 32;

/// Errors that can arise while running the OPRF protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Ristretto point provided by the peer failed to decompress.
    InvalidElement,
    /// The blinding scalar was zero, retry the protocol.
    InvalidScalar,
}

/// Server-side secret key.
#[derive(Clone, Zeroize)]
pub struct ServerKey {
    scalar: Scalar,
}

impl ServerKey {
    /// Sample a fresh server key from the RNG.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        loop {
            let sk = Scalar::random(rng);
            if sk != Scalar::zero() {
                return Self { scalar: sk };
            }
        }
    }

    /// Derive the corresponding public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            point: (self.scalar * RISTRETTO_BASEPOINT_POINT).compress(),
        }
    }

    /// Evaluate the OPRF on a blinded element.
    pub fn evaluate(&self, blinded: &BlindedElement) -> Evaluation {
        let point = blinded.point * self.scalar;
        Evaluation {
            point: point.compress(),
        }
    }

    /// Expose raw scalar for testing (std only).
    #[cfg(feature = "std")]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.scalar.to_bytes()
    }
}

/// Server public key (compressed point).
#[derive(Clone)]
pub struct PublicKey {
    point: CompressedRistretto,
}

impl PublicKey {
    pub fn to_bytes(&self) -> [u8; ELEMENT_LEN] {
        self.point.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8; ELEMENT_LEN]) -> Result<Self, Error> {
        let compressed = CompressedRistretto::from_slice(bytes);
        if compressed.decompress().is_none() {
            return Err(Error::InvalidElement);
        }
        Ok(Self { point: compressed })
    }
}

/// Blinded input produced by the client.
#[derive(Clone)]
pub struct BlindedElement {
    point: RistrettoPoint,
}

impl BlindedElement {
    pub fn to_bytes(&self) -> [u8; ELEMENT_LEN] {
        self.point.compress().to_bytes()
    }

    pub fn from_bytes(bytes: &[u8; ELEMENT_LEN]) -> Result<Self, Error> {
        let compressed = CompressedRistretto::from_slice(bytes);
        let point = compressed.decompress().ok_or(Error::InvalidElement)?;
        Ok(Self { point })
    }
}

/// Evaluation returned by the server (compressed point).
#[derive(Clone)]
pub struct Evaluation {
    point: CompressedRistretto,
}

impl Evaluation {
    pub fn to_bytes(&self) -> [u8; ELEMENT_LEN] {
        self.point.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8; ELEMENT_LEN]) -> Result<Self, Error> {
        let point = CompressedRistretto::from_slice(bytes);
        if point.decompress().is_none() {
            return Err(Error::InvalidElement);
        }
        Ok(Self { point })
    }
}

/// Internal client state required to finalize the protocol.
#[derive(Zeroize)]
pub struct ClientState {
    blind: Scalar,
    seed_hash: [u8; 64],
}

/// Client interface for blinding inputs and finalizing evaluations.
pub struct Client;

fn hash_to_point(input: &[u8]) -> RistrettoPoint {
    RistrettoPoint::hash_from_bytes::<Sha512>(input)
}

impl Client {
    /// Blind an input (typically `rid`) and return the state and blinded element.
    pub fn blind<R: RngCore + CryptoRng>(input: &[u8], rng: &mut R) -> Result<(ClientState, BlindedElement), Error> {
        let mut seed_arr = [0u8; 64];
        let seed_hash = Sha512::digest(input);
        seed_arr.copy_from_slice(&seed_hash);

        let point = hash_to_point(input);
        let mut blind = Scalar::random(rng);
        while blind == Scalar::zero() {
            blind = Scalar::random(rng);
        }
        let blinded_point = point * blind;
        let state = ClientState { blind, seed_hash: seed_arr };
        Ok((state, BlindedElement { point: blinded_point }))
    }

    /// Finalize the server evaluation, returning the OPRF output τ.
    pub fn finalize(state: &ClientState, evaluation: &Evaluation) -> Result<[u8; OUTPUT_LEN], Error> {
        let point = evaluation
            .point
            .decompress()
            .ok_or(Error::InvalidElement)?;
        let inverse = state.blind.invert();
        let unblinded = point * inverse;
        let mut hasher = Sha512::new();
        hasher.update(unblinded.compress().as_bytes());
        hasher.update(&state.seed_hash);
        let digest = hasher.finalize();
        let mut output = [0u8; OUTPUT_LEN];
        output.copy_from_slice(&digest[..OUTPUT_LEN]);
        Ok(output)
    }
}

impl Drop for ClientState {
    fn drop(&mut self) {
        self.blind.zeroize();
        self.seed_hash.zeroize();
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use subtle::ConstantTimeEq;

    #[test]
    fn oprf_roundtrip() {
        let mut rng = OsRng;
        let sk = ServerKey::generate(&mut rng);
        let input = b"test identifier";

        let (state, blinded) = Client::blind(input, &mut rng).expect("blind");
        let eval = sk.evaluate(&blinded);
        let tau = Client::finalize(&state, &eval).expect("finalize");

        assert_ne!(&tau, &[0u8; OUTPUT_LEN]);
    }

    #[test]
    fn determinism_given_reevaluation() {
        let mut rng = OsRng;
        let sk = ServerKey::generate(&mut rng);
        let input = b"deterministic";

        let (state1, blinded1) = Client::blind(input, &mut rng).expect("blind1");
        let eval1 = sk.evaluate(&blinded1);
        let tau1 = Client::finalize(&state1, &eval1).expect("tau1");

        let (state2, blinded2) = Client::blind(input, &mut rng).expect("blind2");
        let eval2 = sk.evaluate(&blinded2);
        let tau2 = Client::finalize(&state2, &eval2).expect("tau2");

        // The output should depend only on input and server key, not randomness.
        assert_eq!(tau1, tau2);
    }

    #[test]
    fn different_inputs_yield_different_outputs() {
        let mut rng = OsRng;
        let sk = ServerKey::generate(&mut rng);

        let (s1, b1) = Client::blind(b"alpha", &mut rng).expect("blind alpha");
        let tau1 = Client::finalize(&s1, &sk.evaluate(&b1)).expect("tau alpha");

        let (s2, b2) = Client::blind(b"beta", &mut rng).expect("blind beta");
        let tau2 = Client::finalize(&s2, &sk.evaluate(&b2)).expect("tau beta");

        assert!(tau1.ct_ne(&tau2).unwrap_u8() == 1);
    }
}
