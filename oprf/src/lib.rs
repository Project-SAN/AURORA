#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};
use zeroize::Zeroize;

const DST_HASH_TO_GROUP: &[u8] = b"OPRFV1-HashToGroup-ristretto255-SHA512";
const DST_FINALIZE: &[u8] = b"OPRFV1-Finalize-ristretto255-SHA512";

pub const ELEMENT_LEN: usize = 32;
pub const OUTPUT_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidElement,
    InvalidScalar,
}

#[derive(Clone, Zeroize)]
pub struct ServerKey {
    scalar: Scalar,
}

impl ServerKey {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        loop {
            let candidate = Scalar::random(rng);
            if candidate != Scalar::zero() {
                return Self { scalar: candidate };
            }
        }
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            point: (self.scalar * RISTRETTO_BASEPOINT_POINT).compress(),
        }
    }

    pub fn evaluate(&self, blinded: &BlindedElement) -> Result<Evaluation, Error> {
        let point = blinded.point.decompress().ok_or(Error::InvalidElement)?;
        Ok(Evaluation {
            point: (self.scalar * point).compress(),
        })
    }
}

#[derive(Clone)]
pub struct PublicKey {
    point: CompressedRistretto,
}

impl PublicKey {
    pub fn to_bytes(&self) -> [u8; ELEMENT_LEN] {
        self.point.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8; ELEMENT_LEN]) -> Result<Self, Error> {
        let candidate = CompressedRistretto::from_slice(bytes);
        if candidate.decompress().is_none() {
            return Err(Error::InvalidElement);
        }
        Ok(Self { point: candidate })
    }
}

#[derive(Clone)]
pub struct BlindedElement {
    point: CompressedRistretto,
}

impl BlindedElement {
    pub fn to_bytes(&self) -> [u8; ELEMENT_LEN] {
        self.point.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8; ELEMENT_LEN]) -> Result<Self, Error> {
        let candidate = CompressedRistretto::from_slice(bytes);
        if candidate.decompress().is_none() {
            return Err(Error::InvalidElement);
        }
        Ok(Self { point: candidate })
    }
}

#[derive(Clone)]
pub struct Evaluation {
    point: CompressedRistretto,
}

impl Evaluation {
    pub fn to_bytes(&self) -> [u8; ELEMENT_LEN] {
        self.point.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8; ELEMENT_LEN]) -> Result<Self, Error> {
        let candidate = CompressedRistretto::from_slice(bytes);
        if candidate.decompress().is_none() {
            return Err(Error::InvalidElement);
        }
        Ok(Self { point: candidate })
    }
}

#[derive(Zeroize)]
pub struct ClientState {
    blind: Scalar,
    input: Vec<u8>,
}

impl Drop for ClientState {
    fn drop(&mut self) {
        self.blind.zeroize();
        self.input.zeroize();
    }
}

pub struct Client;

impl Client {
    pub fn blind<R: RngCore + CryptoRng>(input: &[u8], rng: &mut R) -> Result<(ClientState, BlindedElement), Error> {
        let mut blind = Scalar::random(rng);
        while blind == Scalar::zero() {
            blind = Scalar::random(rng);
        }
        let point = hash_to_group(input) * blind;
        let state = ClientState {
            blind,
            input: input.to_vec(),
        };
        Ok((state, BlindedElement { point: point.compress() }))
    }

    pub fn finalize(state: &ClientState, evaluation: &Evaluation, info: &[u8]) -> Result<[u8; OUTPUT_LEN], Error> {
        let point = evaluation
            .point
            .decompress()
            .ok_or(Error::InvalidElement)?;
        let unblinded = point * state.blind.invert();
        Ok(finalize_output(&unblinded, &state.input, info))
    }
}

fn expand_message_xmd(msg: &[u8], dst: &[u8], len: usize) -> Vec<u8> {
    const BLOCK_SIZE: usize = 128; // SHA-512 block size
    let ell = (len + 64 - 1) / 64;
    let dst_len = dst.len() as u8;

    let mut hasher = Sha512::new();
    hasher.update(&[0u8; BLOCK_SIZE]);
    hasher.update(msg);
    hasher.update([(len >> 8) as u8, (len & 0xFF) as u8]);
    hasher.update([dst_len]);
    hasher.update(dst);
    let b0 = hasher.finalize();

    let mut uniform_bytes = Vec::with_capacity(ell * 64);
    let mut previous = [0u8; 64];

    for i in 1..=ell {
        let mut block_input = [0u8; 64];
        block_input.copy_from_slice(&b0[..64]);
        if i > 1 {
            for j in 0..64 {
                block_input[j] ^= previous[j];
            }
        }
        let mut h = Sha512::new();
        h.update(&block_input);
        h.update([i as u8]);
        h.update([dst_len]);
        h.update(dst);
        let bi = h.finalize();
        previous.copy_from_slice(&bi[..64]);
        uniform_bytes.extend_from_slice(&previous);
    }

    uniform_bytes.truncate(len);
    uniform_bytes
}

fn hash_to_group(msg: &[u8]) -> RistrettoPoint {
    let uniform = expand_message_xmd(msg, DST_HASH_TO_GROUP, 64);
    let mut buf = [0u8; 64];
    buf.copy_from_slice(&uniform[..64]);
    RistrettoPoint::from_uniform_bytes(&buf)
}

fn hash_to_scalar(input: &[u8], dst: &[u8]) -> Scalar {
    let uniform = expand_message_xmd(input, dst, 64);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&uniform[..64]);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn finalize_output(unblinded: &RistrettoPoint, input: &[u8], info: &[u8]) -> [u8; OUTPUT_LEN] {
    let mut material = Vec::with_capacity(ELEMENT_LEN + input.len() + info.len());
    material.extend_from_slice(unblinded.compress().as_bytes());
    material.extend_from_slice(input);
    material.extend_from_slice(info);
    let scalar = hash_to_scalar(&material, DST_FINALIZE);
    let mut out = [0u8; OUTPUT_LEN];
    out.copy_from_slice(&scalar.to_bytes()[..OUTPUT_LEN]);
    out
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
        let eval = sk.evaluate(&blinded).expect("eval");
        let tau = Client::finalize(&state, &eval, &[]).expect("finalize");

        assert_ne!(&tau, &[0u8; OUTPUT_LEN]);
    }

    #[test]
    fn determinism_given_reevaluation() {
        let mut rng = OsRng;
        let sk = ServerKey::generate(&mut rng);
        let input = b"deterministic";

        let (state1, blinded1) = Client::blind(input, &mut rng).expect("blind1");
        let eval1 = sk.evaluate(&blinded1).expect("eval1");
        let tau1 = Client::finalize(&state1, &eval1, b"info").expect("tau1");

        let (state2, blinded2) = Client::blind(input, &mut rng).expect("blind2");
        let eval2 = sk.evaluate(&blinded2).expect("eval2");
        let tau2 = Client::finalize(&state2, &eval2, b"info").expect("tau2");

        assert_eq!(tau1, tau2);
    }

    #[test]
    fn different_inputs_or_info_diverge() {
        let mut rng = OsRng;
        let sk = ServerKey::generate(&mut rng);

        let (s1, b1) = Client::blind(b"alpha", &mut rng).expect("blind alpha");
        let tau1 = Client::finalize(&s1, &sk.evaluate(&b1).expect("eval1"), b"info").expect("tau alpha");

        let (s2, b2) = Client::blind(b"beta", &mut rng).expect("blind beta");
        let tau2 = Client::finalize(&s2, &sk.evaluate(&b2).expect("eval2"), b"info").expect("tau beta");
        assert!(tau1.ct_ne(&tau2).unwrap_u8() == 1);

        let tau3 = Client::finalize(&s1, &sk.evaluate(&b1).expect("eval3"), b"other").expect("tau alpha other");
        assert!(tau1.ct_ne(&tau3).unwrap_u8() == 1);
    }
}
