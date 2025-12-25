use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand_core::RngCore;
use sha2::{Digest, Sha512};

pub fn derive_key_from_seed(seed: &[u8]) -> Scalar {
    Scalar::from_bytes_mod_order_wide(&hash_to_wide(seed))
}

pub fn eval_unblinded(key: &Scalar, input: &[u8]) -> [u8; 32] {
    let point = hash_to_point(input);
    (point * key).compress().to_bytes()
}

pub fn blind<R: RngCore>(input: &[u8], rng: &mut R) -> (Scalar, [u8; 32]) {
    let mut wide = [0u8; 64];
    rng.fill_bytes(&mut wide);
    let blind = Scalar::from_bytes_mod_order_wide(&wide);
    let point = hash_to_point(input);
    let blinded = (point * blind).compress().to_bytes();
    (blind, blinded)
}

pub fn eval_blinded(key: &Scalar, blinded: &[u8; 32]) -> Option<[u8; 32]> {
    let point = CompressedRistretto(*blinded).decompress()?;
    Some((point * key).compress().to_bytes())
}

pub fn unblind(blind: &Scalar, evaluated: &[u8; 32]) -> Option<[u8; 32]> {
    let point = CompressedRistretto(*evaluated).decompress()?;
    let inv = blind.invert();
    Some((point * inv).compress().to_bytes())
}

fn hash_to_wide(input: &[u8]) -> [u8; 64] {
    let digest = Sha512::digest(input);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    wide
}

fn hash_to_point(input: &[u8]) -> RistrettoPoint {
    RistrettoPoint::from_uniform_bytes(&hash_to_wide(input))
}
