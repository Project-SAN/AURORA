use rand_core::{CryptoRng, RngCore};
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

pub struct DhKeyPair {
    pub secret: [u8; 32],
    pub public: [u8; 32],
}

impl DhKeyPair {
    pub fn generate<R: RngCore + CryptoRng>(mut rng: R) -> Self {
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        // Clamp for X25519
        secret[0] &= 248;
        secret[31] &= 127;
        secret[31] |= 64;
        let public = x25519(secret, X25519_BASEPOINT_BYTES);
        Self { secret, public }
    }

    pub fn derive(&self, peer_public: &[u8; 32]) -> [u8; 32] {
        x25519(self.secret, *peer_public)
    }
}
