use rand_core::{CryptoRng, RngCore};
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

pub type PublicKey = [u8; 32];
pub type SecretKey = [u8; 32];

pub struct KeyPair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

impl KeyPair {
    pub fn generate<R: RngCore + CryptoRng>(mut rng: R) -> Self {
        let mut secret: SecretKey = [0u8; 32];
        rng.fill_bytes(&mut secret);
        // Clamp for X25519
        secret[0] &= 248;
        secret[31] &= 127;
        secret[31] |= 64;

        let public: PublicKey = x25519(secret, X25519_BASEPOINT_BYTES);
        Self { secret, public }
    }

    pub fn derive(&self, peer_public: &[u8; 32]) -> [u8; 32] {
        x25519(self.secret, *peer_public)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    struct TestRng(ChaCha20Rng);

    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            self.0.next_u32()
        }

        fn next_u64(&mut self) -> u64 {
            self.0.next_u64()
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.0.fill_bytes(dest)
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.0.try_fill_bytes(dest)
        }
    }

    impl CryptoRng for TestRng {}

    #[test]
    fn test_keypair_generation() {
        let mut rng = TestRng(ChaCha20Rng::seed_from_u64(42));
        let keypair = KeyPair::generate(&mut rng);

        assert_eq!(keypair.secret[0] & 7, 0);
        assert_eq!(keypair.secret[31] & 128, 0);
        assert_eq!(keypair.secret[31] & 64, 64);
        assert_ne!(keypair.public, [0u8; 32]);
    }

    #[test]
    fn test_key_derivation() {
        let mut rng1 = TestRng(ChaCha20Rng::seed_from_u64(100));
        let mut rng2 = TestRng(ChaCha20Rng::seed_from_u64(200));
        let keypair = KeyPair::generate(&mut rng1);
        let peer_keypair = KeyPair::generate(&mut rng2);

        let shared1 = keypair.derive(&peer_keypair.public);
        let shared2 = peer_keypair.derive(&keypair.public);

        assert_eq!(shared1, shared2);
        assert_ne!(shared1, [0u8; 32]);
    }

    #[test]
    fn test_different_peers_different_secrets() {
        let mut rng1 = TestRng(ChaCha20Rng::seed_from_u64(300));
        let mut rng2 = TestRng(ChaCha20Rng::seed_from_u64(400));
        let mut rng3 = TestRng(ChaCha20Rng::seed_from_u64(500));
        let keypair = KeyPair::generate(&mut rng1);
        let peer1 = KeyPair::generate(&mut rng2);
        let peer2 = KeyPair::generate(&mut rng3);

        let shared1 = keypair.derive(&peer1.public);
        let shared2 = keypair.derive(&peer2.public);

        assert_ne!(shared1, shared2);
    }

    #[test]
    fn test_deterministic_derivation() {
        let mut rng1 = TestRng(ChaCha20Rng::seed_from_u64(600));
        let mut rng2 = TestRng(ChaCha20Rng::seed_from_u64(700));
        let keypair = KeyPair::generate(&mut rng1);
        let peer = KeyPair::generate(&mut rng2);

        let shared1 = keypair.derive(&peer.public);
        let shared2 = keypair.derive(&peer.public);

        assert_eq!(shared1, shared2);
    }
}
