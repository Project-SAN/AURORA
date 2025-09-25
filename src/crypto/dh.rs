use rand_core::{CryptoRng, RngCore};
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};

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

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::SmallRng, SeedableRng};

    // Wrapper to make SmallRng compatible with our CryptoRng requirement (for testing only)
    struct TestRng(SmallRng);

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

    // Mark as CryptoRng for testing purposes only
    impl CryptoRng for TestRng {}

    #[test]
    fn test_keypair_generation() {
        let mut rng = TestRng(SmallRng::seed_from_u64(42));
        let keypair = DhKeyPair::generate(&mut rng);

        // Check that secret key is properly clamped
        assert_eq!(keypair.secret[0] & 7, 0);
        assert_eq!(keypair.secret[31] & 128, 0);
        assert_eq!(keypair.secret[31] & 64, 64);

        // Check that public key is not all zeros
        assert_ne!(keypair.public, [0u8; 32]);
    }

    #[test]
    fn test_key_derivation() {
        let mut rng1 = TestRng(SmallRng::seed_from_u64(100));
        let mut rng2 = TestRng(SmallRng::seed_from_u64(200));
        let keypair = DhKeyPair::generate(&mut rng1);
        let peer_keypair = DhKeyPair::generate(&mut rng2);

        let shared1 = keypair.derive(&peer_keypair.public);
        let shared2 = peer_keypair.derive(&keypair.public);

        // DH property: both sides should derive the same shared secret
        assert_eq!(shared1, shared2);

        // Shared secret should not be all zeros
        assert_ne!(shared1, [0u8; 32]);
    }

    #[test]
    fn test_different_peers_different_secrets() {
        let mut rng1 = TestRng(SmallRng::seed_from_u64(300));
        let mut rng2 = TestRng(SmallRng::seed_from_u64(400));
        let mut rng3 = TestRng(SmallRng::seed_from_u64(500));
        let keypair = DhKeyPair::generate(&mut rng1);
        let peer1 = DhKeyPair::generate(&mut rng2);
        let peer2 = DhKeyPair::generate(&mut rng3);

        let shared1 = keypair.derive(&peer1.public);
        let shared2 = keypair.derive(&peer2.public);

        // Different peers should result in different shared secrets
        assert_ne!(shared1, shared2);
    }

    #[test]
    fn test_deterministic_derivation() {
        let mut rng1 = TestRng(SmallRng::seed_from_u64(600));
        let mut rng2 = TestRng(SmallRng::seed_from_u64(700));
        let keypair = DhKeyPair::generate(&mut rng1);
        let peer = DhKeyPair::generate(&mut rng2);

        let shared1 = keypair.derive(&peer.public);
        let shared2 = keypair.derive(&peer.public);

        // Same inputs should produce same output
        assert_eq!(shared1, shared2);
    }
}
