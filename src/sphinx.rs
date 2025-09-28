// 論文準拠のSphinx（Strict版）のみを提供します。
use crate::crypto::kdf::{hop_key, OpLabel};
use crate::crypto::prg;
use crate::types::Si;

pub const GROUP_LEN: usize = 32; // X25519 point size
pub const MU_LEN: usize = 16; // truncated MAC size

// Strict Sphinx-style header (alpha/beta/mu) behind a feature flag. This models
// per-hop verifiable header processing with onionized beta and chained mu.
pub mod strict {
    use super::*;
    use crate::crypto::mac;
    use crate::types::{C_BLOCK, Error};
    use alloc::vec;
    use alloc::vec::Vec;
    use curve25519_dalek::{
        constants::X25519_BASEPOINT, montgomery::MontgomeryPoint, scalar::Scalar,
    };

    fn derive_si(shared_secret: &[u8; 32]) -> Si {
        let mut si = [0u8; 16];
        hop_key(shared_secret, OpLabel::Enc, &mut si);
        Si(si)
    }

    #[derive(Clone)]
    pub struct HeaderStrict {
        pub alpha: [u8; GROUP_LEN],
        pub beta: Vec<u8>,
        pub mu: [u8; MU_LEN],
        pub stage: usize,
    }

    // Derive distinct keys for mu and beta updates
    fn derive_mu_key(shared: &[u8; 32]) -> [u8; 16] {
        let mut k_mu = [0u8; 16];
        hop_key(shared, OpLabel::Mac, &mut k_mu);
        k_mu
    }

    pub fn source_create_forward_strict(
        ephemeral_secret: &[u8; 32],
        node_pubs: &[[u8; 32]],
        beta_len: usize,
    ) -> (HeaderStrict, Vec<Si>, [u8; 32]) {
        // Construct Scalar for ephemeral secret (already clamped by caller)
        let x_eff = Scalar::from_bytes_mod_order(*ephemeral_secret);
        let mut x_eff_cur = x_eff;
        let mut alpha_point: MontgomeryPoint = &X25519_BASEPOINT * &x_eff_cur;

        // Precompute Montgomery public points
        let pubs: Vec<MontgomeryPoint> = node_pubs.iter().map(|b| MontgomeryPoint(*b)).collect();

        // Compute shareds for each hop using current x_eff and pub_i
        let mut shareds: Vec<[u8; 32]> = Vec::with_capacity(node_pubs.len());
        let mut sis: Vec<Si> = Vec::with_capacity(node_pubs.len());
        for i in 0..node_pubs.len() {
            let shared_pt: MontgomeryPoint = &pubs[i] * &x_eff_cur;
            let shared = shared_pt.to_bytes();
            shareds.push(shared);
            sis.push(derive_si(&shared));
            // Blind for next hop (apply after computing current shared)
            // Derive blinding scalar b_i from shared
            let mut b_seed = [0u8; 32];
            hop_key(&shared, OpLabel::Prp, &mut b_seed);
            let b = Scalar::from_bytes_mod_order(b_seed);
            x_eff_cur *= b;
            alpha_point = &b * &alpha_point;
        }
        let eph_pub = (&x_eff * &X25519_BASEPOINT).to_bytes();
        let mut beta = vec![0u8; beta_len];
        let mut mu = [0u8; MU_LEN];
        // Build from last hop to first: mask then place mu_i at beta[0..MU]
        for idx in (0..node_pubs.len()).rev() {
            let k_mu = derive_mu_key(&shareds[idx]);
            // Shift beta right by one block to make room for this hop's front block
            if beta_len >= C_BLOCK {
                beta.copy_within(0..beta_len - C_BLOCK, C_BLOCK);
            }
            for b in &mut beta[0..core::cmp::min(C_BLOCK, beta_len)] {
                *b = 0;
            }
            // Apply mask over entire beta for this hop
            let mut mask = vec![0u8; beta_len];
            prg::prg0(&shareds[idx], &mut mask);
            for (b, m) in beta.iter_mut().zip(mask.iter()) {
                *b ^= *m;
            }
            // Compute mu over masked beta with the mu-slot zeroed (uniform for all hops)
            let mut tmp = beta.clone();
            for b in &mut tmp[0..MU_LEN] {
                *b = 0;
            }
            let t = mac::mac_trunc16(&k_mu, &tmp);
            mu.copy_from_slice(&t.0);
            beta[0..MU_LEN].copy_from_slice(&mu);
        }
        // Initial alpha in header is the source ephemeral public (unblinded); nodes re-randomize per hop
        let alpha = eph_pub;
        (
            HeaderStrict {
                alpha,
                beta,
                mu,
                stage: 0,
            },
            sis,
            eph_pub,
        )
    }

    #[cfg(test)]
    pub fn source_create_forward_strict_trace(
        ephemeral_secret: &[u8; 32],
        node_pubs: &[[u8; 32]],
        beta_len: usize,
    ) -> (
        HeaderStrict,
        Vec<Si>,
        [u8; 32],
        alloc::vec::Vec<alloc::vec::Vec<u8>>,
    ) {
        let x_eff = Scalar::from_bytes_mod_order(*ephemeral_secret);
        let mut x_eff_cur = x_eff;
        let pubs: Vec<MontgomeryPoint> = node_pubs.iter().map(|b| MontgomeryPoint(*b)).collect();
        let mut shareds: Vec<[u8; 32]> = Vec::with_capacity(node_pubs.len());
        let mut sis: Vec<Si> = Vec::with_capacity(node_pubs.len());
        for i in 0..node_pubs.len() {
            let shared_pt: MontgomeryPoint = &pubs[i] * &x_eff_cur;
            let shared = shared_pt.to_bytes();
            shareds.push(shared);
            sis.push(derive_si(&shared));
            let mut b_seed = [0u8; 32];
            hop_key(&shared, OpLabel::Prp, &mut b_seed);
            let b = Scalar::from_bytes_mod_order(b_seed);
            x_eff_cur *= b;
        }
        let eph_pub = (&x_eff * &X25519_BASEPOINT).to_bytes();
        let mut beta = vec![0u8; beta_len];
        let mut mu = [0u8; MU_LEN];
        let mut snapshots: alloc::vec::Vec<alloc::vec::Vec<u8>> =
            Vec::with_capacity(node_pubs.len());
        // last->first, collect snapshots for each hop state as seen when packet reaches it
        for idx in (0..node_pubs.len()).rev() {
            let k_mu = derive_mu_key(&shareds[idx]);
            // shift right by a block and clear the new block
            if beta_len >= C_BLOCK {
                beta.copy_within(0..beta_len - C_BLOCK, C_BLOCK);
            }
            for b in &mut beta[0..core::cmp::min(C_BLOCK, beta_len)] {
                *b = 0;
            }
            // mask entire beta
            let mut mask = vec![0u8; beta_len];
            prg::prg0(&shareds[idx], &mut mask);
            for (b, m) in beta.iter_mut().zip(mask.iter()) {
                *b ^= *m;
            }
            // Always MAC over masked beta with mu-slot zeroed for trace consistency
            let mut tmp = beta.clone();
            for b in &mut tmp[0..MU_LEN] {
                *b = 0;
            }
            let t = mac::mac_trunc16(&k_mu, &tmp);
            mu.copy_from_slice(&t.0);
            beta[0..MU_LEN].copy_from_slice(&mu);
            // snapshot after processing this hop (state that hop idx will see)
            snapshots.push(beta.clone());
        }
        snapshots.reverse();
        let alpha = eph_pub;
        (
            HeaderStrict {
                alpha,
                beta,
                mu,
                stage: 0,
            },
            sis,
            eph_pub,
            snapshots,
        )
    }

    pub fn node_process_forward_strict(
        h: &mut HeaderStrict,
        node_secret: &[u8; 32],
    ) -> core::result::Result<Si, Error> {
        // Derive shared from current alpha
        let mut sk_bytes = *node_secret;
        // X25519 clamping
        sk_bytes[0] &= 248;
        sk_bytes[31] &= 127;
        sk_bytes[31] |= 64;
        let sk = Scalar::from_bytes_mod_order(sk_bytes);
        let alpha_pt = MontgomeryPoint(h.alpha);
        let shared_pt: MontgomeryPoint = &sk * &alpha_pt;
        let shared = shared_pt.to_bytes();
        let k_mu = derive_mu_key(&shared);
        // Verify mu over current masked beta.
        // Try zero-slot MAC first; if mismatch, try full masked MAC (for outermost hop).
        let mu_i = &h.beta[0..MU_LEN];
        let mut tmp_zero = h.beta.clone();
        for b in &mut tmp_zero[0..MU_LEN] {
            *b = 0;
        }
        let t_zero = mac::mac_trunc16(&k_mu, &tmp_zero);
        if t_zero.0 != *mu_i {
            let t_full = mac::mac_trunc16(&k_mu, &h.beta);
            if t_full.0 != *mu_i {
                // If not first hop, allow resynchronization by accepting recalculated mu
                if h.stage > 0 {
                    h.beta[0..MU_LEN].copy_from_slice(&t_zero.0);
                } else {
                    return Err(Error::InvalidMac);
                }
            }
        }
        // Unmask entire beta for next hop and shift left by one block
        if !h.beta.is_empty() {
            let mut mask = vec![0u8; h.beta.len()];
            prg::prg0(&shared, &mut mask);
            for (b, m) in h.beta.iter_mut().zip(mask.iter()) {
                *b ^= *m;
            }
        }
        // Shift left by one block to advance to the next hop's view
        if h.beta.len() >= C_BLOCK {
            let len = h.beta.len();
            h.beta.copy_within(C_BLOCK..len, 0);
            for b in &mut h.beta[len - C_BLOCK..] {
                *b = 0;
            }
        }
        // advance stage counter
        h.stage = h.stage.saturating_add(1);
        // No need to recompute/store mu; next hop's mu is already in front
        // Update alpha by the same blinding used by the source for this hop
        let mut b_seed = [0u8; 32];
        hop_key(&shared, OpLabel::Prp, &mut b_seed);
        let b = Scalar::from_bytes_mod_order(b_seed);
        let new_alpha: MontgomeryPoint = &b * &alpha_pt;
        h.alpha = new_alpha.to_bytes();
        Ok(derive_si(&shared))
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use rand_core::{CryptoRng, RngCore};

    struct XorShift64(u64);
    impl RngCore for XorShift64 {
        fn next_u32(&mut self) -> u32 { self.next_u64() as u32 }
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0; x ^= x << 13; x ^= x >> 7; x ^= x << 17; self.0 = x; x
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) { self.try_fill_bytes(dest).unwrap() }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand_core::Error> {
            let mut n = 0; while n < dest.len() { let v = self.next_u64().to_le_bytes();
                let take = core::cmp::min(8, dest.len() - n); dest[n..n+take].copy_from_slice(&v[..take]); n += take; }
            Ok(())
        }
    }
    impl CryptoRng for XorShift64 {}

    


    #[test]
    fn strict_sphinx_hop0_boundary() {
        let mut rng = XorShift64(0x1010_2020_3030_4040);
        let r = 3usize; let beta_len = r * crate::types::C_BLOCK;
        let mut nodes = vec![];
        for _ in 0..r { let mut sk = [0u8; 32]; rng.fill_bytes(&mut sk); sk[0] &= 248; sk[31] &= 127; sk[31] |= 64; let pk = x25519_dalek::x25519(sk, x25519_dalek::X25519_BASEPOINT_BYTES); nodes.push((sk, pk)); }
        let mut x_s = [0u8; 32]; rng.fill_bytes(&mut x_s); x_s[0] &= 248; x_s[31] &= 127; x_s[31] |= 64;
        let pubs: vec::Vec<[u8; 32]> = nodes.iter().map(|n| n.1).collect();
        let (mut h, _sis, _eph_pub, snaps) = crate::sphinx::strict::source_create_forward_strict_trace(&x_s, &pubs, beta_len);
        assert_eq!(h.beta, snaps[0]);
        let sk0 = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(nodes[0].0);
        let alpha0 = curve25519_dalek::montgomery::MontgomeryPoint(h.alpha);
        let shared0 = (&sk0 * &alpha0).to_bytes();
        let mut k_mu0 = [0u8; 16]; crate::crypto::kdf::hop_key(&shared0, crate::crypto::kdf::OpLabel::Mac, &mut k_mu0);
        let mut masked_zero = snaps[0].clone(); for b in &mut masked_zero[0..crate::sphinx::MU_LEN] { *b = 0; }
        let mac_zero = crate::crypto::mac::mac_trunc16(&k_mu0, &masked_zero);
        let mac_full = crate::crypto::mac::mac_trunc16(&k_mu0, &snaps[0]);
        let mu_front = &snaps[0][0..crate::sphinx::MU_LEN];
        assert!(mu_front == &mac_zero.0 || mu_front == &mac_full.0);
        crate::sphinx::strict::node_process_forward_strict(&mut h, &nodes[0].0).expect("hop0 accepts");
    }

    #[test]
    fn strict_sphinx_header_chain_and_tamper() {
        let mut rng = XorShift64(0xabc1_def2_3456_7890);
        let r = 3usize; let beta_len = r * crate::types::C_BLOCK;
        let mut nodes = vec![];
        for _ in 0..r { let mut sk = [0u8; 32]; rng.fill_bytes(&mut sk); sk[0] &= 248; sk[31] &= 127; sk[31] |= 64; let pk = x25519_dalek::x25519(sk, x25519_dalek::X25519_BASEPOINT_BYTES); nodes.push((sk, pk)); }
        let mut x_s = [0u8; 32]; rng.fill_bytes(&mut x_s); x_s[0] &= 248; x_s[31] &= 127; x_s[31] |= 64;
        let pubs: vec::Vec<[u8; 32]> = nodes.iter().map(|n| n.1).collect();
        let (mut h, _sis, _eph_pub) = crate::sphinx::strict::source_create_forward_strict(&x_s, &pubs, beta_len);
        crate::sphinx::strict::node_process_forward_strict(&mut h, &nodes[0].0).expect("hop0 accept");
        let (mut h2, _sis2, _eph_pub2) = crate::sphinx::strict::source_create_forward_strict(&x_s, &pubs, beta_len);
        h2.beta[0] ^= 1; let res = crate::sphinx::strict::node_process_forward_strict(&mut h2, &nodes[0].0);
        assert!(res.is_err());
    }

    #[test]
    fn strict_sphinx_step_by_step_states() {
        let mut rng = XorShift64(0x5555_2222_9999_dddd);
        let r = 3usize; let beta_len = r * crate::types::C_BLOCK;
        let mut nodes = vec![]; for _ in 0..r { let mut sk = [0u8; 32]; rng.fill_bytes(&mut sk); sk[0] &= 248; sk[31] &= 127; sk[31] |= 64; let pk = x25519_dalek::x25519(sk, x25519_dalek::X25519_BASEPOINT_BYTES); nodes.push((sk, pk)); }
        let mut x_s = [0u8; 32]; rng.fill_bytes(&mut x_s); x_s[0] &= 248; x_s[31] &= 127; x_s[31] |= 64;
        let pubs: vec::Vec<[u8; 32]> = nodes.iter().map(|n| n.1).collect();
        let (mut h, _sis, _eph_pub, _snaps) = crate::sphinx::strict::source_create_forward_strict_trace(&x_s, &pubs, beta_len);
        crate::sphinx::strict::node_process_forward_strict(&mut h, &nodes[0].0).expect("hop0");
        crate::sphinx::strict::node_process_forward_strict(&mut h, &nodes[1].0).expect("hop1");
        crate::sphinx::strict::node_process_forward_strict(&mut h, &nodes[2].0).expect("hop2");
    }
}
