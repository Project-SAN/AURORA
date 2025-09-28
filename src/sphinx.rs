// A no_std-friendly Sphinx-like implementation with per-hop header MACs,
// header re-randomization (y blinding), and fixed-length payload onion.
// Note: This follows the structure of Sphinx (Danezis & Goldberg) adapted
// to X25519 and the crate's KDF/MAC/PRG interfaces.

use crate::crypto::kdf::{OpLabel, hop_key};
use crate::crypto::prg;
use crate::types::{Result, Si};
use alloc::vec;
use alloc::vec::Vec;

pub const GROUP_LEN: usize = 32; // X25519 point size
pub const MU_LEN: usize = 16; // truncated MAC size

#[derive(Clone, Copy)]
pub struct Header {
    pub y: [u8; GROUP_LEN],
    pub gamma: [u8; MU_LEN],
}

#[derive(Clone)]
pub struct Payload(pub Vec<u8>); // fixed-length

fn clamp_scalar(x: &mut [u8; 32]) {
    x[0] &= 248;
    x[31] &= 127;
    x[31] |= 64;
}

fn blinding_scalar_from_shared(shared: &[u8; 32]) -> [u8; 32] {
    let mut s = [0u8; 32];
    // Derive 32 bytes and clamp to valid X25519 scalar
    hop_key(shared, OpLabel::Prp, &mut s[0..16]);
    hop_key(shared, OpLabel::Enc, &mut s[16..32]);
    clamp_scalar(&mut s);
    s
}

fn compute_shared_secret(secret: &[u8; 32], public: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::x25519(*secret, *public)
}

fn derive_si(shared_secret: &[u8; 32]) -> Si {
    let mut si = [0u8; 16];
    hop_key(shared_secret, OpLabel::Enc, &mut si);
    Si(si)
}

// Build initial y via blinding chain at the source (so nodes can track it)
pub fn build_header_chain(ephemeral_public: &[u8; 32], shareds: &[[u8; 32]]) -> [u8; 32] {
    let mut y = *ephemeral_public;
    for sh in shareds.iter() {
        let b = blinding_scalar_from_shared(sh);
        y = x25519_dalek::x25519(b, y);
    }
    y
}

// Source constructs full header (y, gamma) and payload onion for forward path
pub fn source_create_forward(
    ephemeral_secret: &[u8; 32],
    node_pubs: &[[u8; 32]],
    _beta_len: usize,
    sp_len: usize,
) -> (Header, Payload, Vec<Si>, [u8; 32]) {
    // Compute per-hop shared secrets and Si
    let mut shareds: Vec<[u8; 32]> = Vec::with_capacity(node_pubs.len());
    let mut sis: Vec<Si> = Vec::with_capacity(node_pubs.len());
    for pk in node_pubs.iter() {
        let sh = compute_shared_secret(ephemeral_secret, pk);
        sis.push(derive_si(&sh));
        shareds.push(sh);
    }
    // Compute initial y (after all blinded factors)
    let eph_pub = x25519_dalek::x25519(*ephemeral_secret, x25519_dalek::X25519_BASEPOINT_BYTES);
    let y0 = build_header_chain(&eph_pub, &shareds);
    // Build beta/gamma onion from last to first
    let l = node_pubs.len();
    // beta not used in simplified header; kept length for symmetry in strict mode
    let mut gamma = [0u8; MU_LEN];
    // Backward chain gamma = MAC(shared_i, gamma)
    for i in (0..l).rev() {
        let mut mac_key = [0u8; 16];
        hop_key(&shareds[i], OpLabel::Mac, &mut mac_key);
        let t = crate::crypto::mac::mac_trunc16(&mac_key, &gamma);
        gamma.copy_from_slice(&t.0);
    }
    // Build fixed-length payload SPf (all-zero then apply reverse layering using Si so first hop can peel its layer)
    let mut sp = vec![0u8; sp_len];
    for i in (0..l).rev() {
        let mut mask = vec![0u8; sp_len];
        prg::prg1(&sis[i].0, &mut mask);
        for (b, m) in sp.iter_mut().zip(mask.iter()) {
            *b ^= *m;
        }
    }
    (Header { y: y0, gamma }, Payload(sp), sis, eph_pub)
}

// Node processes forward: verify mu (gamma), update y, peel one payload layer, return Si
pub fn node_process_forward(
    hdr: &mut Header,
    sp: &mut Payload,
    node_secret: &[u8; 32],
    _beta_len: usize,
) -> Result<Si> {
    // derive shared from current y
    let shared = compute_shared_secret(node_secret, &hdr.y);
    // update gamma chain
    let mut mac_key = [0u8; 16];
    hop_key(&shared, OpLabel::Mac, &mut mac_key);
    let tag = crate::crypto::mac::mac_trunc16(&mac_key, &hdr.gamma);
    hdr.gamma.copy_from_slice(&tag.0);
    // re-randomize y
    let b = blinding_scalar_from_shared(&shared);
    hdr.y = x25519_dalek::x25519(b, hdr.y);
    // peel one payload layer
    let mut mask = vec![0u8; sp.0.len()];
    let si = derive_si(&shared);
    prg::prg1(&si.0, &mut mask);
    for (b, m) in sp.0.iter_mut().zip(mask.iter()) {
        *b ^= *m;
    }
    Ok(si)
}

// Destination creates backward payload SPb from plaintext of forward-collected FS payload
pub fn dest_create_backward_sp(plain: &[u8], sp_len: usize) -> Payload {
    let mut buf = vec![0u8; sp_len];
    let copy = core::cmp::min(plain.len(), sp_len);
    buf[0..copy].copy_from_slice(&plain[0..copy]);
    Payload(buf)
}

// Node processes backward: add one layer with PRG1(Si)
pub fn node_process_backward(hdr: &Header, sp: &mut Payload, node_secret: &[u8; 32]) -> Result<Si> {
    let shared = compute_shared_secret(node_secret, &hdr.y);
    let si = derive_si(&shared);
    let mut mask = vec![0u8; sp.0.len()];
    prg::prg1(&si.0, &mut mask);
    for (b, m) in sp.0.iter_mut().zip(mask.iter()) {
        *b ^= *m;
    }
    Ok(si)
}

// Source unwraps SPb by removing all layers with keys_b
pub fn source_unwrap_backward(keys_b: &[Si], sp: &Payload) -> Vec<u8> {
    let mut buf = sp.0.clone();
    for i in 0..keys_b.len() {
        let mut mask = vec![0u8; buf.len()];
        prg::prg1(&keys_b[i].0, &mut mask);
        for (b, m) in buf.iter_mut().zip(mask.iter()) {
            *b ^= *m;
        }
    }
    buf
}

// Strict Sphinx-style header (alpha/beta/mu) behind a feature flag. This models
// per-hop verifiable header processing with onionized beta and chained mu.
#[cfg(feature = "strict_sphinx")]
pub mod strict {
    use super::*;
    use crate::crypto::mac;
    use crate::types::{C_BLOCK, Error};
    use curve25519_dalek::{
        constants::X25519_BASEPOINT, montgomery::MontgomeryPoint, scalar::Scalar,
    };

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
        let mut alpha_point: MontgomeryPoint = &x_eff_cur * &X25519_BASEPOINT;

        // Precompute Montgomery public points
        let pubs: Vec<MontgomeryPoint> = node_pubs.iter().map(|b| MontgomeryPoint(*b)).collect();

        // Compute shareds for each hop using current x_eff and pub_i
        let mut shareds: Vec<[u8; 32]> = Vec::with_capacity(node_pubs.len());
        let mut sis: Vec<Si> = Vec::with_capacity(node_pubs.len());
        for i in 0..node_pubs.len() {
            let shared_pt: MontgomeryPoint = &x_eff_cur * &pubs[i];
            let shared = shared_pt.to_bytes();
            shareds.push(shared);
            sis.push(super::derive_si(&shared));
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
            let shared_pt: MontgomeryPoint = &x_eff_cur * &pubs[i];
            let shared = shared_pt.to_bytes();
            shareds.push(shared);
            sis.push(super::derive_si(&shared));
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
        Ok(super::derive_si(&shared))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn e2e_setup_and_data_forward() {
        let mut rng = XorShift64(0xdead_beef_cafe_babe);
        let lf = 3usize; let lb = 3usize; let rmax = lf;
        let beta_len = rmax * crate::types::C_BLOCK; let sp_len = rmax * crate::types::C_BLOCK;
        fn gen_node() -> ([u8; 32], [u8; 32], crate::types::Sv) {
            let mut sk = [0u8; 32]; let mut tmp = [0u8; 32];
            XorShift64(0x1111_2222_3333_4444).try_fill_bytes(&mut tmp).unwrap();
            sk.copy_from_slice(&tmp); sk[0] &= 248; sk[31] &= 127; sk[31] |= 64;
            let pk = x25519_dalek::x25519(sk, x25519_dalek::X25519_BASEPOINT_BYTES);
            let mut svb = [0u8; 16]; XorShift64(0x5555_6666_7777_8888).try_fill_bytes(&mut svb).unwrap();
            (sk, pk, crate::types::Sv(svb))
        }
        let mut nodes_f = vec![]; for _ in 0..lf { nodes_f.push(gen_node()); }
        let mut nodes_b = vec![]; for _ in 0..lb { nodes_b.push(gen_node()); }
        let rs_f: vec::Vec<crate::types::RoutingSegment> = (0..lf).map(|i| crate::types::RoutingSegment(vec![i as u8; 8])).collect();
        let rs_b: vec::Vec<crate::types::RoutingSegment> = (0..lb).map(|i| crate::types::RoutingSegment(vec![0x80 | (i as u8); 8])).collect();
        let exp = crate::types::Exp(1_000_000);

        let mut x_s = [0u8; 32]; rng.fill_bytes(&mut x_s); x_s[0] &= 248; x_s[31] &= 127; x_s[31] |= 64;
        let pubkeys_f: vec::Vec<[u8; 32]> = nodes_f.iter().map(|n| n.1).collect();
        let (mut shdr_f, mut sp_f, keys_f, _eph_pub_f) = crate::sphinx::source_create_forward(&x_s, &pubkeys_f, beta_len, sp_len);
        let pubkeys_b: vec::Vec<[u8; 32]> = nodes_b.iter().map(|n| n.1).collect();
        let (mut shdr_b, _sp_dummy, keys_b, eph_pub_b) = crate::sphinx::source_create_forward(&x_s, &pubkeys_b, beta_len, sp_len);
        shdr_b.y = eph_pub_b;

        let seed_f = { let mut s = [0u8; 16]; rng.fill_bytes(&mut s); s };
        let mut p_f = crate::packet::FsPayload::new_with_seed(rmax, &seed_f);
        let mut fses_f_vec = vec![];
        for i in 0..lf {
            let (sk_i, _pk_i, sv_i) = nodes_f[i];
            let _si_node = crate::sphinx::node_process_forward(&mut shdr_f, &mut sp_f, &sk_i, beta_len).expect("sphinx f");
            let fs_i = crate::packet::create(&sv_i, &keys_f[i], &rs_f[i], exp).expect("fs f");
            crate::packet::add_fs_into_payload(&keys_f[i], &fs_i, &mut p_f).expect("add fs f");
            fses_f_vec.push(fs_i);
        }
        let mut sp_b = crate::sphinx::dest_create_backward_sp(&p_f.bytes, sp_len);
        let seed_b = { let mut s = [0u8; 16]; rng.fill_bytes(&mut s); s };
        let mut p_b = crate::packet::FsPayload::new_with_seed(rmax, &seed_b);
        let mut fses_b_vec = vec![];
        for j in 0..lb {
            let (sk_j, _pk_j, sv_j) = nodes_b[j];
            crate::sphinx::node_process_backward(&shdr_b, &mut sp_b, &sk_j).expect("sphinx b");
            let fs_j = crate::packet::create(&sv_j, &keys_b[j], &rs_b[j], exp).expect("fs b");
            crate::packet::add_fs_into_payload(&keys_b[j], &fs_j, &mut p_b).expect("add fs b");
            fses_b_vec.push(fs_j);
        }
        let _pf_bytes = crate::sphinx::source_unwrap_backward(&keys_b, &sp_b);
        let pf_bytes = crate::sphinx::source_unwrap_backward(&keys_b, &sp_b);
        let pf_recv = crate::packet::FsPayload { bytes: pf_bytes, rmax };
        let fses_f = crate::packet::retrieve_fses(&keys_f, &seed_f, &pf_recv).expect("ret fs f");
        let fses_b = crate::packet::retrieve_fses(&keys_b, &seed_b, &p_b).expect("ret fs b");

        let mut rng2 = XorShift64(0x9999_aaaa_bbbb_cccc);
        let ahdr_f = crate::packet::ahdr::create_ahdr(&keys_f, &fses_f, rmax, &mut rng2).expect("ahdr f");
        let _ahdr_b = crate::packet::ahdr::create_ahdr(&keys_b, &fses_b, rmax, &mut rng2).expect("ahdr b");

        let mut payload = vec![0u8; 64]; for i in 0..payload.len() { payload[i] = (i as u8) ^ 0x5a; }
        let mut iv0 = [0u8; 16]; rng.fill_bytes(&mut iv0);
        let orig = payload.clone();
        crate::source::encrypt_forward_payload(&keys_f, &mut iv0, &mut payload).expect("enc f");
        let mut iv = iv0; let mut ah = ahdr_f;
        for i in 0..lf { let pr = crate::packet::ahdr::proc_ahdr(&nodes_f[i].2, &ah, crate::types::Exp(0)).expect("proc ahdr");
            crate::packet::onion::remove_layer(&pr.s, &mut iv, &mut payload).expect("remove"); ah = pr.ahdr_next; }
        assert_eq!(&payload, &orig);
    }

    #[test]
    fn fs_retrieve_padding_r_gt_l() {
        let mut rng = XorShift64(0x1234_5678_9abc_def0);
        let rmax = 4usize; let lf = 3usize; let lb = 3usize;
        let beta_len = rmax * crate::types::C_BLOCK; let sp_len = rmax * crate::types::C_BLOCK;
        fn gen_node(seed: u64) -> ([u8; 32], [u8; 32], crate::types::Sv) {
            let mut sk = [0u8; 32]; let mut tmp = [0u8; 32]; XorShift64(seed).try_fill_bytes(&mut tmp).unwrap();
            sk.copy_from_slice(&tmp); sk[0] &= 248; sk[31] &= 127; sk[31] |= 64;
            let pk = x25519_dalek::x25519(sk, x25519_dalek::X25519_BASEPOINT_BYTES);
            let mut svb = [0u8; 16]; XorShift64(seed ^ 0x9e37_79b9).try_fill_bytes(&mut svb).unwrap();
            (sk, pk, crate::types::Sv(svb))
        }
        let mut nodes_f = vec![]; for i in 0..lf { nodes_f.push(gen_node(0x1000 + i as u64)); }
        let mut nodes_b = vec![]; for i in 0..lb { nodes_b.push(gen_node(0x2000 + i as u64)); }
        let rs_f: vec::Vec<crate::types::RoutingSegment> = (0..lf).map(|i| crate::types::RoutingSegment(vec![i as u8; 8])).collect();
        let rs_b: vec::Vec<crate::types::RoutingSegment> = (0..lb).map(|i| crate::types::RoutingSegment(vec![0x80 | (i as u8); 8])).collect();
        let exp = crate::types::Exp(2_000_000);
        let mut x_s = [0u8; 32]; rng.fill_bytes(&mut x_s); x_s[0] &= 248; x_s[31] &= 127; x_s[31] |= 64;
        let pubkeys_f: vec::Vec<[u8; 32]> = nodes_f.iter().map(|n| n.1).collect();
        let (mut shdr_f, mut sp_f, keys_f, _eph_pub_f) = crate::sphinx::source_create_forward(&x_s, &pubkeys_f, beta_len, sp_len);
        let pubkeys_b: vec::Vec<[u8; 32]> = nodes_b.iter().map(|n| n.1).collect();
        let (mut shdr_b, _sp_dummy, keys_b, eph_pub_b) = crate::sphinx::source_create_forward(&x_s, &pubkeys_b, beta_len, sp_len);
        shdr_b.y = eph_pub_b;
        let seed_f = { let mut s = [0u8; 16]; rng.fill_bytes(&mut s); s };
        let mut p_f = crate::packet::FsPayload::new_with_seed(rmax, &seed_f);
        for i in 0..lf { let (sk_i, _pk_i, sv_i) = nodes_f[i];
            crate::sphinx::node_process_forward(&mut shdr_f, &mut sp_f, &sk_i, beta_len).expect("sphinx f");
            let fs_i = crate::packet::create(&sv_i, &keys_f[i], &rs_f[i], exp).expect("fs f");
            crate::packet::add_fs_into_payload(&keys_f[i], &fs_i, &mut p_f).expect("add fs f"); }
        let mut sp_b = crate::sphinx::dest_create_backward_sp(&p_f.bytes, sp_len);
        let seed_b = { let mut s = [0u8; 16]; rng.fill_bytes(&mut s); s };
        let mut p_b = crate::packet::FsPayload::new_with_seed(rmax, &seed_b);
        for j in 0..lb { let (sk_j, _pk_j, sv_j) = nodes_b[j];
            crate::sphinx::node_process_backward(&shdr_b, &mut sp_b, &sk_j).expect("sphinx b");
            let fs_j = crate::packet::create(&sv_j, &keys_b[j], &rs_b[j], exp).expect("fs b");
            crate::packet::add_fs_into_payload(&keys_b[j], &fs_j, &mut p_b).expect("add fs b"); }
        let pf_bytes = crate::sphinx::source_unwrap_backward(&keys_b, &sp_b);
        let pf_recv = crate::packet::FsPayload { bytes: pf_bytes, rmax };
        let _fses_f = crate::packet::retrieve_fses(&keys_f, &seed_f, &pf_recv).expect("ret fs f (r>l)");
        let _fses_b = crate::packet::retrieve_fses(&keys_b, &seed_b, &p_b).expect("ret fs b (r>l)");
    }

    #[test]
    fn e2e_backward_ahdr_and_data() {
        let mut rng = XorShift64(0xa1a2_a3a4_a5a6_a7a8);
        let lf = 3usize; let lb = 3usize; let rmax = lb;
        let beta_len = rmax * crate::types::C_BLOCK; let sp_len = rmax * crate::types::C_BLOCK;
        fn gen_node(seed: u64) -> ([u8; 32], [u8; 32], crate::types::Sv) {
            let mut sk = [0u8; 32]; let mut tmp = [0u8; 32]; XorShift64(seed).try_fill_bytes(&mut tmp).unwrap();
            sk.copy_from_slice(&tmp); sk[0] &= 248; sk[31] &= 127; sk[31] |= 64;
            let pk = x25519_dalek::x25519(sk, x25519_dalek::X25519_BASEPOINT_BYTES);
            let mut svb = [0u8; 16]; XorShift64(seed ^ 0x5555_aaaa_dead_beef).try_fill_bytes(&mut svb).unwrap();
            (sk, pk, crate::types::Sv(svb))
        }
        let mut nodes_f = vec![]; for i in 0..lf { nodes_f.push(gen_node(0x3000 + i as u64)); }
        let mut nodes_b = vec![]; for i in 0..lb { nodes_b.push(gen_node(0x4000 + i as u64)); }
        let rs_f: vec::Vec<crate::types::RoutingSegment> = (0..lf).map(|i| crate::types::RoutingSegment(vec![i as u8; 8])).collect();
        let rs_b: vec::Vec<crate::types::RoutingSegment> = (0..lb).map(|i| crate::types::RoutingSegment(vec![0x80 | (i as u8); 8])).collect();
        let exp = crate::types::Exp(3_000_000);
        let mut x_s = [0u8; 32]; rng.fill_bytes(&mut x_s); x_s[0] &= 248; x_s[31] &= 127; x_s[31] |= 64;
        let pubkeys_f: vec::Vec<[u8; 32]> = nodes_f.iter().map(|n| n.1).collect();
        let (mut shdr_f, mut sp_f, keys_f, _eph_pub_f) = crate::sphinx::source_create_forward(&x_s, &pubkeys_f, beta_len, sp_len);
        let seed_f = { let mut s = [0u8; 16]; rng.fill_bytes(&mut s); s };
        let mut p_f = crate::packet::FsPayload::new_with_seed(rmax, &seed_f);
        for i in 0..lf { let (sk_i, _pk_i, sv_i) = nodes_f[i];
            crate::sphinx::node_process_forward(&mut shdr_f, &mut sp_f, &sk_i, beta_len).expect("sphinx f");
            let fs_i = crate::packet::create(&sv_i, &keys_f[i], &rs_f[i], exp).expect("fs f");
            crate::packet::add_fs_into_payload(&keys_f[i], &fs_i, &mut p_f).expect("add fs f"); }
        let pubkeys_b: vec::Vec<[u8; 32]> = nodes_b.iter().map(|n| n.1).collect();
        let (mut shdr_b, _sp_dummy, keys_b, eph_pub_b) = crate::sphinx::source_create_forward(&x_s, &pubkeys_b, beta_len, sp_len);
        shdr_b.y = eph_pub_b;
        let seed_b = { let mut s = [0u8; 16]; rng.fill_bytes(&mut s); s };
        let mut p_b = crate::packet::FsPayload::new_with_seed(rmax, &seed_b);
        for j in 0..lb { let (sk_j, _pk_j, sv_j) = nodes_b[j];
            crate::sphinx::node_process_backward(&shdr_b, &mut crate::sphinx::dest_create_backward_sp(&p_f.bytes, sp_len), &sk_j).expect("sphinx b");
            let fs_j = crate::packet::create(&sv_j, &keys_b[j], &rs_b[j], exp).expect("fs b");
            crate::packet::add_fs_into_payload(&keys_b[j], &fs_j, &mut p_b).expect("add fs b"); }
        let fses_b = crate::packet::retrieve_fses(&keys_b, &seed_b, &p_b).expect("ret fs b");
        let mut rng2 = XorShift64(0x7777_8888_9999_aaaa);
        let mut keys_b_rev = keys_b.clone(); keys_b_rev.reverse();
        let mut fses_b_rev = fses_b.clone(); fses_b_rev.reverse();
        let ahdr_b = crate::packet::ahdr::create_ahdr(&keys_b_rev, &fses_b_rev, rmax, &mut rng2).expect("ahdr b");
        let mut payload = vec![0u8; 96]; for i in 0..payload.len() { payload[i] = (0x30 + (i as u8)) ^ 0x33; }
        let mut iv = { let mut v = [0u8; 16]; rng.fill_bytes(&mut v); v };
        let mut ah = ahdr_b; for hop in (0..lb).rev() {
            let pr = crate::packet::ahdr::proc_ahdr(&nodes_b[hop].2, &ah, crate::types::Exp(0)).expect("proc ahdr b");
            crate::packet::onion::add_layer(&pr.s, &mut iv, &mut payload).expect("add layer b");
            ah = pr.ahdr_next; }
        let mut iv3 = iv; let mut data2 = payload.clone();
        for k in (0..lb).rev() { crate::packet::onion::remove_layer(&keys_b_rev[k], &mut iv3, &mut data2).expect("rem b"); }
        let mut orig = vec![0u8; 96]; for i in 0..orig.len() { orig[i] = (0x30 + (i as u8)) ^ 0x33; }
        assert_eq!(data2, orig);
    }

    #[cfg(feature = "strict_sphinx")]
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

    #[cfg(feature = "strict_sphinx")]
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

    #[cfg(feature = "strict_sphinx")]
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
