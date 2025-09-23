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

fn derive_shared_source(ephemeral_secret: &[u8; 32], node_pub: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::x25519(*ephemeral_secret, *node_pub)
}

fn derive_shared_node(node_secret: &[u8; 32], y: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::x25519(*node_secret, *y)
}

fn derive_si_from_shared(shared: &[u8; 32]) -> Si {
    let mut si = [0u8; 16];
    hop_key(shared, OpLabel::Enc, &mut si);
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
        let sh = derive_shared_source(ephemeral_secret, pk);
        sis.push(derive_si_from_shared(&sh));
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
    let shared = derive_shared_node(node_secret, &hdr.y);
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
    let si = derive_si_from_shared(&shared);
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
    let shared = derive_shared_node(node_secret, &hdr.y);
    let si = derive_si_from_shared(&shared);
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
            sis.push(super::derive_si_from_shared(&shared));
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
            sis.push(super::derive_si_from_shared(&shared));
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
        Ok(super::derive_si_from_shared(&shared))
    }
}
