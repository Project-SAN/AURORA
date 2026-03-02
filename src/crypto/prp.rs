use crate::crypto::aegis::core::{encrypt_detached, TAG128_LEN};
use crate::crypto::kdf::{hop_key, OpLabel};
use crate::crypto::{mac, prg};
use alloc::vec;

extern crate alloc;

const FEISTEL_ROUNDS: usize = 8;

fn derive_prp_key(key_src: &[u8]) -> [u8; 16] {
    let mut k = [0u8; 16];
    hop_key(key_src, OpLabel::Prp, &mut k);
    k
}

pub fn prp_enc(key_src: &[u8], block: &mut [u8; 16]) {
    let k = derive_prp_key(key_src);
    feistel_encrypt_block(&k, block);
}

pub fn prp_dec(key_src: &[u8], block: &mut [u8; 16]) {
    let k = derive_prp_key(key_src);
    feistel_decrypt_block(&k, block);
}

pub fn prp_enc_bytes(key_src: &[u8], data: &mut [u8]) {
    assert!(data.len().is_multiple_of(16));
    let k = derive_prp_key(key_src);
    for chunk in data.chunks_mut(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        feistel_encrypt_block(&k, &mut block);
        chunk.copy_from_slice(&block);
    }
}

pub fn prp_dec_bytes(key_src: &[u8], data: &mut [u8]) {
    assert!(data.len().is_multiple_of(16));
    let k = derive_prp_key(key_src);
    for chunk in data.chunks_mut(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        feistel_decrypt_block(&k, &mut block);
        chunk.copy_from_slice(&block);
    }
}

fn pi_apply(key_src: &[u8], data: &mut [u8]) {
    if data.is_empty() {
        return;
    }
    let mut stream = vec![0u8; data.len()];
    prg::prg2(key_src, &mut stream);
    for (b, s) in data.iter_mut().zip(stream.iter()) {
        *b ^= *s;
    }
}

pub fn pi_encrypt(key_src: &[u8], data: &mut [u8]) {
    pi_apply(key_src, data)
}

pub fn pi_decrypt(key_src: &[u8], data: &mut [u8]) {
    pi_apply(key_src, data)
}

fn derive_lioness_keys(base: &[u8; 16]) -> ([u8; 16], [u8; 16], [u8; 16], [u8; 16]) {
    let mut k1 = [0u8; 16];
    let mut k2 = [0u8; 16];
    let mut k3 = [0u8; 16];
    let mut k4 = [0u8; 16];
    hop_key(base, OpLabel::Pi1, &mut k1);
    hop_key(base, OpLabel::Pi2, &mut k2);
    hop_key(base, OpLabel::Pi3, &mut k3);
    hop_key(base, OpLabel::Pi4, &mut k4);
    (k1, k2, k3, k4)
}

fn prg_with_tweak(key: &[u8; 16], tweak: &[u8; 16], out: &mut [u8]) {
    let mut seed = [0u8; 16];
    for (i, s) in seed.iter_mut().enumerate() {
        *s = key[i] ^ tweak[i];
    }
    prg::prg2(&seed, out);
}

fn feistel_encrypt_block(key: &[u8; 16], block: &mut [u8; 16]) {
    let mut l = [0u8; 8];
    let mut r = [0u8; 8];
    l.copy_from_slice(&block[..8]);
    r.copy_from_slice(&block[8..]);

    for round in 0..FEISTEL_ROUNDS {
        let f = prf_round(key, round as u8, &r);
        let mut next_r = [0u8; 8];
        for i in 0..8 {
            next_r[i] = l[i] ^ f[i];
        }
        l = r;
        r = next_r;
    }

    block[..8].copy_from_slice(&l);
    block[8..].copy_from_slice(&r);
}

fn feistel_decrypt_block(key: &[u8; 16], block: &mut [u8; 16]) {
    let mut l = [0u8; 8];
    let mut r = [0u8; 8];
    l.copy_from_slice(&block[..8]);
    r.copy_from_slice(&block[8..]);

    for round in (0..FEISTEL_ROUNDS).rev() {
        let ri = l;
        let f = prf_round(key, round as u8, &ri);
        let mut li = [0u8; 8];
        for i in 0..8 {
            li[i] = r[i] ^ f[i];
        }
        l = li;
        r = ri;
    }

    block[..8].copy_from_slice(&l);
    block[8..].copy_from_slice(&r);
}

fn prf_round(key: &[u8; 16], round: u8, input: &[u8; 8]) -> [u8; 8] {
    let mut nonce = [0u8; 16];
    nonce[0] = round;
    nonce[1..9].copy_from_slice(input);
    nonce[9] = 0xA5;
    let zeros = [0u8; 8];
    let (stream, _) = encrypt_detached(key, &nonce, b"AURORA-PRP", &zeros, TAG128_LEN)
        .expect("AEGIS-128L internal call with fixed tag size must succeed");
    let mut out = [0u8; 8];
    out.copy_from_slice(&stream[..8]);
    out
}

pub fn lioness_encrypt(key_src: &[u8], data: &mut [u8]) {
    assert!(key_src.len() == 16, "lioness key must be 16 bytes");
    assert!(data.len() >= 16, "lioness requires message >= 16 bytes");
    let mut base = [0u8; 16];
    base.copy_from_slice(key_src);
    let (k1, k2, k3, k4) = derive_lioness_keys(&base);
    let (l_slice, r_slice) = data.split_at_mut(16);
    let mut l = [0u8; 16];
    l.copy_from_slice(l_slice);

    if !r_slice.is_empty() {
        let mut ks = vec![0u8; r_slice.len()];
        prg_with_tweak(&k1, &l, &mut ks);
        for (r, s) in r_slice.iter_mut().zip(ks.iter()) {
            *r ^= *s;
        }
    }

    let tag2 = mac::mac_trunc16(&k2, r_slice);
    for (l_b, t) in l.iter_mut().zip(tag2.0.iter()) {
        *l_b ^= *t;
    }

    if !r_slice.is_empty() {
        let mut ks = vec![0u8; r_slice.len()];
        prg_with_tweak(&k3, &l, &mut ks);
        for (r, s) in r_slice.iter_mut().zip(ks.iter()) {
            *r ^= *s;
        }
    }

    let tag4 = mac::mac_trunc16(&k4, r_slice);
    for (l_b, t) in l.iter_mut().zip(tag4.0.iter()) {
        *l_b ^= *t;
    }

    l_slice.copy_from_slice(&l);
}

pub fn lioness_decrypt(key_src: &[u8], data: &mut [u8]) {
    assert!(key_src.len() == 16, "lioness key must be 16 bytes");
    assert!(data.len() >= 16, "lioness requires message >= 16 bytes");
    let mut base = [0u8; 16];
    base.copy_from_slice(key_src);
    let (k1, k2, k3, k4) = derive_lioness_keys(&base);
    let (l_slice, r_slice) = data.split_at_mut(16);
    let mut l = [0u8; 16];
    l.copy_from_slice(l_slice);

    let tag4 = mac::mac_trunc16(&k4, r_slice);
    for (l_b, t) in l.iter_mut().zip(tag4.0.iter()) {
        *l_b ^= *t;
    }

    if !r_slice.is_empty() {
        let mut ks = vec![0u8; r_slice.len()];
        prg_with_tweak(&k3, &l, &mut ks);
        for (r, s) in r_slice.iter_mut().zip(ks.iter()) {
            *r ^= *s;
        }
    }

    let tag2 = mac::mac_trunc16(&k2, r_slice);
    for (l_b, t) in l.iter_mut().zip(tag2.0.iter()) {
        *l_b ^= *t;
    }

    if !r_slice.is_empty() {
        let mut ks = vec![0u8; r_slice.len()];
        prg_with_tweak(&k1, &l, &mut ks);
        for (r, s) in r_slice.iter_mut().zip(ks.iter()) {
            *r ^= *s;
        }
    }

    l_slice.copy_from_slice(&l);
}

#[cfg(test)]
mod tests {
    use super::{prp_dec, prp_dec_bytes, prp_enc, prp_enc_bytes};
    use alloc::vec;
    use rand_chacha::ChaCha20Rng;
    use rand_core::{RngCore, SeedableRng};

    #[test]
    fn prp_block_roundtrip_randomized() {
        let mut rng = ChaCha20Rng::seed_from_u64(0xA570_A55A);
        for _ in 0..256 {
            let mut key = [0u8; 16];
            let mut block = [0u8; 16];
            rng.fill_bytes(&mut key);
            rng.fill_bytes(&mut block);
            let orig = block;
            prp_enc(&key, &mut block);
            prp_dec(&key, &mut block);
            assert_eq!(block, orig);
        }
    }

    #[test]
    fn prp_bytes_roundtrip_multiple_blocks() {
        let mut rng = ChaCha20Rng::seed_from_u64(0x1A2B_3C4D);
        let mut key = [0u8; 16];
        rng.fill_bytes(&mut key);
        let mut data = vec![0u8; 16 * 12];
        rng.fill_bytes(&mut data);
        let orig = data.clone();
        prp_enc_bytes(&key, &mut data);
        assert_ne!(data, orig);
        prp_dec_bytes(&key, &mut data);
        assert_eq!(data, orig);
    }
}
