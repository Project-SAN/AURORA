use crate::crypto::kdf::{hop_key, OpLabel};
use crate::crypto::{mac, prg};
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use alloc::vec;

extern crate alloc;

fn derive_prp_key(key_src: &[u8]) -> [u8; 16] {
    let mut k = [0u8; 16];
    hop_key(key_src, OpLabel::Prp, &mut k);
    k
}

pub fn prp_enc(key_src: &[u8], block: &mut [u8; 16]) {
    let k = derive_prp_key(key_src);
    let cipher = Aes128::new((&k).into());
    cipher.encrypt_block(block.into());
}

pub fn prp_dec(key_src: &[u8], block: &mut [u8; 16]) {
    let k = derive_prp_key(key_src);
    let cipher = Aes128::new((&k).into());
    cipher.decrypt_block(block.into());
}

pub fn prp_enc_bytes(key_src: &[u8], data: &mut [u8]) {
    assert!(data.len().is_multiple_of(16));
    let k = derive_prp_key(key_src);
    let cipher = Aes128::new((&k).into());
    for chunk in data.chunks_mut(16) {
        cipher.encrypt_block(chunk.into());
    }
}

pub fn prp_dec_bytes(key_src: &[u8], data: &mut [u8]) {
    assert!(data.len().is_multiple_of(16));
    let k = derive_prp_key(key_src);
    let cipher = Aes128::new((&k).into());
    for chunk in data.chunks_mut(16) {
        cipher.decrypt_block(chunk.into());
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
