use crate::crypto::aegis::core::apply_keystream_in_place;
use crate::crypto::kdf::{hop_key, OpLabel};
use alloc::vec;

fn prg(key_src: &[u8], out: &mut [u8], label: OpLabel) {
    let mut k = [0u8; 16];
    hop_key(key_src, label, &mut k);
    // Use zero nonce for deterministic stream expansion.
    let nonce = [0u8; 16];
    apply_keystream_in_place(&k, &nonce, out);
}

pub fn prg0(key_src: &[u8], out: &mut [u8]) {
    prg(key_src, out, OpLabel::Prg0)
}
pub fn prg1(key_src: &[u8], out: &mut [u8]) {
    prg(key_src, out, OpLabel::Prg1)
}
pub fn prg2(key_src: &[u8], out: &mut [u8]) {
    prg(key_src, out, OpLabel::Prg2)
}

pub fn xor_prg0(key_src: &[u8], data: &mut [u8]) {
    xor_prg(key_src, data, OpLabel::Prg0)
}

pub fn xor_prg2(key_src: &[u8], data: &mut [u8]) {
    xor_prg(key_src, data, OpLabel::Prg2)
}

fn xor_prg(key_src: &[u8], data: &mut [u8], label: OpLabel) {
    let mut mask = vec![0u8; data.len()];
    prg(key_src, &mut mask, label);
    for (byte, mask_byte) in data.iter_mut().zip(mask.iter()) {
        *byte ^= *mask_byte;
    }
}
