use crate::crypto::aegis::core::apply_keystream_in_place;
use crate::crypto::kdf::{hop_key, OpLabel};

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
