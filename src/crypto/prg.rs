use crate::crypto::kdf::{hop_key, OpLabel};
use crate::crypto::ctr;

fn prg(key_src: &[u8], out: &mut [u8], label: OpLabel) {
    let mut k = [0u8; 16];
    hop_key(key_src, label, &mut k);
    // Use zero IV for expanding into a keystream buffer.
    let iv = [0u8; 16];
    out.fill(0);
    ctr::apply_keystream(&k, &iv, out);
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
