use crate::crypto::kdf::{OpLabel, hop_key};
use aes::Aes128;
use ctr::cipher::{KeyIvInit, StreamCipher, generic_array::GenericArray};

type Aes128Ctr = ctr::Ctr128BE<Aes128>;

fn prg(key_src: &[u8], out: &mut [u8], label: OpLabel) {
    let mut k = [0u8; 16];
    hop_key(key_src, label, &mut k);
    // Use zero IV for expanding into a keystream buffer
    let iv = [0u8; 16];
    let mut cipher = Aes128Ctr::new(GenericArray::from_slice(&k), GenericArray::from_slice(&iv));
    cipher.apply_keystream(out);
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
