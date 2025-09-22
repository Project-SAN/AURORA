use crate::crypto::kdf::{hop_key, OpLabel};
use aes::Aes128;
use ctr::cipher::{generic_array::GenericArray, KeyIvInit, StreamCipher};

type Aes128Ctr = ctr::Ctr128BE<Aes128>;

pub fn enc(key_src: &[u8], iv: &[u8; 16], buf: &mut [u8]) {
    let mut k = [0u8; 16];
    hop_key(key_src, OpLabel::Enc, &mut k);
    let mut cipher = Aes128Ctr::new(GenericArray::from_slice(&k), GenericArray::from_slice(iv));
    cipher.apply_keystream(buf);
}

pub fn dec(key_src: &[u8], iv: &[u8; 16], buf: &mut [u8]) {
    let mut k = [0u8; 16];
    // Use the same key as enc since CTR is symmetric
    hop_key(key_src, OpLabel::Enc, &mut k);
    let mut cipher = Aes128Ctr::new(GenericArray::from_slice(&k), GenericArray::from_slice(iv));
    cipher.apply_keystream(buf);
}
