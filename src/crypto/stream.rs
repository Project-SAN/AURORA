use crate::crypto::kdf::{hop_key, OpLabel};
use crate::crypto::ctr;

pub fn encrypt(key_src: &[u8], iv: &[u8; 16], buf: &mut [u8]) {
    let mut k = [0u8; 16];
    hop_key(key_src, OpLabel::Enc, &mut k);
    ctr::apply_keystream(&k, iv, buf);
}

pub fn decrypt(key_src: &[u8], iv: &[u8; 16], buf: &mut [u8]) {
    let mut k = [0u8; 16];
    // Use the same key as enc since CTR is symmetric
    hop_key(key_src, OpLabel::Enc, &mut k);
    ctr::apply_keystream(&k, iv, buf);
}
