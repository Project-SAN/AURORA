use crate::crypto::kdf::{hop_key, OpLabel};
use aes::Aes128;
use ctr::cipher::{KeyIvInit, StreamCipher};

type Aes128Ctr = ctr::Ctr128BE<Aes128>;

pub fn encrypt(key_src: &[u8], iv: &[u8; 16], buf: &mut [u8]) {
    let mut k = [0u8; 16];
    hop_key(key_src, OpLabel::Enc, &mut k);
    let mut cipher = Aes128Ctr::new((&k).into(), iv.into());
    cipher.apply_keystream(buf);
}

pub fn decrypt(key_src: &[u8], iv: &[u8; 16], buf: &mut [u8]) {
    let mut k = [0u8; 16];
    // Use the same key as enc since CTR is symmetric
    hop_key(key_src, OpLabel::Enc, &mut k);
    let mut cipher = Aes128Ctr::new((&k).into(), iv.into());
    cipher.apply_keystream(buf);
}
