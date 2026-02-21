use crate::crypto::ctr;
use crate::crypto::kdf::{hop_key, OpLabel};

pub fn encrypt(key_src: &[u8], iv: &[u8; 16], buf: &mut [u8]) {
    let mut k = [0u8; 16];
    hop_key(key_src, OpLabel::Enc, &mut k);
    ctr::apply_keystream(&k, iv, buf);
}

pub fn decrypt(key_src: &[u8], iv: &[u8; 16], buf: &mut [u8]) {
    let mut k = [0u8; 16];
    // CTR mode is symmetric: decryption uses the same keystream as encryption,
    // so we intentionally reuse the encryption hop label here.
    hop_key(key_src, OpLabel::Enc, &mut k);
    ctr::apply_keystream(&k, iv, buf);
}
