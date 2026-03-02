use alloc::vec;

use crate::crypto::aegis::core::{encrypt_detached, TAG128_LEN};

pub fn apply_keystream(key: &[u8; 16], iv: &[u8; 16], buf: &mut [u8]) {
    if buf.is_empty() {
        return;
    }

    let zeros = vec![0u8; buf.len()];
    let (stream, _) = encrypt_detached(key, iv, &[], &zeros, TAG128_LEN)
        .expect("AEGIS-128L internal call with fixed tag size must succeed");
    for (dst, src) in buf.iter_mut().zip(stream.iter()) {
        *dst ^= *src;
    }
}
