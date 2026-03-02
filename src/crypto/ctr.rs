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

#[cfg(test)]
mod tests {
    use super::apply_keystream;

    #[test]
    fn keystream_is_symmetric() {
        let key = [0x42u8; 16];
        let iv = [0x11u8; 16];
        let mut data = *b"aurora-aegis-ctr-roundtrip";
        let orig = data;
        apply_keystream(&key, &iv, &mut data);
        assert_ne!(data, orig);
        apply_keystream(&key, &iv, &mut data);
        assert_eq!(data, orig);
    }
}
