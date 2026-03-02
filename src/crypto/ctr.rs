use crate::crypto::aegis::core::apply_keystream_in_place;

pub fn apply_keystream(key: &[u8; 16], iv: &[u8; 16], buf: &mut [u8]) {
    apply_keystream_in_place(key, iv, buf);
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
