use alloc::vec::Vec;

use crate::crypto::aegis::core::{open, seal, TAG128_LEN};
use crate::types::{Error, Result, Si};

const ONION_AD: &[u8] = b"AURORA-ONION-LAYER";

// {O', IV} = ADD_LAYER(s, IV, O)
// IV is used as the AEAD nonce for this packet and is carried unchanged.
pub fn add_layer(s: &Si, iv: &mut [u8; 16], payload: &mut Vec<u8>) -> Result<()> {
    let sealed = seal(&s.0, iv, ONION_AD, payload.as_slice(), TAG128_LEN)?;
    payload.clear();
    payload.extend_from_slice(&sealed);
    Ok(())
}

// {O, IV} = REMOVE_LAYER(s, IV, O')
pub fn remove_layer(s: &Si, iv: &mut [u8; 16], payload: &mut Vec<u8>) -> Result<()> {
    let opened = open(&s.0, iv, ONION_AD, payload.as_slice(), TAG128_LEN)?;
    payload.clear();
    payload.extend_from_slice(&opened);
    Ok(())
}

pub fn add_layer_suffix(
    s: &Si,
    iv: &mut [u8; 16],
    payload: &mut Vec<u8>,
    suffix_offset: usize,
) -> Result<()> {
    if suffix_offset > payload.len() {
        return Err(Error::Length);
    }
    let mut tail = payload[suffix_offset..].to_vec();
    add_layer(s, iv, &mut tail)?;
    payload.truncate(suffix_offset);
    payload.extend_from_slice(&tail);
    Ok(())
}

pub fn remove_layer_suffix(
    s: &Si,
    iv: &mut [u8; 16],
    payload: &mut Vec<u8>,
    suffix_offset: usize,
) -> Result<()> {
    if suffix_offset > payload.len() {
        return Err(Error::Length);
    }
    let mut tail = payload[suffix_offset..].to_vec();
    remove_layer(s, iv, &mut tail)?;
    payload.truncate(suffix_offset);
    payload.extend_from_slice(&tail);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    #[test]
    fn add_remove_roundtrip_and_tag_growth() {
        let s = Si([0x11; 16]);
        let mut iv = [0x22; 16];
        let mut payload = b"hello onion payload".to_vec();
        let plain = payload.clone();
        let iv_before = iv;

        add_layer(&s, &mut iv, &mut payload).expect("seal");
        assert_eq!(payload.len(), plain.len() + TAG128_LEN);
        assert_eq!(iv, iv_before);

        remove_layer(&s, &mut iv, &mut payload).expect("open");
        assert_eq!(payload, plain);
        assert_eq!(iv, iv_before);
    }

    #[test]
    fn suffix_roundtrip_preserves_prefix() {
        let s = Si([0x33; 16]);
        let mut iv = [0x44; 16];
        let mut payload = Vec::new();
        payload.extend_from_slice(b"PREFIX");
        payload.extend_from_slice(b"BODY-BODY");
        let original = payload.clone();
        let off = 6usize;

        add_layer_suffix(&s, &mut iv, &mut payload, off).expect("seal suffix");
        assert_eq!(&payload[..off], &original[..off]);
        assert_eq!(payload.len(), original.len() + TAG128_LEN);

        remove_layer_suffix(&s, &mut iv, &mut payload, off).expect("open suffix");
        assert_eq!(payload, original);
    }

    #[test]
    fn tampered_tag_is_rejected() {
        let s = Si([0x77; 16]);
        let mut iv = [0x88; 16];
        let mut payload = b"tamper-check".to_vec();
        add_layer(&s, &mut iv, &mut payload).expect("seal");
        let last = payload.len() - 1;
        payload[last] ^= 0x01;
        let err = remove_layer(&s, &mut iv, &mut payload).expect_err("must fail");
        assert_eq!(err, Error::Crypto);
    }

    #[test]
    fn suffix_offset_bounds_checked() {
        let s = Si([0x99; 16]);
        let mut iv = [0xAA; 16];
        let mut payload = vec![1, 2, 3];
        let err = add_layer_suffix(&s, &mut iv, &mut payload, 4).expect_err("oob");
        assert_eq!(err, Error::Length);
        let err = remove_layer_suffix(&s, &mut iv, &mut payload, 4).expect_err("oob");
        assert_eq!(err, Error::Length);
    }
}
