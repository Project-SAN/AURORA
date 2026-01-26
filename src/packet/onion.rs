use crate::crypto::ops::{prp_dec, prp_enc, stream_decrypt, stream_encrypt};
use crate::types::{Result, Si};

// {O', IV'} = ADD_LAYER(s, IV, O)
pub fn add_layer(s: &Si, iv: &mut [u8; 16], payload: &mut [u8]) -> Result<()> {
    stream_encrypt(&s.0, iv, payload);
    prp_enc(&s.0, iv);
    Ok(())
}

// {O', IV'} = REMOVE_LAYER(s, IV, O)
pub fn remove_layer(s: &Si, iv: &mut [u8; 16], payload: &mut [u8]) -> Result<()> {
    // Inverse of ADD_LAYER: first compute previous IV = PRP^{-1}(s; IV),
    // then decrypt with that IV, and update IV to previous.
    let mut prev = *iv;
    prp_dec(&s.0, &mut prev);
    stream_decrypt(&s.0, &prev, payload);
    *iv = prev;
    Ok(())
}
