use crate::types::{Ahdr, Chdr, Error, Nonce, Result, Si};

// Build a forward data packet payload per Alg.19:
// - Input: CHDR (Data), AHDR (forward), random nonce IV0, and plaintext payload.
// - Apply onion encryption layers with forward keys (last->first) to produce O0 and
//   update IV in-place to the value carried in CHDR for the first hop.
// Note: The forward per-hop keys Si must be provided by the caller based on the
// prior setup. This function does not derive keys from AHDR.

/// Build a forward data packet payload by applying onion encryption layers.
pub fn build(
    chdr: &mut Chdr,
    _ahdr: &Ahdr,
    keys_f: &[Si],
    iv0: &mut Nonce,
    payload: &mut [u8],
) -> Result<()> {
    // CHDR must be a data header
    if !matches!(chdr.typ, crate::types::PacketType::Data) {
        return Err(Error::Length);
    }
    // Start from the provided IV0 (random nonce) and apply layers from last to first
    let mut iv = iv0.0;
    for key in keys_f.iter().rev() {
        crate::packet::onion::add_layer(key, &mut iv, payload)?;
    }
    // Update IV0 (for caller) and CHDR.specific to the final IV carried on the wire
    iv0.0 = iv;
    chdr.specific = iv;
    Ok(())
}

// Destination-side helper: build backward AHDR from per-hop keys and node contexts.
// The caller must provide keys in the order of traversal (destination -> ... -> source).
// Place AHDRb into the first data payload buffer.
// Extract AHDRb from the first data payload buffer.
// Encrypt a forward payload at the source: apply layers from last to first
pub fn encrypt_forward_payload(keys: &[Si], iv0: &mut [u8; 16], payload: &mut [u8]) -> Result<()> {
    let mut iv = *iv0;
    for key in keys.iter().rev() {
        crate::packet::onion::add_layer(key, &mut iv, payload)?;
    }
    *iv0 = iv;
    Ok(())
}

// Decrypt a backward payload at the source: remove layers from first to last
pub fn decrypt_backward_payload(keys: &[Si], iv0: &mut [u8; 16], payload: &mut [u8]) -> Result<()> {
    let mut iv = *iv0;
    for key in keys {
        crate::packet::onion::remove_layer(key, &mut iv, payload)?;
    }
    *iv0 = iv;
    Ok(())
}
