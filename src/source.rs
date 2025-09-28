use crate::types::{Ahdr, Chdr, Error, Nonce, Result, Si};
use rand_core::RngCore;

// (removed) initialize_session: thin AHDR wrapper was unnecessary

// Build a forward data packet payload per Alg.19:
// - Input: CHDR (Data), AHDR (forward), random nonce IV0, and plaintext payload.
// - Apply onion encryption layers with forward keys (last->first) to produce O0 and
//   update IV in-place to the value carried in CHDR for the first hop.
// Note: The forward per-hop keys Si must be provided by the caller based on the
// prior setup. This function does not derive keys from AHDR.
pub fn build_data_packet(
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
    for i in (0..keys_f.len()).rev() {
        crate::packet::onion::add_layer(&keys_f[i], &mut iv, payload)?;
    }
    // Update IV0 (for caller) and CHDR.specific to the final IV carried on the wire
    iv0.0 = iv;
    chdr.specific = iv;
    Ok(())
}

// Destination-side helper: build backward AHDR from per-hop keys and node contexts.
// The caller must provide keys in the order of traversal (destination -> ... -> source).
// (removed) dest_build_ahdr_b: tests inline the construction

// Place AHDRb into the first data payload buffer.
// (removed) embed_ahdrb_into_first_data_payload

// Extract AHDRb from the first data payload buffer.
// (removed) extract_ahdrb_from_first_data_payload

// Encrypt a forward payload at the source: apply layers from last to first
pub fn encrypt_forward_payload(keys: &[Si], iv0: &mut [u8; 16], payload: &mut [u8]) -> Result<()> {
    let mut iv = *iv0;
    for i in (0..keys.len()).rev() {
        crate::packet::onion::add_layer(&keys[i], &mut iv, payload)?;
    }
    *iv0 = iv;
    Ok(())
}

// Decrypt a backward payload at the source: remove layers from first to last
pub fn decrypt_backward_payload(keys: &[Si], iv0: &mut [u8; 16], payload: &mut [u8]) -> Result<()> {
    let mut iv = *iv0;
    for i in 0..keys.len() {
        crate::packet::onion::remove_layer(&keys[i], &mut iv, payload)?;
    }
    *iv0 = iv;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{CryptoRng, RngCore};

    struct XorShift64(u64);
    impl RngCore for XorShift64 {
        fn next_u32(&mut self) -> u32 { self.next_u64() as u32 }
        fn next_u64(&mut self) -> u64 { let mut x = self.0; x ^= x << 13; x ^= x >> 7; x ^= x << 17; self.0 = x; x }
        fn fill_bytes(&mut self, dest: &mut [u8]) { self.try_fill_bytes(dest).unwrap() }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand_core::Error> {
            let mut n = 0; while n < dest.len() { let v = self.next_u64().to_le_bytes(); let take = core::cmp::min(8, dest.len() - n); dest[n..n+take].copy_from_slice(&v[..take]); n += take; } Ok(())
        }
    }
    impl CryptoRng for XorShift64 {}

    #[test]
    fn build_data_packet_forward_end_to_end() {
        use crate::types::{C_BLOCK, Exp, RoutingSegment, Sv, Nonce};
        let mut rng = XorShift64(0xdead_beef_c0de_ca1f);
        let lf = 3usize; let rmax = lf; let beta_len = rmax * C_BLOCK; let sp_len = rmax * C_BLOCK;
        fn gen_node(seed: u64) -> ([u8; 32], [u8; 32], Sv) {
            let mut sk = [0u8; 32]; let mut tmp = [0u8; 32]; XorShift64(seed).try_fill_bytes(&mut tmp).unwrap();
            sk.copy_from_slice(&tmp); sk[0] &= 248; sk[31] &= 127; sk[31] |= 64;
            let pk = x25519_dalek::x25519(sk, x25519_dalek::X25519_BASEPOINT_BYTES);
            let mut svb = [0u8; 16]; XorShift64(seed ^ 0x1122_3344_5566_7788).try_fill_bytes(&mut svb).unwrap();
            (sk, pk, Sv(svb))
        }
        let mut nodes_f = alloc::vec::Vec::new(); for i in 0..lf { nodes_f.push(gen_node(0x5000 + i as u64)); }
        let rs_f: alloc::vec::Vec<RoutingSegment> = (0..lf).map(|i| RoutingSegment(alloc::vec![i as u8; 8])).collect();
        let exp = Exp(4_200_000);
        let mut x_s = [0u8; 32]; rng.fill_bytes(&mut x_s); x_s[0] &= 248; x_s[31] &= 127; x_s[31] |= 64;
        let pubkeys_f: alloc::vec::Vec<[u8; 32]> = nodes_f.iter().map(|n| n.1).collect();
        let (_shdr_f, _sp_f, keys_f, _eph_pub_f) = crate::sphinx::source_create_forward(&x_s, &pubkeys_f, beta_len, sp_len);
        let fses_f: alloc::vec::Vec<crate::types::Fs> = (0..lf)
            .map(|i| crate::packet::create(&nodes_f[i].2, &keys_f[i], &rs_f[i], exp).unwrap()).collect();
        let mut rng2 = XorShift64(0x0bad_cafe_dead_beef);
        let ahdr_f = crate::packet::ahdr::create_ahdr(&keys_f, &fses_f, rmax, &mut rng2).unwrap();
        let mut chdr = crate::packet::chdr::data_header(lf as u8, Nonce([0u8; 16]));
        let mut iv0 = Nonce([0u8; 16]); rng.fill_bytes(&mut iv0.0);
        let mut payload = alloc::vec![0u8; 80]; for i in 0..payload.len() { payload[i] = (0xa0 ^ (i as u8)).wrapping_add(7); }
        let orig = payload.clone();
        crate::source::build_data_packet(&mut chdr, &ahdr_f, &keys_f, &mut iv0, &mut payload).expect("build data packet");
        let mut ah = ahdr_f; let mut iv = chdr.specific;
        for i in 0..lf {
            let pr = crate::packet::ahdr::proc_ahdr(&nodes_f[i].2, &ah, Exp(0)).expect("proc");
            crate::packet::onion::remove_layer(&pr.s, &mut iv, &mut payload).expect("rem");
            ah = pr.ahdr_next;
        }
        assert_eq!(payload, orig);
    }
}
