use alloc::vec;
use alloc::vec::Vec;

use crate::types::{Error, Result};
use subtle::ConstantTimeEq;

pub const KEY_LEN: usize = 16;
pub const NONCE_LEN: usize = 16;
pub const TAG128_LEN: usize = 16;
pub const TAG256_LEN: usize = 32;

type Block = [u8; 16];
type State = [Block; 8];

const C0: Block = [
    0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62,
];
const C1: Block = [
    0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd,
];

const AES_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

fn check_tag_len(tag_len: usize) -> Result<()> {
    match tag_len {
        TAG128_LEN | TAG256_LEN => Ok(()),
        _ => Err(Error::Length),
    }
}

pub fn seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ad: &[u8],
    msg: &[u8],
    tag_len: usize,
) -> Result<Vec<u8>> {
    let (mut ct, tag) = encrypt_detached(key, nonce, ad, msg, tag_len)?;
    ct.extend_from_slice(&tag);
    Ok(ct)
}

pub fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ad: &[u8],
    data: &[u8],
    tag_len: usize,
) -> Result<Vec<u8>> {
    check_tag_len(tag_len)?;
    if data.len() < tag_len {
        return Err(Error::Length);
    }
    let split = data.len() - tag_len;
    decrypt_detached(key, nonce, ad, &data[..split], &data[split..])
}

pub fn encrypt_detached(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ad: &[u8],
    msg: &[u8],
    tag_len: usize,
) -> Result<(Vec<u8>, Vec<u8>)> {
    check_tag_len(tag_len)?;
    let mut state = init(*key, *nonce);
    absorb_data(&mut state, ad);
    let ct = encrypt_message(&mut state, msg);
    let tag = finalize(&mut state, ad.len(), msg.len(), tag_len);
    Ok((ct, tag))
}

pub fn decrypt_detached(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ad: &[u8],
    ct: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>> {
    check_tag_len(tag.len())?;
    let mut state = init(*key, *nonce);
    absorb_data(&mut state, ad);
    let mut msg = decrypt_message(&mut state, ct);
    let expected_tag = finalize(&mut state, ad.len(), msg.len(), tag.len());
    if expected_tag.ct_eq(tag).unwrap_u8() != 1 {
        msg.fill(0);
        return Err(Error::Crypto);
    }
    Ok(msg)
}

/// Apply AEGIS-128L-derived keystream directly to `buf` in-place.
///
/// This is a stream-only helper for CTR-like internal use: no tag is produced
/// and no heap allocation is performed.
pub fn apply_keystream_in_place(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], buf: &mut [u8]) {
    if buf.is_empty() {
        return;
    }
    let mut state = init(*key, *nonce);
    let zero = [0u8; 16];
    let mut offset = 0usize;

    while offset + 32 <= buf.len() {
        let (z0, z1) = z_blocks(&state);
        for (dst, src) in buf[offset..offset + 16].iter_mut().zip(z0.iter()) {
            *dst ^= *src;
        }
        for (dst, src) in buf[offset + 16..offset + 32].iter_mut().zip(z1.iter()) {
            *dst ^= *src;
        }
        state_update(&mut state, zero, zero);
        offset += 32;
    }

    if offset < buf.len() {
        let (z0, z1) = z_blocks(&state);
        let rem = buf.len() - offset;
        let first = rem.min(16);
        for (dst, src) in buf[offset..offset + first].iter_mut().zip(z0.iter()) {
            *dst ^= *src;
        }
        if rem > 16 {
            let tail = rem - 16;
            for (dst, src) in buf[offset + 16..offset + 16 + tail]
                .iter_mut()
                .zip(z1.iter())
            {
                *dst ^= *src;
            }
        }
        state_update(&mut state, zero, zero);
    }
}

fn init(key: Block, nonce: Block) -> State {
    let key_nonce = xor_block(key, nonce);
    let mut state = [
        key_nonce,
        C1,
        C0,
        C1,
        key_nonce,
        xor_block(key, C0),
        xor_block(key, C1),
        xor_block(key, C0),
    ];
    for _ in 0..10 {
        state_update(&mut state, nonce, key);
    }
    state
}

fn absorb_data(state: &mut State, ad: &[u8]) {
    let mut offset = 0usize;
    while offset + 32 <= ad.len() {
        let m0 = load_block(&ad[offset..offset + 16]);
        let m1 = load_block(&ad[offset + 16..offset + 32]);
        state_update(state, m0, m1);
        offset += 32;
    }
    if offset < ad.len() {
        let mut last = [0u8; 32];
        let rem = ad.len() - offset;
        last[..rem].copy_from_slice(&ad[offset..]);
        let m0 = load_block(&last[..16]);
        let m1 = load_block(&last[16..]);
        state_update(state, m0, m1);
    }
}

fn encrypt_message(state: &mut State, msg: &[u8]) -> Vec<u8> {
    let mut ct = vec![0u8; msg.len()];
    let mut offset = 0usize;
    while offset + 32 <= msg.len() {
        let m0 = load_block(&msg[offset..offset + 16]);
        let m1 = load_block(&msg[offset + 16..offset + 32]);
        let (c0, c1) = enc_block(state, m0, m1);
        store_block(&mut ct[offset..offset + 16], c0);
        store_block(&mut ct[offset + 16..offset + 32], c1);
        offset += 32;
    }
    if offset < msg.len() {
        let mut last = [0u8; 32];
        let rem = msg.len() - offset;
        last[..rem].copy_from_slice(&msg[offset..]);
        let m0 = load_block(&last[..16]);
        let m1 = load_block(&last[16..]);
        let (c0, c1) = enc_block(state, m0, m1);
        let mut full = [0u8; 32];
        store_block(&mut full[..16], c0);
        store_block(&mut full[16..], c1);
        ct[offset..].copy_from_slice(&full[..rem]);
    }
    ct
}

fn decrypt_message(state: &mut State, ct: &[u8]) -> Vec<u8> {
    let mut msg = vec![0u8; ct.len()];
    let mut offset = 0usize;
    while offset + 32 <= ct.len() {
        let c0 = load_block(&ct[offset..offset + 16]);
        let c1 = load_block(&ct[offset + 16..offset + 32]);
        let (m0, m1) = dec_block(state, c0, c1);
        store_block(&mut msg[offset..offset + 16], m0);
        store_block(&mut msg[offset + 16..offset + 32], m1);
        offset += 32;
    }
    if offset < ct.len() {
        let rem = ct.len() - offset;
        let mut padded_ct = [0u8; 32];
        padded_ct[..rem].copy_from_slice(&ct[offset..]);
        let c0 = load_block(&padded_ct[..16]);
        let c1 = load_block(&padded_ct[16..]);

        let (z0, z1) = z_blocks(state);
        let m0 = xor_block(c0, z0);
        let m1 = xor_block(c1, z1);

        let mut full = [0u8; 32];
        store_block(&mut full[..16], m0);
        store_block(&mut full[16..], m1);
        msg[offset..].copy_from_slice(&full[..rem]);
        full[rem..].fill(0);
        let u0 = load_block(&full[..16]);
        let u1 = load_block(&full[16..]);
        state_update(state, u0, u1);
    }
    msg
}

fn finalize(
    state: &mut State,
    ad_len_bytes: usize,
    msg_len_bytes: usize,
    tag_len: usize,
) -> Vec<u8> {
    let mut lengths = [0u8; 16];
    let ad_bits = (ad_len_bytes as u64).wrapping_shl(3);
    let msg_bits = (msg_len_bytes as u64).wrapping_shl(3);
    lengths[..8].copy_from_slice(&ad_bits.to_le_bytes());
    lengths[8..].copy_from_slice(&msg_bits.to_le_bytes());

    let t = xor_block(state[2], lengths);
    for _ in 0..7 {
        state_update(state, t, t);
    }

    let mut tag0 = state[0];
    for slot in state.iter().take(7).skip(1) {
        tag0 = xor_block(tag0, *slot);
    }

    if tag_len == TAG128_LEN {
        return tag0.to_vec();
    }

    let mut tag1 = state[4];
    for slot in state.iter().take(8).skip(5) {
        tag1 = xor_block(tag1, *slot);
    }
    let mut out = Vec::with_capacity(TAG256_LEN);
    out.extend_from_slice(&tag0);
    out.extend_from_slice(&tag1);
    out
}

fn enc_block(state: &mut State, m0: Block, m1: Block) -> (Block, Block) {
    let (z0, z1) = z_blocks(state);
    let c0 = xor_block(m0, z0);
    let c1 = xor_block(m1, z1);
    state_update(state, m0, m1);
    (c0, c1)
}

fn dec_block(state: &mut State, c0: Block, c1: Block) -> (Block, Block) {
    let (z0, z1) = z_blocks(state);
    let m0 = xor_block(c0, z0);
    let m1 = xor_block(c1, z1);
    state_update(state, m0, m1);
    (m0, m1)
}

fn z_blocks(state: &State) -> (Block, Block) {
    let z0 = xor_block(xor_block(state[1], state[6]), and_block(state[2], state[3]));
    let z1 = xor_block(xor_block(state[2], state[5]), and_block(state[6], state[7]));
    (z0, z1)
}

fn state_update(state: &mut State, m0: Block, m1: Block) {
    let s0 = state[0];
    let s1 = state[1];
    let s2 = state[2];
    let s3 = state[3];
    let s4 = state[4];
    let s5 = state[5];
    let s6 = state[6];
    let s7 = state[7];
    state[0] = aes_round(s7, xor_block(s0, m0));
    state[1] = aes_round(s0, s1);
    state[2] = aes_round(s1, s2);
    state[3] = aes_round(s2, s3);
    state[4] = aes_round(s3, xor_block(s4, m1));
    state[5] = aes_round(s4, s5);
    state[6] = aes_round(s5, s6);
    state[7] = aes_round(s6, s7);
}

fn aes_round(input: Block, round_key: Block) -> Block {
    let mut sub = [0u8; 16];
    for i in 0..16 {
        sub[i] = AES_SBOX[input[i] as usize];
    }

    let shifted = [
        sub[0], sub[5], sub[10], sub[15], sub[4], sub[9], sub[14], sub[3], sub[8], sub[13], sub[2],
        sub[7], sub[12], sub[1], sub[6], sub[11],
    ];

    let mut mixed = [0u8; 16];
    for col in 0..4 {
        let i = col * 4;
        let a0 = shifted[i];
        let a1 = shifted[i + 1];
        let a2 = shifted[i + 2];
        let a3 = shifted[i + 3];
        mixed[i] = mul2(a0) ^ mul3(a1) ^ a2 ^ a3;
        mixed[i + 1] = a0 ^ mul2(a1) ^ mul3(a2) ^ a3;
        mixed[i + 2] = a0 ^ a1 ^ mul2(a2) ^ mul3(a3);
        mixed[i + 3] = mul3(a0) ^ a1 ^ a2 ^ mul2(a3);
    }
    xor_block(mixed, round_key)
}

#[inline]
fn mul2(x: u8) -> u8 {
    let hi = x & 0x80;
    let mut out = x << 1;
    if hi != 0 {
        out ^= 0x1b;
    }
    out
}

#[inline]
fn mul3(x: u8) -> u8 {
    mul2(x) ^ x
}

#[inline]
fn xor_block(a: Block, b: Block) -> Block {
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = a[i] ^ b[i];
    }
    out
}

#[inline]
fn and_block(a: Block, b: Block) -> Block {
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = a[i] & b[i];
    }
    out
}

#[inline]
fn load_block(input: &[u8]) -> Block {
    let mut out = [0u8; 16];
    out.copy_from_slice(&input[..16]);
    out
}

#[inline]
fn store_block(out: &mut [u8], block: Block) {
    out[..16].copy_from_slice(&block);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct PositiveVector {
        key: &'static str,
        nonce: &'static str,
        ad: &'static str,
        msg: &'static str,
        ct: &'static str,
        tag128: &'static str,
        tag256: &'static str,
    }

    struct NegativeVector {
        key: &'static str,
        nonce: &'static str,
        ad: &'static str,
        ct: &'static str,
        tag128: &'static str,
        tag256: &'static str,
    }

    #[test]
    fn aes_round_matches_spec_vector() {
        let input = block("000102030405060708090a0b0c0d0e0f");
        let rk = block("101112131415161718191a1b1c1d1e1f");
        let expected = block("7a7b4e5638782546a8c0477a3b813f43");
        assert_eq!(aes_round(input, rk), expected);
    }

    #[test]
    fn update_matches_spec_vector() {
        let mut state = [
            block("9b7e60b24cc873ea894ecc07911049a3"),
            block("330be08f35300faa2ebf9a7b0d274658"),
            block("7bbd5bd2b049f7b9b515cf26fbe7756c"),
            block("c35a00f55ea86c3886ec5e928f87db18"),
            block("9ebccafce87cab446396c4334592c91f"),
            block("58d83e31f256371e60fc6bb257114601"),
            block("1639b56ea322c88568a176585bc915de"),
            block("640818ffb57dc0fbc2e72ae93457e39a"),
        ];
        let m0 = block("033e6975b94816879e42917650955aa0");
        let m1 = block("fcc1968a46b7e97861bd6e89af6aa55f");
        state_update(&mut state, m0, m1);
        let expected = [
            block("596ab773e4433ca0127c73f60536769d"),
            block("790394041a3d26ab697bde865014652d"),
            block("38cf49e4b65248acd533041b64dd0611"),
            block("16d8e58748f437bfff1797f780337cee"),
            block("9689ecdf08228c74d7e3360cca53d0a5"),
            block("a21746bb193a569e331e1aa985d0d729"),
            block("09d714e6fcf9177a8ed1cde7e3d259a6"),
            block("61279ba73167f0ab76f0a11bf203bdff"),
        ];
        assert_eq!(state, expected);
    }

    #[test]
    fn encrypt_vectors_match_spec() {
        for tv in positive_vectors() {
            let key = block(tv.key);
            let nonce = block(tv.nonce);
            let ad = hex(tv.ad);
            let msg = hex(tv.msg);
            let expected_ct = hex(tv.ct);
            let expected_tag128 = hex(tv.tag128);
            let expected_tag256 = hex(tv.tag256);

            let (ct128, tag128) =
                encrypt_detached(&key, &nonce, &ad, &msg, TAG128_LEN).expect("encrypt 128");
            assert_eq!(ct128, expected_ct);
            assert_eq!(tag128, expected_tag128);

            let (ct256, tag256) =
                encrypt_detached(&key, &nonce, &ad, &msg, TAG256_LEN).expect("encrypt 256");
            assert_eq!(ct256, expected_ct);
            assert_eq!(tag256, expected_tag256);

            let dec128 = decrypt_detached(&key, &nonce, &ad, &ct128, &tag128).expect("decrypt 128");
            assert_eq!(dec128, msg);

            let dec256 = decrypt_detached(&key, &nonce, &ad, &ct256, &tag256).expect("decrypt 256");
            assert_eq!(dec256, msg);
        }
    }

    #[test]
    fn negative_vectors_fail_verification() {
        for tv in negative_vectors() {
            let key = block(tv.key);
            let nonce = block(tv.nonce);
            let ad = hex(tv.ad);
            let ct = hex(tv.ct);
            let tag128 = hex(tv.tag128);
            let tag256 = hex(tv.tag256);

            let err128 = decrypt_detached(&key, &nonce, &ad, &ct, &tag128).expect_err("must fail");
            assert_eq!(err128, Error::Crypto);

            let err256 = decrypt_detached(&key, &nonce, &ad, &ct, &tag256).expect_err("must fail");
            assert_eq!(err256, Error::Crypto);
        }
    }

    #[test]
    fn seal_and_open_roundtrip() {
        let key = block("10010000000000000000000000000000");
        let nonce = block("10000200000000000000000000000000");
        let ad = hex("0001020304050607");
        let msg = hex("000102030405060708090a0b0c0d");
        let encoded = seal(&key, &nonce, &ad, &msg, TAG128_LEN).expect("seal");
        let opened = open(&key, &nonce, &ad, &encoded, TAG128_LEN).expect("open");
        assert_eq!(opened, msg);
    }

    fn positive_vectors() -> [PositiveVector; 5] {
        [
            PositiveVector {
                key: "10010000000000000000000000000000",
                nonce: "10000200000000000000000000000000",
                ad: "",
                msg: "00000000000000000000000000000000",
                ct: "c1c0e58bd913006feba00f4b3cc3594e",
                tag128: "abe0ece80c24868a226a35d16bdae37a",
                tag256: "abe0ece80c24868a226a35d16bdae37acace4617af1bd0f7d064c639a5c79ee4",
            },
            PositiveVector {
                key: "10010000000000000000000000000000",
                nonce: "10000200000000000000000000000000",
                ad: "",
                msg: "",
                ct: "",
                tag128: "c2b879a67def9d74e6c14f708bbcc9b4",
                tag256: "c2b879a67def9d74e6c14f708bbcc9b4f2184c4e12120249335c4ee84bafe25d",
            },
            PositiveVector {
                key: "10010000000000000000000000000000",
                nonce: "10000200000000000000000000000000",
                ad: "0001020304050607",
                msg: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                ct: "79d94593d8c2119d7e8fd9b8fc77845c5c077a05b2528b6ac54b563aed8efe84",
                tag128: "cc6f3372f6aa1bb82388d695c3962d9a",
                tag256: "cc6f3372f6aa1bb82388d695c3962d9a4cfbab6528ddef89f17d74ef8ecd82b3",
            },
            PositiveVector {
                key: "10010000000000000000000000000000",
                nonce: "10000200000000000000000000000000",
                ad: "0001020304050607",
                msg: "000102030405060708090a0b0c0d",
                ct: "79d94593d8c2119d7e8fd9b8fc77",
                tag128: "5c04b3dba849b2701effbe32c7f0fab7",
                tag256: "5c04b3dba849b2701effbe32c7f0fab74a55a15dbfec81a76f35ed0b9c8b04ac",
            },
            PositiveVector {
                key: "10010000000000000000000000000000",
                nonce: "10000200000000000000000000000000",
                ad: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829",
                msg: "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637",
                ct: "b31052ad1cca4e291abcf2df3502e6bdb1bfd6db36798be3607b1f94d34478aa7ede7f7a990fec10",
                tag128: "7542a745733014f9474417b337399507",
                tag256: "7542a745733014f9474417b337399507fc835ff574aca3fc27c33be0db2aff98",
            },
        ]
    }

    fn negative_vectors() -> [NegativeVector; 4] {
        [
            NegativeVector {
                key: "10000200000000000000000000000000",
                nonce: "10010000000000000000000000000000",
                ad: "0001020304050607",
                ct: "79d94593d8c2119d7e8fd9b8fc77",
                tag128: "5c04b3dba849b2701effbe32c7f0fab7",
                tag256: "5c04b3dba849b2701effbe32c7f0fab74a55a15dbfec81a76f35ed0b9c8b04ac",
            },
            NegativeVector {
                key: "10010000000000000000000000000000",
                nonce: "10000200000000000000000000000000",
                ad: "0001020304050607",
                ct: "79d94593d8c2119d7e8fd9b8fc78",
                tag128: "5c04b3dba849b2701effbe32c7f0fab7",
                tag256: "5c04b3dba849b2701effbe32c7f0fab74a55a15dbfec81a76f35ed0b9c8b04ac",
            },
            NegativeVector {
                key: "10010000000000000000000000000000",
                nonce: "10000200000000000000000000000000",
                ad: "0001020304050608",
                ct: "79d94593d8c2119d7e8fd9b8fc77",
                tag128: "5c04b3dba849b2701effbe32c7f0fab7",
                tag256: "5c04b3dba849b2701effbe32c7f0fab74a55a15dbfec81a76f35ed0b9c8b04ac",
            },
            NegativeVector {
                key: "10010000000000000000000000000000",
                nonce: "10000200000000000000000000000000",
                ad: "0001020304050607",
                ct: "79d94593d8c2119d7e8fd9b8fc77",
                tag128: "6c04b3dba849b2701effbe32c7f0fab8",
                tag256: "86f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ad",
            },
        ]
    }

    fn hex(input: &str) -> Vec<u8> {
        let mut nibbles = Vec::new();
        for byte in input.bytes() {
            if byte.is_ascii_hexdigit() {
                nibbles.push(byte);
            }
        }
        assert_eq!(nibbles.len() % 2, 0, "hex must have even number of nibbles");
        let mut out = Vec::with_capacity(nibbles.len() / 2);
        let mut i = 0usize;
        while i < nibbles.len() {
            let hi = from_hex(nibbles[i]);
            let lo = from_hex(nibbles[i + 1]);
            out.push((hi << 4) | lo);
            i += 2;
        }
        out
    }

    fn block(input: &str) -> [u8; 16] {
        let bytes = hex(input);
        assert_eq!(bytes.len(), 16);
        let mut out = [0u8; 16];
        out.copy_from_slice(&bytes);
        out
    }

    fn from_hex(x: u8) -> u8 {
        match x {
            b'0'..=b'9' => x - b'0',
            b'a'..=b'f' => x - b'a' + 10,
            b'A'..=b'F' => x - b'A' + 10,
            _ => panic!("invalid hex nibble: {x}"),
        }
    }
}
