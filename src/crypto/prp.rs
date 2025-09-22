use crate::crypto::kdf::{hop_key, OpLabel};
use aes::Aes128;
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};

// PRP on 128-bit block (used for IV mutation and FS seal key-derivation)

pub fn prp_enc(key_src: &[u8], block: &mut [u8; 16]) {
    let mut k = [0u8; 16];
    hop_key(key_src, OpLabel::Prp, &mut k);
    let cipher = Aes128::new(GenericArray::from_slice(&k));
    let mut b = GenericArray::from_mut_slice(&mut block[..]);
    cipher.encrypt_block(&mut b);
}

pub fn prp_dec(key_src: &[u8], block: &mut [u8; 16]) {
    let mut k = [0u8; 16];
    hop_key(key_src, OpLabel::Prp, &mut k);
    let cipher = Aes128::new(GenericArray::from_slice(&k));
    let mut b = GenericArray::from_mut_slice(&mut block[..]);
    cipher.decrypt_block(&mut b);
}

pub fn prp_enc_bytes(key_src: &[u8], data: &mut [u8]) {
    assert!(data.len() % 16 == 0);
    let mut k = [0u8; 16];
    hop_key(key_src, OpLabel::Prp, &mut k);
    let cipher = Aes128::new(GenericArray::from_slice(&k));
    for chunk in data.chunks_mut(16) {
        let mut b = GenericArray::from_mut_slice(chunk);
        cipher.encrypt_block(&mut b);
    }
}

pub fn prp_dec_bytes(key_src: &[u8], data: &mut [u8]) {
    assert!(data.len() % 16 == 0);
    let mut k = [0u8; 16];
    hop_key(key_src, OpLabel::Prp, &mut k);
    let cipher = Aes128::new(GenericArray::from_slice(&k));
    for chunk in data.chunks_mut(16) {
        let mut b = GenericArray::from_mut_slice(chunk);
        cipher.decrypt_block(&mut b);
    }
}
