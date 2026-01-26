use crate::types::{Mac, Result};

pub use crate::crypto::kdf::{hop_key, OpLabel};
pub use crate::crypto::mac::{mac_trunc16, verify_trunc16};
pub use crate::crypto::prg::{prg0, prg1, prg2};
pub use crate::crypto::prp::{
    lioness_decrypt, lioness_encrypt, prp_dec, prp_dec_bytes, prp_enc, prp_enc_bytes,
};
pub use crate::crypto::stream::{decrypt as stream_decrypt, encrypt as stream_encrypt};

pub trait CryptoOps {
    fn hop_key(&self, input: &[u8], op: OpLabel, out: &mut [u8]);
    fn prg0(&self, key_src: &[u8], out: &mut [u8]);
    fn prg1(&self, key_src: &[u8], out: &mut [u8]);
    fn prg2(&self, key_src: &[u8], out: &mut [u8]);
    fn prp_enc(&self, key_src: &[u8], block: &mut [u8; 16]);
    fn prp_dec(&self, key_src: &[u8], block: &mut [u8; 16]);
    fn prp_enc_bytes(&self, key_src: &[u8], data: &mut [u8]);
    fn prp_dec_bytes(&self, key_src: &[u8], data: &mut [u8]);
    fn mac_trunc16(&self, key: &[u8], data: &[u8]) -> Mac;
    fn verify_trunc16(&self, key: &[u8], data: &[u8], mac16: &Mac) -> Result<()>;
    fn stream_encrypt(&self, key_src: &[u8], iv: &[u8; 16], buf: &mut [u8]);
    fn stream_decrypt(&self, key_src: &[u8], iv: &[u8; 16], buf: &mut [u8]);
    fn lioness_encrypt(&self, key_src: &[u8], data: &mut [u8]);
    fn lioness_decrypt(&self, key_src: &[u8], data: &mut [u8]);
}

pub struct DefaultCryptoOps;

impl CryptoOps for DefaultCryptoOps {
    fn hop_key(&self, input: &[u8], op: OpLabel, out: &mut [u8]) {
        hop_key(input, op, out)
    }

    fn prg0(&self, key_src: &[u8], out: &mut [u8]) {
        prg0(key_src, out)
    }

    fn prg1(&self, key_src: &[u8], out: &mut [u8]) {
        prg1(key_src, out)
    }

    fn prg2(&self, key_src: &[u8], out: &mut [u8]) {
        prg2(key_src, out)
    }

    fn prp_enc(&self, key_src: &[u8], block: &mut [u8; 16]) {
        prp_enc(key_src, block)
    }

    fn prp_dec(&self, key_src: &[u8], block: &mut [u8; 16]) {
        prp_dec(key_src, block)
    }

    fn prp_enc_bytes(&self, key_src: &[u8], data: &mut [u8]) {
        prp_enc_bytes(key_src, data)
    }

    fn prp_dec_bytes(&self, key_src: &[u8], data: &mut [u8]) {
        prp_dec_bytes(key_src, data)
    }

    fn mac_trunc16(&self, key: &[u8], data: &[u8]) -> Mac {
        mac_trunc16(key, data)
    }

    fn verify_trunc16(&self, key: &[u8], data: &[u8], mac16: &Mac) -> Result<()> {
        verify_trunc16(key, data, mac16)
    }

    fn stream_encrypt(&self, key_src: &[u8], iv: &[u8; 16], buf: &mut [u8]) {
        stream_encrypt(key_src, iv, buf)
    }

    fn stream_decrypt(&self, key_src: &[u8], iv: &[u8; 16], buf: &mut [u8]) {
        stream_decrypt(key_src, iv, buf)
    }

    fn lioness_encrypt(&self, key_src: &[u8], data: &mut [u8]) {
        lioness_encrypt(key_src, data)
    }

    fn lioness_decrypt(&self, key_src: &[u8], data: &mut [u8]) {
        lioness_decrypt(key_src, data)
    }
}
