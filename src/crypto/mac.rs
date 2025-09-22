use crate::types::{Error, Mac, Result};
use hmac::{Hmac, Mac as _};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub fn mac_trunc16(key: &[u8], data: &[u8]) -> Mac {
    let mut mac = HmacSha256::new_from_slice(key).expect("key len");
    mac.update(data);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&tag[..16]);
    Mac(out)
}

pub fn verify_trunc16(key: &[u8], data: &[u8], mac16: &Mac) -> Result<()> {
    let expected = mac_trunc16(key, data);
    if subtle::ConstantTimeEq::ct_eq(&expected.0[..], &mac16.0[..]).unwrap_u8() == 1 {
        Ok(())
    } else {
        Err(Error::InvalidMac)
    }
}
