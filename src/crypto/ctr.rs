use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};

#[cfg(feature = "hornet-log")]
macro_rules! hlog {
    ($($tt:tt)*) => {
        crate::log::emit(core::format_args!($($tt)*));
    };
}

#[cfg(not(feature = "hornet-log"))]
macro_rules! hlog {
    ($($tt:tt)*) => {};
}

pub fn apply_keystream(key: &[u8; 16], iv: &[u8; 16], buf: &mut [u8]) {
    hlog!("ctr: aes init");
    let cipher = Aes128::new(key.into());
    hlog!("ctr: aes init done");
    let mut counter = *iv;
    let mut block = [0u8; 16];
    let mut offset = 0usize;
    while offset < buf.len() {
        block.copy_from_slice(&counter);
        let block_ga = GenericArray::from_mut_slice(&mut block);
        cipher.encrypt_block(block_ga);
        let take = (buf.len() - offset).min(16);
        for i in 0..take {
            buf[offset + i] ^= block[i];
        }
        incr_be(&mut counter);
        offset += take;
    }
    hlog!("ctr: done");
}

fn incr_be(counter: &mut [u8; 16]) {
    for b in counter.iter_mut().rev() {
        let (new, carry) = b.overflowing_add(1);
        *b = new;
        if !carry {
            break;
        }
    }
}
