use crate::crypto::kdf::{hop_key, OpLabel};
use crate::crypto::ctr;

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

fn label_name(label: OpLabel) -> &'static str {
    match label {
        OpLabel::Prg0 => "prg0",
        OpLabel::Prg1 => "prg1",
        OpLabel::Prg2 => "prg2",
        OpLabel::Mac => "mac",
        OpLabel::Prp => "prp",
        OpLabel::Enc => "enc",
        OpLabel::Dec => "dec",
        OpLabel::Pi => "pi",
        OpLabel::Pi1 => "pi1",
        OpLabel::Pi2 => "pi2",
        OpLabel::Pi3 => "pi3",
        OpLabel::Pi4 => "pi4",
        OpLabel::Tau => "tau",
    }
}

fn prg(key_src: &[u8], out: &mut [u8], label: OpLabel) {
    let label_name = label_name(label);
    hlog!("prg: {} start len={}", label_name, out.len());
    let mut k = [0u8; 16];
    hlog!("prg: {} hop_key", label_name);
    hop_key(key_src, label, &mut k);
    // Use zero IV for expanding into a keystream buffer.
    let iv = [0u8; 16];
    out.fill(0);
    hlog!("prg: {} ctr apply", label_name);
    ctr::apply_keystream(&k, &iv, out);
    hlog!("prg: {} done", label_name);
}

pub fn prg0(key_src: &[u8], out: &mut [u8]) {
    prg(key_src, out, OpLabel::Prg0)
}
pub fn prg1(key_src: &[u8], out: &mut [u8]) {
    prg(key_src, out, OpLabel::Prg1)
}
pub fn prg2(key_src: &[u8], out: &mut [u8]) {
    prg(key_src, out, OpLabel::Prg2)
}
