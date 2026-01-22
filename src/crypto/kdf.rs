use hkdf::Hkdf;
use sha2::Sha256;

#[derive(Copy, Clone)]
pub enum OpLabel {
    Mac,
    Prg0,
    Prg1,
    Prg2,
    Prp,
    Enc,
    Dec,
    Pi,
    Pi1,
    Pi2,
    Pi3,
    Pi4,
    Tau,
}

pub fn hop_key(input: &[u8], op: OpLabel, out: &mut [u8]) {
    let info = match op {
        OpLabel::Mac => b"MAC".as_slice(),
        OpLabel::Prg0 => b"PRG0".as_slice(),
        OpLabel::Prg1 => b"PRG1".as_slice(),
        OpLabel::Prg2 => b"PRG2".as_slice(),
        OpLabel::Prp => b"PRP".as_slice(),
        OpLabel::Enc => b"ENC".as_slice(),
        OpLabel::Dec => b"DEC".as_slice(),
        OpLabel::Pi => b"PI".as_slice(),
        OpLabel::Pi1 => b"PI1".as_slice(),
        OpLabel::Pi2 => b"PI2".as_slice(),
        OpLabel::Pi3 => b"PI3".as_slice(),
        OpLabel::Pi4 => b"PI4".as_slice(),
        OpLabel::Tau => b"TAU".as_slice(),
    };
    let hk = Hkdf::<Sha256>::new(None, input);
    hk.expand(info, out).expect("HKDF expand");
}
