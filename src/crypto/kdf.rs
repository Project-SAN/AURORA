use hkdf::Hkdf;
use sha2::Sha256;

pub enum OpLabel {
    Mac,
    Prg0,
    Prg1,
    Prg2,
    Prp,
    Enc,
    Dec,
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
    };
    let hk = Hkdf::<Sha256>::new(None, input);
    hk.expand(info, out).expect("HKDF expand");
}
