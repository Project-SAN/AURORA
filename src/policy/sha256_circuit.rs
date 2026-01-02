use alloc::vec::Vec;
use dusk_plonk::prelude::{BlsScalar, Composer, Constraint, Witness};

#[derive(Clone, Copy, Debug)]
pub struct Byte {
    pub value: u8,
    pub witness: Witness,
}

impl Byte {
    pub fn witness<C: Composer>(composer: &mut C, value: u8) -> Self {
        let witness = composer.append_witness(BlsScalar::from(value as u64));
        composer.component_range(witness, 8);
        Self { value, witness }
    }

    pub fn constant<C: Composer>(composer: &mut C, value: u8) -> Self {
        let witness = composer.append_witness(BlsScalar::from(value as u64));
        composer.assert_equal_constant(witness, BlsScalar::from(value as u64), None);
        composer.component_range(witness, 8);
        Self { value, witness }
    }
}

#[derive(Clone, Copy, Debug)]
struct Word {
    value: u32,
    witness: Witness,
}

impl Word {
    fn witness<C: Composer>(composer: &mut C, value: u32) -> Self {
        let witness = composer.append_witness(BlsScalar::from(value as u64));
        composer.component_range(witness, 32);
        Self { value, witness }
    }

    fn constant<C: Composer>(composer: &mut C, value: u32) -> Self {
        let witness = composer.append_witness(BlsScalar::from(value as u64));
        composer.assert_equal_constant(witness, BlsScalar::from(value as u64), None);
        composer.component_range(witness, 32);
        Self { value, witness }
    }
}

fn word_from_bytes_be<C: Composer>(composer: &mut C, bytes: &[Byte; 4]) -> Word {
    let value = u32::from_be_bytes([
        bytes[0].value,
        bytes[1].value,
        bytes[2].value,
        bytes[3].value,
    ]);
    let word = Word::witness(composer, value);
    let term0 = composer.gate_add(
        Constraint::new()
            .left(BlsScalar::from(1u64 << 24))
            .a(bytes[0].witness)
            .right(BlsScalar::from(1u64 << 16))
            .b(bytes[1].witness),
    );
    let term1 = composer.gate_add(
        Constraint::new()
            .left(BlsScalar::from(1u64 << 8))
            .a(bytes[2].witness)
            .right(1)
            .b(bytes[3].witness),
    );
    let combined = composer.gate_add(Constraint::new().left(1).a(term0).right(1).b(term1));
    composer.assert_equal(word.witness, combined);
    word
}

fn word_to_bytes_be<C: Composer>(composer: &mut C, word: Word) -> [Byte; 4] {
    let bytes = word.value.to_be_bytes();
    let b0 = Byte::witness(composer, bytes[0]);
    let b1 = Byte::witness(composer, bytes[1]);
    let b2 = Byte::witness(composer, bytes[2]);
    let b3 = Byte::witness(composer, bytes[3]);
    let term0 = composer.gate_add(
        Constraint::new()
            .left(BlsScalar::from(1u64 << 24))
            .a(b0.witness)
            .right(BlsScalar::from(1u64 << 16))
            .b(b1.witness),
    );
    let term1 = composer.gate_add(
        Constraint::new()
            .left(BlsScalar::from(1u64 << 8))
            .a(b2.witness)
            .right(1)
            .b(b3.witness),
    );
    let combined = composer.gate_add(Constraint::new().left(1).a(term0).right(1).b(term1));
    composer.assert_equal(word.witness, combined);
    [b0, b1, b2, b3]
}

fn xor_word<C: Composer>(composer: &mut C, a: Word, b: Word) -> Word {
    let witness = composer.append_logic_xor(a.witness, b.witness, 32);
    composer.component_range(witness, 32);
    Word {
        value: a.value ^ b.value,
        witness,
    }
}

fn and_word<C: Composer>(composer: &mut C, a: Word, b: Word) -> Word {
    let witness = composer.append_logic_and(a.witness, b.witness, 32);
    composer.component_range(witness, 32);
    Word {
        value: a.value & b.value,
        witness,
    }
}

fn not_word<C: Composer>(composer: &mut C, a: Word) -> Word {
    let value = !a.value;
    let witness = composer.append_witness(BlsScalar::from(value as u64));
    composer.component_range(witness, 32);
    let sum = composer.gate_add(
        Constraint::new()
            .left(1)
            .a(witness)
            .right(1)
            .b(a.witness)
            .constant(-BlsScalar::from(u32::MAX as u64)),
    );
    composer.assert_equal_constant(sum, BlsScalar::zero(), None);
    Word { value, witness }
}

fn pack_bits_le<C: Composer>(composer: &mut C, bits: [Witness; 32], value: u32) -> Word {
    let word = Word::witness(composer, value);
    let recomposed = composer.component_decomposition::<32>(word.witness);
    for i in 0..32 {
        composer.assert_equal(bits[i], recomposed[i]);
    }
    word
}

fn rot_word<C: Composer>(composer: &mut C, word: Word, n: usize) -> Word {
    let bits = composer.component_decomposition::<32>(word.witness);
    let mut rot_bits = [C::ZERO; 32];
    for i in 0..32 {
        rot_bits[i] = bits[(i + n) % 32];
    }
    pack_bits_le(composer, rot_bits, word.value.rotate_right(n as u32))
}

fn shr_word<C: Composer>(composer: &mut C, word: Word, n: usize) -> Word {
    let bits = composer.component_decomposition::<32>(word.witness);
    let zero = composer.append_witness(BlsScalar::zero());
    composer.assert_equal_constant(zero, BlsScalar::zero(), None);
    let mut shr_bits = [zero; 32];
    for i in 0..32 {
        if i + n < 32 {
            shr_bits[i] = bits[i + n];
        }
    }
    pack_bits_le(composer, shr_bits, word.value >> n)
}

fn add_mod32<C: Composer>(composer: &mut C, values: &[Word]) -> Word {
    let total: u64 = values.iter().map(|w| w.value as u64).sum();
    let sum_value = (total & 0xffff_ffff) as u32;
    let carry_value = (total >> 32) as u32;
    let sum = Word::witness(composer, sum_value);
    let carry = composer.append_witness(BlsScalar::from(carry_value as u64));
    composer.component_range(carry, 4);

    let mut acc = values[0].witness;
    for value in values.iter().skip(1) {
        acc = composer.gate_add(Constraint::new().left(1).a(acc).right(1).b(value.witness));
    }
    let recomposed = composer.gate_add(
        Constraint::new()
            .left(1)
            .a(sum.witness)
            .right(BlsScalar::from(1u64 << 32))
            .b(carry),
    );
    composer.assert_equal(acc, recomposed);
    sum
}

const K: [u32; 64] = [
    0x428a2f98,
    0x71374491,
    0xb5c0fbcf,
    0xe9b5dba5,
    0x3956c25b,
    0x59f111f1,
    0x923f82a4,
    0xab1c5ed5,
    0xd807aa98,
    0x12835b01,
    0x243185be,
    0x550c7dc3,
    0x72be5d74,
    0x80deb1fe,
    0x9bdc06a7,
    0xc19bf174,
    0xe49b69c1,
    0xefbe4786,
    0x0fc19dc6,
    0x240ca1cc,
    0x2de92c6f,
    0x4a7484aa,
    0x5cb0a9dc,
    0x76f988da,
    0x983e5152,
    0xa831c66d,
    0xb00327c8,
    0xbf597fc7,
    0xc6e00bf3,
    0xd5a79147,
    0x06ca6351,
    0x14292967,
    0x27b70a85,
    0x2e1b2138,
    0x4d2c6dfc,
    0x53380d13,
    0x650a7354,
    0x766a0abb,
    0x81c2c92e,
    0x92722c85,
    0xa2bfe8a1,
    0xa81a664b,
    0xc24b8b70,
    0xc76c51a3,
    0xd192e819,
    0xd6990624,
    0xf40e3585,
    0x106aa070,
    0x19a4c116,
    0x1e376c08,
    0x2748774c,
    0x34b0bcb5,
    0x391c0cb3,
    0x4ed8aa4a,
    0x5b9cca4f,
    0x682e6ff3,
    0x748f82ee,
    0x78a5636f,
    0x84c87814,
    0x8cc70208,
    0x90befffa,
    0xa4506ceb,
    0xbef9a3f7,
    0xc67178f2,
];

const H0: [u32; 8] = [
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19,
];

fn compress_block<C: Composer>(composer: &mut C, state: [Word; 8], block: [Word; 16]) -> [Word; 8] {
    let mut w: Vec<Word> = Vec::with_capacity(64);
    w.extend_from_slice(&block);
    for t in 16..64 {
        let w15 = w[t - 15];
        let r7 = rot_word(composer, w15, 7);
        let r18 = rot_word(composer, w15, 18);
        let t0 = xor_word(composer, r7, r18);
        let shr3 = shr_word(composer, w15, 3);
        let s0 = xor_word(composer, t0, shr3);

        let w2 = w[t - 2];
        let r17 = rot_word(composer, w2, 17);
        let r19 = rot_word(composer, w2, 19);
        let t1 = xor_word(composer, r17, r19);
        let shr10 = shr_word(composer, w2, 10);
        let s1 = xor_word(composer, t1, shr10);
        let wt = add_mod32(composer, &[w[t - 16], s0, w[t - 7], s1]);
        w.push(wt);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    for t in 0..64 {
        let e6 = rot_word(composer, e, 6);
        let e11 = rot_word(composer, e, 11);
        let e25 = rot_word(composer, e, 25);
        let t2 = xor_word(composer, e6, e11);
        let s1 = xor_word(composer, t2, e25);
        let ef = and_word(composer, e, f);
        let not_e = not_word(composer, e);
        let neg = and_word(composer, not_e, g);
        let ch = xor_word(composer, ef, neg);
        let kt = Word::constant(composer, K[t]);
        let temp1 = add_mod32(composer, &[h, s1, ch, kt, w[t]]);
        let a2 = rot_word(composer, a, 2);
        let a13 = rot_word(composer, a, 13);
        let a22 = rot_word(composer, a, 22);
        let t3 = xor_word(composer, a2, a13);
        let s0 = xor_word(composer, t3, a22);
        let ab = and_word(composer, a, b);
        let ac = and_word(composer, a, c);
        let t4 = xor_word(composer, ab, ac);
        let bc = and_word(composer, b, c);
        let maj = xor_word(composer, t4, bc);
        let temp2 = add_mod32(composer, &[s0, maj]);

        h = g;
        g = f;
        f = e;
        e = add_mod32(composer, &[d, temp1]);
        d = c;
        c = b;
        b = a;
        a = add_mod32(composer, &[temp1, temp2]);
    }

    [
        add_mod32(composer, &[state[0], a]),
        add_mod32(composer, &[state[1], b]),
        add_mod32(composer, &[state[2], c]),
        add_mod32(composer, &[state[3], d]),
        add_mod32(composer, &[state[4], e]),
        add_mod32(composer, &[state[5], f]),
        add_mod32(composer, &[state[6], g]),
        add_mod32(composer, &[state[7], h]),
    ]
}

fn sha256_two_blocks<C: Composer>(composer: &mut C, block0: [Byte; 64], block1: [Byte; 64]) -> [Byte; 32] {
    let mut words0 = [Word { value: 0, witness: C::ZERO }; 16];
    for i in 0..16 {
        let bytes = [block0[i * 4], block0[i * 4 + 1], block0[i * 4 + 2], block0[i * 4 + 3]];
        words0[i] = word_from_bytes_be(composer, &bytes);
    }
    let mut words1 = [Word { value: 0, witness: C::ZERO }; 16];
    for i in 0..16 {
        let bytes = [block1[i * 4], block1[i * 4 + 1], block1[i * 4 + 2], block1[i * 4 + 3]];
        words1[i] = word_from_bytes_be(composer, &bytes);
    }

    let mut state = [Word { value: 0, witness: C::ZERO }; 8];
    for i in 0..8 {
        state[i] = Word::constant(composer, H0[i]);
    }

    let state = compress_block(composer, state, words0);
    let state = compress_block(composer, state, words1);

    let mut out = [Byte { value: 0, witness: C::ZERO }; 32];
    for (i, word) in state.iter().enumerate() {
        let bytes = word_to_bytes_be(composer, *word);
        out[i * 4] = bytes[0];
        out[i * 4 + 1] = bytes[1];
        out[i * 4 + 2] = bytes[2];
        out[i * 4 + 3] = bytes[3];
    }
    out
}

fn xor_byte_const<C: Composer>(composer: &mut C, byte: Byte, constant: u8) -> Byte {
    let const_byte = Byte::constant(composer, constant);
    let witness = composer.append_logic_xor(byte.witness, const_byte.witness, 8);
    composer.component_range(witness, 8);
    Byte {
        value: byte.value ^ constant,
        witness,
    }
}

fn build_second_block<C: Composer>(
    composer: &mut C,
    msg: &[Byte],
    total_len_bytes: usize,
) -> [Byte; 64] {
    let mut block = [Byte { value: 0, witness: C::ZERO }; 64];
    for i in 0..64 {
        block[i] = Byte::constant(composer, 0);
    }
    let mut idx = 0;
    for b in msg.iter() {
        block[idx] = *b;
        idx += 1;
    }
    block[idx] = Byte::constant(composer, 0x80);

    let bit_len = (total_len_bytes as u64) * 8;
    let len_bytes = bit_len.to_be_bytes();
    for i in 0..8 {
        block[56 + i] = Byte::constant(composer, len_bytes[i]);
    }
    block
}

pub fn hmac_sha256_fixed<C: Composer>(
    composer: &mut C,
    key: &[Byte; 32],
    msg: &[Byte],
) -> [Byte; 32] {
    let mut ipad_block = [Byte { value: 0, witness: C::ZERO }; 64];
    let mut opad_block = [Byte { value: 0, witness: C::ZERO }; 64];
    for i in 0..64 {
        ipad_block[i] = Byte::constant(composer, 0);
        opad_block[i] = Byte::constant(composer, 0);
    }

    for i in 0..32 {
        ipad_block[i] = xor_byte_const(composer, key[i], 0x36);
        opad_block[i] = xor_byte_const(composer, key[i], 0x5c);
    }
    for i in 32..64 {
        ipad_block[i] = Byte::constant(composer, 0x36);
        opad_block[i] = Byte::constant(composer, 0x5c);
    }

    let total_len_inner = 64 + msg.len();
    let block1_inner = build_second_block(composer, msg, total_len_inner);
    let inner_hash = sha256_two_blocks(composer, ipad_block, block1_inner);

    let total_len_outer = 64 + inner_hash.len();
    let block1_outer = build_second_block(composer, &inner_hash, total_len_outer);
    sha256_two_blocks(composer, opad_block, block1_outer)
}

pub fn hkdf_sha256<C: Composer>(
    composer: &mut C,
    salt: &[Byte; 32],
    ikm: &[Byte; 32],
) -> [Byte; 32] {
    let prk = hmac_sha256_fixed(composer, salt, ikm);
    let info = [Byte::constant(composer, 0x01)];
    hmac_sha256_fixed(composer, &prk, &info)
}

pub fn enforce_bytes_as_public_scalar<C: Composer>(
    composer: &mut C,
    bytes: &[Byte],
    public: BlsScalar,
) {
    let mut acc = composer.append_witness(BlsScalar::zero());
    composer.assert_equal_constant(acc, BlsScalar::zero(), None);
    let mut factor = BlsScalar::one();
    let base = BlsScalar::from(256u64);
    for byte in bytes {
        acc = composer.gate_add(
            Constraint::new()
                .left(1)
                .a(acc)
                .right(factor)
                .b(byte.witness),
        );
        factor *= base;
    }
    composer.assert_equal_constant(acc, BlsScalar::zero(), Some(public));
}
