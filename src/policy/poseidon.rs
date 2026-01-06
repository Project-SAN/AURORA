use alloc::vec::Vec;
use dusk_bytes::Serializable;
use dusk_plonk::prelude::BlsScalar;

const ARITY: usize = 2;
pub const WIDTH: usize = ARITY + 1;
const DOMAIN_TAG: u64 = (1u64 << ARITY) - 1;

const SECURITY_LEVEL: usize = 128;
const PRIME_BITLEN: usize = 256;

#[derive(Clone)]
pub struct PoseidonParams {
    pub mds: [[BlsScalar; WIDTH]; WIDTH],
    pub round_constants: Vec<BlsScalar>,
    pub full_rounds: usize,
    pub partial_rounds: usize,
    pub half_full_rounds: usize,
    pub domain_tag: BlsScalar,
}

pub fn poseidon_params() -> PoseidonParams {
    init_poseidon_params()
}

pub fn poseidon_hash2(inputs: [BlsScalar; 2]) -> BlsScalar {
    let params = poseidon_params();
    let mut state = [
        params.domain_tag,
        inputs[0],
        inputs[1],
    ];
    let mut rc_iter = params.round_constants.iter();

    for _ in 0..params.half_full_rounds {
        add_round_constants(&mut state, &mut rc_iter);
        sbox_full(&mut state);
        state = mds_mul(&state, &params.mds);
    }

    for _ in 0..params.partial_rounds {
        add_round_constants(&mut state, &mut rc_iter);
        state[0] = sbox(state[0]);
        state = mds_mul(&state, &params.mds);
    }

    for _ in 0..params.half_full_rounds {
        add_round_constants(&mut state, &mut rc_iter);
        sbox_full(&mut state);
        state = mds_mul(&state, &params.mds);
    }

    state[0]
}

fn init_poseidon_params() -> PoseidonParams {
    let (full_rounds, partial_rounds) = round_numbers_base(ARITY);
    let round_constants = round_constants(ARITY, full_rounds, partial_rounds);
    let mds = generate_mds(WIDTH);
    PoseidonParams {
        mds,
        round_constants,
        full_rounds,
        partial_rounds,
        half_full_rounds: full_rounds / 2,
        domain_tag: BlsScalar::from(DOMAIN_TAG),
    }
}

fn add_round_constants<'a>(
    state: &mut [BlsScalar; WIDTH],
    rc_iter: &mut impl Iterator<Item = &'a BlsScalar>,
) {
    for element in state.iter_mut() {
        *element += rc_iter.next().expect("round constants");
    }
}

fn sbox_full(state: &mut [BlsScalar; WIDTH]) {
    for element in state.iter_mut() {
        *element = sbox(*element);
    }
}

fn sbox(x: BlsScalar) -> BlsScalar {
    let x2 = x * x;
    let x4 = x2 * x2;
    x4 * x
}

fn mds_mul(state: &[BlsScalar; WIDTH], mds: &[[BlsScalar; WIDTH]; WIDTH]) -> [BlsScalar; WIDTH] {
    let mut out = [BlsScalar::zero(); WIDTH];
    for i in 0..WIDTH {
        let mut acc = BlsScalar::zero();
        for j in 0..WIDTH {
            acc += mds[i][j] * state[j];
        }
        out[i] = acc;
    }
    out
}

fn round_numbers_base(arity: usize) -> (usize, usize) {
    let t = arity + 1;
    calc_round_numbers(t, true)
}

fn calc_round_numbers(t: usize, security_margin: bool) -> (usize, usize) {
    let mut rf = 0;
    let mut rp = 0;
    let mut n_sboxes_min = usize::MAX;

    for mut rf_test in (2..=1000).step_by(2) {
        for mut rp_test in 4..200 {
            if round_numbers_are_secure(t, rf_test, rp_test) {
                if security_margin {
                    rf_test += 2;
                    rp_test = (1.075 * rp_test as f32).ceil() as usize;
                }
                let n_sboxes = t * rf_test + rp_test;
                if n_sboxes < n_sboxes_min || (n_sboxes == n_sboxes_min && rf_test < rf) {
                    rf = rf_test;
                    rp = rp_test;
                    n_sboxes_min = n_sboxes;
                }
            }
        }
    }

    (rf, rp)
}

fn round_numbers_are_secure(t: usize, rf: usize, rp: usize) -> bool {
    let (rp, t, n, m) = (rp as f32, t as f32, PRIME_BITLEN as f32, SECURITY_LEVEL as f32);
    let rf_stat = if m <= (n - 3.0) * (t + 1.0) { 6.0 } else { 10.0 };
    let rf_interp = 0.43 * m + t.log2() - rp;
    let rf_grob_1 = 0.21 * n - rp;
    let rf_grob_2 = (0.14 * n - 1.0 - rp) / (t - 1.0);
    let rf_max = [rf_stat, rf_interp, rf_grob_1, rf_grob_2]
        .iter()
        .map(|rf| rf.ceil() as usize)
        .max()
        .unwrap();
    rf >= rf_max
}

fn round_constants(arity: usize, r_f: usize, r_p: usize) -> Vec<BlsScalar> {
    let t = arity + 1;
    let field_size = 256u16;
    generate_constants(field_size, t as u16, r_f as u16, r_p as u16)
}

fn generate_mds(t: usize) -> [[BlsScalar; WIDTH]; WIDTH] {
    let mut mds = [[BlsScalar::zero(); WIDTH]; WIDTH];
    for i in 0..t {
        for j in 0..t {
            let mut tmp = BlsScalar::from(i as u64);
            tmp += BlsScalar::from((t + j) as u64);
            tmp = tmp.invert().expect("mds inverse");
            mds[i][j] = tmp;
        }
    }
    mds
}
fn generate_constants(field_size: u16, t: u16, r_f: u16, r_p: u16) -> Vec<BlsScalar> {
    let num_constants = (r_f + r_p) * t;
    let mut init_sequence: Vec<bool> = Vec::new();
    append_bits(&mut init_sequence, 2, 1u8); // field
    append_bits(&mut init_sequence, 4, 1u8); // sbox
    append_bits(&mut init_sequence, 12, field_size);
    append_bits(&mut init_sequence, 12, t);
    append_bits(&mut init_sequence, 10, r_f);
    append_bits(&mut init_sequence, 10, r_p);
    append_bits(
        &mut init_sequence,
        30,
        0b111111111111111111111111111111u128,
    );

    let mut grain = Grain::new(init_sequence, field_size);
    let mut round_constants = Vec::new();
    while round_constants.len() < num_constants as usize {
        let mut repr = [0u8; 32];
        grain.get_next_bytes(&mut repr);
        repr.reverse();
        if let Ok(fr) = BlsScalar::from_bytes(&repr) {
            round_constants.push(fr);
        }
    }
    round_constants
}

fn append_bits<T: Into<u128>>(vec: &mut Vec<bool>, n: usize, from: T) {
    let val = from.into();
    for i in (0..n).rev() {
        vec.push((val >> i) & 1 != 0);
    }
}

struct Grain {
    state: Vec<bool>,
    field_size: u16,
}

impl Grain {
    fn new(init_sequence: Vec<bool>, field_size: u16) -> Self {
        assert_eq!(80, init_sequence.len());
        let mut g = Grain {
            state: init_sequence,
            field_size,
        };
        for _ in 0..160 {
            g.generate_new_bit();
        }
        g
    }

    fn generate_new_bit(&mut self) -> bool {
        let new_bit = self.bit(62)
            ^ self.bit(51)
            ^ self.bit(38)
            ^ self.bit(23)
            ^ self.bit(13)
            ^ self.bit(0);
        self.state.remove(0);
        self.state.push(new_bit);
        new_bit
    }

    fn bit(&self, index: usize) -> bool {
        self.state[index]
    }

    fn next_byte(&mut self, bit_count: usize) -> u8 {
        let mut acc: u8 = 0;
        self.take(bit_count).for_each(|bit| {
            acc <<= 1;
            if bit {
                acc += 1;
            }
        });
        acc
    }

    fn get_next_bytes(&mut self, result: &mut [u8]) {
        let remainder_bits = self.field_size as usize % 8;
        if remainder_bits > 0 {
            result[0] = self.next_byte(remainder_bits);
        } else {
            result[0] = self.next_byte(8);
        }
        for item in result.iter_mut().skip(1) {
            *item = self.next_byte(8)
        }
    }
}

impl Iterator for Grain {
    type Item = bool;

    fn next(&mut self) -> Option<Self::Item> {
        let mut new_bit = self.generate_new_bit();
        while !new_bit {
            let _new_bit = self.generate_new_bit();
            new_bit = self.generate_new_bit();
        }
        new_bit = self.generate_new_bit();
        Some(new_bit)
    }
}
