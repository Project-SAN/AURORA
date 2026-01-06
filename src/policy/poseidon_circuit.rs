use dusk_plonk::prelude::{BlsScalar, Composer, Constraint, Witness};

use crate::policy::poseidon::{poseidon_params, PoseidonParams, WIDTH};
use crate::policy::sha256_circuit::Byte;

#[derive(Clone, Copy)]
struct FieldElem {
    value: BlsScalar,
    witness: Witness,
}

impl FieldElem {
    fn witness<C: Composer>(composer: &mut C, value: BlsScalar) -> Self {
        let witness = composer.append_witness(value);
        Self { value, witness }
    }

    fn constant<C: Composer>(composer: &mut C, value: BlsScalar) -> Self {
        let witness = composer.append_witness(value);
        composer.assert_equal_constant(witness, value, None);
        Self { value, witness }
    }
}

pub fn poseidon_hash2_circuit<C: Composer>(
    composer: &mut C,
    salt: [Byte; 32],
    secret: [Byte; 32],
    public_salt: BlsScalar,
    public_hkey: BlsScalar,
) {
    let salt_scalar = enforce_bytes_as_scalar(composer, &salt, public_salt, true);
    let secret_scalar_value = bytes_to_scalar_le(&secret);
    let secret_scalar = enforce_bytes_as_scalar(composer, &secret, secret_scalar_value, false);

    let output = poseidon_permute(composer, [salt_scalar, secret_scalar]);
    composer.assert_equal_constant(output.witness, BlsScalar::zero(), Some(public_hkey));
}

fn poseidon_permute<C: Composer>(composer: &mut C, inputs: [FieldElem; 2]) -> FieldElem {
    let params = poseidon_params();
    let mut state = [
        FieldElem::constant(composer, params.domain_tag),
        inputs[0],
        inputs[1],
    ];
    let mut rc_iter = params.round_constants.iter();

    for _ in 0..params.half_full_rounds {
        add_round_constants(composer, &mut state, &mut rc_iter);
        sbox_full(composer, &mut state);
        state = mds_mul(composer, &state, &params);
    }

    for _ in 0..params.partial_rounds {
        add_round_constants(composer, &mut state, &mut rc_iter);
        state[0] = sbox(composer, state[0]);
        state = mds_mul(composer, &state, &params);
    }

    for _ in 0..params.half_full_rounds {
        add_round_constants(composer, &mut state, &mut rc_iter);
        sbox_full(composer, &mut state);
        state = mds_mul(composer, &state, &params);
    }

    state[0]
}

fn add_round_constants<'a, C: Composer>(
    composer: &mut C,
    state: &mut [FieldElem; WIDTH],
    rc_iter: &mut impl Iterator<Item = &'a BlsScalar>,
) {
    for element in state.iter_mut() {
        let c = rc_iter.next().expect("round constants");
        *element = add_const(composer, *element, *c);
    }
}

fn sbox_full<C: Composer>(composer: &mut C, state: &mut [FieldElem; WIDTH]) {
    for element in state.iter_mut() {
        *element = sbox(composer, *element);
    }
}

fn sbox<C: Composer>(composer: &mut C, x: FieldElem) -> FieldElem {
    let x2 = mul(composer, x, x);
    let x4 = mul(composer, x2, x2);
    mul(composer, x4, x)
}

fn mds_mul<C: Composer>(
    composer: &mut C,
    state: &[FieldElem; WIDTH],
    params: &PoseidonParams,
) -> [FieldElem; WIDTH] {
    let mut out = [FieldElem::witness(composer, BlsScalar::zero()); WIDTH];
    for i in 0..WIDTH {
        let coeff0 = params.mds[i][0];
        let coeff1 = params.mds[i][1];
        let coeff2 = params.mds[i][2];
        let acc_value =
            coeff0 * state[0].value + coeff1 * state[1].value + coeff2 * state[2].value;
        let acc0 = composer.gate_add(
            Constraint::new()
                .left(coeff0)
                .a(state[0].witness)
                .right(coeff1)
                .b(state[1].witness),
        );
        let witness = composer.gate_add(
            Constraint::new()
                .left(1)
                .a(acc0)
                .right(coeff2)
                .b(state[2].witness),
        );
        out[i] = FieldElem {
            value: acc_value,
            witness,
        };
    }
    out
}

fn add_const<C: Composer>(composer: &mut C, a: FieldElem, c: BlsScalar) -> FieldElem {
    let witness = composer.gate_add(
        Constraint::new()
            .left(1)
            .a(a.witness)
            .constant(c),
    );
    FieldElem {
        value: a.value + c,
        witness,
    }
}

fn mul<C: Composer>(composer: &mut C, a: FieldElem, b: FieldElem) -> FieldElem {
    let witness = composer.gate_mul(Constraint::new().mult(1).a(a.witness).b(b.witness));
    FieldElem {
        value: a.value * b.value,
        witness,
    }
}

fn enforce_bytes_as_scalar<C: Composer>(
    composer: &mut C,
    bytes: &[Byte; 32],
    value: BlsScalar,
    public: bool,
) -> FieldElem {
    let witness = composer.append_witness(value);
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
    if public {
        composer.assert_equal(witness, acc);
        composer.assert_equal_constant(acc, BlsScalar::zero(), Some(value));
    } else {
        composer.assert_equal(acc, witness);
    }
    FieldElem { value, witness }
}

fn bytes_to_scalar_le(bytes: &[Byte; 32]) -> BlsScalar {
    let mut acc = BlsScalar::zero();
    let base = BlsScalar::from(256u64);
    let mut factor = BlsScalar::one();
    for byte in bytes {
        acc += BlsScalar::from(byte.value as u64) * factor;
        factor *= base;
    }
    acc
}
