use alloc::vec::Vec;
use ark_ff::{BigInteger, Field, PrimeField};

use super::{ConstraintSystem, LinearCombination, Variable};

/// 変数が 0/1 のブール値であることを強制する: v * (v - 1) = 0
pub fn enforce_boolean<F: Field>(cs: &mut ConstraintSystem<F>, var: Variable) {
    let a = LinearCombination::from(var);
    let mut b = LinearCombination::from(var);
    b.constant -= F::one();
    cs.enforce(a, b, LinearCombination::zero());
}

/// 2 変数が等しいことを強制する。
pub fn enforce_equal<F: Field>(cs: &mut ConstraintSystem<F>, left: Variable, right: Variable) {
    let mut diff = LinearCombination::from(left);
    diff += -LinearCombination::from(right);
    cs.enforce(diff, LinearCombination::from(F::one()), LinearCombination::zero());
}

/// cond が 1 のとき left = right を強制する (cond はブール値想定)。
pub fn enforce_conditional_equal<F: Field>(
    cs: &mut ConstraintSystem<F>,
    cond: Variable,
    left: Variable,
    right: Variable,
) {
    let mut diff = LinearCombination::from(left);
    diff += -LinearCombination::from(right);
    let cond_lc = LinearCombination::from(cond);
    cs.enforce(cond_lc, diff, LinearCombination::zero());
}

/// リトルエンディアンでのビット分解を強制する。
/// `var` の値が `bits` (0/1) の線形結合 `sum bits[i] * 2^i` と一致する。
pub fn decompose_to_bits_le<F: PrimeField>(
    cs: &mut ConstraintSystem<F>,
    var: Variable,
    value: F,
    num_bits: usize,
) -> Vec<Variable> {
    let mut bits = Vec::with_capacity(num_bits);
    let mut linear = LinearCombination::from(var);
    let mut coeff = F::one();
    let two = F::from(2u64);
    let value_bigint = value.into_bigint();

    for i in 0..num_bits {
        let bit = if value_bigint.get_bit(i as usize) {
            F::one()
        } else {
            F::zero()
        };
        let bit_var = cs.alloc_aux(bit);
        enforce_boolean(cs, bit_var);
        linear.push_term(bit_var, -coeff);
        coeff *= two;
        bits.push(bit_var);
    }

    cs.enforce(linear, LinearCombination::from(F::one()), LinearCombination::zero());
    bits
}

/// ビット列からフィールド要素を再構成し、`value` と一致する変数を返す。
pub fn pack_bits_le<F: Field>(
    cs: &mut ConstraintSystem<F>,
    bits: &[Variable],
    value: F,
) -> Variable {
    let var = cs.alloc_aux(value);
    let mut lc = LinearCombination::from(var);
    let mut coeff = F::one();
    let two = F::from(2u64);

    for bit in bits {
        lc.push_term(*bit, -coeff);
        coeff *= two;
    }

    cs.enforce(lc, LinearCombination::from(F::one()), LinearCombination::zero());
    var
}

/// left <= right を保証する。差分(right - left)のビット長を `num_bits`
/// に制限することで、範囲チェックを実現する。
pub fn enforce_less_equal<F: PrimeField>(
    cs: &mut ConstraintSystem<F>,
    left: Variable,
    left_value: F,
    right: Variable,
    right_value: F,
    num_bits: usize,
) {
    let diff_value = right_value - left_value;
    let diff_var = cs.alloc_aux(diff_value);
    let bits = decompose_to_bits_le(cs, diff_var, diff_value, num_bits);
    let mut lc = LinearCombination::from(left);
    lc += LinearCombination::from(diff_var);
    cs.enforce(lc, LinearCombination::from(F::one()), LinearCombination::from(right));

    // diff_var must equal packed bits (already enforced by decompose), but we need to
    // ensure each bit is boolean -> already by decompose. Nothing else required.
    // Drop bits to avoid warnings.
    let _ = bits;
}

/// min <= value <= max を保証する。`num_bits` は各差分のビット長。
pub fn enforce_value_in_range<F: PrimeField>(
    cs: &mut ConstraintSystem<F>,
    value: Variable,
    value_value: F,
    min: Variable,
    min_value: F,
    max: Variable,
    max_value: F,
    num_bits: usize,
) {
    enforce_less_equal(cs, min, min_value, value, value_value, num_bits);
    enforce_less_equal(cs, value, value_value, max, max_value, num_bits);
}

/// `value_bits` の上位 `prefix_len` ビットが `prefix_bits` と一致することを強制。
pub fn enforce_prefix_match<F: Field>(
    cs: &mut ConstraintSystem<F>,
    value_bits: &[Variable],
    prefix_bits: &[Variable],
    prefix_len: usize,
) {
    assert!(prefix_len <= value_bits.len());
    assert!(prefix_len <= prefix_bits.len());
    for i in 0..prefix_len {
        enforce_equal(cs, value_bits[i], prefix_bits[i]);
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;

    #[test]
    fn boolean_constraint_accepts_binary_values() {
        let mut cs = ConstraintSystem::<Fr>::new();
        let zero = cs.alloc_aux(Fr::from(0u64));
        let one = cs.alloc_aux(Fr::from(1u64));
        enforce_boolean(&mut cs, zero);
        enforce_boolean(&mut cs, one);
        assert!(cs.is_satisfied());

        let mut cs_fail = ConstraintSystem::<Fr>::new();
        let two = cs_fail.alloc_aux(Fr::from(2u64));
        enforce_boolean(&mut cs_fail, two);
        assert!(!cs_fail.is_satisfied());
    }

    #[test]
    fn equality_and_conditional_constraints() {
        let mut cs = ConstraintSystem::<Fr>::new();
        let left = cs.alloc_aux(Fr::from(5u64));
        let right = cs.alloc_aux(Fr::from(5u64));
        enforce_equal(&mut cs, left, right);

        let cond = cs.alloc_aux(Fr::from(1u64));
        let x = cs.alloc_aux(Fr::from(7u64));
        let y = cs.alloc_aux(Fr::from(7u64));
        enforce_conditional_equal(&mut cs, cond, x, y);
        assert!(cs.is_satisfied());

        let mut cs_fail = ConstraintSystem::<Fr>::new();
        let cond = cs_fail.alloc_aux(Fr::from(1u64));
        let a = cs_fail.alloc_aux(Fr::from(2u64));
        let b = cs_fail.alloc_aux(Fr::from(3u64));
        enforce_conditional_equal(&mut cs_fail, cond, a, b);
        assert!(!cs_fail.is_satisfied());
    }

    #[test]
    fn bit_decomposition_roundtrip() {
        let mut cs = ConstraintSystem::<Fr>::new();
        let value = Fr::from(0b1011u64);
        let var = cs.alloc_aux(value);
        let bits = decompose_to_bits_le(&mut cs, var, value, 4);
        assert_eq!(bits.len(), 4);
        assert!(cs.is_satisfied());

        let packed = pack_bits_le(&mut cs, &bits, value);
        enforce_equal(&mut cs, var, packed);
        assert!(cs.is_satisfied());
    }

    #[test]
    fn less_equal_and_range() {
        let mut cs = ConstraintSystem::<Fr>::new();
        let left_val = Fr::from(3u64);
        let right_val = Fr::from(9u64);
        let mid_val = Fr::from(5u64);

        let left = cs.alloc_aux(left_val);
        let right = cs.alloc_aux(right_val);
        let mid = cs.alloc_aux(mid_val);

        enforce_less_equal(&mut cs, left, left_val, right, right_val, 8);
        enforce_value_in_range(&mut cs, mid, mid_val, left, left_val, right, right_val, 8);
        assert!(cs.is_satisfied());

        let mut cs_fail = ConstraintSystem::<Fr>::new();
        let a_val = Fr::from(6u64);
        let b_val = Fr::from(4u64);
        let a = cs_fail.alloc_aux(a_val);
        let b = cs_fail.alloc_aux(b_val);
        enforce_less_equal(&mut cs_fail, a, a_val, b, b_val, 8);
        assert!(!cs_fail.is_satisfied());
    }
}
