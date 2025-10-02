use ark_ff::Field;

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
}
