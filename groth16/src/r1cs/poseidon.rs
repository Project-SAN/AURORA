use alloc::vec;
use alloc::vec::Vec;
use ark_bls12_381::Fr;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;

use crate::math::poseidon::{poseidon_config, PoseidonMerklePath};
use super::gadgets::enforce_boolean;
use super::{ConstraintSystem, LinearCombination, Variable};

/// Poseidon の two-to-one ハッシュ (rate=2, capacity=1) を R1CS 上で実行し、
/// 出力変数と値を返す。`left_value`/`right_value` は witness として割り当てた値を渡す。
pub fn poseidon_hash_two(
    cs: &mut ConstraintSystem<Fr>,
    left_var: Variable,
    left_value: Fr,
    right_var: Variable,
    right_value: Fr,
) -> (Variable, Fr) {
    let params = poseidon_config();
    let state_len = params.rate + params.capacity;
    let mut state_vars: Vec<Variable> = Vec::with_capacity(state_len);
    let mut state_vals = vec![Fr::from(0u64); state_len];

    // 初期状態 (=0) を変数として確定させておく。
    for value in &state_vals {
        let var = cs.alloc_aux(*value);
        enforce_variable_equals_constant(cs, var, *value);
        state_vars.push(var);
    }

    // 1つ目の rate スロットに left を吸収。
    let rate_start = params.capacity;
    let (var, val) = absorb_element(cs, state_vars[rate_start], state_vals[rate_start], left_var, left_value);
    state_vars[rate_start] = var;
    state_vals[rate_start] = val;

    // 2つ目の rate スロットに right を吸収。
    let second_idx = rate_start + 1;
    let (var, val) = absorb_element(
        cs,
        state_vars[second_idx],
        state_vals[second_idx],
        right_var,
        right_value,
    );
    state_vars[second_idx] = var;
    state_vals[second_idx] = val;

    // Poseidon permutation
    apply_poseidon_permutation(cs, &params, &mut state_vars, &mut state_vals);

    // 出力は最初の rate スロット。
    (
        state_vars[params.capacity],
        state_vals[params.capacity],
    )
}

/// Poseidon mercle pathを R1CS 上で計算し、root hash変数と値を返す。
/// `siblings_vars` と `sibling_values` は path.siblings と同じ長さであること。
pub fn enforce_poseidon_merkle_path(
    cs: &mut ConstraintSystem<Fr>,
    leaf_var: Variable,
    leaf_value: Fr,
    path: &PoseidonMerklePath,
    sibling_vars: &[Variable],
    sibling_values: &[Fr],
    flag_vars: &[Variable],
    flag_values: &[Fr],
) -> (Variable, Fr) {
    assert_eq!(path.siblings.len(), sibling_vars.len());
    assert_eq!(path.siblings.len(), sibling_values.len());
    assert_eq!(path.siblings.len(), flag_vars.len());
    assert_eq!(path.siblings.len(), flag_values.len());

    let mut current_var = leaf_var;
    let mut current_value = leaf_value;

    let one = Fr::from(1u64);
    let minus_one = -one;

    for (((sibling_var, sibling_value), flag_var), flag_value) in sibling_vars
        .iter()
        .zip(sibling_values.iter())
        .zip(flag_vars.iter())
        .zip(flag_values.iter())
    {
        let sibling_var = *sibling_var;
        let flag_var = *flag_var;
        let sibling_value = *sibling_value;
        let flag_value = *flag_value;

        enforce_boolean(cs, flag_var);

        // diff = sibling - current
        let diff_value = sibling_value - current_value;
        let diff_var = cs.alloc_aux(diff_value);
        let mut diff_lc = LinearCombination::from(diff_var);
        diff_lc.push_term(sibling_var, minus_one);
        diff_lc.push_term(current_var, one);
        cs.enforce(diff_lc, LinearCombination::from(one), LinearCombination::zero());

        // prod = flag * diff
        let prod_value = flag_value * diff_value;
        let prod_var = cs.alloc_aux(prod_value);
        cs.enforce(
            LinearCombination::from(flag_var),
            LinearCombination::from(diff_var),
            LinearCombination::from(prod_var),
        );

        // left = current + prod
        let left_value = current_value + prod_value;
        let left_var = cs.alloc_aux(left_value);
        let mut left_lc = LinearCombination::from(left_var);
        left_lc.push_term(current_var, minus_one);
        left_lc.push_term(prod_var, minus_one);
        cs.enforce(left_lc, LinearCombination::from(one), LinearCombination::zero());

        // right = sibling - prod
        let right_value = sibling_value - prod_value;
        let right_var = cs.alloc_aux(right_value);
        let mut right_lc = LinearCombination::from(right_var);
        right_lc.push_term(sibling_var, minus_one);
        right_lc.push_term(prod_var, one);
        cs.enforce(right_lc, LinearCombination::from(one), LinearCombination::zero());

        let (parent_var, parent_val) = poseidon_hash_two(cs, left_var, left_value, right_var, right_value);
        current_var = parent_var;
        current_value = parent_val;
    }

    (current_var, current_value)
}

fn absorb_element(
    cs: &mut ConstraintSystem<Fr>,
    previous_var: Variable,
    previous_value: Fr,
    element_var: Variable,
    element_value: Fr,
) -> (Variable, Fr) {
    let new_value = previous_value + element_value;
    let new_var = cs.alloc_aux(new_value);

    let mut lc = LinearCombination::from(new_var);
    let minus_one = -Fr::from(1u64);
    lc.push_term(previous_var, minus_one);
    lc.push_term(element_var, minus_one);
    cs.enforce(lc, LinearCombination::from(Fr::from(1u64)), LinearCombination::zero());

    (new_var, new_value)
}

fn apply_poseidon_permutation(
    cs: &mut ConstraintSystem<Fr>,
    params: &PoseidonConfig<Fr>,
    state_vars: &mut [Variable],
    state_vals: &mut [Fr],
) {
    let total_rounds = params.full_rounds + params.partial_rounds;
    let half_full = params.full_rounds / 2;
    let mut round = 0usize;

    for _ in 0..half_full {
        add_round_constants(cs, params, state_vars, state_vals, round);
        apply_full_sbox(cs, state_vars, state_vals);
        apply_mds(cs, params, state_vars, state_vals);
        round += 1;
    }

    for _ in 0..params.partial_rounds {
        add_round_constants(cs, params, state_vars, state_vals, round);
        apply_partial_sbox(cs, state_vars, state_vals);
        apply_mds(cs, params, state_vars, state_vals);
        round += 1;
    }

    for _ in round..total_rounds {
        add_round_constants(cs, params, state_vars, state_vals, round);
        apply_full_sbox(cs, state_vars, state_vals);
        apply_mds(cs, params, state_vars, state_vals);
        round += 1;
    }
}

fn add_round_constants(
    cs: &mut ConstraintSystem<Fr>,
    params: &PoseidonConfig<Fr>,
    state_vars: &mut [Variable],
    state_vals: &mut [Fr],
    round: usize,
) {
    for i in 0..state_vars.len() {
        let constant = params.ark[round][i];
        let new_value = state_vals[i] + constant;
        let new_var = cs.alloc_aux(new_value);

        let mut lc = LinearCombination::from(new_var);
        lc.push_term(state_vars[i], -Fr::from(1u64));
        lc.constant -= constant;
        cs.enforce(lc, LinearCombination::from(Fr::from(1u64)), LinearCombination::zero());

        state_vars[i] = new_var;
        state_vals[i] = new_value;
    }
}

fn apply_full_sbox(
    cs: &mut ConstraintSystem<Fr>,
    state_vars: &mut [Variable],
    state_vals: &mut [Fr],
) {
    for i in 0..state_vars.len() {
        let (var, value) = apply_sbox(cs, state_vars[i], state_vals[i]);
        state_vars[i] = var;
        state_vals[i] = value;
    }
}

fn apply_partial_sbox(
    cs: &mut ConstraintSystem<Fr>,
    state_vars: &mut [Variable],
    state_vals: &mut [Fr],
) {
    let (var, value) = apply_sbox(cs, state_vars[0], state_vals[0]);
    state_vars[0] = var;
    state_vals[0] = value;
}

fn apply_sbox(
    cs: &mut ConstraintSystem<Fr>,
    var: Variable,
    value: Fr,
) -> (Variable, Fr) {
    // alpha = 17 -> compute via successive squaring
    let square = |cs: &mut ConstraintSystem<Fr>, x_var: Variable, x_value: Fr| -> (Variable, Fr) {
        let value = x_value * x_value;
        let var = cs.alloc_aux(value);
        cs.enforce(
            LinearCombination::from(x_var),
            LinearCombination::from(x_var),
            LinearCombination::from(var),
        );
        (var, value)
    };

    let mul = |cs: &mut ConstraintSystem<Fr>,
               left_var: Variable,
               left_value: Fr,
               right_var: Variable,
               right_value: Fr|
     -> (Variable, Fr) {
        let value = left_value * right_value;
        let var = cs.alloc_aux(value);
        cs.enforce(
            LinearCombination::from(left_var),
            LinearCombination::from(right_var),
            LinearCombination::from(var),
        );
        (var, value)
    };

    let (x2_var, x2_val) = square(cs, var, value);
    let (x4_var, x4_val) = square(cs, x2_var, x2_val);
    let (x8_var, x8_val) = square(cs, x4_var, x4_val);
    let (x16_var, x16_val) = square(cs, x8_var, x8_val);
    let (x17_var, x17_val) = mul(cs, x16_var, x16_val, var, value);

    (x17_var, x17_val)
}

fn apply_mds(
    cs: &mut ConstraintSystem<Fr>,
    params: &PoseidonConfig<Fr>,
    state_vars: &mut [Variable],
    state_vals: &mut [Fr],
) {
    let t = state_vars.len();
    let mut new_vars = Vec::with_capacity(t);
    let mut new_vals = Vec::with_capacity(t);

    for i in 0..t {
        let mut acc = Fr::from(0u64);
        for j in 0..t {
            acc += state_vals[j] * params.mds[i][j];
        }
        let new_var = cs.alloc_aux(acc);
        let mut lc = LinearCombination::from(new_var);
        for j in 0..t {
            let coeff = -params.mds[i][j];
            lc.push_term(state_vars[j], coeff);
        }
        cs.enforce(lc, LinearCombination::from(Fr::from(1u64)), LinearCombination::zero());
        new_vars.push(new_var);
        new_vals.push(acc);
    }

    state_vars.copy_from_slice(&new_vars);
    state_vals.copy_from_slice(&new_vals);
}

fn enforce_variable_equals_constant(
    cs: &mut ConstraintSystem<Fr>,
    var: Variable,
    constant: Fr,
) {
    let mut lc = LinearCombination::from(var);
    lc.constant -= constant;
    cs.enforce(lc, LinearCombination::from(Fr::from(1u64)), LinearCombination::zero());
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::math::poseidon::{hash_pair, PoseidonMerkleTree};
    use crate::r1cs::gadgets::enforce_equal;

    #[test]
    fn poseidon_hash_two_matches_native() {
        let mut cs = ConstraintSystem::<Fr>::new();
        let left_value = Fr::from(3u64);
        let right_value = Fr::from(11u64);
        let left_var = cs.alloc_aux(left_value);
        let right_var = cs.alloc_aux(right_value);

        let (hash_var, hash_val) = poseidon_hash_two(&mut cs, left_var, left_value, right_var, right_value);
        let expected = hash_pair(left_value, right_value);
        let expected_var = cs.alloc_aux(expected);
        enforce_variable_equals_constant(&mut cs, expected_var, expected);
        enforce_equal(&mut cs, hash_var, expected_var);
        assert_eq!(hash_val, expected);
        assert!(cs.is_satisfied());
    }

    #[test]
    fn merkle_path_verification_succeeds() {
        let leaves: Vec<Fr> = (0u64..4).map(Fr::from).collect();
        let tree = PoseidonMerkleTree::new(&leaves).expect("tree");
        let root_value = tree.root();

        for (idx, leaf) in leaves.iter().enumerate() {
            let mut cs = ConstraintSystem::<Fr>::new();
            let leaf_var = cs.alloc_aux(*leaf);
            let path = tree.authentication_path(idx).expect("path");

            let sibling_vars: Vec<Variable> = path
                .siblings
                .iter()
                .map(|node| cs.alloc_aux(node.sibling))
                .collect();
            let sibling_values: Vec<Fr> = path
                .siblings
                .iter()
                .map(|node| node.sibling)
                .collect();
            let flag_values: Vec<Fr> = path
                .siblings
                .iter()
                .map(|node| if node.sibling_is_left { Fr::from(1u64) } else { Fr::from(0u64) })
                .collect();
            let flag_vars: Vec<Variable> = flag_values
                .iter()
                .map(|value| cs.alloc_aux(*value))
                .collect();

            let (result_var, result_value) = enforce_poseidon_merkle_path(
                &mut cs,
                leaf_var,
                *leaf,
                &path,
                &sibling_vars,
                &sibling_values,
                &flag_vars,
                &flag_values,
            );
            let root_var = cs.alloc_aux(root_value);
            enforce_variable_equals_constant(&mut cs, root_var, root_value);
            enforce_equal(&mut cs, result_var, root_var);
            assert_eq!(result_value, root_value);
            assert!(cs.is_satisfied());
        }
    }

    #[test]
    fn merkle_path_verification_fails_with_wrong_sibling() {
        let leaves: Vec<Fr> = (0u64..4).map(Fr::from).collect();
        let tree = PoseidonMerkleTree::new(&leaves).expect("tree");
        let path = tree.authentication_path(0).expect("path");

        let mut cs = ConstraintSystem::<Fr>::new();
        let leaf_value = leaves[0];
        let leaf_var = cs.alloc_aux(leaf_value);

        let mut sibling_values: Vec<Fr> = path
            .siblings
            .iter()
            .map(|node| node.sibling)
            .collect();
        sibling_values[0] += Fr::from(1u64); // 改竄

        let sibling_vars: Vec<Variable> = sibling_values
            .iter()
            .map(|value| cs.alloc_aux(*value))
            .collect();
        let flag_values: Vec<Fr> = path
            .siblings
            .iter()
            .map(|node| if node.sibling_is_left { Fr::from(1u64) } else { Fr::from(0u64) })
            .collect();
        let flag_vars: Vec<Variable> = flag_values
            .iter()
            .map(|value| cs.alloc_aux(*value))
            .collect();

        let (result_var, _) = enforce_poseidon_merkle_path(
            &mut cs,
            leaf_var,
            leaf_value,
            &path,
            &sibling_vars,
            &sibling_values,
            &flag_vars,
            &flag_values,
        );
        let root_value = tree.root();
        let root_var = cs.alloc_aux(root_value);
        enforce_variable_equals_constant(&mut cs, root_var, root_value);
        enforce_equal(&mut cs, result_var, root_var);
        assert!(!cs.is_satisfied());
    }

    #[test]
    fn merkle_path_verification_fails_with_wrong_flag() {
        let leaves: Vec<Fr> = (0u64..4).map(Fr::from).collect();
        let tree = PoseidonMerkleTree::new(&leaves).expect("tree");
        let path = tree.authentication_path(0).expect("path");

        let mut cs = ConstraintSystem::<Fr>::new();
        let leaf_value = leaves[0];
        let leaf_var = cs.alloc_aux(leaf_value);

        let sibling_values: Vec<Fr> = path
            .siblings
            .iter()
            .map(|node| node.sibling)
            .collect();
        let sibling_vars: Vec<Variable> = sibling_values
            .iter()
            .map(|value| cs.alloc_aux(*value))
            .collect();

        let mut flag_values: Vec<Fr> = path
            .siblings
            .iter()
            .map(|node| if node.sibling_is_left { Fr::from(1u64) } else { Fr::from(0u64) })
            .collect();
        // flip first flag
        flag_values[0] = if flag_values[0] == Fr::from(1u64) {
            Fr::from(0u64)
        } else {
            Fr::from(1u64)
        };
        let flag_vars: Vec<Variable> = flag_values
            .iter()
            .map(|value| cs.alloc_aux(*value))
            .collect();

        let (result_var, _) = enforce_poseidon_merkle_path(
            &mut cs,
            leaf_var,
            leaf_value,
            &path,
            &sibling_vars,
            &sibling_values,
            &flag_vars,
            &flag_values,
        );
        let root_value = tree.root();
        let root_var = cs.alloc_aux(root_value);
        enforce_variable_equals_constant(&mut cs, root_var, root_value);
        enforce_equal(&mut cs, result_var, root_var);
        assert!(!cs.is_satisfied());
    }
}
