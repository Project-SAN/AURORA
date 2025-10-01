#![no_std]

extern crate alloc;

pub mod math;
pub mod r1cs;
pub mod prover;
pub mod verifier;

pub use r1cs::{Constraint, ConstraintSystem, LinearCombination, Variable, VariableType};

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use rand::thread_rng;
    use alloc::vec;

    #[test]
    fn groth16_roundtrip() {
        let mut cs = ConstraintSystem::<Fr>::new();
        let x = cs.alloc_input(Fr::from(3u64));
        let y = cs.alloc_aux(Fr::from(11u64));
        let product = Fr::from(33u64);

        cs.enforce(LinearCombination::from(x), LinearCombination::from(y), LinearCombination::from(product));
        assert!(cs.is_satisfied());

        let mut rng = thread_rng();
        let (pk, vk) = prover::setup(cs.clone(), &mut rng).expect("setup");
        let proof = prover::prove(&pk, cs.clone(), &mut rng).expect("prove");
        let inputs = vec![Fr::from(3u64)];

        assert_eq!(vk.gamma_abc_g1.len(), inputs.len() + 1, "vk-public mismatch");

        assert!(verifier::verify(&vk, &proof, &inputs).expect("verify"));
        let pvk = verifier::prepare(&vk);
        assert!(verifier::verify_prepared(&pvk, &proof, &inputs).expect("verify prepared"));
    }
}
