use alloc::vec::Vec;
use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, LinearCombination as ArkLC, SynthesisError, Variable as ArkVar};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};

use crate::r1cs::{ConstraintSystem, LinearCombination, VariableType};

#[derive(Clone)]
struct StaticCircuit<F: ark_ff::Field> {
    cs: ConstraintSystem<F>,
}

impl<F: ark_ff::Field> StaticCircuit<F> {
    fn new(cs: ConstraintSystem<F>) -> Self {
        Self { cs }
    }
}

impl<F: ark_ff::Field> ConstraintSynthesizer<F> for StaticCircuit<F> {
    fn generate_constraints(self, cs_ref: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let mut input_vars: Vec<ArkVar> = Vec::with_capacity(self.cs.inputs.len());
        let mut aux_vars: Vec<ArkVar> = Vec::with_capacity(self.cs.aux.len());

        let one = ArkVar::One;

        for value in self.cs.inputs.iter() {
            let var = cs_ref.new_input_variable(|| Ok(*value))?;
            input_vars.push(var);
        }
        for value in self.cs.aux.iter() {
            let var = cs_ref.new_witness_variable(|| Ok(*value))?;
            aux_vars.push(var);
        }

        for constraint in self.cs.constraints.iter() {
            let a = convert_lc(&constraint.a, one, &input_vars, &aux_vars);
            let b = convert_lc(&constraint.b, one, &input_vars, &aux_vars);
            let c = convert_lc(&constraint.c, one, &input_vars, &aux_vars);
            cs_ref.enforce_constraint(a, b, c)?;
        }
        Ok(())
    }
}

fn convert_lc<F: ark_ff::Field>(
    lc: &LinearCombination<F>,
    one: ArkVar,
    inputs: &[ArkVar],
    aux: &[ArkVar],
) -> ArkLC<F> {
    let mut out = ArkLC::zero();
    out += (lc.constant, one);
    for (var, coeff) in lc.terms.iter() {
        let ark_var = match var.var_type {
            VariableType::Input => inputs[var.index],
            VariableType::Aux => aux[var.index],
        };
        out += (*coeff, ark_var);
    }
    out
}

pub fn setup<R: RngCore + CryptoRng>(
    cs: ConstraintSystem<Fr>,
    rng: &mut R,
) -> Result<(ProvingKey<Bls12_381>, VerifyingKey<Bls12_381>), SynthesisError> {
    let circuit = StaticCircuit::new(cs);
    Groth16::<Bls12_381>::circuit_specific_setup(circuit, rng)
}

pub fn prove<R: RngCore + CryptoRng>(
    pk: &ProvingKey<Bls12_381>,
    cs: ConstraintSystem<Fr>,
    rng: &mut R,
) -> Result<Proof<Bls12_381>, SynthesisError> {
    let circuit = StaticCircuit::new(cs);
    Groth16::<Bls12_381>::prove(pk, circuit, rng)
}
