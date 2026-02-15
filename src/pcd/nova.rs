use crate::pcd::{PcdBackend, PcdState};
use crate::types::{Error, Result};
use bincode;
use ff::PrimeField;
use nova_snark::frontend::num::AllocatedNum;
use nova_snark::frontend::{ConstraintSystem, SynthesisError};
use nova_snark::nova::{PublicParams, RecursiveSNARK};
use nova_snark::provider::hyperkzg;
use nova_snark::provider::ipa_pc;
use nova_snark::provider::{Bn256EngineKZG, GrumpkinEngine};
use nova_snark::traits::circuit::StepCircuit;
use nova_snark::traits::{snark::RelaxedR1CSSNARKTrait, Engine, Group};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

type E1 = Bn256EngineKZG;
type E2 = GrumpkinEngine;
type Scalar1 = <E1 as Engine>::Scalar;
type EE1 = hyperkzg::EvaluationEngine<E1>;
type EE2 = ipa_pc::EvaluationEngine<E2>;
type S1 = nova_snark::spartan::ppsnark::RelaxedR1CSSNARK<E1, EE1>;
type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>;

#[derive(Clone, Debug, Default)]
struct PcdStepCircuit;

impl<F: PrimeField> StepCircuit<F> for PcdStepCircuit {
    fn arity(&self) -> usize {
        4
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z_in: &[AllocatedNum<F>],
    ) -> core::result::Result<Vec<AllocatedNum<F>>, SynthesisError> {
        if z_in.len() != 4 {
            return Err(SynthesisError::AssignmentMissing);
        }
        let hkey_in = &z_in[0];
        let seq_in = &z_in[1];
        let root_in = &z_in[2];
        let target_in = &z_in[3];

        let hkey_out = AllocatedNum::alloc(cs.namespace(|| "hkey_out"), || {
            hkey_in.get_value().ok_or(SynthesisError::AssignmentMissing)
        })?;
        let root_out = AllocatedNum::alloc(cs.namespace(|| "root_out"), || {
            root_in.get_value().ok_or(SynthesisError::AssignmentMissing)
        })?;
        let target_out = AllocatedNum::alloc(cs.namespace(|| "target_out"), || {
            target_in
                .get_value()
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let seq_out = AllocatedNum::alloc(cs.namespace(|| "seq_out"), || {
            let one = F::ONE;
            let value = seq_in
                .get_value()
                .ok_or(SynthesisError::AssignmentMissing)?;
            Ok(value + one)
        })?;

        cs.enforce(
            || "hkey_out = hkey_in",
            |lc| lc + hkey_out.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + hkey_in.get_variable(),
        );
        cs.enforce(
            || "root_out = root_in",
            |lc| lc + root_out.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + root_in.get_variable(),
        );
        cs.enforce(
            || "target_out = target_in",
            |lc| lc + target_out.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + target_in.get_variable(),
        );
        cs.enforce(
            || "seq_out = seq_in + 1",
            |lc| lc + seq_out.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + seq_in.get_variable() + CS::one(),
        );

        Ok(vec![hkey_out, seq_out, root_out, target_out])
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PcdNovaProof {
    num_steps: u64,
    snark: RecursiveSNARK<E1, E2, PcdStepCircuit>,
}

pub struct NovaPcdBackend {
    pp: PublicParams<E1, E2, PcdStepCircuit>,
    circuit: PcdStepCircuit,
    modulus: BigUint,
}

impl NovaPcdBackend {
    pub fn new() -> Result<Self> {
        let circuit = PcdStepCircuit::default();
        let pp = PublicParams::setup(&circuit, &*S1::ck_floor(), &*S2::ck_floor())
            .map_err(|_| Error::PolicyViolation)?;
        let modulus = <<E1 as Engine>::GE as Group>::group_params()
            .2
            .to_biguint()
            .ok_or(Error::PolicyViolation)?;
        Ok(Self {
            pp,
            circuit,
            modulus,
        })
    }

    fn scalar_from_bytes<F: PrimeField>(&self, bytes: &[u8]) -> Result<F> {
        let mut value = BigUint::from_bytes_be(bytes);
        if value >= self.modulus {
            value %= &self.modulus;
        }
        let repr = value.to_str_radix(10);
        F::from_str_vartime(&repr).ok_or(Error::PolicyViolation)
    }

    fn z0_from_state(&self, state: &PcdState) -> Result<Vec<Scalar1>> {
        Ok(vec![
            self.scalar_from_bytes::<Scalar1>(&state.hkey)?,
            Scalar1::from(0u64),
            self.scalar_from_bytes::<Scalar1>(&state.root)?,
            self.scalar_from_bytes::<Scalar1>(&state.htarget)?,
        ])
    }

    fn state_to_z(&self, state: &PcdState) -> Result<Vec<Scalar1>> {
        Ok(vec![
            self.scalar_from_bytes::<Scalar1>(&state.hkey)?,
            Scalar1::from(state.seq),
            self.scalar_from_bytes::<Scalar1>(&state.root)?,
            self.scalar_from_bytes::<Scalar1>(&state.htarget)?,
        ])
    }

    fn decode_proof(&self, bytes: &[u8]) -> Result<PcdNovaProof> {
        bincode::deserialize(bytes).map_err(|_| Error::PolicyViolation)
    }

    fn encode_proof(&self, proof: &PcdNovaProof) -> Result<Vec<u8>> {
        bincode::serialize(proof).map_err(|_| Error::PolicyViolation)
    }
}

impl PcdBackend for NovaPcdBackend {
    fn hash(&self, state: &PcdState) -> [u8; 32] {
        state.hash()
    }

    fn step(&self, prev: &PcdState) -> PcdState {
        prev.next_seq()
    }

    fn prove_base(&self, initial: &PcdState) -> Result<Vec<u8>> {
        if initial.seq == 0 {
            return Err(Error::PolicyViolation);
        }
        let z0 = self.z0_from_state(initial)?;
        let mut snark = RecursiveSNARK::new(&self.pp, &self.circuit, &z0)
            .map_err(|_| Error::PolicyViolation)?;
        let mut num_steps = 0u64;
        while num_steps < initial.seq {
            snark
                .prove_step(&self.pp, &self.circuit)
                .map_err(|_| Error::PolicyViolation)?;
            num_steps = num_steps.saturating_add(1);
        }
        let proof = PcdNovaProof { num_steps, snark };
        self.encode_proof(&proof)
    }

    fn prove_step(&self, prev: &PcdState, prev_proof: &[u8]) -> Result<Vec<u8>> {
        if prev.seq == 0 {
            return Err(Error::PolicyViolation);
        }
        let mut proof = self.decode_proof(prev_proof)?;
        if proof.num_steps != prev.seq {
            return Err(Error::PolicyViolation);
        }
        proof
            .snark
            .prove_step(&self.pp, &self.circuit)
            .map_err(|_| Error::PolicyViolation)?;
        proof.num_steps = proof.num_steps.saturating_add(1);
        self.encode_proof(&proof)
    }

    fn verify_step(&self, prev: &PcdState, proof: &[u8]) -> Result<()> {
        if prev.seq == 0 {
            return Err(Error::PolicyViolation);
        }
        let proof = self.decode_proof(proof)?;
        if proof.num_steps != prev.seq {
            return Err(Error::PolicyViolation);
        }
        let z0 = self.z0_from_state(prev)?;
        let zi = proof
            .snark
            .verify(&self.pp, proof.num_steps as usize, &z0)
            .map_err(|_| Error::PolicyViolation)?;
        let expected = self.state_to_z(prev)?;
        if zi != expected {
            return Err(Error::PolicyViolation);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nova_pcd_base_and_verify() {
        let backend = NovaPcdBackend::new().expect("backend");
        let state = PcdState {
            hkey: [1u8; 32],
            seq: 1,
            root: [2u8; 32],
            htarget: [3u8; 32],
        };
        let proof = backend.prove_base(&state).expect("proof");
        backend.verify_step(&state, &proof).expect("verify");
        let mut corrupted = proof.clone();
        if let Some(first) = corrupted.first_mut() {
            *first ^= 0xFF;
        } else {
            corrupted.push(0xFF);
        }
        let result = backend.verify_step(&state, &corrupted);
        assert!(matches!(result, Err(Error::PolicyViolation)));
    }
}
