use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof, VerifyingKey};
use ark_relations::r1cs::SynthesisError;
use ark_snark::SNARK;

pub fn prepare(vk: &VerifyingKey<Bls12_381>) -> PreparedVerifyingKey<Bls12_381> {
    prepare_verifying_key(vk)
}

pub fn verify(vk: &VerifyingKey<Bls12_381>, proof: &Proof<Bls12_381>, public_inputs: &[Fr]) -> Result<bool, SynthesisError> {
    Groth16::<Bls12_381>::verify(vk, public_inputs, proof)
}

pub fn verify_prepared(
    pvk: &PreparedVerifyingKey<Bls12_381>,
    proof: &Proof<Bls12_381>,
    public_inputs: &[Fr],
) -> Result<bool, SynthesisError> {
    Groth16::<Bls12_381>::verify_with_processed_vk(pvk, public_inputs, proof)
}
