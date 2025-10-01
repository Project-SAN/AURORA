use ark_bls12_381::{G1Projective, G2Projective};
use ark_ec::Group;
use ark_ff::PrimeField;

pub fn g1_add(a: &G1Projective, b: &G1Projective) -> G1Projective {
    *a + *b
}

pub fn g1_mul_scalar(base: &G1Projective, scalar: &ark_bls12_381::Fr) -> G1Projective {
    base.mul_bigint(scalar.into_bigint())
}

pub fn g2_mul_scalar(base: &G2Projective, scalar: &ark_bls12_381::Fr) -> G2Projective {
    base.mul_bigint(scalar.into_bigint())
}
