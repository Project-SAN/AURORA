use ark_bls12_381::{Fq, Fr, G1Projective, G2Projective};
use ark_ff::{One, Zero};

pub type ScalarField = Fr;
pub type BaseField = Fq;
pub type G1 = G1Projective;
pub type G2 = G2Projective;

pub fn fr_one() -> ScalarField {
    ScalarField::one()
}

pub fn fr_zero() -> ScalarField {
    ScalarField::zero()
}
