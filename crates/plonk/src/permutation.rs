#![cfg(feature = "alloc")]

use alloc::vec::Vec;
use core::fmt;

use ark_ff::PrimeField;

use crate::poly::EvaluationDomain;

/// Bayer–Groth型置換議論のZ多項式を構成する。
pub fn compute_grand_product<F: PrimeField>(
    domain: &EvaluationDomain<F>,
    identity: &[&[F]],
    sigma: &[&[F]],
    witness: &[&[F]],
    beta: F,
    gamma: F,
) -> Result<Vec<F>, PermutationError> {
    let width = witness.len();
    if width == 0 || sigma.len() != width || identity.len() != width {
        return Err(PermutationError::ArityMismatch);
    }

    let n = domain.size();
    for column in witness.iter().chain(identity.iter()).chain(sigma.iter()) {
        if column.len() != n {
            return Err(PermutationError::SupportMismatch);
        }
    }

    let mut z = Vec::with_capacity(n);
    let mut accumulator = F::one();
    for idx in 0..n {
        let mut numerator = F::one();
        let mut denominator = F::one();
        for col in 0..width {
            numerator *= witness[col][idx] + beta * identity[col][idx] + gamma;
            denominator *= witness[col][idx] + beta * sigma[col][idx] + gamma;
        }
        let denom_inv = denominator
            .inverse()
            .ok_or(PermutationError::ZeroDenominator { index: idx })?;
        accumulator *= numerator * denom_inv;
        z.push(accumulator);
    }

    Ok(z)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermutationError {
    ArityMismatch,
    SupportMismatch,
    ZeroDenominator { index: usize },
}

impl fmt::Display for PermutationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PermutationError::ArityMismatch => write!(f, "permutation arity mismatch"),
            PermutationError::SupportMismatch => write!(f, "permutation column length mismatch"),
            PermutationError::ZeroDenominator { index } => {
                write!(f, "non invertible denominator at row {index}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PermutationError {}

#[cfg(all(test, feature = "curve-bls12-381"))]
mod tests {
    use super::*;
    use alloc::vec;
    use ark_bls12_381::Fr;
    use ark_ff::One;

    #[test]
    fn grand_product_identity_permutation() {
        let domain = EvaluationDomain::<Fr>::new(4).unwrap();
        let identity_vec: Vec<Vec<Fr>> = vec![
            (0..4).map(|i| domain.element(i)).collect(),
        ];
        let sigma_vec = identity_vec.clone();
        let witness_vec = vec![vec![Fr::from(1u64); 4]];
        let identity: Vec<&[Fr]> = identity_vec.iter().map(|v| v.as_slice()).collect();
        let sigma: Vec<&[Fr]> = sigma_vec.iter().map(|v| v.as_slice()).collect();
        let witness: Vec<&[Fr]> = witness_vec.iter().map(|v| v.as_slice()).collect();
        let beta = Fr::from(7u64);
        let gamma = Fr::from(9u64);

        let product = compute_grand_product(&domain, &identity, &sigma, &witness, beta, gamma).unwrap();
        assert_eq!(product.len(), 4);
        assert_eq!(product.last().copied().unwrap(), Fr::one());
    }
}
