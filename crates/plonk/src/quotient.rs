#![cfg(feature = "alloc")]

use alloc::{vec, vec::Vec};
use core::fmt;

use ark_ff::{PrimeField, Zero};
use ark_poly::univariate::DensePolynomial;
use ark_poly::DenseUVPolynomial;

use crate::poly::EvaluationDomain;

pub struct QuotientBuilder<F: PrimeField> {
    domain: EvaluationDomain<F>,
    evaluations: Vec<F>,
}

impl<F: PrimeField> QuotientBuilder<F> {
    pub fn new(domain: EvaluationDomain<F>) -> Self {
        let evaluations = vec![F::zero(); domain.size()];
        Self { domain, evaluations }
    }

    pub fn add_scaled(&mut self, column: &[F], scale: F) {
        for (target, value) in self.evaluations.iter_mut().zip(column.iter()) {
            *target += *value * scale;
        }
    }

    pub fn add_in_place(&mut self, column: &[F]) {
        for (target, value) in self.evaluations.iter_mut().zip(column.iter()) {
            *target += *value;
        }
    }

    pub fn finalize(mut self) -> Result<DensePolynomial<F>, QuotientError> {
        self.domain.ifft_in_place(&mut self.evaluations);
        let numerator = DensePolynomial::from_coefficients_vec(self.evaluations.clone());
        let (quotient, remainder) = numerator.divide_by_vanishing_poly(self.domain.inner().clone());
        if !remainder.is_zero() {
            return Err(QuotientError::NonZeroRemainder);
        }
        Ok(quotient)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuotientError {
    NonZeroRemainder,
}

impl fmt::Display for QuotientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QuotientError::NonZeroRemainder => write!(f, "vanishing polynomial division left remainder"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for QuotientError {}

#[cfg(all(test, feature = "curve-bls12-381"))]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ff::{One, Zero};

    #[test]
    fn quotient_builder_zero_numerator() {
        let domain = EvaluationDomain::<Fr>::new(4).unwrap();
        let builder = QuotientBuilder::new(domain.clone());
        let quotient = builder.finalize().unwrap();
        assert!(quotient.is_zero());
    }

    #[test]
    fn quotient_builder_detects_non_divisible() {
        let domain = EvaluationDomain::<Fr>::new(4).unwrap();
        let mut builder = QuotientBuilder::new(domain.clone());
        let data: Vec<_> = (0..domain.size()).map(|_| Fr::one()).collect();
        builder.add_in_place(&data);
        let err = builder.finalize().unwrap_err();
        assert!(matches!(err, QuotientError::NonZeroRemainder));
    }
}
