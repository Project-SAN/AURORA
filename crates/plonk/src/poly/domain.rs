#![cfg(feature = "alloc")]

use alloc::vec::Vec;
use core::fmt;

use ark_ff::PrimeField;
use ark_poly::domain::general::GeneralEvaluationDomain;
use ark_poly::univariate::DensePolynomial;
use ark_poly::EvaluationDomain as _;

/// Roots-of-unityドメインの薄いラッパー。
#[derive(Clone)]
pub struct EvaluationDomain<F: PrimeField> {
    inner: GeneralEvaluationDomain<F>,
}

impl<F: PrimeField> EvaluationDomain<F> {
    pub fn new(size: usize) -> Result<Self, DomainError> {
        let inner = GeneralEvaluationDomain::<F>::new(size)
            .ok_or(DomainError::UnsupportedSize { size })?;
        Ok(Self { inner })
    }

    pub fn size(&self) -> usize {
        self.inner.size()
    }

    pub fn generator(&self) -> F {
        self.inner.group_gen()
    }

    pub fn element(&self, index: usize) -> F {
        self.inner.element(index)
    }

    pub fn fft_in_place(&self, values: &mut Vec<F>) {
        self.inner.fft_in_place(values)
    }

    pub fn ifft_in_place(&self, values: &mut Vec<F>) {
        self.inner.ifft_in_place(values)
    }

    pub fn vanishing_polynomial(&self) -> DensePolynomial<F> {
        self.inner.vanishing_polynomial().into()
    }

    pub fn evaluate_vanishing_polynomial(&self, point: F) -> F {
        self.inner.evaluate_vanishing_polynomial(point)
    }

    pub(crate) fn inner(&self) -> &GeneralEvaluationDomain<F> {
        &self.inner
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainError {
    UnsupportedSize { size: usize },
}

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DomainError::UnsupportedSize { size } => write!(f, "domain size {size} unsupported"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DomainError {}
