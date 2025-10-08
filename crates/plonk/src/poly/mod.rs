#![cfg(feature = "alloc")]

pub mod domain;
pub mod lagrange;

pub use domain::{DomainError, EvaluationDomain};
pub use lagrange::evaluate_lagrange_basis;
