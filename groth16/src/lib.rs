#![no_std]

extern crate alloc;

pub mod math;
pub mod r1cs;
pub mod prover;
pub mod verifier;

pub use r1cs::{Constraint, ConstraintSystem, LinearCombination, Variable, VariableType};
