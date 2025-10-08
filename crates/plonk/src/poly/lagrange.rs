#![cfg(feature = "alloc")]

use ark_ff::PrimeField;

use super::EvaluationDomain;

/// ドメイン上のLagrange基底多項式L_iを任意点で評価する。
pub fn evaluate_lagrange_basis<F: PrimeField>(domain: &EvaluationDomain<F>, index: usize, point: F) -> F {
    let omega_i = domain.element(index);
    if point == omega_i {
        return F::ONE;
    }

    let n = domain.size() as u64;
    let numerator = point.pow(&[n]) - F::ONE;
    let denominator = F::from(domain.size() as u128) * (point - omega_i);
    numerator * denominator.inverse().expect("non-zero denominator")
}
