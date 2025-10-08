#![cfg(feature = "alloc")]
#![allow(dead_code)]

use alloc::{vec, vec::Vec};
use core::ops::MulAssign;

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{PrimeField, Zero};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};

use crate::srs::{CommitmentKey, VerifierKey};

/// KZGコミットメントで使用する汎用エラー。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KzgError {
    DegreeTooLarge { polynomial_degree: usize, srs_capacity: usize },
}

/// プロバーが生成するコミットメント。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Commitment<E: Pairing> {
    pub point: E::G1Affine,
}

/// 評価開示時に送る証明。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvaluationProof<E: Pairing> {
    pub quotient_commitment: E::G1Affine,
}

/// 多項式にコミットし、`Commitment`を返す。
pub fn commit<E>(
    key: &CommitmentKey<E>,
    poly: &DensePolynomial<E::ScalarField>,
) -> Result<Commitment<E>, KzgError>
where
    E: Pairing,
    E::ScalarField: PrimeField,
    E::G1Affine: AffineRepr<ScalarField = E::ScalarField>,
{
    if poly.degree() > key.degree() {
        return Err(KzgError::DegreeTooLarge {
            polynomial_degree: poly.degree(),
            srs_capacity: key.degree(),
        });
    }

    let point = multi_scalar_mul::<E>(key, poly.coeffs()).into_affine();
    Ok(Commitment { point })
}

/// 多項式`poly`の評価`poly(point)`を開示し、対応する証明を返す。
pub fn open<E>(
    key: &CommitmentKey<E>,
    poly: &DensePolynomial<E::ScalarField>,
    point: E::ScalarField,
) -> Result<(E::ScalarField, EvaluationProof<E>), KzgError>
where
    E: Pairing,
    E::ScalarField: PrimeField,
    E::G1Affine: AffineRepr<ScalarField = E::ScalarField>,
{
    if poly.degree() > key.degree() {
        return Err(KzgError::DegreeTooLarge {
            polynomial_degree: poly.degree(),
            srs_capacity: key.degree(),
        });
    }

    let (quotient_coeffs, value) = divide_by_linear(poly.coeffs(), point);
    let quotient_commitment = multi_scalar_mul::<E>(key, &quotient_coeffs).into_affine();

    Ok((
        value,
        EvaluationProof {
            quotient_commitment,
        },
    ))
}

/// KZG検証式 `e(C - y·G, H) == e(π, τ·H - z·H)` をチェックする。
pub fn verify<E>(
    key: &VerifierKey<E>,
    polynomial_commitment: &Commitment<E>,
    evaluation_point: E::ScalarField,
    claimed_value: E::ScalarField,
    proof: &EvaluationProof<E>,
) -> bool
where
    E: Pairing,
    E::ScalarField: PrimeField,
    E::G1Affine: AffineRepr<ScalarField = E::ScalarField>,
    E::G2Affine: AffineRepr<ScalarField = E::ScalarField>,
{
    let mut lhs_g1 = polynomial_commitment.point.into_group();
    let mut value_component = key.g_generator.into_group();
    value_component.mul_assign(claimed_value);
    lhs_g1 -= value_component;

    let mut rhs_g2 = key.h_tau.into_group();
    let mut point_component = key.h_generator.into_group();
    point_component.mul_assign(evaluation_point);
    rhs_g2 -= point_component;

    let lhs = E::pairing(lhs_g1.into_affine(), key.h_generator);
    let rhs = E::pairing(proof.quotient_commitment, rhs_g2.into_affine());
    lhs == rhs
}

fn multi_scalar_mul<E>(key: &CommitmentKey<E>, scalars: &[E::ScalarField]) -> E::G1
where
    E: Pairing,
    E::ScalarField: PrimeField,
    E::G1Affine: AffineRepr<ScalarField = E::ScalarField>,
{
    let mut acc = E::G1::zero();
    for (scalar, base) in scalars.iter().zip(key.powers().iter()) {
        if scalar.is_zero() {
            continue;
        }
        let mut term = base.clone().into_group();
        term.mul_assign(*scalar);
        acc += term;
    }
    acc
}

fn divide_by_linear<F>(coeffs: &[F], point: F) -> (Vec<F>, F)
where
    F: PrimeField,
{
    if coeffs.is_empty() {
        return (Vec::new(), F::ZERO);
    }

    let mut quotient = vec![F::ZERO; coeffs.len().saturating_sub(1)];
    let mut current = F::ZERO;
    for (idx, coeff) in coeffs.iter().enumerate().rev() {
        current *= point;
        current += *coeff;
        if idx > 0 {
            quotient[idx - 1] = current;
        }
    }

    (quotient, current)
}
#[cfg(all(test, feature = "curve-bls12-381"))]
mod tests {
    use super::*;

    use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective};
    use ark_ec::PrimeGroup;
    use crate::srs::KzgSrs;

    fn powers_of_tau(size: usize, tau: Fr) -> KzgSrs<Bls12_381> {
        assert!(size >= 2);

        let mut g1 = Vec::with_capacity(size);
        let mut g2 = Vec::with_capacity(size);

        let mut current1 = G1Projective::generator();
        let mut current2 = G2Projective::generator();

        for _ in 0..size {
            g1.push(current1.into_affine());
            g2.push(current2.into_affine());
            current1.mul_assign(tau);
            current2.mul_assign(tau);
        }

        KzgSrs::new(g1, g2).expect("valid SRS")
    }

    #[test]
    fn commit_open_verify_roundtrip() {
        let srs = powers_of_tau(8, Fr::from(5u64));
        let keys = srs.extract_keys(7).expect("keys");

        let poly = DensePolynomial::from_coefficients_vec(vec![
            Fr::from(3u64),
            Fr::from(5u64),
            Fr::from(2u64),
        ]);

        let commitment = commit::<Bls12_381>(&keys.committer, &poly).expect("commit");
        let point = Fr::from(11u64);
        let (value, proof) = open::<Bls12_381>(&keys.committer, &poly, point).expect("open");

        assert!(verify::<Bls12_381>(&keys.verifier, &commitment, point, value, &proof));
        assert!(!verify::<Bls12_381>(
            &keys.verifier,
            &commitment,
            point,
            value + Fr::from(1u64),
            &proof,
        ));
    }

    #[test]
    fn commit_rejects_large_degree() {
        let srs = powers_of_tau(3, Fr::from(2u64));
        let keys = srs.extract_keys(2).expect("keys");
        let poly = DensePolynomial::from_coefficients_vec(vec![
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        ]);

        let err = commit::<Bls12_381>(&keys.committer, &poly).unwrap_err();
        assert!(matches!(err, KzgError::DegreeTooLarge { .. }));
    }

    #[test]
    fn divide_by_linear_matches_evaluation() {
        let coeffs = [Fr::from(1u64), Fr::from(4u64), Fr::from(3u64)];
        let point = Fr::from(9u64);
        let poly = DensePolynomial::from_coefficients_vec(coeffs.to_vec());
        let (quotient, value) = divide_by_linear(&coeffs, point);

        assert_eq!(value, poly.evaluate(&point));

        let test_x = Fr::from(13u64);
        let quotient_poly = DensePolynomial::from_coefficients_vec(quotient.clone());
        let reconstructed = (test_x - point) * quotient_poly.evaluate(&test_x) + value;
        assert_eq!(reconstructed, poly.evaluate(&test_x));
    }
}
