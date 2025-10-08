#![cfg(feature = "alloc")]

use alloc::{vec, vec::Vec};
use core::fmt;

use ark_ec::pairing::Pairing;
use ark_ff::{One, PrimeField, Zero};
use ark_poly::univariate::DensePolynomial;
use ark_poly::{DenseUVPolynomial, Polynomial};

use crate::kzg::{commit, open, Commitment, EvaluationProof, KzgError};
use crate::permutation::{compute_grand_product, PermutationError};
use crate::poly::EvaluationDomain;
use crate::quotient::{QuotientBuilder, QuotientError};
use crate::srs::KzgKeys;

#[derive(Debug, Clone)]
pub struct GateSelectors<F: PrimeField> {
    pub q_l: Vec<F>,
    pub q_r: Vec<F>,
    pub q_o: Vec<F>,
    pub q_m: Vec<F>,
    pub q_c: Vec<F>,
}

#[derive(Debug, Clone)]
pub struct WireValues<F: PrimeField> {
    pub left: Vec<F>,
    pub right: Vec<F>,
    pub output: Vec<F>,
}

#[derive(Debug, Clone)]
pub struct PermutationPolynomials<F: PrimeField> {
    pub sigma: [Vec<F>; 3],
    pub identity: [Vec<F>; 3],
}

#[derive(Debug, Clone)]
pub struct PublicInputs<F: PrimeField> {
    pub assignments: Vec<(usize, F)>,
}

#[derive(Debug, Clone, Copy)]
pub struct TranscriptChallenges<F: PrimeField> {
    pub beta: F,
    pub gamma: F,
    pub alpha: F,
    pub zeta: F,
    pub nu: F,
    pub omega: F,
}

#[derive(Debug)]
pub struct PlonkProof<E: Pairing> {
    pub wire_commitments: [Commitment<E>; 3],
    pub permutation_commitment: Commitment<E>,
    pub quotient_commitment: Commitment<E>,
    pub wire_evaluations: [E::ScalarField; 3],
    pub selector_evaluations: [E::ScalarField; 5],
    pub permutation_evaluations: [E::ScalarField; 3],
    pub grand_product_eval: E::ScalarField,
    pub grand_product_shifted_eval: E::ScalarField,
    pub quotient_eval: E::ScalarField,
    pub wire_openings: [EvaluationProof<E>; 3],
    pub permutation_opening: EvaluationProof<E>,
    pub quotient_opening: EvaluationProof<E>,
}

#[derive(Debug)]
pub enum ProverError<F: PrimeField> {
    InvalidLength { expected: usize, found: usize },
    Permutation(PermutationError),
    Quotient(QuotientError),
    Kzg(KzgError),
    GrandProductNotNormalized(F),
}

impl<F: PrimeField> fmt::Display for ProverError<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProverError::InvalidLength { expected, found } => {
                write!(f, "expected length {expected}, found {found}")
            }
            ProverError::Permutation(err) => write!(f, "permutation error: {err}"),
            ProverError::Quotient(err) => write!(f, "quotient error: {err}"),
            ProverError::Kzg(err) => write!(f, "kzg error: {err:?}"),
            ProverError::GrandProductNotNormalized(v) => {
                write!(f, "grand product last value should be 1, got {v}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl<F: PrimeField> std::error::Error for ProverError<F> {}

pub fn prove<E: Pairing>(
    domain: &EvaluationDomain<E::ScalarField>,
    gates: &GateSelectors<E::ScalarField>,
    wires: &WireValues<E::ScalarField>,
    permutation: &PermutationPolynomials<E::ScalarField>,
    public_inputs: &PublicInputs<E::ScalarField>,
    challenges: TranscriptChallenges<E::ScalarField>,
    keys: &KzgKeys<E>,
) -> Result<PlonkProof<E>, ProverError<E::ScalarField>> {
    let n = domain.size();

    ensure_len(&gates.q_l, n)?;
    ensure_len(&gates.q_r, n)?;
    ensure_len(&gates.q_o, n)?;
    ensure_len(&gates.q_m, n)?;
    ensure_len(&gates.q_c, n)?;
    ensure_len(&wires.left, n)?;
    ensure_len(&wires.right, n)?;
    ensure_len(&wires.output, n)?;
    for column in permutation.sigma.iter().chain(permutation.identity.iter()) {
        ensure_len(column, n)?;
    }

    let mut left_eval = wires.left.clone();
    let mut right_eval = wires.right.clone();
    let mut output_eval = wires.output.clone();
    domain.ifft_in_place(&mut left_eval);
    domain.ifft_in_place(&mut right_eval);
    domain.ifft_in_place(&mut output_eval);

    let wire_polys = [
        DensePolynomial::from_coefficients_vec(left_eval.clone()),
        DensePolynomial::from_coefficients_vec(right_eval.clone()),
        DensePolynomial::from_coefficients_vec(output_eval.clone()),
    ];
    let blinded_wire_polys = blind_witness_polynomials(domain, &wire_polys, challenges.nu);

    let wire_commitments = [
        commit(&keys.committer, &blinded_wire_polys[0]).map_err(ProverError::Kzg)?,
        commit(&keys.committer, &blinded_wire_polys[1]).map_err(ProverError::Kzg)?,
        commit(&keys.committer, &blinded_wire_polys[2]).map_err(ProverError::Kzg)?,
    ];

    let identity_cols = permutation.identity.clone();
    let sigma_cols = permutation.sigma.clone();
    let identity_refs: Vec<&[E::ScalarField]> = identity_cols.iter().map(|c| c.as_slice()).collect();
    let sigma_refs: Vec<&[E::ScalarField]> = sigma_cols.iter().map(|c| c.as_slice()).collect();
    let witness_refs: Vec<&[E::ScalarField]> =
        vec![wires.left.as_slice(), wires.right.as_slice(), wires.output.as_slice()];

    let grand_product_evals = compute_grand_product(
        domain,
        &identity_refs,
        &sigma_refs,
        &witness_refs,
        challenges.beta,
        challenges.gamma,
    )
    .map_err(ProverError::Permutation)?;

    if grand_product_evals.last().copied().unwrap_or_else(E::ScalarField::zero) != E::ScalarField::one() {
        return Err(ProverError::GrandProductNotNormalized(
            grand_product_evals
                .last()
                .copied()
                .unwrap_or_else(E::ScalarField::zero),
        ));
    }

    let mut z_coeffs = grand_product_evals.clone();
    domain.ifft_in_place(&mut z_coeffs);
    let z_polynomial = DensePolynomial::from_coefficients_vec(z_coeffs);
    let permutation_commitment = commit(&keys.committer, &z_polynomial).map_err(ProverError::Kzg)?;

    let quotient_polynomial = build_quotient_polynomial(
        domain,
        gates,
        wires,
        &grand_product_evals,
        &identity_cols,
        &sigma_cols,
        public_inputs,
        challenges.beta,
        challenges.gamma,
        challenges.alpha,
    )?;

    let blinded_quotient = blind_polynomial_with_scalar(domain, &quotient_polynomial, challenges.omega);
    let quotient_commitment = commit(&keys.committer, &blinded_quotient).map_err(ProverError::Kzg)?;

    let selector_polys = selectors_to_polynomials(domain, gates);
    let sigma_polys = sigma_to_polynomials(domain, &sigma_cols);

    let zeta = challenges.zeta;
    let generator = domain.generator();

    let wire_evaluations = [
        blinded_wire_polys[0].evaluate(&zeta),
        blinded_wire_polys[1].evaluate(&zeta),
        blinded_wire_polys[2].evaluate(&zeta),
    ];

    let selector_evaluations = [
        selector_polys[0].evaluate(&zeta),
        selector_polys[1].evaluate(&zeta),
        selector_polys[2].evaluate(&zeta),
        selector_polys[3].evaluate(&zeta),
        selector_polys[4].evaluate(&zeta),
    ];

    let permutation_evaluations = [
        sigma_polys[0].evaluate(&zeta),
        sigma_polys[1].evaluate(&zeta),
        sigma_polys[2].evaluate(&zeta),
    ];

    let grand_product_eval = z_polynomial.evaluate(&zeta);
    let grand_product_shifted_eval = z_polynomial.evaluate(&(zeta * generator));
    let quotient_eval = blinded_quotient.evaluate(&zeta);

    let wire_openings = [
        open(&keys.committer, &blinded_wire_polys[0], zeta).map_err(ProverError::Kzg)?.1,
        open(&keys.committer, &blinded_wire_polys[1], zeta).map_err(ProverError::Kzg)?.1,
        open(&keys.committer, &blinded_wire_polys[2], zeta).map_err(ProverError::Kzg)?.1,
    ];
    let permutation_opening = open(&keys.committer, &z_polynomial, zeta).map_err(ProverError::Kzg)?.1;
    let quotient_opening = open(&keys.committer, &blinded_quotient, zeta).map_err(ProverError::Kzg)?.1;

    Ok(PlonkProof {
        wire_commitments,
        permutation_commitment,
        quotient_commitment,
        wire_evaluations,
        selector_evaluations,
        permutation_evaluations,
        grand_product_eval,
        grand_product_shifted_eval,
        quotient_eval,
        wire_openings,
        permutation_opening,
        quotient_opening,
    })
}

fn selectors_to_polynomials<F: PrimeField>(
    domain: &EvaluationDomain<F>,
    selectors: &GateSelectors<F>,
) -> [DensePolynomial<F>; 5] {
    let mut ql = selectors.q_l.clone();
    let mut qr = selectors.q_r.clone();
    let mut qo = selectors.q_o.clone();
    let mut qm = selectors.q_m.clone();
    let mut qc = selectors.q_c.clone();
    domain.ifft_in_place(&mut ql);
    domain.ifft_in_place(&mut qr);
    domain.ifft_in_place(&mut qo);
    domain.ifft_in_place(&mut qm);
    domain.ifft_in_place(&mut qc);
    [
        DensePolynomial::from_coefficients_vec(ql),
        DensePolynomial::from_coefficients_vec(qr),
        DensePolynomial::from_coefficients_vec(qo),
        DensePolynomial::from_coefficients_vec(qm),
        DensePolynomial::from_coefficients_vec(qc),
    ]
}

fn sigma_to_polynomials<F: PrimeField>(
    domain: &EvaluationDomain<F>,
    sigma_cols: &[Vec<F>; 3],
) -> [DensePolynomial<F>; 3] {
    let mut s1 = sigma_cols[0].clone();
    let mut s2 = sigma_cols[1].clone();
    let mut s3 = sigma_cols[2].clone();
    domain.ifft_in_place(&mut s1);
    domain.ifft_in_place(&mut s2);
    domain.ifft_in_place(&mut s3);
    [
        DensePolynomial::from_coefficients_vec(s1),
        DensePolynomial::from_coefficients_vec(s2),
        DensePolynomial::from_coefficients_vec(s3),
    ]
}

fn build_quotient_polynomial<F: PrimeField>(
    domain: &EvaluationDomain<F>,
    gates: &GateSelectors<F>,
    wires: &WireValues<F>,
    grand_product: &[F],
    identity_cols: &[Vec<F>; 3],
    sigma_cols: &[Vec<F>; 3],
    public_inputs: &PublicInputs<F>,
    beta: F,
    gamma: F,
    alpha: F,
) -> Result<DensePolynomial<F>, ProverError<F>> {
    let n = domain.size();
    let mut public_eval = vec![F::zero(); n];
    for &(index, value) in &public_inputs.assignments {
        if index >= n {
            return Err(ProverError::InvalidLength { expected: n, found: index });
        }
        public_eval[index] -= value;
    }

    let mut arithmetic = vec![F::zero(); n];
    for i in 0..n {
        let a = wires.left[i];
        let b = wires.right[i];
        let c = wires.output[i];
        arithmetic[i] = gates.q_l[i] * a
            + gates.q_r[i] * b
            + gates.q_o[i] * c
            + gates.q_m[i] * a * b
            + gates.q_c[i]
            + public_eval[i];
    }

    let mut permutation_term = vec![F::zero(); n];
    let mut boundary_term = vec![F::zero(); n];

    let mut id_products = vec![F::one(); n];
    let mut sigma_products = vec![F::one(); n];
    for i in 0..n {
        let wires_row = [wires.left[i], wires.right[i], wires.output[i]];
        for col in 0..3 {
            id_products[i] *= wires_row[col] + beta * identity_cols[col][i] + gamma;
            sigma_products[i] *= wires_row[col] + beta * sigma_cols[col][i] + gamma;
        }
    }

    for i in 0..n {
        let current_z = grand_product[i];
        let next_z = if i + 1 < n { grand_product[i + 1] } else { F::one() };
        permutation_term[i] = current_z * sigma_products[i] - next_z * id_products[i];
    }

    boundary_term[0] = grand_product[0] - F::one();

    let mut builder = QuotientBuilder::new(domain.clone());
    builder.add_in_place(&arithmetic);
    builder.add_scaled(&permutation_term, alpha);
    builder.add_scaled(&boundary_term, alpha * alpha);
    builder
        .finalize()
        .map_err(ProverError::Quotient)
}

fn ensure_len<F: PrimeField>(slice: &[F], expected: usize) -> Result<(), ProverError<F>> {
    if slice.len() != expected {
        return Err(ProverError::InvalidLength {
            expected,
            found: slice.len(),
        });
    }
    Ok(())
}

fn blind_witness_polynomials<F: PrimeField>(
    domain: &EvaluationDomain<F>,
    polys: &[DensePolynomial<F>; 3],
    seed: F,
) -> [DensePolynomial<F>; 3] {
    let mut scalars = [F::one(); 3];
    let mut power = seed;
    for scalar in scalars.iter_mut() {
        if power.is_zero() {
            *scalar = F::one();
        } else {
            *scalar = power;
        }
        power *= seed;
    }

    [
        blind_polynomial_with_scalar(domain, &polys[0], scalars[0]),
        blind_polynomial_with_scalar(domain, &polys[1], scalars[1]),
        blind_polynomial_with_scalar(domain, &polys[2], scalars[2]),
    ]
}

fn blind_polynomial_with_scalar<F: PrimeField>(
    domain: &EvaluationDomain<F>,
    poly: &DensePolynomial<F>,
    scalar: F,
) -> DensePolynomial<F> {
    if scalar.is_zero() {
        return poly.clone();
    }
    let zh = domain.vanishing_polynomial();
    let scaled = scale_polynomial(&zh, scalar);
    let mut result = poly.clone();
    result += &scaled;
    result
}

fn scale_polynomial<F: PrimeField>(poly: &DensePolynomial<F>, factor: F) -> DensePolynomial<F> {
    let coeffs = poly
        .coeffs()
        .iter()
        .map(|c| *c * factor)
        .collect();
    DensePolynomial::from_coefficients_vec(coeffs)
}

#[cfg(all(test, feature = "curve-bls12-381"))]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective};
    use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
    use ark_ff::{One, Zero};
    use core::ops::MulAssign;

    use crate::srs::KzgSrs;

    fn dummy_domain() -> EvaluationDomain<Fr> {
        EvaluationDomain::new(4).unwrap()
    }

    fn dummy_keys(domain: &EvaluationDomain<Fr>) -> KzgKeys<Bls12_381> {
        let size = domain.size() + 8;
        let mut g1 = Vec::with_capacity(size);
        let mut g2 = Vec::with_capacity(size);
        let mut current1 = G1Projective::generator();
        let mut current2 = G2Projective::generator();
        let scalar = Fr::from(5u64);
        for _ in 0..size {
            let affine1 = current1.into_affine();
            let affine2 = current2.into_affine();
            g1.push(affine1);
            g2.push(affine2);
            current1 = affine1.into_group();
            current2 = affine2.into_group();
            current1.mul_assign(scalar);
            current2.mul_assign(scalar);
        }
        let srs = KzgSrs::<Bls12_381>::new(g1, g2).unwrap();
        srs.extract_keys(domain.size()).unwrap()
    }

    #[test]
    fn basic_prover_pipeline_runs() {
        let domain = dummy_domain();
        let gates = GateSelectors {
            q_l: vec![Fr::one(); 4],
            q_r: vec![Fr::one(); 4],
            q_o: vec![-Fr::one(); 4],
            q_m: vec![Fr::zero(); 4],
            q_c: vec![Fr::zero(); 4],
        };
        let wires = WireValues {
            left: vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)],
            right: vec![Fr::from(1u64); 4],
            output: vec![Fr::from(2u64), Fr::from(3u64), Fr::from(4u64), Fr::from(5u64)],
        };
        let permutation = PermutationPolynomials {
            sigma: [
                wires.left.clone(),
                wires.right.clone(),
                wires.output.clone(),
            ],
            identity: [
                wires.left.clone(),
                wires.right.clone(),
                wires.output.clone(),
            ],
        };
        let public_inputs = PublicInputs { assignments: vec![] };
        let challenges = TranscriptChallenges {
            beta: Fr::from(2u64),
            gamma: Fr::from(3u64),
            alpha: Fr::from(4u64),
            zeta: Fr::from(5u64),
            nu: Fr::from(6u64),
            omega: Fr::from(7u64),
        };
        let keys = dummy_keys(&domain);

        let proof = prove::<Bls12_381>(
            &domain,
            &gates,
            &wires,
            &permutation,
            &public_inputs,
            challenges,
            &keys,
        )
        .expect("proof generation");
        assert_eq!(proof.wire_commitments.len(), 3);
    }
}
