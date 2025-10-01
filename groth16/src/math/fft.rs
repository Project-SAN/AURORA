use alloc::vec::Vec;
use ark_ff::FftField;
use ark_poly::domain::Radix2EvaluationDomain;
use ark_poly::EvaluationDomain;

pub fn evaluate_poly<F: FftField>(coeffs: &[F]) -> (Radix2EvaluationDomain<F>, Vec<F>) {
    let domain = Radix2EvaluationDomain::<F>::new(coeffs.len()).expect("domain size must be power of two");
    let mut evals = coeffs.to_vec();
    domain.fft_in_place(&mut evals);
    (domain, evals)
}
