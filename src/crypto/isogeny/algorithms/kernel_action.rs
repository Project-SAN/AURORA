//! Julia-aligned kernel coefficient extraction helpers.
//!
//! This module ports the pure arithmetic part of `kernel_coefficients` and
//! `kernel_generator` from the SQIsignIQO Julia implementation. The current
//! path is a reference port for action matrices that fit in `i128`, which is
//! enough to wire the backend structure before the full wide-matrix torsion
//! action backend lands.

use alloc::vec::Vec;

use crate::crypto::isogeny::curve::montgomery::{CurveError, MontgomeryCurve};
use crate::crypto::isogeny::curve::point::CurvePoint;
use crate::crypto::isogeny::curve::weierstrass::ShortWeierstrassCurve;
use crate::crypto::isogeny::ideal::ideal::{IdealError, LeftIdeal};
use crate::crypto::isogeny::ideal::quaternion::{QuaternionElement, QuaternionError};

pub type Result<T> = core::result::Result<T, KernelActionError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KernelActionError {
    Ideal(IdealError),
    Curve(CurveError),
    Quaternion(QuaternionError),
    NoElementPrimeTo,
    MatrixOverflow,
    UnsupportedDegree,
    NonInvertibleCoefficient,
}

impl From<IdealError> for KernelActionError {
    fn from(value: IdealError) -> Self {
        Self::Ideal(value)
    }
}

impl From<CurveError> for KernelActionError {
    fn from(value: CurveError) -> Self {
        Self::Curve(value)
    }
}

impl From<QuaternionError> for KernelActionError {
    fn from(value: QuaternionError) -> Self {
        Self::Quaternion(value)
    }
}

pub type ActionMatrix = [[i128; 2]; 2];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TorsionActionMatrices {
    pub basis_i: ActionMatrix,
    pub basis_j: ActionMatrix,
    pub basis_k: ActionMatrix,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelCoefficients {
    pub a: i128,
    pub b: i128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawKernelVector {
    pub a: i128,
    pub b: i128,
    pub modulus: i128,
}

pub fn element_prime_to(ideal: &LeftIdeal, l: u64) -> Result<QuaternionElement> {
    let mut candidates = Vec::new();
    candidates.push(ideal.generator());
    for coeff_bound in [2, 3, 4, 6, 8] {
        candidates.extend(ideal.enumerate_short_elements(coeff_bound, 32)?);
    }
    for candidate in candidates {
        if candidate.reduced_norm().rem_u64(l).unwrap_or(0) != 0 {
            return Ok(candidate);
        }
    }
    Err(KernelActionError::NoElementPrimeTo)
}

pub fn kernel_coefficients_e0_from_element(
    alpha: QuaternionElement,
    l: u64,
    e: usize,
    matrices: &TorsionActionMatrices,
) -> Result<KernelCoefficients> {
    let matrix = action_matrix(alpha, matrices)?;
    kernel_coefficients_from_matrix(matrix, l, e)
}

pub fn kernel_coefficients_e0(
    ideal: &LeftIdeal,
    l: u64,
    e: usize,
    matrices: &TorsionActionMatrices,
) -> Result<KernelCoefficients> {
    let alpha = element_prime_to(ideal, l)?;
    kernel_coefficients_e0_from_element(alpha, l, e, matrices)
}

pub fn kernel_coefficients(
    ideal: &LeftIdeal,
    basis_change: ActionMatrix,
    l: u64,
    e: usize,
    matrices: &TorsionActionMatrices,
) -> Result<KernelCoefficients> {
    let coeffs = kernel_coefficients_e0(ideal, l, e, matrices)?;
    let lifted = [
        basis_change[0][0]
            .checked_mul(coeffs.a)
            .and_then(|v| {
                basis_change[0][1]
                    .checked_mul(coeffs.b)
                    .and_then(|w| v.checked_add(w))
            })
            .ok_or(KernelActionError::MatrixOverflow)?,
        basis_change[1][0]
            .checked_mul(coeffs.a)
            .and_then(|v| {
                basis_change[1][1]
                    .checked_mul(coeffs.b)
                    .and_then(|w| v.checked_add(w))
            })
            .ok_or(KernelActionError::MatrixOverflow)?,
    ];
    normalize_coefficients(lifted[0], lifted[1], l, e)
}

pub fn kernel_vector(
    ideal: &LeftIdeal,
    basis_change: ActionMatrix,
    l: u64,
    e: usize,
    matrices: &TorsionActionMatrices,
) -> Result<RawKernelVector> {
    let coeffs = kernel_coefficients_e0(ideal, l, e, matrices)?;
    let modulus = prime_power_i128(l, e)?;
    let lifted = apply_basis_change_raw(basis_change, coeffs.a, coeffs.b, modulus)?;
    Ok(RawKernelVector {
        a: lifted[0],
        b: lifted[1],
        modulus,
    })
}

pub fn kernel_generator_affine(
    curve: &MontgomeryCurve,
    p: &CurvePoint,
    q: &CurvePoint,
    ideal: &LeftIdeal,
    basis_change: ActionMatrix,
    l: u64,
    e: usize,
    matrices: &TorsionActionMatrices,
) -> Result<CurvePoint> {
    let coeffs = kernel_coefficients(ideal, basis_change, l, e, matrices)?;
    let modulus = prime_power_i128(l, e)?;
    if coeffs.a == 1 {
        let q_term = curve.scalar_mul_u64(q, mod_nonnegative(coeffs.b, modulus) as u64)?;
        Ok(curve.add(p, &q_term)?)
    } else {
        let p_term = curve.scalar_mul_u64(p, mod_nonnegative(coeffs.a, modulus) as u64)?;
        Ok(curve.add(&p_term, q)?)
    }
}

pub fn kernel_generator_curve(
    curve: &ShortWeierstrassCurve,
    p: &CurvePoint,
    q: &CurvePoint,
    ideal: &LeftIdeal,
    basis_change: ActionMatrix,
    l: u64,
    e: usize,
    matrices: &TorsionActionMatrices,
) -> Result<CurvePoint> {
    let coeffs = kernel_coefficients(ideal, basis_change, l, e, matrices)?;
    let modulus = prime_power_i128(l, e)?;
    if coeffs.a == 1 {
        let q_term = curve
            .scalar_mul_u64(q, mod_nonnegative(coeffs.b, modulus) as u64)
            .map_err(|_| KernelActionError::Curve(CurveError::PointNotOnCurve))?;
        curve
            .add(p, &q_term)
            .map_err(|_| KernelActionError::Curve(CurveError::PointNotOnCurve))
    } else {
        let p_term = curve
            .scalar_mul_u64(p, mod_nonnegative(coeffs.a, modulus) as u64)
            .map_err(|_| KernelActionError::Curve(CurveError::PointNotOnCurve))?;
        curve
            .add(&p_term, q)
            .map_err(|_| KernelActionError::Curve(CurveError::PointNotOnCurve))
    }
}

pub fn kernel_generator_curve_raw(
    curve: &ShortWeierstrassCurve,
    p: &CurvePoint,
    q: &CurvePoint,
    ideal: &LeftIdeal,
    basis_change: ActionMatrix,
    l: u64,
    e: usize,
    matrices: &TorsionActionMatrices,
) -> Result<CurvePoint> {
    let vector = kernel_vector(ideal, basis_change, l, e, matrices)?;
    let p_term = curve
        .scalar_mul_u64(p, mod_nonnegative(vector.a, vector.modulus) as u64)
        .map_err(|_| KernelActionError::Curve(CurveError::PointNotOnCurve))?;
    let q_term = curve
        .scalar_mul_u64(q, mod_nonnegative(vector.b, vector.modulus) as u64)
        .map_err(|_| KernelActionError::Curve(CurveError::PointNotOnCurve))?;
    curve
        .add(&p_term, &q_term)
        .map_err(|_| KernelActionError::Curve(CurveError::PointNotOnCurve))
}

pub fn mul_action_matrices_mod(
    lhs: ActionMatrix,
    rhs: ActionMatrix,
    modulus: i128,
) -> Result<ActionMatrix> {
    let mut out = [[0i128; 2]; 2];
    for row in 0..2 {
        for col in 0..2 {
            let mut acc = 0i128;
            for mid in 0..2 {
                acc = acc
                    .checked_add(
                        lhs[row][mid]
                            .checked_mul(rhs[mid][col])
                            .ok_or(KernelActionError::MatrixOverflow)?,
                    )
                    .ok_or(KernelActionError::MatrixOverflow)?;
            }
            out[row][col] = mod_nonnegative(acc, modulus);
        }
    }
    Ok(out)
}

pub fn inv_action_matrix_mod(matrix: ActionMatrix, modulus: i128) -> Result<ActionMatrix> {
    let det = mod_nonnegative(
        matrix[0][0]
            .checked_mul(matrix[1][1])
            .and_then(|value| matrix[0][1].checked_mul(matrix[1][0]).and_then(|other| value.checked_sub(other)))
            .ok_or(KernelActionError::MatrixOverflow)?,
        modulus,
    );
    let inv_det = inv_mod_i128(det, modulus).ok_or(KernelActionError::NonInvertibleCoefficient)?;
    Ok([
        [
            mod_nonnegative(
                matrix[1][1]
                    .checked_mul(inv_det)
                    .ok_or(KernelActionError::MatrixOverflow)?,
                modulus,
            ),
            mod_nonnegative(
                (-matrix[0][1])
                    .checked_mul(inv_det)
                    .ok_or(KernelActionError::MatrixOverflow)?,
                modulus,
            ),
        ],
        [
            mod_nonnegative(
                (-matrix[1][0])
                    .checked_mul(inv_det)
                    .ok_or(KernelActionError::MatrixOverflow)?,
                modulus,
            ),
            mod_nonnegative(
                matrix[0][0]
                    .checked_mul(inv_det)
                    .ok_or(KernelActionError::MatrixOverflow)?,
                modulus,
            ),
        ],
    ])
}

fn action_matrix(
    alpha: QuaternionElement,
    matrices: &TorsionActionMatrices,
) -> Result<ActionMatrix> {
    let coeffs = alpha.coeffs();
    let scalar = coeffs[0]
        .try_to_i128()
        .ok_or(KernelActionError::MatrixOverflow)?;
    let coeff_i = coeffs[1]
        .try_to_i128()
        .ok_or(KernelActionError::MatrixOverflow)?;
    let coeff_j = coeffs[2]
        .try_to_i128()
        .ok_or(KernelActionError::MatrixOverflow)?;
    let coeff_k = coeffs[3]
        .try_to_i128()
        .ok_or(KernelActionError::MatrixOverflow)?;

    let identity = [[1i128, 0], [0, 1]];
    combine_action_matrices(
        [
            (scalar, identity),
            (coeff_i, matrices.basis_i),
            (coeff_j, matrices.basis_j),
            (coeff_k, matrices.basis_k),
        ]
        .as_slice(),
    )
}

fn combine_action_matrices(terms: &[(i128, ActionMatrix)]) -> Result<ActionMatrix> {
    let mut out = [[0i128; 2]; 2];
    for (scalar, matrix) in terms {
        for row in 0..2 {
            for col in 0..2 {
                out[row][col] = out[row][col]
                    .checked_add(
                        matrix[row][col]
                            .checked_mul(*scalar)
                            .ok_or(KernelActionError::MatrixOverflow)?,
                    )
                    .ok_or(KernelActionError::MatrixOverflow)?;
            }
        }
    }
    Ok(out)
}

fn apply_basis_change_raw(
    basis_change: ActionMatrix,
    a: i128,
    b: i128,
    modulus: i128,
) -> Result<[i128; 2]> {
    Ok([
        mod_nonnegative(
            basis_change[0][0]
                .checked_mul(a)
                .and_then(|v| {
                    basis_change[0][1]
                        .checked_mul(b)
                        .and_then(|w| v.checked_add(w))
                })
                .ok_or(KernelActionError::MatrixOverflow)?,
            modulus,
        ),
        mod_nonnegative(
            basis_change[1][0]
                .checked_mul(a)
                .and_then(|v| {
                    basis_change[1][1]
                        .checked_mul(b)
                        .and_then(|w| v.checked_add(w))
                })
                .ok_or(KernelActionError::MatrixOverflow)?,
            modulus,
        ),
    ])
}

fn kernel_coefficients_from_matrix(
    matrix: ActionMatrix,
    l: u64,
    e: usize,
) -> Result<KernelCoefficients> {
    let (a, b) = if matrix[0][0] % l as i128 != 0 || matrix[0][1] % l as i128 != 0 {
        (matrix[0][1], -matrix[0][0])
    } else {
        (matrix[1][1], -matrix[1][0])
    };
    normalize_coefficients(a, b, l, e)
}

fn normalize_coefficients(a: i128, b: i128, l: u64, e: usize) -> Result<KernelCoefficients> {
    let n = prime_power_i128(l, e)?;
    if a % l as i128 != 0 {
        let inv = inv_mod_i128(a, n).ok_or(KernelActionError::NonInvertibleCoefficient)?;
        Ok(KernelCoefficients {
            a: 1,
            b: mod_nonnegative(
                b.checked_mul(inv)
                    .ok_or(KernelActionError::MatrixOverflow)?,
                n,
            ),
        })
    } else {
        let inv = inv_mod_i128(b, n).ok_or(KernelActionError::NonInvertibleCoefficient)?;
        Ok(KernelCoefficients {
            a: mod_nonnegative(
                a.checked_mul(inv)
                    .ok_or(KernelActionError::MatrixOverflow)?,
                n,
            ),
            b: 1,
        })
    }
}

fn prime_power_i128(l: u64, e: usize) -> Result<i128> {
    let mut acc = 1i128;
    for _ in 0..e {
        acc = acc
            .checked_mul(i128::from(l))
            .ok_or(KernelActionError::UnsupportedDegree)?;
    }
    Ok(acc)
}

fn mod_nonnegative(value: i128, modulus: i128) -> i128 {
    let mut reduced = value % modulus;
    if reduced < 0 {
        reduced += modulus;
    }
    reduced
}

fn inv_mod_i128(value: i128, modulus: i128) -> Option<i128> {
    let mut t = 0i128;
    let mut new_t = 1i128;
    let mut r = modulus;
    let mut new_r = mod_nonnegative(value, modulus);
    while new_r != 0 {
        let q = r / new_r;
        let temp_t = t.checked_sub(q.checked_mul(new_t)?)?;
        t = new_t;
        new_t = temp_t;
        let temp_r = r.checked_sub(q.checked_mul(new_r)?)?;
        r = new_r;
        new_r = temp_r;
    }
    if r != 1 {
        return None;
    }
    Some(mod_nonnegative(t, modulus))
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::{
        element_prime_to, inv_action_matrix_mod, kernel_coefficients,
        kernel_coefficients_e0_from_element, kernel_generator_affine, mul_action_matrices_mod,
        ActionMatrix, KernelCoefficients, TorsionActionMatrices,
    };
    use crate::crypto::isogeny::curve::montgomery::MontgomeryCurve;
    use crate::crypto::isogeny::curve::point::CurvePoint;
    use crate::crypto::isogeny::field::{Fp2, FpModulus};
    use crate::crypto::isogeny::ideal::ideal::LeftIdeal;
    use crate::crypto::isogeny::ideal::order::MaximalOrder;
    use crate::crypto::isogeny::ideal::quaternion::{QuaternionAlgebra, QuaternionElement};

    fn matrices() -> TorsionActionMatrices {
        TorsionActionMatrices {
            basis_i: [[0, 1], [1, 0]],
            basis_j: [[0, 0], [0, 0]],
            basis_k: [[0, 0], [0, 0]],
        }
    }

    fn identity_matrix() -> ActionMatrix {
        [[1, 0], [0, 1]]
    }

    fn modulus19() -> FpModulus {
        FpModulus::from_u64(19).unwrap()
    }

    fn fp2(value: u64) -> Fp2 {
        Fp2::from_u64(&modulus19(), value)
    }

    fn curve19() -> MontgomeryCurve {
        MontgomeryCurve::new(fp2(5)).unwrap()
    }

    fn affine(x: u64, y: u64) -> CurvePoint {
        CurvePoint::affine(fp2(x), fp2(y))
    }

    fn enumerate_points(curve: &MontgomeryCurve) -> Vec<CurvePoint> {
        let mut points = Vec::new();
        for x in 0..19u64 {
            for y in 0..19u64 {
                let point = affine(x, y);
                if curve.validate_point(&point).is_ok() {
                    points.push(point);
                }
            }
        }
        points
    }

    fn sample_points(curve: &MontgomeryCurve) -> (CurvePoint, CurvePoint) {
        let points = enumerate_points(curve);
        let p = points
            .iter()
            .copied()
            .find(|point| !point.y.is_zero())
            .unwrap();
        let q = points
            .iter()
            .copied()
            .find(|point| point.x != p.x && *point != p.negate() && !point.y.is_zero())
            .unwrap();
        (p, q)
    }

    #[test]
    fn element_prime_to_picks_short_basis_element() {
        let algebra = QuaternionAlgebra::new(5).unwrap();
        let order = MaximalOrder::reference(algebra);
        let generator = QuaternionElement::from_coeffs(algebra, [3, 0, 0, 0]);
        let basis = [
            QuaternionElement::one(algebra),
            QuaternionElement::basis_i(algebra),
            QuaternionElement::basis_j(algebra),
            QuaternionElement::basis_k(algebra),
        ];
        let ideal = LeftIdeal::with_basis(order, order, generator, 9u64, basis).unwrap();
        let alpha = element_prime_to(&ideal, 3).unwrap();
        assert_ne!(alpha.reduced_norm().rem_u64(3).unwrap(), 0);
    }

    #[test]
    fn kernel_coefficients_e0_matches_julia_normalization() {
        let algebra = QuaternionAlgebra::new(5).unwrap();
        let alpha = QuaternionElement::from_coeffs(algebra, [1, 1, 0, 0]);
        let coeffs = kernel_coefficients_e0_from_element(alpha, 2, 3, &matrices()).unwrap();
        assert_eq!(coeffs, KernelCoefficients { a: 1, b: 7 });
    }

    #[test]
    fn kernel_coefficients_apply_basis_change() {
        let algebra = QuaternionAlgebra::new(5).unwrap();
        let order = MaximalOrder::reference(algebra);
        let ideal =
            LeftIdeal::principal(order, QuaternionElement::from_coeffs(algebra, [1, 1, 0, 0]))
                .unwrap();
        let coeffs = kernel_coefficients(&ideal, [[1, 1], [0, 1]], 3, 3, &matrices()).unwrap();
        assert_eq!(coeffs.b, 1);
        assert_eq!(coeffs.a, 0);
    }

    #[test]
    fn kernel_generator_affine_matches_expected_linear_combination() {
        let curve = curve19();
        let (p, q) = sample_points(&curve);
        let algebra = QuaternionAlgebra::new(5).unwrap();
        let order = MaximalOrder::reference(algebra);
        let ideal =
            LeftIdeal::principal(order, QuaternionElement::from_coeffs(algebra, [1, 1, 0, 0]))
                .unwrap();
        let generator =
            kernel_generator_affine(&curve, &p, &q, &ideal, identity_matrix(), 3, 3, &matrices())
                .unwrap();
        let expected = curve
            .add(&p, &curve.scalar_mul_u64(&q, 26).unwrap())
            .unwrap();
        assert_eq!(generator, expected);
    }

    #[test]
    fn action_matrix_inverse_mod_matches_identity() {
        let matrix = [[1i128, 2], [3, 4]];
        let inv = inv_action_matrix_mod(matrix, 11).unwrap();
        assert_eq!(mul_action_matrices_mod(matrix, inv, 11).unwrap(), [[1, 0], [0, 1]]);
        assert_eq!(mul_action_matrices_mod(inv, matrix, 11).unwrap(), [[1, 0], [0, 1]]);
    }
}
