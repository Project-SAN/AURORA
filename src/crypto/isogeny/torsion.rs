//! Deterministic torsion-basis generation and helpers.
//!
//! At this stage we provide the algebraic handling of a `2^a`-torsion basis:
//! exact-order checks, reduction to `E[2]`, basis validation, and linear
//! combinations / basis transforms. Deterministic basis generation from hints is
//! still a later step once the corresponding isogeny-side machinery exists.

use alloc::vec::Vec;

use crate::crypto::isogeny::curve::montgomery::{CurveError, MontgomeryCurve};
use crate::crypto::isogeny::curve::point::CurvePoint;
use crate::crypto::isogeny::field::{Fp, Fp2};
use crate::crypto::isogeny::pairing::{weil_pairing_power_of_two, PairingError};

pub type Result<T> = core::result::Result<T, TorsionError>;

const REFERENCE_ENUMERATION_BOUND: u64 = 31;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TorsionError {
    Curve(CurveError),
    Pairing(PairingError),
    InvalidPower,
    PointOrderMismatch,
    DependentBasis,
    ReferenceEnumerationUnsupported,
    HintOutOfRange,
}

impl From<CurveError> for TorsionError {
    fn from(value: CurveError) -> Self {
        Self::Curve(value)
    }
}

impl From<PairingError> for TorsionError {
    fn from(value: PairingError) -> Self {
        Self::Pairing(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TorsionBasis {
    pub p: CurvePoint,
    pub q: CurvePoint,
    pub power: usize,
    pub hint: u16,
}

impl TorsionBasis {
    pub fn new(p: CurvePoint, q: CurvePoint, power: usize, hint: u16) -> Self {
        Self { p, q, power, hint }
    }

    pub fn with_hint(mut self, hint: u16) -> Self {
        self.hint = hint;
        self
    }

    pub fn validate(&self, curve: &MontgomeryCurve) -> Result<()> {
        if self.power == 0 {
            return Err(TorsionError::InvalidPower);
        }
        if !has_exact_power_of_two_order(curve, &self.p, self.power)? {
            return Err(TorsionError::PointOrderMismatch);
        }
        if !has_exact_power_of_two_order(curve, &self.q, self.power)? {
            return Err(TorsionError::PointOrderMismatch);
        }

        let (p2, q2) = self.reduce_to_two_torsion(curve)?;
        if p2.is_infinity() || q2.is_infinity() || p2 == q2 {
            return Err(TorsionError::DependentBasis);
        }

        let pairing = weil_pairing_power_of_two(curve, &self.p, &self.q, self.power)?;
        if !pairing.has_exact_power_of_two_order(self.power) {
            return Err(TorsionError::DependentBasis);
        }
        Ok(())
    }

    pub fn reduce_to_two_torsion(
        &self,
        curve: &MontgomeryCurve,
    ) -> Result<(CurvePoint, CurvePoint)> {
        Ok((
            mul_by_pow2(curve, &self.p, self.power - 1)?,
            mul_by_pow2(curve, &self.q, self.power - 1)?,
        ))
    }

    pub fn linear_combination(
        &self,
        curve: &MontgomeryCurve,
        p_coeff: &[u64],
        q_coeff: &[u64],
    ) -> Result<CurvePoint> {
        self.validate(curve)?;
        let p_term = curve.scalar_mul(&self.p, p_coeff)?;
        let q_term = curve.scalar_mul(&self.q, q_coeff)?;
        Ok(curve.add(&p_term, &q_term)?)
    }

    pub fn transform(
        &self,
        curve: &MontgomeryCurve,
        m11: &[u64],
        m12: &[u64],
        m21: &[u64],
        m22: &[u64],
    ) -> Result<Self> {
        let p = self.linear_combination(curve, m11, m12)?;
        let q = self.linear_combination(curve, m21, m22)?;
        let basis = Self::new(p, q, self.power, self.hint);
        basis.validate(curve)?;
        Ok(basis)
    }

    pub fn reference_hint(&self, curve: &MontgomeryCurve) -> Result<u16> {
        self.validate(curve)?;
        let bases = reference_enumerate_bases(curve, self.power)?;
        bases
            .iter()
            .position(|basis| basis.p == self.p && basis.q == self.q)
            .map(|index| index as u16)
            .ok_or(TorsionError::HintOutOfRange)
    }

    pub fn from_reference_hint(curve: &MontgomeryCurve, power: usize, hint: u16) -> Result<Self> {
        let bases = reference_enumerate_bases(curve, power)?;
        bases
            .get(hint as usize)
            .copied()
            .map(|basis| basis.with_hint(hint))
            .ok_or(TorsionError::HintOutOfRange)
    }
}

pub fn is_in_power_of_two_torsion(
    curve: &MontgomeryCurve,
    point: &CurvePoint,
    power: usize,
) -> Result<bool> {
    if power == 0 {
        return Err(TorsionError::InvalidPower);
    }
    Ok(mul_by_pow2(curve, point, power)?.is_infinity())
}

pub fn has_exact_power_of_two_order(
    curve: &MontgomeryCurve,
    point: &CurvePoint,
    power: usize,
) -> Result<bool> {
    if power == 0 {
        return Err(TorsionError::InvalidPower);
    }
    if point.is_infinity() {
        return Ok(false);
    }

    let top = mul_by_pow2(curve, point, power - 1)?;
    if top.is_infinity() {
        return Ok(false);
    }
    Ok(curve.double(&top)?.is_infinity())
}

pub fn mul_by_pow2(
    curve: &MontgomeryCurve,
    point: &CurvePoint,
    power: usize,
) -> Result<CurvePoint> {
    curve.validate_point(point)?;
    let mut acc = *point;
    for _ in 0..power {
        acc = curve.double(&acc)?;
    }
    Ok(acc)
}

fn reference_enumerate_points(curve: &MontgomeryCurve) -> Result<Vec<CurvePoint>> {
    let prime = curve
        .modulus()
        .to_u64()
        .filter(|prime| *prime <= REFERENCE_ENUMERATION_BOUND)
        .ok_or(TorsionError::ReferenceEnumerationUnsupported)?;
    let modulus = *curve.modulus();
    let mut points = Vec::new();
    for x0 in 0..prime {
        for x1 in 0..prime {
            let x = Fp2::new(Fp::from_u64(&modulus, x0), Fp::from_u64(&modulus, x1))
                .map_err(CurveError::from)?;
            if let Some(y) = curve.rhs(&x)?.sqrt() {
                let point = CurvePoint::affine(x, y);
                if curve.is_on_curve(&point)? {
                    points.push(point);
                    let neg = point.negate();
                    if neg != point {
                        points.push(neg);
                    }
                }
            }
        }
    }
    Ok(points)
}

fn reference_enumerate_bases(curve: &MontgomeryCurve, power: usize) -> Result<Vec<TorsionBasis>> {
    if power == 0 {
        return Err(TorsionError::InvalidPower);
    }

    let points = reference_enumerate_points(curve)?;
    let candidates: Vec<_> = points
        .into_iter()
        .filter(|point| has_exact_power_of_two_order(curve, point, power).unwrap_or(false))
        .collect();

    let mut bases = Vec::new();
    for &p in &candidates {
        for &q in &candidates {
            let basis = TorsionBasis::new(p, q, power, 0);
            if basis.validate(curve).is_ok() {
                bases.push(basis);
                if bases.len() > u16::MAX as usize {
                    return Err(TorsionError::ReferenceEnumerationUnsupported);
                }
            }
        }
    }
    Ok(bases)
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use super::{
        has_exact_power_of_two_order, is_in_power_of_two_torsion, mul_by_pow2, TorsionBasis,
        TorsionError,
    };
    use crate::crypto::isogeny::curve::montgomery::MontgomeryCurve;
    use crate::crypto::isogeny::curve::point::CurvePoint;
    use crate::crypto::isogeny::field::{Fp2, FpModulus};

    fn fp2(modulus: &FpModulus, c0: u64, c1: u64) -> Fp2 {
        Fp2::new(
            crate::crypto::isogeny::field::Fp::from_u64(modulus, c0),
            crate::crypto::isogeny::field::Fp::from_u64(modulus, c1),
        )
        .unwrap()
    }

    fn enumerate_curve_points(curve: &MontgomeryCurve, prime: u64) -> Vec<CurvePoint> {
        let modulus = *curve.modulus();
        let mut points = vec![curve.identity()];
        for x0 in 0..prime {
            for x1 in 0..prime {
                let x = fp2(&modulus, x0, x1);
                for y0 in 0..prime {
                    for y1 in 0..prime {
                        let y = fp2(&modulus, y0, y1);
                        let point = CurvePoint::affine(x, y);
                        if curve.is_on_curve(&point).unwrap() {
                            points.push(point);
                        }
                    }
                }
            }
        }
        points
    }

    fn find_curve_and_basis(power: usize) -> (MontgomeryCurve, TorsionBasis) {
        let modulus = FpModulus::from_u64(19).unwrap();
        for a in 0..19u64 {
            let curve = match MontgomeryCurve::new(Fp2::from_u64(&modulus, a)) {
                Ok(curve) => curve,
                Err(_) => continue,
            };
            let points = enumerate_curve_points(&curve, 19);
            let candidates: Vec<_> = points
                .iter()
                .copied()
                .filter(|point| has_exact_power_of_two_order(&curve, point, power).unwrap())
                .collect();
            for &p in &candidates {
                for &q in &candidates {
                    let basis = TorsionBasis::new(p, q, power, 0);
                    if basis.validate(&curve).is_ok() {
                        return (curve, basis);
                    }
                }
            }
        }
        panic!("failed to find a small test curve with a 2^a-torsion basis");
    }

    #[test]
    fn detects_exact_power_of_two_order() {
        let (curve, basis) = find_curve_and_basis(2);
        assert!(has_exact_power_of_two_order(&curve, &basis.p, 2).unwrap());
        assert!(has_exact_power_of_two_order(&curve, &basis.q, 2).unwrap());
        assert!(!has_exact_power_of_two_order(&curve, &curve.identity(), 2).unwrap());
    }

    #[test]
    fn reduction_to_two_torsion_and_membership_work() {
        let (curve, basis) = find_curve_and_basis(2);
        let (p2, q2) = basis.reduce_to_two_torsion(&curve).unwrap();
        assert!(!p2.is_infinity());
        assert!(!q2.is_infinity());
        assert_ne!(p2, q2);
        assert!(curve.double(&p2).unwrap().is_infinity());
        assert!(curve.double(&q2).unwrap().is_infinity());
        assert!(is_in_power_of_two_torsion(&curve, &basis.p, 2).unwrap());
        assert_eq!(mul_by_pow2(&curve, &basis.p, 2).unwrap(), curve.identity());
    }

    #[test]
    fn validation_rejects_dependent_basis() {
        let (curve, basis) = find_curve_and_basis(2);
        let bad = TorsionBasis::new(basis.p, basis.p, basis.power, basis.hint);
        assert_eq!(bad.validate(&curve), Err(TorsionError::DependentBasis));
    }

    #[test]
    fn linear_combination_matches_manual_group_law() {
        let (curve, basis) = find_curve_and_basis(2);
        let point = basis.linear_combination(&curve, &[1], &[1]).unwrap();
        let manual = curve.add(&basis.p, &basis.q).unwrap();
        assert_eq!(point, manual);

        let point = basis.linear_combination(&curve, &[3], &[2]).unwrap();
        let p_term = curve.scalar_mul_u64(&basis.p, 3).unwrap();
        let q_term = curve.scalar_mul_u64(&basis.q, 2).unwrap();
        assert_eq!(point, curve.add(&p_term, &q_term).unwrap());
    }

    #[test]
    fn transform_produces_another_valid_basis() {
        let (curve, basis) = find_curve_and_basis(2);
        let transformed = basis.transform(&curve, &[0], &[1], &[1], &[0]).unwrap();
        transformed.validate(&curve).unwrap();

        assert_eq!(transformed.p, basis.q);
        assert_eq!(transformed.q, basis.p);
    }

    #[test]
    fn reference_hint_roundtrip_recovers_basis() {
        let (curve, basis) = find_curve_and_basis(2);
        let hint = basis.reference_hint(&curve).unwrap();
        let reconstructed = TorsionBasis::from_reference_hint(&curve, basis.power, hint).unwrap();
        assert_eq!(reconstructed.p, basis.p);
        assert_eq!(reconstructed.q, basis.q);
        assert_eq!(reconstructed.power, basis.power);
        assert_eq!(reconstructed.hint, hint);
    }

    #[test]
    fn reference_hint_rejects_large_modulus() {
        use crate::crypto::isogeny::params::NIST_LEVEL1_BASE;

        let curve = MontgomeryCurve::new(Fp2::one(&NIST_LEVEL1_BASE.modulus)).unwrap();
        assert_eq!(
            TorsionBasis::from_reference_hint(&curve, 2, 0),
            Err(TorsionError::ReferenceEnumerationUnsupported)
        );
    }
}
