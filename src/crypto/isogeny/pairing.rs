//! Weil pairing and related target-group representations.

use crate::crypto::isogeny::curve::montgomery::{CurveError, MontgomeryCurve};
use crate::crypto::isogeny::curve::point::CurvePoint;
use crate::crypto::isogeny::field::{Fp, Fp2};

const AUX_SEARCH_BOUND: u64 = 8;

pub type Result<T> = core::result::Result<T, PairingError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingError {
    Curve(CurveError),
    InvalidPower,
    DegenerateEvaluation,
    AuxiliaryPointNotFound,
}

impl From<CurveError> for PairingError {
    fn from(value: CurveError) -> Self {
        Self::Curve(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PairingValue(pub Fp2);

impl PairingValue {
    pub fn one(modulus: &crate::crypto::isogeny::field::FpModulus) -> Self {
        Self(Fp2::one(modulus))
    }

    pub fn is_one(&self) -> bool {
        self.0.is_one()
    }

    pub fn invert(&self) -> Result<Self> {
        Ok(Self(self.0.invert().map_err(CurveError::from)?))
    }

    pub fn mul(&self, rhs: &Self) -> Result<Self> {
        Ok(Self(self.0.mul(&rhs.0).map_err(CurveError::from)?))
    }

    pub fn has_exact_power_of_two_order(&self, power: usize) -> bool {
        if power == 0 {
            return false;
        }
        let mut value = self.0;
        for _ in 1..power {
            value = value.square();
        }
        if value.is_one() {
            return false;
        }
        value.square().is_one()
    }
}

pub fn weil_pairing_power_of_two(
    curve: &MontgomeryCurve,
    p: &CurvePoint,
    q: &CurvePoint,
    power: usize,
) -> Result<PairingValue> {
    if power == 0 {
        return Err(PairingError::InvalidPower);
    }
    curve.validate_point(p)?;
    curve.validate_point(q)?;

    let aux = find_auxiliary_point(curve, p, q, power)?;
    pairing_with_auxiliary(curve, p, q, power, &aux)
}

fn pairing_with_auxiliary(
    curve: &MontgomeryCurve,
    p: &CurvePoint,
    q: &CurvePoint,
    power: usize,
    aux: &CurvePoint,
) -> Result<PairingValue> {
    curve.validate_point(aux)?;

    let q_plus_aux = curve.add(q, aux)?;
    let p_plus_aux = curve.add(p, aux)?;

    let fp_qs = miller_power_of_two(curve, p, power, &q_plus_aux)?;
    let fp_s = miller_power_of_two(curve, p, power, aux)?;
    let fq_s = miller_power_of_two(curve, q, power, aux)?;
    let fq_ps = miller_power_of_two(curve, q, power, &p_plus_aux)?;

    if fp_qs.is_zero() || fp_s.is_zero() || fq_s.is_zero() || fq_ps.is_zero() {
        return Err(PairingError::DegenerateEvaluation);
    }

    let numerator = fp_qs.mul(&fq_s).map_err(CurveError::from)?;
    let denominator = fp_s.mul(&fq_ps).map_err(CurveError::from)?;
    if denominator.is_zero() {
        return Err(PairingError::DegenerateEvaluation);
    }

    Ok(PairingValue(
        numerator
            .mul(&denominator.invert().map_err(CurveError::from)?)
            .map_err(CurveError::from)?,
    ))
}

fn miller_power_of_two(
    curve: &MontgomeryCurve,
    base: &CurvePoint,
    power: usize,
    target: &CurvePoint,
) -> Result<Fp2> {
    if power == 0 {
        return Err(PairingError::InvalidPower);
    }
    curve.validate_point(base)?;
    curve.validate_point(target)?;

    let mut f = Fp2::one(curve.modulus());
    let mut v = *base;
    for _ in 0..power {
        let g = line_ratio(curve, &v, &v, target)?;
        if g.is_zero() {
            return Err(PairingError::DegenerateEvaluation);
        }
        f = f.square().mul(&g).map_err(CurveError::from)?;
        v = curve.double(&v)?;
    }
    Ok(f)
}

fn line_ratio(
    curve: &MontgomeryCurve,
    p: &CurvePoint,
    q: &CurvePoint,
    t: &CurvePoint,
) -> Result<Fp2> {
    curve.validate_point(p)?;
    curve.validate_point(q)?;
    curve.validate_point(t)?;

    if p.is_infinity() || q.is_infinity() {
        return Ok(Fp2::one(curve.modulus()));
    }

    if p.x == q.x && p.y.add(&q.y).map_err(CurveError::from)?.is_zero() {
        let value = t.x.sub(&p.x).map_err(CurveError::from)?;
        if value.is_zero() {
            return Err(PairingError::DegenerateEvaluation);
        }
        return Ok(value);
    }

    let lambda = if p == q {
        if p.y.is_zero() {
            let value = t.x.sub(&p.x).map_err(CurveError::from)?;
            if value.is_zero() {
                return Err(PairingError::DegenerateEvaluation);
            }
            return Ok(value);
        }
        let three = Fp2::from_u64(curve.modulus(), 3);
        let two = Fp2::from_u64(curve.modulus(), 2);
        let one = Fp2::one(curve.modulus());
        let numerator = three
            .mul(&p.x.square())
            .map_err(CurveError::from)?
            .add(
                &two.mul(&curve.a.mul(&p.x).map_err(CurveError::from)?)
                    .map_err(CurveError::from)?,
            )
            .map_err(CurveError::from)?
            .add(&one)
            .map_err(CurveError::from)?;
        let denominator = two.mul(&p.y).map_err(CurveError::from)?;
        if denominator.is_zero() {
            return Err(PairingError::DegenerateEvaluation);
        }
        numerator
            .mul(&denominator.invert().map_err(CurveError::from)?)
            .map_err(CurveError::from)?
    } else {
        let numerator = q.y.sub(&p.y).map_err(CurveError::from)?;
        let denominator = q.x.sub(&p.x).map_err(CurveError::from)?;
        if denominator.is_zero() {
            return Err(PairingError::DegenerateEvaluation);
        }
        numerator
            .mul(&denominator.invert().map_err(CurveError::from)?)
            .map_err(CurveError::from)?
    };

    let sum = curve.add(p, q)?;
    let numerator =
        t.y.sub(&p.y)
            .map_err(CurveError::from)?
            .sub(
                &lambda
                    .mul(&t.x.sub(&p.x).map_err(CurveError::from)?)
                    .map_err(CurveError::from)?,
            )
            .map_err(CurveError::from)?;

    if sum.is_infinity() {
        if numerator.is_zero() {
            return Err(PairingError::DegenerateEvaluation);
        }
        return Ok(numerator);
    }

    let denominator = t.x.sub(&sum.x).map_err(CurveError::from)?;
    if numerator.is_zero() || denominator.is_zero() {
        return Err(PairingError::DegenerateEvaluation);
    }
    Ok(numerator
        .mul(&denominator.invert().map_err(CurveError::from)?)
        .map_err(CurveError::from)?)
}

fn find_auxiliary_point(
    curve: &MontgomeryCurve,
    p: &CurvePoint,
    q: &CurvePoint,
    power: usize,
) -> Result<CurvePoint> {
    for c0 in 0..=AUX_SEARCH_BOUND {
        for c1 in 0..=AUX_SEARCH_BOUND {
            let x = Fp2::new(
                Fp::from_u64(curve.modulus(), c0),
                Fp::from_u64(curve.modulus(), c1),
            )
            .map_err(CurveError::from)?;
            if let Some(y) = curve.rhs(&x)?.sqrt() {
                for point in [CurvePoint::affine(x, y), CurvePoint::affine(x, y.neg())] {
                    if point.is_infinity() {
                        continue;
                    }
                    if pairing_with_auxiliary(curve, p, q, power, &point).is_ok() {
                        return Ok(point);
                    }
                }
            }
        }
    }
    Err(PairingError::AuxiliaryPointNotFound)
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use super::{weil_pairing_power_of_two, PairingValue};
    use crate::crypto::isogeny::curve::montgomery::MontgomeryCurve;
    use crate::crypto::isogeny::curve::point::CurvePoint;
    use crate::crypto::isogeny::field::{Fp, Fp2, FpModulus};

    fn fp2(modulus: &FpModulus, c0: u64, c1: u64) -> Fp2 {
        Fp2::new(Fp::from_u64(modulus, c0), Fp::from_u64(modulus, c1)).unwrap()
    }

    fn enumerate_curve_points(curve: &MontgomeryCurve, prime: u64) -> Vec<CurvePoint> {
        let modulus = *curve.modulus();
        let mut points = vec![curve.identity()];
        for x0 in 0..prime {
            for x1 in 0..prime {
                let x = fp2(&modulus, x0, x1);
                if let Some(y) = curve.rhs(&x).unwrap().sqrt() {
                    let p = CurvePoint::affine(x, y);
                    if curve.is_on_curve(&p).unwrap() {
                        points.push(p);
                    }
                    let neg = p.negate();
                    if neg != p {
                        points.push(neg);
                    }
                }
            }
        }
        points
    }

    fn find_curve_and_basis(power: usize) -> (MontgomeryCurve, CurvePoint, CurvePoint) {
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
                .filter(|point| {
                    if point.is_infinity() {
                        return false;
                    }
                    let mut acc = *point;
                    for _ in 0..power {
                        acc = curve.double(&acc).unwrap();
                    }
                    if !acc.is_infinity() {
                        return false;
                    }
                    let mut acc = *point;
                    for _ in 0..power.saturating_sub(1) {
                        acc = curve.double(&acc).unwrap();
                    }
                    !acc.is_infinity()
                })
                .collect();
            for &p in &candidates {
                for &q in &candidates {
                    if let Ok(pairing) = weil_pairing_power_of_two(&curve, &p, &q, power) {
                        if pairing.has_exact_power_of_two_order(power) {
                            return (curve, p, q);
                        }
                    }
                }
            }
        }
        panic!("failed to find test basis for pairing");
    }

    #[test]
    fn pairing_of_basis_has_exact_power_of_two_order() {
        let (curve, p, q) = find_curve_and_basis(2);
        let pairing = weil_pairing_power_of_two(&curve, &p, &q, 2).unwrap();
        assert!(pairing.has_exact_power_of_two_order(2));
        assert!(!pairing.is_one());
    }

    #[test]
    fn pairing_is_alternating_and_antisymmetric() {
        let (curve, p, q) = find_curve_and_basis(2);
        let e_pp = weil_pairing_power_of_two(&curve, &p, &p, 2).unwrap();
        assert!(e_pp.is_one());

        let e_pq = weil_pairing_power_of_two(&curve, &p, &q, 2).unwrap();
        let e_qp = weil_pairing_power_of_two(&curve, &q, &p, 2).unwrap();
        assert_eq!(e_pq.mul(&e_qp).unwrap(), PairingValue::one(curve.modulus()));
    }
}
