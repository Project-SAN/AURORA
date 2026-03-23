//! X-only Montgomery arithmetic aligned with the Julia `Proj1` layer.
//!
//! This is the correctness-first foundation needed for the PRISM/SQIsign
//! ideal-to-isogeny path. We keep the formulas explicit and validate them
//! against the affine Montgomery implementation on small reference curves.

use crate::crypto::isogeny::curve::montgomery::{CurveError, MontgomeryCurve};
use crate::crypto::isogeny::curve::point::CurvePoint;
use crate::crypto::isogeny::field::{Fp2, FpError, FpModulus};

pub type Result<T> = core::result::Result<T, XOnlyError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XOnlyError {
    Curve(CurveError),
    Field(FpError),
    PointAtInfinity,
}

impl From<CurveError> for XOnlyError {
    fn from(value: CurveError) -> Self {
        Self::Curve(value)
    }
}

impl From<FpError> for XOnlyError {
    fn from(value: FpError) -> Self {
        Self::Field(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proj1 {
    pub x: Fp2,
    pub z: Fp2,
}

impl Proj1 {
    pub fn identity(modulus: &FpModulus) -> Self {
        Self {
            x: Fp2::one(modulus),
            z: Fp2::zero(modulus),
        }
    }

    pub fn affine_x(x: Fp2) -> Self {
        let modulus = *x.modulus();
        Self {
            x,
            z: Fp2::one(&modulus),
        }
    }

    pub fn from_point(point: &CurvePoint) -> Result<Self> {
        if point.is_infinity() {
            return Err(XOnlyError::PointAtInfinity);
        }
        Ok(Self::affine_x(point.x))
    }

    pub fn is_identity(&self) -> bool {
        self.z.is_zero()
    }

    pub fn to_affine_x(&self) -> Result<Fp2> {
        if self.is_identity() {
            return Err(XOnlyError::PointAtInfinity);
        }
        Ok(self.x.mul(&self.z.invert()?)?)
    }
}

pub fn x_dbl(curve: &MontgomeryCurve, point: &Proj1) -> Result<Proj1> {
    let a24 = curve.a24()?;
    let t0 = point.x.add(&point.z)?;
    let t1 = point.x.sub(&point.z)?;
    let t0_sq = t0.square();
    let t1_sq = t1.square();
    let t2 = t0_sq.sub(&t1_sq)?;
    let x = t0_sq.mul(&t1_sq)?;
    let z = t2.mul(&t1_sq.add(&a24.mul(&t2)?)?)?;
    Ok(Proj1 { x, z })
}

pub fn x_dble(curve: &MontgomeryCurve, point: &Proj1, power: usize) -> Result<Proj1> {
    let mut acc = *point;
    for _ in 0..power {
        acc = x_dbl(curve, &acc)?;
    }
    Ok(acc)
}

pub fn x_add(lhs: &Proj1, rhs: &Proj1, diff: &Proj1) -> Result<Proj1> {
    let t0 = lhs.x.add(&lhs.z)?;
    let t1 = lhs.x.sub(&lhs.z)?;
    let t2 = rhs.x.add(&rhs.z)?;
    let t3 = rhs.x.sub(&rhs.z)?;
    let t4 = t0.mul(&t3)?;
    let t5 = t1.mul(&t2)?;
    let sum = t4.add(&t5)?;
    let delta = t4.sub(&t5)?;
    let x = diff.z.mul(&sum.square())?;
    let z = diff.x.mul(&delta.square())?;
    Ok(Proj1 { x, z })
}

pub fn ladder(curve: &MontgomeryCurve, point: &Proj1, scalar: &[u64]) -> Result<Proj1> {
    let modulus = curve.modulus();
    let x1 = point.x;
    let mut x2 = Fp2::one(modulus);
    let mut z2 = Fp2::zero(modulus);
    let mut x3 = point.x;
    let mut z3 = point.z;
    let a24 = curve.a24()?;
    let mut swap = false;

    let total_bits = bit_length(scalar);
    for bit_index in (0..total_bits).rev() {
        let bit = get_bit(scalar, bit_index);
        if bit != swap {
            core::mem::swap(&mut x2, &mut x3);
            core::mem::swap(&mut z2, &mut z3);
            swap = bit;
        }

        let a = x2.add(&z2)?;
        let aa = a.square();
        let b = x2.sub(&z2)?;
        let bb = b.square();
        let e = aa.sub(&bb)?;

        let c = x3.add(&z3)?;
        let d = x3.sub(&z3)?;
        let da = d.mul(&a)?;
        let cb = c.mul(&b)?;
        let x3_next = da.add(&cb)?.square();
        let z3_next = x1.mul(&da.sub(&cb)?.square())?;
        let x2_next = aa.mul(&bb)?;
        let z2_next = e.mul(&aa.add(&a24.mul(&e)?)?)?;

        x2 = x2_next;
        z2 = z2_next;
        x3 = x3_next;
        z3 = z3_next;
    }

    if swap {
        core::mem::swap(&mut x2, &mut x3);
        core::mem::swap(&mut z2, &mut z3);
    }

    Ok(Proj1 { x: x2, z: z2 })
}

/// Reference three-point ladder with the Julia-facing signature.
///
/// The full x-only ladder3pt formulas are the next optimization step. For now
/// we keep the public interface and compute the same result from the affine
/// group law, then expose it as a projective x-coordinate.
pub fn ladder3pt_affine(
    curve: &MontgomeryCurve,
    scalar: &[u64],
    p: &CurvePoint,
    q: &CurvePoint,
) -> Result<Proj1> {
    curve.validate_point(p)?;
    curve.validate_point(q)?;
    let q_term = curve.scalar_mul(q, scalar)?;
    let sum = curve.add(p, &q_term)?;
    if sum.is_infinity() {
        return Ok(Proj1::identity(curve.modulus()));
    }
    Ok(Proj1::affine_x(sum.x))
}

pub fn x_of_difference(
    curve: &MontgomeryCurve,
    lhs: &CurvePoint,
    rhs: &CurvePoint,
) -> Result<Proj1> {
    curve.validate_point(lhs)?;
    curve.validate_point(rhs)?;
    let diff = curve.add(lhs, &curve.negate(rhs)?)?;
    if diff.is_infinity() {
        return Ok(Proj1::identity(curve.modulus()));
    }
    Ok(Proj1::affine_x(diff.x))
}

fn bit_length(limbs: &[u64]) -> usize {
    let mut len = limbs.len();
    while len > 1 && limbs[len - 1] == 0 {
        len -= 1;
    }
    if len == 0 || (len == 1 && limbs[0] == 0) {
        return 0;
    }
    64 * (len - 1) + (64 - limbs[len - 1].leading_zeros() as usize)
}

fn get_bit(limbs: &[u64], bit_index: usize) -> bool {
    let limb_index = bit_index / 64;
    let bit = bit_index % 64;
    limbs
        .get(limb_index)
        .map(|limb| ((limb >> bit) & 1) == 1)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::{ladder, ladder3pt_affine, x_add, x_dbl, x_of_difference, Proj1};
    use crate::crypto::isogeny::curve::montgomery::MontgomeryCurve;
    use crate::crypto::isogeny::curve::point::CurvePoint;
    use crate::crypto::isogeny::field::{Fp2, FpModulus};

    fn modulus19() -> FpModulus {
        FpModulus::from_u64(19).unwrap()
    }

    fn fp2(value: u64) -> Fp2 {
        Fp2::from_u64(&modulus19(), value)
    }

    fn affine(x: u64, y: u64) -> CurvePoint {
        CurvePoint::affine(fp2(x), fp2(y))
    }

    fn curve19() -> MontgomeryCurve {
        MontgomeryCurve::new(fp2(5)).unwrap()
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
        let candidates = enumerate_points(curve);
        let p = candidates
            .iter()
            .copied()
            .find(|point| curve.validate_point(point).is_ok() && !point.y.is_zero())
            .unwrap();
        let q = candidates
            .iter()
            .copied()
            .find(|point| {
                curve.validate_point(point).is_ok()
                    && !point.y.is_zero()
                    && point.x != p.x
                    && *point != p.negate()
            })
            .unwrap();
        (p, q)
    }

    #[test]
    fn x_dbl_matches_affine_double_x_coordinate() {
        let curve = curve19();
        let (p, _) = sample_points(&curve);
        let x_p = Proj1::from_point(&p).unwrap();
        let doubled = x_dbl(&curve, &x_p).unwrap().to_affine_x().unwrap();
        let affine_double = curve.double(&p).unwrap();
        assert_eq!(doubled, affine_double.x);
    }

    #[test]
    fn x_add_matches_affine_sum_x_coordinate() {
        let curve = curve19();
        let (p, q) = sample_points(&curve);
        let p_x = Proj1::from_point(&p).unwrap();
        let q_x = Proj1::from_point(&q).unwrap();
        let diff_x = x_of_difference(&curve, &p, &q).unwrap();
        let sum_x = x_add(&p_x, &q_x, &diff_x).unwrap().to_affine_x().unwrap();
        let sum = curve.add(&p, &q).unwrap();
        assert_eq!(sum_x, sum.x);
    }

    #[test]
    fn ladder_matches_affine_scalar_multiplication() {
        let curve = curve19();
        let (p, _) = sample_points(&curve);
        let x_p = Proj1::from_point(&p).unwrap();
        let x_mul = ladder(&curve, &x_p, &[3]).unwrap().to_affine_x().unwrap();
        let affine_mul = curve.scalar_mul_u64(&p, 3).unwrap();
        assert_eq!(x_mul, affine_mul.x);
    }

    #[test]
    fn ladder3pt_affine_matches_affine_linear_combination() {
        let curve = curve19();
        let (p, q) = sample_points(&curve);
        let x = ladder3pt_affine(&curve, &[5], &p, &q)
            .unwrap()
            .to_affine_x()
            .unwrap();
        let target = curve
            .add(&p, &curve.scalar_mul_u64(&q, 5).unwrap())
            .unwrap();
        assert_eq!(x, target.x);
    }
}
