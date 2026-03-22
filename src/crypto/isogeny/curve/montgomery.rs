//! Montgomery-model curve arithmetic over `Fp2`.
//!
//! We work with the affine model
//! `y^2 = x^3 + A x^2 + x`
//! which is the `B = 1` specialization commonly used as a normalization step in
//! the PRISM/SQIsign literature. The formulas below are correctness-first and
//! intended to stabilize the algebraic interface before we optimize with x-only
//! ladders or projective formulas.

use crate::crypto::isogeny::curve::point::CurvePoint;
use crate::crypto::isogeny::field::{Fp2, FpError, FpModulus};

pub type Result<T> = core::result::Result<T, CurveError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CurveError {
    Field(FpError),
    ModulusMismatch,
    PointNotOnCurve,
    SingularCurve,
}

impl From<FpError> for CurveError {
    fn from(value: FpError) -> Self {
        Self::Field(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MontgomeryCurve {
    pub a: Fp2,
}

impl MontgomeryCurve {
    pub fn new(a: Fp2) -> Result<Self> {
        let four = Fp2::from_u64(a.modulus(), 4);
        if a.square().sub(&four)?.is_zero() {
            return Err(CurveError::SingularCurve);
        }
        Ok(Self { a })
    }

    pub fn modulus(&self) -> &FpModulus {
        self.a.modulus()
    }

    pub fn identity(&self) -> CurvePoint {
        CurvePoint::infinity(self.modulus())
    }

    pub fn is_on_curve(&self, point: &CurvePoint) -> Result<bool> {
        self.ensure_point_modulus(point)?;
        if point.is_infinity() {
            return Ok(true);
        }
        Ok(point.y.square() == self.rhs(&point.x)?)
    }

    pub fn validate_point(&self, point: &CurvePoint) -> Result<()> {
        if self.is_on_curve(point)? {
            Ok(())
        } else {
            Err(CurveError::PointNotOnCurve)
        }
    }

    pub fn negate(&self, point: &CurvePoint) -> Result<CurvePoint> {
        self.ensure_point_modulus(point)?;
        if point.is_infinity() {
            Ok(*point)
        } else {
            Ok(point.negate())
        }
    }

    pub fn add(&self, lhs: &CurvePoint, rhs: &CurvePoint) -> Result<CurvePoint> {
        self.validate_point(lhs)?;
        self.validate_point(rhs)?;

        if lhs.is_infinity() {
            return Ok(*rhs);
        }
        if rhs.is_infinity() {
            return Ok(*lhs);
        }
        if lhs.x == rhs.x {
            if lhs.y.add(&rhs.y)?.is_zero() {
                return Ok(self.identity());
            }
            return self.double(lhs);
        }

        let dy = rhs.y.sub(&lhs.y)?;
        let dx = rhs.x.sub(&lhs.x)?;
        let lambda = dy.mul(&dx.invert()?)?;
        let x3 = lambda.square().sub(&self.a)?.sub(&lhs.x)?.sub(&rhs.x)?;
        let y3 = lambda.mul(&lhs.x.sub(&x3)?)?.sub(&lhs.y)?;
        Ok(CurvePoint::affine(x3, y3))
    }

    pub fn double(&self, point: &CurvePoint) -> Result<CurvePoint> {
        self.validate_point(point)?;

        if point.is_infinity() || point.y.is_zero() {
            return Ok(self.identity());
        }

        let one = Fp2::one(self.modulus());
        let two = Fp2::from_u64(self.modulus(), 2);
        let three = Fp2::from_u64(self.modulus(), 3);

        let x2 = point.x.square();
        let numerator = three
            .mul(&x2)?
            .add(&two.mul(&self.a.mul(&point.x)?)?)?
            .add(&one)?;
        let denominator = two.mul(&point.y)?;
        let lambda = numerator.mul(&denominator.invert()?)?;
        let x3 = lambda.square().sub(&self.a)?.sub(&point.x.double())?;
        let y3 = lambda.mul(&point.x.sub(&x3)?)?.sub(&point.y)?;
        Ok(CurvePoint::affine(x3, y3))
    }

    pub fn scalar_mul(&self, point: &CurvePoint, scalar: &[u64]) -> Result<CurvePoint> {
        self.validate_point(point)?;

        let mut acc = self.identity();
        let total_bits = bit_length(scalar);
        for bit_index in (0..total_bits).rev() {
            acc = self.double(&acc)?;
            if get_bit(scalar, bit_index) {
                acc = self.add(&acc, point)?;
            }
        }
        Ok(acc)
    }

    pub fn scalar_mul_u64(&self, point: &CurvePoint, scalar: u64) -> Result<CurvePoint> {
        self.scalar_mul(point, &[scalar])
    }

    pub fn rhs(&self, x: &Fp2) -> Result<Fp2> {
        self.ensure_fp2_modulus(x)?;
        let x2 = x.square();
        let x3 = x2.mul(x)?;
        Ok(x3.add(&self.a.mul(&x2)?)?.add(x)?)
    }

    fn ensure_point_modulus(&self, point: &CurvePoint) -> Result<()> {
        self.ensure_fp2_modulus(&point.x)?;
        self.ensure_fp2_modulus(&point.y)?;
        Ok(())
    }

    fn ensure_fp2_modulus(&self, value: &Fp2) -> Result<()> {
        if value.modulus() == self.modulus() {
            Ok(())
        } else {
            Err(CurveError::ModulusMismatch)
        }
    }
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

    use super::{CurveError, MontgomeryCurve};
    use crate::crypto::isogeny::curve::point::CurvePoint;
    use crate::crypto::isogeny::field::{Fp, Fp2, FpModulus};

    fn modulus19() -> FpModulus {
        FpModulus::from_u64(19).unwrap()
    }

    fn base(value: u64) -> Fp2 {
        let modulus = modulus19();
        Fp2::from_u64(&modulus, value)
    }

    fn curve19() -> MontgomeryCurve {
        MontgomeryCurve::new(base(5)).unwrap()
    }

    fn affine(x: u64, y: u64) -> CurvePoint {
        CurvePoint::affine(base(x), base(y))
    }

    fn enumerate_base_points(curve: &MontgomeryCurve) -> Vec<CurvePoint> {
        let mut points = Vec::new();
        for x in 0..19u64 {
            for y in 0..19u64 {
                let point = affine(x, y);
                if curve.is_on_curve(&point).unwrap() {
                    points.push(point);
                }
            }
        }
        points
    }

    fn sample_points(curve: &MontgomeryCurve) -> (CurvePoint, CurvePoint, CurvePoint) {
        let points = enumerate_base_points(curve);
        let p = *points
            .iter()
            .find(|candidate| !candidate.y.is_zero())
            .unwrap();
        let q = *points
            .iter()
            .find(|candidate| candidate.x != p.x && **candidate != p.negate())
            .unwrap();
        let r = *points
            .iter()
            .find(|candidate| candidate.x != p.x && candidate.x != q.x && **candidate != q.negate())
            .unwrap();
        (p, q, r)
    }

    #[test]
    fn rejects_singular_parameters() {
        let singular = MontgomeryCurve::new(base(2));
        assert_eq!(singular, Err(CurveError::SingularCurve));

        let minus_two = MontgomeryCurve::new(base(17));
        assert_eq!(minus_two, Err(CurveError::SingularCurve));
    }

    #[test]
    fn identity_and_membership_work() {
        let curve = curve19();
        let identity = curve.identity();
        assert!(curve.is_on_curve(&identity).unwrap());

        let (point, _, _) = sample_points(&curve);
        assert!(curve.is_on_curve(&point).unwrap());

        let invalid = affine(1, 1);
        assert!(!curve.is_on_curve(&invalid).unwrap());
        assert_eq!(
            curve.validate_point(&invalid),
            Err(CurveError::PointNotOnCurve)
        );
    }

    #[test]
    fn negation_addition_and_doubling_behave_as_expected() {
        let curve = curve19();
        let (point, _, _) = sample_points(&curve);
        let neg = curve.negate(&point).unwrap();
        assert_eq!(curve.add(&point, &neg).unwrap(), curve.identity());

        let doubled = curve.double(&point).unwrap();
        assert_eq!(doubled, curve.add(&point, &point).unwrap());
        assert!(curve.is_on_curve(&doubled).unwrap());
    }

    #[test]
    fn addition_is_commutative_for_sample_points() {
        let curve = curve19();
        let (p, q, _) = sample_points(&curve);
        assert_eq!(curve.add(&p, &q).unwrap(), curve.add(&q, &p).unwrap());
    }

    #[test]
    fn scalar_mul_matches_repeated_addition() {
        let curve = curve19();
        let (point, _, _) = sample_points(&curve);
        let mut accum = curve.identity();
        for scalar in 0..8u64 {
            assert_eq!(curve.scalar_mul_u64(&point, scalar).unwrap(), accum);
            accum = curve.add(&accum, &point).unwrap();
        }
    }

    #[test]
    fn associativity_holds_for_sample_points() {
        let curve = curve19();
        let (p, q, r) = sample_points(&curve);
        let left = curve.add(&curve.add(&p, &q).unwrap(), &r).unwrap();
        let right = curve.add(&p, &curve.add(&q, &r).unwrap()).unwrap();
        assert_eq!(left, right);
    }

    #[test]
    fn scalar_mul_respects_group_order_for_base_field_point() {
        let curve = curve19();
        let (point, _, _) = sample_points(&curve);
        let mut order = 1u64;
        let mut accum = point;
        while !accum.is_infinity() {
            accum = curve.add(&accum, &point).unwrap();
            order += 1;
            assert!(order < 128);
        }
        assert_eq!(
            curve.scalar_mul_u64(&point, order).unwrap(),
            curve.identity()
        );
    }

    #[test]
    fn mismatched_modulus_is_rejected() {
        let curve = curve19();
        let other_modulus = FpModulus::from_u64(17).unwrap();
        let point = CurvePoint::affine(
            Fp2::new(Fp::from_u64(&other_modulus, 1), Fp::zero(&other_modulus)).unwrap(),
            Fp2::new(Fp::from_u64(&other_modulus, 1), Fp::zero(&other_modulus)).unwrap(),
        );
        assert_eq!(curve.is_on_curve(&point), Err(CurveError::ModulusMismatch));
    }
}
