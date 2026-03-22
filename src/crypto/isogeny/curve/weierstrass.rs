//! Short-Weierstrass curve arithmetic and Montgomery conversion helpers.

use crate::crypto::isogeny::curve::montgomery::MontgomeryCurve;
use crate::crypto::isogeny::curve::point::CurvePoint;
use crate::crypto::isogeny::field::{Fp2, FpError, FpModulus};

pub type Result<T> = core::result::Result<T, WeierstrassError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WeierstrassError {
    Field(FpError),
    ModulusMismatch,
    PointNotOnCurve,
    SingularCurve,
}

impl From<FpError> for WeierstrassError {
    fn from(value: FpError) -> Self {
        Self::Field(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShortWeierstrassCurve {
    pub a: Fp2,
    pub b: Fp2,
}

impl ShortWeierstrassCurve {
    pub fn new(a: Fp2, b: Fp2) -> Result<Self> {
        if a.modulus() != b.modulus() {
            return Err(WeierstrassError::ModulusMismatch);
        }
        let four = Fp2::from_u64(a.modulus(), 4);
        let twenty_seven = Fp2::from_u64(a.modulus(), 27);
        let discriminant = four
            .mul(&a.square())?
            .add(&twenty_seven.mul(&b.square())?)?;
        if discriminant.is_zero() {
            return Err(WeierstrassError::SingularCurve);
        }
        Ok(Self { a, b })
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
            Err(WeierstrassError::PointNotOnCurve)
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

        let lambda = rhs.y.sub(&lhs.y)?.mul(&rhs.x.sub(&lhs.x)?.invert()?)?;
        let x3 = lambda.square().sub(&lhs.x)?.sub(&rhs.x)?;
        let y3 = lambda.mul(&lhs.x.sub(&x3)?)?.sub(&lhs.y)?;
        Ok(CurvePoint::affine(x3, y3))
    }

    pub fn double(&self, point: &CurvePoint) -> Result<CurvePoint> {
        self.validate_point(point)?;
        if point.is_infinity() || point.y.is_zero() {
            return Ok(self.identity());
        }

        let three = Fp2::from_u64(self.modulus(), 3);
        let two = Fp2::from_u64(self.modulus(), 2);
        let lambda = three
            .mul(&point.x.square())?
            .add(&self.a)?
            .mul(&two.mul(&point.y)?.invert()?)?;
        let x3 = lambda.square().sub(&point.x.double())?;
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
        Ok(x3.add(&self.a.mul(x)?)?.add(&self.b)?)
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
            Err(WeierstrassError::ModulusMismatch)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MontgomeryIsomorphism {
    montgomery: MontgomeryCurve,
    weierstrass: ShortWeierstrassCurve,
    x_shift: Fp2,
}

impl MontgomeryIsomorphism {
    pub fn new(montgomery: MontgomeryCurve) -> Result<Self> {
        let modulus = montgomery.modulus();
        let inv3 = Fp2::from_u64(modulus, 3).invert()?;
        let inv27 = Fp2::from_u64(modulus, 27).invert()?;
        let x_shift = montgomery.a.mul(&inv3)?;
        let a = Fp2::one(modulus).sub(&montgomery.a.square().mul(&inv3)?)?;
        let b = montgomery
            .a
            .square()
            .mul(&montgomery.a)?
            .mul(&Fp2::from_u64(modulus, 2))?
            .mul(&inv27)?
            .sub(&montgomery.a.mul(&inv3)?)?;
        let weierstrass = ShortWeierstrassCurve::new(a, b)?;
        Ok(Self {
            montgomery,
            weierstrass,
            x_shift,
        })
    }

    pub fn montgomery_curve(&self) -> &MontgomeryCurve {
        &self.montgomery
    }

    pub fn weierstrass_curve(&self) -> &ShortWeierstrassCurve {
        &self.weierstrass
    }

    pub fn to_weierstrass_point(&self, point: &CurvePoint) -> Result<CurvePoint> {
        self.montgomery
            .validate_point(point)
            .map_err(|error| match error {
                crate::crypto::isogeny::curve::montgomery::CurveError::Field(inner) => {
                    WeierstrassError::Field(inner)
                }
                crate::crypto::isogeny::curve::montgomery::CurveError::ModulusMismatch => {
                    WeierstrassError::ModulusMismatch
                }
                crate::crypto::isogeny::curve::montgomery::CurveError::PointNotOnCurve => {
                    WeierstrassError::PointNotOnCurve
                }
                crate::crypto::isogeny::curve::montgomery::CurveError::SingularCurve => {
                    WeierstrassError::SingularCurve
                }
            })?;
        if point.is_infinity() {
            return Ok(self.weierstrass.identity());
        }
        let x = point.x.add(&self.x_shift)?;
        let y = point.y;
        Ok(CurvePoint::affine(x, y))
    }

    pub fn to_montgomery_point(&self, point: &CurvePoint) -> Result<CurvePoint> {
        self.weierstrass.validate_point(point)?;
        if point.is_infinity() {
            return Ok(self.montgomery.identity());
        }
        let x = point.x.sub(&self.x_shift)?;
        let y = point.y;
        let result = CurvePoint::affine(x, y);
        self.montgomery
            .validate_point(&result)
            .map_err(|error| match error {
                crate::crypto::isogeny::curve::montgomery::CurveError::Field(inner) => {
                    WeierstrassError::Field(inner)
                }
                crate::crypto::isogeny::curve::montgomery::CurveError::ModulusMismatch => {
                    WeierstrassError::ModulusMismatch
                }
                crate::crypto::isogeny::curve::montgomery::CurveError::PointNotOnCurve => {
                    WeierstrassError::PointNotOnCurve
                }
                crate::crypto::isogeny::curve::montgomery::CurveError::SingularCurve => {
                    WeierstrassError::SingularCurve
                }
            })?;
        Ok(result)
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
    use alloc::{vec, vec::Vec};

    use super::{MontgomeryIsomorphism, ShortWeierstrassCurve, WeierstrassError};
    use crate::crypto::isogeny::curve::montgomery::MontgomeryCurve;
    use crate::crypto::isogeny::curve::point::CurvePoint;
    use crate::crypto::isogeny::field::{Fp, Fp2, FpModulus};

    fn modulus19() -> FpModulus {
        FpModulus::from_u64(19).unwrap()
    }

    fn base(value: u64) -> Fp2 {
        Fp2::from_u64(&modulus19(), value)
    }

    fn montgomery19() -> MontgomeryCurve {
        MontgomeryCurve::new(base(5)).unwrap()
    }

    fn affine(x: u64, y: u64) -> CurvePoint {
        CurvePoint::affine(base(x), base(y))
    }

    fn enumerate_montgomery_points(curve: &MontgomeryCurve) -> Vec<CurvePoint> {
        let mut points = vec![curve.identity()];
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

    #[test]
    fn rejects_singular_short_weierstrass_curve() {
        let zero = Fp2::zero(&modulus19());
        assert_eq!(
            ShortWeierstrassCurve::new(zero, zero),
            Err(WeierstrassError::SingularCurve)
        );
    }

    #[test]
    fn montgomery_conversion_roundtrips_points() {
        let montgomery = montgomery19();
        let iso = MontgomeryIsomorphism::new(montgomery).unwrap();
        for point in enumerate_montgomery_points(&montgomery) {
            let sw = iso.to_weierstrass_point(&point).unwrap();
            assert!(iso.weierstrass_curve().is_on_curve(&sw).unwrap());
            let recovered = iso.to_montgomery_point(&sw).unwrap();
            assert_eq!(recovered, point);
        }
    }

    #[test]
    fn short_weierstrass_group_law_matches_expected_identity_behaviour() {
        let iso = MontgomeryIsomorphism::new(montgomery19()).unwrap();
        let curve = iso.weierstrass_curve();
        let points = enumerate_montgomery_points(iso.montgomery_curve())
            .into_iter()
            .filter(|point| !point.is_infinity())
            .map(|point| iso.to_weierstrass_point(&point).unwrap())
            .collect::<Vec<_>>();
        let p = points[0];
        let q = points[1];

        assert_eq!(curve.add(&curve.identity(), &p).unwrap(), p);
        assert_eq!(curve.add(&p, &curve.identity()).unwrap(), p);
        assert_eq!(curve.add(&p, &q).unwrap(), curve.add(&q, &p).unwrap());
        assert_eq!(curve.add(&p, &p.negate()).unwrap(), curve.identity());
    }

    #[test]
    fn conversion_matches_expected_shift_for_a_zero_curve() {
        let modulus = modulus19();
        let montgomery = MontgomeryCurve::new(Fp2::zero(&modulus)).unwrap();
        let iso = MontgomeryIsomorphism::new(montgomery).unwrap();
        let point = CurvePoint::affine(
            Fp2::from_base(Fp::from_u64(&modulus, 0)),
            Fp2::from_base(Fp::from_u64(&modulus, 0)),
        );
        let sw_point = iso.to_weierstrass_point(&point).unwrap();
        assert_eq!(sw_point, point);
        assert_eq!(iso.weierstrass_curve().a.to_u64_pair(), Some((1, 0)));
        assert_eq!(iso.weierstrass_curve().b.to_u64_pair(), Some((0, 0)));
    }
}
