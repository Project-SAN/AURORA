//! Small kernel Vélu isogenies over short-Weierstrass curves.

use alloc::vec::Vec;

use crate::crypto::isogeny::curve::point::CurvePoint;
use crate::crypto::isogeny::curve::weierstrass::{ShortWeierstrassCurve, WeierstrassError};
use crate::crypto::isogeny::field::{Fp, Fp2, FpError};

pub type Result<T> = core::result::Result<T, VeluError>;

const SEARCH_BOUND: u64 = 16;
const MAX_KERNEL_ORDER: usize = 257;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VeluError {
    Curve(WeierstrassError),
    UnsupportedKernelOrder,
    KernelPointAtInfinity,
    KernelOrderMismatch,
    SamplePointSearchFailed,
}

impl From<WeierstrassError> for VeluError {
    fn from(value: WeierstrassError) -> Self {
        Self::Curve(value)
    }
}

impl From<FpError> for VeluError {
    fn from(value: FpError) -> Self {
        Self::Curve(WeierstrassError::Field(value))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VeluIsogeny {
    domain: ShortWeierstrassCurve,
    codomain: ShortWeierstrassCurve,
    kernel_order: usize,
    kernel_points: Vec<CurvePoint>,
}

impl VeluIsogeny {
    pub fn from_kernel(
        domain: ShortWeierstrassCurve,
        generator: CurvePoint,
        kernel_order: usize,
    ) -> Result<Self> {
        if kernel_order < 2
            || kernel_order > MAX_KERNEL_ORDER
            || (kernel_order != 2 && kernel_order % 2 == 0)
        {
            return Err(VeluError::UnsupportedKernelOrder);
        }
        if generator.is_infinity() {
            return Err(VeluError::KernelPointAtInfinity);
        }
        domain.validate_point(&generator)?;
        validate_exact_kernel_order(&domain, &generator, kernel_order)?;

        let kernel_points = enumerate_kernel_points(&domain, &generator, kernel_order)?;
        let codomain = interpolate_codomain(&domain, &kernel_points)?;
        Ok(Self {
            domain,
            codomain,
            kernel_order,
            kernel_points,
        })
    }

    pub fn domain(&self) -> &ShortWeierstrassCurve {
        &self.domain
    }

    pub fn codomain(&self) -> &ShortWeierstrassCurve {
        &self.codomain
    }

    pub fn degree(&self) -> usize {
        self.kernel_order
    }

    pub fn kernel_points(&self) -> &[CurvePoint] {
        &self.kernel_points
    }

    pub fn map_point(&self, point: &CurvePoint) -> Result<CurvePoint> {
        self.domain.validate_point(point)?;
        if point.is_infinity() || self.contains_kernel_point(point) {
            return Ok(self.codomain.identity());
        }

        let mut x = point.x;
        let mut y = point.y;
        for kernel_point in &self.kernel_points {
            let sum = self.domain.add(point, kernel_point)?;
            x = x.add(&sum.x.sub(&kernel_point.x)?)?;
            y = y.add(&sum.y.sub(&kernel_point.y)?)?;
        }
        let image = CurvePoint::affine(x, y);
        self.codomain.validate_point(&image)?;
        Ok(image)
    }

    pub fn is_homomorphism_for(&self, p: &CurvePoint, q: &CurvePoint) -> Result<bool> {
        let lhs = self.map_point(&self.domain.add(p, q)?)?;
        let rhs = self
            .codomain
            .add(&self.map_point(p)?, &self.map_point(q)?)?;
        Ok(lhs == rhs)
    }

    fn contains_kernel_point(&self, point: &CurvePoint) -> bool {
        self.kernel_points
            .iter()
            .any(|candidate| candidate == point)
    }
}

fn validate_exact_kernel_order(
    curve: &ShortWeierstrassCurve,
    generator: &CurvePoint,
    kernel_order: usize,
) -> Result<()> {
    if curve.scalar_mul_u64(generator, kernel_order as u64)? != curve.identity() {
        return Err(VeluError::KernelOrderMismatch);
    }
    for prime in prime_divisors(kernel_order) {
        if curve.scalar_mul_u64(generator, (kernel_order / prime) as u64)? == curve.identity() {
            return Err(VeluError::KernelOrderMismatch);
        }
    }
    Ok(())
}

fn enumerate_kernel_points(
    curve: &ShortWeierstrassCurve,
    generator: &CurvePoint,
    kernel_order: usize,
) -> Result<Vec<CurvePoint>> {
    let mut points = Vec::with_capacity(kernel_order - 1);
    let mut acc = *generator;
    for _ in 1..kernel_order {
        if acc.is_infinity() {
            return Err(VeluError::KernelOrderMismatch);
        }
        points.push(acc);
        acc = curve.add(&acc, generator)?;
    }
    if acc != curve.identity() {
        return Err(VeluError::KernelOrderMismatch);
    }
    Ok(points)
}

fn interpolate_codomain(
    domain: &ShortWeierstrassCurve,
    kernel_points: &[CurvePoint],
) -> Result<ShortWeierstrassCurve> {
    let mut samples = Vec::new();
    for point in sample_points(domain)? {
        if kernel_points.iter().any(|kernel| *kernel == point) {
            continue;
        }
        let image = map_with_kernel(domain, kernel_points, &point)?;
        if image.is_infinity() {
            continue;
        }
        if samples
            .iter()
            .all(|sample: &(CurvePoint, CurvePoint)| sample.0.x != image.x)
        {
            samples.push((image, point));
            if samples.len() == 2 {
                break;
            }
        }
    }
    if samples.len() < 2 {
        return Err(VeluError::SamplePointSearchFailed);
    }

    let (image1, _) = samples[0];
    let (image2, _) = samples[1];
    let rhs1 = image1.y.square().sub(&image1.x.square().mul(&image1.x)?)?;
    let rhs2 = image2.y.square().sub(&image2.x.square().mul(&image2.x)?)?;
    let a = rhs1.sub(&rhs2)?.mul(&image1.x.sub(&image2.x)?.invert()?)?;
    let b = rhs1.sub(&a.mul(&image1.x)?)?;
    let codomain = ShortWeierstrassCurve::new(a, b)?;

    for (image, _) in &samples {
        codomain.validate_point(image)?;
    }
    Ok(codomain)
}

fn map_with_kernel(
    domain: &ShortWeierstrassCurve,
    kernel_points: &[CurvePoint],
    point: &CurvePoint,
) -> Result<CurvePoint> {
    if point.is_infinity() || kernel_points.iter().any(|candidate| candidate == point) {
        return Ok(domain.identity());
    }
    let mut x = point.x;
    let mut y = point.y;
    for kernel_point in kernel_points {
        let sum = domain.add(point, kernel_point)?;
        x = x.add(&sum.x.sub(&kernel_point.x)?)?;
        y = y.add(&sum.y.sub(&kernel_point.y)?)?;
    }
    Ok(CurvePoint::affine(x, y))
}

fn sample_points(curve: &ShortWeierstrassCurve) -> Result<Vec<CurvePoint>> {
    let modulus = curve.modulus();
    let mut points = Vec::new();
    for x0 in 0..=SEARCH_BOUND {
        for x1 in 0..=SEARCH_BOUND {
            let x = Fp2::new(Fp::from_u64(modulus, x0), Fp::from_u64(modulus, x1))
                .map_err(WeierstrassError::from)?;
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

fn prime_divisors(mut value: usize) -> Vec<usize> {
    let mut divisors = Vec::new();
    let mut divisor = 2usize;
    while divisor * divisor <= value {
        if value % divisor == 0 {
            divisors.push(divisor);
            while value % divisor == 0 {
                value /= divisor;
            }
        }
        divisor += if divisor == 2 { 1 } else { 2 };
    }
    if value > 1 {
        divisors.push(value);
    }
    divisors
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use super::{Result, VeluError, VeluIsogeny};
    use crate::crypto::isogeny::curve::montgomery::MontgomeryCurve;
    use crate::crypto::isogeny::curve::point::CurvePoint;
    use crate::crypto::isogeny::curve::weierstrass::{
        MontgomeryIsomorphism, ShortWeierstrassCurve,
    };
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

    fn enumerate_points(curve: &ShortWeierstrassCurve) -> Vec<CurvePoint> {
        let modulus = *curve.modulus();
        let mut points = vec![curve.identity()];
        for x0 in 0..19u64 {
            for x1 in 0..1u64 {
                let x = Fp2::new(Fp::from_u64(&modulus, x0), Fp::from_u64(&modulus, x1)).unwrap();
                if let Some(y) = curve.rhs(&x).unwrap().sqrt() {
                    let point = CurvePoint::affine(x, y);
                    if curve.is_on_curve(&point).unwrap() {
                        points.push(point);
                        let neg = point.negate();
                        if neg != point {
                            points.push(neg);
                        }
                    }
                }
            }
        }
        points
    }

    fn find_point_of_order(curve: &ShortWeierstrassCurve, order: u64) -> CurvePoint {
        enumerate_points(curve)
            .into_iter()
            .find(|point| {
                if point.is_infinity() {
                    return false;
                }
                if curve.scalar_mul_u64(point, order).unwrap() != curve.identity() {
                    return false;
                }
                for prime in [3u64, 5, 7, 11] {
                    if order % prime == 0
                        && curve.scalar_mul_u64(point, order / prime).unwrap() == curve.identity()
                    {
                        return false;
                    }
                }
                true
            })
            .expect("expected point of requested order")
    }

    fn sample_non_kernel_point(curve: &ShortWeierstrassCurve, kernel: &[CurvePoint]) -> CurvePoint {
        enumerate_points(curve)
            .into_iter()
            .find(|point| !point.is_infinity() && kernel.iter().all(|candidate| candidate != point))
            .unwrap()
    }

    #[test]
    fn rejects_large_or_unsupported_even_kernel_orders() {
        let iso = MontgomeryIsomorphism::new(montgomery19()).unwrap();
        let curve = *iso.weierstrass_curve();
        let generator = find_point_of_order(&curve, 3);
        assert_eq!(
            VeluIsogeny::from_kernel(curve, generator, 4),
            Err(VeluError::UnsupportedKernelOrder)
        );
        assert_eq!(
            VeluIsogeny::from_kernel(curve, generator, 1024),
            Err(VeluError::UnsupportedKernelOrder)
        );
    }

    #[test]
    fn kernel_points_map_to_infinity() -> Result<()> {
        let iso = MontgomeryIsomorphism::new(montgomery19()).unwrap();
        let curve = *iso.weierstrass_curve();
        let generator = find_point_of_order(&curve, 3);
        let isogeny = VeluIsogeny::from_kernel(curve, generator, 3)?;
        assert_eq!(
            isogeny.map_point(&generator)?,
            isogeny.codomain().identity()
        );
        assert_eq!(
            isogeny.map_point(&curve.identity())?,
            isogeny.codomain().identity()
        );
        Ok(())
    }

    #[test]
    fn mapped_points_land_on_codomain() -> Result<()> {
        let iso = MontgomeryIsomorphism::new(montgomery19()).unwrap();
        let curve = *iso.weierstrass_curve();
        let generator = find_point_of_order(&curve, 3);
        let isogeny = VeluIsogeny::from_kernel(curve, generator, 3)?;
        let point = sample_non_kernel_point(&curve, isogeny.kernel_points());
        let image = isogeny.map_point(&point)?;
        assert!(isogeny.codomain().is_on_curve(&image)?);
        Ok(())
    }

    #[test]
    fn velu_map_is_a_homomorphism_for_sample_points() -> Result<()> {
        let iso = MontgomeryIsomorphism::new(montgomery19()).unwrap();
        let curve = *iso.weierstrass_curve();
        let generator = find_point_of_order(&curve, 3);
        let isogeny = VeluIsogeny::from_kernel(curve, generator, 3)?;
        let points: Vec<_> = enumerate_points(&curve)
            .into_iter()
            .filter(|point| {
                !point.is_infinity() && isogeny.kernel_points().iter().all(|k| k != point)
            })
            .collect();
        let p = points[0];
        let q = points[1];
        assert!(isogeny.is_homomorphism_for(&p, &q)?);
        Ok(())
    }

    #[test]
    fn degree_two_kernel_is_supported() -> Result<()> {
        let iso = MontgomeryIsomorphism::new(montgomery19()).unwrap();
        let curve = *iso.weierstrass_curve();
        let generator = find_point_of_order(&curve, 2);
        let isogeny = VeluIsogeny::from_kernel(curve, generator, 2)?;
        assert_eq!(
            isogeny.map_point(&generator)?,
            isogeny.codomain().identity()
        );
        Ok(())
    }
}
