//! Quadratic extension field arithmetic over `u^2 = -1`.

use super::fp::{Fp, FpError, FpModulus, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fp2 {
    pub c0: Fp,
    pub c1: Fp,
}

impl Fp2 {
    pub fn new(c0: Fp, c1: Fp) -> Result<Self> {
        if c0.modulus() != c1.modulus() {
            return Err(FpError::ModulusMismatch);
        }
        Ok(Self { c0, c1 })
    }

    pub fn zero(modulus: &FpModulus) -> Self {
        Self {
            c0: Fp::zero(modulus),
            c1: Fp::zero(modulus),
        }
    }

    pub fn one(modulus: &FpModulus) -> Self {
        Self {
            c0: Fp::one(modulus),
            c1: Fp::zero(modulus),
        }
    }

    pub fn from_base(c0: Fp) -> Self {
        let modulus = *c0.modulus();
        Self {
            c0,
            c1: Fp::zero(&modulus),
        }
    }

    pub fn from_u64(modulus: &FpModulus, value: u64) -> Self {
        Self {
            c0: Fp::from_u64(modulus, value),
            c1: Fp::zero(modulus),
        }
    }

    pub fn modulus(&self) -> &FpModulus {
        self.c0.modulus()
    }

    pub fn to_u64_pair(&self) -> Option<(u64, u64)> {
        Some((self.c0.to_u64()?, self.c1.to_u64()?))
    }

    pub fn is_zero(&self) -> bool {
        self.c0.is_zero() && self.c1.is_zero()
    }

    pub fn is_one(&self) -> bool {
        self.c0.is_one() && self.c1.is_zero()
    }

    pub fn add(&self, rhs: &Self) -> Result<Self> {
        self.ensure_same_modulus(rhs)?;
        Self::new(self.c0.add(&rhs.c0)?, self.c1.add(&rhs.c1)?)
    }

    pub fn double(&self) -> Self {
        self.add(self).expect("Fp2 elements share a modulus")
    }

    pub fn sub(&self, rhs: &Self) -> Result<Self> {
        self.ensure_same_modulus(rhs)?;
        Self::new(self.c0.sub(&rhs.c0)?, self.c1.sub(&rhs.c1)?)
    }

    pub fn neg(&self) -> Self {
        Self {
            c0: self.c0.neg(),
            c1: self.c1.neg(),
        }
    }

    pub fn conjugate(&self) -> Self {
        Self {
            c0: self.c0.clone(),
            c1: self.c1.neg(),
        }
    }

    pub fn square(&self) -> Self {
        let a2 = self.c0.square();
        let b2 = self.c1.square();
        let real = a2.sub(&b2).expect("Fp2 components share a modulus");
        let imag = self
            .c0
            .mul(&self.c1)
            .expect("Fp2 components share a modulus")
            .double();
        Self { c0: real, c1: imag }
    }

    pub fn mul(&self, rhs: &Self) -> Result<Self> {
        self.ensure_same_modulus(rhs)?;
        let ac = self.c0.mul(&rhs.c0)?;
        let bd = self.c1.mul(&rhs.c1)?;
        let ad = self.c0.mul(&rhs.c1)?;
        let bc = self.c1.mul(&rhs.c0)?;
        let real = ac.sub(&bd)?;
        let imag = ad.add(&bc)?;
        Self::new(real, imag)
    }

    pub fn norm(&self) -> Fp {
        let a2 = self.c0.square();
        let b2 = self.c1.square();
        a2.add(&b2).expect("Fp2 components share a modulus")
    }

    pub fn invert(&self) -> Result<Self> {
        if self.is_zero() {
            return Err(FpError::NotInvertible);
        }
        let inv_norm = self.norm().invert()?;
        let c0 = self.c0.mul(&inv_norm)?;
        let c1 = self.c1.neg().mul(&inv_norm)?;
        Self::new(c0, c1)
    }

    pub fn sqrt(&self) -> Option<Self> {
        if self.is_zero() {
            return Some(*self);
        }
        if self.c1.is_zero() {
            if let Some(root) = self.c0.sqrt() {
                return Some(Self::from_base(root));
            }
            if let Some(root) = self.c0.neg().sqrt() {
                return Self::new(Fp::zero(self.modulus()), root).ok();
            }
            return None;
        }

        let two_inv = Fp::from_u64(self.modulus(), 2).invert().ok()?;
        let alpha = self.c0.square().add(&self.c1.square()).ok()?.sqrt()?;

        let x_sq = self.c0.add(&alpha).ok()?.mul(&two_inv).ok()?;
        if let Some(x) = x_sq.sqrt() {
            if x.is_zero() {
                return None;
            }
            let denom = x.double();
            let y = self.c1.mul(&denom.invert().ok()?).ok()?;
            let candidate = Self::new(x, y).ok()?;
            if candidate.square() == *self {
                return Some(candidate);
            }
        }

        let y_sq = alpha.sub(&self.c0).ok()?.mul(&two_inv).ok()?;
        if let Some(y) = y_sq.sqrt() {
            if y.is_zero() {
                return None;
            }
            let denom = y.double();
            let x = self.c1.mul(&denom.invert().ok()?).ok()?;
            let candidate = Self::new(x, y).ok()?;
            if candidate.square() == *self {
                return Some(candidate);
            }
        }
        None
    }

    fn ensure_same_modulus(&self, rhs: &Self) -> Result<()> {
        if self.modulus() == rhs.modulus() {
            Ok(())
        } else {
            Err(FpError::ModulusMismatch)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Fp2;
    use crate::crypto::isogeny::field::fp::{Fp, FpError, FpModulus};

    fn fp19(value: u64) -> Fp {
        let modulus = FpModulus::from_u64(19).unwrap();
        Fp::from_u64(&modulus, value)
    }

    fn fp2_19(c0: u64, c1: u64) -> Fp2 {
        Fp2::new(fp19(c0), fp19(c1)).unwrap()
    }

    #[test]
    fn constructors_require_matching_moduli() {
        let p17 = FpModulus::from_u64(17).unwrap();
        let p19 = FpModulus::from_u64(19).unwrap();
        let a = Fp::from_u64(&p17, 1);
        let b = Fp::from_u64(&p19, 1);
        assert_eq!(Fp2::new(a, b), Err(FpError::ModulusMismatch));
    }

    #[test]
    fn addition_subtraction_and_negation_work() {
        let a = fp2_19(3, 4);
        let b = fp2_19(5, 7);
        let sum = a.add(&b).unwrap();
        assert_eq!(sum.c0.to_u64(), Some(8));
        assert_eq!(sum.c1.to_u64(), Some(11));

        let diff = a.sub(&b).unwrap();
        assert_eq!(diff.c0.to_u64(), Some(17));
        assert_eq!(diff.c1.to_u64(), Some(16));

        let neg = a.neg();
        assert_eq!(neg.c0.to_u64(), Some(16));
        assert_eq!(neg.c1.to_u64(), Some(15));
    }

    #[test]
    fn multiplication_and_square_use_u_squared_minus_one() {
        let a = fp2_19(3, 4);
        let b = fp2_19(5, 7);
        let product = a.mul(&b).unwrap();
        assert_eq!(product.c0.to_u64(), Some(6));
        assert_eq!(product.c1.to_u64(), Some(3));

        let square = a.square();
        assert_eq!(square.c0.to_u64(), Some(12));
        assert_eq!(square.c1.to_u64(), Some(5));
    }

    #[test]
    fn conjugation_norm_and_inversion_work() {
        let a = fp2_19(3, 4);
        let conj = a.conjugate();
        assert_eq!(conj.c0.to_u64(), Some(3));
        assert_eq!(conj.c1.to_u64(), Some(15));
        assert_eq!(a.norm().to_u64(), Some(6));

        let inv = a.invert().unwrap();
        assert_eq!(inv.c0.to_u64(), Some(10));
        assert_eq!(inv.c1.to_u64(), Some(12));

        let one = a.mul(&inv).unwrap();
        assert_eq!(one.c0.to_u64(), Some(1));
        assert_eq!(one.c1.to_u64(), Some(0));
    }

    #[test]
    fn square_root_works_for_quadratic_extension_elements() {
        let z = fp2_19(3, 4);
        let sq = z.square();
        let root = sq.sqrt().unwrap();
        assert_eq!(root.square(), sq);

        let base_square = fp2_19(9, 0);
        let root = base_square.sqrt().unwrap();
        assert_eq!(root.square(), base_square);
    }
}
