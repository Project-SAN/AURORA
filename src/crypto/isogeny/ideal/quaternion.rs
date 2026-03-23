//! Quaternion algebra types backing the Deuring correspondence.

use crate::crypto::isogeny::arith::{IsogenyInteger, QuaternionInteger};

pub type Result<T> = core::result::Result<T, QuaternionError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuaternionError {
    InvalidRamifiedPrime,
    AlgebraMismatch,
    CoefficientOverflow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuaternionAlgebra {
    ramified_prime: u32,
}

impl QuaternionAlgebra {
    pub fn new(ramified_prime: u32) -> Result<Self> {
        if ramified_prime <= 1 || ramified_prime & 1 == 0 {
            return Err(QuaternionError::InvalidRamifiedPrime);
        }
        Ok(Self { ramified_prime })
    }

    pub const fn new_unchecked(ramified_prime: u32) -> Self {
        Self { ramified_prime }
    }

    pub const fn ramified_prime(&self) -> u32 {
        self.ramified_prime
    }
}

impl Default for QuaternionAlgebra {
    fn default() -> Self {
        Self::new_unchecked(3)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuaternionElement {
    algebra: QuaternionAlgebra,
    coeffs: [QuaternionInteger; 4],
}

impl QuaternionElement {
    pub fn zero(algebra: QuaternionAlgebra) -> Self {
        Self::from_coeffs(algebra, [0, 0, 0, 0])
    }

    pub fn one(algebra: QuaternionAlgebra) -> Self {
        Self::from_coeffs(algebra, [1, 0, 0, 0])
    }

    pub fn basis_i(algebra: QuaternionAlgebra) -> Self {
        Self::from_coeffs(algebra, [0, 1, 0, 0])
    }

    pub fn basis_j(algebra: QuaternionAlgebra) -> Self {
        Self::from_coeffs(algebra, [0, 0, 1, 0])
    }

    pub fn basis_k(algebra: QuaternionAlgebra) -> Self {
        Self::from_coeffs(algebra, [0, 0, 0, 1])
    }

    pub fn from_coeffs<T>(algebra: QuaternionAlgebra, coeffs: [T; 4]) -> Self
    where
        T: Into<QuaternionInteger> + Copy,
    {
        Self {
            algebra,
            coeffs: coeffs.map(Into::into),
        }
    }

    pub const fn algebra(&self) -> QuaternionAlgebra {
        self.algebra
    }

    pub fn coeffs(&self) -> [QuaternionInteger; 4] {
        self.coeffs
    }

    pub fn is_zero(&self) -> bool {
        self.coeffs.iter().all(QuaternionInteger::is_zero)
    }

    pub fn add(&self, rhs: &Self) -> Result<Self> {
        if self.algebra != rhs.algebra {
            return Err(QuaternionError::AlgebraMismatch);
        }
        let mut coeffs = [QuaternionInteger::zero(); 4];
        for (dst, (lhs, rhs)) in coeffs
            .iter_mut()
            .zip(self.coeffs.iter().zip(rhs.coeffs.iter()))
        {
            *dst = lhs
                .checked_add(rhs)
                .ok_or(QuaternionError::CoefficientOverflow)?;
        }
        Ok(Self::from_coeffs(self.algebra, coeffs))
    }

    pub fn sub(&self, rhs: &Self) -> Result<Self> {
        if self.algebra != rhs.algebra {
            return Err(QuaternionError::AlgebraMismatch);
        }
        let mut coeffs = [QuaternionInteger::zero(); 4];
        for (dst, (lhs, rhs)) in coeffs
            .iter_mut()
            .zip(self.coeffs.iter().zip(rhs.coeffs.iter()))
        {
            *dst = lhs
                .checked_sub(rhs)
                .ok_or(QuaternionError::CoefficientOverflow)?;
        }
        Ok(Self::from_coeffs(self.algebra, coeffs))
    }

    pub fn neg(&self) -> Result<Self> {
        let mut coeffs = [QuaternionInteger::zero(); 4];
        for (dst, coeff) in coeffs.iter_mut().zip(self.coeffs.iter()) {
            *dst = coeff
                .checked_neg()
                .ok_or(QuaternionError::CoefficientOverflow)?;
        }
        Ok(Self::from_coeffs(self.algebra, coeffs))
    }

    pub fn scale(&self, scalar: i128) -> Result<Self> {
        let mut coeffs = [QuaternionInteger::zero(); 4];
        for (dst, coeff) in coeffs.iter_mut().zip(self.coeffs.iter()) {
            *dst = coeff
                .scale_i128(scalar)
                .ok_or(QuaternionError::CoefficientOverflow)?;
        }
        Ok(Self::from_coeffs(self.algebra, coeffs))
    }

    pub fn conjugate(&self) -> Self {
        Self::from_coeffs(
            self.algebra,
            [
                self.coeffs[0],
                self.coeffs[1]
                    .checked_neg()
                    .expect("quaternion conjugation coefficient fits in QuaternionInteger"),
                self.coeffs[2]
                    .checked_neg()
                    .expect("quaternion conjugation coefficient fits in QuaternionInteger"),
                self.coeffs[3]
                    .checked_neg()
                    .expect("quaternion conjugation coefficient fits in QuaternionInteger"),
            ],
        )
    }

    pub fn multiply(&self, rhs: &Self) -> Result<Self> {
        if self.algebra != rhs.algebra {
            return Err(QuaternionError::AlgebraMismatch);
        }

        let p = QuaternionInteger::from(u64::from(self.algebra.ramified_prime()));
        let [a1, b1, c1, d1] = self.coeffs;
        let [a2, b2, c2, d2] = rhs.coeffs;

        let c_terms = checked_add_coeff(checked_mul_coeff(c1, c2)?, checked_mul_coeff(d1, d2)?)?;
        let scalar = checked_sub_coeff(
            checked_sub_coeff(checked_mul_coeff(a1, a2)?, checked_mul_coeff(b1, b2)?)?,
            checked_mul_coeff(p, c_terms)?,
        )?;

        let cd_delta = checked_sub_coeff(checked_mul_coeff(c1, d2)?, checked_mul_coeff(d1, c2)?)?;
        let i_coeff = checked_add_coeff(
            checked_add_coeff(checked_mul_coeff(a1, b2)?, checked_mul_coeff(b1, a2)?)?,
            checked_mul_coeff(p, cd_delta)?,
        )?;

        let j_coeff = checked_sub_coeff(
            checked_add_coeff(checked_mul_coeff(a1, c2)?, checked_mul_coeff(c1, a2)?)?,
            checked_sub_coeff(checked_mul_coeff(b1, d2)?, checked_mul_coeff(d1, b2)?)?,
        )?;

        let k_coeff = checked_add_coeff(
            checked_add_coeff(checked_mul_coeff(a1, d2)?, checked_mul_coeff(d1, a2)?)?,
            checked_sub_coeff(checked_mul_coeff(b1, c2)?, checked_mul_coeff(c1, b2)?)?,
        )?;

        Ok(Self::from_coeffs(
            self.algebra,
            [scalar, i_coeff, j_coeff, k_coeff],
        ))
    }

    pub fn reduced_trace(&self) -> QuaternionInteger {
        self.coeffs[0]
            .scale_i128(2)
            .expect("reduced trace fits in QuaternionInteger")
    }

    pub fn try_reduced_norm(&self) -> Option<IsogenyInteger> {
        let a_sq = coeff_try_square(self.coeffs[0])?;
        let b_sq = coeff_try_square(self.coeffs[1])?;
        let c_sq = coeff_try_square(self.coeffs[2])?;
        let d_sq = coeff_try_square(self.coeffs[3])?;
        let p = IsogenyInteger::from(u64::from(self.algebra.ramified_prime()));
        let cd = c_sq.checked_add(&d_sq)?;
        let pcd = p.checked_mul(&cd)?;
        a_sq.checked_add(&b_sq)
            .and_then(|sum| sum.checked_add(&pcd))
    }

    pub fn reduced_norm(&self) -> IsogenyInteger {
        self.try_reduced_norm()
            .expect("reduced norm fits in IsogenyInteger")
    }
}

fn coeff_try_square(coeff: QuaternionInteger) -> Option<IsogenyInteger> {
    let abs = IsogenyInteger::from_be_slice(&coeff.unsigned_abs().to_be_bytes_trimmed())?;
    abs.checked_mul(&abs)
}

fn checked_add_coeff(lhs: QuaternionInteger, rhs: QuaternionInteger) -> Result<QuaternionInteger> {
    lhs.checked_add(&rhs)
        .ok_or(QuaternionError::CoefficientOverflow)
}

fn checked_sub_coeff(lhs: QuaternionInteger, rhs: QuaternionInteger) -> Result<QuaternionInteger> {
    lhs.checked_sub(&rhs)
        .ok_or(QuaternionError::CoefficientOverflow)
}

fn checked_mul_coeff(lhs: QuaternionInteger, rhs: QuaternionInteger) -> Result<QuaternionInteger> {
    lhs.checked_mul(&rhs)
        .ok_or(QuaternionError::CoefficientOverflow)
}

#[cfg(test)]
mod tests {
    use super::{QuaternionAlgebra, QuaternionElement, QuaternionError};
    use crate::crypto::isogeny::arith::{IsogenyInteger, QuaternionInteger};

    #[test]
    fn rejects_invalid_ramified_prime() {
        assert_eq!(
            QuaternionAlgebra::new(0),
            Err(QuaternionError::InvalidRamifiedPrime)
        );
        assert_eq!(
            QuaternionAlgebra::new(2),
            Err(QuaternionError::InvalidRamifiedPrime)
        );
    }

    #[test]
    fn basis_relations_match_reference_algebra() {
        let algebra = QuaternionAlgebra::new(5).unwrap();
        let i = QuaternionElement::basis_i(algebra);
        let j = QuaternionElement::basis_j(algebra);
        let k = QuaternionElement::basis_k(algebra);

        assert_eq!(
            i.multiply(&i).unwrap(),
            QuaternionElement::from_coeffs(algebra, [-1, 0, 0, 0])
        );
        assert_eq!(
            j.multiply(&j).unwrap(),
            QuaternionElement::from_coeffs(algebra, [-5, 0, 0, 0])
        );
        assert_eq!(
            k.multiply(&k).unwrap(),
            QuaternionElement::from_coeffs(algebra, [-5, 0, 0, 0])
        );
        assert_eq!(i.multiply(&j).unwrap(), k);
        assert_eq!(j.multiply(&i).unwrap(), k.neg().unwrap());
    }

    #[test]
    fn conjugation_and_norm_work() {
        let algebra = QuaternionAlgebra::new(5).unwrap();
        let x = QuaternionElement::from_coeffs(algebra, [3, -2, 4, 1]);
        let x_bar = x.conjugate();
        let product = x.multiply(&x_bar).unwrap();
        let norm = x.reduced_norm();
        assert_eq!(
            product,
            QuaternionElement::from_coeffs(
                algebra,
                [
                    i128::try_from(norm.try_to_u128().unwrap()).unwrap(),
                    0,
                    0,
                    0
                ],
            )
        );
        assert_eq!(x.reduced_trace(), QuaternionInteger::from(6i32));
    }

    #[test]
    fn reduced_norm_is_multiplicative() {
        let algebra = QuaternionAlgebra::new(7).unwrap();
        let x = QuaternionElement::from_coeffs(algebra, [2, 1, -1, 3]);
        let y = QuaternionElement::from_coeffs(algebra, [1, -2, 2, 0]);
        let xy = x.multiply(&y).unwrap();
        assert_eq!(
            xy.reduced_norm(),
            x.reduced_norm().checked_mul(&y.reduced_norm()).unwrap()
        );
    }

    #[test]
    fn arithmetic_rejects_mismatched_algebras() {
        let x = QuaternionElement::one(QuaternionAlgebra::new(3).unwrap());
        let y = QuaternionElement::one(QuaternionAlgebra::new(5).unwrap());
        assert_eq!(x.add(&y), Err(QuaternionError::AlgebraMismatch));
        assert_eq!(x.multiply(&y), Err(QuaternionError::AlgebraMismatch));
    }

    #[test]
    fn reduced_norm_supports_values_beyond_u128() {
        let algebra = QuaternionAlgebra::new(u32::MAX).unwrap();
        let x = QuaternionElement::from_coeffs(algebra, [0, 0, 1i128 << 62, 0]);
        let norm = x.reduced_norm();
        assert!(norm.bit_len() > 128);
        assert_eq!(
            norm,
            IsogenyInteger::from(u64::from(u32::MAX))
                .checked_mul(&IsogenyInteger::pow2(124).unwrap())
                .unwrap()
        );
    }

    #[test]
    fn scaling_matches_repeated_addition() {
        let algebra = QuaternionAlgebra::new(11).unwrap();
        let x = QuaternionElement::from_coeffs(algebra, [2, -1, 3, 0]);
        let scaled = x.scale(3).unwrap();
        let repeated = x.add(&x).unwrap().add(&x).unwrap();
        assert_eq!(scaled, repeated);
        assert_eq!(x.scale(-1).unwrap(), x.neg().unwrap());
    }
}
