//! Prime-field arithmetic over a runtime-selected odd modulus.
//!
//! The storage is now fixed-width and stack-allocated: every element carries a
//! modulus descriptor and uses up to `MAX_LIMBS` little-endian `u64` limbs.
//! Different PRISM parameter sets therefore map to fixed limb widths without
//! any heap traffic in the field core.

use alloc::vec::Vec;
use core::cmp::{max, Ordering};

pub const MAX_LIMBS: usize = 8;
const MAX_SUM_LIMBS: usize = MAX_LIMBS + 1;
const MAX_PRODUCT_LIMBS: usize = MAX_LIMBS * 2;

pub type Result<T> = core::result::Result<T, FpError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FpError {
    InvalidModulus,
    ModulusMismatch,
    NotInvertible,
    InputTooWide,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FpModulus {
    limbs: [u64; MAX_LIMBS],
    limb_len: usize,
}

impl FpModulus {
    pub fn new(limbs: &[u64]) -> Result<Self> {
        if limbs.is_empty() || limbs.len() > MAX_LIMBS {
            return Err(FpError::InvalidModulus);
        }
        let limb_len = normalize_len(limbs, limbs.len());
        if limb_len == 0 {
            return Err(FpError::InvalidModulus);
        }
        if limbs[0] & 1 == 0 {
            return Err(FpError::InvalidModulus);
        }
        if limb_len == 1 && limbs[0] <= 2 {
            return Err(FpError::InvalidModulus);
        }

        let mut out = [0u64; MAX_LIMBS];
        out[..limb_len].copy_from_slice(&limbs[..limb_len]);
        Ok(Self {
            limbs: out,
            limb_len,
        })
    }

    pub fn from_u64(value: u64) -> Result<Self> {
        Self::new(&[value])
    }

    pub fn from_le_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_LIMBS * 8 {
            return Err(FpError::InputTooWide);
        }
        let (limbs, limb_len) = le_bytes_to_fixed_limbs(bytes)?;
        Self::new(&limbs[..limb_len])
    }

    pub fn from_be_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_LIMBS * 8 {
            return Err(FpError::InputTooWide);
        }
        let mut le = [0u8; MAX_LIMBS * 8];
        let len = bytes.len();
        for i in 0..len {
            le[i] = bytes[len - 1 - i];
        }
        Self::from_le_bytes(&le[..len])
    }

    pub const fn from_shifted_cofactor(cofactor: u32, shift: usize) -> Self {
        let mut limbs = [0u64; MAX_LIMBS];
        let word = shift / 64;
        let bit = shift % 64;
        limbs[word] = (cofactor as u64) << bit;
        if bit != 0 && word + 1 < MAX_LIMBS {
            limbs[word + 1] = (cofactor as u64) >> (64 - bit);
        }

        let mut i = 0usize;
        loop {
            if limbs[i] != 0 {
                limbs[i] -= 1;
                break;
            }
            limbs[i] = u64::MAX;
            i += 1;
        }

        let mut limb_len = MAX_LIMBS;
        while limb_len > 1 && limbs[limb_len - 1] == 0 {
            limb_len -= 1;
        }
        Self { limbs, limb_len }
    }

    pub const fn limbs(&self) -> &[u64; MAX_LIMBS] {
        &self.limbs
    }

    pub fn as_limbs(&self) -> &[u64] {
        &self.limbs[..self.limb_len]
    }

    pub fn to_u64(&self) -> Option<u64> {
        if self.limb_len == 1 {
            Some(self.limbs[0])
        } else {
            None
        }
    }

    pub const fn limb_len(&self) -> usize {
        self.limb_len
    }

    pub fn bits(&self) -> usize {
        bit_length(&self.limbs, self.limb_len)
    }

    pub fn byte_len(&self) -> usize {
        (self.bits() + 7) / 8
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fp {
    modulus: FpModulus,
    limbs: [u64; MAX_LIMBS],
}

impl Fp {
    pub fn zero(modulus: &FpModulus) -> Self {
        Self {
            modulus: *modulus,
            limbs: [0u64; MAX_LIMBS],
        }
    }

    pub fn one(modulus: &FpModulus) -> Self {
        Self::from_u64(modulus, 1)
    }

    pub fn from_u64(modulus: &FpModulus, value: u64) -> Self {
        Self::from_limbs(modulus, &[value])
    }

    pub fn from_limbs(modulus: &FpModulus, limbs: &[u64]) -> Self {
        let limb_len = normalize_len(limbs, limbs.len());
        if limb_len == 0 {
            return Self::zero(modulus);
        }
        Self {
            modulus: *modulus,
            limbs: mod_reduce(limbs, limb_len, modulus),
        }
    }

    pub fn from_le_bytes(modulus: &FpModulus, bytes: &[u8]) -> Self {
        let mut acc = Self::zero(modulus);
        for &byte in bytes.iter().rev() {
            acc = acc.mul_small(256);
            if byte != 0 {
                acc = acc.add_small(byte as u64);
            }
        }
        acc
    }

    pub fn from_be_bytes(modulus: &FpModulus, bytes: &[u8]) -> Self {
        let mut acc = Self::zero(modulus);
        for &byte in bytes {
            acc = acc.mul_small(256);
            if byte != 0 {
                acc = acc.add_small(byte as u64);
            }
        }
        acc
    }

    pub fn modulus(&self) -> &FpModulus {
        &self.modulus
    }

    pub fn canonical_limbs(&self) -> &[u64] {
        &self.limbs[..self.modulus.limb_len()]
    }

    pub fn is_zero(&self) -> bool {
        is_zero(&self.limbs, self.modulus.limb_len())
    }

    pub fn is_one(&self) -> bool {
        self.limbs[0] == 1
            && self.limbs[1..self.modulus.limb_len()]
                .iter()
                .all(|&limb| limb == 0)
    }

    pub fn to_u64(&self) -> Option<u64> {
        if self.limbs[1..self.modulus.limb_len()]
            .iter()
            .all(|&limb| limb == 0)
        {
            Some(self.limbs[0])
        } else {
            None
        }
    }

    pub fn to_le_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.modulus.byte_len());
        for limb in self.canonical_limbs() {
            out.extend_from_slice(&limb.to_le_bytes());
        }
        out.truncate(self.modulus.byte_len());
        out
    }

    pub fn to_be_bytes(&self) -> Vec<u8> {
        let mut out = self.to_le_bytes();
        out.reverse();
        out
    }

    pub fn add(&self, rhs: &Self) -> Result<Self> {
        self.ensure_same_modulus(rhs)?;
        let (sum, sum_len) = add_limbs::<MAX_SUM_LIMBS>(
            &self.limbs,
            self.modulus.limb_len(),
            &rhs.limbs,
            rhs.modulus.limb_len(),
        );
        Ok(Self {
            modulus: self.modulus,
            limbs: mod_reduce(&sum, sum_len, &self.modulus),
        })
    }

    pub fn double(&self) -> Self {
        self.add(self)
            .expect("field element and modulus must match")
    }

    pub fn sub(&self, rhs: &Self) -> Result<Self> {
        self.ensure_same_modulus(rhs)?;
        let limbs = if cmp_limbs(
            &self.limbs,
            self.modulus.limb_len(),
            &rhs.limbs,
            rhs.modulus.limb_len(),
        ) != Ordering::Less
        {
            let (diff, _) = sub_limbs::<MAX_LIMBS>(
                &self.limbs,
                self.modulus.limb_len(),
                &rhs.limbs,
                rhs.modulus.limb_len(),
            );
            diff
        } else {
            let (lifted, lifted_len) = add_limbs::<MAX_SUM_LIMBS>(
                &self.limbs,
                self.modulus.limb_len(),
                self.modulus.as_limbs(),
                self.modulus.limb_len(),
            );
            let (diff, _) =
                sub_limbs::<MAX_SUM_LIMBS>(&lifted, lifted_len, &rhs.limbs, rhs.modulus.limb_len());
            copy_truncated::<MAX_SUM_LIMBS, MAX_LIMBS>(&diff)
        };

        Ok(Self {
            modulus: self.modulus,
            limbs,
        })
    }

    pub fn neg(&self) -> Self {
        if self.is_zero() {
            return *self;
        }
        let (diff, _) = sub_limbs::<MAX_LIMBS>(
            self.modulus.as_limbs(),
            self.modulus.limb_len(),
            &self.limbs,
            self.modulus.limb_len(),
        );
        Self {
            modulus: self.modulus,
            limbs: diff,
        }
    }

    pub fn mul(&self, rhs: &Self) -> Result<Self> {
        self.ensure_same_modulus(rhs)?;
        let (product, product_len) = mul_limbs(
            &self.limbs,
            self.modulus.limb_len(),
            &rhs.limbs,
            rhs.modulus.limb_len(),
        );
        Ok(Self {
            modulus: self.modulus,
            limbs: mod_reduce(&product, product_len, &self.modulus),
        })
    }

    pub fn square(&self) -> Self {
        self.mul(self)
            .expect("field element and modulus must match")
    }

    pub fn pow_vartime(&self, exponent: &[u64]) -> Self {
        let exponent_len = normalize_len(exponent, exponent.len());
        let mut acc = Self::one(&self.modulus);
        let total_bits = bit_length(exponent, exponent_len);
        for bit_index in (0..total_bits).rev() {
            acc = acc.square();
            if get_bit(exponent, bit_index) {
                acc = acc.mul(self).expect("field element and modulus must match");
            }
        }
        acc
    }

    pub fn invert(&self) -> Result<Self> {
        if self.is_zero() {
            return Err(FpError::NotInvertible);
        }
        let (exponent, exponent_len) =
            sub_small(self.modulus.as_limbs(), self.modulus.limb_len(), 2)
                .ok_or(FpError::InvalidModulus)?;
        Ok(self.pow_vartime(&exponent[..exponent_len]))
    }

    pub fn sqrt(&self) -> Option<Self> {
        if self.is_zero() {
            return Some(*self);
        }
        if self.modulus.as_limbs()[0] & 3 != 3 {
            return None;
        }
        let (sum, sum_len) =
            add_limbs::<MAX_SUM_LIMBS>(self.modulus.as_limbs(), self.modulus.limb_len(), &[1], 1);
        let (exponent, exponent_len) = shr_bits(&sum, sum_len, 2);
        let candidate = self.pow_vartime(&exponent[..exponent_len]);
        if candidate.square() == *self {
            Some(candidate)
        } else {
            None
        }
    }

    fn add_small(&self, small: u64) -> Self {
        let (sum, sum_len) =
            add_limbs::<MAX_SUM_LIMBS>(&self.limbs, self.modulus.limb_len(), &[small], 1);
        Self {
            modulus: self.modulus,
            limbs: mod_reduce(&sum, sum_len, &self.modulus),
        }
    }

    fn mul_small(&self, small: u64) -> Self {
        let (product, product_len) = mul_limbs(&self.limbs, self.modulus.limb_len(), &[small], 1);
        Self {
            modulus: self.modulus,
            limbs: mod_reduce(&product, product_len, &self.modulus),
        }
    }

    fn ensure_same_modulus(&self, rhs: &Self) -> Result<()> {
        if self.modulus == rhs.modulus {
            Ok(())
        } else {
            Err(FpError::ModulusMismatch)
        }
    }
}

fn normalize_len(limbs: &[u64], mut len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    while len > 1 && limbs[len - 1] == 0 {
        len -= 1;
    }
    len
}

fn is_zero(limbs: &[u64], len: usize) -> bool {
    limbs[..len].iter().all(|&limb| limb == 0)
}

fn cmp_limbs(a: &[u64], a_len: usize, b: &[u64], b_len: usize) -> Ordering {
    let a_len = normalize_len(a, a_len);
    let b_len = normalize_len(b, b_len);
    if a_len != b_len {
        return a_len.cmp(&b_len);
    }
    for i in (0..a_len).rev() {
        if a[i] != b[i] {
            return a[i].cmp(&b[i]);
        }
    }
    Ordering::Equal
}

fn add_limbs<const OUT: usize>(
    a: &[u64],
    a_len: usize,
    b: &[u64],
    b_len: usize,
) -> ([u64; OUT], usize) {
    let len = max(a_len, b_len);
    let mut out = [0u64; OUT];
    let mut carry = 0u128;
    for i in 0..len {
        let ai = a.get(i).copied().unwrap_or(0) as u128;
        let bi = b.get(i).copied().unwrap_or(0) as u128;
        let sum = ai + bi + carry;
        out[i] = sum as u64;
        carry = sum >> 64;
    }
    let mut out_len = len;
    if carry != 0 {
        out[len] = carry as u64;
        out_len += 1;
    }
    (out, normalize_len(&out, out_len))
}

fn sub_limbs<const OUT: usize>(
    a: &[u64],
    a_len: usize,
    b: &[u64],
    b_len: usize,
) -> ([u64; OUT], usize) {
    debug_assert!(cmp_limbs(a, a_len, b, b_len) != Ordering::Less);
    let mut out = [0u64; OUT];
    let mut borrow = 0u128;
    for i in 0..a_len {
        let ai = a[i] as u128;
        let bi = b.get(i).copied().unwrap_or(0) as u128;
        let subtrahend = bi + borrow;
        if ai >= subtrahend {
            out[i] = (ai - subtrahend) as u64;
            borrow = 0;
        } else {
            out[i] = ((1u128 << 64) + ai - subtrahend) as u64;
            borrow = 1;
        }
    }
    debug_assert_eq!(borrow, 0);
    (out, normalize_len(&out, a_len))
}

fn mul_limbs(
    a: &[u64],
    a_len: usize,
    b: &[u64],
    b_len: usize,
) -> ([u64; MAX_PRODUCT_LIMBS], usize) {
    if is_zero(a, a_len) || is_zero(b, b_len) {
        return ([0u64; MAX_PRODUCT_LIMBS], 1);
    }
    let mut out = [0u64; MAX_PRODUCT_LIMBS];
    for i in 0..a_len {
        let mut carry = 0u128;
        for j in 0..b_len {
            let idx = i + j;
            let accum = (a[i] as u128) * (b[j] as u128) + (out[idx] as u128) + carry;
            out[idx] = accum as u64;
            carry = accum >> 64;
        }
        let mut idx = i + b_len;
        while carry != 0 {
            debug_assert!(idx < MAX_PRODUCT_LIMBS);
            let accum = (out[idx] as u128) + carry;
            out[idx] = accum as u64;
            carry = accum >> 64;
            idx += 1;
        }
    }
    (out, normalize_len(&out, a_len + b_len))
}

fn mod_reduce(value: &[u64], value_len: usize, modulus: &FpModulus) -> [u64; MAX_LIMBS] {
    if value_len == 0 || is_zero(value, value_len) {
        return [0u64; MAX_LIMBS];
    }
    if cmp_limbs(value, value_len, modulus.as_limbs(), modulus.limb_len()) == Ordering::Less {
        let mut out = [0u64; MAX_LIMBS];
        let copy_len = core::cmp::min(value_len, MAX_LIMBS);
        out[..copy_len].copy_from_slice(&value[..copy_len]);
        return out;
    }

    let mut remainder = [0u64; MAX_SUM_LIMBS];
    let mut remainder_len = 1usize;
    let total_bits = bit_length(value, value_len);
    for bit_index in (0..total_bits).rev() {
        shl1_assign(&mut remainder, &mut remainder_len);
        if get_bit(value, bit_index) {
            remainder[0] |= 1;
        }
        remainder_len = normalize_len(&remainder, remainder_len);
        if cmp_limbs(
            &remainder,
            remainder_len,
            modulus.as_limbs(),
            modulus.limb_len(),
        ) != Ordering::Less
        {
            let (next, next_len) = sub_limbs::<MAX_SUM_LIMBS>(
                &remainder,
                remainder_len,
                modulus.as_limbs(),
                modulus.limb_len(),
            );
            remainder = next;
            remainder_len = next_len;
        }
    }

    copy_truncated::<MAX_SUM_LIMBS, MAX_LIMBS>(&remainder)
}

fn shl1_assign<const N: usize>(limbs: &mut [u64; N], len: &mut usize) {
    let mut carry = 0u64;
    for limb in limbs.iter_mut().take(*len) {
        let next = *limb >> 63;
        *limb = (*limb << 1) | carry;
        carry = next;
    }
    if carry != 0 {
        limbs[*len] = carry;
        *len += 1;
    }
}

fn bit_length(limbs: &[u64], len: usize) -> usize {
    let len = normalize_len(limbs, len);
    if is_zero(limbs, len) {
        return 0;
    }
    let top = limbs[len - 1];
    64 * (len - 1) + (64 - top.leading_zeros() as usize)
}

fn get_bit(limbs: &[u64], bit_index: usize) -> bool {
    let limb_index = bit_index / 64;
    let bit = bit_index % 64;
    limbs
        .get(limb_index)
        .map(|limb| ((limb >> bit) & 1) == 1)
        .unwrap_or(false)
}

fn sub_small(limbs: &[u64], len: usize, small: u64) -> Option<([u64; MAX_LIMBS], usize)> {
    if cmp_limbs(limbs, len, &[small], 1) == Ordering::Less {
        return None;
    }
    let mut out = [0u64; MAX_LIMBS];
    out[..len].copy_from_slice(&limbs[..len]);
    let (value, mut borrow) = out[0].overflowing_sub(small);
    out[0] = value;
    let mut idx = 1usize;
    while borrow {
        let (next, overflow) = out[idx].overflowing_sub(1);
        out[idx] = next;
        borrow = overflow;
        idx += 1;
    }
    Some((out, normalize_len(&out, len)))
}

fn le_bytes_to_fixed_limbs(bytes: &[u8]) -> Result<([u64; MAX_LIMBS], usize)> {
    if bytes.len() > MAX_LIMBS * 8 {
        return Err(FpError::InputTooWide);
    }
    let mut out = [0u64; MAX_LIMBS];
    for (i, chunk) in bytes.chunks(8).enumerate() {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        out[i] = u64::from_le_bytes(buf);
    }
    Ok((out, normalize_len(&out, (bytes.len() + 7) / 8)))
}

fn copy_truncated<const IN: usize, const OUT: usize>(src: &[u64; IN]) -> [u64; OUT] {
    let mut out = [0u64; OUT];
    out.copy_from_slice(&src[..OUT]);
    out
}

fn shr_bits<const N: usize>(limbs: &[u64; N], len: usize, shift: usize) -> ([u64; N], usize) {
    debug_assert!(shift < 64);
    let mut out = [0u64; N];
    let word_shift = shift / 64;
    let bit_shift = shift % 64;
    if len <= word_shift {
        return (out, 1);
    }
    let out_len = len - word_shift;
    for i in 0..out_len {
        let src = i + word_shift;
        out[i] = limbs[src] >> bit_shift;
        if bit_shift != 0 && src + 1 < len {
            out[i] |= limbs[src + 1] << (64 - bit_shift);
        }
    }
    let out_len = normalize_len(&out, out_len);
    (out, if out_len == 0 { 1 } else { out_len })
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::{Fp, FpError, FpModulus, MAX_LIMBS};
    use crate::crypto::isogeny::params::{NIST_LEVEL1_BASE, NIST_LEVEL3_BASE, NIST_LEVEL5_BASE};

    fn fp17(value: u64) -> Fp {
        let modulus = FpModulus::from_u64(17).unwrap();
        Fp::from_u64(&modulus, value)
    }

    #[test]
    fn modulus_must_be_odd_and_nontrivial() {
        assert_eq!(FpModulus::from_u64(0), Err(FpError::InvalidModulus));
        assert_eq!(FpModulus::from_u64(2), Err(FpError::InvalidModulus));
        assert_eq!(FpModulus::from_u64(18), Err(FpError::InvalidModulus));
    }

    #[test]
    fn constructors_normalize_values() {
        let modulus = FpModulus::from_u64(17).unwrap();
        let fp = Fp::from_u64(&modulus, 35);
        assert_eq!(fp.to_u64(), Some(1));

        let le = Fp::from_le_bytes(&modulus, &[0x23, 0x00]);
        assert_eq!(le.to_u64(), Some(1));

        let be = Fp::from_be_bytes(&modulus, &[0x00, 0x23]);
        assert_eq!(be.to_u64(), Some(1));
        assert_eq!(be.to_le_bytes(), vec![0x01]);
        assert_eq!(be.to_be_bytes(), vec![0x01]);
    }

    #[test]
    fn addition_and_subtraction_wrap_correctly() {
        assert_eq!(fp17(9).add(&fp17(10)).unwrap().to_u64(), Some(2));
        assert_eq!(fp17(3).sub(&fp17(5)).unwrap().to_u64(), Some(15));
        assert_eq!(fp17(0).neg().to_u64(), Some(0));
        assert_eq!(fp17(3).neg().to_u64(), Some(14));
    }

    #[test]
    fn multiplication_and_square_reduce_mod_p() {
        assert_eq!(fp17(7).mul(&fp17(5)).unwrap().to_u64(), Some(1));
        assert_eq!(fp17(7).square().to_u64(), Some(15));
        assert_eq!(fp17(9).double().to_u64(), Some(1));
    }

    #[test]
    fn inversion_works_for_non_zero_elements() {
        let inv = fp17(5).invert().unwrap();
        assert_eq!(inv.to_u64(), Some(7));
        assert_eq!(fp17(5).mul(&inv).unwrap().to_u64(), Some(1));
        assert_eq!(fp17(0).invert(), Err(FpError::NotInvertible));
    }

    #[test]
    fn mismatched_moduli_are_rejected() {
        let p17 = FpModulus::from_u64(17).unwrap();
        let p19 = FpModulus::from_u64(19).unwrap();
        let a = Fp::from_u64(&p17, 3);
        let b = Fp::from_u64(&p19, 3);
        assert_eq!(a.add(&b), Err(FpError::ModulusMismatch));
        assert_eq!(a.mul(&b), Err(FpError::ModulusMismatch));
    }

    #[test]
    fn modulus_constants_fit_fixed_storage() {
        for params in [NIST_LEVEL1_BASE, NIST_LEVEL3_BASE, NIST_LEVEL5_BASE] {
            assert!(params.modulus.limb_len() <= MAX_LIMBS);
            let cofactor_bits = (u32::BITS - params.cofactor.leading_zeros()) as usize;
            assert_eq!(
                params.modulus.bits(),
                params.two_torsion_bits + cofactor_bits
            );
        }
    }

    #[test]
    fn shifted_cofactor_moduli_match_expected_low_words() {
        let level1 = NIST_LEVEL1_BASE.modulus;
        assert_eq!(level1.as_limbs()[0], u64::MAX);
        assert_eq!(level1.as_limbs()[1], u64::MAX);
        assert_eq!(level1.as_limbs()[2], u64::MAX);
        assert_eq!(level1.as_limbs()[3], 0x04ff_ffff_ffff_ffff);

        let level3 = NIST_LEVEL3_BASE.modulus;
        assert_eq!(level3.as_limbs()[0], u64::MAX);
        assert_eq!(level3.as_limbs()[5], 0x40ff_ffff_ffff_ffff);
    }

    #[test]
    fn square_root_works_for_residues() {
        let modulus = FpModulus::from_u64(19).unwrap();
        let sixteen = Fp::from_u64(&modulus, 16);
        let root = sixteen.sqrt().unwrap();
        assert_eq!(root.square(), sixteen);
        assert!(Fp::from_u64(&modulus, 2).sqrt().is_none());
        assert!(Fp::from_u64(&modulus, 1).sqrt().unwrap().is_one());
    }
}
