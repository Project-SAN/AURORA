use alloc::{vec, vec::Vec};
use core::cmp::Ordering;

/// Fixed-width unsigned integer for PRISM bookkeeping values.
///
/// The paper-level challenge degree `q(2^a-q)` reaches roughly `2^(2a)`, so the
/// largest salt-PRISM parameter set needs around 640 bits. We reserve 768 bits
/// so degree/norm arithmetic can stay `no_std` and heap-free.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WideUint<const LIMBS: usize> {
    limbs: [u64; LIMBS],
}

/// Canonical width for salt-PRISM degree and norm bookkeeping.
pub type IsogenyInteger = WideUint<12>;
/// Fixed-width signed integer for quaternion coefficients.
pub type QuaternionInteger = SignedWideInt<32>;

impl IsogenyInteger {
    pub const BYTES: usize = 96;

    pub fn to_be_bytes_fixed(&self) -> [u8; Self::BYTES] {
        let mut out = [0u8; Self::BYTES];
        for (index, limb) in self.limbs().iter().rev().enumerate() {
            let start = index * 8;
            out[start..start + 8].copy_from_slice(&limb.to_be_bytes());
        }
        out
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignedWideInt<const LIMBS: usize> {
    negative: bool,
    magnitude: WideUint<LIMBS>,
}

impl<const LIMBS: usize> SignedWideInt<LIMBS> {
    pub const BYTES: usize = 1 + LIMBS * 8;

    pub const fn zero() -> Self {
        Self {
            negative: false,
            magnitude: WideUint::zero(),
        }
    }

    pub fn from_i128(value: i128) -> Self {
        if value < 0 {
            Self {
                negative: true,
                magnitude: WideUint::from_u128(value.unsigned_abs()),
            }
        } else {
            Self {
                negative: false,
                magnitude: WideUint::from_u128(value as u128),
            }
        }
    }

    pub fn is_zero(&self) -> bool {
        self.magnitude.is_zero()
    }

    pub fn is_negative(&self) -> bool {
        self.negative && !self.magnitude.is_zero()
    }

    pub fn is_positive(&self) -> bool {
        !self.negative && !self.magnitude.is_zero()
    }

    pub fn magnitude(&self) -> WideUint<LIMBS> {
        self.magnitude
    }

    pub fn unsigned_abs(&self) -> WideUint<LIMBS> {
        self.magnitude
    }

    pub fn checked_neg(&self) -> Option<Self> {
        Some(if self.is_zero() {
            *self
        } else {
            Self {
                negative: !self.negative,
                magnitude: self.magnitude,
            }
        })
    }

    pub fn checked_add(&self, rhs: &Self) -> Option<Self> {
        match (self.is_negative(), rhs.is_negative()) {
            (false, false) => Some(Self::from_parts(
                false,
                self.magnitude.checked_add(&rhs.magnitude)?,
            )),
            (true, true) => Some(Self::from_parts(
                true,
                self.magnitude.checked_add(&rhs.magnitude)?,
            )),
            (false, true) => Self::sub_magnitudes(self.magnitude, rhs.magnitude),
            (true, false) => Self::sub_magnitudes(rhs.magnitude, self.magnitude),
        }
    }

    pub fn checked_sub(&self, rhs: &Self) -> Option<Self> {
        self.checked_add(&rhs.checked_neg()?)
    }

    pub fn checked_mul(&self, rhs: &Self) -> Option<Self> {
        let magnitude = self.magnitude.checked_mul(&rhs.magnitude)?;
        Some(Self::from_parts(
            self.is_negative() ^ rhs.is_negative(),
            magnitude,
        ))
    }

    pub fn scale_i128(&self, scalar: i128) -> Option<Self> {
        self.checked_mul(&Self::from_i128(scalar))
    }

    pub fn try_to_i128(&self) -> Option<i128> {
        let value = self.magnitude.try_to_u128()?;
        if self.is_negative() {
            let magnitude = i128::try_from(value).ok()?;
            magnitude.checked_neg()
        } else {
            i128::try_from(value).ok()
        }
    }

    pub fn from_be_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::BYTES {
            return None;
        }
        let negative = match bytes[0] {
            0 => false,
            1 => true,
            _ => return None,
        };
        let magnitude = WideUint::from_be_slice(&bytes[1..])?;
        Some(Self::from_parts(negative, magnitude))
    }

    pub fn to_be_bytes(&self) -> Vec<u8> {
        let mut out = vec![0u8; Self::BYTES];
        self.encode_be_fixed_into(&mut out)
            .expect("signed wide integer fixed encoding has the expected width");
        out
    }

    fn encode_be_fixed_into(&self, out: &mut [u8]) -> Option<()> {
        if out.len() != Self::BYTES {
            return None;
        }
        out.fill(0);
        out[0] = u8::from(self.is_negative());
        for (index, limb) in self.magnitude.limbs().iter().rev().enumerate() {
            let start = 1 + index * 8;
            out[start..start + 8].copy_from_slice(&limb.to_be_bytes());
        }
        Some(())
    }

    fn from_parts(negative: bool, magnitude: WideUint<LIMBS>) -> Self {
        if magnitude.is_zero() {
            Self::zero()
        } else {
            Self {
                negative,
                magnitude,
            }
        }
    }

    fn sub_magnitudes(lhs: WideUint<LIMBS>, rhs: WideUint<LIMBS>) -> Option<Self> {
        match lhs.cmp(&rhs) {
            Ordering::Greater => Some(Self::from_parts(false, lhs.checked_sub(&rhs)?)),
            Ordering::Equal => Some(Self::zero()),
            Ordering::Less => Some(Self::from_parts(true, rhs.checked_sub(&lhs)?)),
        }
    }
}

impl SignedWideInt<32> {
    pub fn to_be_bytes_fixed(&self) -> [u8; 257] {
        let mut out = [0u8; 257];
        self.encode_be_fixed_into(&mut out)
            .expect("quaternion integer fixed encoding has the expected width");
        out
    }
}

impl<const LIMBS: usize> WideUint<LIMBS> {
    pub const fn zero() -> Self {
        Self {
            limbs: [0u64; LIMBS],
        }
    }

    pub const fn one() -> Self {
        let mut limbs = [0u64; LIMBS];
        if LIMBS > 0 {
            limbs[0] = 1;
        }
        Self { limbs }
    }

    pub const fn from_u64(value: u64) -> Self {
        let mut limbs = [0u64; LIMBS];
        if LIMBS > 0 {
            limbs[0] = value;
        }
        Self { limbs }
    }

    pub const fn from_u128(value: u128) -> Self {
        let mut limbs = [0u64; LIMBS];
        if LIMBS > 0 {
            limbs[0] = value as u64;
        }
        if LIMBS > 1 {
            limbs[1] = (value >> 64) as u64;
        }
        Self { limbs }
    }

    pub fn from_be_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > LIMBS * 8 {
            let excess = bytes.len() - LIMBS * 8;
            if bytes[..excess].iter().any(|byte| *byte != 0) {
                return None;
            }
        }

        let mut limbs = [0u64; LIMBS];
        let start = bytes.len().saturating_sub(LIMBS * 8);
        let trimmed = &bytes[start..];
        let mut cursor = trimmed.len();
        let mut limb = 0usize;
        while cursor > 0 && limb < LIMBS {
            let chunk_start = cursor.saturating_sub(8);
            let chunk = &trimmed[chunk_start..cursor];
            let mut buf = [0u8; 8];
            let offset = 8 - chunk.len();
            buf[offset..].copy_from_slice(chunk);
            limbs[limb] = u64::from_be_bytes(buf);
            cursor = chunk_start;
            limb += 1;
        }
        Some(Self { limbs })
    }

    pub fn to_be_bytes_trimmed(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(LIMBS * 8);
        let mut started = false;
        for limb in self.limbs.iter().rev() {
            let bytes = limb.to_be_bytes();
            if !started {
                if *limb == 0 {
                    continue;
                }
                let first = bytes
                    .iter()
                    .position(|byte| *byte != 0)
                    .unwrap_or(bytes.len() - 1);
                out.extend_from_slice(&bytes[first..]);
                started = true;
            } else {
                out.extend_from_slice(&bytes);
            }
        }
        if out.is_empty() {
            out.push(0);
        }
        out
    }

    pub fn to_be_bytes_trimmed_padded<const BYTES: usize>(&self) -> [u8; BYTES] {
        let mut out = [0u8; BYTES];
        let bytes = self.to_be_bytes_trimmed();
        let start = BYTES.saturating_sub(bytes.len());
        out[start..start + bytes.len()].copy_from_slice(&bytes);
        out
    }

    pub const fn limbs(&self) -> &[u64; LIMBS] {
        &self.limbs
    }

    pub fn try_to_u128(&self) -> Option<u128> {
        if LIMBS > 2 && self.limbs[2..].iter().any(|limb| *limb != 0) {
            return None;
        }
        let low = self.limbs.first().copied().unwrap_or(0) as u128;
        let high = self.limbs.get(1).copied().unwrap_or(0) as u128;
        Some(low | (high << 64))
    }

    pub fn try_to_u64(&self) -> Option<u64> {
        if LIMBS > 1 && self.limbs[1..].iter().any(|limb| *limb != 0) {
            return None;
        }
        Some(self.limbs.first().copied().unwrap_or(0))
    }

    pub fn try_to_usize(&self) -> Option<usize> {
        let value = self.try_to_u64()?;
        usize::try_from(value).ok()
    }

    pub fn is_zero(&self) -> bool {
        self.limbs.iter().all(|limb| *limb == 0)
    }

    pub fn is_even(&self) -> bool {
        self.limbs.first().copied().unwrap_or(0) & 1 == 0
    }

    pub fn bit_len(&self) -> usize {
        for (index, limb) in self.limbs.iter().enumerate().rev() {
            if *limb != 0 {
                return index * 64 + (64 - limb.leading_zeros() as usize);
            }
        }
        0
    }

    pub fn trailing_zeros(&self) -> Option<usize> {
        for (index, limb) in self.limbs.iter().enumerate() {
            if *limb != 0 {
                return Some(index * 64 + limb.trailing_zeros() as usize);
            }
        }
        None
    }

    pub fn checked_add(&self, rhs: &Self) -> Option<Self> {
        let mut out = [0u64; LIMBS];
        let mut carry = 0u128;
        for (index, dst) in out.iter_mut().enumerate() {
            let accum = self.limbs[index] as u128 + rhs.limbs[index] as u128 + carry;
            *dst = accum as u64;
            carry = accum >> 64;
        }
        if carry == 0 {
            Some(Self { limbs: out })
        } else {
            None
        }
    }

    pub fn checked_sub(&self, rhs: &Self) -> Option<Self> {
        if self < rhs {
            return None;
        }
        let mut out = [0u64; LIMBS];
        let mut borrow = 0u128;
        for (index, dst) in out.iter_mut().enumerate() {
            let lhs = self.limbs[index] as u128;
            let rhs = rhs.limbs[index] as u128 + borrow;
            if lhs >= rhs {
                *dst = (lhs - rhs) as u64;
                borrow = 0;
            } else {
                *dst = ((1u128 << 64) + lhs - rhs) as u64;
                borrow = 1;
            }
        }
        debug_assert_eq!(borrow, 0);
        Some(Self { limbs: out })
    }

    pub fn checked_mul(&self, rhs: &Self) -> Option<Self> {
        let mut out = [0u64; LIMBS];
        for i in 0..LIMBS {
            let mut carry = 0u128;
            for j in 0..LIMBS {
                let index = i + j;
                if index >= LIMBS {
                    if self.limbs[i] != 0 && rhs.limbs[j] != 0 {
                        return None;
                    }
                    continue;
                }
                let accum =
                    self.limbs[i] as u128 * rhs.limbs[j] as u128 + out[index] as u128 + carry;
                out[index] = accum as u64;
                carry = accum >> 64;
            }
            if carry != 0 {
                return None;
            }
        }
        Some(Self { limbs: out })
    }

    pub fn shl_bits(&self, bits: usize) -> Option<Self> {
        if bits == 0 {
            return Some(*self);
        }
        let limb_shift = bits / 64;
        let bit_shift = bits % 64;
        if limb_shift >= LIMBS {
            return if self.is_zero() {
                Some(Self::zero())
            } else {
                None
            };
        }

        let mut out = [0u64; LIMBS];
        for index in (0..LIMBS).rev() {
            let Some(src) = index.checked_sub(limb_shift) else {
                continue;
            };
            out[index] |= self.limbs[src] << bit_shift;
            if bit_shift != 0 {
                if src == 0 {
                    continue;
                }
                out[index] |= self.limbs[src - 1] >> (64 - bit_shift);
            }
        }

        for index in 0..limb_shift {
            if self.limbs[LIMBS - 1 - index] != 0 {
                return None;
            }
        }
        if bit_shift != 0 {
            let overflow_src = LIMBS - 1 - limb_shift;
            if self.limbs[overflow_src] >> (64 - bit_shift) != 0 {
                return None;
            }
        }

        Some(Self { limbs: out })
    }

    pub fn shr_bits(&self, bits: usize) -> Self {
        if bits == 0 {
            return *self;
        }
        let limb_shift = bits / 64;
        let bit_shift = bits % 64;
        if limb_shift >= LIMBS {
            return Self::zero();
        }

        let mut out = [0u64; LIMBS];
        for index in 0..(LIMBS - limb_shift) {
            let src = index + limb_shift;
            out[index] |= self.limbs[src] >> bit_shift;
            if bit_shift != 0 && src + 1 < LIMBS {
                out[index] |= self.limbs[src + 1] << (64 - bit_shift);
            }
        }

        Self { limbs: out }
    }

    pub fn pow2(bit: usize) -> Option<Self> {
        let limb = bit / 64;
        let offset = bit % 64;
        if limb >= LIMBS {
            return None;
        }
        let mut limbs = [0u64; LIMBS];
        limbs[limb] = 1u64 << offset;
        Some(Self { limbs })
    }

    pub fn rem_u64(&self, divisor: u64) -> Option<u64> {
        if divisor == 0 {
            return None;
        }
        let mut rem = 0u128;
        for limb in self.limbs.iter().rev() {
            let accum = (rem << 64) | u128::from(*limb);
            rem = accum % u128::from(divisor);
        }
        Some(rem as u64)
    }

    pub fn div_rem_u64(&self, divisor: u64) -> Option<(Self, u64)> {
        if divisor == 0 {
            return None;
        }
        let mut out = [0u64; LIMBS];
        let mut rem = 0u128;
        for (index, limb) in self.limbs.iter().enumerate().rev() {
            let accum = (rem << 64) | u128::from(*limb);
            out[index] = (accum / u128::from(divisor)) as u64;
            rem = accum % u128::from(divisor);
        }
        Some((Self { limbs: out }, rem as u64))
    }

    pub fn div_rem(&self, divisor: &Self) -> Option<(Self, Self)> {
        if divisor.is_zero() {
            return None;
        }
        if self < divisor {
            return Some((Self::zero(), *self));
        }
        if divisor == &Self::one() {
            return Some((*self, Self::zero()));
        }

        let mut quotient = Self::zero();
        let mut remainder = *self;
        let shift = remainder.bit_len().saturating_sub(divisor.bit_len());
        for bit in (0..=shift).rev() {
            let Some(shifted) = divisor.shl_bits(bit) else {
                continue;
            };
            if shifted > remainder {
                continue;
            }
            remainder = remainder.checked_sub(&shifted)?;
            quotient.limbs[bit / 64] |= 1u64 << (bit % 64);
        }

        Some((quotient, remainder))
    }

    pub fn checked_div_exact(&self, divisor: &Self) -> Option<Self> {
        let (quotient, remainder) = self.div_rem(divisor)?;
        if remainder.is_zero() {
            Some(quotient)
        } else {
            None
        }
    }
}

impl<const LIMBS: usize> Default for WideUint<LIMBS> {
    fn default() -> Self {
        Self::zero()
    }
}

impl<const LIMBS: usize> Default for SignedWideInt<LIMBS> {
    fn default() -> Self {
        Self::zero()
    }
}

impl<const LIMBS: usize> From<u16> for WideUint<LIMBS> {
    fn from(value: u16) -> Self {
        Self::from_u64(u64::from(value))
    }
}

impl<const LIMBS: usize> From<u32> for WideUint<LIMBS> {
    fn from(value: u32) -> Self {
        Self::from_u64(u64::from(value))
    }
}

impl<const LIMBS: usize> From<u64> for WideUint<LIMBS> {
    fn from(value: u64) -> Self {
        Self::from_u64(value)
    }
}

impl<const LIMBS: usize> From<usize> for WideUint<LIMBS> {
    fn from(value: usize) -> Self {
        Self::from_u64(value as u64)
    }
}

impl<const LIMBS: usize> From<u128> for WideUint<LIMBS> {
    fn from(value: u128) -> Self {
        Self::from_u128(value)
    }
}

impl<const LIMBS: usize> From<i32> for WideUint<LIMBS> {
    fn from(value: i32) -> Self {
        Self::from_u64(value as u64)
    }
}

impl<const LIMBS: usize> From<i32> for SignedWideInt<LIMBS> {
    fn from(value: i32) -> Self {
        Self::from_i128(i128::from(value))
    }
}

impl<const LIMBS: usize> From<i64> for SignedWideInt<LIMBS> {
    fn from(value: i64) -> Self {
        Self::from_i128(i128::from(value))
    }
}

impl<const LIMBS: usize> From<i128> for SignedWideInt<LIMBS> {
    fn from(value: i128) -> Self {
        Self::from_i128(value)
    }
}

impl<const LIMBS: usize> From<u32> for SignedWideInt<LIMBS> {
    fn from(value: u32) -> Self {
        Self::from_i128(i128::from(value))
    }
}

impl<const LIMBS: usize> From<u64> for SignedWideInt<LIMBS> {
    fn from(value: u64) -> Self {
        Self {
            negative: false,
            magnitude: WideUint::from_u64(value),
        }
    }
}

impl<const LIMBS: usize> PartialOrd for SignedWideInt<LIMBS> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<const LIMBS: usize> Ord for SignedWideInt<LIMBS> {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self.is_negative(), other.is_negative()) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (false, false) => self.magnitude.cmp(&other.magnitude),
            (true, true) => other.magnitude.cmp(&self.magnitude),
        }
    }
}

impl<const LIMBS: usize> PartialEq<i128> for SignedWideInt<LIMBS> {
    fn eq(&self, other: &i128) -> bool {
        self.try_to_i128() == Some(*other)
    }
}

impl<const LIMBS: usize> PartialOrd<i128> for SignedWideInt<LIMBS> {
    fn partial_cmp(&self, other: &i128) -> Option<Ordering> {
        let rhs = Self::from(*other);
        Some(self.cmp(&rhs))
    }
}

impl<const LIMBS: usize> PartialEq<SignedWideInt<LIMBS>> for i128 {
    fn eq(&self, other: &SignedWideInt<LIMBS>) -> bool {
        other == self
    }
}

impl<const LIMBS: usize> PartialOrd<SignedWideInt<LIMBS>> for i128 {
    fn partial_cmp(&self, other: &SignedWideInt<LIMBS>) -> Option<Ordering> {
        other.partial_cmp(self).map(Ordering::reverse)
    }
}

impl<const LIMBS: usize> PartialEq<u128> for WideUint<LIMBS> {
    fn eq(&self, other: &u128) -> bool {
        self.try_to_u128() == Some(*other)
    }
}

impl<const LIMBS: usize> PartialOrd<u128> for WideUint<LIMBS> {
    fn partial_cmp(&self, other: &u128) -> Option<Ordering> {
        Some(match self.try_to_u128() {
            Some(value) => value.cmp(other),
            None => Ordering::Greater,
        })
    }
}

impl<const LIMBS: usize> PartialEq<WideUint<LIMBS>> for u128 {
    fn eq(&self, other: &WideUint<LIMBS>) -> bool {
        other == self
    }
}

impl<const LIMBS: usize> PartialOrd<WideUint<LIMBS>> for u128 {
    fn partial_cmp(&self, other: &WideUint<LIMBS>) -> Option<Ordering> {
        other.partial_cmp(self).map(Ordering::reverse)
    }
}

impl<const LIMBS: usize> PartialOrd for WideUint<LIMBS> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<const LIMBS: usize> Ord for WideUint<LIMBS> {
    fn cmp(&self, other: &Self) -> Ordering {
        for index in (0..LIMBS).rev() {
            match self.limbs[index].cmp(&other.limbs[index]) {
                Ordering::Equal => continue,
                ordering => return ordering,
            }
        }
        Ordering::Equal
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::{IsogenyInteger, QuaternionInteger, WideUint};

    #[test]
    fn bytes_roundtrip_preserves_value() {
        type Int = WideUint<4>;
        let value = Int::from_be_slice(&[
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba,
            0xdc, 0xfe,
        ])
        .unwrap();
        assert_eq!(
            value.to_be_bytes_trimmed(),
            vec![
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba,
                0xdc, 0xfe,
            ]
        );
    }

    #[test]
    fn bit_length_tracks_limb_boundaries() {
        type Int = WideUint<4>;
        assert_eq!(Int::zero().bit_len(), 0);
        assert_eq!(Int::one().bit_len(), 1);
        assert_eq!(Int::pow2(63).unwrap().bit_len(), 64);
        assert_eq!(Int::pow2(64).unwrap().bit_len(), 65);
        assert_eq!(Int::pow2(191).unwrap().bit_len(), 192);
    }

    #[test]
    fn arithmetic_works_across_multiple_limbs() {
        type Int = WideUint<4>;
        let lhs = Int::pow2(130)
            .unwrap()
            .checked_add(&Int::from_u64(17))
            .unwrap();
        let rhs = Int::pow2(65)
            .unwrap()
            .checked_add(&Int::from_u64(9))
            .unwrap();
        let sum = lhs.checked_add(&rhs).unwrap();
        let product = lhs.checked_mul(&rhs).unwrap();

        assert_eq!(sum.bit_len(), 131);
        assert_eq!(sum.rem_u64(17).unwrap(), 15);
        assert!(product.bit_len() >= 196);
    }

    #[test]
    fn division_by_small_integer_roundtrips() {
        type Int = WideUint<4>;
        let value = Int::pow2(190)
            .unwrap()
            .checked_add(&Int::pow2(64).unwrap())
            .unwrap()
            .checked_add(&Int::from_u64(123))
            .unwrap();
        let (quotient, rem) = value.div_rem_u64(17).unwrap();
        let rebuilt = quotient
            .checked_mul(&Int::from_u64(17))
            .unwrap()
            .checked_add(&Int::from_u64(rem))
            .unwrap();
        assert_eq!(rebuilt, value);
    }

    #[test]
    fn wide_division_roundtrips() {
        type Int = WideUint<4>;
        let dividend = Int::pow2(200)
            .unwrap()
            .checked_add(&Int::pow2(127).unwrap())
            .unwrap()
            .checked_add(&Int::from_u64(99))
            .unwrap();
        let divisor = Int::pow2(65)
            .unwrap()
            .checked_add(&Int::from_u64(7))
            .unwrap();
        let (quotient, remainder) = dividend.div_rem(&divisor).unwrap();
        let rebuilt = quotient
            .checked_mul(&divisor)
            .unwrap()
            .checked_add(&remainder)
            .unwrap();
        assert_eq!(rebuilt, dividend);
        assert!(remainder < divisor);
    }

    #[test]
    fn shifts_and_trailing_zeros_work_across_limbs() {
        type Int = WideUint<4>;
        let value = Int::pow2(133).unwrap();
        assert_eq!(value.trailing_zeros(), Some(133));
        assert_eq!(value.shr_bits(69), Int::pow2(64).unwrap());
        assert_eq!(value.shr_bits(134), Int::zero());
    }

    #[test]
    fn level1_challenge_degree_exceeds_u128() {
        let q = IsogenyInteger::pow2(191).unwrap();
        let two_a = IsogenyInteger::pow2(192).unwrap();
        let complement = two_a.checked_sub(&q).unwrap();
        let degree = q.checked_mul(&complement).unwrap();
        assert!(degree.bit_len() > 128);
        assert_eq!(degree.bit_len(), 383);
        assert_eq!(degree.try_to_u128(), None);
    }

    #[test]
    fn signed_arithmetic_and_bytes_roundtrip() {
        let lhs = QuaternionInteger::from(-17i32);
        let rhs = QuaternionInteger::from(9i32);
        assert_eq!(
            lhs.checked_add(&rhs).unwrap(),
            QuaternionInteger::from(-8i32)
        );
        assert_eq!(
            lhs.checked_sub(&rhs).unwrap(),
            QuaternionInteger::from(-26i32)
        );
        assert_eq!(
            lhs.checked_mul(&rhs).unwrap(),
            QuaternionInteger::from(-153i32)
        );
        assert_eq!(lhs.checked_neg().unwrap(), QuaternionInteger::from(17i32));

        let encoded = lhs.to_be_bytes_fixed();
        assert_eq!(QuaternionInteger::from_be_slice(&encoded).unwrap(), lhs);
    }
}
