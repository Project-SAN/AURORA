//! Random ideal sampling by target norm.

use alloc::vec::Vec;

use rand_core::RngCore;

use crate::crypto::isogeny::arith::{IsogenyInteger, QuaternionInteger};
use crate::crypto::isogeny::ideal::ideal::{IdealError, LeftIdeal};
use crate::crypto::isogeny::ideal::order::MaximalOrder;
use crate::crypto::isogeny::ideal::quaternion::QuaternionElement;

pub type Result<T> = core::result::Result<T, RandomIdealError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RandomIdealError {
    InvalidNorm,
    Ideal(IdealError),
}

impl From<IdealError> for RandomIdealError {
    fn from(error: IdealError) -> Self {
        Self::Ideal(error)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RandomIdealSampler;

impl RandomIdealSampler {
    const EXACT_REDUCED_NORM_SEARCH_LIMIT: u64 = 1 << 12;
    const SHORT_ELEMENT_ENUMERATION_LIMIT: usize = 256;
    const SHORT_ELEMENT_ENUMERATION_COEFF_BOUND_MAX: u64 = 4;

    pub fn sample_given_norm<R: RngCore>(
        order: &MaximalOrder,
        target_norm: impl Into<IsogenyInteger>,
        rng: &mut R,
    ) -> Result<LeftIdeal> {
        let target_norm = target_norm.into();
        if target_norm == 0 {
            return Err(RandomIdealError::InvalidNorm);
        }

        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);

        if let Some(generator) = Self::exact_reduced_norm_generator(order, target_norm, &seed) {
            return LeftIdeal::principal(*order, generator).map_err(RandomIdealError::from);
        }

        let mut coeffs = [QuaternionInteger::zero(); 4];
        for (idx, chunk) in seed.chunks_exact(8).enumerate() {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(chunk);
            let raw = u64::from_le_bytes(bytes);
            coeffs[idx] = QuaternionInteger::from(i128::from(raw & 0x3fff) - 0x1fff);
        }
        let low_bits = target_norm.rem_u64(1 << 13).unwrap_or(0);
        coeffs[0] = coeffs[0]
            .checked_add(&QuaternionInteger::from(
                (i128::from(low_bits) & 0x1fff) | 1,
            ))
            .ok_or(RandomIdealError::Ideal(IdealError::Quaternion(
                crate::crypto::isogeny::ideal::quaternion::QuaternionError::CoefficientOverflow,
            )))?;
        if coeffs.iter().all(QuaternionInteger::is_zero) {
            coeffs[0] = QuaternionInteger::from(1i32);
        }

        let generator = QuaternionElement::from_coeffs(order.algebra(), coeffs);
        LeftIdeal::new(*order, *order, generator, target_norm).map_err(RandomIdealError::from)
    }

    fn exact_reduced_norm_generator(
        order: &MaximalOrder,
        target_norm: IsogenyInteger,
        seed: &[u8; 32],
    ) -> Option<QuaternionElement> {
        let target = target_norm.try_to_u64()?;
        if target == 0 || target > Self::EXACT_REDUCED_NORM_SEARCH_LIMIT {
            return None;
        }
        let algebra = order.algebra();
        let coeff_bound = integer_sqrt(target).saturating_add(1);
        if coeff_bound <= Self::SHORT_ELEMENT_ENUMERATION_COEFF_BOUND_MAX {
            let order_ideal = LeftIdeal::principal(*order, QuaternionElement::one(algebra)).ok()?;
            let enumerated = order_ideal
                .enumerate_short_elements(
                    i32::try_from(coeff_bound).ok()?,
                    Self::SHORT_ELEMENT_ENUMERATION_LIMIT,
                )
                .ok()?;
            let mut enumerated_candidates = enumerated
                .into_iter()
                .filter(|candidate| candidate.reduced_norm() == target_norm)
                .collect::<Vec<_>>();
            if !enumerated_candidates.is_empty() {
                let primitive = enumerated_candidates
                    .iter()
                    .copied()
                    .filter(is_primitive_generator)
                    .collect::<Vec<_>>();
                let candidates = if primitive.is_empty() {
                    &mut enumerated_candidates
                } else {
                    return select_candidate_from_seed(&primitive, seed);
                };
                return select_candidate_from_seed(candidates, seed);
            }
        }

        let ramified_prime = u64::from(algebra.ramified_prime());
        let mut candidates = Vec::new();
        let max_cd = integer_sqrt(target / ramified_prime.max(1));
        for c in 0..=max_cd {
            let c_sq = c.checked_mul(c)?;
            for d in 0..=max_cd {
                let d_sq = d.checked_mul(d)?;
                let cd_sq = c_sq.checked_add(d_sq)?;
                let weighted = ramified_prime.checked_mul(cd_sq)?;
                if weighted > target {
                    break;
                }
                let remainder = target - weighted;
                let max_a = integer_sqrt(remainder);
                for a in 0..=max_a {
                    let a_sq = a.checked_mul(a)?;
                    if a_sq > remainder {
                        break;
                    }
                    let b_sq = remainder - a_sq;
                    let b = integer_sqrt(b_sq);
                    if b.checked_mul(b)? != b_sq {
                        continue;
                    }
                    push_signed_candidates(&mut candidates, algebra, a, b, c, d);
                }
            }
        }
        if candidates.is_empty() {
            return None;
        }
        let primitive = candidates
            .iter()
            .copied()
            .filter(|candidate| is_primitive_generator(candidate))
            .collect::<Vec<_>>();
        let candidates = if primitive.is_empty() {
            candidates
        } else {
            primitive
        };
        select_candidate_from_seed(&candidates, seed)
    }
}

fn select_candidate_from_seed(
    candidates: &[QuaternionElement],
    seed: &[u8; 32],
) -> Option<QuaternionElement> {
    if candidates.is_empty() {
        return None;
    }
    let mut selector_bytes = [0u8; 8];
    selector_bytes.copy_from_slice(&seed[..8]);
    let index = (u64::from_le_bytes(selector_bytes) as usize) % candidates.len();
    candidates.get(index).copied()
}

fn push_signed_candidates(
    out: &mut Vec<QuaternionElement>,
    algebra: crate::crypto::isogeny::ideal::quaternion::QuaternionAlgebra,
    a: u64,
    b: u64,
    c: u64,
    d: u64,
) {
    const SIGNS: [i128; 2] = [1, -1];
    for sa in SIGNS {
        for sb in SIGNS {
            for sc in SIGNS {
                for sd in SIGNS {
                    let coeffs = [
                        sa * i128::from(a),
                        sb * i128::from(b),
                        sc * i128::from(c),
                        sd * i128::from(d),
                    ];
                    if coeffs.iter().all(|coeff| *coeff == 0) {
                        continue;
                    }
                    let candidate = QuaternionElement::from_coeffs(algebra, coeffs);
                    if out.iter().any(|existing| existing == &candidate) {
                        continue;
                    }
                    out.push(candidate);
                }
            }
        }
    }
}

fn integer_sqrt(value: u64) -> u64 {
    if value < 2 {
        return value;
    }
    let mut x0 = value;
    let mut x1 = (x0 + value / x0) / 2;
    while x1 < x0 {
        x0 = x1;
        x1 = (x0 + value / x0) / 2;
    }
    x0
}

fn is_primitive_generator(generator: &QuaternionElement) -> bool {
    let mut coeffs = generator.coeffs().into_iter();
    let Some(first) = coeffs.next() else {
        return false;
    };
    let Some(mut gcd) = first.unsigned_abs().try_to_u64() else {
        return false;
    };
    for coeff in coeffs {
        let Some(value) = coeff.unsigned_abs().try_to_u64() else {
            return false;
        };
        gcd = gcd_u64(gcd, value);
    }
    gcd == 1
}

fn gcd_u64(mut lhs: u64, mut rhs: u64) -> u64 {
    while rhs != 0 {
        let rem = lhs % rhs;
        lhs = rhs;
        rhs = rem;
    }
    lhs
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::{RandomIdealError, RandomIdealSampler};
    use crate::crypto::isogeny::arith::IsogenyInteger;
    use crate::crypto::isogeny::ideal::order::MaximalOrder;
    use crate::crypto::isogeny::ideal::quaternion::QuaternionAlgebra;

    #[test]
    fn sampler_rejects_zero_norm() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(5).unwrap());
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        assert_eq!(
            RandomIdealSampler::sample_given_norm(&order, 0, &mut rng),
            Err(RandomIdealError::InvalidNorm)
        );
    }

    #[test]
    fn sampler_is_deterministic_for_seed_and_target_norm() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(5).unwrap());
        let mut rng1 = ChaCha20Rng::from_seed([9u8; 32]);
        let mut rng2 = ChaCha20Rng::from_seed([9u8; 32]);
        let i1 = RandomIdealSampler::sample_given_norm(&order, 37, &mut rng1).unwrap();
        let i2 = RandomIdealSampler::sample_given_norm(&order, 37, &mut rng2).unwrap();
        assert_eq!(i1, i2);
        assert_eq!(i1.norm(), 37);
    }

    #[test]
    fn sampler_binds_output_to_target_norm() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(7).unwrap());
        let mut rng = ChaCha20Rng::from_seed([11u8; 32]);
        let i1 = RandomIdealSampler::sample_given_norm(&order, 17, &mut rng).unwrap();
        let i2 = RandomIdealSampler::sample_given_norm(&order, 19, &mut rng).unwrap();
        assert_ne!(i1.generator(), i2.generator());
        assert_eq!(i1.norm(), 17);
        assert_eq!(i2.norm(), 19);
    }

    #[test]
    fn sampler_prefers_exact_reduced_norm_for_small_targets() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(5).unwrap());
        let mut rng = ChaCha20Rng::from_seed([13u8; 32]);
        let ideal = RandomIdealSampler::sample_given_norm(&order, 37, &mut rng).unwrap();
        assert_eq!(ideal.norm(), 37);
        assert_eq!(
            ideal.generator().reduced_norm(),
            IsogenyInteger::from(37u64)
        );
    }

    #[test]
    fn sampler_exact_search_supports_small_odd_prime_powers() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(5).unwrap());
        let mut rng = ChaCha20Rng::from_seed([17u8; 32]);
        let ideal = RandomIdealSampler::sample_given_norm(&order, 9, &mut rng).unwrap();
        assert_eq!(ideal.norm(), 9);
        assert_eq!(ideal.generator().reduced_norm(), IsogenyInteger::from(9u64));
    }

    #[test]
    fn sampler_exact_search_prefers_primitive_generators() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(5).unwrap());
        let mut rng = ChaCha20Rng::from_seed([19u8; 32]);
        let ideal = RandomIdealSampler::sample_given_norm(&order, 9, &mut rng).unwrap();
        let coeffs = ideal.generator().coeffs();
        let gcd = coeffs
            .into_iter()
            .map(|coeff| coeff.unsigned_abs().try_to_u64().unwrap())
            .reduce(super::gcd_u64)
            .unwrap();
        assert_eq!(gcd, 1);
    }
}
