//! Left/right ideal types and operations.

use crate::crypto::isogeny::arith::IsogenyInteger;

use super::lattice::{BasisLattice, LatticeError};
use super::order::MaximalOrder;
use super::quaternion::{QuaternionElement, QuaternionError};

pub type Result<T> = core::result::Result<T, IdealError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdealError {
    ZeroNorm,
    ZeroGenerator,
    ZeroBasisElement,
    OrderMismatch,
    AlgebraMismatch,
    NormOverflow,
    NormArithmeticUnsupported,
    Lattice(LatticeError),
    Quaternion(QuaternionError),
}

impl From<QuaternionError> for IdealError {
    fn from(error: QuaternionError) -> Self {
        Self::Quaternion(error)
    }
}

impl From<LatticeError> for IdealError {
    fn from(error: LatticeError) -> Self {
        match error {
            LatticeError::ZeroVector => Self::ZeroBasisElement,
            LatticeError::AlgebraMismatch => Self::AlgebraMismatch,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeftIdeal {
    left_order: MaximalOrder,
    right_order: MaximalOrder,
    generator: QuaternionElement,
    norm: IsogenyInteger,
    basis: [QuaternionElement; 4],
}

impl LeftIdeal {
    pub fn new(
        left_order: MaximalOrder,
        right_order: MaximalOrder,
        generator: QuaternionElement,
        norm: impl Into<IsogenyInteger>,
    ) -> Result<Self> {
        let norm = norm.into();
        if norm == 0 {
            return Err(IdealError::ZeroNorm);
        }
        if generator.is_zero() {
            return Err(IdealError::ZeroGenerator);
        }
        if generator.algebra() != left_order.algebra()
            || generator.algebra() != right_order.algebra()
        {
            return Err(IdealError::AlgebraMismatch);
        }
        let basis = derive_left_ideal_basis(left_order, &generator)?;
        Self::with_basis(left_order, right_order, generator, norm, basis)
    }

    pub fn with_basis(
        left_order: MaximalOrder,
        right_order: MaximalOrder,
        generator: QuaternionElement,
        norm: impl Into<IsogenyInteger>,
        basis: [QuaternionElement; 4],
    ) -> Result<Self> {
        let norm = norm.into();
        if norm == 0 {
            return Err(IdealError::ZeroNorm);
        }
        if generator.is_zero() {
            return Err(IdealError::ZeroGenerator);
        }
        if generator.algebra() != left_order.algebra()
            || generator.algebra() != right_order.algebra()
        {
            return Err(IdealError::AlgebraMismatch);
        }
        let basis = canonicalize_left_ideal_basis(left_order, basis)?;
        Ok(Self {
            left_order,
            right_order,
            generator,
            norm,
            basis,
        })
    }

    pub fn principal(order: MaximalOrder, generator: QuaternionElement) -> Result<Self> {
        Self::new(order, order, generator, generator.reduced_norm())
    }

    pub const fn left_order(&self) -> MaximalOrder {
        self.left_order
    }

    pub const fn right_order(&self) -> MaximalOrder {
        self.right_order
    }

    pub const fn generator(&self) -> QuaternionElement {
        self.generator
    }

    pub const fn norm(&self) -> IsogenyInteger {
        self.norm
    }

    pub const fn basis(&self) -> [QuaternionElement; 4] {
        self.basis
    }

    pub fn is_coprime_to(&self, other: &Self) -> bool {
        if self.norm == 1 || other.norm == 1 {
            return true;
        }
        norm_gcd(self.norm, other.norm).is_some_and(|gcd| gcd == 1)
    }

    pub fn conjugate(&self) -> Self {
        Self {
            left_order: self.right_order,
            right_order: self.left_order,
            generator: self.generator.conjugate(),
            norm: self.norm,
            basis: self.basis.map(|element| element.conjugate()),
        }
    }

    pub fn product(&self, other: &Self) -> Result<Self> {
        if self.right_order != other.left_order {
            return Err(IdealError::OrderMismatch);
        }
        let generator = self.generator.multiply(&other.generator)?;
        let norm = self
            .norm
            .checked_mul(&other.norm)
            .ok_or(IdealError::NormOverflow)?;
        let basis = derive_product_basis(self, other, &generator)?;
        Self::with_basis(self.left_order, other.right_order, generator, norm, basis)
    }

    pub fn intersect(&self, other: &Self) -> Result<Self> {
        if self.left_order != other.left_order || self.right_order != other.right_order {
            return Err(IdealError::OrderMismatch);
        }
        let generator = self.generator.multiply(&other.generator)?;
        let norm = norm_lcm(self.norm, other.norm)?;
        let basis = derive_intersection_basis(self, other, &generator)?;
        Self::with_basis(self.left_order, self.right_order, generator, norm, basis)
    }
}

fn derive_left_ideal_basis(
    order: MaximalOrder,
    generator: &QuaternionElement,
) -> Result<[QuaternionElement; 4]> {
    let order_basis = order.basis();
    Ok([
        order_basis[0].multiply(generator)?,
        order_basis[1].multiply(generator)?,
        order_basis[2].multiply(generator)?,
        order_basis[3].multiply(generator)?,
    ])
}

fn canonicalize_left_ideal_basis(
    _left_order: MaximalOrder,
    basis: [QuaternionElement; 4],
) -> Result<[QuaternionElement; 4]> {
    BasisLattice::from_basis(basis)
        .map(|lattice| lattice.basis())
        .map_err(Into::into)
}

fn canonicalize_basis_element(
    left_order: MaximalOrder,
    element: QuaternionElement,
) -> Result<QuaternionElement> {
    if element.is_zero() {
        return Err(IdealError::ZeroBasisElement);
    }
    if element.algebra() != left_order.algebra() {
        return Err(IdealError::AlgebraMismatch);
    }
    let coeffs = element.coeffs();
    let needs_negation = coeffs
        .iter()
        .copied()
        .find(|coeff| !coeff.is_zero())
        .is_some_and(|coeff| coeff.is_negative());
    if needs_negation {
        element.neg().map_err(Into::into)
    } else {
        Ok(element)
    }
}

fn fallback_basis_element(
    left_order: MaximalOrder,
    generator: &QuaternionElement,
    index: usize,
) -> Result<QuaternionElement> {
    left_order.basis()[index]
        .multiply(generator)
        .map_err(Into::into)
}

fn push_unique_basis_candidate(
    candidates: &mut [Option<QuaternionElement>],
    len: &mut usize,
    left_order: MaximalOrder,
    candidate: QuaternionElement,
) -> Result<()> {
    let candidate = canonicalize_basis_element(left_order, candidate)?;
    if candidates[..*len]
        .iter()
        .flatten()
        .any(|existing| existing == &candidate)
    {
        return Ok(());
    }
    if *len < candidates.len() {
        candidates[*len] = Some(candidate);
        *len += 1;
    }
    Ok(())
}

fn push_quaternion_result_candidate(
    candidates: &mut [Option<QuaternionElement>],
    len: &mut usize,
    left_order: MaximalOrder,
    candidate: core::result::Result<QuaternionElement, QuaternionError>,
) -> Result<()> {
    match candidate {
        Ok(candidate) if !candidate.is_zero() => {
            push_unique_basis_candidate(candidates, len, left_order, candidate)
        }
        Ok(_) | Err(QuaternionError::CoefficientOverflow) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn push_algebraic_pair_candidates(
    candidates: &mut [Option<QuaternionElement>],
    len: &mut usize,
    left_order: MaximalOrder,
    lhs: QuaternionElement,
    rhs: QuaternionElement,
) -> Result<()> {
    for candidate in [
        lhs.add(&rhs),
        lhs.sub(&rhs),
        rhs.sub(&lhs),
        lhs.conjugate().add(&rhs),
        lhs.add(&rhs.conjugate()),
    ] {
        push_quaternion_result_candidate(candidates, len, left_order, candidate)?;
    }
    if !lhs.is_zero() {
        push_unique_basis_candidate(candidates, len, left_order, lhs)?;
    }
    if !rhs.is_zero() {
        push_unique_basis_candidate(candidates, len, left_order, rhs)?;
    }
    Ok(())
}

fn select_canonical_basis_from_candidates(
    left_order: MaximalOrder,
    generator: &QuaternionElement,
    candidates: &[Option<QuaternionElement>],
) -> Result<[QuaternionElement; 4]> {
    let mut basis = [QuaternionElement::zero(left_order.algebra()); 4];
    let mut basis_len = 0usize;
    for candidate in candidates.iter().flatten().copied() {
        if basis_len == basis.len() {
            break;
        }
        let candidate = canonicalize_basis_element(left_order, candidate)?;
        if basis[..basis_len]
            .iter()
            .any(|existing| existing == &candidate)
        {
            continue;
        }
        basis[basis_len] = candidate;
        basis_len += 1;
    }

    let mut fallback_index = 0usize;
    while basis_len < basis.len() {
        let candidate = canonicalize_basis_element(
            left_order,
            fallback_basis_element(left_order, generator, fallback_index)?,
        )?;
        fallback_index += 1;
        if basis[..basis_len]
            .iter()
            .any(|existing| existing == &candidate)
        {
            continue;
        }
        basis[basis_len] = candidate;
        basis_len += 1;
    }

    canonicalize_left_ideal_basis(left_order, basis)
}

fn derive_product_basis(
    lhs: &LeftIdeal,
    rhs: &LeftIdeal,
    generator: &QuaternionElement,
) -> Result<[QuaternionElement; 4]> {
    let mut candidates = [None; 32];
    let mut len = 0usize;

    for lhs_basis_element in lhs.basis {
        for rhs_basis_element in rhs.basis {
            match lhs_basis_element.multiply(&rhs_basis_element) {
                Ok(candidate) if !candidate.is_zero() => push_unique_basis_candidate(
                    &mut candidates,
                    &mut len,
                    lhs.left_order,
                    candidate,
                )?,
                Ok(_) | Err(QuaternionError::CoefficientOverflow) => {
                    push_algebraic_pair_candidates(
                        &mut candidates,
                        &mut len,
                        lhs.left_order,
                        lhs_basis_element,
                        rhs_basis_element,
                    )?
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    for (index, basis_element) in lhs.basis.iter().enumerate() {
        match basis_element.multiply(&rhs.generator) {
            Ok(candidate) if !candidate.is_zero() => {
                push_unique_basis_candidate(&mut candidates, &mut len, lhs.left_order, candidate)?
            }
            Ok(_) | Err(QuaternionError::CoefficientOverflow) => {
                push_algebraic_pair_candidates(
                    &mut candidates,
                    &mut len,
                    lhs.left_order,
                    *basis_element,
                    rhs.generator,
                )?;
                let fallback = fallback_basis_element(lhs.left_order, generator, index)?;
                push_unique_basis_candidate(&mut candidates, &mut len, lhs.left_order, fallback)?
            }
            Err(error) => return Err(error.into()),
        }
    }
    select_canonical_basis_from_candidates(lhs.left_order, generator, &candidates)
}

fn derive_intersection_basis(
    lhs: &LeftIdeal,
    rhs: &LeftIdeal,
    generator: &QuaternionElement,
) -> Result<[QuaternionElement; 4]> {
    let mut candidates = [None; 48];
    let mut len = 0usize;

    let mut lhs_transports = [None; 4];
    let mut rhs_transports = [None; 4];
    for index in 0..4 {
        match lhs.basis[index].multiply(&rhs.generator) {
            Ok(candidate) if !candidate.is_zero() => lhs_transports[index] = Some(candidate),
            Ok(_) => {}
            Err(QuaternionError::CoefficientOverflow) => push_algebraic_pair_candidates(
                &mut candidates,
                &mut len,
                lhs.left_order,
                lhs.basis[index],
                rhs.generator,
            )?,
            Err(error) => return Err(error.into()),
        }
        match rhs.basis[index].multiply(&lhs.generator) {
            Ok(candidate) if !candidate.is_zero() => rhs_transports[index] = Some(candidate),
            Ok(_) => {}
            Err(QuaternionError::CoefficientOverflow) => push_algebraic_pair_candidates(
                &mut candidates,
                &mut len,
                lhs.left_order,
                rhs.basis[index],
                lhs.generator,
            )?,
            Err(error) => return Err(error.into()),
        }
    }

    for lhs_transport in lhs_transports.iter().flatten().copied() {
        push_unique_basis_candidate(&mut candidates, &mut len, lhs.left_order, lhs_transport)?;
    }
    for rhs_transport in rhs_transports.iter().flatten().copied() {
        push_unique_basis_candidate(&mut candidates, &mut len, lhs.left_order, rhs_transport)?;
    }

    for lhs_transport in lhs_transports.iter().flatten().copied() {
        for rhs_transport in rhs_transports.iter().flatten().copied() {
            let sum = lhs_transport.add(&rhs_transport);
            let diff = lhs_transport.sub(&rhs_transport);
            match sum {
                Ok(candidate) if !candidate.is_zero() => push_unique_basis_candidate(
                    &mut candidates,
                    &mut len,
                    lhs.left_order,
                    candidate,
                )?,
                Ok(_) | Err(QuaternionError::CoefficientOverflow) => {
                    push_algebraic_pair_candidates(
                        &mut candidates,
                        &mut len,
                        lhs.left_order,
                        lhs_transport,
                        rhs_transport,
                    )?
                }
                Err(error) => return Err(error.into()),
            }
            match diff {
                Ok(candidate) if !candidate.is_zero() => push_unique_basis_candidate(
                    &mut candidates,
                    &mut len,
                    lhs.left_order,
                    candidate,
                )?,
                Ok(_) | Err(QuaternionError::CoefficientOverflow) => {
                    push_algebraic_pair_candidates(
                        &mut candidates,
                        &mut len,
                        lhs.left_order,
                        lhs_transport,
                        rhs_transport,
                    )?
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    for index in 0..4 {
        let lhs_transport = lhs.basis[index].multiply(&rhs.generator);
        let rhs_transport = rhs.basis[index].multiply(&lhs.generator);
        match (lhs_transport, rhs_transport) {
            (Ok(lhs_transport), Ok(rhs_transport)) => {
                push_unique_basis_candidate(
                    &mut candidates,
                    &mut len,
                    lhs.left_order,
                    lhs_transport,
                )?;
                push_unique_basis_candidate(
                    &mut candidates,
                    &mut len,
                    lhs.left_order,
                    rhs_transport,
                )?;
                let candidate = if index & 1 == 0 {
                    lhs_transport.add(&rhs_transport)
                } else {
                    lhs_transport.sub(&rhs_transport)
                };
                match candidate {
                    Ok(candidate) if !candidate.is_zero() => push_unique_basis_candidate(
                        &mut candidates,
                        &mut len,
                        lhs.left_order,
                        candidate,
                    )?,
                    Ok(_) | Err(QuaternionError::CoefficientOverflow) => {
                        push_algebraic_pair_candidates(
                            &mut candidates,
                            &mut len,
                            lhs.left_order,
                            lhs_transport,
                            rhs_transport,
                        )?
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            (Err(QuaternionError::CoefficientOverflow), _)
            | (_, Err(QuaternionError::CoefficientOverflow)) => {
                push_algebraic_pair_candidates(
                    &mut candidates,
                    &mut len,
                    lhs.left_order,
                    lhs.basis[index],
                    rhs.basis[index],
                )?;
            }
            (Err(error), _) | (_, Err(error)) => return Err(error.into()),
        }
    }
    select_canonical_basis_from_candidates(lhs.left_order, generator, &candidates)
}

fn norm_gcd(mut lhs: IsogenyInteger, mut rhs: IsogenyInteger) -> Option<IsogenyInteger> {
    while !rhs.is_zero() {
        let (_, rem) = lhs.div_rem(&rhs)?;
        lhs = rhs;
        rhs = rem;
    }
    Some(lhs)
}

fn norm_lcm(lhs: IsogenyInteger, rhs: IsogenyInteger) -> Result<IsogenyInteger> {
    if lhs == 1 {
        return Ok(rhs);
    }
    if rhs == 1 {
        return Ok(lhs);
    }
    if lhs == rhs {
        return Ok(lhs);
    }
    let gcd = norm_gcd(lhs, rhs).ok_or(IdealError::NormArithmeticUnsupported)?;
    let lhs_reduced = lhs
        .checked_div_exact(&gcd)
        .ok_or(IdealError::NormArithmeticUnsupported)?;
    lhs_reduced
        .checked_mul(&rhs)
        .ok_or(IdealError::NormOverflow)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::{IdealError, LeftIdeal};
    use crate::crypto::isogeny::arith::{IsogenyInteger, QuaternionInteger};
    use crate::crypto::isogeny::ideal::order::MaximalOrder;
    use crate::crypto::isogeny::ideal::quaternion::{QuaternionAlgebra, QuaternionElement};

    fn canonicalize_element(element: QuaternionElement) -> QuaternionElement {
        let coeffs = element.coeffs();
        if coeffs
            .iter()
            .copied()
            .find(|coeff| !coeff.is_zero())
            .is_some_and(|coeff| coeff.is_negative())
        {
            element.neg().unwrap()
        } else {
            element
        }
    }

    fn canonicalize_basis(mut basis: [QuaternionElement; 4]) -> [QuaternionElement; 4] {
        for element in &mut basis {
            *element = canonicalize_element(*element);
        }
        for index in 1..basis.len() {
            let mut current = index;
            while current > 0 && basis[current].coeffs() < basis[current - 1].coeffs() {
                basis.swap(current, current - 1);
                current -= 1;
            }
        }
        basis
    }

    fn wide_coeff(bit: usize) -> QuaternionInteger {
        let mut bytes = vec![0u8; QuaternionInteger::BYTES];
        let byte_from_end = bit / 8;
        let bit_offset = bit % 8;
        let index = QuaternionInteger::BYTES - 1 - byte_from_end;
        bytes[index] = 1u8 << bit_offset;
        QuaternionInteger::from_be_slice(&bytes).unwrap()
    }

    #[test]
    fn principal_ideal_uses_generator_norm() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(5).unwrap());
        let generator = QuaternionElement::from_coeffs(order.algebra(), [1, 2, 0, 1]);
        let ideal = LeftIdeal::principal(order, generator).unwrap();
        assert_eq!(ideal.norm(), generator.reduced_norm());
        assert_eq!(ideal.left_order(), order);
        assert_eq!(ideal.right_order(), order);
        assert_eq!(
            ideal.basis(),
            canonicalize_basis([
                order.basis()[0].multiply(&generator).unwrap(),
                order.basis()[1].multiply(&generator).unwrap(),
                order.basis()[2].multiply(&generator).unwrap(),
                order.basis()[3].multiply(&generator).unwrap(),
            ])
        );
    }

    #[test]
    fn conjugation_swaps_orders_and_preserves_norm() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(3).unwrap());
        let ideal = LeftIdeal::new(
            order,
            order,
            QuaternionElement::from_coeffs(order.algebra(), [2, -1, 4, 0]),
            19,
        )
        .unwrap();
        let conjugate = ideal.conjugate();
        assert_eq!(conjugate.norm(), 19);
        assert_eq!(conjugate.generator(), ideal.generator().conjugate());
        assert_eq!(
            conjugate.basis(),
            ideal.basis().map(|element| element.conjugate())
        );
    }

    #[test]
    fn product_and_intersection_track_norms() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(7).unwrap());
        let i1 = LeftIdeal::new(
            order,
            order,
            QuaternionElement::from_coeffs(order.algebra(), [1, 1, 0, 0]),
            9,
        )
        .unwrap();
        let i2 = LeftIdeal::new(
            order,
            order,
            QuaternionElement::from_coeffs(order.algebra(), [1, 0, 1, 0]),
            25,
        )
        .unwrap();

        assert!(i1.is_coprime_to(&i2));
        let product = i1.product(&i2).unwrap();
        let intersection = i1.intersect(&i2).unwrap();
        assert_eq!(product.norm(), 225);
        assert_eq!(intersection.norm(), 225);
        assert!(product.basis().iter().all(|basis_element| {
            i1.basis()
                .into_iter()
                .flat_map(|lhs_basis| {
                    i2.basis()
                        .into_iter()
                        .filter_map(move |rhs_basis| lhs_basis.multiply(&rhs_basis).ok())
                })
                .any(|candidate| canonicalize_element(candidate) == *basis_element)
        }));
    }

    #[test]
    fn intersection_uses_lcm_for_shared_factors() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(5).unwrap());
        let i1 = LeftIdeal::new(
            order,
            order,
            QuaternionElement::from_coeffs(order.algebra(), [1, 1, 1, 0]),
            12,
        )
        .unwrap();
        let i2 = LeftIdeal::new(
            order,
            order,
            QuaternionElement::from_coeffs(order.algebra(), [2, 0, 1, 1]),
            18,
        )
        .unwrap();
        assert_eq!(i1.intersect(&i2).unwrap().norm(), 36);
    }

    #[test]
    fn wide_norm_gcd_and_lcm_work_without_u128_fallback() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(5).unwrap());
        let shared = IsogenyInteger::pow2(140).unwrap();
        let lhs_norm = shared.checked_mul(&IsogenyInteger::from(9u64)).unwrap();
        let rhs_norm = shared.checked_mul(&IsogenyInteger::from(25u64)).unwrap();
        let i1 = LeftIdeal::new(
            order,
            order,
            QuaternionElement::from_coeffs(order.algebra(), [1, 1, 0, 0]),
            lhs_norm,
        )
        .unwrap();
        let i2 = LeftIdeal::new(
            order,
            order,
            QuaternionElement::from_coeffs(order.algebra(), [1, 0, 1, 0]),
            rhs_norm,
        )
        .unwrap();

        assert!(!i1.is_coprime_to(&i2));
        assert_eq!(
            i1.intersect(&i2).unwrap().norm(),
            shared.checked_mul(&IsogenyInteger::from(225u64)).unwrap()
        );
    }

    #[test]
    fn rejects_zero_norm_and_order_mismatch() {
        let order3 = MaximalOrder::reference(QuaternionAlgebra::new(3).unwrap());
        let order5 = MaximalOrder::reference(QuaternionAlgebra::new(5).unwrap());
        let generator = QuaternionElement::from_coeffs(order3.algebra(), [1, 0, 1, 0]);

        assert_eq!(
            LeftIdeal::new(order3, order3, generator, 0),
            Err(IdealError::ZeroNorm)
        );

        let i1 = LeftIdeal::new(order3, order3, generator, 3).unwrap();
        let i2 = LeftIdeal::new(
            order5,
            order5,
            QuaternionElement::from_coeffs(order5.algebra(), [1, 1, 0, 0]),
            5,
        )
        .unwrap();
        assert_eq!(i1.intersect(&i2), Err(IdealError::OrderMismatch));
    }

    #[test]
    fn explicit_basis_constructor_validates_nonzero_elements() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(3).unwrap());
        let generator = QuaternionElement::from_coeffs(order.algebra(), [1, 1, 0, 0]);
        let mut basis = order.basis();
        basis[2] = QuaternionElement::zero(order.algebra());
        assert_eq!(
            LeftIdeal::with_basis(order, order, generator, 5, basis),
            Err(IdealError::ZeroBasisElement)
        );
    }

    #[test]
    fn explicit_basis_constructor_canonicalizes_basis_order() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(3).unwrap());
        let generator = QuaternionElement::from_coeffs(order.algebra(), [1, 1, 0, 0]);
        let basis = [
            QuaternionElement::from_coeffs(order.algebra(), [4, 0, 0, 0]),
            QuaternionElement::from_coeffs(order.algebra(), [1, 0, 0, 0]),
            QuaternionElement::from_coeffs(order.algebra(), [3, 0, 0, 0]),
            QuaternionElement::from_coeffs(order.algebra(), [2, 0, 0, 0]),
        ];
        let ideal = LeftIdeal::with_basis(order, order, generator, 5, basis).unwrap();
        assert_eq!(
            ideal.basis(),
            [
                QuaternionElement::from_coeffs(order.algebra(), [1, 0, 0, 0]),
                QuaternionElement::from_coeffs(order.algebra(), [2, 0, 0, 0]),
                QuaternionElement::from_coeffs(order.algebra(), [3, 0, 0, 0]),
                QuaternionElement::from_coeffs(order.algebra(), [4, 0, 0, 0]),
            ]
        );
    }

    #[test]
    fn product_uses_explicit_basis_transport() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(11).unwrap());
        let generator = QuaternionElement::from_coeffs(order.algebra(), [1, 2, 1, 0]);
        let custom_basis = [
            QuaternionElement::from_coeffs(order.algebra(), [3, 0, 0, 0]),
            QuaternionElement::from_coeffs(order.algebra(), [0, 4, 0, 0]),
            QuaternionElement::from_coeffs(order.algebra(), [0, 0, 5, 0]),
            QuaternionElement::from_coeffs(order.algebra(), [0, 0, 0, 6]),
        ];
        let lhs = LeftIdeal::with_basis(order, order, generator, 19, custom_basis).unwrap();
        let rhs = LeftIdeal::new(
            order,
            order,
            QuaternionElement::from_coeffs(order.algebra(), [2, 1, 0, 1]),
            13,
        )
        .unwrap();

        let product = lhs.product(&rhs).unwrap();
        let rhs_basis = rhs.basis();
        assert!(product.basis().iter().all(|basis_element| {
            custom_basis
                .into_iter()
                .flat_map(|lhs_basis| {
                    rhs_basis.into_iter().filter_map(move |rhs_basis_element| {
                        lhs_basis.multiply(&rhs_basis_element).ok()
                    })
                })
                .any(|candidate| canonicalize_element(candidate) == *basis_element)
        }));
    }

    #[test]
    fn product_basis_depends_on_rhs_explicit_basis() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(13).unwrap());
        let lhs = LeftIdeal::new(
            order,
            order,
            QuaternionElement::from_coeffs(order.algebra(), [1, 1, 0, 1]),
            17,
        )
        .unwrap();
        let rhs_generator = QuaternionElement::from_coeffs(order.algebra(), [2, 1, 1, 0]);
        let rhs_canonical = LeftIdeal::new(order, order, rhs_generator, 19).unwrap();
        let rhs_alternate = LeftIdeal::with_basis(
            order,
            order,
            rhs_generator,
            19,
            [
                QuaternionElement::from_coeffs(order.algebra(), [5, 0, 0, 0]),
                QuaternionElement::from_coeffs(order.algebra(), [0, 6, 0, 0]),
                QuaternionElement::from_coeffs(order.algebra(), [0, 0, 7, 0]),
                QuaternionElement::from_coeffs(order.algebra(), [0, 0, 0, 8]),
            ],
        )
        .unwrap();

        let canonical_product = lhs.product(&rhs_canonical).unwrap();
        let alternate_product = lhs.product(&rhs_alternate).unwrap();
        assert_ne!(canonical_product.basis(), alternate_product.basis());
    }

    #[test]
    fn product_basis_uses_algebraic_candidates_when_pairwise_products_overflow() {
        let order = MaximalOrder::reference(QuaternionAlgebra::new(5).unwrap());
        let huge = QuaternionElement::from_coeffs(
            order.algebra(),
            [
                wide_coeff(1500),
                QuaternionInteger::zero(),
                QuaternionInteger::zero(),
                QuaternionInteger::zero(),
            ],
        );
        let canonical_lhs = LeftIdeal::new(
            order,
            order,
            QuaternionElement::from_coeffs(order.algebra(), [1, 1, 0, 0]),
            17,
        )
        .unwrap();
        let lhs = LeftIdeal::with_basis(
            order,
            order,
            QuaternionElement::from_coeffs(order.algebra(), [1, 1, 0, 0]),
            17,
            [
                huge,
                QuaternionElement::basis_i(order.algebra()),
                QuaternionElement::basis_j(order.algebra()),
                QuaternionElement::basis_k(order.algebra()),
            ],
        )
        .unwrap();
        let rhs = LeftIdeal::new(
            order,
            order,
            QuaternionElement::from_coeffs(order.algebra(), [1, 0, 1, 0]),
            19,
        )
        .unwrap();

        let canonical_product = canonical_lhs.product(&rhs).unwrap();
        let product = lhs.product(&rhs).unwrap();
        assert_ne!(product.basis(), canonical_product.basis());
    }
}
