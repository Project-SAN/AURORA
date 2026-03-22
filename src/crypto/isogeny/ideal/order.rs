//! Order types in the supersingular quaternion algebra.

use super::quaternion::{QuaternionAlgebra, QuaternionElement};

pub type Result<T> = core::result::Result<T, OrderError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrderError {
    EmptyBasis,
    AlgebraMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaximalOrder {
    algebra: QuaternionAlgebra,
    basis: [QuaternionElement; 4],
}

impl MaximalOrder {
    pub fn new(basis: [QuaternionElement; 4]) -> Result<Self> {
        let algebra = basis[0].algebra();
        if basis.iter().any(|element| element.algebra() != algebra) {
            return Err(OrderError::AlgebraMismatch);
        }
        Ok(Self { algebra, basis })
    }

    pub fn reference(algebra: QuaternionAlgebra) -> Self {
        Self {
            algebra,
            basis: [
                QuaternionElement::one(algebra),
                QuaternionElement::basis_i(algebra),
                QuaternionElement::basis_j(algebra),
                QuaternionElement::basis_k(algebra),
            ],
        }
    }

    pub const fn algebra(&self) -> QuaternionAlgebra {
        self.algebra
    }

    pub const fn basis(&self) -> [QuaternionElement; 4] {
        self.basis
    }

    pub fn one(&self) -> QuaternionElement {
        self.basis[0]
    }

    pub fn contains(&self, element: &QuaternionElement) -> bool {
        element.algebra() == self.algebra
    }
}

impl Default for MaximalOrder {
    fn default() -> Self {
        Self::reference(QuaternionAlgebra::default())
    }
}

#[cfg(test)]
mod tests {
    use super::{MaximalOrder, OrderError};
    use crate::crypto::isogeny::ideal::quaternion::{QuaternionAlgebra, QuaternionElement};

    #[test]
    fn reference_order_uses_standard_basis() {
        let algebra = QuaternionAlgebra::new(5).unwrap();
        let order = MaximalOrder::reference(algebra);
        assert_eq!(order.basis()[0], QuaternionElement::one(algebra));
        assert_eq!(order.basis()[1], QuaternionElement::basis_i(algebra));
        assert!(order.contains(&QuaternionElement::from_coeffs(algebra, [2, 3, 4, 5])));
    }

    #[test]
    fn constructing_order_requires_common_algebra() {
        let basis = [
            QuaternionElement::one(QuaternionAlgebra::new(3).unwrap()),
            QuaternionElement::basis_i(QuaternionAlgebra::new(3).unwrap()),
            QuaternionElement::basis_j(QuaternionAlgebra::new(3).unwrap()),
            QuaternionElement::basis_k(QuaternionAlgebra::new(5).unwrap()),
        ];
        assert_eq!(MaximalOrder::new(basis), Err(OrderError::AlgebraMismatch));
    }
}
