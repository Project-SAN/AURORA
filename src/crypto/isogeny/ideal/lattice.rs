//! Explicit quaternion-lattice basis helpers.

use crate::crypto::isogeny::arith::QuaternionInteger;

use super::quaternion::{QuaternionAlgebra, QuaternionElement};

pub type Result<T> = core::result::Result<T, LatticeError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LatticeError {
    ZeroVector,
    AlgebraMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BasisLattice {
    algebra: QuaternionAlgebra,
    rows: [[QuaternionInteger; 4]; 4],
}

impl BasisLattice {
    pub fn from_basis(basis: [QuaternionElement; 4]) -> Result<Self> {
        let algebra = basis[0].algebra();
        let mut rows = [[QuaternionInteger::zero(); 4]; 4];
        for (index, element) in basis.into_iter().enumerate() {
            if element.algebra() != algebra {
                return Err(LatticeError::AlgebraMismatch);
            }
            rows[index] = canonicalize_row(element.coeffs())?;
        }
        sort_rows(&mut rows);
        Ok(Self { algebra, rows })
    }

    pub const fn algebra(&self) -> QuaternionAlgebra {
        self.algebra
    }

    pub const fn rows(&self) -> [[QuaternionInteger; 4]; 4] {
        self.rows
    }

    pub fn basis(&self) -> [QuaternionElement; 4] {
        self.rows
            .map(|row| QuaternionElement::from_coeffs(self.algebra, row))
    }

    pub fn row_commitment_payload(&self) -> [[u8; QuaternionInteger::BYTES]; 16] {
        let mut out = [[0u8; QuaternionInteger::BYTES]; 16];
        for (row_index, row) in self.rows.iter().enumerate() {
            for (col_index, coeff) in row.iter().enumerate() {
                out[row_index * 4 + col_index] = coeff.to_be_bytes_fixed();
            }
        }
        out
    }
}

fn canonicalize_row(mut row: [QuaternionInteger; 4]) -> Result<[QuaternionInteger; 4]> {
    if row.iter().all(QuaternionInteger::is_zero) {
        return Err(LatticeError::ZeroVector);
    }
    let needs_negation = row
        .iter()
        .copied()
        .find(|coeff| !coeff.is_zero())
        .is_some_and(|coeff| coeff.is_negative());
    if needs_negation {
        for coeff in &mut row {
            *coeff = coeff
                .checked_neg()
                .expect("canonical lattice row negation fits in QuaternionInteger");
        }
    }
    Ok(row)
}

fn sort_rows(rows: &mut [[QuaternionInteger; 4]; 4]) {
    for index in 1..rows.len() {
        let mut current = index;
        while current > 0 && rows[current] < rows[current - 1] {
            rows.swap(current, current - 1);
            current -= 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BasisLattice, LatticeError};
    use crate::crypto::isogeny::arith::QuaternionInteger;
    use crate::crypto::isogeny::ideal::quaternion::{QuaternionAlgebra, QuaternionElement};

    #[test]
    fn lattice_canonicalizes_sign_and_order() {
        let algebra = QuaternionAlgebra::new(5).unwrap();
        let lattice = BasisLattice::from_basis([
            QuaternionElement::from_coeffs(algebra, [-3, 0, 0, 0]),
            QuaternionElement::from_coeffs(algebra, [0, -2, 0, 0]),
            QuaternionElement::from_coeffs(algebra, [0, 0, 4, 0]),
            QuaternionElement::from_coeffs(algebra, [0, 0, 0, -1]),
        ])
        .unwrap();
        let basis = lattice.basis();
        assert_eq!(
            basis[0].coeffs(),
            [
                QuaternionInteger::from(0i32),
                QuaternionInteger::from(0i32),
                QuaternionInteger::from(0i32),
                QuaternionInteger::from(1i32),
            ]
        );
        assert_eq!(
            basis[1].coeffs(),
            [
                QuaternionInteger::from(0i32),
                QuaternionInteger::from(0i32),
                QuaternionInteger::from(4i32),
                QuaternionInteger::from(0i32),
            ]
        );
        assert_eq!(
            basis[2].coeffs(),
            [
                QuaternionInteger::from(0i32),
                QuaternionInteger::from(2i32),
                QuaternionInteger::from(0i32),
                QuaternionInteger::from(0i32),
            ]
        );
        assert_eq!(
            basis[3].coeffs(),
            [
                QuaternionInteger::from(3i32),
                QuaternionInteger::from(0i32),
                QuaternionInteger::from(0i32),
                QuaternionInteger::from(0i32),
            ]
        );
    }

    #[test]
    fn lattice_rejects_zero_vector() {
        let algebra = QuaternionAlgebra::new(5).unwrap();
        assert_eq!(
            BasisLattice::from_basis([
                QuaternionElement::zero(algebra),
                QuaternionElement::basis_i(algebra),
                QuaternionElement::basis_j(algebra),
                QuaternionElement::basis_k(algebra),
            ]),
            Err(LatticeError::ZeroVector)
        );
    }
}
