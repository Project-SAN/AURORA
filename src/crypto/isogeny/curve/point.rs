//! Point representation shared by torsion and pairing code.

use crate::crypto::isogeny::field::{Fp2, FpModulus};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CurvePoint {
    pub x: Fp2,
    pub y: Fp2,
    pub infinity: bool,
}

impl CurvePoint {
    pub fn infinity(modulus: &FpModulus) -> Self {
        Self {
            x: Fp2::zero(modulus),
            y: Fp2::zero(modulus),
            infinity: true,
        }
    }

    pub fn affine(x: Fp2, y: Fp2) -> Self {
        Self {
            x,
            y,
            infinity: false,
        }
    }

    pub fn is_infinity(&self) -> bool {
        self.infinity
    }

    pub fn negate(&self) -> Self {
        if self.infinity {
            *self
        } else {
            Self {
                x: self.x,
                y: self.y.neg(),
                infinity: false,
            }
        }
    }
}
