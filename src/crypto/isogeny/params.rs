//! Base parameter sets for supersingular isogeny arithmetic.

use crate::crypto::isogeny::field::fp::FpModulus;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SupersingularParameters {
    /// Small odd cofactor `f` in primes of the form `p = f * 2^e - 1`.
    pub cofactor: u32,
    /// The available rational `2^e` torsion exponent.
    pub two_torsion_bits: usize,
    /// The fixed-width base field modulus `p`.
    pub modulus: FpModulus,
}

impl SupersingularParameters {
    pub const fn new(cofactor: u32, two_torsion_bits: usize) -> Self {
        Self {
            cofactor,
            two_torsion_bits,
            modulus: FpModulus::from_shifted_cofactor(cofactor, two_torsion_bits),
        }
    }
}

pub const NIST_LEVEL1_BASE: SupersingularParameters = SupersingularParameters::new(5, 248);
pub const NIST_LEVEL3_BASE: SupersingularParameters = SupersingularParameters::new(65, 376);
pub const NIST_LEVEL5_BASE: SupersingularParameters = SupersingularParameters::new(27, 500);
