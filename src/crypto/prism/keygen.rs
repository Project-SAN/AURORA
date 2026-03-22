//! Key generation orchestration for PRISM-family schemes.

use super::backend::{PrismBackend, PrismError, Result};

pub fn keygen_with_backend<B: PrismBackend>(
    backend: &mut B,
) -> Result<(B::VerifyingKey, B::SigningKey), B::Error> {
    backend.keygen().map_err(PrismError::Backend)
}
