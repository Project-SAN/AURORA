//! Integer helpers for isogeny bookkeeping.
//!
//! These types are intentionally separate from finite-field arithmetic: they are
//! used for ideal norms, isogeny degrees, and other paper-sized integers that do
//! not fit in `u128` at the NIST parameter levels used by salt-PRISM.

mod wide_uint;

pub use wide_uint::{IsogenyInteger, QuaternionInteger, SignedWideInt, WideUint};
