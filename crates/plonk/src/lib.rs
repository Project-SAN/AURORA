#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod curve;
#[cfg(feature = "alloc")]
pub mod srs;
#[cfg(feature = "alloc")]
pub mod kzg;
#[cfg(feature = "alloc")]
pub mod poly;
#[cfg(feature = "alloc")]
pub mod permutation;
#[cfg(feature = "alloc")]
pub mod quotient;
#[cfg(feature = "alloc")]
pub mod prover;

/// コアとなる算術・FFT・証明構成を段階的に実装する際の共通公開APIをまとめる予定のモジュール。
pub mod prelude {
    pub use subtle::ConstantTimeEq;
}

/// ライブラリが`no_std`環境でも正しくリンクされるかを確認するヘルパ。
pub fn is_no_std_ready() -> bool {
    cfg!(feature = "alloc")
}
