#![allow(dead_code)]

use ark_ec::pairing::Pairing;

/// PLONKで利用する双線形写像エンジンを抽象化するための型。
pub trait Engine: Pairing + 'static {}

impl<T> Engine for T where T: Pairing + 'static {}

/// BLS12-381バックエンドを有効化している場合のデフォルトエンジン。
#[cfg(feature = "curve-bls12-381")]
pub type DefaultEngine = ark_bls12_381::Bls12_381;

/// BLS12-381のスカラー場を再エクスポート。
#[cfg(feature = "curve-bls12-381")]
pub type ScalarField = <ark_bls12_381::Bls12_381 as Pairing>::ScalarField;

/// BLS12-381のG1/G2射影座標。
#[cfg(feature = "curve-bls12-381")]
pub type G1Affine = <ark_bls12_381::Bls12_381 as Pairing>::G1Affine;
#[cfg(feature = "curve-bls12-381")]
pub type G2Affine = <ark_bls12_381::Bls12_381 as Pairing>::G2Affine;

/// G1/G2の射影形式。
#[cfg(feature = "curve-bls12-381")]
pub type G1Projective = <ark_bls12_381::Bls12_381 as Pairing>::G1;
#[cfg(feature = "curve-bls12-381")]
pub type G2Projective = <ark_bls12_381::Bls12_381 as Pairing>::G2;
