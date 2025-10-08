#![cfg(feature = "alloc")]
#![allow(dead_code)]

use core::{fmt, ops::RangeInclusive};

use alloc::{sync::Arc, vec::Vec};

use ark_ec::{pairing::Pairing, AffineRepr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use ark_std::io::{Cursor, Read};

const FORMAT_MAGIC: &[u8; 4] = b"KZGS";
const FORMAT_VERSION: u8 = 1;

/// 外部提供のPowers-of-Tau SRSを保持する構造体。
#[derive(Clone, Debug)]
pub struct KzgSrs<E: Pairing> {
    g1_powers: Vec<E::G1Affine>,
    g2_powers: Vec<E::G2Affine>,
}

impl<E: Pairing> KzgSrs<E> {
    /// SRSの基本形を構築する。最低限の長さチェックを行う。
    pub fn new(g1_powers: Vec<E::G1Affine>, g2_powers: Vec<E::G2Affine>) -> Result<Self, SrsError> {
        if g1_powers.len() < 2 || g2_powers.len() < 2 {
            return Err(SrsError::InvalidLength);
        }
        Ok(Self {
            g1_powers,
            g2_powers,
        })
    }

    /// 証明に利用できる最大次数（g1側のベース多項式本数 - 1）を返す。
    pub fn max_degree(&self) -> usize {
        self.g1_powers.len().saturating_sub(1)
    }

    /// G1側の累乗列を参照する。
    pub fn g1_powers(&self) -> &[E::G1Affine] {
        &self.g1_powers
    }

    /// G2側の累乗列を参照する。
    pub fn g2_powers(&self) -> &[E::G2Affine] {
        &self.g2_powers
    }

    /// SRSがPowers-of-Tauとして整合しているかを基本的に検査する。
    pub fn validate(&self) -> Result<(), SrsError>
    where
        E::G1Affine: AffineRepr,
        E::G2Affine: AffineRepr,
    {
        let g1_gen = E::G1Affine::generator();
        let g2_gen = E::G2Affine::generator();

        if self.g1_powers.first().copied() != Some(g1_gen) {
            return Err(SrsError::UnexpectedGenerator);
        }
        if self.g2_powers.first().copied() != Some(g2_gen) {
            return Err(SrsError::UnexpectedGenerator);
        }

        if self.g2_powers.len() < 2 {
            return Err(SrsError::InvalidLength);
        }

        // e(g^{tau^{i+1}}, h) == e(g^{tau^{i}}, h^{tau}) を確認
        for i in 0..(self.g1_powers.len() - 1) {
            let left = E::pairing(self.g1_powers[i + 1], self.g2_powers[0]);
            let right = E::pairing(self.g1_powers[i], self.g2_powers[1]);
            if left != right {
                return Err(SrsError::InconsistentPowers { index: i + 1 });
            }
        }

        Ok(())
    }

    /// 指定次数までをサポートするProver鍵を取得する。
    pub fn prover_key(&self, degree: usize) -> Result<ProverKey<'_, E>, SrsError> {
        if degree > self.max_degree() {
            return Err(SrsError::UnsupportedDegree { requested: degree, range: 0..=self.max_degree() });
        }
        Ok(ProverKey {
            g1_powers: &self.g1_powers[..=degree],
            g2_powers: &self.g2_powers,
        })
    }

    /// 所定次数で利用できるコミットメント鍵を返す。内部状態とは独立した所有データとなる。
    pub fn commitment_key(&self, degree: usize) -> Result<CommitmentKey<E>, SrsError>
    where
        E::G1Affine: Copy,
    {
        if degree > self.max_degree() {
            return Err(SrsError::UnsupportedDegree { requested: degree, range: 0..=self.max_degree() });
        }
        let powers: Arc<[E::G1Affine]> = Arc::from(self.g1_powers[..=degree].to_vec().into_boxed_slice());
        Ok(CommitmentKey { g1_powers: powers })
    }

    /// 指定次数に対応するVerifier鍵を抽出する。
    pub fn verifier_key(&self, degree: usize) -> Result<VerifierKey<E>, SrsError>
    where
        E::G1Affine: Copy,
        E::G2Affine: Copy,
    {
        if degree == 0 || degree > self.max_degree() {
            return Err(SrsError::UnsupportedDegree { requested: degree, range: 1..=self.max_degree() });
        }
        Ok(VerifierKey {
            g_generator: self.g1_powers[0],
            g_tau_n: self.g1_powers[degree],
            h_generator: self.g2_powers[0],
            h_tau: self.g2_powers[1],
        })
    }

    /// `commitment_key` と `verifier_key` をまとめて取得するヘルパ。
    pub fn extract_keys(&self, degree: usize) -> Result<KzgKeys<E>, SrsError>
    where
        E::G1Affine: Copy,
        E::G2Affine: Copy,
    {
        let committer = self.commitment_key(degree)?;
        let verifier = self.verifier_key(degree)?;
        Ok(KzgKeys { committer, verifier })
    }

    /// SRSをフォーマット1でシリアライズする。
    pub fn to_bytes(&self) -> Result<Vec<u8>, SrsError>
    where
        E::G1Affine: CanonicalSerialize,
        E::G2Affine: CanonicalSerialize,
    {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(FORMAT_MAGIC);
        bytes.push(FORMAT_VERSION);
        bytes.extend_from_slice(&(self.g1_powers.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(self.g2_powers.len() as u32).to_le_bytes());

        for point in &self.g1_powers {
            point
                .serialize_with_mode(&mut bytes, Compress::Yes)
                .map_err(|_| SrsError::Serialization)?;
        }
        for point in &self.g2_powers {
            point
                .serialize_with_mode(&mut bytes, Compress::Yes)
                .map_err(|_| SrsError::Serialization)?;
        }

        Ok(bytes)
    }

    /// フォーマット1のバイト列からSRSを復元する。
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SrsError>
    where
        E::G1Affine: CanonicalDeserialize,
        E::G2Affine: CanonicalDeserialize,
    {
        if bytes.len() < 9 {
            return Err(SrsError::InvalidFormat);
        }

        let mut cursor = Cursor::new(bytes);

        let mut magic = [0u8; 4];
        cursor.read_exact(&mut magic).map_err(|_| SrsError::Io)?;
        if &magic != FORMAT_MAGIC {
            return Err(SrsError::InvalidFormat);
        }

        let mut version = [0u8; 1];
        cursor.read_exact(&mut version).map_err(|_| SrsError::Io)?;
        if version[0] != FORMAT_VERSION {
            return Err(SrsError::UnsupportedVersion(version[0]));
        }

        let mut len_buf = [0u8; 4];
        cursor.read_exact(&mut len_buf).map_err(|_| SrsError::Io)?;
        let g1_len = u32::from_le_bytes(len_buf) as usize;
        cursor.read_exact(&mut len_buf).map_err(|_| SrsError::Io)?;
        let g2_len = u32::from_le_bytes(len_buf) as usize;

        let g1_powers = read_points::<E::G1Affine>(&mut cursor, g1_len)?;
        let g2_powers = read_points::<E::G2Affine>(&mut cursor, g2_len)?;

        Self::new(g1_powers, g2_powers)
    }

    /// バイト列からSRSを復元し、`validate`で整合性をチェックしてから返す高水準API。
    pub fn load_and_validate(bytes: &[u8]) -> Result<Self, SrsError>
    where
        E::G1Affine: CanonicalDeserialize + AffineRepr,
        E::G2Affine: CanonicalDeserialize + AffineRepr,
    {
        let srs = Self::from_bytes(bytes)?;
        srs.validate()?;
        Ok(srs)
    }
}

fn read_points<A>(cursor: &mut Cursor<&[u8]>, len: usize) -> Result<Vec<A>, SrsError>
where
    A: CanonicalDeserialize,
{
    let mut points = Vec::with_capacity(len);
    for _ in 0..len {
        let point = A::deserialize_with_mode(&mut *cursor, Compress::Yes, Validate::No)
            .map_err(|_| SrsError::Serialization)?;
        points.push(point);
    }
    Ok(points)
}

/// Proverが利用する鍵スライス。
pub struct ProverKey<'a, E: Pairing> {
    pub g1_powers: &'a [E::G1Affine],
    pub g2_powers: &'a [E::G2Affine],
}

/// KZGコミットメントで利用する共通鍵（G1累乗列）。
#[derive(Clone, Debug)]
pub struct CommitmentKey<E: Pairing> {
    g1_powers: Arc<[E::G1Affine]>,
}

impl<E: Pairing> CommitmentKey<E> {
    pub fn powers(&self) -> &[E::G1Affine] {
        &self.g1_powers
    }

    pub fn degree(&self) -> usize {
        self.g1_powers.len().saturating_sub(1)
    }
}

/// Verifierが利用する最小限のパラメータ。
#[derive(Clone, Copy, Debug)]
pub struct VerifierKey<E: Pairing> {
    pub g_generator: E::G1Affine,
    pub g_tau_n: E::G1Affine,
    pub h_generator: E::G2Affine,
    pub h_tau: E::G2Affine,
}

impl<E: Pairing> VerifierKey<E> {
    /// pairingチェックに必要な (g^{\tau^n}, h^{\tau}) を返すヘルパ。
    pub fn degree_pairing_check(&self) -> (E::G1Affine, E::G2Affine) {
        (self.g_tau_n, self.h_tau)
    }
}

/// コミッタ鍵とベリファイア鍵をまとめた構造体。
#[derive(Clone, Debug)]
pub struct KzgKeys<E: Pairing> {
    pub committer: CommitmentKey<E>,
    pub verifier: VerifierKey<E>,
}

/// SRS読み込み・検証で発生しうるエラー。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SrsError {
    InvalidLength,
    UnexpectedGenerator,
    InconsistentPowers { index: usize },
    UnsupportedDegree { requested: usize, range: RangeInclusive<usize> },
    InvalidFormat,
    UnsupportedVersion(u8),
    Serialization,
    Io,
}

impl fmt::Display for SrsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SrsError::InvalidLength => write!(f, "invalid SRS length"),
            SrsError::UnexpectedGenerator => write!(f, "unexpected generator in SRS"),
            SrsError::InconsistentPowers { index } => write!(f, "pairing check failed at index {index}"),
            SrsError::UnsupportedDegree { requested, range } => {
                write!(f, "degree {requested} not in supported range {range:?}")
            }
            SrsError::InvalidFormat => write!(f, "invalid SRS format"),
            SrsError::UnsupportedVersion(v) => write!(f, "unsupported SRS version {v}"),
            SrsError::Serialization => write!(f, "failed to (de)serialize SRS"),
            SrsError::Io => write!(f, "failed to read SRS bytes"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SrsError {}

#[cfg(all(test, feature = "curve-bls12-381"))]
mod tests {
    use super::*;

    use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
    use ark_ec::{CurveGroup, PrimeGroup};
    use core::ops::MulAssign;

    fn make_powers_of_tau(size: usize, tau: Fr) -> KzgSrs<Bls12_381> {
        assert!(size >= 2);

        let mut g1: Vec<G1Affine> = Vec::with_capacity(size);
        let mut g2: Vec<G2Affine> = Vec::with_capacity(size);

        let mut current1 = G1Projective::generator();
        let mut current2 = G2Projective::generator();

        for _ in 0..size {
            let affine1 = current1.into_affine();
            let affine2 = current2.into_affine();
            g1.push(affine1);
            g2.push(affine2);
            current1 = affine1.into_group();
            current2 = affine2.into_group();
            current1.mul_assign(tau);
            current2.mul_assign(tau);
        }

        KzgSrs::new(g1, g2).expect("powers of tau")
    }

    #[test]
    fn load_and_validate_rejects_invalid_generator() {
        let mut srs = make_powers_of_tau(4, Fr::from(2u64));
        srs.g1_powers[0] = G1Affine::identity();
        let bytes = srs.to_bytes().unwrap();
        let err = KzgSrs::<Bls12_381>::load_and_validate(&bytes).unwrap_err();
        assert!(matches!(err, SrsError::UnexpectedGenerator));
    }

    #[test]
    fn load_and_validate_accepts_valid_srs() {
        let srs = make_powers_of_tau(6, Fr::from(5u64));
        let bytes = srs.to_bytes().unwrap();
        let decoded = KzgSrs::<Bls12_381>::load_and_validate(&bytes).expect("valid SRS");
        assert_eq!(decoded.max_degree(), 5);
        let vk = decoded.verifier_key(4).expect("vk");
        assert_eq!(vk.g_generator, decoded.g1_powers()[0]);
        assert_eq!(vk.g_tau_n, decoded.g1_powers()[4]);
        assert_eq!(vk.h_generator, decoded.g2_powers()[0]);
        assert_eq!(vk.h_tau, decoded.g2_powers()[1]);
    }

    #[test]
    fn unsupported_degree_reports_range() {
        let srs = make_powers_of_tau(3, Fr::from(3u64));
        let err = srs.verifier_key(10).unwrap_err();
        if let SrsError::UnsupportedDegree { requested, range } = err {
            assert_eq!(requested, 10);
            assert_eq!(range, (1..=2));
        } else {
            panic!("unexpected error variant: {err:?}");
        }
    }

    #[test]
    fn extract_keys_returns_consistent_views() {
        let srs = make_powers_of_tau(5, Fr::from(7u64));
        let keys = srs.extract_keys(4).expect("keys");
        assert_eq!(keys.committer.degree(), 4);
        assert_eq!(keys.committer.powers().len(), 5);
        assert_eq!(keys.committer.powers()[0], srs.g1_powers()[0]);
        assert_eq!(keys.verifier.g_tau_n, srs.g1_powers()[4]);
        assert_eq!(keys.verifier.h_tau, srs.g2_powers()[1]);
    }
}
