use core::{fmt, marker::PhantomData, num::NonZeroU32};

use digest::{ExtendableOutput, XofReader};
use rand_core::{CryptoRng, RngCore};

/// Errors returned by XDRBG.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum XdrbgError {
    /// `generate`/`reseed` was called before `instantiate`.
    NotInstantiated,
    /// Additional input `alpha` is too long for the recommended encoding.
    AlphaTooLong { len: usize, max: usize },
    /// Seed material is shorter than required for the chosen parameter set.
    SeedTooShort { len: usize, required: usize },
    /// Requested output exceeds the recommended maxout for a single Generate call.
    MaxOutExceeded { requested: usize, max: usize },
    /// Domain must be 0, 1, or 2.
    InvalidDomain { domain: u8 },
}

impl fmt::Display for XdrbgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            XdrbgError::NotInstantiated => write!(f, "XDRBG is not instantiated"),
            XdrbgError::AlphaTooLong { len, max } => {
                write!(f, "alpha too long: {len} bytes (max {max})")
            }
            XdrbgError::SeedTooShort { len, required } => {
                write!(f, "seed too short: {len} bytes (require at least {required})")
            }
            XdrbgError::MaxOutExceeded { requested, max } => {
                write!(f, "requested {requested} bytes exceeds maxout {max} bytes")
            }
            XdrbgError::InvalidDomain { domain } => {
                write!(f, "invalid domain value {domain}; expected 0, 1, or 2")
            }
        }
    }
}



/// Parameter set for an XDRBG instantiation.
///
/// All lengths are in bits unless explicitly stated otherwise.
pub trait XdrbgParams {
    /// Internal state size |V| in bytes.
    const STATE_BYTES: usize;
    /// Minimum seed min-entropy required by Instantiate (Hinit) in bits.
    const HINIT_BITS: usize;
    /// Minimum seed min-entropy required by Reseed (Hrsd) in bits.
    const HRSD_BITS: usize;
    /// Recommended max output from a single Generate call in bits.
    const MAXOUT_BITS: usize;
    /// Maximum allowed alpha length for the recommended encoding (Appendix B).
    const MAX_ALPHA_BYTES: usize = 84;

    #[inline(always)]
    fn bits_to_min_bytes(bits: usize) -> usize {
        bits.div_ceil(8)
    }
    #[inline(always)]
    fn hinit_min_seed_bytes() -> usize {
        Self::bits_to_min_bytes(Self::HINIT_BITS)
    }
    #[inline(always)]
    fn hrsd_min_seed_bytes() -> usize {
        Self::bits_to_min_bytes(Self::HRSD_BITS)
    }
    #[inline(always)]
    fn maxout_bytes() -> usize {
        Self::bits_to_min_bytes(Self::MAXOUT_BITS)
    }
}

/// XDRBG implementation generic over:
/// - `X`: an XOF implementing `digest::ExtendableOutput` (e.g., `sha3::Shake256`)
/// - `P`: an XDRBG parameter set (`XdrbgParams`)
///
/// Implements Algorithm 2 from the XDRBG paper using the recommended encoding:
/// encode(S, α, n) = S || α || byte(n*85 + |α|), with |α| <= 84 and n in {0,1,2}.
pub struct Xdrbg<X, P>
where
    P: XdrbgParams,
{
    v: [u8; 64],
    instantiated: bool,
    _pd: PhantomData<(X, P)>,
}

impl<X, P> Xdrbg<X, P>
where
    P: XdrbgParams,
{
    /// Create an unseeded XDRBG instance. You must call `instantiate` before generating output.
    #[inline]
    pub fn new_unseeded() -> Self {
        Self {
            v: [0u8; 64],
            instantiated: false,
            _pd: PhantomData,
        }
    }

    /// Returns whether `instantiate` has been called at least once.
    #[inline]
    pub fn is_instantiated(&self) -> bool {
        self.instantiated
    }

    /// Instantiate the DRBG state from `seed` and optional `alpha`.
    ///
    /// This performs exactly one XOF query and sets the internal state `V`.
    pub fn instantiate(&mut self, seed: &[u8], alpha: &[u8]) -> Result<(), XdrbgError>
    where
        X: ExtendableOutput + Default,
    {
        self.validate_alpha(alpha)?;

        let required = P::hinit_min_seed_bytes();
        if seed.len() < required {
            return Err(XdrbgError::SeedTooShort {
                len: seed.len(),
                required,
            });
        }

        // V <- XOF( encode(seed, alpha, 0), |V| )
        let mut xof = X::default();
        xof.update(seed);
        xof.update(alpha);
        xof.update(&[Self::encode_tag(alpha.len(), 0)?]);
        let mut reader = xof.finalize_xof();
        reader.read(&mut self.v[..P::STATE_BYTES]);

        self.instantiated = true;
        Ok(())
    }

    /// Reseed the DRBG state from current state, `seed`, and optional `alpha`.
    ///
    /// This performs exactly one XOF query.
    pub fn reseed(&mut self, seed: &[u8], alpha: &[u8]) -> Result<(), XdrbgError>
    where
        X: ExtendableOutput + Default,
    {
        if !self.instantiated {
            return Err(XdrbgError::NotInstantiated);
        }
        self.validate_alpha(alpha)?;

        let required = P::hrsd_min_seed_bytes();
        if seed.len() < required {
            return Err(XdrbgError::SeedTooShort {
                len: seed.len(),
                required,
            });
        }

        // V <- XOF( encode((V' || seed), alpha, 1), |V| )
        let mut xof = X::default();
        xof.update(&self.v[..P::STATE_BYTES]);
        xof.update(seed);
        xof.update(alpha);
        xof.update(&[Self::encode_tag(alpha.len(), 1)?]);
        let mut reader = xof.finalize_xof();
        reader.read(&mut self.v[..P::STATE_BYTES]);

        Ok(())
    }

    /// Generate output using exactly one Generate call (one XOF query).
    ///
    /// This enforces the recommended `maxout` limit for a single Generate call.
    pub fn generate_once(&mut self, alpha: &[u8], out: &mut [u8]) -> Result<(), XdrbgError>
    where
        X: ExtendableOutput + Default,
    {
        if !self.instantiated {
            return Err(XdrbgError::NotInstantiated);
        }
        self.validate_alpha(alpha)?;

        let max = P::maxout_bytes();
        if out.len() > max {
            return Err(XdrbgError::MaxOutExceeded {
                requested: out.len(),
                max,
            });
        }

        // T <- XOF( encode(V', alpha, 2), |V| + |out| )
        // V <- first |V| bytes of T
        // Σ <- remaining bytes of T
        let mut xof = X::default();
        xof.update(&self.v[..P::STATE_BYTES]);
        xof.update(alpha);
        xof.update(&[Self::encode_tag(alpha.len(), 2)?]);

        let mut reader = xof.finalize_xof();
        reader.read(&mut self.v[..P::STATE_BYTES]);
        reader.read(out);

        Ok(())
    }

    /// Generate arbitrary-length output, splitting across multiple Generate calls.
    pub fn generate(&mut self, alpha: &[u8], out: &mut [u8]) -> Result<(), XdrbgError>
    where
        X: ExtendableOutput + Default,
    {
        let max = P::maxout_bytes();
        let mut pos = 0usize;
        while pos < out.len() {
            let remaining = out.len() - pos;
            let take = if remaining > max { max } else { remaining };
            self.generate_once(alpha, &mut out[pos..pos + take])?;
            pos += take;
        }
        Ok(())
    }

    /// Convenience wrapper: `generate` with empty `alpha`.
    #[inline]
    pub fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), XdrbgError>
    where
        X: ExtendableOutput + Default,
    {
        self.generate(&[], out)
    }

    #[inline]
    fn validate_alpha(&self, alpha: &[u8]) -> Result<(), XdrbgError> {
        if alpha.len() > P::MAX_ALPHA_BYTES {
            return Err(XdrbgError::AlphaTooLong {
                len: alpha.len(),
                max: P::MAX_ALPHA_BYTES,
            });
        }
        Ok(())
    }

    /// tag = n*85 + |alpha|, with n in {0,1,2} and |alpha| <= 84.
    #[inline]
    fn encode_tag(alpha_len: usize, domain: u8) -> Result<u8, XdrbgError> {
        if domain > 2 {
            return Err(XdrbgError::InvalidDomain { domain });
        }
        let tag = (domain as usize) * 85 + alpha_len;
        Ok(tag as u8)
    }
}

impl<X, P> Default for Xdrbg<X, P>
where
    P: XdrbgParams,
{
    fn default() -> Self {
        Self::new_unseeded()
    }
}

impl<X, P> fmt::Debug for Xdrbg<X, P>
where
    P: XdrbgParams,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Xdrbg")
            .field("instantiated", &self.instantiated)
            .field("state_bytes", &P::STATE_BYTES)
            .finish_non_exhaustive()
    }
}

impl<X, P> RngCore for Xdrbg<X, P>
where
    X: ExtendableOutput + Default,
    P: XdrbgParams,
{
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf)
            .expect("xdrbg: failed to generate random bytes");
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf)
            .expect("xdrbg: failed to generate random bytes");
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.try_fill_bytes(dest)
            .expect("xdrbg: failed to generate random bytes");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.generate(&[], dest).map_err(xdrbg_to_rand_error)
    }
}

impl<X, P> CryptoRng for Xdrbg<X, P>
where
    X: ExtendableOutput + Default,
    P: XdrbgParams,
{
}

fn xdrbg_to_rand_error(err: XdrbgError) -> rand_core::Error {
    let code = rand_core::Error::CUSTOM_START
        + match err {
            XdrbgError::NotInstantiated => 1,
            XdrbgError::AlphaTooLong { .. } => 2,
            XdrbgError::SeedTooShort { .. } => 3,
            XdrbgError::MaxOutExceeded { .. } => 4,
            XdrbgError::InvalidDomain { .. } => 5,
        };
    rand_core::Error::from(NonZeroU32::new(code).unwrap())
}

/// XDRBG-128 (SHAKE128, |V|=256 bits, Hinit=192, Hrsd=128, maxout=2432 bits).
pub struct Xdrbg128Params;

impl XdrbgParams for Xdrbg128Params {
    const STATE_BYTES: usize = 32;
    const HINIT_BITS: usize = 192;
    const HRSD_BITS: usize = 128;
    const MAXOUT_BITS: usize = 2432;
}

/// XDRBG-192 (SHAKE256, |V|=512 bits, Hinit=240, Hrsd=240, maxout=2752 bits).
pub struct Xdrbg192Params;

impl XdrbgParams for Xdrbg192Params {
    const STATE_BYTES: usize = 64;
    const HINIT_BITS: usize = 240;
    const HRSD_BITS: usize = 240;
    const MAXOUT_BITS: usize = 2752;
}

/// XDRBG-256 (SHAKE256, |V|=512 bits, Hinit=384, Hrsd=256, maxout=2752 bits).
pub struct Xdrbg256Params;

impl XdrbgParams for Xdrbg256Params {
    const STATE_BYTES: usize = 64;
    const HINIT_BITS: usize = 384;
    const HRSD_BITS: usize = 256;
    const MAXOUT_BITS: usize = 2752;
}

pub type Xdrbg128 = Xdrbg<sha3::Shake128, Xdrbg128Params>;
pub type Xdrbg192 = Xdrbg<sha3::Shake256, Xdrbg192Params>;
pub type Xdrbg256 = Xdrbg<sha3::Shake256, Xdrbg256Params>;
