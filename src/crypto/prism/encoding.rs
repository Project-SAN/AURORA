//! Signature encoding choices discussed in Section 7.2 of the paper.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureEncoding {
    CurveAndPoints,
    CurveAndBasisCoefficients,
}
