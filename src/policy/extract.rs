use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

/// Result type for extraction routines.
pub type Result<T> = core::result::Result<T, ExtractionError>;

/// Errors that can occur while parsing payload metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractionError {
    MissingField,
    InvalidFormat,
    Unsupported,
    Overflow,
}

/// Target values that a policy can reason about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetValue {
    Domain(Vec<u8>),
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
}

impl TargetValue {
    /// Return a canonical byte representation used for commitments/witnesses.
    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            TargetValue::Domain(bytes) => bytes.clone(),
            TargetValue::Ipv4(ip) => ip.to_vec(),
            TargetValue::Ipv6(ip) => ip.to_vec(),
        }
    }

    /// Produce a witness-friendly encoding with zero-padding to `limb` bytes.
    pub fn to_witness_bytes(&self, limb: usize, max_limbs: usize) -> Result<Vec<u8>> {
        let data = self.as_bytes();
        let total = limb
            .checked_mul(max_limbs)
            .ok_or(ExtractionError::Overflow)?;
        if data.len() > total {
            return Err(ExtractionError::Overflow);
        }
        let mut out = vec![0u8; total];
        out[..data.len()].copy_from_slice(&data);
        Ok(out)
    }
}

/// Extractor trait: parse a payload into a target value understood by the circuit.
pub trait Extractor {
    fn extract(&self, payload: &[u8]) -> Result<TargetValue>;
}

/// Naive HTTP Host header extractor.
#[derive(Debug, Default, Clone)]
pub struct HttpHostExtractor;

impl Extractor for HttpHostExtractor {
    fn extract(&self, payload: &[u8]) -> Result<TargetValue> {
        let mut host_line: Option<Vec<u8>> = None;
        for raw_line in payload.split(|&b| b == b'\n') {
            let line = trim_line(raw_line);
            if line.len() < 5 {
                continue;
            }
            if line[..5].eq_ignore_ascii_case(b"host:") {
                host_line = Some(line[5..].to_vec());
                break;
            }
        }
        let value = host_line.ok_or(ExtractionError::MissingField)?;
        let hostname = normalize_ascii(&value);
        if hostname.is_empty() {
            return Err(ExtractionError::InvalidFormat);
        }
        Ok(TargetValue::Domain(hostname.into_bytes()))
    }
}

fn trim_line(line: &[u8]) -> Vec<u8> {
    let mut slice = line;
    if let Some(pos) = slice.iter().position(|&b| b == b'\r') {
        slice = &slice[..pos];
    }
    let mut start = 0;
    let mut end = slice.len();
    while start < end && slice[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && slice[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    slice[start..end].to_vec()
}

fn normalize_ascii(input: &[u8]) -> String {
    let mut out = String::new();
    for &b in input {
        if b == b' ' || b == b'\t' {
            continue;
        }
        out.push((b as char).to_ascii_lowercase());
    }
    out
}

/// Extractor that treats the payload as raw IPv4.
#[derive(Debug, Default, Clone)]
pub struct RawIpv4Extractor;

impl Extractor for RawIpv4Extractor {
    fn extract(&self, payload: &[u8]) -> Result<TargetValue> {
        if payload.len() < 4 {
            return Err(ExtractionError::InvalidFormat);
        }
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&payload[..4]);
        Ok(TargetValue::Ipv4(buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HTTP_REQ: &str = "GET / HTTP/1.1\r\nHost: Example.COM\r\nUser-Agent: Test\r\n\r\n";

    #[test]
    fn extract_http_host() {
        let extractor = HttpHostExtractor::default();
        let value = extractor
            .extract(HTTP_REQ.as_bytes())
            .expect("host extracted");
        assert_eq!(value.as_bytes(), b"example.com");
    }

    #[test]
    fn http_host_missing() {
        let extractor = HttpHostExtractor::default();
        assert!(matches!(
            extractor.extract(b"GET / HTTP/1.1\r\n\r\n"),
            Err(ExtractionError::MissingField)
        ));
    }

    #[test]
    fn witness_padding() {
        let value = TargetValue::Domain(b"abc".to_vec());
        let buf = value.to_witness_bytes(16, 2).expect("witness bytes");
        assert_eq!(buf.len(), 32);
        assert_eq!(&buf[..3], b"abc");
    }
}
