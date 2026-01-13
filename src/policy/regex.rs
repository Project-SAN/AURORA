use alloc::string::String;
use alloc::vec::Vec;

use crate::types::{Error, Result};

#[cfg(feature = "regex-policy")]
use regex::Regex;

#[derive(Clone, Debug)]
pub struct RegexPolicy {
    #[cfg(feature = "regex-policy")]
    patterns: Vec<Regex>,
    #[cfg(not(feature = "regex-policy"))]
    _phantom: (),
}

impl RegexPolicy {
    pub fn new(patterns: &[String]) -> Result<Self> {
        #[cfg(feature = "regex-policy")]
        {
            let mut compiled = Vec::with_capacity(patterns.len());
            for pattern in patterns {
                let regex = Regex::new(pattern).map_err(|_| Error::PolicyViolation)?;
                compiled.push(regex);
            }
            Ok(Self { patterns: compiled })
        }
        #[cfg(not(feature = "regex-policy"))]
        {
            let _ = patterns;
            Err(Error::PolicyViolation)
        }
    }

    pub fn matches(&self, payload: &[u8]) -> Result<bool> {
        #[cfg(feature = "regex-policy")]
        {
            let text = core::str::from_utf8(payload).map_err(|_| Error::PolicyViolation)?;
            Ok(self.patterns.iter().any(|regex| regex.is_match(text)))
        }
        #[cfg(not(feature = "regex-policy"))]
        {
            let _ = payload;
            Err(Error::PolicyViolation)
        }
    }
}

pub fn exact_literals(patterns: &[String]) -> Result<Vec<String>> {
    let mut out = Vec::with_capacity(patterns.len());
    for pattern in patterns {
        if contains_regex_meta(pattern) {
            return Err(Error::NotImplemented);
        }
        out.push(pattern.clone());
    }
    Ok(out)
}

fn contains_regex_meta(pattern: &str) -> bool {
    pattern.chars().any(|c| matches!(c, '.' | '^' | '$' | '*' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '\\'))
}
