#![allow(dead_code)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use crate::fs;
use hornet::router::storage::{RouterStorage, StoredState};
use hornet::types::{Error, Result};

pub struct UserlandRouterStorage {
    path: String,
}

impl UserlandRouterStorage {
    pub fn new(path: impl Into<String>) -> Self {
        Self { path: path.into() }
    }
}

impl RouterStorage for UserlandRouterStorage {
    fn load(&self) -> Result<StoredState> {
        let data = read_all(&self.path)?;
        serde_json::from_slice(&data).map_err(|_| Error::Crypto)
    }

    fn save(&self, state: &StoredState) -> Result<()> {
        let data = serde_json::to_vec_pretty(state).map_err(|_| Error::Crypto)?;
        write_all(&self.path, &data)
    }
}

fn read_all(path: &str) -> Result<Vec<u8>> {
    let handle = fs::open(path, fs::O_READ).ok_or(Error::Crypto)?;
    let mut out = Vec::new();
    let mut buf = [0u8; 512];
    loop {
        match fs::read(handle, &mut buf) {
            Some(0) => break,
            Some(n) => out.extend_from_slice(&buf[..n]),
            None => {
                let _ = fs::close(handle);
                return Err(Error::Crypto);
            }
        }
    }
    if !fs::close(handle) {
        return Err(Error::Crypto);
    }
    Ok(out)
}

fn write_all(path: &str, data: &[u8]) -> Result<()> {
    let handle = fs::open(path, fs::O_CREATE | fs::O_WRITE | fs::O_TRUNC).ok_or(Error::Crypto)?;
    let mut offset = 0usize;
    while offset < data.len() {
        match fs::write(handle, &data[offset..]) {
            Some(0) | None => {
                let _ = fs::close(handle);
                return Err(Error::Crypto);
            }
            Some(n) => offset += n,
        }
    }
    if !fs::close(handle) {
        return Err(Error::Crypto);
    }
    if !fs::sync() {
        return Err(Error::Crypto);
    }
    Ok(())
}
