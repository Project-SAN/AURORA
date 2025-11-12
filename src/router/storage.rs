use crate::policy::PolicyMetadata;
use crate::types::{Result, Sv};
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Serialize, Deserialize)]
pub struct StoredState {
    policies: Vec<PolicyMetadata>,
    sv: [u8; 16],
    #[serde(default)]
    si: Option<[u8; 16]>,
}

pub trait RouterStorage {
    fn load(&self) -> Result<StoredState>;
    fn save(&self, state: &StoredState) -> Result<()>;
}

pub struct FileRouterStorage {
    path: PathBuf,
}

impl FileRouterStorage {
    pub fn new<P: Into<PathBuf>>(path: P) -> Self {
        Self { path: path.into() }
    }
}

impl RouterStorage for FileRouterStorage {
    fn load(&self) -> Result<StoredState> {
        let data = fs::read(&self.path).map_err(|_| crate::types::Error::Crypto)?;
        let state: StoredState =
            serde_json::from_slice(&data).map_err(|_| crate::types::Error::Crypto)?;
        Ok(state)
    }

    fn save(&self, state: &StoredState) -> Result<()> {
        let data = serde_json::to_vec_pretty(state).map_err(|_| crate::types::Error::Crypto)?;
        fs::write(&self.path, data).map_err(|_| crate::types::Error::Crypto)
    }
}

impl StoredState {
    pub fn new(policies: Vec<PolicyMetadata>, sv: Sv, si: Option<[u8; 16]>) -> Self {
        Self {
            policies,
            sv: sv.0,
            si,
        }
    }

    pub fn policies(&self) -> &[PolicyMetadata] {
        &self.policies
    }

    pub fn sv(&self) -> Sv {
        Sv(self.sv)
    }

    pub fn si(&self) -> Option<[u8; 16]> {
        self.si
    }

    pub fn into_parts(self) -> (Vec<PolicyMetadata>, Sv, Option<[u8; 16]>) {
        (self.policies, Sv(self.sv), self.si)
    }
}
