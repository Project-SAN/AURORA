use std::fs;
use std::path::PathBuf;

use crate::types::{Error, Result};

use super::{RouterStorage, StoredState};

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
        let data = fs::read(&self.path).map_err(|_| Error::Crypto)?;
        let state: StoredState = serde_json::from_slice(&data).map_err(|_| Error::Crypto)?;
        Ok(state)
    }

    fn save(&self, state: &StoredState) -> Result<()> {
        let data = serde_json::to_vec_pretty(state).map_err(|_| Error::Crypto)?;
        fs::write(&self.path, data).map_err(|_| Error::Crypto)
    }
}
