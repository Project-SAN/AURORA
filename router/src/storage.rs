use std::fs;
use std::path::PathBuf;

use aurora::router::storage::{RouterStorage, StoredState};
use aurora::types::Error;

pub struct FileRouterStorage {
    path: PathBuf,
}

impl FileRouterStorage {
    pub fn new<P: Into<PathBuf>>(path: P) -> Self {
        Self { path: path.into() }
    }
}

impl RouterStorage for FileRouterStorage {
    fn load(&self) -> core::result::Result<StoredState, Error> {
        let data = fs::read(&self.path).map_err(|_| Error::Crypto)?;
        let state: StoredState = serde_json::from_slice(&data).map_err(|_| Error::Crypto)?;
        Ok(state)
    }

    fn save(&self, state: &StoredState) -> core::result::Result<(), Error> {
        let data = serde_json::to_vec(state).map_err(|_| Error::Crypto)?;
        fs::write(&self.path, data).map_err(|_| Error::Crypto)
    }
}
