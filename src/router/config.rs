use crate::types::Result;
use alloc::string::String;
use core::time::Duration;

#[derive(Clone, Debug)]
pub struct RouterConfig {
    pub directory_url: String,
    pub directory_public_key: String,
    pub router_id: Option<String>,
    pub directory_poll_interval: Duration,
    pub storage_path: String,
}

impl RouterConfig {
    pub fn new(directory_url: impl Into<String>, directory_public_key: impl Into<String>) -> Self {
        Self {
            directory_url: directory_url.into(),
            directory_public_key: directory_public_key.into(),
            router_id: None,
            directory_poll_interval: Duration::from_secs(60),
            storage_path: "router_state.json".into(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.directory_url.is_empty() || self.directory_public_key.is_empty() {
            return Err(crate::types::Error::Length);
        }
        Ok(())
    }

    #[cfg(feature = "std")]
    pub fn from_env() -> Result<Self> {
        config_std::from_env()
    }
}

#[cfg(feature = "std")]
#[path = "config_std.rs"]
mod config_std;
