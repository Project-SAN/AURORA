use crate::types::Result;
use alloc::string::String;
use core::time::Duration;

#[derive(Clone, Debug)]
pub struct RouterConfig {
    pub directory_url: String,
    pub directory_secret: String,
    pub expected_policy_id: Option<[u8; 32]>,
    pub router_name: Option<String>,
    pub async_validate: bool,
    #[cfg(feature = "std")]
    pub directory_poll_interval: Duration,
    #[cfg(feature = "std")]
    pub storage_path: String,
}

impl RouterConfig {
    pub fn new(directory_url: impl Into<String>, directory_secret: impl Into<String>) -> Self {
        Self {
            directory_url: directory_url.into(),
            directory_secret: directory_secret.into(),
            expected_policy_id: None,
            router_name: None,
            async_validate: false,
            #[cfg(feature = "std")]
            directory_poll_interval: Duration::from_secs(60),
            #[cfg(feature = "std")]
            storage_path: "router_state.json".into(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.directory_url.is_empty() || self.directory_secret.is_empty() {
            return Err(crate::types::Error::Length);
        }
        Ok(())
    }

    #[cfg(feature = "std")]
    pub fn from_env() -> Result<Self> {
        super::config_std::from_env()
    }
}
