use crate::types::Result;
use alloc::string::String;
#[cfg(feature = "std")]
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct RouterConfig {
    pub directory_url: String,
    pub directory_secret: String,
    #[cfg(feature = "std")]
    pub directory_poll_interval: Duration,
}

impl RouterConfig {
    pub fn new(directory_url: impl Into<String>, directory_secret: impl Into<String>) -> Self {
        Self {
            directory_url: directory_url.into(),
            directory_secret: directory_secret.into(),
            #[cfg(feature = "std")]
            directory_poll_interval: Duration::from_secs(60),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.directory_url.is_empty() || self.directory_secret.is_empty() {
            return Err(crate::types::Error::Length);
        }
        Ok(())
    }
}
