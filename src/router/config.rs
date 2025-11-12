use crate::types::Result;
use alloc::string::String;

#[derive(Clone, Debug)]
pub struct RouterConfig {
    pub directory_url: String,
    pub directory_secret: String,
}

impl RouterConfig {
    pub fn new(directory_url: impl Into<String>, directory_secret: impl Into<String>) -> Self {
        Self {
            directory_url: directory_url.into(),
            directory_secret: directory_secret.into(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.directory_url.is_empty() || self.directory_secret.is_empty() {
            return Err(crate::types::Error::Length);
        }
        Ok(())
    }
}
