use std::env;
use std::time::Duration;

use aurora::types::Error;

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

    pub fn validate(&self) -> core::result::Result<(), Error> {
        if self.directory_url.is_empty() || self.directory_public_key.is_empty() {
            return Err(Error::Length);
        }
        Ok(())
    }

    pub fn from_env() -> core::result::Result<Self, Error> {
        let url =
            env::var("HORNET_DIR_URL").unwrap_or_else(|_| "https://example.com/directory".into());
        let public_key = env::var("HORNET_DIR_PUBKEY").unwrap_or_default();
        let router_id = env::var("HORNET_ROUTER_ID").ok().filter(|s| !s.is_empty());
        let poll = env::var("HORNET_DIR_INTERVAL")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(60);
        let storage =
            env::var("HORNET_STORAGE_PATH").unwrap_or_else(|_| "router_state.json".into());
        let mut cfg = RouterConfig::new(url, public_key);
        cfg.router_id = router_id;
        cfg.directory_poll_interval = Duration::from_secs(poll);
        cfg.storage_path = storage;
        cfg.validate()?;
        Ok(cfg)
    }
}
