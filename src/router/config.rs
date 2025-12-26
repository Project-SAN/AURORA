use crate::types::Result;
use alloc::string::String;
#[cfg(feature = "std")]
use std::time::Duration;

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
        use std::env;
        use crate::utils::decode_hex;
        let url =
            env::var("HORNET_DIR_URL").unwrap_or_else(|_| "https://example.com/directory".into());
        let secret = env::var("HORNET_DIR_SECRET").unwrap_or_else(|_| "shared-secret".into());
        let poll = env::var("HORNET_DIR_INTERVAL")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(60);
        let storage =
            env::var("HORNET_STORAGE_PATH").unwrap_or_else(|_| "router_state.json".into());
        let router_name = env::var("HORNET_ROUTER_NAME").ok();
        let async_validate = env::var("HORNET_ASYNC_VALIDATE")
            .ok()
            .as_deref()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let expected_policy_id = match env::var("HORNET_POLICY_ID_HEX") {
            Ok(hex) => {
                let bytes = decode_hex(hex.as_str()).map_err(|_| crate::types::Error::Length)?;
                if bytes.len() != 32 {
                    return Err(crate::types::Error::Length);
                }
                let mut id = [0u8; 32];
                id.copy_from_slice(&bytes);
                Some(id)
            }
            Err(_) => None,
        };
        let mut cfg = Self::new(url, secret);
        cfg.directory_poll_interval = Duration::from_secs(poll);
        cfg.storage_path = storage;
        cfg.expected_policy_id = expected_policy_id;
        cfg.router_name = router_name;
        cfg.async_validate = async_validate;
        cfg.validate()?;
        Ok(cfg)
    }
}
