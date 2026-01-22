use std::env;

use crate::types::Result;

use super::RouterConfig;

pub fn from_env() -> Result<RouterConfig> {
    let url = env::var("HORNET_DIR_URL").unwrap_or_else(|_| "https://example.com/directory".into());
    let public_key = env::var("HORNET_DIR_PUBKEY").unwrap_or_default();
    let router_id = env::var("HORNET_ROUTER_ID").ok().filter(|s| !s.is_empty());
    let poll = env::var("HORNET_DIR_INTERVAL")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(60);
    let storage = env::var("HORNET_STORAGE_PATH").unwrap_or_else(|_| "router_state.json".into());
    let mut cfg = RouterConfig::new(url, public_key);
    cfg.router_id = router_id;
    cfg.directory_poll_interval = core::time::Duration::from_secs(poll);
    cfg.storage_path = storage;
    cfg.validate()?;
    Ok(cfg)
}
