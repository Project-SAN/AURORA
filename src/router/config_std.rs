use super::config::RouterConfig;
use crate::types::Result;
use crate::utils::decode_hex;
use core::time::Duration;
use std::env;

pub fn from_env() -> Result<RouterConfig> {
    let url =
        env::var("HORNET_DIR_URL").unwrap_or_else(|_| "https://example.com/directory".into());
    let secret = env::var("HORNET_DIR_SECRET").unwrap_or_else(|_| "shared-secret".into());
    let poll = env::var("HORNET_DIR_INTERVAL")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(60);
    let storage = env::var("HORNET_STORAGE_PATH").unwrap_or_else(|_| "router_state.json".into());
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
    let mut cfg = RouterConfig::new(url, secret);
    cfg.directory_poll_interval = Duration::from_secs(poll);
    cfg.storage_path = storage;
    cfg.expected_policy_id = expected_policy_id;
    cfg.router_name = router_name;
    cfg.async_validate = async_validate;
    cfg.validate()?;
    Ok(cfg)
}
