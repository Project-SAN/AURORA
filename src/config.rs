#![allow(dead_code)]

/// Default JSON blocklist location used by the demo binaries.
pub const DEFAULT_BLOCKLIST_PATH: &str = "config/blocklist.json";

/// Policy label used to derive proving/verification keys for the demo policy.
pub const DEFAULT_POLICY_LABEL: &[u8] = b"default-blocklist-policy";

/// Local Policy Authority base URL used by the demo client binary.
pub const DEFAULT_AUTHORITY_URL: &str = "http://127.0.0.1:8080";
