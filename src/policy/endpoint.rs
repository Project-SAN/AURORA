#[cfg(feature = "std")]
pub fn authority_url_from_env(default_url: &str) -> String {
    std::env::var("POLICY_AUTHORITY_URL").unwrap_or_else(|_| default_url.to_string())
}

#[cfg(feature = "std")]
pub fn policy_bundle_url_from_env(authority_url: &str) -> Option<String> {
    std::env::var("POLICY_BUNDLE_URL")
        .ok()
        .or_else(|| {
            let trimmed = authority_url.trim_end_matches('/');
            Some(format!("{trimmed}/policy-bundle"))
        })
}

#[cfg(feature = "std")]
pub fn witness_url_from_env(authority_url: &str) -> String {
    std::env::var("POLICY_WITNESS_URL")
        .ok()
        .or_else(|| {
            let trimmed = authority_url.trim_end_matches('/');
            Some(format!("{trimmed}/witness"))
        })
        .unwrap_or_else(|| "http://127.0.0.1:8080/witness".into())
}

#[cfg(feature = "std")]
pub fn oprf_url_from_env(authority_url: &str) -> Option<String> {
    std::env::var("POLICY_OPRF_URL")
        .ok()
        .or_else(|| {
            let trimmed = authority_url.trim_end_matches('/');
            Some(format!("{trimmed}/oprf"))
        })
}
