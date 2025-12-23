use crate::router::Router;
use crate::setup::directory::{self, DirectoryAnnouncement};
use crate::types::Result;

/// Applies a directory JSON string (already verified) to the router.
pub fn apply_announcement(router: &mut Router, announcement: &DirectoryAnnouncement) -> Result<()> {
    router.install_directory(announcement)
}

/// Convenience helper: verify a signed JSON body with the shared secret
/// and install the contained policies into the router.
pub fn apply_signed_announcement(router: &mut Router, body: &str, secret: &[u8]) -> Result<()> {
    let announcement = directory::from_signed_json(body, secret)?;
    apply_announcement(router, &announcement)
}

#[cfg(feature = "std")]
pub mod client {
    use super::apply_signed_announcement;
    use crate::router::{config::RouterConfig, Router};
    use crate::types::Result;

    pub trait DirectoryClient {
        fn fetch_signed(&self) -> Result<String>;
    }

    #[cfg(feature = "http-client")]
    pub struct HttpDirectoryClient<'a> {
        config: &'a RouterConfig,
    }

    #[cfg(feature = "http-client")]
    impl<'a> HttpDirectoryClient<'a> {
        pub fn new(config: &'a RouterConfig) -> Self {
            Self { config }
        }
    }

    #[cfg(feature = "http-client")]
    impl<'a> DirectoryClient for HttpDirectoryClient<'a> {
        fn fetch_signed(&self) -> Result<String> {
            let response = ureq::get(&self.config.directory_url)
                .call()
                .map_err(|_| crate::types::Error::Crypto)?;
            let body = response
                .into_string()
                .map_err(|_| crate::types::Error::Crypto)?;
            Ok(body)
        }
    }

    pub fn sync_once(
        router: &mut Router,
        config: &RouterConfig,
        client: &dyn DirectoryClient,
    ) -> Result<()> {
        let body = client.fetch_signed()?;
        apply_signed_announcement(router, &body, config.directory_secret.as_bytes())
    }
}
