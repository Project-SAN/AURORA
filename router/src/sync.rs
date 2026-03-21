use aurora::router::Router;
use aurora::setup::directory::{self, DirectoryAnnouncement};
use aurora::types::Error;
use aurora::utils::decode_hex;

use crate::config::RouterConfig;

pub fn apply_announcement(
    router: &mut Router,
    announcement: &DirectoryAnnouncement,
) -> core::result::Result<(), Error> {
    router.install_directory(announcement)
}

pub fn apply_signed_announcement(
    router: &mut Router,
    body: &str,
    public_key: &[u8],
) -> core::result::Result<(), Error> {
    let announcement = directory::from_signed_json(body, public_key)?;
    apply_announcement(router, &announcement)
}

pub trait DirectoryClient {
    fn fetch_signed(&self) -> core::result::Result<String, Error>;
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
    fn fetch_signed(&self) -> core::result::Result<String, Error> {
        let response = ureq::get(&self.config.directory_url)
            .call()
            .map_err(|_| Error::Crypto)?;
        let body = response.into_string().map_err(|_| Error::Crypto)?;
        Ok(body)
    }
}

pub fn sync_once(
    router: &mut Router,
    config: &RouterConfig,
    client: &dyn DirectoryClient,
) -> core::result::Result<(), Error> {
    let body = client.fetch_signed()?;
    let key_bytes = decode_hex(&config.directory_public_key).map_err(|_| Error::Crypto)?;
    if key_bytes.len() != 32 {
        return Err(Error::Length);
    }
    apply_signed_announcement(router, &body, &key_bytes)
}
