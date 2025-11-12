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
