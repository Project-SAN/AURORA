pub mod core;
pub mod payload;

// Re-export core FS operations at module root
pub use core::{fs_create, fs_create_from_chdr, fs_open};
// Re-export payload algorithms to keep call-sites simple
pub use payload::{add_fs_into_payload, retrieve_fses, FsPayload};

