pub mod chdr;
pub mod ahdr;
pub mod onion;
pub mod fs_core;
pub mod fs_payload;

// Re-export FS functions for convenience
pub use fs_core::{fs_create, fs_create_from_chdr, fs_open};
pub use fs_payload::{add_fs_into_payload, retrieve_fses, FsPayload};