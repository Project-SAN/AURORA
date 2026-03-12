use alloc::vec::Vec;

use crate::routing::IpAddr;

/// Controls whether the exit transport uses a plain TCP connection or a TLS-wrapped one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitMode {
    /// Plain TCP connection to the exit destination.
    Tcp,
    /// TLS-wrapped connection to the exit destination.
    Tls,
}

pub trait ExitTransport {
    fn send(
        &mut self,
        addr: &IpAddr,
        port: u16,
        mode: ExitMode,
        request: &[u8],
    ) -> core::result::Result<Vec<u8>, crate::types::Error>;
}

#[cfg(feature = "std")]
#[path = "exit_std.rs"]
mod exit_std;
#[cfg(feature = "std")]
pub use exit_std::TcpExitTransport;
