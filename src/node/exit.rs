use alloc::vec::Vec;

use crate::routing::IpAddr;
use crate::types::Result;

pub trait ExitTransport {
    fn send(&mut self, addr: &IpAddr, port: u16, tls: bool, request: &[u8]) -> Result<Vec<u8>>;
}

#[cfg(feature = "std")]
mod exit_std;
#[cfg(feature = "std")]
pub use exit_std::TcpExitTransport;
