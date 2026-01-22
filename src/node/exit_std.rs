use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as FmtWrite;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::routing::IpAddr;
use crate::types::{Error, Result};

use super::ExitTransport;

pub struct TcpExitTransport;

impl TcpExitTransport {
    pub fn new() -> Self {
        Self
    }
}

impl ExitTransport for TcpExitTransport {
    fn send(&mut self, addr: &IpAddr, port: u16, _tls: bool, request: &[u8]) -> Result<Vec<u8>> {
        let addr_str = match addr {
            IpAddr::V4(octets) => format!(
                "{}.{}.{}.{}:{}",
                octets[0], octets[1], octets[2], octets[3], port
            ),
            IpAddr::V6(bytes) => {
                let mut buf = String::new();
                buf.push('[');
                for (i, chunk) in bytes.chunks(2).enumerate() {
                    if i > 0 {
                        buf.push(':');
                    }
                    let value = u16::from_be_bytes([chunk[0], chunk[1]]);
                    let _ = FmtWrite::write_fmt(&mut buf, format_args!("{:x}", value));
                }
                buf.push(']');
                let _ = FmtWrite::write_fmt(&mut buf, format_args!(":{}", port));
                buf
            }
        };

        let mut stream = TcpStream::connect(addr_str).map_err(|_| Error::Crypto)?;
        stream.write_all(request).map_err(|_| Error::Crypto)?;
        stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
        let mut response = Vec::new();
        let _ = stream.read_to_end(&mut response);
        Ok(response)
    }
}
