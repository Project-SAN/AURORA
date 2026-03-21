use std::collections::BTreeMap;
use std::fmt::Write as FmtWrite;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::string::String;
use std::time::Duration;
use std::vec::Vec;

use aurora::node::exit::{ExitMode, ExitTransport};
use aurora::routing::IpAddr;
use aurora::types::Error;

const STREAM_DATA_OFFSET: usize = 64;

pub struct TcpExitTransport {
    sessions: BTreeMap<u64, TcpStream>,
}

impl TcpExitTransport {
    pub fn new() -> Self {
        Self {
            sessions: BTreeMap::new(),
        }
    }
}

impl ExitTransport for TcpExitTransport {
    fn send(
        &mut self,
        addr: &IpAddr,
        port: u16,
        _mode: ExitMode,
        request: &[u8],
    ) -> core::result::Result<Vec<u8>, Error> {
        // _mode is reserved for future TLS support; currently only plain TCP is implemented.
        if let Some(frame) = parse_stream_frame(request) {
            return self.handle_stream_frame(addr, port, frame);
        }

        let addr_str = socket_addr_string(addr, port);

        let mut stream = TcpStream::connect(&addr_str).map_err(|_| Error::Crypto)?;
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
        stream.write_all(request).map_err(|_| Error::Crypto)?;
        stream.flush().map_err(|_| Error::Crypto)?;
        let mut response = Vec::new();
        let _ = stream.read_to_end(&mut response);
        Ok(response)
    }
}

impl TcpExitTransport {
    fn handle_stream_frame(
        &mut self,
        addr: &IpAddr,
        port: u16,
        frame: StreamFrame<'_>,
    ) -> core::result::Result<Vec<u8>, Error> {
        match frame.op {
            StreamOp::Open => {
                let key = frame.session_id;
                if !self.sessions.contains_key(&key) {
                    let addr_str = socket_addr_string(addr, port);
                    let stream = TcpStream::connect(&addr_str).map_err(|_| Error::Crypto)?;
                    stream
                        .set_read_timeout(Some(Duration::from_millis(60)))
                        .ok();
                    stream.set_write_timeout(Some(Duration::from_secs(2))).ok();
                    self.sessions.insert(key, stream);
                }
                let stream = self.sessions.get_mut(&key).ok_or(Error::Crypto)?;
                if frame.data.is_empty() {
                    return Ok(Vec::new());
                }
                stream.write_all(frame.data).map_err(|_| Error::Crypto)?;
                stream.flush().map_err(|_| Error::Crypto)?;
                read_available(stream)
            }
            StreamOp::Data => {
                if !self.sessions.contains_key(&frame.session_id) {
                    let addr_str = socket_addr_string(addr, port);
                    let stream = TcpStream::connect(&addr_str).map_err(|_| Error::Crypto)?;
                    stream
                        .set_read_timeout(Some(Duration::from_millis(60)))
                        .ok();
                    stream.set_write_timeout(Some(Duration::from_secs(2))).ok();
                    self.sessions.insert(frame.session_id, stream);
                }
                let stream = self
                    .sessions
                    .get_mut(&frame.session_id)
                    .ok_or(Error::Crypto)?;
                stream.write_all(frame.data).map_err(|_| Error::Crypto)?;
                stream.flush().map_err(|_| Error::Crypto)?;
                read_available(stream)
            }
            StreamOp::Close => {
                self.sessions.remove(&frame.session_id);
                Ok(Vec::new())
            }
        }
    }
}

#[derive(Clone, Copy)]
enum StreamOp {
    Open,
    Data,
    Close,
}

struct StreamFrame<'a> {
    op: StreamOp,
    session_id: u64,
    data: &'a [u8],
}

fn parse_stream_frame(req: &[u8]) -> Option<StreamFrame<'_>> {
    if req.len() < STREAM_DATA_OFFSET || &req[..4] != b"HRS1" {
        return None;
    }
    let op = match req[4] {
        1 => StreamOp::Open,
        2 => StreamOp::Data,
        3 => StreamOp::Close,
        _ => return None,
    };
    let mut sid = [0u8; 8];
    sid.copy_from_slice(&req[8..16]);
    let session_id = u64::from_be_bytes(sid);
    let data_len = u16::from_be_bytes([req[6], req[7]]) as usize;
    let off = STREAM_DATA_OFFSET;
    if off + data_len > req.len() {
        return None;
    }
    Some(StreamFrame {
        op,
        session_id,
        data: &req[off..off + data_len],
    })
}

// Read until the OS reports that no more bytes are immediately available.
fn read_available(stream: &mut TcpStream) -> core::result::Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                break
            }
            Err(_) => return Err(Error::Crypto),
        }
    }
    Ok(out)
}

fn socket_addr_string(addr: &IpAddr, port: u16) -> String {
    match addr {
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
    }
}
