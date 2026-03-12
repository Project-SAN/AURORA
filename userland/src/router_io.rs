extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::socket::{ConnectState, TcpListener, TcpSocket};
use crate::sys;
use aurora::forward::Forward;
use aurora::node::{ExitMode, ExitTransport};
use aurora::router::io::{
    encode_frame_bytes, read_incoming_packet, IncomingPacket, PacketListener, PacketReader,
};
use aurora::routing::{self, IpAddr, RouteElem};
use aurora::types::{Ahdr, Chdr, Error, PacketDirection, RoutingSegment, Sv};

const STREAM_DATA_OFFSET: usize = 64;

pub struct UserlandPacketListener {
    listener: TcpListener,
    sv: Sv,
}

impl UserlandPacketListener {
    pub fn listen(port: u16, sv: Sv) -> core::result::Result<Self, Error> {
        let listener = TcpListener::listen(port).map_err(|_| Error::Crypto)?;
        Ok(Self { listener, sv })
    }
}

impl PacketListener for UserlandPacketListener {
    fn next(&mut self) -> core::result::Result<Option<IncomingPacket>, Error> {
        match self.listener.accept().map_err(|_| Error::Crypto)? {
            None => Ok(None),
            Some(mut socket) => {
                let packet = match read_incoming_packet(&mut socket, self.sv) {
                    Ok(packet) => packet,
                    Err(_) => {
                        let _ = socket.close();
                        return Err(Error::Crypto);
                    }
                };
                let _ = socket.close();
                Ok(Some(packet))
            }
        }
    }
}

impl PacketReader for TcpSocket {
    fn read_exact(&mut self, buf: &mut [u8]) -> core::result::Result<(), Error> {
        let mut offset = 0usize;
        let mut spins = 0u32;
        while offset < buf.len() {
            let read = self.recv(&mut buf[offset..]).map_err(|_| Error::Crypto)?;
            if read == 0 {
                spins = spins.saturating_add(1);
                if spins > 4096 {
                    return Err(Error::Crypto);
                }
                sys::sleep(1);
                continue;
            }
            offset += read;
        }
        Ok(())
    }
}

pub struct UserlandForward;

impl UserlandForward {
    pub fn new() -> Self {
        Self
    }
}

impl Forward for UserlandForward {
    fn send(
        &mut self,
        rseg: &RoutingSegment,
        chdr: &Chdr,
        ahdr: &Ahdr,
        payload: &mut Vec<u8>,
        direction: PacketDirection,
    ) -> core::result::Result<(), Error> {
        let elems = routing::elems_from_segment(rseg).map_err(|_| Error::Length)?;
        let hop = elems.first().ok_or(Error::Length)?;
        let (ip, port) = match hop {
            RouteElem::NextHop { addr, port } => (addr, *port),
            RouteElem::ExitTcp { addr, port, .. } => (addr, *port),
        };

        let ip = match ip {
            IpAddr::V4(octets) => *octets,
            IpAddr::V6(_) => return Err(Error::NotImplemented),
        };

        debug_log("router-io: forward send start");
        debug_log_addr("router-io: forward addr", ip, port);
        debug_log_usize("router-io: forward payload_len", payload.len());
        let socket = TcpSocket::new().map_err(|_| Error::Crypto)?;
        if connect_ipv4(&socket, ip, port).is_err() {
            debug_log("router-io: forward connect failed");
            return Err(Error::Crypto);
        }
        debug_log("router-io: forward connected");
        let frame = encode_frame_bytes(direction, chdr, ahdr, payload.as_slice());
        if send_all(&socket, &frame).is_err() {
            debug_log("router-io: forward send failed");
            return Err(Error::Crypto);
        }
        debug_log_usize("router-io: forward frame_len", frame.len());
        let _ = socket.close();
        Ok(())
    }
}

pub struct UserlandExitTransport {
    sessions: BTreeMap<u64, TcpSocket>,
}

impl UserlandExitTransport {
    pub fn new() -> Self {
        Self {
            sessions: BTreeMap::new(),
        }
    }
}

impl ExitTransport for UserlandExitTransport {
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

        let ip = match addr {
            IpAddr::V4(octets) => *octets,
            IpAddr::V6(_) => return Err(Error::NotImplemented),
        };

        debug_log("router-io: exit request start");
        debug_log_addr("router-io: exit addr", ip, port);
        debug_log_usize("router-io: exit req_len", request.len());
        debug_log_preview("router-io: exit req", request);
        let socket = TcpSocket::new().map_err(|_| Error::Crypto)?;
        if connect_ipv4(&socket, ip, port).is_err() {
            debug_log("router-io: exit connect failed");
            return Err(Error::Crypto);
        }
        debug_log("router-io: exit connected");
        if send_all(&socket, request).is_err() {
            debug_log("router-io: exit send failed");
            return Err(Error::Crypto);
        }
        debug_log("router-io: exit request sent");
        let response = recv_to_idle(&socket)?;
        debug_log_usize("router-io: exit rsp_len", response.len());
        let _ = socket.close();
        Ok(response)
    }
}

impl UserlandExitTransport {
    fn handle_stream_frame(
        &mut self,
        addr: &IpAddr,
        port: u16,
        frame: StreamFrame<'_>,
    ) -> core::result::Result<Vec<u8>, Error> {
        let ip = match addr {
            IpAddr::V4(octets) => *octets,
            IpAddr::V6(_) => return Err(Error::NotImplemented),
        };

        match frame.op {
            StreamOp::Open => {
                debug_log("router-io: stream open start");
                debug_log_addr("router-io: stream open addr", ip, port);
                debug_log_u64("router-io: stream open sid", frame.session_id);
                if !self.sessions.contains_key(&frame.session_id) {
                    let socket = TcpSocket::new().map_err(|_| Error::Crypto)?;
                    if connect_ipv4(&socket, ip, port).is_err() {
                        debug_log("router-io: stream open connect failed");
                        return Err(Error::Crypto);
                    }
                    self.sessions.insert(frame.session_id, socket);
                }
                debug_log("router-io: stream open ok");
                Ok(Vec::new())
            }
            StreamOp::Data => {
                debug_log("router-io: stream data start");
                debug_log_u64("router-io: stream data sid", frame.session_id);
                debug_log_usize("router-io: stream data len", frame.data.len());
                if frame.data.is_empty() {
                    debug_log("router-io: stream data mode=poll");
                } else {
                    debug_log("router-io: stream data mode=push");
                }
                if !self.sessions.contains_key(&frame.session_id) {
                    debug_log("router-io: stream data for unknown session");
                    return Err(Error::PolicyViolation);
                }
                let socket = self.sessions.get(&frame.session_id).ok_or(Error::Crypto)?;
                if !frame.data.is_empty() && send_all(socket, frame.data).is_err() {
                    debug_log("router-io: stream data send failed");
                    return Err(Error::Crypto);
                }
                match recv_available(socket) {
                    Ok(bytes) => {
                        debug_log_usize("router-io: stream data rsp_len", bytes.len());
                        Ok(bytes)
                    }
                    Err(err) => {
                        debug_log("router-io: stream data recv failed");
                        Err(err)
                    }
                }
            }
            StreamOp::Close => {
                debug_log("router-io: stream close");
                debug_log_u64("router-io: stream close sid", frame.session_id);
                if let Some(socket) = self.sessions.remove(&frame.session_id) {
                    let _ = socket.close();
                }
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
    if req.len() < STREAM_DATA_OFFSET {
        return None;
    }
    if req.get(..4) != Some(b"HRS1") {
        return None;
    }
    let op = match req[4] {
        1 => StreamOp::Open,
        2 => StreamOp::Data,
        3 => StreamOp::Close,
        _ => return None,
    };
    let data_len = u16::from_be_bytes([req[6], req[7]]) as usize;
    let mut sid = [0u8; 8];
    sid.copy_from_slice(&req[8..16]);
    let session_id = u64::from_be_bytes(sid);
    let data_end = STREAM_DATA_OFFSET.checked_add(data_len)?;
    if data_end > req.len() {
        return None;
    }
    Some(StreamFrame {
        op,
        session_id,
        data: &req[STREAM_DATA_OFFSET..data_end],
    })
}

fn connect_ipv4(
    socket: &TcpSocket,
    ip: [u8; 4],
    port: u16,
) -> core::result::Result<(), Error> {
    let mut state = socket.connect(ip, port).map_err(|_| Error::Crypto)?;
    let mut spins = 0u32;
    while state == ConnectState::InProgress {
        spins = spins.saturating_add(1);
        if spins > 2000 {
            return Err(Error::Crypto);
        }
        sys::sleep(1);
        state = socket.connect(ip, port).map_err(|_| Error::Crypto)?;
    }
    Ok(())
}

fn debug_log(msg: &str) {
    let _ = sys::write(1, msg.as_bytes());
    let _ = sys::write(1, b"\n");
}

fn debug_log_usize(prefix: &str, value: usize) {
    let _ = sys::write(1, prefix.as_bytes());
    let _ = sys::write(1, b"=");
    write_decimal(value as u64);
    let _ = sys::write(1, b"\n");
}

fn debug_log_u64(prefix: &str, value: u64) {
    let _ = sys::write(1, prefix.as_bytes());
    let _ = sys::write(1, b"=");
    write_decimal(value);
    let _ = sys::write(1, b"\n");
}

fn debug_log_addr(prefix: &str, ip: [u8; 4], port: u16) {
    let _ = sys::write(1, prefix.as_bytes());
    let _ = sys::write(1, b"=");
    write_decimal(ip[0] as u64);
    let _ = sys::write(1, b".");
    write_decimal(ip[1] as u64);
    let _ = sys::write(1, b".");
    write_decimal(ip[2] as u64);
    let _ = sys::write(1, b".");
    write_decimal(ip[3] as u64);
    let _ = sys::write(1, b":");
    write_decimal(port as u64);
    let _ = sys::write(1, b"\n");
}

fn debug_log_preview(prefix: &str, bytes: &[u8]) {
    let _ = sys::write(1, prefix.as_bytes());
    let _ = sys::write(1, b"=");
    let limit = core::cmp::min(bytes.len(), 48);
    for &b in &bytes[..limit] {
        let ch = if (0x20..=0x7e).contains(&b) { b } else { b'.' };
        let _ = sys::write(1, &[ch]);
    }
    let _ = sys::write(1, b"\n");
}

fn write_decimal(mut value: u64) {
    let mut buf = [0u8; 20];
    let mut i = 0usize;
    if value == 0 {
        let _ = sys::write(1, b"0");
        return;
    }
    while value > 0 && i < buf.len() {
        buf[i] = b'0' + (value % 10) as u8;
        value /= 10;
        i += 1;
    }
    buf[..i].reverse();
    let _ = sys::write(1, &buf[..i]);
}

fn send_all(socket: &TcpSocket, buf: &[u8]) -> core::result::Result<(), Error> {
    let mut offset = 0usize;
    let mut spins = 0u32;
    while offset < buf.len() {
        let written = socket.send(&buf[offset..]).map_err(|_| Error::Crypto)?;
        if written == 0 {
            spins = spins.saturating_add(1);
            if spins > 4096 {
                return Err(Error::Crypto);
            }
            sys::sleep(1);
            continue;
        }
        spins = 0;
        offset += written;
    }
    Ok(())
}

fn recv_to_idle(socket: &TcpSocket) -> core::result::Result<Vec<u8>, Error> {
    let mut response = Vec::new();
    let mut buf = [0u8; 512];
    let mut idle_spins = 0u32;
    let idle_limit_empty = 10_000u32;
    let idle_limit_after_data = 200u32;
    loop {
        match socket.recv(&mut buf) {
            Ok(0) => {
                idle_spins = idle_spins.saturating_add(1);
                let limit = if response.is_empty() {
                    idle_limit_empty
                } else {
                    idle_limit_after_data
                };
                if idle_spins > limit {
                    break;
                }
                sys::sleep(1);
            }
            Ok(n) => {
                idle_spins = 0;
                response.extend_from_slice(&buf[..n]);
            }
            Err(_) => return Err(Error::Crypto),
        }
    }
    Ok(response)
}

fn recv_available(socket: &TcpSocket) -> core::result::Result<Vec<u8>, Error> {
    let mut response = Vec::new();
    let mut buf = [0u8; 2048];
    let mut idle_spins = 0u32;
    // Tunnel mode is polled repeatedly by the proxy; return quickly when
    // no bytes are currently available so source-side response listeners
    // do not timeout before this call returns.
    let idle_limit_empty = 300u32;
    let idle_limit_after_data = 80u32;
    loop {
        match socket.recv(&mut buf) {
            Ok(0) => {
                idle_spins = idle_spins.saturating_add(1);
                let limit = if response.is_empty() {
                    idle_limit_empty
                } else {
                    idle_limit_after_data
                };
                if idle_spins > limit {
                    break;
                }
                sys::sleep(1);
            }
            Ok(n) => {
                idle_spins = 0;
                debug_log_usize("router-io: stream recv chunk", n);
                response.extend_from_slice(&buf[..n]);
            }
            Err(_) => {
                debug_log("router-io: stream recv syscall error");
                return Err(Error::Crypto);
            }
        }
    }
    debug_log_u64("router-io: stream recv idle_spins", idle_spins as u64);
    Ok(response)
}
