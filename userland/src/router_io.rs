#![allow(dead_code)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as FmtWrite;

use crate::socket::{ConnectState, TcpListener, TcpSocket};
use crate::sys;
use hornet::forward::Forward;
use hornet::node::ExitTransport;
use hornet::router::io::{encode_frame_bytes, read_incoming_packet, IncomingPacket, PacketListener, PacketReader};
use hornet::routing::{self, IpAddr, RouteElem};
use hornet::types::{Ahdr, Chdr, Error, PacketDirection, Result, RoutingSegment, Sv};

pub struct UserlandPacketListener {
    listener: TcpListener,
    sv: Sv,
}

impl UserlandPacketListener {
    pub fn listen(port: u16, sv: Sv) -> Result<Self> {
        let listener = TcpListener::listen(port).map_err(|_| Error::Crypto)?;
        Ok(Self { listener, sv })
    }

    pub fn update_sv(&mut self, sv: Sv) {
        self.sv = sv;
    }
}

impl PacketListener for UserlandPacketListener {
    fn next(&mut self) -> Result<Option<IncomingPacket>> {
        match self.listener.accept().map_err(|_| Error::Crypto)? {
            None => Ok(None),
            Some(mut socket) => {
                log_line("listener: accepted");
                log_line("listener: reading packet");
                let packet = match read_incoming_packet(&mut socket, self.sv) {
                    Ok(packet) => packet,
                    Err(err) => {
                        log_args(format_args!("listener: read error {:?}", err));
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
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        log_args(format_args!("reader: read_exact {} bytes", buf.len()));
        let mut offset = 0usize;
        let mut spins = 0u32;
        while offset < buf.len() {
            let read = self
                .recv(&mut buf[offset..])
                .map_err(|_| Error::Crypto)?;
            log_args(format_args!("reader: recv {} bytes", read));
            if read == 0 {
                return Err(Error::Crypto);
            }
            offset += read;
            spins = spins.saturating_add(1);
            if spins > 1024 {
                log_line("reader: too many recv iterations");
                return Err(Error::Crypto);
            }
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
    ) -> Result<()> {
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

        let socket = TcpSocket::new().map_err(|_| Error::Crypto)?;
        let addr = format_ipv4(ip, port);
        log_args(format_args!("forward: connect {}", addr));
        if connect_ipv4(&socket, ip, port, "forward").is_err() {
            log_args(format_args!("forward: connect failed {}", addr));
            return Err(Error::Crypto);
        }
        let frame = encode_frame_bytes(direction, chdr, ahdr, payload.as_slice());
        if send_all(&socket, &frame).is_err() {
            log_args(format_args!("forward: send failed {}", addr));
            return Err(Error::Crypto);
        }
        log_args(format_args!(
            "forward: sent {} bytes -> {}",
            frame.len(),
            addr
        ));
        let _ = socket.close();
        Ok(())
    }
}

pub struct UserlandExitTransport;

impl UserlandExitTransport {
    pub fn new() -> Self {
        Self
    }
}

impl ExitTransport for UserlandExitTransport {
    fn send(&mut self, addr: &IpAddr, port: u16, tls: bool, request: &[u8]) -> Result<Vec<u8>> {
        if tls {
            return Err(Error::NotImplemented);
        }

        let ip = match addr {
            IpAddr::V4(octets) => *octets,
            IpAddr::V6(_) => return Err(Error::NotImplemented),
        };

        let socket = TcpSocket::new().map_err(|_| Error::Crypto)?;
        let addr = format_ipv4(ip, port);
        log_args(format_args!("exit: connect {}", addr));
        if connect_ipv4(&socket, ip, port, "exit").is_err() {
            log_args(format_args!("exit: connect failed {}", addr));
            return Err(Error::Crypto);
        }
        if send_all(&socket, request).is_err() {
            log_args(format_args!("exit: send failed {}", addr));
            return Err(Error::Crypto);
        }
        let response = recv_to_idle(&socket)?;
        log_args(format_args!(
            "exit: response {} bytes from {}",
            response.len(),
            addr
        ));
        let _ = socket.close();
        Ok(response)
    }
}

fn connect_ipv4(socket: &TcpSocket, ip: [u8; 4], port: u16, label: &str) -> Result<()> {
    let mut state = socket.connect(ip, port).map_err(|_| Error::Crypto)?;
    let mut spins = 0u32;
    while state == ConnectState::InProgress {
        spins = spins.saturating_add(1);
        if spins > 2000 {
            log_args(format_args!(
                "{}: connect timeout {}",
                label,
                format_ipv4(ip, port)
            ));
            return Err(Error::Crypto);
        }
        sys::sleep(1);
        state = socket.connect(ip, port).map_err(|_| Error::Crypto)?;
    }
    Ok(())
}

fn send_all(socket: &TcpSocket, buf: &[u8]) -> Result<()> {
    let mut offset = 0usize;
    while offset < buf.len() {
        let written = socket.send(&buf[offset..]).map_err(|_| Error::Crypto)?;
        if written == 0 {
            return Err(Error::Crypto);
        }
        offset += written;
    }
    Ok(())
}

fn recv_to_idle(socket: &TcpSocket) -> Result<Vec<u8>> {
    let mut response = Vec::new();
    let mut buf = [0u8; 512];
    let mut idle_spins = 0u32;
    loop {
        match socket.recv(&mut buf) {
            Ok(0) => {
                idle_spins = idle_spins.saturating_add(1);
                if idle_spins > 200 {
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

fn format_ipv4(ip: [u8; 4], port: u16) -> String {
    let mut buf = String::new();
    let _ = FmtWrite::write_fmt(
        &mut buf,
        format_args!("{}.{}.{}.{}:{}", ip[0], ip[1], ip[2], ip[3], port),
    );
    buf
}

fn log_line(msg: &str) {
    let _ = sys::write(1, msg.as_bytes());
    let _ = sys::write(1, b"\n");
}

fn log_args(args: core::fmt::Arguments<'_>) {
    let mut buf = String::new();
    let _ = FmtWrite::write_fmt(&mut buf, args);
    log_line(&buf);
}
