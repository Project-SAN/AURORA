use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as FmtWrite;

use crate::forward::Forward;
use crate::routing::{self, IpAddr, RouteElem};
use crate::types::{Ahdr, Chdr, Error, PacketDirection, Result, RoutingSegment, Sv};

use super::{
    encode_frame_bytes, read_incoming_packet, IncomingPacket, PacketListener, PacketReader,
};

fn format_ip(addr: &IpAddr, port: u16) -> String {
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

impl<T: std::io::Read> PacketReader for T {
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        std::io::Read::read_exact(self, buf).map_err(|_| Error::Crypto)
    }
}

pub struct TcpPacketListener {
    listener: std::net::TcpListener,
    sv: Sv,
}

impl TcpPacketListener {
    pub fn bind(addr: &str, sv: Sv) -> std::io::Result<Self> {
        let listener = std::net::TcpListener::bind(addr)?;
        listener.set_nonblocking(false)?;
        Ok(Self { listener, sv })
    }

    pub fn update_sv(&mut self, sv: Sv) {
        self.sv = sv;
    }
}

impl PacketListener for TcpPacketListener {
    fn next(&mut self) -> Result<Option<IncomingPacket>> {
        let (mut stream, _) = self.listener.accept().map_err(|_| Error::Crypto)?;
        let packet = read_incoming_packet(&mut stream, self.sv)?;
        Ok(Some(packet))
    }
}

pub struct TcpForward;

impl TcpForward {
    pub fn new() -> Self {
        Self
    }

    #[cfg(test)]
    fn resolve_next_hop(segment: &RoutingSegment) -> Result<String> {
        let elems = routing::elems_from_segment(segment).map_err(|_| Error::Length)?;
        let hop = elems.first().ok_or(Error::Length)?;
        match hop {
            RouteElem::NextHop { addr, port } => Ok(format_ip(addr, *port)),
            RouteElem::ExitTcp { addr, port, .. } => Ok(format_ip(addr, *port)),
        }
    }
}

impl Forward for TcpForward {
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

        match hop {
            RouteElem::NextHop { addr, port } => {
                let addr_str = format_ip(addr, *port);
                eprintln!(
                    "[FORWARD] send {:?} -> {} (payload={}, ahdr={})",
                    direction,
                    addr_str,
                    payload.len(),
                    ahdr.bytes.len()
                );
                let mut stream =
                    std::net::TcpStream::connect(addr_str).map_err(|_| Error::Crypto)?;
                let frame = encode_frame_bytes(direction, chdr, ahdr, payload.as_slice());
                std::io::Write::write_all(&mut stream, &frame).map_err(|_| Error::Crypto)
            }
            RouteElem::ExitTcp { addr, port, .. } => {
                let addr_str = format_ip(addr, *port);
                eprintln!(
                    "[FORWARD] send {:?} -> {} (payload={}, ahdr={})",
                    direction,
                    addr_str,
                    payload.len(),
                    ahdr.bytes.len()
                );
                let mut stream =
                    std::net::TcpStream::connect(addr_str).map_err(|_| Error::Crypto)?;
                let frame = encode_frame_bytes(direction, chdr, ahdr, payload.as_slice());
                std::io::Write::write_all(&mut stream, &frame).map_err(|_| Error::Crypto)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::{self, IpAddr as RouteIp, RouteElem};
    use crate::types::{PacketType, Sv};
    use std::io::Cursor;

    #[test]
    fn tcp_forward_resolves_first_hop_from_multihop_segment() {
        let segment = routing::segment_from_elems(&[
            RouteElem::NextHop {
                addr: RouteIp::V4([10, 0, 0, 1]),
                port: 9_000,
            },
            RouteElem::ExitTcp {
                addr: RouteIp::V4([203, 0, 113, 5]),
                port: 443,
                tls: true,
            },
        ]);
        let addr = TcpForward::resolve_next_hop(&segment).expect("first hop");
        assert_eq!(addr, "10.0.0.1:9000");
    }

    #[test]
    fn encode_then_decode_roundtrip() {
        let mut chdr = Chdr {
            typ: PacketType::Data,
            hops: 1,
            specific: [0u8; 16],
        };
        chdr.specific[0] = 0xAA;
        let ahdr = Ahdr {
            bytes: vec![0xBB, 0xCC],
        };
        let payload = vec![0xDD, 0xEE, 0xFF];
        let frame = encode_frame_bytes(PacketDirection::Forward, &chdr, &ahdr, &payload);
        let mut cursor = Cursor::new(frame);
        let incoming = read_incoming_packet(&mut cursor, Sv([0x11; 16])).expect("decode");
        assert_eq!(incoming.direction, PacketDirection::Forward);
        assert_eq!(incoming.chdr.hops, 1);
        assert_eq!(incoming.ahdr.bytes, ahdr.bytes);
        assert_eq!(incoming.payload, payload);
    }
}
