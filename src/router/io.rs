#[cfg(feature = "std")]
use crate::forward::Forward;
#[cfg(feature = "std")]
use crate::routing::{self, IpAddr, RouteElem};
use crate::types::{Ahdr, Chdr, Error, PacketDirection, PacketType, Result, Sv};
#[cfg(feature = "std")]
use crate::types::RoutingSegment;
use alloc::vec;
use alloc::vec::Vec;
#[cfg(feature = "std")]
use alloc::string::String;
#[cfg(feature = "std")]
use core::fmt::Write as FmtWrite;

pub struct IncomingPacket {
    pub direction: PacketDirection,
    pub sv: Sv,
    pub chdr: Chdr,
    pub ahdr: Ahdr,
    pub payload: Vec<u8>,
}

pub trait PacketListener {
    fn next(&mut self) -> Result<Option<IncomingPacket>>;
}

pub trait PacketReader {
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<()>;
}

fn packet_type_to_u8(pt: PacketType) -> u8 {
    match pt {
        PacketType::Setup => 0,
        PacketType::Data => 1,
    }
}

fn packet_type_from_u8(value: u8) -> Result<PacketType> {
    match value {
        0 => Ok(PacketType::Setup),
        1 => Ok(PacketType::Data),
        _ => Err(Error::Length),
    }
}

fn direction_from_u8(value: u8) -> Result<PacketDirection> {
    match value {
        0 => Ok(PacketDirection::Forward),
        1 => Ok(PacketDirection::Backward),
        _ => Err(Error::Length),
    }
}

fn direction_to_u8(direction: PacketDirection) -> u8 {
    match direction {
        PacketDirection::Forward => 0,
        PacketDirection::Backward => 1,
    }
}

pub fn encode_frame_bytes(
    direction: PacketDirection,
    chdr: &Chdr,
    ahdr: &Ahdr,
    payload: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(4 + 16 + 8 + ahdr.bytes.len() + payload.len());
    frame.push(direction_to_u8(direction));
    frame.push(packet_type_to_u8(chdr.typ));
    frame.push(chdr.hops);
    frame.push(0);
    frame.extend_from_slice(&chdr.specific);
    frame.extend_from_slice(&(ahdr.bytes.len() as u32).to_le_bytes());
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(&ahdr.bytes);
    frame.extend_from_slice(payload);
    frame
}

pub fn read_incoming_packet<R: PacketReader>(reader: &mut R, sv: Sv) -> Result<IncomingPacket> {
    let mut header = [0u8; 4];
    reader.read_exact(&mut header)?;
    let direction = direction_from_u8(header[0])?;
    let pkt_type = packet_type_from_u8(header[1])?;
    let hops = header[2];
    let mut specific = [0u8; 16];
    reader.read_exact(&mut specific)?;
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let ahdr_len = u32::from_le_bytes(len_buf) as usize;
    reader.read_exact(&mut len_buf)?;
    let payload_len = u32::from_le_bytes(len_buf) as usize;
    let mut ahdr_bytes = vec![0u8; ahdr_len];
    if ahdr_len > 0 {
        reader.read_exact(&mut ahdr_bytes)?;
    }
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        reader.read_exact(&mut payload)?;
    }
    Ok(IncomingPacket {
        direction,
        sv,
        chdr: Chdr {
            typ: pkt_type,
            hops,
            specific,
        },
        ahdr: Ahdr { bytes: ahdr_bytes },
        payload,
    })
}

#[cfg(feature = "std")]
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

#[cfg(feature = "std")]
impl<T: std::io::Read> PacketReader for T {
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        std::io::Read::read_exact(self, buf).map_err(|_| Error::Crypto)
    }
}

#[cfg(feature = "std")]
pub struct TcpPacketListener {
    listener: std::net::TcpListener,
    sv: Sv,
}

#[cfg(feature = "std")]
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

#[cfg(feature = "std")]
impl PacketListener for TcpPacketListener {
    fn next(&mut self) -> Result<Option<IncomingPacket>> {
        let (mut stream, _) = self.listener.accept().map_err(|_| Error::Crypto)?;
        let packet = read_incoming_packet(&mut stream, self.sv)?;
        Ok(Some(packet))
    }
}

#[cfg(feature = "std")]
pub struct TcpForward;

#[cfg(feature = "std")]
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

#[cfg(feature = "std")]
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
                let mut stream = std::net::TcpStream::connect(addr_str).map_err(|_| Error::Crypto)?;
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
                let mut stream = std::net::TcpStream::connect(addr_str).map_err(|_| Error::Crypto)?;
                let frame = encode_frame_bytes(direction, chdr, ahdr, payload.as_slice());
                std::io::Write::write_all(&mut stream, &frame).map_err(|_| Error::Crypto)
            }
        }
    }
}

#[cfg(all(test, feature = "std"))]
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
    fn frame_encoding_roundtrip_preserves_fields() {
        let sv = Sv([0x44; 16]);
        let chdr = Chdr {
            typ: PacketType::Data,
            hops: 3,
            specific: [0xAB; 16],
        };
        let ahdr_bytes = vec![0x10, 0x20, 0x30, 0x40];
        let ahdr = Ahdr {
            bytes: ahdr_bytes.clone(),
        };
        let payload = vec![0x55, 0x66, 0x77];
        let frame = encode_frame_bytes(PacketDirection::Backward, &chdr, &ahdr, payload.as_slice());
        let mut cursor = Cursor::new(frame);
        let packet = read_incoming_packet(&mut cursor, sv).expect("decode incoming");
        assert_eq!(packet.direction, PacketDirection::Backward);
        assert_eq!(packet.chdr.typ, PacketType::Data);
        assert_eq!(packet.chdr.hops, 3);
        assert_eq!(packet.chdr.specific, [0xAB; 16]);
        assert_eq!(packet.ahdr.bytes, ahdr_bytes);
        assert_eq!(packet.payload, payload);
    }
}
