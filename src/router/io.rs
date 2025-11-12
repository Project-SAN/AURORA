use crate::forward::Forward;
use crate::router::runtime::PacketDirection;
use crate::routing::{self, IpAddr, RouteElem};
use crate::types::{Ahdr, Chdr, Error, PacketType, Result, RoutingSegment, Sv};
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as FmtWrite;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

pub struct IncomingPacket {
    pub direction: PacketDirection,
    pub sv: Sv,
    pub chdr: Chdr,
    pub ahdr: Ahdr,
    pub payload: Vec<u8>,
}

pub trait PacketListener {
    fn next(&mut self) -> std::io::Result<IncomingPacket>;
}

fn packet_type_to_u8(pt: PacketType) -> u8 {
    match pt {
        PacketType::Setup => 0,
        PacketType::Data => 1,
    }
}

fn packet_type_from_u8(value: u8) -> std::io::Result<PacketType> {
    match value {
        0 => Ok(PacketType::Setup),
        1 => Ok(PacketType::Data),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unknown packet type",
        )),
    }
}

fn direction_from_u8(value: u8) -> std::io::Result<PacketDirection> {
    match value {
        0 => Ok(PacketDirection::Forward),
        1 => Ok(PacketDirection::Backward),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unknown direction",
        )),
    }
}

fn direction_to_u8(direction: PacketDirection) -> u8 {
    match direction {
        PacketDirection::Forward => 0,
        PacketDirection::Backward => 1,
    }
}

pub struct TcpPacketListener {
    listener: TcpListener,
    sv: Sv,
}

impl TcpPacketListener {
    pub fn bind(addr: &str, sv: Sv) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(false)?;
        Ok(Self { listener, sv })
    }

    pub fn update_sv(&mut self, sv: Sv) {
        self.sv = sv;
    }
}

impl PacketListener for TcpPacketListener {
    fn next(&mut self) -> std::io::Result<IncomingPacket> {
        let (mut stream, _) = self.listener.accept()?;
        let mut header = [0u8; 4];
        stream.read_exact(&mut header)?;
        let direction = direction_from_u8(header[0])?;
        let pkt_type = packet_type_from_u8(header[1])?;
        let hops = header[2];
        let mut specific = [0u8; 16];
        stream.read_exact(&mut specific)?;
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf)?;
        let ahdr_len = u32::from_le_bytes(len_buf) as usize;
        stream.read_exact(&mut len_buf)?;
        let payload_len = u32::from_le_bytes(len_buf) as usize;
        let mut ahdr_bytes = vec![0u8; ahdr_len];
        if ahdr_len > 0 {
            stream.read_exact(&mut ahdr_bytes)?;
        }
        let mut payload = vec![0u8; payload_len];
        if payload_len > 0 {
            stream.read_exact(&mut payload)?;
        }
        let chdr = Chdr {
            typ: pkt_type,
            hops,
            specific,
        };
        let ahdr = Ahdr { bytes: ahdr_bytes };
        Ok(IncomingPacket {
            direction,
            sv: self.sv,
            chdr,
            ahdr,
            payload,
        })
    }
}

pub struct TcpForward;

impl TcpForward {
    pub fn new() -> Self {
        Self
    }

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
    ) -> Result<()> {
        let addr = Self::resolve_next_hop(rseg)?;
        let mut stream = TcpStream::connect(addr).map_err(|_| Error::Crypto)?;
        let mut frame = Vec::new();
        frame.push(direction_to_u8(PacketDirection::Forward));
        frame.push(packet_type_to_u8(chdr.typ));
        frame.push(chdr.hops);
        frame.push(0);
        frame.extend_from_slice(&chdr.specific);
        frame.extend_from_slice(&(ahdr.bytes.len() as u32).to_le_bytes());
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(&ahdr.bytes);
        frame.extend_from_slice(payload);
        stream.write_all(&frame).map_err(|_| Error::Crypto)
    }
}

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
