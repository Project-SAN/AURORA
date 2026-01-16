use crate::types::{Ahdr, Chdr, Error, PacketDirection, PacketType, Result, Sv};
use alloc::vec;
use alloc::vec::Vec;

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
mod io_std;
#[cfg(feature = "std")]
pub use io_std::{TcpForward, TcpPacketListener};
