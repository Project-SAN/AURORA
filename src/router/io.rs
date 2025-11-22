use crate::forward::Forward;
use crate::routing::{self, IpAddr, RouteElem};
use crate::types::{Ahdr, Chdr, Error, PacketType, Result, RoutingSegment, Sv, Exp, PacketDirection};
use crate::packet::{ahdr::proc_ahdr, onion};
use crate::policy::PolicyCapsule;
use std::time::{SystemTime, UNIX_EPOCH};
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
        read_incoming_packet(&mut stream, self.sv)
    }
}

pub struct TcpForward {
    sv: Sv,
}

impl TcpForward {
    pub fn new(sv: Sv) -> Self {
        Self { sv }
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
        direction: PacketDirection,
    ) -> Result<()> {
        let elems = routing::elems_from_segment(rseg).map_err(|_| Error::Length)?;
        let hop = elems.first().ok_or(Error::Length)?;

        match hop {
            RouteElem::NextHop { addr, port } => {
                let addr_str = format_ip(addr, *port);
                let mut stream = TcpStream::connect(addr_str).map_err(|_| Error::Crypto)?;
                let frame = encode_frame_bytes(direction, chdr, ahdr, payload.as_slice());
                stream.write_all(&frame).map_err(|_| Error::Crypto)
            }
            RouteElem::ExitTcp { addr, port, .. } => {
                eprintln!("[EXIT] Processing ExitTcp to {}:{}", format_ip(addr, *port), port);
                eprintln!("[EXIT] Payload length: {}", payload.len());
                // Exit Node Logic
                // 1. Extract Backward AHDR from payload
                // Payload structure: [Capsule][CanonicalBytes][AHDR_Len][AHDR][RealPayload]
                
                // Skip Capsule
                let (_, cap_len) = PolicyCapsule::decode(payload).unwrap_or((PolicyCapsule {
                    policy_id: [0; 32],
                    version: 0,
                    proof: vec![],
                    commitment: vec![],
                    aux: vec![],
                }, 0));
                
                if payload.len() < cap_len {
                    return Err(Error::Length);
                }
                let after_capsule = &payload[cap_len..];
                
                // Skip Canonical Bytes
                let canon_len = parse_canonical_len(after_capsule)?;
                if after_capsule.len() < canon_len {
                    return Err(Error::Length);
                }
                let inner = &after_capsule[canon_len..];
                eprintln!("[EXIT] Skipped capsule: {} bytes, canonical: {} bytes", cap_len, canon_len);
                eprintln!("[EXIT] Remaining inner length: {}", inner.len());

                if inner.len() < 4 {
                    return Err(Error::Length);
                }
                let ahdr_len = u32::from_le_bytes([inner[0], inner[1], inner[2], inner[3]]) as usize;
                if inner.len() < 4 + ahdr_len {
                    return Err(Error::Length);
                }
                let backward_ahdr_bytes = inner[4..4 + ahdr_len].to_vec();
                let backward_ahdr = Ahdr { bytes: backward_ahdr_bytes };
                let real_payload = &inner[4 + ahdr_len..];
                eprintln!("[EXIT] Extracted backward AHDR: {} bytes, real payload: {} bytes", ahdr_len, real_payload.len());
                eprintln!("[EXIT] Real payload (first 100 bytes): {:?}", &real_payload[..real_payload.len().min(100)]);

                // 2. Connect to Target
                let addr_str = format_ip(addr, *port);
                eprintln!("[EXIT] Connecting to target: {}", addr_str);
                let mut stream = TcpStream::connect(addr_str).map_err(|e| {
                    eprintln!("[EXIT] Connection failed: {}", e);
                    Error::Crypto
                })?;
                eprintln!("[EXIT] Connected, sending {} bytes", real_payload.len());
                stream.write_all(real_payload).map_err(|e| {
                    eprintln!("[EXIT] Write failed: {}", e);
                    Error::Crypto
                })?;
                eprintln!("[EXIT] Request sent, reading response...");

                // 3. Read Response
                let mut response = Vec::new();
                stream.read_to_end(&mut response).map_err(|e| {
                    eprintln!("[EXIT] Read failed: {}", e);
                    Error::Crypto
                })?;
                eprintln!("[EXIT] Received response: {} bytes", response.len());
                eprintln!("[EXIT] Response (first 100 bytes): {:?}", &response[..response.len().min(100)]);

                // 4. Process Backward Path (First Hop / Exit)
                // We act as the first node in the backward path.
                // We need to process the AHDR to get the next hop (Middle) and add a layer.
                
                let now_secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                let now = Exp(now_secs as u32);
                
                eprintln!("[EXIT] Processing backward AHDR...");
                let res = proc_ahdr(&self.sv, &backward_ahdr, now)?;
                eprintln!("[EXIT] Backward AHDR processed, next hop segment: {} bytes", res.r.0.len());
                
                // Add onion layer
                // Use specific from original chdr? No, for backward path, we start with a fresh IV?
                // Or does the Client provide an IV?
                // The Client provided `iv` in `chdr.specific`.
                // But for backward path, we usually use the IV from the packet.
                // Since we are creating the packet, we can use a random IV or derived IV.
                // However, `process_data` uses `chdr.specific`.
                // Let's use a fresh zero IV or random?
                // The Client expects to decrypt. `decrypt_backward_payload` uses `iv0`.
                // The Client knows `iv0`? 
                // In `hornet_data_sender.rs`, `iv_resp = specific`.
                // So the Client uses whatever IV we send back in `specific`.
                // So we can generate a random IV here.
                
                let mut iv = [0u8; 16];
                // rand::thread_rng().fill_bytes(&mut iv); // Need rand
                // Or just use 0 for now, or derive from something.
                // Let's use 0s for simplicity or if we can't easily import rand.
                // Actually, `ahdr` processing gives `s`.
                // We should use `s` to encrypt.
                
                onion::add_layer(&res.s, &mut iv, &mut response)?;
                
                // 5. Send Backward Packet to Next Hop (res.r)
                // Construct Backward CHDR
                let backward_chdr = Chdr {
                    typ: PacketType::Data,
                    hops: chdr.hops, // Keep same hop count? Or 0? It doesn't matter much for forwarding.
                    specific: iv,
                };
                
                // Resolve next hop from res.r
                // Recursively call send? No, res.r is a NextHop segment.
                // We can just call send logic for NextHop.
                // But we can't call `self.send` easily because of borrow.
                // So just duplicate NextHop logic here.
                
                let next_elems = routing::elems_from_segment(&res.r).map_err(|_| Error::Length)?;
                let next_hop = next_elems.first().ok_or(Error::Length)?;
                
                if let RouteElem::NextHop { addr: next_addr, port: next_port } = next_hop {
                    let next_addr_str = format_ip(next_addr, *next_port);
                    let mut back_stream = TcpStream::connect(next_addr_str).map_err(|_| Error::Crypto)?;
                    let back_frame = encode_frame_bytes(
                        PacketDirection::Backward,
                        &backward_chdr,
                        &res.ahdr_next,
                        &response
                    );
                    eprintln!("[EXIT] Sending backward packet: AHDR {} bytes, payload {} bytes, total frame {} bytes", 
                              res.ahdr_next.bytes.len(), response.len(), back_frame.len());
                    back_stream.write_all(&back_frame).map_err(|_| Error::Crypto)?;
                    Ok(())
                } else {
                    Err(Error::NotImplemented)
                }
            }
        }
    }

}

fn parse_canonical_len(buf: &[u8]) -> Result<usize> {
    if buf.is_empty() {
        return Err(Error::Length);
    }
    let tag = buf[0];
    match tag {
        0x01 | 0x02 => { // Exact or Prefix
            if buf.len() < 5 { return Err(Error::Length); }
            let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
            Ok(1 + 4 + len)
        }
        0x03 => { // CIDR
            if buf.len() < 2 { return Err(Error::Length); }
            let ver = buf[1];
            match ver {
                4 => Ok(1 + 1 + 1 + 4),
                6 => Ok(1 + 1 + 1 + 16),
                _ => Err(Error::Length),
            }
        }
        0x04 => { // Range
            if buf.len() < 5 { return Err(Error::Length); }
            let len1 = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
            if buf.len() < 5 + len1 + 4 { return Err(Error::Length); }
            let len2 = u32::from_be_bytes([buf[5 + len1], buf[5 + len1 + 1], buf[5 + len1 + 2], buf[5 + len1 + 3]]) as usize;
            Ok(1 + 4 + len1 + 4 + len2)
        }
        _ => Err(Error::Length),
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

fn encode_frame_bytes(
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

fn read_incoming_packet<R: Read>(reader: &mut R, sv: Sv) -> std::io::Result<IncomingPacket> {
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
        assert_eq!(packet.sv.0, sv.0);
        assert!(matches!(packet.chdr.typ, PacketType::Data));
        assert_eq!(packet.chdr.hops, chdr.hops);
        assert_eq!(packet.chdr.specific, chdr.specific);
        assert_eq!(packet.ahdr.bytes, ahdr_bytes);
        assert_eq!(packet.payload, payload);
    }
}
