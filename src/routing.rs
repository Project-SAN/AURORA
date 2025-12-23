//! Routing TLV encoding/decoding for no_std environments.
//! Provides a typed representation and conversion to/from `types::RoutingSegment` bytes.
use crate::types::{Error, Result, RoutingSegment};
use alloc::vec::Vec;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IpAddr {
    V4([u8; 4]),
    V6([u8; 16]),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteElem {
    NextHop { addr: IpAddr, port: u16 },
    ExitTcp { addr: IpAddr, port: u16, tls: bool },
}

// TLV type identifiers
const T_NEXT_HOP4: u8 = 0x01;
const T_NEXT_HOP6: u8 = 0x02;
const T_EXIT_TCP4: u8 = 0x11;
const T_EXIT_TCP6: u8 = 0x12; // value layout includes flags (bit0: TLS)

fn be_u16(x: u16) -> [u8; 2] {
    x.to_be_bytes()
}
fn read_be_u16(b: &[u8]) -> u16 {
    let mut t = [0u8; 2];
    t.copy_from_slice(b);
    u16::from_be_bytes(t)
}

pub fn encode_elems(elems: &[RouteElem]) -> Vec<u8> {
    let mut out = Vec::new();
    for e in elems {
        match e {
            RouteElem::NextHop {
                addr: IpAddr::V4(ip),
                port,
            } => {
                out.push(T_NEXT_HOP4);
                out.push(6); // len
                out.extend_from_slice(ip);
                out.extend_from_slice(&be_u16(*port));
            }
            RouteElem::NextHop {
                addr: IpAddr::V6(ip),
                port,
            } => {
                out.push(T_NEXT_HOP6);
                out.push(18); // len
                out.extend_from_slice(ip);
                out.extend_from_slice(&be_u16(*port));
            }
            RouteElem::ExitTcp {
                addr: IpAddr::V4(ip),
                port,
                tls,
            } => {
                out.push(T_EXIT_TCP4);
                out.push(7); // flags(1) + ip4(4) + port(2)
                out.push(if *tls { 1 } else { 0 });
                out.extend_from_slice(ip);
                out.extend_from_slice(&be_u16(*port));
            }
            RouteElem::ExitTcp {
                addr: IpAddr::V6(ip),
                port,
                tls,
            } => {
                out.push(T_EXIT_TCP6);
                out.push(19); // flags(1) + ip6(16) + port(2)
                out.push(if *tls { 1 } else { 0 });
                out.extend_from_slice(ip);
                out.extend_from_slice(&be_u16(*port));
            }
        }
    }
    out
}

pub fn decode_elems(mut bytes: &[u8]) -> Result<Vec<RouteElem>> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 2 {
            return Err(Error::Length);
        }
        let t = bytes[0];
        let l = bytes[1] as usize;
        bytes = &bytes[2..];
        if t == 0 {
            if l != 0 {
                return Err(Error::Length);
            }
            if bytes.iter().any(|&b| b != 0) {
                return Err(Error::Length);
            }
            break;
        }
        if bytes.len() < l {
            return Err(Error::Length);
        }
        let val = &bytes[..l];
        bytes = &bytes[l..];
        match (t, l) {
            (T_NEXT_HOP4, 6) => {
                let mut ip = [0u8; 4];
                ip.copy_from_slice(&val[0..4]);
                let port = read_be_u16(&val[4..6]);
                out.push(RouteElem::NextHop {
                    addr: IpAddr::V4(ip),
                    port,
                });
            }
            (T_NEXT_HOP6, 18) => {
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&val[0..16]);
                let port = read_be_u16(&val[16..18]);
                out.push(RouteElem::NextHop {
                    addr: IpAddr::V6(ip),
                    port,
                });
            }
            (T_EXIT_TCP4, 7) => {
                let flags = val[0];
                let mut ip = [0u8; 4];
                ip.copy_from_slice(&val[1..5]);
                let port = read_be_u16(&val[5..7]);
                out.push(RouteElem::ExitTcp {
                    addr: IpAddr::V4(ip),
                    port,
                    tls: (flags & 1) != 0,
                });
            }
            (T_EXIT_TCP6, 19) => {
                let flags = val[0];
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&val[1..17]);
                let port = read_be_u16(&val[17..19]);
                out.push(RouteElem::ExitTcp {
                    addr: IpAddr::V6(ip),
                    port,
                    tls: (flags & 1) != 0,
                });
            }
            _ => return Err(Error::Length),
        }
    }
    Ok(out)
}

pub fn segment_from_elems(elems: &[RouteElem]) -> RoutingSegment {
    RoutingSegment(encode_elems(elems))
}

pub fn elems_from_segment(seg: &RoutingSegment) -> Result<Vec<RouteElem>> {
    decode_elems(&seg.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_simple_v4() {
        let elems = [RouteElem::NextHop {
            addr: IpAddr::V4([192, 168, 1, 1]),
            port: 9000,
        }];
        let seg = segment_from_elems(&elems);
        let parsed = elems_from_segment(&seg).unwrap();
        assert_eq!(parsed, elems);
    }

    #[test]
    fn roundtrip_mixed_v6_and_exit_tls() {
        let elems = [
            RouteElem::NextHop {
                addr: IpAddr::V6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
                port: 1234,
            },
            RouteElem::ExitTcp {
                addr: IpAddr::V4([93, 184, 216, 34]),
                port: 443,
                tls: true,
            }, // example.com
        ];
        let seg = segment_from_elems(&elems);
        let parsed = elems_from_segment(&seg).unwrap();
        assert_eq!(parsed, elems);
    }

    #[test]
    fn reject_truncated() {
        let mut bytes = alloc::vec![T_NEXT_HOP4, 6, 10, 0, 0, 0, 0]; // too short (missing 1 byte of port)
        assert!(decode_elems(&bytes).is_err());
        // invalid TLV len/type combination
        bytes = alloc::vec![T_NEXT_HOP4, 5, 0, 0, 0, 0, 0];
        assert!(decode_elems(&bytes).is_err());
    }

    #[test]
    fn decode_ignores_zero_padding() {
        let base = RouteElem::NextHop {
            addr: IpAddr::V4([127, 0, 0, 1]),
            port: 7102,
        };
        let mut bytes = encode_elems(&[base.clone()]);
        bytes.resize(bytes.len() + 4, 0); // pad to simulate FS zero padding
        let parsed = decode_elems(&bytes).expect("decode padded segment");
        assert_eq!(parsed, alloc::vec![base]);
    }
}
