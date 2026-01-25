use crate::packet::payload::Payload;
use crate::setup::SetupPacket;
use crate::sphinx;
use crate::types::{Chdr, Error, Result, C_BLOCK};
use alloc::vec::Vec;

/// Encoded representation of a setup packet, suitable for sending on the wire.
pub struct EncodedSetup {
    pub header: Vec<u8>,
    pub payload: Vec<u8>,
}

/// Serialize a `SetupPacket` into `(header_bytes, payload_bytes)` where
/// the payload consists of the FS payload followed by TLVs, each prefixed
/// with a u16 length.
pub fn encode(packet: &SetupPacket) -> Result<EncodedSetup> {
    let header = sphinx::encode_header(&packet.shdr)?;
    let tlv_stream = encode_tlv_stream(&packet.tlvs)?;
    let mut payload = packet.payload.bytes.clone();
    payload.extend_from_slice(&tlv_stream);
    Ok(EncodedSetup { header, payload })
}

/// Deserialize a `SetupPacket` from the raw header/payload byte slices
/// provided by the transport.
pub fn decode(chdr: Chdr, header: &[u8], payload: &[u8]) -> Result<SetupPacket> {
    let shdr = sphinx::decode_header(header)?;
    let rmax = shdr.rmax;
    let fs_len = expected_payload_len(rmax);
    if payload.len() < fs_len {
        return Err(Error::Length);
    }
    let (fs_bytes, tlv_bytes) = payload.split_at(fs_len);
    let payload = Payload::from_bytes(fs_bytes.to_vec(), rmax)?;
    let tlvs = decode_tlv_stream(tlv_bytes)?;
    Ok(SetupPacket {
        chdr,
        shdr,
        payload,
        rmax,
        tlvs,
    })
}

fn encode_tlv_stream(tlvs: &[Vec<u8>]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for tlv in tlvs {
        let len = tlv.len();
        if len > u16::MAX as usize {
            return Err(Error::Length);
        }
        out.extend_from_slice(&(len as u16).to_be_bytes());
        out.extend_from_slice(tlv);
    }
    Ok(out)
}

fn decode_tlv_stream(bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut cursor = 0usize;
    let mut out = Vec::new();
    while cursor < bytes.len() {
        if bytes.len() - cursor < 2 {
            return Err(Error::Length);
        }
        let len = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
        cursor += 2;
        if bytes.len() - cursor < len {
            return Err(Error::Length);
        }
        out.push(bytes[cursor..cursor + len].to_vec());
        cursor += len;
    }
    Ok(out)
}

fn expected_payload_len(rmax: usize) -> usize {
    rmax * C_BLOCK
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup;
    use crate::types::{Exp, PacketType, RoutingSegment, Sv};
    use alloc::vec;
    use rand_core::{CryptoRng, RngCore};

    struct XorShift64(u64);
    impl RngCore for XorShift64 {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.try_fill_bytes(dest).unwrap()
        }
        fn try_fill_bytes(
            &mut self,
            dest: &mut [u8],
        ) -> core::result::Result<(), rand_core::Error> {
            let mut idx = 0;
            while idx < dest.len() {
                let v = self.next_u64().to_le_bytes();
                let take = core::cmp::min(8, dest.len() - idx);
                dest[idx..idx + take].copy_from_slice(&v[..take]);
                idx += take;
            }
            Ok(())
        }
    }
    impl CryptoRng for XorShift64 {}

    fn gen_node(seed: u64) -> ([u8; 32], [u8; 32], Sv, RoutingSegment) {
        let mut sk = [0u8; 32];
        let mut tmp = [0u8; 32];
        XorShift64(seed).try_fill_bytes(&mut tmp).unwrap();
        sk.copy_from_slice(&tmp);
        sk[0] &= 248;
        sk[31] &= 127;
        sk[31] |= 64;
        let pk = x25519_dalek::x25519(sk, x25519_dalek::X25519_BASEPOINT_BYTES);
        let mut svb = [0u8; 16];
        XorShift64(seed ^ 0x9e37_79b9)
            .try_fill_bytes(&mut svb)
            .unwrap();
        let rseg = RoutingSegment(vec![seed as u8; 8]);
        (sk, pk, Sv(svb), rseg)
    }

    #[test]
    fn encode_decode_roundtrip() {
        let mut rng = XorShift64(0xDEADBEEF);
        let hops = 2usize;
        let rmax = 3usize;
        let mut nodes = Vec::new();
        for i in 0..hops {
            nodes.push(gen_node(0x7000 + i as u64));
        }
        let pubs: Vec<[u8; 32]> = nodes.iter().map(|n| n.1).collect();
        let exp = Exp(42);
        let mut x_s = [0u8; 32];
        rng.fill_bytes(&mut x_s);
        x_s[0] &= 248;
        x_s[31] &= 127;
        x_s[31] |= 64;
        let mut state = setup::source_init(&x_s, &pubs, rmax, exp, &mut rng);
        state.packet.tlvs.push(vec![0xA1, 0x01, 0x02]);
        let encoded = encode(&state.packet).expect("encode");
        let mut chdr = crate::types::Chdr {
            typ: PacketType::Setup,
            hops: state.packet.chdr.hops,
            specific: state.packet.chdr.specific,
        };
        chdr.hops = state.packet.chdr.hops;
        let decoded = decode(chdr, &encoded.header, &encoded.payload).expect("decode setup packet");
        assert_eq!(decoded.rmax, state.packet.rmax);
        assert_eq!(decoded.payload.bytes, state.packet.payload.bytes);
        assert_eq!(decoded.tlvs, state.packet.tlvs);
        assert_eq!(decoded.shdr.alpha, state.packet.shdr.alpha);
        assert_eq!(decoded.shdr.beta, state.packet.shdr.beta);
        assert_eq!(decoded.shdr.gamma, state.packet.shdr.gamma);
        assert_eq!(decoded.shdr.hops, state.packet.shdr.hops);
        assert_eq!(decoded.shdr.rmax, state.packet.shdr.rmax);
        assert_eq!(decoded.chdr.hops, state.packet.chdr.hops);
    }

    #[test]
    fn decode_requires_complete_payload() {
        fn sample_chdr() -> crate::types::Chdr {
            crate::types::Chdr {
                typ: PacketType::Setup,
                hops: 1,
                specific: [0u8; 16],
            }
        }
        let header = sphinx::Header {
            alpha: [0xAA; sphinx::GROUP_LEN],
            beta: sphinx::InlineBytes::new(&vec![0u8; (2 * 1 + 1) * sphinx::KAPPA_BYTES])
                .expect("beta"),
            gamma: [0xBB; sphinx::MU_LEN],
            rmax: 1,
            hops: 1,
            stage: 0,
        };
        let header_bytes = sphinx::encode_header(&header).expect("encode header");
        let payload = vec![0u8; C_BLOCK - 1];
        assert!(matches!(
            decode(sample_chdr(), &header_bytes, &payload),
            Err(Error::Length)
        ));
        // ensure decode_tlv_stream catches truncated tlv
        let payload = {
            let mut bytes = vec![0u8; C_BLOCK];
            bytes.extend_from_slice(&[0x00, 0x04, 0xDE, 0xAD]);
            bytes
        };
        assert!(matches!(
            decode(sample_chdr(), &header_bytes, &payload),
            Err(Error::Length)
        ));
    }
}
