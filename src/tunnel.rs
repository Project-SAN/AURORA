use alloc::collections::BTreeMap;

use crate::types::Error;

const TUNNEL_MAGIC: &[u8; 4] = b"HRSX";
const TUNNEL_VERSION: u8 = 1;
const HEADER_LEN: usize = 4 + 1 + 1 + 8 + 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TunnelOp {
    Open = 1,
    Continue = 2,
    Close = 3,
}

impl TunnelOp {
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Open),
            2 => Some(Self::Continue),
            3 => Some(Self::Close),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TunnelPrefix {
    pub op: TunnelOp,
    pub session_id: u64,
    pub policy_id: [u8; 32],
}

impl TunnelPrefix {
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[..4].copy_from_slice(TUNNEL_MAGIC);
        out[4] = TUNNEL_VERSION;
        out[5] = self.op as u8;
        out[6..14].copy_from_slice(&self.session_id.to_be_bytes());
        out[14..46].copy_from_slice(&self.policy_id);
        out
    }

    pub fn decode(payload: &[u8]) -> core::result::Result<Option<(Self, usize)>, Error> {
        if payload.len() < HEADER_LEN {
            return Ok(None);
        }
        if &payload[..4] != TUNNEL_MAGIC {
            return Ok(None);
        }
        if payload[4] != TUNNEL_VERSION {
            return Err(Error::Length);
        }
        let op = TunnelOp::from_u8(payload[5]).ok_or(Error::Length)?;
        let mut sid = [0u8; 8];
        sid.copy_from_slice(&payload[6..14]);
        let mut policy_id = [0u8; 32];
        policy_id.copy_from_slice(&payload[14..46]);
        Ok(Some((
            Self {
                op,
                session_id: u64::from_be_bytes(sid),
                policy_id,
            },
            HEADER_LEN,
        )))
    }
}

#[derive(Default)]
pub struct TunnelRegistry {
    sessions: BTreeMap<u64, [u8; 32]>,
}

impl TunnelRegistry {
    pub fn authorize(&mut self, prefix: TunnelPrefix) {
        self.sessions.insert(prefix.session_id, prefix.policy_id);
    }

    pub fn is_authorized(&self, prefix: TunnelPrefix) -> bool {
        self.sessions.get(&prefix.session_id) == Some(&prefix.policy_id)
    }

    pub fn close(&mut self, prefix: TunnelPrefix) {
        if self.is_authorized(prefix) {
            self.sessions.remove(&prefix.session_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_roundtrip() {
        let prefix = TunnelPrefix {
            op: TunnelOp::Continue,
            session_id: 0x1122_3344_5566_7788,
            policy_id: [0xAB; 32],
        };
        let encoded = prefix.encode();
        let (decoded, consumed) = TunnelPrefix::decode(&encoded)
            .expect("decode")
            .expect("prefix");
        assert_eq!(decoded, prefix);
        assert_eq!(consumed, encoded.len());
    }
}
