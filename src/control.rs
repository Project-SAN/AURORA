use alloc::vec::Vec;

use crate::types::{Error, Result};

const MAGIC: &[u8; 4] = b"CTRL";
const VERSION: u8 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControlMessage {
    ResendRequest {
        policy_id: [u8; 32],
        sequence: Option<u64>,
    },
}

pub fn encode(msg: &ControlMessage) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    match msg {
        ControlMessage::ResendRequest {
            policy_id,
            sequence,
        } => {
            out.push(1u8);
            out.extend_from_slice(policy_id);
            match sequence {
                Some(seq) => {
                    out.push(1u8);
                    out.extend_from_slice(&seq.to_be_bytes());
                }
                None => {
                    out.push(0u8);
                }
            }
        }
    }
    out
}

pub fn decode(buf: &[u8]) -> Result<ControlMessage> {
    if buf.len() < 6 {
        return Err(Error::Length);
    }
    if &buf[..4] != MAGIC {
        return Err(Error::Length);
    }
    if buf[4] != VERSION {
        return Err(Error::Length);
    }
    let msg_type = buf[5];
    match msg_type {
        1 => {
            if buf.len() < 6 + 32 + 1 {
                return Err(Error::Length);
            }
            let mut policy_id = [0u8; 32];
            policy_id.copy_from_slice(&buf[6..38]);
            let flag = buf[38];
            let sequence = if flag == 1 {
                if buf.len() < 39 + 8 {
                    return Err(Error::Length);
                }
                let mut seq_bytes = [0u8; 8];
                seq_bytes.copy_from_slice(&buf[39..47]);
                Some(u64::from_be_bytes(seq_bytes))
            } else {
                None
            };
            Ok(ControlMessage::ResendRequest {
                policy_id,
                sequence,
            })
        }
        _ => Err(Error::Length),
    }
}
