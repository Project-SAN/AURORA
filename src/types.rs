use alloc::vec::Vec;

pub const K_MAC: usize = 16; // 128-bit MAC truncation
pub const FS_LEN: usize = 32; // 256-bit FS core
pub const C_BLOCK: usize = FS_LEN + K_MAC; // 48 bytes
pub const R_MAX: usize = 7; // maximum supported path length (configurable)

#[derive(Clone, Copy)]
pub struct Exp(pub u32); // coarse-grained expiration time

#[derive(Clone, Copy)]
pub struct Nonce(pub [u8; 16]); // also used as initial IV0 in CHDR for data

#[derive(Clone, Copy)]
pub struct Mac(pub [u8; K_MAC]);

#[derive(Clone, Copy)]
pub struct Fs(pub [u8; FS_LEN]);

// Opaque routing segment interpreted by the node's data plane
#[derive(Clone)]
pub struct RoutingSegment(pub Vec<u8>);

// Node long-term secret used to seal/unseal FS via PRP(hPRP(SV))
#[derive(Clone, Copy)]
pub struct Sv(pub [u8; 16]);

// Per-path shared symmetric key between source and hop i
#[derive(Clone, Copy)]
pub struct Si(pub [u8; 16]);

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Setup = 0x01,
    Data = 0x02,
    Reject = 0x03,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketDirection {
    Forward,
    Backward,
}

#[derive(Clone, Copy)]
pub struct Chdr {
    pub typ: PacketType,
    pub hops: u8,
    // setup: EXP, data: nonce/IV0
    pub specific: [u8; 16],
}

pub struct Ahdr {
    // Fixed-size anonymous header: r blocks of c bytes
    pub bytes: Vec<u8>,
}

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidMac,
    Expired,
    Length,
    Crypto,
    NotImplemented,
    Replay,
    PolicyViolation,
}
