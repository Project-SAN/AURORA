use alloc::vec::Vec;
use core::marker::PhantomData;

pub const K_MAC: usize = 16; // 128-bit MAC truncation
pub const FS_LEN: usize = 32; // 256-bit FS core
pub const C_BLOCK: usize = FS_LEN + K_MAC; // 48 bytes
pub const R_MAX: usize = 7; // maximum supported path length (configurable)

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Exp(pub u32); // coarse-grained expiration time

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Nonce(pub [u8; 16]); // also used as initial IV0 in CHDR for data

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mac(pub [u8; K_MAC]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketDirection {
    Forward,
    Backward,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct HopCount(u8);

impl HopCount {
    pub const MIN: u8 = 1;
    pub const MAX: u8 = R_MAX as u8;

    pub fn new(value: u8) -> Result<Self> {
        if (Self::MIN..=Self::MAX).contains(&value) {
            Ok(Self(value))
        } else {
            Err(Error::Length)
        }
    }

    pub const fn get(self) -> u8 {
        self.0
    }

    pub fn from_usize(value: usize) -> Result<Self> {
        if value > u8::MAX as usize {
            return Err(Error::Length);
        }
        Self::new(value as u8)
    }
}

impl TryFrom<u8> for HopCount {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        Self::new(value)
    }
}

impl TryFrom<usize> for HopCount {
    type Error = Error;

    fn try_from(value: usize) -> Result<Self> {
        Self::from_usize(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RMax(u8);

impl RMax {
    pub const MIN: u8 = 1;
    pub const MAX: u8 = R_MAX as u8;

    pub fn new(value: u8) -> Result<Self> {
        if (Self::MIN..=Self::MAX).contains(&value) {
            Ok(Self(value))
        } else {
            Err(Error::Length)
        }
    }

    pub const fn get(self) -> usize {
        self.0 as usize
    }

    pub fn from_usize(value: usize) -> Result<Self> {
        if value > u8::MAX as usize {
            return Err(Error::Length);
        }
        Self::new(value as u8)
    }
}

impl TryFrom<u8> for RMax {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        Self::new(value)
    }
}

impl TryFrom<usize> for RMax {
    type Error = Error;

    fn try_from(value: usize) -> Result<Self> {
        Self::from_usize(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Stage(u8);

impl Stage {
    pub fn new(value: u8) -> Result<Self> {
        if value <= R_MAX as u8 {
            Ok(Self(value))
        } else {
            Err(Error::Length)
        }
    }

    pub const fn get(self) -> usize {
        self.0 as usize
    }

    pub fn from_usize(value: usize) -> Result<Self> {
        if value > u8::MAX as usize {
            return Err(Error::Length);
        }
        Self::new(value as u8)
    }
}

impl TryFrom<u8> for Stage {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        Self::new(value)
    }
}

impl TryFrom<usize> for Stage {
    type Error = Error;

    fn try_from(value: usize) -> Result<Self> {
        Self::from_usize(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AhdrLen(usize);

impl AhdrLen {
    pub const MIN: usize = C_BLOCK;
    pub const MAX: usize = 2 * R_MAX * C_BLOCK;

    pub fn new(bytes: usize) -> Result<Self> {
        if !(Self::MIN..=Self::MAX).contains(&bytes) || bytes % C_BLOCK != 0 {
            return Err(Error::Length);
        }
        Ok(Self(bytes))
    }

    pub const fn get(self) -> usize {
        self.0
    }

    pub const fn blocks(self) -> usize {
        self.0 / C_BLOCK
    }
}

impl TryFrom<usize> for AhdrLen {
    type Error = Error;

    fn try_from(value: usize) -> Result<Self> {
        Self::new(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PayloadLen(u32);

impl PayloadLen {
    pub fn new(bytes: usize) -> Result<Self> {
        let value = u32::try_from(bytes).map_err(|_| Error::Length)?;
        Ok(Self(value))
    }

    pub const fn from_u32(bytes: u32) -> Self {
        Self(bytes)
    }

    pub const fn get(self) -> usize {
        self.0 as usize
    }

    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

impl TryFrom<usize> for PayloadLen {
    type Error = Error;

    fn try_from(value: usize) -> Result<Self> {
        Self::new(value)
    }
}

impl From<u32> for PayloadLen {
    fn from(value: u32) -> Self {
        Self::from_u32(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PolicyPartCount(u8);

impl PolicyPartCount {
    pub const MAX: u8 = 4;

    pub fn new(value: u8) -> Result<Self> {
        if value <= Self::MAX {
            Ok(Self(value))
        } else {
            Err(Error::Length)
        }
    }

    pub const fn get(self) -> usize {
        self.0 as usize
    }

    pub const fn as_u8(self) -> u8 {
        self.0
    }
}

impl TryFrom<u8> for PolicyPartCount {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        Self::new(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chdr {
    Setup { hops: HopCount, exp: Exp },
    Data { hops: HopCount, nonce: Nonce },
}

impl Chdr {
    pub fn setup(hops: HopCount, exp: Exp) -> Self {
        Self::Setup { hops, exp }
    }

    pub fn data(hops: HopCount, nonce: Nonce) -> Self {
        Self::Data { hops, nonce }
    }

    pub fn packet_type(self) -> PacketType {
        match self {
            Self::Setup { .. } => PacketType::Setup,
            Self::Data { .. } => PacketType::Data,
        }
    }

    pub fn hops(self) -> HopCount {
        match self {
            Self::Setup { hops, .. } | Self::Data { hops, .. } => hops,
        }
    }

    pub fn exp(self) -> Option<Exp> {
        match self {
            Self::Setup { exp, .. } => Some(exp),
            Self::Data { .. } => None,
        }
    }

    pub fn nonce(self) -> Option<Nonce> {
        match self {
            Self::Data { nonce, .. } => Some(nonce),
            Self::Setup { .. } => None,
        }
    }

    pub fn set_nonce(&mut self, nonce: Nonce) -> Result<()> {
        match self {
            Self::Data {
                nonce: current_nonce,
                ..
            } => {
                *current_nonce = nonce;
                Ok(())
            }
            Self::Setup { .. } => Err(Error::Length),
        }
    }

    pub fn to_raw_parts(self) -> (PacketType, u8, [u8; 16]) {
        match self {
            Self::Setup { hops, exp } => {
                let mut specific = [0u8; 16];
                specific[0..4].copy_from_slice(&exp.0.to_be_bytes());
                (PacketType::Setup, hops.get(), specific)
            }
            Self::Data { hops, nonce } => (PacketType::Data, hops.get(), nonce.0),
        }
    }

    pub fn from_raw_parts(typ: PacketType, hops: u8, specific: [u8; 16]) -> Result<Self> {
        let hops = HopCount::new(hops)?;
        match typ {
            PacketType::Setup => {
                let mut b = [0u8; 4];
                b.copy_from_slice(&specific[0..4]);
                Ok(Self::setup(hops, Exp(u32::from_be_bytes(b))))
            }
            PacketType::Data => Ok(Self::data(hops, Nonce(specific))),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataChdr {
    pub hops: HopCount,
    pub nonce: Nonce,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetupChdr {
    pub hops: HopCount,
    pub exp: Exp,
}

impl From<DataChdr> for Chdr {
    fn from(value: DataChdr) -> Self {
        Chdr::data(value.hops, value.nonce)
    }
}

impl From<SetupChdr> for Chdr {
    fn from(value: SetupChdr) -> Self {
        Chdr::setup(value.hops, value.exp)
    }
}

impl TryFrom<Chdr> for DataChdr {
    type Error = Error;

    fn try_from(value: Chdr) -> Result<Self> {
        match value {
            Chdr::Data { hops, nonce } => Ok(Self { hops, nonce }),
            Chdr::Setup { .. } => Err(Error::Length),
        }
    }
}

impl TryFrom<Chdr> for SetupChdr {
    type Error = Error;

    fn try_from(value: Chdr) -> Result<Self> {
        match value {
            Chdr::Setup { hops, exp } => Ok(Self { hops, exp }),
            Chdr::Data { .. } => Err(Error::Length),
        }
    }
}

pub struct Raw;
pub struct LenChecked;
pub struct PolicyChecked;
pub struct OnionProcessed;

pub struct DataPacket<S> {
    pub chdr: DataChdr,
    pub ahdr: Ahdr,
    pub payload: Vec<u8>,
    _state: PhantomData<S>,
}

impl<S> DataPacket<S> {
    pub fn new(chdr: DataChdr, ahdr: Ahdr, payload: Vec<u8>) -> Self {
        Self {
            chdr,
            ahdr,
            payload,
            _state: PhantomData,
        }
    }

    pub fn transition<Next>(self) -> DataPacket<Next> {
        DataPacket {
            chdr: self.chdr,
            ahdr: self.ahdr,
            payload: self.payload,
            _state: PhantomData,
        }
    }

    pub fn into_wire_parts(self) -> (Chdr, Ahdr, Vec<u8>) {
        (self.chdr.into(), self.ahdr, self.payload)
    }
}

impl DataPacket<Raw> {
    pub fn validate_lengths(self) -> Result<DataPacket<LenChecked>> {
        AhdrLen::new(self.ahdr.bytes.len())?;
        let _ = PayloadLen::new(self.payload.len())?;
        Ok(self.transition())
    }
}

impl DataPacket<LenChecked> {
    pub fn mark_policy_checked(self) -> DataPacket<PolicyChecked> {
        self.transition()
    }
}

impl DataPacket<PolicyChecked> {
    pub fn mark_onion_processed(self) -> DataPacket<OnionProcessed> {
        self.transition()
    }
}

pub enum Packet {
    Setup(SetupPacket),
    Data(DataPacket<Raw>),
}

impl Packet {
    pub fn from_wire_parts(chdr: Chdr, ahdr: Ahdr, payload: Vec<u8>) -> Self {
        match chdr {
            Chdr::Setup { hops, exp } => Self::Setup(SetupPacket {
                chdr: SetupChdr { hops, exp },
                ahdr,
                payload,
            }),
            Chdr::Data { hops, nonce } => Self::Data(DataPacket::new(
                DataChdr { hops, nonce },
                ahdr,
                payload,
            )),
        }
    }

    pub fn into_wire_parts(self) -> (Chdr, Ahdr, Vec<u8>) {
        match self {
            Self::Setup(pkt) => (pkt.chdr.into(), pkt.ahdr, pkt.payload),
            Self::Data(pkt) => pkt.into_wire_parts(),
        }
    }
}

pub struct SetupPacket {
    pub chdr: SetupChdr,
    pub ahdr: Ahdr,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
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
