//! Minimal Ascon-p[12] permutation and sponge helpers (no_std).

const ROUND_CONSTANTS: [u8; 12] = [
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b,
];

#[inline]
fn rotr(x: u64, n: u32) -> u64 {
    (x >> n) | (x << (64 - n))
}

#[inline]
fn round(state: &mut [u64; 5], rc: u8) {
    // add round constant
    state[2] ^= (rc as u64) << 56;

    // substitution layer
    state[0] ^= state[4];
    state[4] ^= state[3];
    state[2] ^= state[1];

    let t0 = (!state[0]) & state[1];
    let t1 = (!state[1]) & state[2];
    let t2 = (!state[2]) & state[3];
    let t3 = (!state[3]) & state[4];
    let t4 = (!state[4]) & state[0];

    state[0] ^= t1;
    state[1] ^= t2;
    state[2] ^= t3;
    state[3] ^= t4;
    state[4] ^= t0;

    state[1] ^= state[0];
    state[0] ^= state[4];
    state[3] ^= state[2];
    state[2] = !state[2];

    // linear diffusion
    state[0] ^= rotr(state[0], 19) ^ rotr(state[0], 28);
    state[1] ^= rotr(state[1], 61) ^ rotr(state[1], 39);
    state[2] ^= rotr(state[2], 1) ^ rotr(state[2], 6);
    state[3] ^= rotr(state[3], 10) ^ rotr(state[3], 17);
    state[4] ^= rotr(state[4], 7) ^ rotr(state[4], 41);
}

pub fn permute12(state: &mut [u64; 5]) {
    for &rc in ROUND_CONSTANTS.iter() {
        round(state, rc);
    }
}

const RATE_BYTES: usize = 8;

/// Simple sponge over Ascon-p[12] with 64-bit rate.
/// This is a project-local construction (not a standard Ascon-Hash instantiation).
pub struct Sponge {
    state: [u64; 5],
    buf: [u8; RATE_BYTES],
    pos: usize,
}

impl Sponge {
    pub fn new() -> Self {
        Self {
            state: [0u64; 5],
            buf: [0u8; RATE_BYTES],
            pos: 0,
        }
    }

    pub fn absorb(&mut self, mut data: &[u8]) {
        if data.is_empty() {
            return;
        }

        if self.pos != 0 {
            let take = core::cmp::min(RATE_BYTES - self.pos, data.len());
            self.buf[self.pos..self.pos + take].copy_from_slice(&data[..take]);
            self.pos += take;
            data = &data[take..];
            if self.pos == RATE_BYTES {
                self.absorb_block();
            }
        }

        while data.len() >= RATE_BYTES {
            self.buf.copy_from_slice(&data[..RATE_BYTES]);
            data = &data[RATE_BYTES..];
            self.absorb_block();
        }

        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.pos = data.len();
        }
    }

    pub fn finalize(&mut self) {
        self.buf[self.pos] ^= 0x80;
        self.absorb_block();
    }

    pub fn squeeze(&mut self, out: &mut [u8]) {
        let mut remaining = out;
        while !remaining.is_empty() {
            let mut block = [0u8; RATE_BYTES];
            block.copy_from_slice(&self.state[0].to_be_bytes());
            let take = core::cmp::min(RATE_BYTES, remaining.len());
            remaining[..take].copy_from_slice(&block[..take]);
            remaining = &mut remaining[take..];
            if !remaining.is_empty() {
                permute12(&mut self.state);
            }
        }
    }

    fn absorb_block(&mut self) {
        let word = u64::from_be_bytes(self.buf);
        self.state[0] ^= word;
        permute12(&mut self.state);
        self.buf.fill(0);
        self.pos = 0;
    }
}
