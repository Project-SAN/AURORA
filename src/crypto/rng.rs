use rand_core::{CryptoRng, RngCore};

pub struct RngBox<'a> {
    inner: &'a mut dyn RngCore,
}

impl<'a> RngBox<'a> {
    pub fn new(inner: &'a mut dyn RngCore) -> Self { Self { inner } }
}

impl<'a> RngCore for RngBox<'a> {
    fn next_u32(&mut self) -> u32 { self.inner.next_u32() }
    fn next_u64(&mut self) -> u64 { self.inner.next_u64() }
    fn fill_bytes(&mut self, dest: &mut [u8]) { self.inner.fill_bytes(dest) }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> { self.inner.try_fill_bytes(dest) }
}

impl<'a> CryptoRng for RngBox<'a> {}

