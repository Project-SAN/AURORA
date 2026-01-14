use core::ptr::{read_volatile, write_volatile};

#[derive(Clone, Copy)]
pub struct Hpet {
    base: u64,
    period_fs: u64,
}

impl Hpet {
    pub unsafe fn init(base: u64) -> Option<Self> {
        let cap = read64(base, 0x0);
        let period_fs = cap >> 32;
        if period_fs == 0 {
            return None;
        }
        // enable main counter
        write64(base, 0x10, 0x1);
        // reset main counter
        write64(base, 0xF0, 0x0);
        Some(Self { base, period_fs })
    }

    pub fn ticks(&self) -> u64 {
        unsafe { read64(self.base, 0xF0) }
    }

    pub fn ticks_per_ms(&self) -> u64 {
        // period_fs is femtoseconds per tick.
        // 1 ms = 1_000_000_000_000 fs
        (1_000_000_000_000u64 / self.period_fs).max(1)
    }
}

#[inline]
unsafe fn read64(base: u64, offset: u64) -> u64 {
    read_volatile((base + offset) as *const u64)
}

#[inline]
unsafe fn write64(base: u64, offset: u64, value: u64) {
    write_volatile((base + offset) as *mut u64, value);
}
