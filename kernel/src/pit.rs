const PIT_COMMAND: u16 = 0x43;
const PIT_CHANNEL0: u16 = 0x40;
const PIT_BASE_HZ: u32 = 1_193_182;

pub fn init(hz: u32) {
    let hz = hz.clamp(18, PIT_BASE_HZ);
    let divisor = (PIT_BASE_HZ / hz) as u16;
    unsafe {
        // channel 0, access lobyte/hibyte, mode 3 (square wave), binary
        crate::port::outb(PIT_COMMAND, 0x36);
        crate::port::outb(PIT_CHANNEL0, (divisor & 0xFF) as u8);
        crate::port::outb(PIT_CHANNEL0, (divisor >> 8) as u8);
    }
}
