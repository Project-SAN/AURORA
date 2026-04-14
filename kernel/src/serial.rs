use core::fmt::{self, Write};

#[cfg(target_arch = "x86_64")]
const COM1: u16 = 0x3F8;
#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
const PL011_BASE: usize = 0x0900_0000;
#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
const PL011_DR: usize = 0x00;
#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
const PL011_FR: usize = 0x18;
#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
const PL011_FR_TXFF: u32 = 1 << 5;

pub fn init() {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        crate::port::outb(COM1 + 1, 0x00); // disable interrupts
        crate::port::outb(COM1 + 3, 0x80); // enable DLAB
        crate::port::outb(COM1 + 0, 0x01); // divisor low byte (115200 baud)
        crate::port::outb(COM1 + 1, 0x00); // divisor high byte
        crate::port::outb(COM1 + 3, 0x03); // 8 bits, no parity, one stop bit
        crate::port::outb(COM1 + 2, 0xC7); // enable FIFO, clear, 14-byte threshold
        crate::port::outb(COM1 + 4, 0x0B); // IRQs enabled, RTS/DSR set
    }
}

pub fn write(args: fmt::Arguments) {
    let mut port = SerialPort;
    let _ = port.write_fmt(args);
}

struct SerialPort;

impl SerialPort {
    fn write_byte(&mut self, byte: u8) {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            while (crate::port::inb(COM1 + 5) & 0x20) == 0 {}
            crate::port::outb(COM1, byte);
        }

        #[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
        unsafe {
            while core::ptr::read_volatile((PL011_BASE + PL011_FR) as *const u32) & PL011_FR_TXFF
                != 0
            {}
            core::ptr::write_volatile((PL011_BASE + PL011_DR) as *mut u32, byte as u32);
        }

        #[cfg(not(any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_os = "uefi")
        )))]
        {
            let _ = byte;
        }
    }
}

impl Write for SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            if byte == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(byte);
        }
        Ok(())
    }
}

// port I/O helpers live in crate::port
