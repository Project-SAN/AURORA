use core::fmt::{self, Write};

const COM1: u16 = 0x3F8;

pub fn init() {
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
        unsafe {
            while (crate::port::inb(COM1 + 5) & 0x20) == 0 {}
            crate::port::outb(COM1, byte);
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
