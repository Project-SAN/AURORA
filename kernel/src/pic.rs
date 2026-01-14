const PIC1_COMMAND: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_COMMAND: u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;

const ICW1_INIT: u8 = 0x10;
const ICW1_ICW4: u8 = 0x01;
const ICW4_8086: u8 = 0x01;

pub const PIC1_OFFSET: u8 = 32;
pub const PIC2_OFFSET: u8 = 40;

pub fn init() {
    unsafe {
        crate::port::outb(PIC1_COMMAND, ICW1_INIT | ICW1_ICW4);
        crate::port::outb(PIC2_COMMAND, ICW1_INIT | ICW1_ICW4);

        crate::port::outb(PIC1_DATA, PIC1_OFFSET);
        crate::port::outb(PIC2_DATA, PIC2_OFFSET);

        crate::port::outb(PIC1_DATA, 4);
        crate::port::outb(PIC2_DATA, 2);

        crate::port::outb(PIC1_DATA, ICW4_8086);
        crate::port::outb(PIC2_DATA, ICW4_8086);
        // Mask all IRQs by default; selectively unmask later.
        crate::port::outb(PIC1_DATA, 0xFF);
        crate::port::outb(PIC2_DATA, 0xFF);
    }
}

pub fn eoi(vector: u8) {
    unsafe {
        if vector >= PIC2_OFFSET {
            crate::port::outb(PIC2_COMMAND, 0x20);
        }
        crate::port::outb(PIC1_COMMAND, 0x20);
    }
}

pub fn unmask(irq: u8) {
    unsafe {
        if irq < 8 {
            let mask = crate::port::inb(PIC1_DATA) & !(1 << irq);
            crate::port::outb(PIC1_DATA, mask);
        } else {
            let irq = irq - 8;
            let mask = crate::port::inb(PIC2_DATA) & !(1 << irq);
            crate::port::outb(PIC2_DATA, mask);
        }
    }
}

#[allow(dead_code)]
pub fn mask(irq: u8) {
    unsafe {
        if irq < 8 {
            let mask = crate::port::inb(PIC1_DATA) | (1 << irq);
            crate::port::outb(PIC1_DATA, mask);
        } else {
            let irq = irq - 8;
            let mask = crate::port::inb(PIC2_DATA) | (1 << irq);
            crate::port::outb(PIC2_DATA, mask);
        }
    }
}
