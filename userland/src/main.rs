#![no_std]
#![no_main]

use core::arch::asm;

mod http;
mod socket;
mod sys;

const HTTP_IP: [u8; 4] = [10, 0, 2, 2];
const HTTP_PORT: u16 = 8080;
const HTTP_PATH: &str = "/";
const HTTP_HOST: &str = "10.0.2.2";

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let msg = b"Hello from userland\n";
    sys::write(1, msg);
    if let Some(epoch) = sys::time_epoch() {
        let _ = sys::write(1, b"epoch=");
        write_decimal(epoch);
        let _ = sys::write(1, b"\n");
    } else {
        let _ = sys::write(1, b"epoch=unavailable\n");
    }

    match http::http_get(HTTP_IP, HTTP_PORT, HTTP_PATH, HTTP_HOST) {
        Ok(resp) => http::print_response(&resp),
        Err(err) => http::print_error(err),
    }

    loop {
        sys::sleep(1000);
        unsafe { asm!("pause"); }
    }
}

fn write_decimal(mut value: u64) {
    let mut buf = [0u8; 20];
    let mut i = 0usize;
    if value == 0 {
        buf[0] = b'0';
        let _ = sys::write(1, &buf[..1]);
        return;
    }
    while value > 0 && i < buf.len() {
        let digit = (value % 10) as u8;
        buf[i] = b'0' + digit;
        value /= 10;
        i += 1;
    }
    buf[..i].reverse();
    let _ = sys::write(1, &buf[..i]);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        unsafe { asm!("pause"); }
    }
}
