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

    match http::http_get(HTTP_IP, HTTP_PORT, HTTP_PATH, HTTP_HOST) {
        Ok(resp) => http::print_response(&resp),
        Err(err) => http::print_error(err),
    }

    loop {
        sys::sleep(1000);
        unsafe { asm!("pause"); }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        unsafe { asm!("pause"); }
    }
}
