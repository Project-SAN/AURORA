#![no_std]
#![no_main]

use core::arch::asm;

mod http;
mod echo;
mod socket;
mod sys;

const HTTP_IP: [u8; 4] = [10, 0, 2, 2];
const HTTP_PORT: u16 = 8080;
const HTTP_PATH: &str = "/";
const HTTP_HOST: &str = "10.0.2.2";
const ECHO_PORT: u16 = 1234;
const RUN_HTTP_CLIENT: bool = true;
const RUN_ECHO_SERVER: bool = true;

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

    let mut echo_server = if RUN_ECHO_SERVER {
        match echo::EchoServer::new(ECHO_PORT) {
            Ok(server) => Some(server),
            Err(_) => None,
        }
    } else {
        None
    };

    let mut http_client = if RUN_HTTP_CLIENT {
        match http::HttpClient::new(HTTP_IP, HTTP_PORT, HTTP_PATH, HTTP_HOST) {
            Ok(client) => Some(client),
            Err(err) => {
                http::print_error(err);
                None
            }
        }
    } else {
        None
    };

    loop {
        if let Some(server) = echo_server.as_mut() {
            server.poll();
        }
        if let Some(client) = http_client.as_mut() {
            match client.poll() {
                http::ClientPoll::InProgress => {}
                http::ClientPoll::Done(resp) => {
                    http::print_response(&resp);
                    http_client = None;
                }
                http::ClientPoll::Error(err) => {
                    http::print_error(err);
                    http_client = None;
                }
            }
        }
        sys::sleep(1);
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
