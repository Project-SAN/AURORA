#![no_std]
#![no_main]

use core::arch::asm;
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, Ordering};

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

    if RUN_ECHO_SERVER {
        let ok = unsafe { echo::EchoServer::init_in_place(ECHO_SERVER.get(), ECHO_PORT).is_ok() };
        if ok {
            ECHO_READY.store(true, Ordering::Release);
        }
    }
    if RUN_HTTP_CLIENT {
        let ok = unsafe {
            http::HttpClient::init_in_place(HTTP_CLIENT.get(), HTTP_IP, HTTP_PORT, HTTP_PATH, HTTP_HOST).is_ok()
        };
        if ok {
            HTTP_READY.store(true, Ordering::Release);
        } else {
            http::print_error(http::HttpError::Socket);
        }
    }

    loop {
        if ECHO_READY.load(Ordering::Acquire) {
            unsafe {
                let server = &mut *(*ECHO_SERVER.get()).as_mut_ptr();
                server.poll();
            }
        }
        if HTTP_READY.load(Ordering::Acquire) {
            unsafe {
                let client = &mut *(*HTTP_CLIENT.get()).as_mut_ptr();
                match client.poll() {
                    http::ClientPoll::InProgress => {}
                    http::ClientPoll::Done(resp) => {
                        http::print_response(&resp);
                        HTTP_READY.store(false, Ordering::Release);
                    }
                    http::ClientPoll::Error(err) => {
                        http::print_error(err);
                        HTTP_READY.store(false, Ordering::Release);
                    }
                }
            }
        }
        sys::sleep(1);
        unsafe { asm!("pause"); }
    }
}

struct StaticCell<T>(UnsafeCell<MaybeUninit<T>>);

unsafe impl<T> Sync for StaticCell<T> {}

impl<T> StaticCell<T> {
    const fn new() -> Self {
        Self(UnsafeCell::new(MaybeUninit::uninit()))
    }

    fn get(&self) -> *mut MaybeUninit<T> {
        self.0.get()
    }
}

static ECHO_SERVER: StaticCell<echo::EchoServer> = StaticCell::new();
static HTTP_CLIENT: StaticCell<http::HttpClient> = StaticCell::new();
static ECHO_READY: AtomicBool = AtomicBool::new(false);
static HTTP_READY: AtomicBool = AtomicBool::new(false);

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
