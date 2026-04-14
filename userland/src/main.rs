#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

use core::arch::asm;

mod allocator;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
mod echo;
mod fs;
#[cfg(target_arch = "x86_64")]
mod http;
#[cfg(all(feature = "router", target_arch = "x86_64"))]
mod router_app;
#[cfg(all(feature = "router", target_arch = "x86_64"))]
mod router_io;
#[cfg(all(feature = "router", target_arch = "x86_64"))]
mod router_storage;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
mod socket;
mod sys;
#[cfg(all(feature = "router", target_arch = "x86_64"))]
mod time_provider;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    allocator::init();
    let _ = sys::write(1, b"Hello from userland\n");
    if let Some(epoch) = sys::time_epoch() {
        let _ = sys::write(1, b"userland epoch=");
        write_decimal(epoch);
        let _ = sys::write(1, b"\n");
    }
    run_userland()
}

#[cfg(target_arch = "x86_64")]
use core::cell::UnsafeCell;
#[cfg(target_arch = "x86_64")]
use core::mem::MaybeUninit;
#[cfg(target_arch = "x86_64")]
use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(target_arch = "x86_64")]
const HTTP_IP: [u8; 4] = [10, 0, 2, 2];
#[cfg(target_arch = "x86_64")]
const HTTP_PORT: u16 = 8080;
#[cfg(target_arch = "x86_64")]
const HTTP_PATH: &str = "/";
#[cfg(target_arch = "x86_64")]
const HTTP_HOST: &str = "10.0.2.2";
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const ECHO_PORT: u16 = 1234;
const FS_TEST_PATH: &str = "/HELLO/WRITE.TXT";
#[cfg(target_arch = "x86_64")]
const RUN_HTTP_CLIENT: bool = true;
#[cfg(target_arch = "x86_64")]
const RUN_ECHO_SERVER: bool = false;
#[cfg(all(feature = "router", target_arch = "x86_64"))]
const RUN_ROUTER: bool = true;

#[cfg(target_arch = "x86_64")]
fn run_x86_userland() -> ! {
    #[cfg(feature = "router")]
    if RUN_ROUTER {
        let _ = sys::write(1, b"userland: entering run_router\n");
        router_app::run_router();
    }
    fs_persist_test();

    if RUN_ECHO_SERVER {
        let ok = unsafe { echo::EchoServer::init_in_place(ECHO_SERVER.get(), ECHO_PORT).is_ok() };
        if ok {
            ECHO_READY.store(true, Ordering::Release);
        }
    }
    if RUN_HTTP_CLIENT {
        let ok = unsafe {
            http::HttpClient::init_in_place(
                HTTP_CLIENT.get(),
                HTTP_IP,
                HTTP_PORT,
                HTTP_PATH,
                HTTP_HOST,
            )
            .is_ok()
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
        arch_relax();
    }
}

#[cfg(target_arch = "aarch64")]
fn run_aarch64_userland() -> ! {
    fs_persist_test();
    let mut server = core::mem::MaybeUninit::<echo::EchoServer>::uninit();
    match unsafe { echo::EchoServer::init_in_place(&mut server, ECHO_PORT) } {
        Ok(()) => {
            let _ = sys::write(1, b"userland: echo server listening on 1234\n");
            let mut server = unsafe { server.assume_init() };
            loop {
                server.poll();
                sys::sleep(1);
                arch_relax();
            }
        }
        Err(_) => {
            let _ = sys::write(1, b"userland: echo init failed\n");
        }
    }
    loop {
        sys::sleep(1);
        arch_relax();
    }
}

#[cfg(target_arch = "x86_64")]
fn run_userland() -> ! {
    run_x86_userland()
}

#[cfg(target_arch = "aarch64")]
fn run_userland() -> ! {
    run_aarch64_userland()
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn run_userland() -> ! {
    loop {
        arch_relax();
    }
}

fn fs_persist_test() {
    let _ = sys::write(1, b"fs: persist test\n");
    let _ = fs::mkdir("/HELLO");

    if let Some(fd) = fs::open(FS_TEST_PATH, fs::O_READ) {
        let mut buf = [0u8; 128];
        if let Some(n) = fs::read(fd, &mut buf) {
            let _ = sys::write(1, b"fs: prev=");
            let _ = sys::write(1, &buf[..n]);
            let _ = sys::write(1, b"\n");
        }
        let _ = fs::close(fd);
    } else {
        let _ = sys::write(1, b"fs: prev=<none>\n");
    }

    if let Some(fd) = fs::open(FS_TEST_PATH, fs::O_CREATE | fs::O_WRITE | fs::O_TRUNC) {
        let _ = sys::write(1, b"fs: write\n");
        let _ = fs::write(fd, b"boot epoch=");
        if let Some(epoch) = sys::time_epoch() {
            let mut buf = [0u8; 32];
            let mut i = 0usize;
            let mut v = epoch;
            if v == 0 {
                buf[0] = b'0';
                i = 1;
            } else {
                while v > 0 && i < buf.len() {
                    buf[i] = b'0' + (v % 10) as u8;
                    v /= 10;
                    i += 1;
                }
                buf[..i].reverse();
            }
            let _ = fs::write(fd, &buf[..i]);
        }
        let _ = fs::write(fd, b"\n");
        let _ = fs::close(fd);
        let _ = fs::sync();
    }

    if let Some(fd) = fs::open(FS_TEST_PATH, fs::O_READ) {
        let mut buf = [0u8; 128];
        if let Some(n) = fs::read(fd, &mut buf) {
            let _ = sys::write(1, b"fs: now=");
            let _ = sys::write(1, &buf[..n]);
            let _ = sys::write(1, b"\n");
        }
        let _ = fs::close(fd);
    }
}

#[cfg(target_arch = "x86_64")]
struct StaticCell<T>(UnsafeCell<MaybeUninit<T>>);

#[cfg(target_arch = "x86_64")]
unsafe impl<T> Sync for StaticCell<T> {}

#[cfg(target_arch = "x86_64")]
impl<T> StaticCell<T> {
    const fn new() -> Self {
        Self(UnsafeCell::new(MaybeUninit::uninit()))
    }

    fn get(&self) -> *mut MaybeUninit<T> {
        self.0.get()
    }
}

#[cfg(target_arch = "x86_64")]
static ECHO_SERVER: StaticCell<echo::EchoServer> = StaticCell::new();
#[cfg(target_arch = "x86_64")]
static HTTP_CLIENT: StaticCell<http::HttpClient> = StaticCell::new();
#[cfg(target_arch = "x86_64")]
static ECHO_READY: AtomicBool = AtomicBool::new(false);
#[cfg(target_arch = "x86_64")]
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

fn arch_relax() {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        asm!("pause");
    }

    #[cfg(target_arch = "aarch64")]
    unsafe {
        asm!("yield", options(nomem, nostack, preserves_flags));
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        arch_relax();
    }
}
