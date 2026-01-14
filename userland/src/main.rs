#![no_std]
#![no_main]

use core::arch::asm;

mod socket;
mod sys;

const LISTEN_PORT: u16 = 1234;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let msg = b"Hello from userland\n";
    sys::write(1, msg);
    let _ = unsafe { sys::syscall1(sys::SYS_EXIT, 0) };

    let mut socket = socket::TcpSocket::new();
    loop {
        if let Err(_) = socket.listen(LISTEN_PORT) {
            sys::sleep(10);
            unsafe { asm!("pause"); }
            continue;
        }

        match socket.accept() {
            Ok(true) => {
                let mut buf = [0u8; 512];
                match socket.recv(&mut buf) {
                    Ok(n) if n > 0 => {
                        let _ = socket.send(&buf[..n]);
                    }
                    Ok(_) => {}
                    Err(_) => {
                        let _ = socket.close();
                    }
                }
            }
            Ok(false) => {
                sys::sleep(10);
            }
            Err(_) => {
                let _ = socket.close();
                sys::sleep(10);
            }
        }
        unsafe { asm!("pause"); }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        unsafe { asm!("pause"); }
    }
}
