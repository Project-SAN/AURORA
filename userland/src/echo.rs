use crate::socket::{Error as SocketError, TcpListener, TcpSocket};
use crate::sys;
use core::arch::asm;

const MAX_CLIENTS: usize = 4;
const BUF_SIZE: usize = 512;

#[derive(Copy, Clone)]
struct ClientSlot {
    socket: TcpSocket,
    socket_valid: bool,
    buf: [u8; BUF_SIZE],
    pending_len: usize,
    pending_off: usize,
}

impl ClientSlot {
    const fn new() -> Self {
        Self {
            socket: TcpSocket { handle: 0 },
            socket_valid: false,
            buf: [0u8; BUF_SIZE],
            pending_len: 0,
            pending_off: 0,
        }
    }

    fn clear(&mut self) {
        self.socket_valid = false;
        self.pending_len = 0;
        self.pending_off = 0;
    }
}

pub struct EchoServer {
    listener: TcpListener,
    clients: [ClientSlot; MAX_CLIENTS],
}

impl EchoServer {
    pub fn new(port: u16) -> Result<Self, SocketError> {
        let listener = TcpListener::listen(port)?;
        Ok(Self {
            listener,
            clients: [ClientSlot::new(); MAX_CLIENTS],
        })
    }

    pub unsafe fn init_in_place(
        slot: *mut core::mem::MaybeUninit<Self>,
        port: u16,
    ) -> Result<(), SocketError> {
        let ptr = (*slot).as_mut_ptr();
        core::ptr::write_bytes(ptr as *mut u8, 0, core::mem::size_of::<Self>());
        let listener = TcpListener::listen(port)?;
        core::ptr::write(&mut (*ptr).listener, listener);
        Ok(())
    }

    pub fn poll(&mut self) {
        if let Ok(Some(socket)) = self.listener.accept() {
            if let Some(slot) = self.clients.iter_mut().find(|c| !c.socket_valid) {
                slot.socket = socket;
                slot.socket_valid = true;
                slot.pending_len = 0;
                slot.pending_off = 0;
            } else {
                let _ = socket.close();
            }
        }

        for slot in self.clients.iter_mut() {
            if !slot.socket_valid {
                continue;
            }
            let socket = slot.socket;

            if slot.pending_len > slot.pending_off {
                let data = &slot.buf[slot.pending_off..slot.pending_len];
                match socket.send(data) {
                    Ok(0) => {}
                    Ok(n) => {
                        slot.pending_off += n;
                        if slot.pending_off >= slot.pending_len {
                            slot.pending_len = 0;
                            slot.pending_off = 0;
                        }
                    }
                    Err(SocketError::SysError) => {
                        let _ = socket.close();
                        slot.clear();
                    }
                }
                continue;
            }

            match socket.recv(&mut slot.buf) {
                Ok(0) => {}
                Ok(n) => {
                    slot.pending_len = n;
                    slot.pending_off = 0;
                }
                Err(SocketError::SysError) => {
                    let _ = socket.close();
                    slot.clear();
                }
            }
        }
    }
}

#[allow(dead_code)]
pub fn run_echo_server(port: u16) -> ! {
    let mut server = match EchoServer::new(port) {
        Ok(server) => server,
        Err(_) => loop {
            sys::sleep(1000);
            unsafe { asm!("pause"); }
        },
    };
    loop {
        server.poll();
        sys::sleep(1);
        unsafe { asm!("pause"); }
    }
}
