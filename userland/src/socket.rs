use crate::sys;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    SysError,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectState {
    InProgress,
    Connected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpSocket {
    pub(crate) handle: u64,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpListener {
    handle: u64,
}

impl TcpSocket {
    pub fn new() -> Result<Self, Error> {
        let ret = unsafe { sys::syscall0(sys::SYS_NET_SOCKET) };
        if ret == u64::MAX {
            Err(Error::SysError)
        } else {
            Ok(Self { handle: ret })
        }
    }

    pub fn recv(&self, buf: &mut [u8]) -> Result<usize, Error> {
        let ret = unsafe {
            sys::syscall3(
                sys::SYS_NET_RECV,
                self.handle,
                buf.as_mut_ptr() as u64,
                buf.len() as u64,
            )
        };
        if ret == u64::MAX {
            Err(Error::SysError)
        } else {
            Ok(ret as usize)
        }
    }

    pub fn send(&self, buf: &[u8]) -> Result<usize, Error> {
        let ret = unsafe {
            sys::syscall3(
                sys::SYS_NET_SEND,
                self.handle,
                buf.as_ptr() as u64,
                buf.len() as u64,
            )
        };
        if ret == u64::MAX {
            Err(Error::SysError)
        } else {
            Ok(ret as usize)
        }
    }

    pub fn close(&self) -> Result<(), Error> {
        let ret = unsafe { sys::syscall1(sys::SYS_NET_CLOSE, self.handle) };
        if ret == u64::MAX {
            Err(Error::SysError)
        } else {
            Ok(())
        }
    }

    pub fn connect(&self, ip: [u8; 4], port: u16) -> Result<ConnectState, Error> {
        let ip = u32::from_be_bytes(ip);
        let ret = unsafe {
            sys::syscall3(
                sys::SYS_NET_CONNECT,
                self.handle,
                ip as u64,
                port as u64,
            )
        };
        if ret == u64::MAX {
            Err(Error::SysError)
        } else if ret == 0 {
            Ok(ConnectState::Connected)
        } else {
            Ok(ConnectState::InProgress)
        }
    }
}

#[allow(dead_code)]
impl TcpListener {
    pub fn listen(port: u16) -> Result<Self, Error> {
        let handle = unsafe { sys::syscall0(sys::SYS_NET_SOCKET) };
        if handle == u64::MAX {
            return Err(Error::SysError);
        }
        let ret = unsafe { sys::syscall2(sys::SYS_NET_LISTEN, handle, port as u64) };
        if ret == u64::MAX {
            let _ = unsafe { sys::syscall1(sys::SYS_NET_CLOSE, handle) };
            Err(Error::SysError)
        } else {
            Ok(Self { handle })
        }
    }

    pub fn accept(&self) -> Result<Option<TcpSocket>, Error> {
        let ret = unsafe { sys::syscall1(sys::SYS_NET_ACCEPT, self.handle) };
        if ret == u64::MAX {
            Err(Error::SysError)
        } else if ret == 0 {
            Ok(None)
        } else {
            Ok(Some(TcpSocket { handle: ret }))
        }
    }

    pub fn close(&self) -> Result<(), Error> {
        let ret = unsafe { sys::syscall1(sys::SYS_NET_CLOSE, self.handle) };
        if ret == u64::MAX {
            Err(Error::SysError)
        } else {
            Ok(())
        }
    }
}
