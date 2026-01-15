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

pub struct TcpSocket;

impl TcpSocket {
    pub const fn new() -> Self {
        Self
    }

    pub fn recv(&self, buf: &mut [u8]) -> Result<usize, Error> {
        let ret = unsafe {
            sys::syscall2(sys::SYS_NET_RECV, buf.as_mut_ptr() as u64, buf.len() as u64)
        };
        if ret == u64::MAX {
            Err(Error::SysError)
        } else {
            Ok(ret as usize)
        }
    }

    pub fn send(&self, buf: &[u8]) -> Result<usize, Error> {
        let ret =
            unsafe { sys::syscall2(sys::SYS_NET_SEND, buf.as_ptr() as u64, buf.len() as u64) };
        if ret == u64::MAX {
            Err(Error::SysError)
        } else {
            Ok(ret as usize)
        }
    }

    pub fn close(&self) -> Result<(), Error> {
        let ret = unsafe { sys::syscall0(sys::SYS_NET_CLOSE) };
        if ret == u64::MAX {
            Err(Error::SysError)
        } else {
            Ok(())
        }
    }

    pub fn connect(&self, ip: [u8; 4], port: u16) -> Result<ConnectState, Error> {
        let ip = u32::from_be_bytes(ip);
        let ret = unsafe { sys::syscall2(sys::SYS_NET_CONNECT, ip as u64, port as u64) };
        if ret == u64::MAX {
            Err(Error::SysError)
        } else if ret == 0 {
            Ok(ConnectState::Connected)
        } else {
            Ok(ConnectState::InProgress)
        }
    }
}
