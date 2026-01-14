use crate::sys;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    SysError,
}

pub struct TcpSocket {
    listened: bool,
}

impl TcpSocket {
    pub const fn new() -> Self {
        Self { listened: false }
    }

    pub fn listen(&mut self, port: u16) -> Result<(), Error> {
        let ret = unsafe { sys::syscall1(sys::SYS_NET_LISTEN, port as u64) };
        if ret == 0 {
            self.listened = true;
            Ok(())
        } else {
            Err(Error::SysError)
        }
    }

    pub fn accept(&self) -> Result<bool, Error> {
        if !self.listened {
            return Ok(false);
        }
        let ret = unsafe { sys::syscall0(sys::SYS_NET_ACCEPT) };
        if ret == u64::MAX {
            Err(Error::SysError)
        } else {
            Ok(ret == 1)
        }
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
}
