use alloc::vec;
use alloc::vec::Vec;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpCidr, Ipv4Address};

use crate::interrupts;
use crate::serial;
use crate::virtio;

const IP_ADDR: [u8; 4] = [10, 0, 2, 15];
const GW_ADDR: [u8; 4] = [10, 0, 2, 2];
const RX_BUF_SIZE: usize = 4096;
const TX_BUF_SIZE: usize = 4096;
const FRAME_BUF_SIZE: usize = 2048;
const RX_POOL_SIZE: usize = 64;
const TX_POOL_SIZE: usize = 64;

pub fn now() -> Instant {
    let ms = interrupts::ticks().saturating_mul(10);
    Instant::from_millis(ms as i64)
}

pub struct VirtioDevice {
    rx_pool: Vec<Vec<u8>>,
    tx_pool: Vec<Vec<u8>>,
}

impl VirtioDevice {
    pub fn new() -> Self {
        let mut rx_pool = Vec::with_capacity(RX_POOL_SIZE);
        for _ in 0..RX_POOL_SIZE {
            rx_pool.push(Vec::with_capacity(FRAME_BUF_SIZE));
        }
        let mut tx_pool = Vec::with_capacity(TX_POOL_SIZE);
        for _ in 0..TX_POOL_SIZE {
            tx_pool.push(Vec::with_capacity(FRAME_BUF_SIZE));
        }
        VirtioDevice { rx_pool, tx_pool }
    }
}

pub struct NetStack {
    iface: Interface,
    sockets: SocketSet<'static>,
    tcp: SocketHandle,
    listen_port: u16,
}

impl NetStack {
    pub fn new(mac: [u8; 6], device: &mut VirtioDevice, now: Instant) -> Self {
        let mut config = Config::new(HardwareAddress::Ethernet(EthernetAddress(mac)));
        config.random_seed = 0xA0B1_C2D3_E4F5_6789;

        let mut iface = Interface::new(config, device, now);
        iface.update_ip_addrs(|addrs| {
            let cidr = IpCidr::new(Ipv4Address::new(IP_ADDR[0], IP_ADDR[1], IP_ADDR[2], IP_ADDR[3]).into(), 24);
            let _ = addrs.push(cidr);
        });
        let _ = iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(GW_ADDR[0], GW_ADDR[1], GW_ADDR[2], GW_ADDR[3]));

        let mut sockets = SocketSet::new(vec![]);
        let tcp_rx = tcp::SocketBuffer::new(vec![0u8; RX_BUF_SIZE]);
        let tcp_tx = tcp::SocketBuffer::new(vec![0u8; TX_BUF_SIZE]);
        let tcp = tcp::Socket::new(tcp_rx, tcp_tx);
        let tcp_handle = sockets.add(tcp);

        serial::write(format_args!(
            "smoltcp: ip={}.{}.{}.{} gw={}.{}.{}.{}\n",
            IP_ADDR[0],
            IP_ADDR[1],
            IP_ADDR[2],
            IP_ADDR[3],
            GW_ADDR[0],
            GW_ADDR[1],
            GW_ADDR[2],
            GW_ADDR[3]
        ));
        Self {
            iface,
            sockets,
            tcp: tcp_handle,
            listen_port: 0,
        }
    }

    pub fn poll(&mut self, device: &mut VirtioDevice, now: Instant) -> Option<u64> {
        let _ = self.iface.poll(now, device, &mut self.sockets);
        self.iface
            .poll_delay(now, &self.sockets)
            .map(|d| d.total_millis())
    }

    pub fn listen(&mut self, port: u16) -> bool {
        if port == 0 {
            return false;
        }
        let socket = self.sockets.get_mut::<tcp::Socket>(self.tcp);
        if socket.is_listening() && self.listen_port == port {
            return true;
        }
        if socket.is_open() && !socket.is_listening() {
            return false;
        }
        if socket.listen(port).is_ok() {
            self.listen_port = port;
            true
        } else {
            false
        }
    }

    pub fn accept(&mut self) -> bool {
        let socket = self.sockets.get_mut::<tcp::Socket>(self.tcp);
        socket.is_active()
    }

    pub fn recv(&mut self, buf: &mut [u8]) -> usize {
        let socket = self.sockets.get_mut::<tcp::Socket>(self.tcp);
        if !socket.can_recv() {
            return 0;
        }
        match socket.recv_slice(buf) {
            Ok(size) => size,
            Err(_) => 0,
        }
    }

    pub fn send(&mut self, buf: &[u8]) -> usize {
        let socket = self.sockets.get_mut::<tcp::Socket>(self.tcp);
        if !socket.can_send() {
            return 0;
        }
        match socket.send_slice(buf) {
            Ok(size) => size,
            Err(_) => 0,
        }
    }

    pub fn close(&mut self) {
        let socket = self.sockets.get_mut::<tcp::Socket>(self.tcp);
        socket.close();
    }
}

pub struct VirtioRxToken {
    frame: Vec<u8>,
    pool: *mut Vec<Vec<u8>>,
}

pub struct VirtioTxToken {
    pool: *mut Vec<Vec<u8>>,
}

impl RxToken for VirtioRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut frame = self.frame;
        let result = f(&mut frame);
        if !self.pool.is_null() {
            unsafe {
                frame.clear();
                if (*self.pool).len() < RX_POOL_SIZE && frame.capacity() <= FRAME_BUF_SIZE {
                    (*self.pool).push(frame);
                }
            }
        }
        result
    }
}

impl TxToken for VirtioTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut frame = if !self.pool.is_null() {
            unsafe { (*self.pool).pop().unwrap_or_else(|| Vec::with_capacity(len)) }
        } else {
            Vec::with_capacity(len)
        };

        if frame.capacity() < len {
            frame.reserve(len - frame.capacity());
        }
        frame.resize(len, 0);
        let result = f(&mut frame);
        if !virtio::send_frame(&frame) {
            serial::write(format_args!("smoltcp: tx drop\n"));
        }
        if !self.pool.is_null() {
            unsafe {
                frame.clear();
                if (*self.pool).len() < TX_POOL_SIZE && frame.capacity() <= FRAME_BUF_SIZE {
                    (*self.pool).push(frame);
                }
            }
        }
        result
    }
}

impl Device for VirtioDevice {
    type RxToken<'a> = VirtioRxToken where Self: 'a;
    type TxToken<'a> = VirtioTxToken where Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let (rx_pool, tx_pool) = (&mut self.rx_pool, &mut self.tx_pool);
        let mut frame = rx_pool.pop().unwrap_or_else(|| Vec::with_capacity(FRAME_BUF_SIZE));
        if frame.capacity() < FRAME_BUF_SIZE {
            frame.reserve(FRAME_BUF_SIZE - frame.capacity());
        }
        frame.resize(FRAME_BUF_SIZE, 0);
        let len = match virtio::recv_frame_into(&mut frame) {
            Some(len) => len,
            None => {
                frame.clear();
                if rx_pool.len() < RX_POOL_SIZE && frame.capacity() <= FRAME_BUF_SIZE {
                    rx_pool.push(frame);
                }
                return None;
            }
        };
        frame.resize(len, 0);
        Some((
            VirtioRxToken {
                frame,
                pool: rx_pool as *mut _,
            },
            VirtioTxToken {
                pool: tx_pool as *mut _,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(VirtioTxToken {
            pool: &mut self.tx_pool as *mut _,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = 1514;
        caps
    }
}
