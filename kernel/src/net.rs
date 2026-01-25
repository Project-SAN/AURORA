use alloc::vec;
use alloc::vec::Vec;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, Ipv4Address};

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
const EPHEMERAL_START: u16 = 49152;
const EPHEMERAL_END: u16 = 65534;
const MAX_SOCKETS: usize = 8;

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

type SocketId = u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SocketState {
    Free,
    Idle,
    Listening,
    Connecting,
    Established,
}

#[derive(Clone, Copy, Debug)]
struct SocketEntry {
    handle: SocketHandle,
    state: SocketState,
    listen_port: u16,
}

pub struct NetStack {
    iface: Interface,
    sockets: SocketSet<'static>,
    entries: Vec<SocketEntry>,
    next_ephemeral: u16,
}

impl NetStack {
    pub fn new(mac: [u8; 6], device: &mut VirtioDevice, now: Instant) -> Self {
        let mut config = Config::new(HardwareAddress::Ethernet(EthernetAddress(mac)));
        config.random_seed = 0xA0B1_C2D3_E4F5_6789;

        let mut iface = Interface::new(config, device, now);
        iface.update_ip_addrs(|addrs| {
            let cidr = IpCidr::new(
                Ipv4Address::new(IP_ADDR[0], IP_ADDR[1], IP_ADDR[2], IP_ADDR[3]).into(),
                24,
            );
            let _ = addrs.push(cidr);
        });
        let _ = iface.routes_mut().add_default_ipv4_route(Ipv4Address::new(
            GW_ADDR[0], GW_ADDR[1], GW_ADDR[2], GW_ADDR[3],
        ));

        let mut sockets = SocketSet::new(vec![]);
        let mut entries = Vec::with_capacity(MAX_SOCKETS);
        for _ in 0..MAX_SOCKETS {
            let tcp_rx = tcp::SocketBuffer::new(vec![0u8; RX_BUF_SIZE]);
            let tcp_tx = tcp::SocketBuffer::new(vec![0u8; TX_BUF_SIZE]);
            let tcp = tcp::Socket::new(tcp_rx, tcp_tx);
            let handle = sockets.add(tcp);
            entries.push(SocketEntry {
                handle,
                state: SocketState::Free,
                listen_port: 0,
            });
        }

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
            entries,
            next_ephemeral: EPHEMERAL_START,
        }
    }

    pub fn poll(&mut self, device: &mut VirtioDevice, now: Instant) -> Option<u64> {
        let _ = self.iface.poll(now, device, &mut self.sockets);
        self.iface
            .poll_delay(now, &self.sockets)
            .map(|d| d.total_millis())
    }

    pub fn socket(&mut self) -> Option<SocketId> {
        self.take_free_entry().map(|idx| idx as SocketId)
    }

    pub fn listen(&mut self, id: SocketId, port: u16) -> bool {
        let idx = match self.valid_index(id) {
            Some(idx) => idx,
            None => return false,
        };
        let state = self.entries[idx].state;
        if state == SocketState::Listening && self.entries[idx].listen_port == port {
            return true;
        }
        if matches!(state, SocketState::Connecting | SocketState::Established) {
            return false;
        }

        let handle = self.entries[idx].handle;
        {
            let socket = self.sockets.get_mut::<tcp::Socket>(handle);
            socket.abort();
            if socket.listen(port).is_err() {
                return false;
            }
        }
        self.entries[idx].state = SocketState::Listening;
        self.entries[idx].listen_port = port;
        true
    }

    pub fn accept(&mut self, listener_id: SocketId) -> Result<Option<SocketId>, ()> {
        let listener_idx = self.valid_index(listener_id).ok_or(())?;
        if self.entries[listener_idx].state != SocketState::Listening {
            return Err(());
        }
        let listen_port = self.entries[listener_idx].listen_port;
        let listener_handle = self.entries[listener_idx].handle;
        let active = {
            let socket = self.sockets.get_mut::<tcp::Socket>(listener_handle);
            socket.is_active() && !socket.is_listening()
        };
        if !active {
            return Ok(None);
        }

        let free_idx = match self.take_free_entry_except(listener_idx) {
            Some(idx) => idx,
            None => {
                let socket = self.sockets.get_mut::<tcp::Socket>(listener_handle);
                socket.abort();
                let _ = socket.listen(listen_port);
                return Err(());
            }
        };

        let free_handle = self.entries[free_idx].handle;
        self.entries[free_idx].handle = listener_handle;
        self.entries[free_idx].state = SocketState::Established;
        self.entries[free_idx].listen_port = 0;

        self.entries[listener_idx].handle = free_handle;
        self.entries[listener_idx].state = SocketState::Listening;
        self.entries[listener_idx].listen_port = listen_port;
        {
            let socket = self.sockets.get_mut::<tcp::Socket>(free_handle);
            socket.abort();
            let _ = socket.listen(listen_port);
        }

        Ok(Some(free_idx as SocketId))
    }

    pub fn recv(&mut self, id: SocketId, buf: &mut [u8]) -> usize {
        let handle = match self.socket_handle(id) {
            Some(handle) => handle,
            None => return 0,
        };
        let socket = self.sockets.get_mut::<tcp::Socket>(handle);
        if !socket.can_recv() {
            return 0;
        }
        match socket.recv_slice(buf) {
            Ok(size) => size,
            Err(_) => 0,
        }
    }

    pub fn send(&mut self, id: SocketId, buf: &[u8]) -> usize {
        let handle = match self.socket_handle(id) {
            Some(handle) => handle,
            None => return 0,
        };
        let socket = self.sockets.get_mut::<tcp::Socket>(handle);
        if !socket.can_send() {
            return 0;
        }
        match socket.send_slice(buf) {
            Ok(size) => size,
            Err(_) => 0,
        }
    }

    pub fn close(&mut self, id: SocketId) {
        let idx = match self.valid_index(id) {
            Some(idx) => idx,
            None => return,
        };
        let handle = self.entries[idx].handle;
        let socket = self.sockets.get_mut::<tcp::Socket>(handle);
        socket.abort();
        self.entries[idx].state = SocketState::Idle;
        self.entries[idx].listen_port = 0;
    }

    pub fn connect(&mut self, id: SocketId, ip: [u8; 4], port: u16) -> Result<bool, ()> {
        let idx = self.valid_index(id).ok_or(())?;
        if self.entries[idx].state == SocketState::Listening {
            return Err(());
        }

        let handle = self.entries[idx].handle;
        let mut needs_connect = false;
        let connected = {
            let socket = self.sockets.get_mut::<tcp::Socket>(handle);
            if socket.may_send() {
                true
            } else if socket.is_open() {
                false
            } else {
                needs_connect = true;
                false
            }
        };
        if needs_connect {
            let local_port = self.alloc_ephemeral_port();
            let remote = (IpAddress::v4(ip[0], ip[1], ip[2], ip[3]), port);
            let socket = self.sockets.get_mut::<tcp::Socket>(handle);
            if socket
                .connect(self.iface.context(), remote, local_port)
                .is_err()
            {
                return Err(());
            }
        }
        self.entries[idx].state = if connected {
            SocketState::Established
        } else {
            SocketState::Connecting
        };
        Ok(connected)
    }

    fn valid_index(&self, id: SocketId) -> Option<usize> {
        let idx = usize::try_from(id).ok()?;
        if idx >= self.entries.len() {
            return None;
        }
        if self.entries[idx].state == SocketState::Free {
            return None;
        }
        Some(idx)
    }

    fn socket_handle(&self, id: SocketId) -> Option<SocketHandle> {
        let idx = self.valid_index(id)?;
        Some(self.entries[idx].handle)
    }

    fn take_free_entry(&mut self) -> Option<usize> {
        self.take_free_entry_except(usize::MAX)
    }

    fn take_free_entry_except(&mut self, except: usize) -> Option<usize> {
        for idx in 0..self.entries.len() {
            if idx == except {
                continue;
            }
            if matches!(
                self.entries[idx].state,
                SocketState::Free | SocketState::Idle
            ) {
                let handle = self.entries[idx].handle;
                {
                    let socket = self.sockets.get_mut::<tcp::Socket>(handle);
                    socket.abort();
                }
                self.entries[idx].state = SocketState::Idle;
                self.entries[idx].listen_port = 0;
                return Some(idx);
            }
        }
        None
    }

    fn alloc_ephemeral_port(&mut self) -> u16 {
        let port = self.next_ephemeral;
        self.next_ephemeral = if port >= EPHEMERAL_END {
            EPHEMERAL_START
        } else {
            port + 1
        };
        port
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
            unsafe {
                (*self.pool)
                    .pop()
                    .unwrap_or_else(|| Vec::with_capacity(len))
            }
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
    type RxToken<'a>
        = VirtioRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = VirtioTxToken
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let (rx_pool, tx_pool) = (&mut self.rx_pool, &mut self.tx_pool);
        let mut frame = rx_pool
            .pop()
            .unwrap_or_else(|| Vec::with_capacity(FRAME_BUF_SIZE));
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
