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
const LISTEN_PORT: u16 = 1234;
const RX_BUF_SIZE: usize = 4096;
const TX_BUF_SIZE: usize = 4096;

pub fn now() -> Instant {
    let ms = interrupts::ticks().saturating_mul(10);
    Instant::from_millis(ms as i64)
}

pub struct VirtioDevice;

impl VirtioDevice {
    pub fn new() -> Self {
        VirtioDevice
    }
}

pub struct NetStack {
    iface: Interface,
    sockets: SocketSet<'static>,
    tcp: SocketHandle,
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
            "smoltcp: ip={}.{}.{}.{} gw={}.{}.{}.{} port={}\n",
            IP_ADDR[0],
            IP_ADDR[1],
            IP_ADDR[2],
            IP_ADDR[3],
            GW_ADDR[0],
            GW_ADDR[1],
            GW_ADDR[2],
            GW_ADDR[3],
            LISTEN_PORT
        ));
        Self {
            iface,
            sockets,
            tcp: tcp_handle,
        }
    }

    pub fn poll(&mut self, device: &mut VirtioDevice, now: Instant) {
        let _ = self.iface.poll(now, device, &mut self.sockets);

        let socket = self.sockets.get_mut::<tcp::Socket>(self.tcp);
        if !socket.is_open() {
            let _ = socket.listen(LISTEN_PORT);
        }

        if socket.can_recv() {
            let mut buf = [0u8; 512];
            let mut copied = 0usize;
            if let Ok(size) = socket.recv_slice(&mut buf) {
                copied = size;
            }
            if copied > 0 && socket.can_send() {
                let _ = socket.send_slice(&buf[..copied]);
            }
        }
    }
}

pub struct VirtioRxToken {
    frame: Vec<u8>,
}

pub struct VirtioTxToken;

impl RxToken for VirtioRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut frame = self.frame;
        f(&mut frame)
    }
}

impl TxToken for VirtioTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut frame = vec![0u8; len];
        let result = f(&mut frame);
        if !virtio::send_frame(&frame) {
            serial::write(format_args!("smoltcp: tx drop\n"));
        }
        result
    }
}

impl Device for VirtioDevice {
    type RxToken<'a> = VirtioRxToken where Self: 'a;
    type TxToken<'a> = VirtioTxToken where Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let frame = virtio::recv_frame()?;
        Some((VirtioRxToken { frame }, VirtioTxToken))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(VirtioTxToken)
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = 1514;
        caps
    }
}
