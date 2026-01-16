#![allow(dead_code)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use hornet::application::setup::RegistrySetupPipeline;
use hornet::node::ReplayCache;
use hornet::policy::{decode_metadata_tlv, PolicyId, POLICY_METADATA_TLV};
use hornet::router::io::PacketListener;
use hornet::router::storage::{RouterStorage, StoredState};
use hornet::router::Router;
use hornet::setup::wire;
use hornet::types::{self, PacketDirection, PacketType, Result as HornetResult};

use crate::router_io::{UserlandExitTransport, UserlandForward, UserlandPacketListener};
use crate::router_storage::UserlandRouterStorage;
use crate::fs;
use crate::sys;

#[cfg(feature = "hornet-time")]
use crate::time_provider::SysTimeProvider;

const ROUTER_CONFIG_PATH: &str = "/router_config.json";
const DEFAULT_LISTEN_PORT: u16 = 7000;
const DEFAULT_CLI_PORT: u16 = 7001;
const DEFAULT_STORAGE_PATH: &str = "/router_state.json";

pub fn run_router() -> ! {
    let mut config = load_config();
    let storage = UserlandRouterStorage::new(config.storage_path.clone());
    let mut router = Router::new();
    let secrets = load_state(&storage, &mut router);
    let mut listener = match UserlandPacketListener::listen(config.listen_port, secrets.sv) {
        Ok(listener) => listener,
        Err(_) => loop {
            sys::sleep(1000);
        },
    };
    let mut cli = CliServer::listen(config.cli_port);
    let time = time_provider();
    let mut forward = UserlandForward::new();
    let mut exit = UserlandExitTransport::new();
    let mut replay = ReplayCache::new();

    loop {
        if let Some(server) = cli.as_mut() {
            server.poll(&mut router, &mut config);
        }
        match listener.next() {
            Ok(Some(mut packet)) => {
                if packet.chdr.typ == PacketType::Setup {
                    let _ = handle_setup_packet(packet, &mut router, &storage, &secrets);
                    continue;
                }
                let res = match packet.direction {
                    PacketDirection::Forward => router.process_forward_packet(
                        packet.sv,
                        &time,
                        &mut forward,
                        Some(&mut exit),
                        &mut replay,
                        &mut packet.chdr,
                        &mut packet.ahdr,
                        &mut packet.payload,
                    ),
                    PacketDirection::Backward => router.process_backward_packet(
                        packet.sv,
                        &time,
                        &mut forward,
                        &mut replay,
                        &mut packet.chdr,
                        &mut packet.ahdr,
                        &mut packet.payload,
                    ),
                };
                let _ = res;
                let _ = router.handle_async_violations();
            }
            Ok(None) => {
                sys::sleep(1);
            }
            Err(_) => {
                sys::sleep(10);
            }
        }
    }
}

#[derive(Clone)]
struct RouterConfig {
    listen_port: u16,
    storage_path: String,
    cli_port: u16,
}

#[derive(Deserialize, Serialize)]
struct RouterConfigFile {
    listen_port: Option<u16>,
    storage_path: Option<String>,
    cli_port: Option<u16>,
}

fn load_config() -> RouterConfig {
    let default = RouterConfig {
        listen_port: DEFAULT_LISTEN_PORT,
        storage_path: DEFAULT_STORAGE_PATH.into(),
        cli_port: DEFAULT_CLI_PORT,
    };
    let data = match read_all(ROUTER_CONFIG_PATH) {
        Ok(bytes) => bytes,
        Err(_) => return default,
    };
    let parsed: RouterConfigFile = match serde_json::from_slice(&data) {
        Ok(cfg) => cfg,
        Err(_) => return default,
    };
    RouterConfig {
        listen_port: parsed.listen_port.unwrap_or(DEFAULT_LISTEN_PORT),
        storage_path: parsed.storage_path.unwrap_or_else(|| DEFAULT_STORAGE_PATH.into()),
        cli_port: parsed.cli_port.unwrap_or(DEFAULT_CLI_PORT),
    }
}

fn read_all(path: &str) -> HornetResult<Vec<u8>> {
    let handle = fs::open(path, fs::O_READ).ok_or(types::Error::Crypto)?;
    let mut out = Vec::new();
    let mut buf = [0u8; 512];
    loop {
        match fs::read(handle, &mut buf) {
            Some(0) => break,
            Some(n) => out.extend_from_slice(&buf[..n]),
            None => {
                let _ = fs::close(handle);
                return Err(types::Error::Crypto);
            }
        }
    }
    if !fs::close(handle) {
        return Err(types::Error::Crypto);
    }
    Ok(out)
}

fn write_all(path: &str, data: &[u8]) -> HornetResult<()> {
    let handle = fs::open(path, fs::O_CREATE | fs::O_WRITE | fs::O_TRUNC)
        .ok_or(types::Error::Crypto)?;
    let mut offset = 0usize;
    while offset < data.len() {
        match fs::write(handle, &data[offset..]) {
            Some(0) | None => {
                let _ = fs::close(handle);
                return Err(types::Error::Crypto);
            }
            Some(n) => offset += n,
        }
    }
    if !fs::close(handle) {
        return Err(types::Error::Crypto);
    }
    if !fs::sync() {
        return Err(types::Error::Crypto);
    }
    Ok(())
}

fn save_config(config: &RouterConfig) -> HornetResult<()> {
    let file = RouterConfigFile {
        listen_port: Some(config.listen_port),
        storage_path: Some(config.storage_path.clone()),
        cli_port: Some(config.cli_port),
    };
    let data = serde_json::to_vec_pretty(&file).map_err(|_| types::Error::Crypto)?;
    write_all(ROUTER_CONFIG_PATH, &data)
}

struct CliServer {
    listener: crate::socket::TcpListener,
}

impl CliServer {
    fn listen(port: u16) -> Option<Self> {
        match crate::socket::TcpListener::listen(port) {
            Ok(listener) => Some(Self { listener }),
            Err(_) => None,
        }
    }

    fn poll(&mut self, router: &mut Router, config: &mut RouterConfig) {
        match self.listener.accept() {
            Ok(Some(socket)) => {
                handle_cli_session(socket, router, config);
            }
            Ok(None) => {}
            Err(_) => {}
        }
    }
}

enum CliMode {
    Exec,
    Config,
}

fn handle_cli_session(
    socket: crate::socket::TcpSocket,
    router: &mut Router,
    config: &mut RouterConfig,
) {
    let _ = send_line(&socket, "AURORA router CLI");
    let mut mode = CliMode::Exec;
    let mut line = Vec::with_capacity(256);
    loop {
        let prompt = match mode {
            CliMode::Exec => "aurora> ",
            CliMode::Config => "aurora(config)# ",
        };
        if send_str(&socket, prompt).is_err() {
            break;
        }
        match read_line(&socket, &mut line) {
            Ok(true) => {
                let cmd = match core::str::from_utf8(&line) {
                    Ok(s) => s,
                    Err(_) => {
                        let _ = send_line(&socket, "invalid utf-8");
                        continue;
                    }
                };
                if !handle_cli_command(&socket, cmd, router, config, &mut mode) {
                    break;
                }
            }
            Ok(false) => break,
            Err(_) => break,
        }
    }
    let _ = socket.close();
}

fn handle_cli_command(
    socket: &crate::socket::TcpSocket,
    input: &str,
    router: &mut Router,
    config: &mut RouterConfig,
    mode: &mut CliMode,
) -> bool {
    let mut parts = input.split_whitespace();
    let cmd = match parts.next() {
        Some(c) => c,
        None => return true,
    };
    match cmd {
        "help" | "?" => {
            let _ = send_line(socket, "show running-config | startup-config | routes | policies");
            let _ = send_line(socket, "configure terminal");
            let _ = send_line(socket, "set listen_port <port> | storage_path <path> | cli_port <port>");
            let _ = send_line(socket, "commit | rollback | write memory | exit");
        }
        "show" => {
            match parts.next() {
                Some("running-config") => show_running_config(socket, config),
                Some("startup-config") => show_startup_config(socket),
                Some("routes") => show_routes(socket, router),
                Some("policies") => show_policies(socket, router),
                _ => {
                    let _ = send_line(socket, "usage: show running-config|startup-config|routes|policies");
                }
            }
        }
        "configure" => {
            if matches!(parts.next(), Some("terminal")) {
                *mode = CliMode::Config;
            } else {
                let _ = send_line(socket, "usage: configure terminal");
            }
        }
        "set" => {
            if !matches!(*mode, CliMode::Config) {
                let _ = send_line(socket, "enter config mode: configure terminal");
                return true;
            }
            match (parts.next(), parts.next()) {
                (Some("listen_port"), Some(value)) => {
                    if let Ok(port) = value.parse::<u16>() {
                        config.listen_port = port;
                        let _ = send_line(socket, "ok (takes effect on restart)");
                    } else {
                        let _ = send_line(socket, "invalid port");
                    }
                }
                (Some("storage_path"), Some(value)) => {
                    config.storage_path = value.into();
                    let _ = send_line(socket, "ok");
                }
                (Some("cli_port"), Some(value)) => {
                    if let Ok(port) = value.parse::<u16>() {
                        config.cli_port = port;
                        let _ = send_line(socket, "ok (takes effect on restart)");
                    } else {
                        let _ = send_line(socket, "invalid port");
                    }
                }
                _ => {
                    let _ = send_line(socket, "usage: set listen_port <port> | storage_path <path> | cli_port <port>");
                }
            }
        }
        "commit" => {
            if save_config(config).is_ok() {
                let _ = send_line(socket, "committed");
            } else {
                let _ = send_line(socket, "commit failed");
            }
            *mode = CliMode::Exec;
        }
        "rollback" => {
            *config = load_config();
            let _ = send_line(socket, "rolled back (takes effect on restart)");
        }
        "write" => {
            if matches!(parts.next(), Some("memory")) {
                if save_config(config).is_ok() {
                    let _ = send_line(socket, "saved");
                } else {
                    let _ = send_line(socket, "save failed");
                }
            } else {
                let _ = send_line(socket, "usage: write memory");
            }
        }
        "copy" => {
            if matches!(parts.next(), Some("running-config"))
                && matches!(parts.next(), Some("startup-config"))
            {
                if save_config(config).is_ok() {
                    let _ = send_line(socket, "saved");
                } else {
                    let _ = send_line(socket, "save failed");
                }
            } else {
                let _ = send_line(socket, "usage: copy running-config startup-config");
            }
        }
        "exit" | "quit" => return false,
        _ => {
            let _ = send_line(socket, "unknown command");
        }
    }
    true
}

fn show_running_config(socket: &crate::socket::TcpSocket, config: &RouterConfig) {
    let _ = send_line(socket, "running-config:");
    let _ = send_kv_u16(socket, "listen_port", config.listen_port);
    let _ = send_kv_u16(socket, "cli_port", config.cli_port);
    let _ = send_kv_str(socket, "storage_path", &config.storage_path);
}

fn show_startup_config(socket: &crate::socket::TcpSocket) {
    match read_all(ROUTER_CONFIG_PATH) {
        Ok(bytes) => {
            let _ = send_line(socket, "startup-config:");
            let _ = send_bytes(socket, &bytes);
            let _ = send_line(socket, "");
        }
        Err(_) => {
            let _ = send_line(socket, "startup-config: <none>");
        }
    }
}

fn show_routes(socket: &crate::socket::TcpSocket, router: &Router) {
    let routes = router.routes();
    let _ = send_line(socket, "routes:");
    for route in routes {
        let mut line = String::new();
        line.push_str("  policy_id=");
        fmt_hex(&route.policy_id, &mut line);
        line.push_str(" segment_len=");
        let _ = core::fmt::Write::write_fmt(&mut line, format_args!("{}", route.segment.0.len()));
        if let Some(iface) = route.interface.as_ref() {
            line.push_str(" interface=");
            line.push_str(iface);
        }
        let _ = send_line(socket, &line);
    }
}

fn show_policies(socket: &crate::socket::TcpSocket, router: &Router) {
    let policies = router.policies();
    let _ = send_line(socket, "policies:");
    for policy in policies {
        let mut line = String::new();
        line.push_str("  policy_id=");
        fmt_hex(&policy.policy_id, &mut line);
        line.push_str(" expiry=");
        let _ = core::fmt::Write::write_fmt(&mut line, format_args!("{}", policy.expiry));
        let _ = send_line(socket, &line);
    }
}

fn fmt_hex(bytes: &[u8], out: &mut String) {
    for &b in bytes {
        let _ = core::fmt::Write::write_fmt(out, format_args!("{:02x}", b));
    }
}

fn send_kv_u16(socket: &crate::socket::TcpSocket, key: &str, value: u16) -> bool {
    let mut line = String::new();
    line.push_str(key);
    line.push_str(": ");
    let _ = core::fmt::Write::write_fmt(&mut line, format_args!("{}", value));
    send_line(socket, &line).is_ok()
}

fn send_kv_str(socket: &crate::socket::TcpSocket, key: &str, value: &str) -> bool {
    let mut line = String::new();
    line.push_str(key);
    line.push_str(": ");
    line.push_str(value);
    send_line(socket, &line).is_ok()
}

fn send_line(socket: &crate::socket::TcpSocket, line: &str) -> HornetResult<()> {
    send_bytes(socket, line.as_bytes())?;
    send_bytes(socket, b"\n")
}

fn send_str(socket: &crate::socket::TcpSocket, s: &str) -> HornetResult<()> {
    send_bytes(socket, s.as_bytes())
}

fn send_bytes(socket: &crate::socket::TcpSocket, buf: &[u8]) -> HornetResult<()> {
    let mut offset = 0usize;
    while offset < buf.len() {
        let written = socket.send(&buf[offset..]).map_err(|_| types::Error::Crypto)?;
        if written == 0 {
            return Err(types::Error::Crypto);
        }
        offset += written;
    }
    Ok(())
}

fn read_line(socket: &crate::socket::TcpSocket, out: &mut Vec<u8>) -> HornetResult<bool> {
    out.clear();
    let mut buf = [0u8; 64];
    loop {
        let n = socket.recv(&mut buf).map_err(|_| types::Error::Crypto)?;
        if n == 0 {
            sys::sleep(1);
            continue;
        }
        for &b in &buf[..n] {
            match b {
                b'\r' => {}
                b'\n' => return Ok(true),
                8 | 127 => {
                    out.pop();
                }
                _ => {
                    if out.len() < 256 {
                        out.push(b);
                    }
                }
            }
        }
    }
}

fn time_provider() -> impl hornet::time::TimeProvider {
    #[cfg(feature = "hornet-time")]
    {
        SysTimeProvider
    }
    #[cfg(not(feature = "hornet-time"))]
    {
        struct DummyTime;
        impl hornet::time::TimeProvider for DummyTime {
            fn now_coarse(&self) -> u32 {
                0
            }
        }
        DummyTime
    }
}

struct RouterSecrets {
    sv: types::Sv,
    node_secret: [u8; 32],
}

impl RouterSecrets {
    fn new(sv: types::Sv, node_secret: [u8; 32]) -> Self {
        Self { sv, node_secret }
    }
}

fn load_state(storage: &dyn RouterStorage, router: &mut Router) -> RouterSecrets {
    match storage.load() {
        Ok(state) => {
            let (policies, routes, sv, node_secret) = state.into_parts();
            let _ = router.install_policies(&policies);
            let _ = router.install_routes(&routes);
            RouterSecrets::new(sv, node_secret)
        }
        Err(_) => RouterSecrets::new(types::Sv([0xAA; 16]), [0x11; 32]),
    }
}

fn persist_state(storage: &dyn RouterStorage, router: &Router, secrets: &RouterSecrets) {
    let state = StoredState::new(
        router.policies(),
        router.routes(),
        secrets.sv,
        secrets.node_secret,
    );
    let _ = storage.save(&state);
}

fn handle_setup_packet(
    packet: hornet::router::io::IncomingPacket,
    router: &mut Router,
    storage: &dyn RouterStorage,
    secrets: &RouterSecrets,
) -> HornetResult<()> {
    if packet.chdr.typ != PacketType::Setup {
        return Err(types::Error::Length);
    }
    let mut setup_packet = wire::decode(packet.chdr, &packet.ahdr.bytes, &packet.payload)?;
    let policy_id = select_policy_id(&setup_packet).ok_or(types::Error::PolicyViolation)?;
    let route_segment = router
        .route_for_policy(&policy_id)
        .cloned()
        .map(|route| route.segment)
        .ok_or(types::Error::NotImplemented)?;
    let mut pipeline = RegistrySetupPipeline::new(router.registry_mut());
    hornet::setup::node_process_with_policy(
        &mut setup_packet,
        &secrets.node_secret,
        &secrets.sv,
        &route_segment,
        Some(&mut pipeline),
    )?;
    persist_state(storage, router, secrets);
    Ok(())
}

fn select_policy_id(packet: &hornet::setup::SetupPacket) -> Option<PolicyId> {
    for tlv in &packet.tlvs {
        if tlv.first().copied() != Some(POLICY_METADATA_TLV) {
            continue;
        }
        if let Ok(meta) = decode_metadata_tlv(tlv) {
            return Some(meta.policy_id);
        }
    }
    None
}
