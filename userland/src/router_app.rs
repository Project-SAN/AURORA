extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use aurora::application::setup::RegistrySetupPipeline;
use aurora::node::ReplayCache;
use aurora::policy::{decode_metadata_tlv, PolicyId, POLICY_METADATA_TLV};
use aurora::router::io::PacketListener;
use aurora::router::storage::{RouterStorage, StoredState};
use aurora::router::Router;
use aurora::setup::directory::from_signed_json;
use aurora::setup::wire;
use aurora::types::{self, PacketDirection, PacketType, Result as AuroraResult};
use aurora::utils::decode_hex;

use crate::fs;
use crate::router_io::{UserlandExitTransport, UserlandForward, UserlandPacketListener};
use crate::router_storage::UserlandRouterStorage;
use crate::sys;

#[cfg(feature = "aurora-time")]
use crate::time_provider::SysTimeProvider;

const ROUTER_CONFIG_PATH: &str = "/router_config.json";
const ROUTER_CONFIG_PATH_FALLBACK: &str = "/ROUTER~1.JSO";
const ROUTER_CONFIG_PATH_FALLBACK_NO_SLASH: &str = "ROUTER~1.JSO";
const ROUTER_CONFIG_PATH_SHORT: &str = "/ROUTER_C.JSO";
const ROUTER_CONFIG_PATH_SHORT_NO_SLASH: &str = "ROUTER_C.JSO";
const DIRECTORY_PATH_FALLBACK: &str = "/DIRECT~1.JSO";
const DIRECTORY_PATH_FALLBACK_NO_SLASH: &str = "DIRECT~1.JSO";
const DEFAULT_LISTEN_PORT: u16 = 7000;
const DEFAULT_CLI_PORT: u16 = 7001;
const DEFAULT_STORAGE_PATH: &str = "/router_state.json";

pub fn run_router() -> ! {
    log_line("router: run_router start");
    let mut config = load_config();
    log_line("router: config loaded");
    let storage = UserlandRouterStorage::new(config.storage_path.clone());
    log_line("router: storage ready");
    let mut router = Router::with_node_id(config.router_id.clone());
    log_line("router: instance ready");
    let secrets = load_state(&storage, &mut router);
    log_line("router: state loaded");
    if config.skip_policy {
        // Drop any policy runtime restored from persisted state when operating in
        // route-only mode.
        router = Router::with_node_id(config.router_id.clone());
        log_line("router: policy runtime disabled");
    }
    load_directory_if_configured(&mut router, &storage, &secrets, &config);
    log_line("router: directory loaded");
    let mut listener = match UserlandPacketListener::listen(config.listen_port, secrets.sv) {
        Ok(listener) => listener,
        Err(_) => loop {
            sys::sleep(1000);
        },
    };
    log_line("router: listener ready");
    let mut cli = CliServer::listen(config.cli_port);
    log_line("router: cli ready");
    let time = time_provider();
    let mut forward = UserlandForward::new();
    let mut exit = UserlandExitTransport::new();
    let mut replay = ReplayCache::new();
    log_line("router: event loop start");

    loop {
        if let Some(server) = cli.as_mut() {
            server.poll(&mut router, &mut config);
        }
        match listener.next() {
            Ok(Some(mut packet)) => {
                if packet.chdr.typ == PacketType::Setup {
                    if let Err(err) = handle_setup_packet(packet, &mut router, &storage, &secrets) {
                        let mut msg = String::new();
                        let _ = core::fmt::Write::write_fmt(
                            &mut msg,
                            format_args!("router: setup error {:?}", err),
                        );
                        log_line(&msg);
                    }
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
                if let Err(err) = res {
                    let mut msg = String::new();
                    let _ = core::fmt::Write::write_fmt(
                        &mut msg,
                        format_args!(
                            "router: packet error {:?} dir={:?} typ={} hops={} payload_len={}",
                            err,
                            packet.direction,
                            packet_type_label(packet.chdr.typ),
                            packet.chdr.hops,
                            packet.payload.len()
                        ),
                    );
                    log_line(&msg);
                }
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

fn packet_type_label(typ: PacketType) -> &'static str {
    match typ {
        PacketType::Setup => "Setup",
        PacketType::Data => "Data",
    }
}

#[derive(Clone)]
struct RouterConfig {
    listen_port: u16,
    storage_path: String,
    cli_port: u16,
    directory_path: Option<String>,
    directory_public_key: Option<String>,
    router_id: Option<String>,
    skip_policy: bool,
}

#[derive(Deserialize, Serialize)]
struct RouterConfigFile {
    listen_port: Option<u16>,
    storage_path: Option<String>,
    cli_port: Option<u16>,
    directory_path: Option<String>,
    directory_public_key: Option<String>,
    router_id: Option<String>,
    skip_policy: Option<bool>,
}

fn load_config() -> RouterConfig {
    let default = RouterConfig {
        listen_port: DEFAULT_LISTEN_PORT,
        storage_path: DEFAULT_STORAGE_PATH.into(),
        cli_port: DEFAULT_CLI_PORT,
        directory_path: None,
        directory_public_key: None,
        router_id: None,
        skip_policy: false,
    };
    let data = match read_all_any(&[
        ROUTER_CONFIG_PATH_SHORT,
        ROUTER_CONFIG_PATH_SHORT_NO_SLASH,
        ROUTER_CONFIG_PATH,
        ROUTER_CONFIG_PATH_FALLBACK,
        ROUTER_CONFIG_PATH_FALLBACK_NO_SLASH,
    ]) {
        Ok(bytes) => bytes,
        Err(_) => {
            log_line("config: using defaults");
            return default;
        }
    };
    let parsed: RouterConfigFile = match serde_json::from_slice(&data) {
        Ok(cfg) => cfg,
        Err(_) => {
            if let Ok(bytes) = read_all_any(&[ROUTER_CONFIG_CONTENT_PATH]) {
                if let Ok(cfg) = serde_json::from_slice::<RouterConfigFile>(&bytes) {
                    return RouterConfig {
                        listen_port: cfg.listen_port.unwrap_or(DEFAULT_LISTEN_PORT),
                        storage_path: cfg
                            .storage_path
                            .unwrap_or_else(|| DEFAULT_STORAGE_PATH.into()),
                        cli_port: cfg.cli_port.unwrap_or(DEFAULT_CLI_PORT),
                        directory_path: cfg.directory_path,
                        directory_public_key: cfg.directory_public_key,
                        router_id: cfg.router_id,
                        skip_policy: cfg.skip_policy.unwrap_or(false),
                    };
                }
            }
            return default;
        }
    };
    RouterConfig {
        listen_port: parsed.listen_port.unwrap_or(DEFAULT_LISTEN_PORT),
        storage_path: parsed
            .storage_path
            .unwrap_or_else(|| DEFAULT_STORAGE_PATH.into()),
        cli_port: parsed.cli_port.unwrap_or(DEFAULT_CLI_PORT),
        directory_path: parsed.directory_path,
        directory_public_key: parsed.directory_public_key,
        router_id: parsed.router_id,
        skip_policy: parsed.skip_policy.unwrap_or(false),
    }
}

fn read_all_any(paths: &[&str]) -> AuroraResult<Vec<u8>> {
    let mut last_err = None;
    for path in paths {
        match read_all(path) {
            Ok(bytes) => return Ok(bytes),
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err.unwrap_or(types::Error::Crypto))
}

fn read_all(path: &str) -> AuroraResult<Vec<u8>> {
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

fn write_all(path: &str, data: &[u8]) -> AuroraResult<()> {
    let handle =
        fs::open(path, fs::O_CREATE | fs::O_WRITE | fs::O_TRUNC).ok_or(types::Error::Crypto)?;
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

fn save_config(config: &RouterConfig) -> AuroraResult<()> {
    let file = RouterConfigFile {
        listen_port: Some(config.listen_port),
        storage_path: Some(config.storage_path.clone()),
        cli_port: Some(config.cli_port),
        directory_path: config.directory_path.clone(),
        directory_public_key: config.directory_public_key.clone(),
        router_id: config.router_id.clone(),
        skip_policy: Some(config.skip_policy),
    };
    let data = serde_json::to_vec_pretty(&file).map_err(|_| types::Error::Crypto)?;
    write_all(ROUTER_CONFIG_PATH_SHORT, &data)
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
            let _ = send_line(
                socket,
                "show running-config | startup-config | routes | policies",
            );
            let _ = send_line(socket, "configure terminal");
            let _ = send_line(
                socket,
                "set listen_port <port> | storage_path <path> | cli_port <port> | directory_path <path> | directory_public_key <hex> | router_id <id>",
            );
            let _ = send_line(socket, "commit | rollback | write memory | exit");
        }
        "show" => match parts.next() {
            Some("running-config") => show_running_config(socket, config),
            Some("startup-config") => show_startup_config(socket),
            Some("routes") => show_routes(socket, router),
            Some("policies") => show_policies(socket, router),
            _ => {
                let _ = send_line(
                    socket,
                    "usage: show running-config|startup-config|routes|policies",
                );
            }
        },
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
                (Some("directory_path"), Some(value)) => {
                    config.directory_path = Some(value.into());
                    let _ = send_line(socket, "ok (takes effect on restart)");
                }
                (Some("directory_public_key"), Some(value)) => {
                    config.directory_public_key = Some(value.into());
                    let _ = send_line(socket, "ok (takes effect on restart)");
                }
                (Some("router_id"), Some(value)) => {
                    config.router_id = Some(value.into());
                    let _ = send_line(socket, "ok (takes effect on restart)");
                }
                (Some("skip_policy"), Some(value)) => {
                    let val = match value {
                        "1" | "true" | "on" => Some(true),
                        "0" | "false" | "off" => Some(false),
                        _ => None,
                    };
                    if let Some(val) = val {
                        config.skip_policy = val;
                        let _ = send_line(socket, "ok (takes effect on restart)");
                    } else {
                        let _ = send_line(socket, "usage: set skip_policy true|false");
                    }
                }
                _ => {
                    let _ = send_line(
                        socket,
                        "usage: set listen_port <port> | storage_path <path> | cli_port <port> | directory_path <path> | directory_public_key <hex> | router_id <id> | skip_policy true|false",
                    );
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
    if let Some(path) = &config.directory_path {
        let _ = send_kv_str(socket, "directory_path", path);
    }
    if let Some(key) = &config.directory_public_key {
        let _ = send_kv_str(socket, "directory_public_key", key);
    }
    if let Some(router_id) = &config.router_id {
        let _ = send_kv_str(socket, "router_id", router_id);
    }
    let _ = send_kv_str(
        socket,
        "skip_policy",
        if config.skip_policy { "true" } else { "false" },
    );
}

fn show_startup_config(socket: &crate::socket::TcpSocket) {
    match read_all_any(&[
        ROUTER_CONFIG_PATH_SHORT,
        ROUTER_CONFIG_PATH_SHORT_NO_SLASH,
        ROUTER_CONFIG_PATH,
        ROUTER_CONFIG_PATH_FALLBACK,
        ROUTER_CONFIG_PATH_FALLBACK_NO_SLASH,
    ]) {
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

fn send_line(socket: &crate::socket::TcpSocket, line: &str) -> AuroraResult<()> {
    send_bytes(socket, line.as_bytes())?;
    send_bytes(socket, b"\n")
}

fn send_str(socket: &crate::socket::TcpSocket, s: &str) -> AuroraResult<()> {
    send_bytes(socket, s.as_bytes())
}

fn send_bytes(socket: &crate::socket::TcpSocket, buf: &[u8]) -> AuroraResult<()> {
    let mut offset = 0usize;
    while offset < buf.len() {
        let written = socket
            .send(&buf[offset..])
            .map_err(|_| types::Error::Crypto)?;
        if written == 0 {
            return Err(types::Error::Crypto);
        }
        offset += written;
    }
    Ok(())
}

fn read_line(socket: &crate::socket::TcpSocket, out: &mut Vec<u8>) -> AuroraResult<bool> {
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

fn time_provider() -> impl aurora::time::TimeProvider {
    #[cfg(feature = "aurora-time")]
    {
        SysTimeProvider
    }
    #[cfg(not(feature = "aurora-time"))]
    {
        struct DummyTime;
        impl aurora::time::TimeProvider for DummyTime {
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

fn load_directory_if_configured(
    router: &mut Router,
    storage: &dyn RouterStorage,
    secrets: &RouterSecrets,
    config: &RouterConfig,
) {
    log_line("directory: begin");
    let path = match config.directory_path.as_deref() {
        Some(path) if !path.is_empty() => path,
        _ => return,
    };
    log_line("directory: path ok");
    let key_hex = match config.directory_public_key.as_deref() {
        Some(key) if !key.is_empty() => key,
        _ => return,
    };
    log_line("directory: key present");

    log_line("directory: read start");
    let body_bytes = match read_all_any(&[
        path,
        DIRECTORY_PATH_FALLBACK,
        DIRECTORY_PATH_FALLBACK_NO_SLASH,
    ]) {
        Ok(bytes) => bytes,
        Err(_) => {
            log_line("directory: read failed");
            return;
        }
    };
    log_line("directory: read ok");
    let body = match core::str::from_utf8(&body_bytes) {
        Ok(text) => text,
        Err(_) => {
            log_line("directory: invalid utf-8");
            return;
        }
    };
    log_line("directory: utf8 ok");
    let key_bytes = match decode_hex(key_hex) {
        Ok(bytes) => bytes,
        Err(_) => {
            log_line("directory: bad public key hex");
            return;
        }
    };
    log_line("directory: key decode ok");
    if key_bytes.len() != 32 {
        log_line("directory: public key length invalid");
        return;
    }
    log_line("directory: verify start");
    match from_signed_json(body, &key_bytes) {
        Ok(directory) => {
            log_line("directory: verify ok");
            let installed = if config.skip_policy {
                let res = router.install_routes(directory.routes());
                if res.is_ok() {
                    log_line("directory: routes loaded (policy skipped)");
                }
                res
            } else {
                let res = router.install_directory(&directory);
                if res.is_ok() {
                    log_line("directory: loaded");
                }
                res
            };
            if installed.is_ok() {
                // Persisting the full directory-derived state can exceed practical
                // limits in the current userland environment and may crash.
                // Runtime operation only needs in-memory install here.
                let _ = (storage, secrets);
                log_line("directory: persist skipped");
            } else {
                log_line("directory: install failed");
            }
        }
        Err(_) => {
            log_line("directory: signature invalid");
        }
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

fn log_line(msg: &str) {
    let _ = sys::write(1, msg.as_bytes());
    let _ = sys::write(1, b"\n");
}

fn handle_setup_packet(
    packet: aurora::router::io::IncomingPacket,
    router: &mut Router,
    storage: &dyn RouterStorage,
    secrets: &RouterSecrets,
) -> AuroraResult<()> {
    if packet.chdr.typ != PacketType::Setup {
        return Err(types::Error::Length);
    }
    let mut setup_packet = wire::decode(packet.chdr, &packet.ahdr.bytes, &packet.payload)?;
    let policy_id = select_policy_id(&setup_packet).or_else(|| {
        let routes = router.routes();
        (routes.len() == 1).then_some(routes[0].policy_id)
    });
    let policy_id = policy_id.ok_or(types::Error::PolicyViolation)?;
    let route_segment = router
        .route_for_policy(&policy_id)
        .cloned()
        .or_else(|| router.routes().into_iter().next())
        .map(|route| route.segment)
        .ok_or(types::Error::NotImplemented)?;
    let mut pipeline = RegistrySetupPipeline::new(router.registry_mut());
    aurora::setup::node_process_with_policy(
        &mut setup_packet,
        &secrets.node_secret,
        &secrets.sv,
        &route_segment,
        Some(&mut pipeline),
    )?;
    // Setup-triggered persistence can overflow practical userland limits.
    let _ = (storage, secrets);
    log_line("setup: persist skipped");
    Ok(())
}

fn select_policy_id(packet: &aurora::setup::SetupPacket) -> Option<PolicyId> {
    for tlv in &packet.tlvs {
        if let Some(policy_id) = decode_policy_id_tlv(tlv) {
            return Some(policy_id);
        }
        if tlv.first().copied() != Some(POLICY_METADATA_TLV) {
            continue;
        }
        if let Ok(meta) = decode_metadata_tlv(tlv) {
            return Some(meta.policy_id);
        }
    }
    None
}

fn decode_policy_id_tlv(tlv: &[u8]) -> Option<PolicyId> {
    if tlv.first().copied() != Some(POLICY_ID_TLV) || tlv.len() != 33 {
        return None;
    }
    let mut policy_id = [0u8; 32];
    policy_id.copy_from_slice(&tlv[1..33]);
    Some(policy_id)
}

const POLICY_ID_TLV: u8 = 0xFE;
const ROUTER_CONFIG_CONTENT_PATH: &str = "/ROUTER_C.JSO";
