use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aurora::policy::blocklist;
use aurora::policy::TargetValue;
use aurora::router::storage::StoredState;
use aurora::routing::{self, IpAddr, RouteElem};
use aurora::setup::directory::RouteAnnouncement;
use aurora::types::{Nonce, PacketType, Si};
use aurora::utils::decode_hex;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use serde::Deserialize;

const STREAM_MAGIC: &[u8; 4] = b"HRS1";
const STREAM_OP_DATA: u8 = 2;
const STREAM_OP_CLOSE: u8 = 3;
const STREAM_DATA_OFFSET: usize = 64;

struct SenderConfig {
    policy_info: String,
    sender_bin: String,
    route_only: String,
    rounds: String,
    payload_len: usize,
    host_offset: usize,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("aurora_proxy error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let bind = env::var("HORNET_PROXY_BIND").unwrap_or_else(|_| "127.0.0.1:18080".to_string());
    let listener = TcpListener::bind(&bind).map_err(|e| format!("bind {bind}: {e}"))?;
    println!("aurora_proxy listening on {bind}");
    loop {
        let (mut stream, peer) = listener.accept().map_err(|e| format!("accept: {e}"))?;
        if let Err(err) = handle_client(&mut stream) {
            eprintln!("proxy client {peer}: {err}");
            let _ = send_http_error(&mut stream, 502, "Bad Gateway", &err);
        }
    }
}

fn handle_client(stream: &mut TcpStream) -> Result<(), String> {
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .ok();
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(5)))
        .ok();

    let req = read_http_request(stream)?;
    let (method, target_host, target_port) = parse_target(&req)?;
    let route_only = env::var("HORNET_PROXY_ROUTE_ONLY").unwrap_or_else(|_| "1".to_string());
    let default_payload_len = if route_only == "1" { 512 } else { 96 };
    let cfg = SenderConfig {
        policy_info: env::var("HORNET_POLICY_INFO")
            .unwrap_or_else(|_| "config/localnet/policy-info.json".to_string()),
        sender_bin: env::var("HORNET_DATA_SENDER_BIN")
            .unwrap_or_else(|_| "target/debug/aurora_data_sender".into()),
        route_only,
        rounds: env::var("HORNET_PROXY_ZKBOO_ROUNDS").unwrap_or_else(|_| "8".to_string()),
        payload_len: env::var("HORNET_PROXY_PAYLOAD_LEN")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(default_payload_len),
        host_offset: env::var("HORNET_PROXY_HOST_OFFSET")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(16),
    };
    let target = format!("{target_host}:{target_port}");

    if method.eq_ignore_ascii_case("CONNECT") {
        handle_connect_tunnel(stream, &cfg, &target, &target_host)
    } else {
        let outbound = normalize_http_request_for_policy(&req, &target_host, &cfg)?;
        eprintln!(
            "[proxy] forward HTTP {}:{} (in={} out={})",
            target_host,
            target_port,
            req.len(),
            outbound.len()
        );
        let response = run_sender(&cfg, &target, &outbound, false, None, None)?;
        eprintln!("[proxy] got response bytes={}", response.len());
        stream
            .write_all(&response)
            .map_err(|e| format!("write response: {e}"))
    }
}

fn handle_connect_tunnel(
    stream: &mut TcpStream,
    cfg: &SenderConfig,
    target: &str,
    host: &str,
) -> Result<(), String> {
    let open_timeout_secs = env::var("HORNET_CONNECT_OPEN_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);
    let data_timeout_override = env::var("HORNET_CONNECT_DATA_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok());
    let poll_timeout_override = env::var("HORNET_CONNECT_POLL_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok());
    let max_poll_timeout_override = env::var("HORNET_CONNECT_MAX_POLL_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok());
    let session_id = fresh_session_id()?;
    let internal_route_only =
        env::var("HORNET_PROXY_INTERNAL_ROUTE_ONLY").ok().as_deref() == Some("1");
    let mut route_only_session = if cfg.route_only == "1" && internal_route_only {
        Some(RouteOnlyTunnelSession::new(cfg, target)?)
    } else {
        None
    };
    // External sender mode must tolerate slower backward responses because
    // each sender process has an ephemeral listener; too-short timeouts
    // lose responses irrecoverably.
    let data_timeout_secs =
        data_timeout_override.unwrap_or(if route_only_session.is_some() { 10 } else { 20 });
    let poll_timeout_secs =
        poll_timeout_override.unwrap_or(if route_only_session.is_some() { 6 } else { 12 });
    let max_poll_timeout_secs =
        max_poll_timeout_override.unwrap_or(if route_only_session.is_some() { 20 } else { 30 });

    // Exit transport auto-opens on first DATA. Skipping explicit OPEN avoids
    // startup delay and duplicate stream state when retries occur.
    let _ = open_timeout_secs;
    eprintln!("[proxy] CONNECT open skipped (DATA auto-open)");
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .map_err(|e| format!("write connect ok: {e}"))?;

    stream
        .set_read_timeout(Some(Duration::from_millis(20)))
        .ok();
    let mut eof = false;
    let mut pending_response = false;
    let mut poll_backoff_ms: u64 = 50;
    let mut empty_polls: u32 = 0;
    let mut last_client_activity = Instant::now();
    let mut last_tunnel_to_client = Instant::now();
    let mut dumped_first_client_chunk = false;
    let client_priority_ms: u64 = env::var("HORNET_CONNECT_CLIENT_PRIORITY_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(500);
    let poll_window_secs: u64 = env::var("HORNET_CONNECT_POLL_WINDOW_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(40);
    let max_empty_polls: u32 = env::var("HORNET_CONNECT_MAX_EMPTY_POLLS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(6);
    let max_chunk = cfg.payload_len.saturating_sub(STREAM_DATA_OFFSET).max(1);
    let mut chunk = vec![0u8; max_chunk];
    loop {
        let mut sent_any = false;
        match stream.read(&mut chunk) {
            Ok(0) => {
                eof = true;
            }
            Ok(n) => {
                sent_any = true;
                let mut total = n;
                let mut extra_reads = 0u32;
                while total < chunk.len() && extra_reads < 8 {
                    match stream.read(&mut chunk[total..]) {
                        Ok(0) => {
                            eof = true;
                            break;
                        }
                        Ok(m) => {
                            total += m;
                            extra_reads = extra_reads.saturating_add(1);
                        }
                        Err(e)
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                || e.kind() == std::io::ErrorKind::TimedOut =>
                        {
                            break;
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                            eof = true;
                            break;
                        }
                        Err(e) => return Err(format!("read tunnel client (coalesce): {e}")),
                    }
                }
                eprintln!("[proxy] CONNECT client->tunnel bytes={}", total);
                if !dumped_first_client_chunk {
                    if let Ok(path) = env::var("HORNET_PROXY_DUMP_FIRST_CHUNK_PATH") {
                        if !path.trim().is_empty() {
                            let _ = fs::write(&path, &chunk[..total]);
                            eprintln!(
                                "[proxy] dumped first CONNECT chunk bytes={} path={}",
                                total, path
                            );
                        }
                    }
                    dumped_first_client_chunk = true;
                }
                let payload = build_stream_payload(
                    cfg.payload_len,
                    cfg.host_offset,
                    host,
                    STREAM_OP_DATA,
                    session_id,
                    &chunk[..total],
                )?;
                let response = send_connect_payload(
                    cfg,
                    target,
                    &mut route_only_session,
                    &payload,
                    data_timeout_secs,
                    true,
                )?;
                if !response.is_empty() {
                    eprintln!("[proxy] CONNECT tunnel->client bytes={}", response.len());
                    stream
                        .write_all(&response)
                        .map_err(|e| format!("write tunnel response: {e}"))?;
                    last_tunnel_to_client = Instant::now();
                }
                last_client_activity = Instant::now();
                pending_response = true;
                poll_backoff_ms = 50;
                empty_polls = 0;
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                eof = true;
            }
            Err(e) => return Err(format!("read tunnel client: {e}")),
        }

        if eof {
            break;
        }

        if pending_response && !sent_any {
            if last_tunnel_to_client.elapsed() < Duration::from_millis(client_priority_ms) {
                // Immediately after receiving server TLS records, prioritize
                // reading the client's next handshake records before issuing
                // long poll requests.
                thread::sleep(Duration::from_millis(5));
                continue;
            }
            if last_client_activity.elapsed() > Duration::from_secs(poll_window_secs) {
                pending_response = false;
                empty_polls = 0;
                poll_backoff_ms = 50;
                thread::sleep(Duration::from_millis(5));
                continue;
            }
            let payload = build_stream_payload(
                cfg.payload_len,
                cfg.host_offset,
                host,
                STREAM_OP_DATA,
                session_id,
                &[],
            )?;
            let current_poll_timeout = core::cmp::min(
                poll_timeout_secs.saturating_add((empty_polls as u64).saturating_mul(2)),
                max_poll_timeout_secs.max(poll_timeout_secs),
            );
            let response = send_connect_payload(
                cfg,
                target,
                &mut route_only_session,
                &payload,
                current_poll_timeout,
                false,
            )?;
            if !response.is_empty() {
                eprintln!(
                    "[proxy] CONNECT poll tunnel->client bytes={}",
                    response.len()
                );
                stream
                    .write_all(&response)
                    .map_err(|err| format!("write tunnel poll response: {err}"))?;
                last_tunnel_to_client = Instant::now();
                pending_response = true;
                poll_backoff_ms = 50;
                empty_polls = 0;
            } else {
                empty_polls = empty_polls.saturating_add(1);
                if empty_polls >= max_empty_polls {
                    // Give control back to client-side read path if peer is silent.
                    pending_response = false;
                    poll_backoff_ms = 50;
                } else {
                    // Keep polling while a tunnel exchange is in-flight.
                    // TLS handshakes often have a silent gap before ServerHello arrives.
                    pending_response = true;
                    thread::sleep(Duration::from_millis(poll_backoff_ms));
                    poll_backoff_ms = (poll_backoff_ms.saturating_mul(2)).min(250);
                }
            }
        } else if !sent_any {
            // Avoid hammering sender with empty DATA frames when no client traffic is pending.
            thread::sleep(Duration::from_millis(10));
        }
    }

    let close_payload = build_stream_payload(
        cfg.payload_len,
        cfg.host_offset,
        host,
        STREAM_OP_CLOSE,
        session_id,
        &[],
    )?;
    if let Some(session) = route_only_session.as_mut() {
        let _ = session.send(&close_payload, 1);
    } else {
        let _ = run_sender_tunnel(cfg, target, &close_payload, Some(0), None)?;
    }
    Ok(())
}

fn send_connect_payload(
    cfg: &SenderConfig,
    target: &str,
    route_only_session: &mut Option<RouteOnlyTunnelSession>,
    payload: &[u8],
    timeout_secs: u64,
    fallback_on_empty: bool,
) -> Result<Vec<u8>, String> {
    if let Some(session) = route_only_session.as_mut() {
        let response = session.send(payload, timeout_secs)?;
        let degrade_on_empty = env::var("HORNET_PROXY_INTERNAL_DEGRADE_ON_EMPTY")
            .ok()
            .as_deref()
            == Some("1");
        let allow_internal_fallback =
            env::var("HORNET_PROXY_INTERNAL_FALLBACK").ok().as_deref() == Some("1");
        if fallback_on_empty && response.is_empty() && degrade_on_empty {
            eprintln!(
                "[proxy] route-only internal empty response, switching to sender mode for remaining tunnel"
            );
            *route_only_session = None;
            return Ok(response);
        }
        if fallback_on_empty && response.is_empty() && allow_internal_fallback {
            eprintln!("[proxy] route-only internal empty response, fallback to sender process");
            return run_sender_tunnel(cfg, target, payload, Some(timeout_secs), None);
        }
        return Ok(response);
    }
    run_sender_tunnel(cfg, target, payload, Some(timeout_secs), None)
}

#[derive(Clone, Deserialize)]
struct PolicyInfo {
    policy_id: String,
    routers: Vec<RouterInfo>,
}

#[derive(Clone, Deserialize)]
struct RouterInfo {
    bind: String,
    storage_path: String,
}

struct RouteOnlyTunnelSession {
    policy_id: [u8; 32],
    routers: Vec<(StoredState, RouterInfo)>,
    target_host: String,
    target_ip: IpAddr,
    target_port: u16,
    entry_addr: String,
    listener: TcpListener,
    return_ip: IpAddr,
    return_port: u16,
    rng: ChaCha20Rng,
}

impl RouteOnlyTunnelSession {
    fn new(cfg: &SenderConfig, target: &str) -> Result<Self, String> {
        let json = fs::read_to_string(&cfg.policy_info)
            .map_err(|err| format!("failed to read {}: {err}", cfg.policy_info))?;
        let info: PolicyInfo = serde_json::from_str(&json)
            .map_err(|err| format!("invalid policy-info JSON: {err}"))?;
        if info.routers.is_empty() {
            return Err("policy-info has no routers".into());
        }
        let policy_id = decode_policy_id(&info.policy_id)?;
        let routers = load_router_states(&info.routers, &policy_id)?;
        let (host, port) = parse_host_port(target, 443)?;
        let (target_ip, target_port) = resolve_target_parts(&host, port)?;
        let entry_addr = env::var("HORNET_PROXY_ENTRY_ADDR")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| normalize_entry_addr(&cfg.policy_info, &routers[0].1.bind));
        let listener = TcpListener::bind("127.0.0.1:0")
            .map_err(|e| format!("failed to bind response listener: {e}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("set nonblocking listener: {e}"))?;
        let local = listener
            .local_addr()
            .map_err(|e| format!("local_addr response listener: {e}"))?;
        let return_ip = if let Ok(host) = env::var("HORNET_PROXY_RETURN_HOST") {
            if !host.trim().is_empty() {
                IpAddr::V4(parse_ipv4_octets(&host)?)
            } else {
                resolve_return_ip(local)?
            }
        } else if let Ok(host) = env::var("HORNET_RETURN_HOST") {
            if !host.trim().is_empty() {
                IpAddr::V4(parse_ipv4_octets(&host)?)
            } else {
                resolve_return_ip(local)?
            }
        } else if cfg.policy_info.contains("config/qemu/") {
            IpAddr::V4([10, 0, 2, 2])
        } else {
            resolve_return_ip(local)?
        };
        let return_port = local.port();
        let rng = ChaCha20Rng::seed_from_u64(derive_seed());
        eprintln!(
            "[proxy][route-only] cfg entry_addr={} return={:?}:{} target={:?}:{}",
            entry_addr, return_ip, return_port, target_ip, target_port
        );
        Ok(Self {
            policy_id,
            routers,
            target_host: host,
            target_ip,
            target_port,
            entry_addr,
            listener,
            return_ip,
            return_port,
            rng,
        })
    }

    fn send(&mut self, request_payload: &[u8], timeout_secs: u64) -> Result<Vec<u8>, String> {
        eprintln!(
            "[proxy][route-only] send req_bytes={} timeout={}s",
            request_payload.len(),
            timeout_secs
        );
        let hops = self.routers.len();
        let rmax = hops;
        let mut keys = Vec::with_capacity(hops);
        for _ in 0..hops {
            let mut si = [0u8; 16];
            self.rng.fill_bytes(&mut si);
            keys.push(Si(si));
        }
        let exp = compute_expiry(600);
        let mut fses = Vec::with_capacity(hops);
        for (hop, (state, _route_info)) in self.routers.iter().enumerate() {
            let segment = if hop == hops - 1 {
                routing::segment_from_elems(&[RouteElem::ExitTcp {
                    addr: self.target_ip.clone(),
                    port: self.target_port,
                }])
            } else {
                let route = select_route(state, &self.policy_id)?;
                route.segment
            };
            let fs = aurora::packet::core::create(&state.sv(), &keys[hop], &segment, exp)
                .map_err(|err| format!("failed to build FS for hop {}: {err:?}", hop))?;
            fses.push(fs);
        }
        let mut ahdr_rng = ChaCha20Rng::seed_from_u64(derive_seed() ^ 0xA55A_A55A);
        let ahdr = aurora::packet::ahdr::create_ahdr(&keys, &fses, rmax, &mut ahdr_rng)
            .map_err(|err| format!("failed to build AHDR: {err:?}"))?;

        let mut iv = {
            let mut buf = [0u8; 16];
            self.rng.fill_bytes(&mut buf);
            Nonce(buf)
        };
        let mut chdr = aurora::packet::chdr::data_header(hops as u8, iv);

        let mut keys_b = Vec::with_capacity(hops);
        for _ in 0..hops {
            let mut si = [0u8; 16];
            self.rng.fill_bytes(&mut si);
            keys_b.push(Si(si));
        }
        let mut fses_b = Vec::with_capacity(hops);
        for (i, hop_idx) in (0..hops).rev().enumerate() {
            let segment = if hop_idx == 0 {
                routing::segment_from_elems(&[RouteElem::NextHop {
                    addr: self.return_ip.clone(),
                    port: self.return_port,
                }])
            } else {
                let prev_router = &self.routers[hop_idx - 1].1;
                let (ip_str, port_str) = prev_router
                    .bind
                    .rsplit_once(':')
                    .ok_or("invalid bind addr")?;
                let port: u16 = port_str.parse().map_err(|_| "invalid bind port")?;
                let ip = parse_ipv4_octets(ip_str)?;
                routing::segment_from_elems(&[RouteElem::NextHop {
                    addr: IpAddr::V4(ip),
                    port,
                }])
            };
            let state = &self.routers[hop_idx].0;
            let fs = aurora::packet::core::create(&state.sv(), &keys_b[i], &segment, exp)
                .map_err(|err| format!("failed to build Backward FS for hop {}: {err:?}", i))?;
            fses_b.push(fs);
        }
        let mut ahdr_b_rng = ChaCha20Rng::seed_from_u64(derive_seed() ^ 0xBEEF_BEEF);
        let ahdr_b = aurora::packet::ahdr::create_ahdr(&keys_b, &fses_b, rmax, &mut ahdr_b_rng)
            .map_err(|err| format!("failed to build Backward AHDR: {err:?}"))?;

        let canonical_bytes = canonical_target_leaf(&self.target_host)?;
        let mut full_payload = Vec::new();
        full_payload.extend_from_slice(&(ahdr_b.bytes.len() as u32).to_le_bytes());
        full_payload.extend_from_slice(&ahdr_b.bytes);
        full_payload.extend_from_slice(request_payload);

        let mut encrypted_tail = Vec::new();
        encrypted_tail.extend_from_slice(&canonical_bytes);
        encrypted_tail.extend_from_slice(&full_payload);
        aurora::source::build(&mut chdr, &ahdr, &keys, &mut iv, &mut encrypted_tail)
            .map_err(|err| format!("failed to build payload: {err:?}"))?;
        let frame = encode_frame(&chdr, &ahdr.bytes, &encrypted_tail)?;
        send_frame_to(&self.entry_addr, &frame)?;
        eprintln!("[proxy][route-only] frame sent bytes={}", frame.len());

        let mut keys_b_reversed = keys_b;
        keys_b_reversed.reverse();
        if timeout_secs == 0 {
            eprintln!("[proxy][route-only] response wait skipped");
            return Ok(Vec::new());
        }
        let deadline = Instant::now() + Duration::from_secs(timeout_secs.max(1));
        loop {
            if Instant::now() >= deadline {
                eprintln!("[proxy][route-only] response timeout");
                return Ok(Vec::new());
            }
            match self.listener.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_nonblocking(false)
                        .map_err(|e| format!("set blocking response stream: {e}"))?;
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    let read_timeout = core::cmp::max(remaining, Duration::from_millis(500));
                    stream
                        .set_read_timeout(Some(read_timeout))
                        .map_err(|e| format!("set read timeout response stream: {e}"))?;
                    let frame = match read_backward_frame(&mut stream) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    let mut payload = frame.payload;
                    let mut iv_resp = frame.specific;
                    if aurora::source::decrypt_backward_payload(
                        &keys_b_reversed,
                        &mut iv_resp,
                        &mut payload,
                    )
                    .is_ok()
                    {
                        eprintln!(
                            "[proxy][route-only] response decrypted bytes={}",
                            payload.len()
                        );
                        return Ok(payload);
                    }
                    eprintln!("[proxy][route-only] stale/unmatched response ignored");
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2));
                }
                Err(e) => return Err(format!("accept response failed: {e}")),
            }
        }
    }
}

struct BackwardFrame {
    specific: [u8; 16],
    payload: Vec<u8>,
}

fn read_backward_frame(stream: &mut TcpStream) -> Result<BackwardFrame, String> {
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .map_err(|e| format!("read backward header failed: {e}"))?;
    let mut specific = [0u8; 16];
    stream
        .read_exact(&mut specific)
        .map_err(|e| format!("read backward specific failed: {e}"))?;
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| format!("read backward ahdr len failed: {e}"))?;
    let ahdr_len = u32::from_le_bytes(len_buf) as usize;
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| format!("read backward payload len failed: {e}"))?;
    let payload_len = u32::from_le_bytes(len_buf) as usize;
    if ahdr_len > 0 {
        let mut ahdr = vec![0u8; ahdr_len];
        stream
            .read_exact(&mut ahdr)
            .map_err(|e| format!("read backward ahdr failed: {e}"))?;
    }
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        stream
            .read_exact(&mut payload)
            .map_err(|e| format!("read backward payload failed: {e}"))?;
    }
    Ok(BackwardFrame { specific, payload })
}

fn run_sender_tunnel(
    cfg: &SenderConfig,
    target: &str,
    request: &[u8],
    response_timeout_secs: Option<u64>,
    response_bind: Option<&str>,
) -> Result<Vec<u8>, String> {
    match run_sender(
        cfg,
        target,
        request,
        true,
        response_timeout_secs,
        response_bind,
    ) {
        Ok(bytes) => Ok(bytes),
        Err(err) if err.contains("Broken pipe") || err.contains("Connection reset") => {
            eprintln!("[proxy] sender transient tunnel error tolerated: {}", err);
            Ok(Vec::new())
        }
        Err(err) => Err(err),
    }
}

fn run_sender(
    cfg: &SenderConfig,
    target: &str,
    request: &[u8],
    allow_response_timeout: bool,
    response_timeout_secs: Option<u64>,
    response_bind: Option<&str>,
) -> Result<Vec<u8>, String> {
    let req_path = write_temp_request(request)?;
    let rsp_path = temp_path("hornet-proxy-rsp")?;
    let mut cmd = Command::new(&cfg.sender_bin);
    cmd.arg(&cfg.policy_info)
        .arg(target)
        .arg("00")
        .env("HORNET_REQUEST_PATH", &req_path)
        .env("HORNET_RESPONSE_OUTPUT_PATH", &rsp_path)
        .env("HORNET_ZKBOO_ROUNDS", &cfg.rounds);
    if let Ok(return_host) = env::var("HORNET_PROXY_RETURN_HOST") {
        if !return_host.is_empty() {
            cmd.env("HORNET_RETURN_HOST", return_host);
        }
    } else if cfg.policy_info.contains("config/qemu/") {
        // QEMU hostfwd topology: guest routers reach host via 10.0.2.2.
        cmd.env("HORNET_RETURN_HOST", "10.0.2.2");
    }
    if let Ok(entry_addr) = env::var("HORNET_PROXY_ENTRY_ADDR") {
        if !entry_addr.is_empty() {
            cmd.env("HORNET_ENTRY_ADDR", entry_addr);
        }
    } else if cfg.policy_info.contains("config/qemu/") {
        let entry_addr = default_entry_addr_for_policy(&cfg.policy_info)
            .unwrap_or_else(|| "127.0.0.1:17011".to_string());
        cmd.env("HORNET_ENTRY_ADDR", entry_addr);
    }
    if !cfg.route_only.is_empty() {
        cmd.env("HORNET_ROUTE_ONLY", &cfg.route_only);
    }
    if let Some(secs) = response_timeout_secs {
        cmd.env("HORNET_RESPONSE_TIMEOUT_SECS", secs.to_string());
    }
    if let Some(bind) = response_bind {
        if !bind.is_empty() {
            cmd.env("HORNET_RESPONSE_BIND", bind);
        }
    }
    let output = cmd
        .output()
        .map_err(|e| format!("spawn aurora_data_sender: {e}"))?;
    let _ = fs::remove_file(&req_path);

    if !output.status.success() {
        let _ = fs::remove_file(&rsp_path);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        if allow_response_timeout
            && (stderr.contains("response timeout after")
                || stdout.contains("response timeout after"))
        {
            if !stdout.trim().is_empty() {
                eprintln!(
                    "[proxy] sender timeout stdout: {}",
                    stdout.replace('\n', " | ")
                );
            }
            eprintln!("[proxy] sender timeout tolerated target={}", target);
            return Ok(Vec::new());
        }
        return Err(format!(
            "aurora_data_sender failed (status={}): {} {}",
            output.status,
            stderr.trim(),
            stdout.trim()
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.trim().is_empty() {
        eprintln!("[proxy] sender stdout: {}", stdout.replace('\n', " | "));
    }
    let bytes = fs::read(&rsp_path).map_err(|e| format!("read sender response output: {e}"))?;
    eprintln!(
        "[proxy] sender ok target={} req_bytes={} rsp_bytes={}",
        target,
        request.len(),
        bytes.len()
    );
    let _ = fs::remove_file(&rsp_path);
    Ok(bytes)
}

fn decode_policy_id(hex: &str) -> Result<[u8; 32], String> {
    let bytes = decode_hex(hex).map_err(|err| format!("invalid policy_id hex: {err}"))?;
    if bytes.len() != 32 {
        return Err("policy_id must be 32 bytes".into());
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    Ok(id)
}

fn load_router_states(
    routers: &[RouterInfo],
    policy_id: &[u8; 32],
) -> Result<Vec<(StoredState, RouterInfo)>, String> {
    let mut out = Vec::new();
    for info in routers {
        let data = fs::read(&info.storage_path)
            .map_err(|err| format!("failed to read {}: {err}", info.storage_path))?;
        let state: StoredState =
            serde_json::from_slice(&data).map_err(|err| format!("invalid state JSON: {err}"))?;
        if select_route(&state, policy_id).is_err() {
            return Err(format!(
                "state {} has no route for policy",
                info.storage_path
            ));
        }
        out.push((state, info.clone()));
    }
    Ok(out)
}

fn select_route(state: &StoredState, policy_id: &[u8; 32]) -> Result<RouteAnnouncement, String> {
    state
        .routes()
        .into_iter()
        .find(|route| &route.policy_id == policy_id)
        .ok_or_else(|| "no route for policy".into())
}

fn resolve_target_parts(hostname: &str, port: u16) -> Result<(IpAddr, u16), String> {
    use std::net::ToSocketAddrs;

    let mut addrs = (hostname, port)
        .to_socket_addrs()
        .map_err(|e| format!("failed to resolve {hostname}:{port}: {e}"))?;
    let addr = addrs
        .next()
        .ok_or_else(|| format!("no suitable address found for {hostname}:{port}"))?;
    match addr {
        std::net::SocketAddr::V4(v4) => Ok((IpAddr::V4(v4.ip().octets()), v4.port())),
        std::net::SocketAddr::V6(v6) => Ok((IpAddr::V6(v6.ip().octets()), v6.port())),
    }
}

fn normalize_entry_addr(policy_info_path: &str, bind: &str) -> String {
    if !policy_info_path.contains("config/qemu/") {
        return bind.to_string();
    }
    let Some((ip, port)) = bind.rsplit_once(':') else {
        return bind.to_string();
    };
    if ip == "10.0.2.2" {
        format!("127.0.0.1:{port}")
    } else {
        bind.to_string()
    }
}

fn default_entry_addr_for_policy(policy_info_path: &str) -> Option<String> {
    let json = fs::read_to_string(policy_info_path).ok()?;
    let info: PolicyInfo = serde_json::from_str(&json).ok()?;
    let first = info.routers.first()?;
    Some(normalize_entry_addr(policy_info_path, &first.bind))
}

fn parse_ipv4_octets(ip: &str) -> Result<[u8; 4], String> {
    let addr: std::net::Ipv4Addr = ip.parse().map_err(|_| "invalid ipv4".to_string())?;
    Ok(addr.octets())
}

fn resolve_return_ip(local_addr: std::net::SocketAddr) -> Result<IpAddr, String> {
    if let Ok(host) = env::var("HORNET_PROXY_RETURN_HOST") {
        if !host.trim().is_empty() {
            return Ok(IpAddr::V4(parse_ipv4_octets(&host)?));
        }
    }
    if let Ok(host) = env::var("HORNET_RETURN_HOST") {
        if !host.trim().is_empty() {
            return Ok(IpAddr::V4(parse_ipv4_octets(&host)?));
        }
    }
    match local_addr {
        std::net::SocketAddr::V4(v4) => Ok(IpAddr::V4(v4.ip().octets())),
        std::net::SocketAddr::V6(v6) => Ok(IpAddr::V6(v6.ip().octets())),
    }
}

fn canonical_target_leaf(host_port: &str) -> Result<Vec<u8>, String> {
    let (host, _port) = parse_host_port(host_port, 443)?;
    let target = if let Ok(addr) = host.parse::<std::net::Ipv4Addr>() {
        TargetValue::Ipv4(addr.octets())
    } else if let Ok(addr) = host.parse::<std::net::Ipv6Addr>() {
        TargetValue::Ipv6(addr.octets())
    } else {
        TargetValue::Domain(host.to_ascii_lowercase().into_bytes())
    };
    let entry = blocklist::entry_from_target(&target)
        .map_err(|err| format!("failed to canonicalise host: {err:?}"))?;
    Ok(entry.leaf_bytes().as_slice().to_vec())
}

fn compute_expiry(delta_secs: u64) -> aurora::types::Exp {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let expiry = now.saturating_add(delta_secs);
    aurora::types::Exp(expiry.min(u32::MAX as u64) as u32)
}

fn derive_seed() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    (nanos ^ (std::process::id() as u128)) as u64
}

fn encode_frame(
    chdr: &aurora::types::Chdr,
    ahdr: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    if ahdr.len() > u32::MAX as usize || payload.len() > u32::MAX as usize {
        return Err("frame too large".into());
    }
    let mut frame = Vec::with_capacity(4 + 16 + 8 + ahdr.len() + payload.len());
    frame.push(0);
    frame.push(match chdr.typ {
        PacketType::Setup => 0,
        PacketType::Data => 1,
    });
    frame.push(chdr.hops);
    frame.push(0);
    frame.extend_from_slice(&chdr.specific);
    frame.extend_from_slice(&(ahdr.len() as u32).to_le_bytes());
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(ahdr);
    frame.extend_from_slice(payload);
    Ok(frame)
}

fn send_frame_to(addr: &str, frame: &[u8]) -> Result<(), String> {
    let mut stream =
        TcpStream::connect(addr).map_err(|err| format!("failed to connect to {}: {err}", addr))?;
    stream
        .write_all(frame)
        .map_err(|err| format!("failed to send frame: {err}"))?;
    Ok(())
}

fn build_stream_payload(
    payload_len: usize,
    host_offset: usize,
    host: &str,
    op: u8,
    session_id: u64,
    data: &[u8],
) -> Result<Vec<u8>, String> {
    if payload_len < STREAM_DATA_OFFSET {
        return Err(format!("payload len must be >= {}", STREAM_DATA_OFFSET));
    }
    let host_header = {
        let mut v = Vec::with_capacity(6 + host.len() + 2);
        v.extend_from_slice(b"Host: ");
        v.extend_from_slice(host.as_bytes());
        v.extend_from_slice(b"\r\n");
        v
    };
    if host_offset + host_header.len() > payload_len {
        return Err("host header does not fit payload policy window".into());
    }
    if data.len() > u16::MAX as usize {
        return Err("data too large".into());
    }
    if STREAM_DATA_OFFSET + data.len() > payload_len {
        return Err("data does not fit payload frame".into());
    }

    let mut out = vec![0u8; payload_len];
    out[..4].copy_from_slice(STREAM_MAGIC);
    out[4] = op;
    out[6..8].copy_from_slice(&(data.len() as u16).to_be_bytes());
    out[8..16].copy_from_slice(&session_id.to_be_bytes());
    out[STREAM_DATA_OFFSET..STREAM_DATA_OFFSET + data.len()].copy_from_slice(data);
    out[host_offset..host_offset + host_header.len()].copy_from_slice(&host_header);
    Ok(out)
}

fn fresh_session_id() -> Result<u64, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "clock error")?
        .as_nanos();
    Ok((now & 0xFFFF_FFFF_FFFF_FFFF) as u64)
}

fn normalize_http_request_for_policy(
    req: &[u8],
    host: &str,
    cfg: &SenderConfig,
) -> Result<Vec<u8>, String> {
    if req.len() == cfg.payload_len {
        return Ok(req.to_vec());
    }
    build_fixed_http_get(host, cfg.payload_len, cfg.host_offset)
}

fn build_fixed_http_get(
    host: &str,
    payload_len: usize,
    host_offset: usize,
) -> Result<Vec<u8>, String> {
    let prefix = b"GET / HTTP/1.1\r\n";
    if host_offset != prefix.len() {
        return Err(format!(
            "host_offset={} is unsupported for fixed GET template (expected {})",
            host_offset,
            prefix.len()
        ));
    }
    let mut out = Vec::new();
    out.extend_from_slice(prefix);
    out.extend_from_slice(b"Host: ");
    out.extend_from_slice(host.as_bytes());
    out.extend_from_slice(b"\r\nConnection: close\r\nX-Pad: ");
    if out.len() + 4 > payload_len {
        return Err("payload_len too small for fixed request".into());
    }
    let pad_len = payload_len - out.len() - 4;
    out.extend(core::iter::repeat_n(b'a', pad_len));
    out.extend_from_slice(b"\r\n\r\n");
    if out.len() != payload_len {
        return Err("failed to construct fixed payload length request".into());
    }
    Ok(out)
}

fn read_http_request(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = stream
            .read(&mut tmp)
            .map_err(|e| format!("read request: {e}"))?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if find_header_end(&buf).is_some() {
            break;
        }
        if buf.len() > 1024 * 1024 {
            return Err("request too large".into());
        }
    }
    if buf.is_empty() {
        return Err("empty request".into());
    }

    let Some(header_end) = find_header_end(&buf) else {
        return Err("incomplete HTTP headers".into());
    };

    let content_len = parse_content_length(&buf[..header_end])?;
    let wanted = header_end + content_len;
    while buf.len() < wanted {
        let n = stream
            .read(&mut tmp)
            .map_err(|e| format!("read body: {e}"))?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    if buf.len() < wanted {
        return Err("incomplete HTTP body".into());
    }
    buf.truncate(wanted);
    Ok(buf)
}

fn parse_target(req: &[u8]) -> Result<(String, String, u16), String> {
    let req_str = std::str::from_utf8(req).map_err(|_| "request is not UTF-8 HTTP text")?;
    let mut lines = req_str.split("\r\n");
    let line = lines.next().ok_or("missing request line")?;
    let mut parts = line.split_whitespace();
    let method = parts.next().ok_or("missing method")?.to_string();
    let uri = parts.next().ok_or("missing URI")?;

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = parse_host_port(uri, 443)?;
        return Ok((method, host, port));
    }

    if let Some(rest) = uri.strip_prefix("http://") {
        let authority = rest.split('/').next().ok_or("invalid absolute URI")?;
        let (host, port) = parse_host_port(authority, 80)?;
        return Ok((method, host, port));
    }

    for h in lines {
        if h.len() >= 5 && h.as_bytes()[..5].eq_ignore_ascii_case(b"host:") {
            let host = h[5..].trim();
            let (host, port) = parse_host_port(host, 80)?;
            return Ok((method, host, port));
        }
    }

    Err("missing Host header".into())
}

fn parse_host_port(s: &str, default_port: u16) -> Result<(String, u16), String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty host".into());
    }
    if let Some(rest) = s.strip_prefix('[') {
        let (inside, after) = rest
            .split_once(']')
            .ok_or("invalid IPv6 host, missing closing bracket")?;
        let port = if let Some(ps) = after.strip_prefix(':') {
            ps.parse::<u16>().map_err(|_| "invalid port")?
        } else {
            default_port
        };
        return Ok((inside.to_string(), port));
    }
    if let Some((host, port_str)) = s.rsplit_once(':') {
        if !host.contains(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                return Ok((host.to_string(), port));
            }
        }
    }
    Ok((s.to_string(), default_port))
}

fn parse_content_length(headers: &[u8]) -> Result<usize, String> {
    let s = std::str::from_utf8(headers).map_err(|_| "headers are not UTF-8")?;
    for line in s.split("\r\n") {
        if line.len() >= 15 && line.as_bytes()[..15].eq_ignore_ascii_case(b"content-length:") {
            let value = line[15..].trim();
            return value
                .parse::<usize>()
                .map_err(|_| "invalid Content-Length".to_string());
        }
    }
    Ok(0)
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn write_temp_request(req: &[u8]) -> Result<PathBuf, String> {
    let path = temp_path("hornet-proxy-req")?;
    fs::write(&path, req).map_err(|e| format!("write temp request: {e}"))?;
    Ok(path)
}

fn temp_path(prefix: &str) -> Result<PathBuf, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "clock error")?
        .as_nanos();
    Ok(PathBuf::from(format!("/tmp/{prefix}-{now}.bin")))
}

fn send_http_error(
    stream: &mut TcpStream,
    code: u16,
    reason: &str,
    body: &str,
) -> Result<(), String> {
    let resp = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream
        .write_all(resp.as_bytes())
        .map_err(|e| format!("write error response: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_target_origin_form_uses_host_header() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (method, host, port) = parse_target(req).expect("parse");
        assert_eq!(method, "GET");
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
    }

    #[test]
    fn parse_target_absolute_uri() {
        let req = b"GET http://example.com/path HTTP/1.1\r\nHost: ignored.invalid\r\n\r\n";
        let (_method, host, port) = parse_target(req).expect("parse");
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
    }

    #[test]
    fn parse_target_connect_tunnel() {
        let req = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        let (method, host, port) = parse_target(req).expect("parse");
        assert_eq!(method, "CONNECT");
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_content_length_zero_by_default() {
        let len = parse_content_length(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n").expect("len");
        assert_eq!(len, 0);
    }

    #[test]
    fn parse_content_length_value() {
        let len = parse_content_length(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 12\r\n\r\n")
            .expect("len");
        assert_eq!(len, 12);
    }
}
