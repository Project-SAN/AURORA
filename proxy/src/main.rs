use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aurora::core::policy::ProofKind;
use aurora::core::policy::{
    encode_extensions_into, CapsuleExtensionRef, AUX_MAX, EXT_TAG_KEY_HASH, EXT_TAG_PAYLOAD_HASH,
    EXT_TAG_SEQUENCE,
};
use aurora::crypto::ascon::{mix_fold, MIX_DOMAIN_KEYBIND, MIX_DOMAIN_PAYLOAD};
use aurora::crypto::zkp::Circuit;
use aurora::policy::blocklist;
use aurora::policy::zkboo::ZkBooProofService;
use aurora::policy::TargetValue;
use aurora::policy::{PolicyMetadata, POLICY_ID_TLV};
use aurora::router::storage::StoredState;
use aurora::routing::{self, IpAddr, RouteElem};
use aurora::setup::directory::RouteAnnouncement;
use aurora::setup::wire;
use aurora::tunnel::{TunnelOp, TunnelPrefix};
use aurora::types::{Chdr, Nonce, PacketType, Si};
use aurora::utils::decode_hex;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use serde::Deserialize;
use x25519_dalek::x25519;

const STREAM_MAGIC: &[u8; 4] = b"HRS1";
const STREAM_OP_OPEN: u8 = 1;
const STREAM_OP_DATA: u8 = 2;
const STREAM_OP_CLOSE: u8 = 3;
const STREAM_DATA_OFFSET: usize = 64;
static SETUP_SENT: AtomicBool = AtomicBool::new(false);

struct SenderConfig {
    policy_info: String,
    route_only: String,
    rounds: String,
    payload_len: usize,
    connect_payload_len: usize,
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
    let route_only = env::var("HORNET_PROXY_ROUTE_ONLY").unwrap_or_else(|_| "0".to_string());
    let default_payload_len = if route_only == "1" { 512 } else { 96 };
    let cfg = SenderConfig {
        policy_info: env::var("HORNET_POLICY_INFO")
            .unwrap_or_else(|_| "config/localnet/policy-info.json".to_string()),
        route_only,
        rounds: env::var("HORNET_PROXY_ZKBOO_ROUNDS").unwrap_or_else(|_| "8".to_string()),
        payload_len: env::var("HORNET_PROXY_PAYLOAD_LEN")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(default_payload_len),
        connect_payload_len: env::var("HORNET_CONNECT_PAYLOAD_LEN")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(512),
        host_offset: env::var("HORNET_PROXY_HOST_OFFSET")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(16),
    };
    maybe_send_setup(&cfg)?;
    let target = format!("{target_host}:{target_port}");
    let response_timeout_secs = env::var("HORNET_PROXY_RESPONSE_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20);

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
        let response = if cfg.route_only == "1" {
            let mut session = RouteOnlyTunnelSession::new(&cfg, &target)?;
            session.send(&outbound, response_timeout_secs)?
        } else {
            let mut session = PolicyTunnelSession::new(&cfg, &target)?;
            session.send_request(&outbound, response_timeout_secs)?
        };
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
    let poll_timeout_override = env::var("HORNET_CONNECT_POLL_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok());
    let max_poll_timeout_override = env::var("HORNET_CONNECT_MAX_POLL_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok());
    let session_id = fresh_session_id()?;
    let mut route_only_session = if cfg.route_only == "1" {
        Some(RouteOnlyTunnelSession::new(cfg, target)?)
    } else {
        None
    };
    let mut policy_session = if cfg.route_only == "1" {
        None
    } else {
        Some(PolicyTunnelSession::new(cfg, target)?)
    };
    let poll_timeout_secs =
        poll_timeout_override.unwrap_or(if route_only_session.is_some() { 6 } else { 12 });
    let max_poll_timeout_secs =
        max_poll_timeout_override.unwrap_or(if route_only_session.is_some() { 20 } else { 30 });
    let connect_open_rounds: u16 = env::var("HORNET_CONNECT_OPEN_ZKBOO_ROUNDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let push_timeout_secs: u64 = env::var("HORNET_CONNECT_PUSH_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);
    let send_gap_ms: u64 = env::var("HORNET_CONNECT_SEND_GAP_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(500);

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
    let max_chunk = cfg
        .connect_payload_len
        .saturating_sub(STREAM_DATA_OFFSET)
        .max(1);
    let mut chunk = vec![0u8; max_chunk];
    let mut tunnel_opened = false;
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
                let mut sent_offset = 0usize;
                while sent_offset < total {
                    let open_now = !tunnel_opened;
                    let frame_payload_len = if open_now {
                        cfg.payload_len
                    } else {
                        cfg.connect_payload_len
                    };
                    let frame_data_cap =
                        frame_payload_len.saturating_sub(STREAM_DATA_OFFSET).max(1);
                    let (frame_end, data_part) = if open_now {
                        (sent_offset, &chunk[sent_offset..sent_offset])
                    } else {
                        let frame_end = core::cmp::min(total, sent_offset + frame_data_cap);
                        (frame_end, &chunk[sent_offset..frame_end])
                    };
                    let payload = build_stream_payload(
                        frame_payload_len,
                        cfg.host_offset,
                        host,
                        if open_now {
                            STREAM_OP_OPEN
                        } else {
                            STREAM_OP_DATA
                        },
                        session_id,
                        data_part,
                    )?;
                    if open_now {
                        eprintln!(
                            "[proxy] CONNECT send OPEN sid={} payload_bytes={}",
                            session_id,
                            data_part.len()
                        );
                    } else {
                        eprintln!(
                            "[proxy] CONNECT send DATA sid={} payload_bytes={}",
                            session_id,
                            data_part.len()
                        );
                    }
                    let frame_timeout_secs = if open_now { 0 } else { push_timeout_secs };
                    let response = if let Some(session) = policy_session.as_mut() {
                        let saved_rounds = session.rounds;
                        if open_now {
                            session.rounds = connect_open_rounds;
                        }
                        let result = session.send(
                            if open_now {
                                TunnelOp::Open
                            } else {
                                TunnelOp::Continue
                            },
                            session_id,
                            &payload,
                            frame_timeout_secs,
                        );
                        session.rounds = saved_rounds;
                        result?
                    } else {
                        send_connect_payload(
                            cfg,
                            target,
                            &mut route_only_session,
                            &payload,
                            frame_timeout_secs,
                            true,
                        )?
                    };
                    if open_now {
                        tunnel_opened = true;
                    }
                    if !response.is_empty() {
                        eprintln!("[proxy] CONNECT tunnel->client bytes={}", response.len());
                        stream
                            .write_all(&response)
                            .map_err(|e| format!("write tunnel response: {e}"))?;
                        last_tunnel_to_client = Instant::now();
                    }
                    if send_gap_ms > 0 && !open_now {
                        thread::sleep(Duration::from_millis(send_gap_ms));
                    }
                    sent_offset = frame_end;
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

        if tunnel_opened && pending_response && !sent_any {
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
                cfg.connect_payload_len,
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
            eprintln!(
                "[proxy] CONNECT poll DATA sid={} timeout={}s",
                session_id, current_poll_timeout
            );
            let response = if let Some(session) = policy_session.as_mut() {
                session.send(
                    TunnelOp::Continue,
                    session_id,
                    &payload,
                    current_poll_timeout,
                )?
            } else {
                send_connect_payload(
                    cfg,
                    target,
                    &mut route_only_session,
                    &payload,
                    current_poll_timeout,
                    false,
                )?
            };
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

    if tunnel_opened {
        let close_payload = build_stream_payload(
            cfg.connect_payload_len,
            cfg.host_offset,
            host,
            STREAM_OP_CLOSE,
            session_id,
            &[],
        )?;
        if let Some(session) = route_only_session.as_mut() {
            let _ = session.send(&close_payload, 1);
        } else if let Some(session) = policy_session.as_mut() {
            let _ = session.send(TunnelOp::Close, session_id, &close_payload, 1);
        } else {
            return Err("proxy tunnel session unavailable".into());
        }
    }
    Ok(())
}

fn send_connect_payload(
    _cfg: &SenderConfig,
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
        if fallback_on_empty && response.is_empty() && (degrade_on_empty || allow_internal_fallback)
        {
            eprintln!("[proxy] route-only internal empty response tolerated");
        }
        return Ok(response);
    }
    Err(format!(
        "route-only tunnel session unavailable for target={target}"
    ))
}

#[derive(Clone, Deserialize)]
struct PolicyInfo {
    policy_id: String,
    #[serde(default)]
    directory_public_key: String,
    routers: Vec<RouterInfo>,
}

#[derive(Clone, Deserialize)]
struct RouterInfo {
    name: String,
    bind: String,
    directory_path: String,
    storage_path: String,
}

struct PolicyTunnelSession {
    policy_id: [u8; 32],
    policy_meta: PolicyMetadata,
    routers: Vec<(StoredState, RouterInfo)>,
    target_host: String,
    target_ip: IpAddr,
    target_port: u16,
    entry_addr: String,
    listener: TcpListener,
    backward_keys_reversed: Vec<Si>,
    backward_ahdr_bytes: Vec<u8>,
    rounds: u16,
    rng: ChaCha20Rng,
}

impl PolicyTunnelSession {
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
        let policy_meta = load_policy_metadata(&info.routers, &policy_id)?;
        let (host, port) = parse_host_port(target, 443)?;
        let (target_ip, target_port) = resolve_target_parts(&host, port)?;
        let entry_addr = env::var("HORNET_PROXY_ENTRY_ADDR")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| normalize_entry_addr(&cfg.policy_info, &routers[0].1.bind));
        let bind_addr = if let Ok(bind) = env::var("HORNET_PROXY_RESPONSE_BIND") {
            if bind.trim().is_empty() {
                default_response_bind(&cfg.policy_info)
            } else {
                bind
            }
        } else {
            default_response_bind(&cfg.policy_info)
        };
        let listener = TcpListener::bind(&bind_addr)
            .map_err(|e| format!("failed to bind response listener {bind_addr}: {e}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("set nonblocking response listener: {e}"))?;
        let local = listener
            .local_addr()
            .map_err(|e| format!("local_addr response listener: {e}"))?;
        let return_ip = resolve_return_ip(local)?;
        let return_port = local.port();
        let rounds = cfg
            .rounds
            .parse::<u16>()
            .map_err(|_| format!("invalid HORNET_PROXY_ZKBOO_ROUNDS: {}", cfg.rounds))?;
        let mut rng = ChaCha20Rng::seed_from_u64(derive_seed());
        let hops = routers.len();
        let exp = compute_expiry(600);
        let mut keys_b = Vec::with_capacity(hops);
        for _ in 0..hops {
            let mut si = [0u8; 16];
            rng.fill_bytes(&mut si);
            keys_b.push(Si(si));
        }
        let mut fses_b = Vec::with_capacity(hops);
        for (i, hop_idx) in (0..hops).rev().enumerate() {
            let segment = if hop_idx == 0 {
                routing::segment_from_elems(&[RouteElem::NextHop {
                    addr: return_ip.clone(),
                    port: return_port,
                }])
            } else {
                let prev_router = &routers[hop_idx - 1].1;
                let (ip_str, port_str) = prev_router
                    .bind
                    .rsplit_once(':')
                    .ok_or("invalid bind addr")?;
                let port: u16 = port_str.parse().map_err(|_| "invalid bind port")?;
                let ip = normalize_router_hop_ip(prev_router, ip_str)?;
                routing::segment_from_elems(&[RouteElem::NextHop {
                    addr: IpAddr::V4(ip),
                    port,
                }])
            };
            let state = &routers[hop_idx].0;
            let fs = aurora::packet::core::create(&state.sv(), &keys_b[i], &segment, exp)
                .map_err(|err| format!("failed to build Backward FS for hop {}: {err:?}", i))?;
            fses_b.push(fs);
        }
        let mut ahdr_b_rng = ChaCha20Rng::seed_from_u64(derive_seed() ^ 0xBEEF_BEEF);
        let backward_ahdr =
            aurora::packet::ahdr::create_ahdr(&keys_b, &fses_b, hops, &mut ahdr_b_rng)
                .map_err(|err| format!("failed to build Backward AHDR: {err:?}"))?;
        let mut backward_keys_reversed = keys_b;
        backward_keys_reversed.reverse();
        eprintln!(
            "[proxy][policy] cfg entry_addr={} return={:?}:{} target={:?}:{} rounds={}",
            entry_addr, return_ip, return_port, target_ip, target_port, rounds
        );
        Ok(Self {
            policy_id,
            policy_meta,
            routers,
            target_host: host,
            target_ip,
            target_port,
            entry_addr,
            listener,
            backward_keys_reversed,
            backward_ahdr_bytes: backward_ahdr.bytes,
            rounds,
            rng,
        })
    }

    fn send(
        &mut self,
        op: TunnelOp,
        session_id: u64,
        request_payload: &[u8],
        timeout_secs: u64,
    ) -> Result<Vec<u8>, String> {
        let request_payload = if matches!(op, TunnelOp::Open) {
            normalize_payload_len(request_payload, policy_payload_len(&self.policy_meta)?)?
        } else {
            request_payload.to_vec()
        };
        let capsule_buf = if matches!(op, TunnelOp::Open) {
            self.build_capsule(&request_payload)?
        } else {
            Vec::new()
        };
        let tunnel_prefix = TunnelPrefix {
            op,
            expects_reply: timeout_secs > 0,
            session_id,
            policy_id: self.policy_id,
        }
        .encode();
        let hops = self.routers.len();
        let rmax = hops;
        let exp = compute_expiry(600);

        let mut keys = Vec::with_capacity(hops);
        for _ in 0..hops {
            let mut si = [0u8; 16];
            self.rng.fill_bytes(&mut si);
            keys.push(Si(si));
        }
        let mut fses = Vec::with_capacity(hops);
        for (hop, (state, route_info)) in self.routers.iter().enumerate() {
            let segment = if hop == hops - 1 {
                routing::segment_from_elems(&[RouteElem::ExitTcp {
                    addr: self.target_ip.clone(),
                    port: self.target_port,
                }])
            } else {
                select_live_segment(route_info, &self.policy_id)
                    .or_else(|_| select_route(state, &self.policy_id).map(|route| route.segment))?
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
        let mut chdr = aurora::packet::chdr::data_header(
            aurora::types::HopCount::new(hops as u8).map_err(|_| "invalid hop count")?,
            iv,
        );

        let canonical_bytes = canonical_target_leaf(&self.target_host)?;
        let mut full_payload = Vec::new();
        full_payload.extend_from_slice(&(self.backward_ahdr_bytes.len() as u32).to_le_bytes());
        full_payload.extend_from_slice(&self.backward_ahdr_bytes);
        full_payload.extend_from_slice(&request_payload);

        let mut encrypted_tail = Vec::new();
        encrypted_tail.extend_from_slice(&canonical_bytes);
        encrypted_tail.extend_from_slice(&full_payload);
        aurora::source::build(&mut chdr, &ahdr, &keys, &mut iv, &mut encrypted_tail)
            .map_err(|err| format!("failed to build payload: {err:?}"))?;
        let mut payload =
            Vec::with_capacity(tunnel_prefix.len() + capsule_buf.len() + encrypted_tail.len());
        payload.extend_from_slice(&tunnel_prefix);
        payload.extend_from_slice(&capsule_buf);
        payload.extend_from_slice(&encrypted_tail);
        let frame = encode_frame(&chdr, &ahdr.bytes, &payload)?;
        send_frame_to(&self.entry_addr, &frame)?;
        eprintln!("[proxy][policy] frame sent bytes={}", frame.len());

        wait_for_backward_response(
            &self.listener,
            timeout_secs,
            &self.backward_keys_reversed,
            "[proxy][policy]",
        )
    }

    fn build_capsule(&mut self, request_payload: &[u8]) -> Result<Vec<u8>, String> {
        let sequence = current_sequence()?;
        let seq_buf = sequence.to_be_bytes();
        let kb_circuit = circuit_from_metadata(&self.policy_meta, ProofKind::KeyBinding)?;
        let cons_circuit = circuit_from_metadata(&self.policy_meta, ProofKind::Consistency)?;
        let pol_circuit = circuit_from_metadata(&self.policy_meta, ProofKind::Policy)?;

        let kb_len = kb_circuit.n_inputs / 8;
        let pol_len = pol_circuit.n_inputs / 8;
        let cons_len = cons_circuit.n_inputs / 8;
        if kb_len * 8 != kb_circuit.n_inputs
            || pol_len * 8 != pol_circuit.n_inputs
            || cons_len * 8 != cons_circuit.n_inputs
        {
            return Err("policy circuit n_inputs must be byte-aligned".into());
        }
        if request_payload.len() != pol_len {
            return Err(format!(
                "request length mismatch: got {} bytes, policy circuit expects {} bytes",
                request_payload.len(),
                pol_len
            ));
        }
        if cons_len != kb_len + pol_len {
            return Err(format!(
                "consistency circuit input must be secret+payload ({}+{} bytes), got {} bytes",
                kb_len, pol_len, cons_len
            ));
        }

        let mut secret = vec![0u8; kb_len];
        self.rng.fill_bytes(&mut secret);
        let hkey = mix_fold(MIX_DOMAIN_KEYBIND, &secret);
        let payload_hash = mix_fold(MIX_DOMAIN_PAYLOAD, request_payload);

        let aux_keybinding = make_aux(&[
            CapsuleExtensionRef {
                tag: EXT_TAG_SEQUENCE,
                data: &seq_buf,
            },
            CapsuleExtensionRef {
                tag: EXT_TAG_KEY_HASH,
                data: &hkey,
            },
        ])?;
        let aux_consistency = make_aux(&[
            CapsuleExtensionRef {
                tag: EXT_TAG_SEQUENCE,
                data: &seq_buf,
            },
            CapsuleExtensionRef {
                tag: EXT_TAG_KEY_HASH,
                data: &hkey,
            },
            CapsuleExtensionRef {
                tag: EXT_TAG_PAYLOAD_HASH,
                data: &payload_hash,
            },
        ])?;
        let aux_policy = make_aux(&[
            CapsuleExtensionRef {
                tag: EXT_TAG_SEQUENCE,
                data: &seq_buf,
            },
            CapsuleExtensionRef {
                tag: EXT_TAG_PAYLOAD_HASH,
                data: &payload_hash,
            },
        ])?;

        let mut consistency_payload = Vec::with_capacity(secret.len() + request_payload.len());
        consistency_payload.extend_from_slice(&secret);
        consistency_payload.extend_from_slice(request_payload);

        let kb = make_part(
            &self.policy_id,
            kb_circuit,
            self.rounds,
            &secret,
            &aux_keybinding,
            ProofKind::KeyBinding,
        )?;
        let cons = make_part(
            &self.policy_id,
            cons_circuit,
            self.rounds,
            &consistency_payload,
            &aux_consistency,
            ProofKind::Consistency,
        )?;
        let pol = make_part(
            &self.policy_id,
            pol_circuit,
            self.rounds,
            request_payload,
            &aux_policy,
            ProofKind::Policy,
        )?;
        let capsule = aurora::policy::PolicyCapsule {
            policy_id: self.policy_id,
            version: aurora::core::policy::POLICY_CAPSULE_VERSION,
            part_count: 3,
            parts: [kb, cons, pol, aurora::policy::ProofPart::default()],
        };
        capsule
            .encode()
            .map_err(|_| "failed to encode capsule".to_string())
    }

    fn send_request(
        &mut self,
        request_payload: &[u8],
        timeout_secs: u64,
    ) -> Result<Vec<u8>, String> {
        let request_payload =
            normalize_payload_len(request_payload, policy_payload_len(&self.policy_meta)?)?;
        let capsule_buf = self.build_capsule(&request_payload)?;
        self.send_inner(&request_payload, &capsule_buf, timeout_secs)
    }

    fn send_inner(
        &mut self,
        request_payload: &[u8],
        capsule_buf: &[u8],
        timeout_secs: u64,
    ) -> Result<Vec<u8>, String> {
        let hops = self.routers.len();
        let rmax = hops;
        let exp = compute_expiry(600);

        let mut keys = Vec::with_capacity(hops);
        for _ in 0..hops {
            let mut si = [0u8; 16];
            self.rng.fill_bytes(&mut si);
            keys.push(Si(si));
        }
        let mut fses = Vec::with_capacity(hops);
        for (hop, (state, route_info)) in self.routers.iter().enumerate() {
            let segment = if hop == hops - 1 {
                routing::segment_from_elems(&[RouteElem::ExitTcp {
                    addr: self.target_ip.clone(),
                    port: self.target_port,
                }])
            } else {
                select_live_segment(route_info, &self.policy_id)
                    .or_else(|_| select_route(state, &self.policy_id).map(|route| route.segment))?
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
        let mut chdr = aurora::packet::chdr::data_header(
            aurora::types::HopCount::new(hops as u8).map_err(|_| "invalid hop count")?,
            iv,
        );

        let canonical_bytes = canonical_target_leaf(&self.target_host)?;
        let mut full_payload = Vec::new();
        full_payload.extend_from_slice(&(self.backward_ahdr_bytes.len() as u32).to_le_bytes());
        full_payload.extend_from_slice(&self.backward_ahdr_bytes);
        full_payload.extend_from_slice(request_payload);

        let mut encrypted_tail = Vec::new();
        encrypted_tail.extend_from_slice(&canonical_bytes);
        encrypted_tail.extend_from_slice(&full_payload);
        aurora::source::build(&mut chdr, &ahdr, &keys, &mut iv, &mut encrypted_tail)
            .map_err(|err| format!("failed to build payload: {err:?}"))?;
        let mut payload = Vec::with_capacity(capsule_buf.len() + encrypted_tail.len());
        payload.extend_from_slice(capsule_buf);
        payload.extend_from_slice(&encrypted_tail);
        let frame = encode_frame(&chdr, &ahdr.bytes, &payload)?;
        send_frame_to(&self.entry_addr, &frame)?;
        eprintln!("[proxy][policy] frame sent bytes={}", frame.len());

        wait_for_backward_response(
            &self.listener,
            timeout_secs,
            &self.backward_keys_reversed,
            "[proxy][policy]",
        )
    }
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
        for (hop, (state, route_info)) in self.routers.iter().enumerate() {
            let segment = if hop == hops - 1 {
                routing::segment_from_elems(&[RouteElem::ExitTcp {
                    addr: self.target_ip.clone(),
                    port: self.target_port,
                }])
            } else {
                select_live_segment(route_info, &self.policy_id)
                    .or_else(|_| select_route(state, &self.policy_id).map(|route| route.segment))?
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
        let mut chdr = aurora::packet::chdr::data_header(
            aurora::types::HopCount::new(hops as u8).map_err(|_| "invalid hop count")?,
            iv,
        );

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
                let ip = normalize_router_hop_ip(prev_router, ip_str)?;
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
        wait_for_backward_response(
            &self.listener,
            timeout_secs,
            &keys_b_reversed,
            "[proxy][route-only]",
        )
    }
}

struct BackwardFrame {
    specific: [u8; 16],
    payload: Vec<u8>,
}

fn wait_for_backward_response(
    listener: &TcpListener,
    timeout_secs: u64,
    backward_keys_reversed: &[Si],
    log_prefix: &str,
) -> Result<Vec<u8>, String> {
    if timeout_secs == 0 {
        eprintln!("{log_prefix} response wait skipped");
        return Ok(Vec::new());
    }
    let deadline = Instant::now() + Duration::from_secs(timeout_secs.max(1));
    loop {
        if Instant::now() >= deadline {
            eprintln!("{log_prefix} response timeout");
            return Ok(Vec::new());
        }
        match listener.accept() {
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
                    Err(err) => {
                        eprintln!("{log_prefix} read backward failed: {err}");
                        continue;
                    }
                };
                let mut payload = frame.payload;
                let mut iv_resp = frame.specific;
                if aurora::source::decrypt_backward_payload(
                    backward_keys_reversed,
                    &mut iv_resp,
                    &mut payload,
                )
                .is_ok()
                {
                    eprintln!("{log_prefix} response decrypted bytes={}", payload.len());
                    return Ok(payload);
                }
                eprintln!("{log_prefix} stale/unmatched response ignored");
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(2));
            }
            Err(e) => return Err(format!("accept response failed: {e}")),
        }
    }
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

fn load_policy_metadata(
    routers: &[RouterInfo],
    policy_id: &[u8; 32],
) -> Result<PolicyMetadata, String> {
    let first = routers
        .first()
        .ok_or_else(|| "policy-info has no routers".to_string())?;
    let body = fs::read_to_string(&first.directory_path)
        .map_err(|err| format!("failed to read directory {}: {err}", first.directory_path))?;
    #[derive(Deserialize)]
    struct DirectoryLike {
        #[serde(default)]
        policies: Vec<PolicyMetadata>,
    }
    let directory: DirectoryLike =
        serde_json::from_str(&body).map_err(|err| format!("invalid directory JSON: {err}"))?;
    directory
        .policies
        .into_iter()
        .find(|p| &p.policy_id == policy_id)
        .ok_or_else(|| "directory did not contain policy metadata for policy_id".to_string())
}

fn select_live_segment(
    router: &RouterInfo,
    policy_id: &[u8; 32],
) -> Result<aurora::types::RoutingSegment, String> {
    #[derive(Deserialize)]
    struct DirectoryLike {
        #[serde(default)]
        routes: Vec<DirectoryRoute>,
    }

    #[derive(Deserialize)]
    struct DirectoryRoute {
        policy_id: String,
        interface: Option<String>,
        segments: Vec<DirectorySegment>,
    }

    #[derive(Deserialize)]
    #[serde(tag = "type")]
    enum DirectorySegment {
        #[serde(rename = "next_hop4")]
        NextHop4 { ip: String, port: u16 },
        #[serde(rename = "exit_tcp4")]
        ExitTcp4 { ip: String, port: u16 },
    }

    let body = fs::read_to_string(&router.directory_path)
        .map_err(|err| format!("failed to read directory {}: {err}", router.directory_path))?;
    let directory: DirectoryLike =
        serde_json::from_str(&body).map_err(|err| format!("invalid directory JSON: {err}"))?;
    let route = directory
        .routes
        .into_iter()
        .find(|route| {
            decode_policy_id(&route.policy_id).ok().as_ref() == Some(policy_id)
                && route.interface.as_deref() == Some(router.name.as_str())
        })
        .ok_or_else(|| {
            format!(
                "directory {} had no route for router {} and policy {:?}",
                router.directory_path, router.name, policy_id
            )
        })?;
    let elems: Result<Vec<RouteElem>, String> = route
        .segments
        .into_iter()
        .map(|segment| match segment {
            DirectorySegment::NextHop4 { ip, port } => Ok(RouteElem::NextHop {
                addr: IpAddr::V4(parse_ipv4_octets(&ip)?),
                port,
            }),
            DirectorySegment::ExitTcp4 { ip, port } => Ok(RouteElem::ExitTcp {
                addr: IpAddr::V4(parse_ipv4_octets(&ip)?),
                port,
            }),
        })
        .collect();
    Ok(routing::segment_from_elems(&elems?))
}

fn normalize_router_hop_ip(router: &RouterInfo, ip_str: &str) -> Result<[u8; 4], String> {
    if router.directory_path.contains("config/qemu/") && ip_str == "127.0.0.1" {
        return Ok([10, 0, 2, 2]);
    }
    parse_ipv4_octets(ip_str)
}

fn resolve_target_parts(hostname: &str, port: u16) -> Result<(IpAddr, u16), String> {
    use std::net::ToSocketAddrs;

    let addrs: Vec<_> = (hostname, port)
        .to_socket_addrs()
        .map_err(|e| format!("failed to resolve {hostname}:{port}: {e}"))?
        .collect();
    let addr = addrs
        .iter()
        .find(|addr| matches!(addr, std::net::SocketAddr::V4(_)))
        .or_else(|| addrs.first())
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

fn default_response_bind(policy_info_path: &str) -> String {
    if policy_info_path.contains("config/qemu/") {
        "0.0.0.0:0".to_string()
    } else {
        "127.0.0.1:0".to_string()
    }
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

fn current_sequence() -> Result<u64, String> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "time went backwards".to_string())?
        .as_nanos();
    let pid = std::process::id() as u128;
    Ok(((nanos ^ (pid << 32)) & 0xFFFF_FFFF_FFFF_FFFF) as u64)
}

fn normalize_payload_len(request: &[u8], expected_len: usize) -> Result<Vec<u8>, String> {
    if request.len() == expected_len {
        return Ok(request.to_vec());
    }
    if request.len() > expected_len {
        return Err(format!(
            "request length mismatch: got {} bytes, policy expects {} bytes",
            request.len(),
            expected_len
        ));
    }
    let mut out = vec![0u8; expected_len];
    out[..request.len()].copy_from_slice(request);
    Ok(out)
}

fn policy_payload_len(meta: &PolicyMetadata) -> Result<usize, String> {
    let circuit = circuit_from_metadata(meta, ProofKind::Policy)?;
    if circuit.n_inputs % 8 != 0 {
        return Err("policy circuit n_inputs must be byte-aligned".into());
    }
    Ok(circuit.n_inputs / 8)
}

fn encode_frame(
    chdr: &aurora::types::Chdr,
    ahdr: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    if ahdr.len() > u32::MAX as usize || payload.len() > u32::MAX as usize {
        return Err("frame too large".into());
    }
    let (typ, hops, specific) = chdr.to_raw_parts();
    let mut frame = Vec::with_capacity(4 + 16 + 8 + ahdr.len() + payload.len());
    frame.push(0);
    frame.push(match typ {
        PacketType::Setup => 0,
        PacketType::Data => 1,
    });
    frame.push(hops);
    frame.push(0);
    frame.extend_from_slice(&specific);
    frame.extend_from_slice(&(ahdr.len() as u32).to_le_bytes());
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(ahdr);
    frame.extend_from_slice(payload);
    Ok(frame)
}

fn send_frame_to(addr: &str, frame: &[u8]) -> Result<TcpStream, String> {
    let mut stream =
        TcpStream::connect(addr).map_err(|err| format!("failed to connect to {}: {err}", addr))?;
    stream
        .write_all(frame)
        .map_err(|err| format!("failed to send frame: {err}"))?;
    Ok(stream)
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

fn circuit_from_metadata(meta: &PolicyMetadata, kind: ProofKind) -> Result<Circuit, String> {
    let entry = meta
        .verifiers
        .iter()
        .find(|e| e.kind == kind as u8)
        .ok_or_else(|| format!("policy metadata missing verifier for {:?}", kind))?;
    Circuit::decode(&entry.verifier_blob)
        .map_err(|err| format!("failed to decode verifier circuit for {:?}: {err:?}", kind))
}

fn make_aux(exts: &[CapsuleExtensionRef<'_>]) -> Result<Vec<u8>, String> {
    let mut buf = [0u8; AUX_MAX];
    let len = encode_extensions_into(exts, &mut buf)
        .map_err(|_| "failed to encode policy extensions".to_string())?;
    Ok(buf[..len].to_vec())
}

fn make_part(
    policy_id: &[u8; 32],
    circuit: Circuit,
    rounds: u16,
    payload: &[u8],
    aux: &[u8],
    kind: ProofKind,
) -> Result<aurora::policy::ProofPart, String> {
    let service = ZkBooProofService::new_with_policy_id(circuit, *policy_id, rounds);
    let capsule = service
        .prove_payload_lsb_first(payload, aux)
        .map_err(|err| format!("failed to prove {:?} with zkboo: {err:?}", kind))?;
    if capsule.part_count as usize != 1 {
        return Err("unexpected zkboo capsule layout".into());
    }
    let mut part = capsule.parts[0].clone();
    part.kind = kind;
    part.set_aux(aux)
        .map_err(|_| "failed to set policy extensions".to_string())?;
    Ok(part)
}

fn maybe_send_setup(cfg: &SenderConfig) -> Result<(), String> {
    if env::var("HORNET_PROXY_SKIP_SETUP").ok().as_deref() == Some("1") {
        return Ok(());
    }
    if SETUP_SENT.load(Ordering::Acquire) {
        return Ok(());
    }
    send_setup(&cfg.policy_info)?;
    SETUP_SENT.store(true, Ordering::Release);
    Ok(())
}

fn send_setup(info_path: &str) -> Result<(), String> {
    let info_json = fs::read_to_string(info_path)
        .map_err(|err| format!("failed to read {info_path}: {err}"))?;
    let info: PolicyInfo = serde_json::from_str(&info_json)
        .map_err(|err| format!("invalid policy-info JSON: {err}"))?;
    if info.routers.is_empty() {
        return Err("policy-info has no routers".into());
    }
    let entry = &info.routers[0];
    let node_pubs = load_node_pubs(&info.routers)?;
    let directory_body = fs::read_to_string(&entry.directory_path)
        .map_err(|err| format!("failed to read {}: {err}", entry.directory_path))?;
    let public_key = decode_hex(&info.directory_public_key)
        .map_err(|err| format!("invalid directory_public_key hex: {err}"))?;
    if public_key.len() != 32 {
        return Err("directory_public_key must be 32 bytes".into());
    }
    let _announcement = aurora::setup::directory::from_signed_json(&directory_body, &public_key)
        .map_err(|err| format!("failed to verify directory: {err:?}"))?;
    let policy_id = decode_policy_id(&info.policy_id)?;

    let mut rng = ChaCha20Rng::seed_from_u64(derive_seed());
    let mut source_secret = [0u8; 32];
    rng.fill_bytes(&mut source_secret);
    clamp_scalar(&mut source_secret);

    let exp = compute_expiry(600);
    let mut state =
        aurora::setup::source_init(&source_secret, &node_pubs, node_pubs.len(), exp, &mut rng);
    state.packet.tlvs.clear();
    let mut policy_tlv = Vec::with_capacity(1 + policy_id.len());
    policy_tlv.push(POLICY_ID_TLV);
    policy_tlv.extend_from_slice(&policy_id);
    state.packet.tlvs.push(policy_tlv);
    let encoded = wire::encode(&state.packet)
        .map_err(|err| format!("failed to encode setup packet: {err:?}"))?;
    let frame = encode_setup_frame(&state.packet.chdr, &encoded.header, &encoded.payload)?;
    let entry_addr = env::var("HORNET_ENTRY_ADDR")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| normalize_entry_addr(info_path, &entry.bind));
    send_frame_to(&entry_addr, &frame)?;
    eprintln!(
        "[proxy] setup sent: {} hops={} target={}",
        entry_addr,
        state.packet.chdr.hops().get(),
        info_path
    );
    Ok(())
}

fn load_node_pubs(routers: &[RouterInfo]) -> Result<Vec<[u8; 32]>, String> {
    let mut pubs = Vec::new();
    for router in routers {
        let data = fs::read(&router.storage_path).map_err(|err| {
            format!(
                "failed to read {} (router {} state): {err}",
                router.storage_path, router.name
            )
        })?;
        let state: StoredState =
            serde_json::from_slice(&data).map_err(|err| format!("invalid state JSON: {err}"))?;
        let node_secret = state.node_secret();
        let pubkey = x25519(node_secret, x25519_dalek::X25519_BASEPOINT_BYTES);
        pubs.push(pubkey);
    }
    Ok(pubs)
}

fn clamp_scalar(bytes: &mut [u8; 32]) {
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
}

fn encode_setup_frame(chdr: &Chdr, header: &[u8], payload: &[u8]) -> Result<Vec<u8>, String> {
    if header.len() > u32::MAX as usize || payload.len() > u32::MAX as usize {
        return Err("setup frame too large".into());
    }
    let (typ, hops, specific) = chdr.to_raw_parts();
    let mut frame = Vec::with_capacity(4 + 16 + 8 + header.len() + payload.len());
    frame.push(0);
    frame.push(match typ {
        PacketType::Setup => 0,
        PacketType::Data => 1,
    });
    frame.push(hops);
    frame.push(0);
    frame.extend_from_slice(&specific);
    frame.extend_from_slice(&(header.len() as u32).to_le_bytes());
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(header);
    frame.extend_from_slice(payload);
    Ok(frame)
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
