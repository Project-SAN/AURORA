use hornet::core::policy::ProofKind;
use hornet::core::policy::{
    encode_extensions_into, CapsuleExtensionRef, AUX_MAX, EXT_TAG_SEQUENCE,
};
use hornet::crypto::zkp::Circuit;
use hornet::policy::blocklist;
use hornet::policy::zkboo::ZkBooProofService;
use hornet::policy::TargetValue;
use hornet::router::storage::StoredState;
use hornet::routing::{self, IpAddr, RouteElem};
use hornet::setup::directory::RouteAnnouncement;
use hornet::types::{Nonce, PacketType, Si};
use hornet::utils::decode_hex;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use serde::Deserialize;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn main() {
    if let Err(err) = run() {
        eprintln!("hornet_data_sender error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args();
    let program = args.next().unwrap_or_else(|| "hornet_data_sender".into());
    let info_path = args
        .next()
        .ok_or_else(|| format!("usage: {program} <policy-info.json> <host> [message]"))?;
    let host = args
        .next()
        .ok_or_else(|| format!("usage: {program} <policy-info.json> <host> [message]"))?;
    let message = args
        .next()
        .unwrap_or_else(|| "hello from hornet_data_sender".into());
    let _control = spawn_control_listener(
        info_path.to_string(),
        host.to_string(),
        message.as_bytes().to_vec(),
    );
    send_data(&info_path, &host, message.as_bytes())
}

fn send_data(info_path: &str, host: &str, payload_tail: &[u8]) -> Result<(), String> {
    let start_total = Instant::now();
    let info: PolicyInfo = {
        let json = fs::read_to_string(info_path)
            .map_err(|err| format!("failed to read {info_path}: {err}"))?;
        serde_json::from_str(&json).map_err(|err| format!("invalid policy-info JSON: {err}"))?
    };
    if info.routers.is_empty() {
        return Err("policy-info has no routers".into());
    }
    let policy_id = decode_policy_id(&info.policy_id)?;
    let routers = load_router_states(&info.routers, &policy_id)?;
    let zkboo_circuit_path = env::var("HORNET_ZKBOO_CIRCUIT_PATH")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let zkboo_circuit_path = zkboo_circuit_path.ok_or_else(|| {
        "ZKBoo-only build: set HORNET_ZKBOO_CIRCUIT_PATH to enable proving".to_string()
    })?;

    // Resolve target host
    let (target_hostname, target_port) = parse_host_port(host, 80)?;
    let (target_ip, target_port) = resolve_target_parts(&target_hostname, target_port)?;
    println!("Resolved {} to {:?}:{}", host, target_ip, target_port);

    let request_payload = read_request_bytes(payload_tail)?;
    let canonical_bytes = {
        let target = target_value_from_hostname(&target_hostname)?;
        let entry = blocklist::entry_from_target(&target)
            .map_err(|err| format!("failed to canonicalise host: {err:?}"))?;
        entry.leaf_bytes()
    };
    let mut rng = ChaCha20Rng::seed_from_u64(derive_seed());
    let sequence = current_sequence()?;
    let policy_aux = {
        let seq_buf = sequence.to_be_bytes();
        let exts = [CapsuleExtensionRef {
            tag: EXT_TAG_SEQUENCE,
            data: &seq_buf,
        }];
        let mut aux_buf = [0u8; AUX_MAX];
        let aux_len = encode_extensions_into(&exts, &mut aux_buf)
            .map_err(|_| "failed to encode policy extensions")?;
        aux_buf[..aux_len].to_vec()
    };

    let capsule = {
        let path = zkboo_circuit_path.as_str();
        let rounds: u16 = env::var("HORNET_ZKBOO_ROUNDS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(64);
        let bytes = fs::read(path)
            .map_err(|err| format!("failed to read ZKBoo circuit ({path}): {err}"))?;
        let circuit = Circuit::decode(&bytes)
            .map_err(|err| format!("failed to decode ZKBoo circuit ({path}): {err:?}"))?;
        let service = ZkBooProofService::new(circuit, rounds);
        if service.policy_id() != &policy_id {
            return Err("policy-id mismatch between policy-info and zkboo circuit".into());
        }

        // Prove exactly one TLS record (header+fragment).
        let plaintext_tls_record = request_payload.as_slice();
        println!("Generating ZKBoo policy proof (rounds={})...", rounds);
        let proof_start = Instant::now();
        let mut capsule = service
            .prove_payload_lsb_first(plaintext_tls_record, &policy_aux)
            .map_err(|err| format!("failed to prove payload with zkboo: {err:?}"))?;
        if let Some(part) = capsule
            .parts
            .iter_mut()
            .take(capsule.part_count as usize)
            .find(|part| part.kind == ProofKind::Policy)
        {
            part.set_aux(&policy_aux)
                .map_err(|_| "failed to set policy extensions")?;
        }
        println!("Proof generated in {:.2?}", proof_start.elapsed());
        capsule
    };
    let hops = routers.len();
    let rmax = hops;
    let mut keys = Vec::with_capacity(hops);
    for _ in 0..hops {
        let mut si = [0u8; 16];
        rng.fill_bytes(&mut si);
        keys.push(Si(si));
    }
    let exp = compute_expiry(600);
    let mut fses = Vec::with_capacity(hops);
    for (hop, (state, _route)) in routers.iter().enumerate() {
        let segment = if hop == hops - 1 {
            // Last hop: construct dynamic exit segment
            let elem = RouteElem::ExitTcp {
                addr: target_ip.clone(),
                port: target_port,
                tls: false, // TODO: infer from port or scheme?
            };
            routing::segment_from_elems(&[elem])
        } else {
            // Intermediate hop: use stored route
            let route = select_route(state, &policy_id)?;
            route.segment
        };

        let fs = hornet::packet::core::create(&state.sv(), &keys[hop], &segment, exp)
            .map_err(|err| format!("failed to build FS for hop {}: {err:?}", hop))?;
        fses.push(fs);
    }
    let mut ahdr_rng = ChaCha20Rng::seed_from_u64(derive_seed() ^ 0xA55AA55A);
    let ahdr = hornet::packet::ahdr::create_ahdr(&keys, &fses, rmax, &mut ahdr_rng)
        .map_err(|err| format!("failed to build AHDR: {err:?}"))?;

    let mut iv = {
        let mut buf = [0u8; 16];
        rng.fill_bytes(&mut buf);
        Nonce(buf)
    };
    let mut chdr = hornet::packet::chdr::data_header(hops as u8, iv);

    // Setup listener for response
    let bind_addr = env::var("HORNET_RESPONSE_BIND").unwrap_or_else(|_| "127.0.0.1:0".into());
    let listener = TcpListener::bind(&bind_addr)
        .map_err(|e| format!("failed to bind listener {bind_addr}: {e}"))?;
    let local_addr = listener
        .local_addr()
        .map_err(|e| format!("failed to get local addr: {e}"))?;
    let (return_ip, return_port) = resolve_return_addr(local_addr)?;
    println!(
        "Listening for response on {} (return port {})",
        local_addr, return_port
    );

    // Construct Backward Path
    // Path: Exit -> Middle -> Entry -> Client
    // We need keys and FSes for [Exit, Middle, Entry]

    let mut keys_b = Vec::with_capacity(hops);
    for _ in 0..hops {
        let mut si = [0u8; 16];
        rng.fill_bytes(&mut si);
        keys_b.push(Si(si));
    }

    let mut fses_b = Vec::with_capacity(hops);
    // Iterate reverse: Exit, Middle, Entry
    for (i, hop_idx) in (0..hops).rev().enumerate() {
        // hop_idx: 2 (Exit), 1 (Middle), 0 (Entry)
        // i: 0, 1, 2 (Index in backward path)

        let segment = if hop_idx == 0 {
            // Entry -> Client
            let elem = RouteElem::NextHop {
                addr: return_ip.clone(),
                port: return_port,
            };
            routing::segment_from_elems(&[elem])
        } else {
            // Exit -> Middle or Middle -> Entry
            // The next hop in backward path is the previous hop in forward path (hop_idx - 1)
            let prev_router = &routers[hop_idx - 1].1;
            // Parse bind address of prev router to get IP/Port
            // Assuming bind is "IP:Port"
            let (ip_str, port_str) = prev_router
                .bind
                .rsplit_once(':')
                .ok_or("invalid bind addr")?;
            let port: u16 = port_str.parse().map_err(|_| "invalid port")?;
            let ip_octets = parse_ipv4_octets(ip_str)?; // Helper needed
            let elem = RouteElem::NextHop {
                addr: IpAddr::V4(ip_octets),
                port,
            };
            routing::segment_from_elems(&[elem])
        };

        // Use keys_b[i]
        // Note: StoredState sv is needed.
        // routers[hop_idx].0 is the state for the node we are processing (Exit, Middle, Entry)
        let state = &routers[hop_idx].0;

        let fs = hornet::packet::core::create(&state.sv(), &keys_b[i], &segment, exp)
            .map_err(|err| format!("failed to build FS for backward hop {}: {err:?}", i))?;
        fses_b.push(fs);
    }

    let mut ahdr_b_rng = ChaCha20Rng::seed_from_u64(derive_seed() ^ 0xBEEFBEEF);
    let ahdr_b = hornet::packet::ahdr::create_ahdr(&keys_b, &fses_b, rmax, &mut ahdr_b_rng)
        .map_err(|err| format!("failed to build Backward AHDR: {err:?}"))?;

    // Prepend Backward AHDR to payload
    let mut full_payload = Vec::new();
    full_payload.extend_from_slice(&(ahdr_b.bytes.len() as u32).to_le_bytes());
    full_payload.extend_from_slice(&ahdr_b.bytes);
    full_payload.extend_from_slice(&request_payload);

    let capsule_buf = capsule.encode().map_err(|_| "failed to encode capsule")?;
    let capsule_len = capsule_buf.len();
    let mut encrypted_tail = Vec::new();
    encrypted_tail.extend_from_slice(canonical_bytes.as_slice());
    encrypted_tail.extend_from_slice(&full_payload); // Use full_payload
    hornet::source::build(&mut chdr, &ahdr, &keys, &mut iv, &mut encrypted_tail)
        .map_err(|err| format!("failed to build payload: {err:?}"))?;
    let mut payload = Vec::with_capacity(capsule_len + encrypted_tail.len());
    payload.extend_from_slice(&capsule_buf);
    payload.extend_from_slice(&encrypted_tail);
    let frame = encode_frame(&chdr, &ahdr.bytes, &payload)?;
    let entry = &routers[0].1;
    let entry_override = env::var("HORNET_ENTRY_ADDR").ok().filter(|s| !s.is_empty());
    let start_rtt = Instant::now();
    if let Some(addr) = entry_override.as_deref() {
        println!("Sending frame to entry override {}", addr);
        send_frame_to(addr, &frame)?;
    } else {
        println!("Sending frame to entry {}", entry.bind);
        send_frame(entry, &frame)?;
    }
    println!(
        "データ送信完了: {} へ {} バイト (hops={})",
        entry.bind,
        payload.len(),
        hops
    );

    // Listen for response with timeout
    println!("Waiting for response...");
    let timeout_secs: u64 = env::var("HORNET_RESPONSE_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(600);
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(listener.accept());
    });
    let (mut stream, addr) = match rx.recv_timeout(Duration::from_secs(timeout_secs)) {
        Ok(Ok(pair)) => pair,
        Ok(Err(err)) => return Err(format!("accept failed: {err}")),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            return Err(format!(
                "response timeout after {}s (no backward packet)",
                timeout_secs
            ));
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            return Err("response accept thread disconnected".to_string());
        }
    };
    println!("Connection from {}", addr);

    // Read response frame
    // Frame format: [direction:1][type:1][hops:1][res:1][specific:16][ahdr_len:4][payload_len:4][ahdr][payload]
    // But wait, the router sends back a HORNET packet.
    // The Client is NOT a router, but it needs to parse the frame.
    // Let's reuse `read_incoming_packet` logic or just read manually.

    // Simple read for now
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .map_err(|e| format!("read header failed: {e}"))?;
    // direction should be 1 (Backward)
    // type should be 1 (Data)

    let mut specific = [0u8; 16];
    stream
        .read_exact(&mut specific)
        .map_err(|e| format!("read specific failed: {e}"))?;

    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| format!("read ahdr len failed: {e}"))?;
    let ahdr_len = u32::from_le_bytes(len_buf) as usize;

    stream
        .read_exact(&mut len_buf)
        .map_err(|e| format!("read payload len failed: {e}"))?;
    let payload_len = u32::from_le_bytes(len_buf) as usize;

    if ahdr_len > 0 {
        let mut ahdr_buf = vec![0u8; ahdr_len];
        stream
            .read_exact(&mut ahdr_buf)
            .map_err(|e| format!("read ahdr failed: {e}"))?;
    }

    let mut encrypted_response = vec![0u8; payload_len];
    stream
        .read_exact(&mut encrypted_response)
        .map_err(|e| format!("read response failed: {e}"))?;

    // Decrypt response
    // Keys for backward path: keys_b
    // IV: specific
    // IMPORTANT: Routers add layers in order Exit→Middle→Entry (keys_b[0]→keys_b[1]→keys_b[2])
    // So we must remove layers in reverse: Entry→Middle→Exit (keys_b[2]→keys_b[1]→keys_b[0])
    let mut iv_resp = specific;
    let mut keys_b_reversed = keys_b.clone();
    keys_b_reversed.reverse();
    hornet::source::decrypt_backward_payload(
        &keys_b_reversed,
        &mut iv_resp,
        &mut encrypted_response,
    )
    .map_err(|e| format!("decrypt failed: {e:?}"))?;

    println!("Round-trip time: {:.2?}", start_rtt.elapsed());
    println!("Total time: {:.2?}", start_total.elapsed());
    println!(
        "Received Response:\n{}",
        String::from_utf8_lossy(&encrypted_response)
    );

    Ok(())
}

fn spawn_control_listener(
    info_path: String,
    host: String,
    payload: Vec<u8>,
) -> Option<std::thread::JoinHandle<()>> {
    let bind = env::var("HORNET_CONTROL_BIND").unwrap_or_else(|_| "127.0.0.1:7100".into());
    let listener = TcpListener::bind(&bind).ok()?;
    Some(thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 128];
            if let Ok(n) = stream.read(&mut buf) {
                if n > 0 {
                    if let Ok(msg) = hornet::control::decode(&buf[..n]) {
                        println!("control message: {:?}", msg);
                        match msg {
                            hornet::control::ControlMessage::ResendRequest { .. } => {
                                let _ = send_data(&info_path, &host, &payload);
                            }
                        }
                    }
                }
            }
        }
    }))
}

fn parse_ipv4_octets(ip: &str) -> Result<[u8; 4], String> {
    let addr: std::net::Ipv4Addr = ip.parse().map_err(|_| "invalid ipv4")?;
    Ok(addr.octets())
}

fn resolve_return_addr(local_addr: std::net::SocketAddr) -> Result<(IpAddr, u16), String> {
    if let Ok(addr) = env::var("HORNET_RETURN_ADDR") {
        let (host, port_str) = addr
            .rsplit_once(':')
            .ok_or("HORNET_RETURN_ADDR must be ip:port")?;
        let port: u16 = port_str.parse().map_err(|_| "invalid return port")?;
        let ip = parse_ipv4_octets(host)?;
        return Ok((IpAddr::V4(ip), port));
    }
    if let Ok(host) = env::var("HORNET_RETURN_HOST") {
        let ip = parse_ipv4_octets(&host)?;
        return Ok((IpAddr::V4(ip), local_addr.port()));
    }
    match local_addr {
        std::net::SocketAddr::V4(v4) => Ok((IpAddr::V4(v4.ip().octets()), v4.port())),
        std::net::SocketAddr::V6(v6) => Ok((IpAddr::V6(v6.ip().octets()), v6.port())),
    }
}

fn resolve_target_parts(hostname: &str, port: u16) -> Result<(IpAddr, u16), String> {
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

fn parse_host_port(host: &str, default_port: u16) -> Result<(String, u16), String> {
    let host = host.trim();
    if host.is_empty() {
        return Err("empty host".into());
    }

    if let Some(rest) = host.strip_prefix('[') {
        let Some((inside, after)) = rest.split_once(']') else {
            return Err("invalid host: missing closing ']'".into());
        };
        let port = if let Some(port_str) = after.strip_prefix(':') {
            port_str
                .parse::<u16>()
                .map_err(|_| "invalid port".to_string())?
        } else if after.is_empty() {
            default_port
        } else {
            return Err("invalid host: unexpected trailing characters after ']'".into());
        };
        return Ok((inside.to_string(), port));
    }

    if let Some((h, p)) = host.rsplit_once(':') {
        // If the left side contains ':' then this is most likely an IPv6 literal without
        // brackets; treat it as a hostname and do not attempt to parse a port.
        if !h.contains(':') {
            if let Ok(port) = p.parse::<u16>() {
                return Ok((h.to_string(), port));
            }
        }
    }

    Ok((host.to_string(), default_port))
}

fn target_value_from_hostname(hostname: &str) -> Result<TargetValue, String> {
    if let Ok(addr) = hostname.parse::<std::net::Ipv4Addr>() {
        return Ok(TargetValue::Ipv4(addr.octets()));
    }
    if let Ok(addr) = hostname.parse::<std::net::Ipv6Addr>() {
        return Ok(TargetValue::Ipv6(addr.octets()));
    }
    Ok(TargetValue::Domain(
        hostname.to_ascii_lowercase().into_bytes(),
    ))
}

fn read_request_bytes(payload_tail: &[u8]) -> Result<Vec<u8>, String> {
    // ZKBoo input bytes. Caller must ensure the circuit input size matches (len * 8).
    //
    // Priority:
    // 1) HORNET_REQUEST_PATH: raw bytes
    // 2) HORNET_TLS_RECORD_PATH: legacy env name (raw bytes)
    // 3) CLI payload_tail: hex bytes
    if let Ok(path) = env::var("HORNET_REQUEST_PATH") {
        if !path.trim().is_empty() {
            return fs::read(&path).map_err(|err| format!("failed to read {path}: {err}"));
        }
    }
    if let Ok(path) = env::var("HORNET_TLS_RECORD_PATH") {
        if !path.trim().is_empty() {
            return fs::read(&path).map_err(|err| format!("failed to read {path}: {err}"));
        }
    }
    let hex = core::str::from_utf8(payload_tail).map_err(|_| {
        "request bytes must be provided as hex (or set HORNET_REQUEST_PATH)".to_string()
    })?;
    decode_hex(hex).map_err(|err| format!("invalid request hex: {err}"))
}

fn load_router_states(
    routers: &[RouterInfo],
    policy_id: &[u8; 32],
) -> Result<Vec<(StoredState, RouterInfo)>, String> {
    let mut out = Vec::new();
    for info in routers {
        let data =
            fs::read(&info.storage_path).map_err(|err| {
                format!(
                    "failed to read {} (router {} state). ルータを一度起動して state を生成してください: {err}",
                    info.storage_path, info.name
                )
            })?;
        let state: StoredState =
            serde_json::from_slice(&data).map_err(|err| format!("invalid state JSON: {err}"))?;
        if select_route(&state, policy_id).is_err() {
            return Err(format!(
                "state {} has no route for policy {:?}",
                info.storage_path, policy_id
            ));
        }
        out.push((state, info.clone()));
    }
    Ok(out)
}

fn select_route(state: &StoredState, policy_id: &[u8; 32]) -> Result<RouteAnnouncement, String> {
    let routes = state.routes();
    routes
        .into_iter()
        .find(|route| &route.policy_id == policy_id)
        .ok_or_else(|| "no route for policy".into())
}

fn encode_frame(
    chdr: &hornet::types::Chdr,
    ahdr: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    if ahdr.len() > u32::MAX as usize || payload.len() > u32::MAX as usize {
        return Err("frame too large".into());
    }
    let mut frame = Vec::with_capacity(4 + 16 + 8 + ahdr.len() + payload.len());
    frame.push(0); // direction = forward
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

fn send_frame(info: &RouterInfo, frame: &[u8]) -> Result<(), String> {
    send_frame_to(&info.bind, frame)
}

fn send_frame_to(addr: &str, frame: &[u8]) -> Result<(), String> {
    let mut stream =
        TcpStream::connect(addr).map_err(|err| format!("failed to connect to {}: {err}", addr))?;
    stream
        .write_all(frame)
        .map_err(|err| format!("failed to send frame: {err}"))?;
    Ok(())
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

fn compute_expiry(delta_secs: u64) -> hornet::types::Exp {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let expiry = now.saturating_add(delta_secs);
    hornet::types::Exp(expiry.min(u32::MAX as u64) as u32)
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
    Ok((nanos & 0xFFFF_FFFF_FFFF_FFFF) as u64)
}

#[derive(Clone, Deserialize)]
struct PolicyInfo {
    policy_id: String,
    routers: Vec<RouterInfo>,
}

#[derive(Clone, Deserialize)]
struct RouterInfo {
    name: String,
    bind: String,
    #[serde(rename = "directory_path")]
    _directory_path: String,
    storage_path: String,
}
