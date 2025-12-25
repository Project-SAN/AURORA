use hornet::router::storage::StoredState;
use hornet::setup::directory;
use hornet::setup::wire;
use hornet::types::{Chdr, PacketType};
use rand::rngs::SmallRng;
use rand::SeedableRng;
use rand_core::RngCore;
use serde::Deserialize;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use x25519_dalek::x25519;

fn main() {
    if let Err(err) = run() {
        if let Some(msg) = err.strip_prefix(REJECT_PREFIX) {
            eprintln!("hornet_sender reject: {msg}");
            std::process::exit(2);
        }
        eprintln!("hornet_sender error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args();
    let program = args.next().unwrap_or_else(|| "hornet_sender".into());
    let info_path = args
        .next()
        .ok_or_else(|| format!("usage: {program} <policy-info.json>"))?;
    send_setup(&info_path)
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
    let announcement =
        directory::from_signed_json(&directory_body, info.directory_secret.as_bytes())
            .map_err(|err| format!("failed to verify directory: {err:?}"))?;

    let mut rng = SmallRng::seed_from_u64(derive_seed());
    let mut source_secret = [0u8; 32];
    rng.fill_bytes(&mut source_secret);
    clamp_scalar(&mut source_secret);

    let exp = compute_expiry(600);
    let mut state =
        hornet::setup::source_init(&source_secret, &node_pubs, node_pubs.len(), exp, &mut rng);
    directory::apply_to_source_state(&mut state, &announcement);
    let encoded = wire::encode(&state.packet)
        .map_err(|err| format!("failed to encode setup packet: {err:?}"))?;
    let frame = encode_frame(&state.packet.chdr, &encoded.header, &encoded.payload)?;
    let mut stream = send_frame(&entry.bind, &frame)?;
    if let Some(reject) = read_reject_frame(&mut stream)? {
        return Err(format!(
            "{REJECT_PREFIX}router rejected setup: {}{}",
            reject.reason,
            reject
                .policy_id
                .as_ref()
                .map(|id| format!(" (policy_id={})", id))
                .unwrap_or_default()
        ));
    }
    println!(
        "送信完了: {} へ setup フレーム ({:?} hops)",
        entry.bind, state.packet.chdr.hops
    );
    Ok(())
}

fn load_node_pubs(routers: &[RouterInfo]) -> Result<Vec<[u8; 32]>, String> {
    let mut pubs = Vec::new();
    for router in routers {
        let data = fs::read(&router.storage_path).map_err(|err| {
            format!(
                "failed to read {} (router {} state). ルータを一度起動して state を生成してください: {err}",
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
    let pid = std::process::id() as u128;
    (nanos ^ pid) as u64
}

fn encode_frame(chdr: &Chdr, header: &[u8], payload: &[u8]) -> Result<Vec<u8>, String> {
    if header.len() > u32::MAX as usize || payload.len() > u32::MAX as usize {
        return Err("setup frame too large".into());
    }
    let mut frame = Vec::with_capacity(4 + 16 + 8 + header.len() + payload.len());
    frame.push(0); // direction = forward
    frame.push(match chdr.typ {
        PacketType::Setup => 0,
        PacketType::Data => 1,
        PacketType::Reject => return Err("reject frames are not sendable".into()),
    });
    frame.push(chdr.hops);
    frame.push(0);
    frame.extend_from_slice(&chdr.specific);
    frame.extend_from_slice(&(header.len() as u32).to_le_bytes());
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(header);
    frame.extend_from_slice(payload);
    Ok(frame)
}

fn send_frame(bind: &str, frame: &[u8]) -> Result<TcpStream, String> {
    let mut stream =
        TcpStream::connect(bind).map_err(|err| format!("failed to connect to {bind}: {err}"))?;
    stream
        .write_all(frame)
        .map_err(|err| format!("failed to send frame: {err}"))?;
    Ok(stream)
}

struct RejectInfo {
    reason: String,
    policy_id: Option<String>,
}

const REJECT_PREFIX: &str = "REJECT:";

fn read_reject_frame(stream: &mut TcpStream) -> Result<Option<RejectInfo>, String> {
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .map_err(|err| format!("set read timeout failed: {err}"))?;
    let mut header = [0u8; 4];
    match stream.read_exact(&mut header) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
        Err(err) if err.kind() == std::io::ErrorKind::TimedOut => return Ok(None),
        Err(err) => return Err(format!("read header failed: {err}")),
    }
    let pkt_type = header[1];
    if pkt_type != 2 {
        return Ok(None);
    }
    let mut specific = [0u8; 16];
    stream
        .read_exact(&mut specific)
        .map_err(|err| format!("read specific failed: {err}"))?;
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|err| format!("read ahdr len failed: {err}"))?;
    let ahdr_len = u32::from_le_bytes(len_buf) as usize;
    stream
        .read_exact(&mut len_buf)
        .map_err(|err| format!("read payload len failed: {err}"))?;
    let payload_len = u32::from_le_bytes(len_buf) as usize;
    if ahdr_len > 0 {
        let mut ahdr_buf = vec![0u8; ahdr_len];
        stream
            .read_exact(&mut ahdr_buf)
            .map_err(|err| format!("read ahdr failed: {err}"))?;
    }
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        stream
            .read_exact(&mut payload)
            .map_err(|err| format!("read payload failed: {err}"))?;
    }
    if payload.len() < 2 {
        return Err("reject payload too short".into());
    }
    let reason = match payload[0] {
        1 => "policy violation",
        2 => "missing policy metadata",
        3 => "policy metadata mismatch",
        _ => "unknown reject reason",
    }
    .to_string();
    let has_policy = payload[1] == 1;
    let policy_id = if has_policy {
        if payload.len() < 2 + 32 {
            return Err("reject payload missing policy_id".into());
        }
        Some(encode_hex(&payload[2..34]))
    } else {
        None
    };
    Ok(Some(RejectInfo { reason, policy_id }))
}

fn encode_hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(TABLE[(b >> 4) as usize] as char);
        out.push(TABLE[(b & 0x0f) as usize] as char);
    }
    out
}

#[derive(Deserialize)]
struct PolicyInfo {
    directory_secret: String,
    routers: Vec<RouterInfo>,
}

#[derive(Deserialize)]
struct RouterInfo {
    name: String,
    bind: String,
    directory_path: String,
    storage_path: String,
}
