use hornet::router::storage::StoredState;
use hornet::setup::directory;
use hornet::setup::wire;
use hornet::types::{Chdr, PacketType};
use hornet::utils::decode_hex;
use rand::rngs::SmallRng;
use rand::SeedableRng;
use rand_core::RngCore;
use serde::Deserialize;
use std::env;
use std::fs;
use std::io::Write;
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};
use x25519_dalek::x25519;

fn main() {
    if let Err(err) = run() {
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
    let public_key = decode_hex(&info.directory_public_key)
        .map_err(|err| format!("invalid directory_public_key hex: {err}"))?;
    if public_key.len() != 32 {
        return Err("directory_public_key must be 32 bytes".into());
    }
    let announcement = directory::from_signed_json(&directory_body, &public_key)
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
    send_frame(&entry.bind, &frame)?;
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

fn send_frame(bind: &str, frame: &[u8]) -> Result<(), String> {
    let mut stream =
        TcpStream::connect(bind).map_err(|err| format!("failed to connect to {bind}: {err}"))?;
    stream
        .write_all(frame)
        .map_err(|err| format!("failed to send frame: {err}"))?;
    Ok(())
}

#[derive(Deserialize)]
struct PolicyInfo {
    directory_public_key: String,
    routers: Vec<RouterInfo>,
}

#[derive(Deserialize)]
struct RouterInfo {
    name: String,
    bind: String,
    directory_path: String,
    storage_path: String,
}
