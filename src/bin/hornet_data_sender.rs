use hornet::policy::blocklist;
use hornet::policy::plonk::PlonkPolicy;
use hornet::policy::Blocklist;
use hornet::policy::Extractor;
use hornet::router::storage::StoredState;
use hornet::routing::{self, IpAddr, RouteElem};
use hornet::setup::directory::RouteAnnouncement;
use hornet::types::{Nonce, PacketType, Si};
use hornet::utils::decode_hex;
use rand::rngs::SmallRng;
use rand::{RngCore, SeedableRng};
use serde::Deserialize;
use std::env;
use std::fs;
use std::io::Write;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{SystemTime, UNIX_EPOCH};

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
    send_data(&info_path, &host, message.as_bytes())
}

fn send_data(info_path: &str, host: &str, payload_tail: &[u8]) -> Result<(), String> {
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
    let blocklist_path =
        env::var("LOCALNET_BLOCKLIST").unwrap_or_else(|_| "config/blocklist.json".into());
    let block_json = fs::read_to_string(&blocklist_path)
        .map_err(|err| format!("failed to read {blocklist_path}: {err}"))?;
    let blocklist = Blocklist::from_json(&block_json)
        .map_err(|err| format!("blocklist parse error: {err:?}"))?;
    let policy = PlonkPolicy::new_from_blocklist(b"localnet-demo", &blocklist)
        .map_err(|err| format!("failed to build policy: {err:?}"))?;
    if policy.policy_id() != &policy_id {
        return Err("policy-id mismatch between policy-info and blocklist".into());
    }

    // Resolve target host
    let (target_ip, target_port) = resolve_target(host)?;
    println!("Resolved {} to {:?}:{}", host, target_ip, target_port);

    let request_payload = format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
    let extractor = hornet::policy::extract::HttpHostExtractor::default();
    let target = extractor
        .extract(request_payload.as_bytes())
        .map_err(|err| format!("failed to extract host: {err:?}"))?;
    let entry = blocklist::entry_from_target(&target)
        .map_err(|err| format!("failed to canonicalise host: {err:?}"))?;
    let canonical_bytes = entry.leaf_bytes();
    let capsule = policy
        .prove_payload(&canonical_bytes)
        .map_err(|err| format!("failed to prove payload: {err:?}"))?;

    let mut rng = SmallRng::seed_from_u64(derive_seed());
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
            .map_err(|err| {
                format!(
                    "failed to build FS for hop {}: {err:?}",
                    hop
                )
            })?;
        fses.push(fs);
    }
    let mut ahdr_rng = SmallRng::seed_from_u64(derive_seed() ^ 0xA55AA55A);
    let ahdr = hornet::packet::ahdr::create_ahdr(&keys, &fses, rmax, &mut ahdr_rng)
        .map_err(|err| format!("failed to build AHDR: {err:?}"))?;

    let mut iv = {
        let mut buf = [0u8; 16];
        rng.fill_bytes(&mut buf);
        Nonce(buf)
    };
    let mut chdr = hornet::packet::chdr::data_header(hops as u8, iv);

    let capsule_bytes = capsule.encode();
    let mut encrypted_tail = Vec::new();
    encrypted_tail.extend_from_slice(&canonical_bytes);
    encrypted_tail.extend_from_slice(payload_tail);
    hornet::source::build(&mut chdr, &ahdr, &keys, &mut iv, &mut encrypted_tail)
        .map_err(|err| format!("failed to build payload: {err:?}"))?;
    let mut payload = capsule_bytes;
    payload.extend_from_slice(&encrypted_tail);
    let frame = encode_frame(&chdr, &ahdr.bytes, &payload)?;
    let entry = &routers[0].1;
    send_frame(entry, &frame)?;
    println!(
        "データ送信完了: {} へ {} バイト (hops={})",
        entry.bind,
        payload.len(),
        hops
    );
    Ok(())
}

fn resolve_target(host: &str) -> Result<(IpAddr, u16), String> {
    let (hostname, port) = if let Some((h, p)) = host.rsplit_once(':') {
        if let Ok(port_num) = p.parse::<u16>() {
            (h, port_num)
        } else {
            (host, 80)
        }
    } else {
        (host, 80)
    };

    // Try to resolve
    let addrs = (hostname, port)
        .to_socket_addrs()
        .map_err(|e| format!("failed to resolve {}: {}", host, e))?;

    for addr in addrs {
        match addr {
            std::net::SocketAddr::V4(v4) => {
                return Ok((IpAddr::V4(v4.ip().octets()), v4.port()));
            }
            std::net::SocketAddr::V6(v6) => {
                return Ok((IpAddr::V6(v6.ip().octets()), v6.port()));
            }
        }
    }

    Err(format!("no suitable address found for {}", host))
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

fn select_route<'a>(
    state: &'a StoredState,
    policy_id: &[u8; 32],
) -> Result<RouteAnnouncement, String> {
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
    let mut stream = TcpStream::connect(&info.bind)
        .map_err(|err| format!("failed to connect to {}: {err}", info.bind))?;
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
