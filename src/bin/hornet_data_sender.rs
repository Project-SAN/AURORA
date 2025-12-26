use hornet::policy::bundle::fetch_policy_bundle;
use hornet::policy::endpoint::{authority_url_from_env, oprf_url_from_env, policy_bundle_url_from_env, witness_url_from_env};
use hornet::policy::plonk::{PlonkPolicy, PolicyRole};
use hornet::policy::Blocklist;
use hornet::policy::oprf;
use hornet::policy::client::{OprfWitnessService, WitnessPreprocessor};
use hornet::router::storage::StoredState;
use hornet::routing::{self, IpAddr, RouteElem};
use hornet::setup::directory::RouteAnnouncement;
use hornet::types::{Nonce, PacketType, Si};
use hornet::utils::{decode_hex, encode_hex};
use rand::rngs::SmallRng;
use rand::{RngCore, SeedableRng};
use serde::Deserialize;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    if let Err(err) = run() {
        if let Some(msg) = err.strip_prefix(REJECT_PREFIX) {
            eprintln!("hornet_data_sender reject: {msg}");
            std::process::exit(2);
        }
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
    if info.routers.len() != 3 {
        return Err(format!(
            "expected 3 routers, got {}",
            info.routers.len()
        ));
    }
    let (policy_open_id, policy_parse_id, policy_check_id) = resolve_policy_ids(&info)?;
    let authority_url = authority_url_from_env("http://127.0.0.1:8080");
    let routers = load_router_states(&info.routers, &policy_open_id)?;
    let bundle_url = policy_bundle_url_from_env(&authority_url);
    let policy_open = load_policy_for_id(&policy_open_id, bundle_url.as_deref())?;
    let policy_parse = if policy_parse_id == policy_open_id {
        policy_open.clone()
    } else {
        load_policy_for_id(&policy_parse_id, bundle_url.as_deref())?
    };
    let policy_check = if policy_check_id == policy_open_id {
        policy_open.clone()
    } else if policy_check_id == policy_parse_id {
        policy_parse.clone()
    } else {
        load_policy_for_id(&policy_check_id, bundle_url.as_deref())?
    };

    // Resolve target host
    let (target_ip, target_port) = resolve_target(host)?;
    println!("Resolved {} to {:?}:{}", host, target_ip, target_port);

    let base_request = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    let mut request_payload = base_request.into_bytes();
    request_payload.extend_from_slice(payload_tail);
    let extractor = hornet::policy::extract::HttpHostExtractor::default();
    let witness_url = witness_url_from_env(&authority_url);
    let oprf_url =
        oprf_url_from_env(&authority_url).ok_or_else(|| "POLICY_OPRF_URL or POLICY_AUTHORITY_URL is required".to_string())?;
    let metadata = policy_check.metadata(0, 0);
    let witness_service = OprfWitnessService::new(oprf_url, witness_url);
    let preprocessor = WitnessPreprocessor::new(extractor, witness_service);
    let request = preprocessor
        .prepare(&metadata, &request_payload, &[])
        .map_err(|err| format!("failed to obtain witness: {err:?}"))?;
    let witness = request
        .non_membership
        .ok_or_else(|| "missing non-membership witness".to_string())?;
    let canonical_bytes = witness.target_leaf.clone();
    let capsule_open = policy_open
        .prove_payload(&witness.target_leaf)
        .map_err(|err| format!("failed to prove opening payload: {err:?}"))?;
    let capsule_parse = policy_parse
        .prove_payload(&witness.target_leaf)
        .map_err(|err| format!("failed to prove parse payload: {err:?}"))?;
    let capsule_check = policy_check
        .prove_payload(&witness.target_leaf)
        .map_err(|err| format!("failed to prove policy payload: {err:?}"))?;

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
            let route = select_route(state, &policy_open_id)?;
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

    // Setup listener for response
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("failed to bind listener: {e}"))?;
    let local_addr = listener.local_addr().map_err(|e| format!("failed to get local addr: {e}"))?;
    println!("Listening for response on {}", local_addr);

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
            let (ip, port) = match local_addr {
                std::net::SocketAddr::V4(v4) => (IpAddr::V4(v4.ip().octets()), v4.port()),
                std::net::SocketAddr::V6(v6) => (IpAddr::V6(v6.ip().octets()), v6.port()),
            };
            let elem = RouteElem::NextHop { addr: ip, port };
            routing::segment_from_elems(&[elem])
        } else {
            // Exit -> Middle or Middle -> Entry
            // The next hop in backward path is the previous hop in forward path (hop_idx - 1)
            let prev_router = &routers[hop_idx - 1].1;
             // Parse bind address of prev router to get IP/Port
             // Assuming bind is "IP:Port"
            let (ip_str, port_str) = prev_router.bind.rsplit_once(':').ok_or("invalid bind addr")?;
            let port: u16 = port_str.parse().map_err(|_| "invalid port")?;
            let ip_octets = parse_ipv4_octets(ip_str)?; // Helper needed
            let elem = RouteElem::NextHop { addr: IpAddr::V4(ip_octets), port };
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

    let mut ahdr_b_rng = SmallRng::seed_from_u64(derive_seed() ^ 0xBEEFBEEF);
    let ahdr_b = hornet::packet::ahdr::create_ahdr(&keys_b, &fses_b, rmax, &mut ahdr_b_rng)
        .map_err(|err| format!("failed to build Backward AHDR: {err:?}"))?;

    // Prepend Backward AHDR to payload
    let mut full_payload = Vec::new();
    full_payload.extend_from_slice(&(ahdr_b.bytes.len() as u32).to_le_bytes());
    full_payload.extend_from_slice(&ahdr_b.bytes);
    full_payload.extend_from_slice(&request_payload);

    let mut encrypted_tail = Vec::new();
    let leaf_len = canonical_bytes.len() as u32;
    encrypted_tail.extend_from_slice(&leaf_len.to_le_bytes());
    encrypted_tail.extend_from_slice(&canonical_bytes);
    encrypted_tail.extend_from_slice(&full_payload); // Use full_payload
    hornet::source::build(&mut chdr, &ahdr, &keys, &mut iv, &mut encrypted_tail)
        .map_err(|err| format!("failed to build payload: {err:?}"))?;
    let mut payload = encrypted_tail;
    for capsule in [capsule_open, capsule_parse, capsule_check].iter().rev() {
        capsule.prepend_to(&mut payload);
    }
    let frame = encode_frame(&chdr, &ahdr.bytes, &payload)?;
    let entry = &routers[0].1;
    let mut stream = send_frame(entry, &frame)?;
    if let Some(reject) = read_reject_frame(&mut stream)? {
        return Err(format!(
            "{REJECT_PREFIX}router rejected packet: {}{}",
            reject.reason,
            reject
                .policy_id
                .as_ref()
                .map(|id| format!(" (policy_id={})", id))
                .unwrap_or_default()
        ));
    }
    println!(
        "データ送信完了: {} へ {} バイト (hops={})",
        entry.bind,
        payload.len(),
        hops
    );

    // Listen for response
    println!("Waiting for response...");
    let (mut stream, addr) = listener.accept().map_err(|e| format!("accept failed: {e}"))?;
    println!("Connection from {}", addr);
    
    // Read response frame
    // Frame format: [direction:1][type:1][hops:1][res:1][specific:16][ahdr_len:4][payload_len:4][ahdr][payload]
    // But wait, the router sends back a HORNET packet.
    // The Client is NOT a router, but it needs to parse the frame.
    // Let's reuse `read_incoming_packet` logic or just read manually.
    
    // Simple read for now
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).map_err(|e| format!("read header failed: {e}"))?;
    // direction should be 1 (Backward)
    // type should be 1 (Data)
    
    let mut specific = [0u8; 16];
    stream.read_exact(&mut specific).map_err(|e| format!("read specific failed: {e}"))?;
    
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).map_err(|e| format!("read ahdr len failed: {e}"))?;
    let ahdr_len = u32::from_le_bytes(len_buf) as usize;
    
    stream.read_exact(&mut len_buf).map_err(|e| format!("read payload len failed: {e}"))?;
    let payload_len = u32::from_le_bytes(len_buf) as usize;
    
    if ahdr_len > 0 {
        let mut ahdr_buf = vec![0u8; ahdr_len];
        stream.read_exact(&mut ahdr_buf).map_err(|e| format!("read ahdr failed: {e}"))?;
    }
    
    let mut encrypted_response = vec![0u8; payload_len];
        stream.read_exact(&mut encrypted_response).map_err(|e| format!("read response failed: {e}"))?;
    
    // Decrypt response
    // Keys for backward path: keys_b
    // IV: specific
    // IMPORTANT: Routers add layers in order Exit→Middle→Entry (keys_b[0]→keys_b[1]→keys_b[2])
    // So we must remove layers in reverse: Entry→Middle→Exit (keys_b[2]→keys_b[1]→keys_b[0])
    let mut iv_resp = specific;
    let mut keys_b_reversed = keys_b.clone();
    keys_b_reversed.reverse();
    hornet::source::decrypt_backward_payload(&keys_b_reversed, &mut iv_resp, &mut encrypted_response)
         .map_err(|e| format!("decrypt failed: {e:?}"))?;
         
    println!("Received Response:\n{}", String::from_utf8_lossy(&encrypted_response));

    Ok(())
}

fn resolve_policy_ids(info: &PolicyInfo) -> Result<([u8; 32], [u8; 32], [u8; 32]), String> {
    let open_hex = env::var("POLICY_OPEN_ID_HEX")
        .ok()
        .or_else(|| env::var("POLICY_ID_HEX").ok())
        .or_else(|| info.policy_id_open.clone())
        .unwrap_or_else(|| info.policy_id.clone());
    let parse_hex = env::var("POLICY_PARSE_ID_HEX")
        .ok()
        .or_else(|| info.policy_id_parse.clone());
    let check_hex = env::var("POLICY_CHECK_ID_HEX")
        .ok()
        .or_else(|| info.policy_id_check.clone());
    let open_id = decode_policy_id(&open_hex)?;
    let parse_id = if let Some(hex) = parse_hex {
        decode_policy_id(&hex)?
    } else {
        open_id
    };
    let check_id = if let Some(hex) = check_hex {
        decode_policy_id(&hex)?
    } else {
        open_id
    };
    Ok((open_id, parse_id, check_id))
}

fn load_policy_for_id(
    policy_id: &[u8; 32],
    bundle_url: Option<&str>,
) -> Result<PlonkPolicy, String> {
    if let Some(bundle_url) = bundle_url {
        let bundle = fetch_policy_bundle(bundle_url, policy_id)?;
        return PlonkPolicy::from_prover_bytes(*policy_id, &bundle.prover_bytes, bundle.block_hashes)
            .map_err(|err| format!("failed to load proving key: {err:?}"));
    }
    let blocklist_path =
        env::var("LOCALNET_BLOCKLIST").unwrap_or_else(|_| "config/blocklist.json".into());
    let block_json = fs::read_to_string(&blocklist_path)
        .map_err(|err| format!("failed to read {blocklist_path}: {err}"))?;
    let blocklist = Blocklist::from_json(&block_json)
        .map_err(|err| format!("blocklist parse error: {err:?}"))?;
    let blocklist = maybe_oprf_blocklist(blocklist)?;
    let labels = candidate_policy_labels();
    for label in labels {
        let role = role_from_label(&label);
        let policy = PlonkPolicy::new_from_blocklist_with_role(label.as_bytes(), &blocklist, role)
            .map_err(|err| format!("failed to build policy: {err:?}"))?;
        if policy.policy_id() == policy_id {
            return Ok(policy);
        }
    }
    Err("policy-id mismatch between policy-info and blocklist".into())
}

fn maybe_oprf_blocklist(blocklist: Blocklist) -> Result<Blocklist, String> {
    let hex = match env::var("POLICY_OPRF_KEY_HEX") {
        Ok(value) => value,
        Err(_) => return Ok(blocklist),
    };
    let seed = decode_hex(hex.as_str()).map_err(|err| format!("OPRF key hex error: {err}"))?;
    let key = oprf::derive_key_from_seed(&seed);
    let mut leaves = Vec::with_capacity(blocklist.len());
    for entry in blocklist.entries() {
        let leaf = entry.leaf_bytes();
        let evaluated = oprf::eval_unblinded(&key, &leaf);
        leaves.push(evaluated.to_vec());
    }
    Ok(Blocklist::from_canonical_bytes(leaves))
}

fn candidate_policy_labels() -> Vec<String> {
    let mut labels = Vec::new();
    if let Ok(label) = env::var("POLICY_LABEL_OPEN") {
        labels.push(label);
    }
    if let Ok(label) = env::var("POLICY_LABEL_PARSE") {
        labels.push(label);
    }
    if let Ok(label) = env::var("POLICY_LABEL_CHECK") {
        labels.push(label);
    }
    if let Ok(base) = env::var("POLICY_LABEL") {
        labels.push(base.clone());
        labels.push(format!("{base}-open"));
        labels.push(format!("{base}-parse"));
        labels.push(format!("{base}-check"));
    }
    labels.push("localnet-demo".to_string());
    labels.push("localnet-demo-open".to_string());
    labels.push("localnet-demo-parse".to_string());
    labels.push("localnet-demo-check".to_string());
    labels
}

fn role_from_label(label: &str) -> PolicyRole {
    if label.ends_with("-open") {
        return PolicyRole::Open;
    }
    if label.ends_with("-parse") {
        return PolicyRole::Parse;
    }
    if label.ends_with("-check") {
        return PolicyRole::Check;
    }
    PolicyRole::Check
}

fn parse_ipv4_octets(ip: &str) -> Result<[u8; 4], String> {
    let addr: std::net::Ipv4Addr = ip.parse().map_err(|_| "invalid ipv4")?;
    Ok(addr.octets())
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
        PacketType::Reject => return Err("reject frames are not sendable".into()),
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

fn send_frame(info: &RouterInfo, frame: &[u8]) -> Result<TcpStream, String> {
    let mut stream = TcpStream::connect(&info.bind)
        .map_err(|err| format!("failed to connect to {}: {err}", info.bind))?;
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
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
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
    #[serde(default)]
    policy_id_open: Option<String>,
    #[serde(default)]
    policy_id_parse: Option<String>,
    #[serde(default)]
    policy_id_check: Option<String>,
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
