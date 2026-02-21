use aurora::core::policy::ProofKind;
use aurora::core::policy::{
    encode_extensions_into, CapsuleExtensionRef, AUX_MAX, EXT_TAG_SEQUENCE,
    EXT_TAG_PAYLOAD_HASH, EXT_TAG_PCD_KEY_HASH,
};
use aurora::crypto::ascon::{mix_fold, MIX_DOMAIN_KEYBIND, MIX_DOMAIN_PAYLOAD};
use aurora::crypto::zkp::Circuit;
use aurora::crypto::zkp::{Engine, Proof, VerifierConfig};
use aurora::policy::PolicyMetadata;
use aurora::policy::blocklist;
use aurora::policy::zkboo::ZkBooProofService;
use aurora::policy::TargetValue;
use aurora::router::storage::StoredState;
use aurora::routing::{self, IpAddr, RouteElem};
use aurora::setup::directory::RouteAnnouncement;
use aurora::types::{Nonce, PacketType, Si};
use aurora::utils::decode_hex;
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
        eprintln!("aurora_data_sender error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args();
    let program = args.next().unwrap_or_else(|| "aurora_data_sender".into());
    let info_path = args
        .next()
        .ok_or_else(|| format!("usage: {program} <policy-info.json> <host> [message]"))?;
    let host = args
        .next()
        .ok_or_else(|| format!("usage: {program} <policy-info.json> <host> [message]"))?;
    let message = args
        .next()
        .unwrap_or_else(|| "hello from aurora_data_sender".into());
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
    let policy_meta = load_policy_metadata(&info.routers, &policy_id)?;

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
    println!("sequence={sequence}");
    let seq_buf = sequence.to_be_bytes();

    let capsule = {
        let rounds: u16 = env::var("HORNET_ZKBOO_ROUNDS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(64);
        let policy_payload = request_payload.as_slice();

        let kb_circuit = circuit_from_metadata(&policy_meta, ProofKind::KeyBinding)?;
        let cons_circuit = circuit_from_metadata(&policy_meta, ProofKind::Consistency)?;
        let pol_circuit = circuit_from_metadata(&policy_meta, ProofKind::Policy)?;
        let local_verify_enabled = env::var("HORNET_LOCAL_VERIFY").ok().as_deref() == Some("1");
        let kb_verify = local_verify_enabled.then(|| kb_circuit.clone());
        let cons_verify = local_verify_enabled.then(|| cons_circuit.clone());
        let pol_verify = local_verify_enabled.then(|| pol_circuit.clone());

        let kb_len = kb_circuit.n_inputs / 8;
        if kb_len * 8 != kb_circuit.n_inputs {
            return Err("keybinding circuit n_inputs must be byte-aligned".into());
        }
        let pol_len = pol_circuit.n_inputs / 8;
        if pol_len * 8 != pol_circuit.n_inputs {
            return Err("policy circuit n_inputs must be byte-aligned".into());
        }
        if policy_payload.len() != pol_len {
            return Err(format!(
                "request length mismatch: got {} bytes, policy circuit expects {} bytes",
                policy_payload.len(),
                pol_len
            ));
        }
        let cons_len = cons_circuit.n_inputs / 8;
        if cons_len * 8 != cons_circuit.n_inputs {
            return Err("consistency circuit n_inputs must be byte-aligned".into());
        }
        if cons_len != kb_len + pol_len {
            return Err(format!(
                "consistency circuit input must be secret+payload ({}+{} bytes), got {} bytes",
                kb_len, pol_len, cons_len
            ));
        }

        let secret = {
            if let Ok(hex) = env::var("HORNET_ZKBOO_SECRET_HEX") {
                if !hex.trim().is_empty() {
                    let bytes = decode_hex(&hex)
                        .map_err(|err| format!("invalid HORNET_ZKBOO_SECRET_HEX: {err}"))?;
                    if bytes.len() != kb_len {
                        return Err(format!(
                            "HORNET_ZKBOO_SECRET_HEX must be {} bytes (got {})",
                            kb_len,
                            bytes.len()
                        ));
                    }
                    bytes
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            }
        };
        let secret = if secret.is_empty() {
            let mut buf = vec![0u8; kb_len];
            rng.fill_bytes(&mut buf);
            buf
        } else {
            secret
        };

        let hkey = mix_fold(MIX_DOMAIN_KEYBIND, &secret);
        let payload_hash = mix_fold(MIX_DOMAIN_PAYLOAD, policy_payload);

        let aux_keybinding = make_aux(&[
            CapsuleExtensionRef {
                tag: EXT_TAG_SEQUENCE,
                data: &seq_buf,
            },
            CapsuleExtensionRef {
                tag: EXT_TAG_PCD_KEY_HASH,
                data: &hkey,
            },
        ])?;
        let aux_consistency = make_aux(&[
            CapsuleExtensionRef {
                tag: EXT_TAG_SEQUENCE,
                data: &seq_buf,
            },
            CapsuleExtensionRef {
                tag: EXT_TAG_PCD_KEY_HASH,
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

        let mut consistency_payload = Vec::with_capacity(secret.len() + policy_payload.len());
        consistency_payload.extend_from_slice(&secret);
        consistency_payload.extend_from_slice(policy_payload);

        println!(
            "Generating ZKBoo proofs (rounds={}): KeyBinding/Consistency/Policy...",
            rounds
        );
        let proof_start = Instant::now();

        let kb = make_part(
            &policy_id,
            kb_circuit,
            rounds,
            &secret,
            &aux_keybinding,
            ProofKind::KeyBinding,
        )?;
        let cons = make_part(
            &policy_id,
            cons_circuit,
            rounds,
            &consistency_payload,
            &aux_consistency,
            ProofKind::Consistency,
        )?;
        let pol = make_part(
            &policy_id,
            pol_circuit,
            rounds,
            policy_payload,
            &aux_policy,
            ProofKind::Policy,
        )?;

        if local_verify_enabled {
            local_verify_part(
                "KeyBinding",
                kb_verify.as_ref().ok_or_else(|| "missing kb circuit".to_string())?,
                &kb,
                &bits_from_bytes_lsb_first(&hkey),
            )?;
            let mut cons_out = Vec::with_capacity(32 * 8 * 2);
            cons_out.extend_from_slice(&bits_from_bytes_lsb_first(&hkey));
            cons_out.extend_from_slice(&bits_from_bytes_lsb_first(&payload_hash));
            local_verify_part(
                "Consistency",
                cons_verify
                    .as_ref()
                    .ok_or_else(|| "missing cons circuit".to_string())?,
                &cons,
                &cons_out,
            )?;
            let mut pol_out = Vec::with_capacity(32 * 8 + 1);
            pol_out.extend_from_slice(&bits_from_bytes_lsb_first(&payload_hash));
            pol_out.push(1);
            local_verify_part(
                "Policy",
                pol_verify
                    .as_ref()
                    .ok_or_else(|| "missing pol circuit".to_string())?,
                &pol,
                &pol_out,
            )?;
            println!("[local-verify] all parts verified");
        }

        println!("Proofs generated in {:.2?}", proof_start.elapsed());

        aurora::policy::PolicyCapsule {
            policy_id,
            version: aurora::core::policy::POLICY_CAPSULE_VERSION,
            part_count: 3,
            parts: [kb, cons, pol, aurora::policy::ProofPart::default()],
        }
    };

    if env::var("HORNET_DRY_RUN").ok().as_deref() == Some("1") {
        let capsule_len = capsule
            .encoded_len()
            .map_err(|_| "failed to compute capsule length".to_string())?;
        println!("[dry-run] capsule_len={capsule_len} bytes");
        return Ok(());
    }
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
            // Last hop: construct dynamic exit segment.
            let elem = RouteElem::ExitTcp {
                addr: target_ip.clone(),
                port: target_port,
            };
            routing::segment_from_elems(&[elem])
        } else {
            // Intermediate hop: use stored route
            let route = select_route(state, &policy_id)?;
            route.segment
        };

        let fs = aurora::packet::core::create(&state.sv(), &keys[hop], &segment, exp)
            .map_err(|err| format!("failed to build FS for hop {}: {err:?}", hop))?;
        fses.push(fs);
    }
    let mut ahdr_rng = ChaCha20Rng::seed_from_u64(derive_seed() ^ 0xA55AA55A);
    let ahdr = aurora::packet::ahdr::create_ahdr(&keys, &fses, rmax, &mut ahdr_rng)
        .map_err(|err| format!("failed to build AHDR: {err:?}"))?;

    let mut iv = {
        let mut buf = [0u8; 16];
        rng.fill_bytes(&mut buf);
        Nonce(buf)
    };
    let mut chdr = aurora::packet::chdr::data_header(hops as u8, iv);

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

        let fs = aurora::packet::core::create(&state.sv(), &keys_b[i], &segment, exp)
            .map_err(|err| format!("failed to build FS for backward hop {}: {err:?}", i))?;
        fses_b.push(fs);
    }

    let mut ahdr_b_rng = ChaCha20Rng::seed_from_u64(derive_seed() ^ 0xBEEFBEEF);
    let ahdr_b = aurora::packet::ahdr::create_ahdr(&keys_b, &fses_b, rmax, &mut ahdr_b_rng)
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
    aurora::source::build(&mut chdr, &ahdr, &keys, &mut iv, &mut encrypted_tail)
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
    aurora::source::decrypt_backward_payload(
        &keys_b_reversed,
        &mut iv_resp,
        &mut encrypted_response,
    )
    .map_err(|e| format!("decrypt failed: {e:?}"))?;

    if let Ok(path) = env::var("HORNET_RESPONSE_OUTPUT_PATH") {
        if !path.trim().is_empty() {
            fs::write(&path, &encrypted_response)
                .map_err(|e| format!("failed to write response output {path}: {e}"))?;
        }
    }

    println!("Round-trip time: {:.2?}", start_rtt.elapsed());
    println!("Total time: {:.2?}", start_total.elapsed());
    println!(
        "Received Response:\n{}",
        String::from_utf8_lossy(&encrypted_response)
    );

    Ok(())
}

fn local_verify_part(
    label: &str,
    circuit: &Circuit,
    part: &aurora::policy::ProofPart,
    expected_outputs: &[u8],
) -> Result<(), String> {
    if expected_outputs.len() != circuit.outputs.len() {
        return Err(format!(
            "[local-verify] {label}: output len mismatch (expected_outputs={} circuit_outputs={})",
            expected_outputs.len(),
            circuit.outputs.len()
        ));
    }
    let proof = Proof::from_part(part).map_err(|err| format!("[local-verify] {label}: {err:?}"))?;
    let engine = Engine;
    engine
        .verify(
            circuit,
            expected_outputs,
            &proof,
            VerifierConfig { rounds: proof.rounds },
        )
        .map_err(|err| format!("[local-verify] {label}: verify failed: {err:?}"))?;
    println!(
        "[local-verify] {label}: ok (rounds={}, proof_len={})",
        proof.rounds,
        part.proof.len()
    );
    Ok(())
}

fn bits_from_bytes_lsb_first(bytes: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() * 8);
    for &b in bytes.iter() {
        for bit in 0..8u8 {
            out.push(((b >> bit) & 1) as u8);
        }
    }
    out
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
                    if let Ok(msg) = aurora::control::decode(&buf[..n]) {
                        println!("control message: {:?}", msg);
                        match msg {
                            aurora::control::ControlMessage::ResendRequest { .. } => {
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
    chdr: &aurora::types::Chdr,
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

#[derive(Clone, Deserialize)]
struct PolicyInfo {
    policy_id: String,
    routers: Vec<RouterInfo>,
}

#[derive(Clone, Deserialize)]
struct RouterInfo {
    name: String,
    bind: String,
    directory_path: String,
    storage_path: String,
}

fn load_policy_metadata(routers: &[RouterInfo], policy_id: &[u8; 32]) -> Result<PolicyMetadata, String> {
    let first = routers.first().ok_or_else(|| "policy-info has no routers".to_string())?;
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
