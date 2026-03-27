use aurora::crypto::zkp::Circuit;
use aurora::demo::DEFAULT_DEMO_POLICY_PAYLOAD_LEN;
use aurora::policy::{PolicyMetadata, ProofKind};
use serde_json::Value;
use std::fs;

fn read_json(path: &str) -> Value {
    let body = fs::read_to_string(path).expect("read config");
    serde_json::from_str(&body).expect("parse json")
}

fn fixed_http_request(host: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"GET / HTTP/1.1\r\n");
    out.extend_from_slice(b"Host: ");
    out.extend_from_slice(host.as_bytes());
    out.extend_from_slice(b"\r\nConnection: close\r\nX-Pad: ");
    let pad_len = DEFAULT_DEMO_POLICY_PAYLOAD_LEN - out.len() - 4;
    out.extend(std::iter::repeat_n(b'a', pad_len));
    out.extend_from_slice(b"\r\n\r\n");
    assert_eq!(out.len(), DEFAULT_DEMO_POLICY_PAYLOAD_LEN);
    out
}

fn bytes_to_bits_lsb(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() * 8);
    for &byte in bytes {
        for bit in 0..8u8 {
            out.push((byte >> bit) & 1);
        }
    }
    out
}

fn load_policy_circuit(path: &str) -> Circuit {
    let doc = read_json(path);
    let metadata: PolicyMetadata =
        serde_json::from_value(doc["policies"][0].clone()).expect("policy metadata");
    let verifier = metadata
        .verifiers
        .iter()
        .find(|entry| entry.kind == ProofKind::Policy as u8)
        .expect("policy verifier");
    Circuit::decode(verifier.verifier_blob.as_slice()).expect("decode circuit")
}

fn allow_bit(circuit: &Circuit, host: &str) -> u8 {
    let payload = fixed_http_request(host);
    let outputs = circuit.eval(&bytes_to_bits_lsb(&payload)).expect("eval");
    outputs[32 * 8]
}

#[test]
fn qemu_policy_info_matches_expected_ports() {
    let doc = read_json("config/qemu/policy-info.host.json");
    let routers = doc["routers"].as_array().expect("routers array");
    assert_eq!(routers.len(), 3);
    assert_eq!(routers[0]["bind"], "127.0.0.1:18111");
    assert_eq!(routers[1]["bind"], "127.0.0.1:18112");
    assert_eq!(routers[2]["bind"], "127.0.0.1:18113");
}

#[test]
fn qemu_router_configs_keep_policy_enabled() {
    for name in ["entry", "middle", "exit"] {
        let path = format!("config/qemu/router-{name}.router_config.json");
        let doc = read_json(&path);
        assert_eq!(doc["skip_policy"], false);
        assert_eq!(doc["storage_path"], "/router_state.json");
        assert_eq!(doc["directory_path"], "/directory.json");
    }
}

#[test]
fn localnet_policy_info_matches_expected_ports() {
    let doc = read_json("config/localnet/policy-info.json");
    let routers = doc["routers"].as_array().expect("routers array");
    assert_eq!(routers.len(), 3);
    assert_eq!(routers[0]["bind"], "127.0.0.1:7101");
    assert_eq!(routers[1]["bind"], "127.0.0.1:7102");
    assert_eq!(routers[2]["bind"], "127.0.0.1:7103");
}

#[test]
fn checked_in_directory_policies_enforce_blocklist_semantics() {
    for path in [
        "config/localnet/router-entry.directory.json",
        "config/qemu/router-entry.directory.json",
    ] {
        let circuit = load_policy_circuit(path);
        assert_eq!(allow_bit(&circuit, "blocked.example"), 0, "{path}");
        assert_eq!(allow_bit(&circuit, "example.org"), 1, "{path}");
    }
}
