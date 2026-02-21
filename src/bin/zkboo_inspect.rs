use aurora::crypto::zkp::Circuit;
use aurora::policy::zkboo::ZkBooPolicy;
use std::env;
use std::fs;

fn main() {
    let path = env::args()
        .nth(1)
        .unwrap_or_else(|| "usage: zkboo_inspect <path/to/circuit.zkbc>".into());
    if path.starts_with("usage:") {
        eprintln!("{path}");
        std::process::exit(2);
    }
    let req_path = env::args().nth(2);

    let bytes = fs::read(&path).unwrap_or_else(|err| {
        eprintln!("failed to read {path}: {err}");
        std::process::exit(1);
    });
    let circuit = Circuit::decode(&bytes).unwrap_or_else(|err| {
        eprintln!("failed to decode circuit ({path}): {err:?}");
        std::process::exit(1);
    });
    let policy = ZkBooPolicy::new(circuit);
    let n_inputs = policy.circuit().n_inputs;
    let gate_count = policy.circuit().gates.len();
    let output_count = policy.circuit().outputs.len();
    if n_inputs % 8 != 0 {
        eprintln!("warning: n_inputs is not a multiple of 8: {n_inputs}");
    }
    println!("policy_id: {}", hex(&policy.policy_id()[..]));
    println!("n_inputs: {n_inputs} bits");
    println!("payload_len: {} bytes", n_inputs / 8);
    println!("gates: {}", gate_count);
    println!("outputs: {}", output_count);

    if let Some(req_path) = req_path {
        let payload = fs::read(&req_path).unwrap_or_else(|err| {
            eprintln!("failed to read request bytes {req_path}: {err}");
            std::process::exit(1);
        });
        if payload.len() * 8 != n_inputs {
            eprintln!(
                "request length mismatch: got {} bytes ({} bits), expected {} bytes ({} bits)",
                payload.len(),
                payload.len() * 8,
                n_inputs / 8,
                n_inputs
            );
            std::process::exit(1);
        }
        let input_bits = payload_bits_lsb_first(&payload);
        match policy.circuit().eval(&input_bits) {
            Ok(out) => println!("eval_outputs: {:?}", out),
            Err(err) => eprintln!("eval failed: {err:?}"),
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0f) as usize] as char);
    }
    out
}

fn payload_bits_lsb_first(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len().saturating_mul(8));
    for &byte in payload {
        for bit in 0..8 {
            out.push(((byte >> bit) & 1) as u8);
        }
    }
    out
}
