use crate::crypto::ascon::{MIX_DOMAIN_KEYBIND, MIX_DOMAIN_PAYLOAD};
use crate::crypto::zkp::{Circuit, WireId};
use alloc::vec::Vec;

type Word = [WireId; 64];

const ROUND_CONSTANTS: [u8; 12] = [
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b,
];

const HASH_IV: u64 = 0x0000_0801_00cc_0002;

pub fn build_keybinding_circuit(secret_len_bytes: usize) -> Circuit {
    build_mix_fold_circuit(secret_len_bytes, MIX_DOMAIN_KEYBIND)
}

pub fn build_payload_hash_circuit(payload_len_bytes: usize) -> Circuit {
    build_mix_fold_circuit(payload_len_bytes, MIX_DOMAIN_PAYLOAD)
}

pub fn build_consistency_circuit(secret_len_bytes: usize, payload_len_bytes: usize) -> Circuit {
    let n_inputs = (secret_len_bytes + payload_len_bytes) * 8;
    let mut circuit = Circuit::new(n_inputs);
    let (zero, one) = const_zero_one(&mut circuit);

    let secret_bits = input_bits(0, secret_len_bytes);
    let payload_bits = input_bits(secret_len_bytes * 8, payload_len_bytes);

    let hkey_bits = mix_fold_bits(
        &mut circuit,
        zero,
        one,
        MIX_DOMAIN_KEYBIND,
        secret_len_bytes,
        &secret_bits,
    );
    let payload_hash_bits = mix_fold_bits(
        &mut circuit,
        zero,
        one,
        MIX_DOMAIN_PAYLOAD,
        payload_len_bytes,
        &payload_bits,
    );

    let mut outputs = Vec::with_capacity(hkey_bits.len() + payload_hash_bits.len());
    outputs.extend_from_slice(&hkey_bits);
    outputs.extend_from_slice(&payload_hash_bits);
    circuit.set_outputs(&outputs);
    circuit.optimized()
}

pub fn build_policy_allow_host_circuit(
    payload_len_bytes: usize,
    host_header_offset: usize,
    host: &str,
) -> Circuit {
    let n_inputs = payload_len_bytes * 8;
    let mut circuit = Circuit::new(n_inputs);
    let (zero, one) = const_zero_one(&mut circuit);

    let payload_bits = input_bits(0, payload_len_bytes);
    let payload_hash_bits = mix_fold_bits(
        &mut circuit,
        zero,
        one,
        MIX_DOMAIN_PAYLOAD,
        payload_len_bytes,
        &payload_bits,
    );

    let expected = {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"Host: ");
        bytes.extend_from_slice(host.as_bytes());
        bytes.extend_from_slice(b"\r\n");
        bytes
    };
    let allow = eq_bytes(
        &mut circuit,
        one,
        &payload_bits,
        host_header_offset,
        &expected,
    );

    let mut outputs = Vec::with_capacity(payload_hash_bits.len() + 1);
    outputs.extend_from_slice(&payload_hash_bits);
    outputs.push(allow);
    circuit.set_outputs(&outputs);
    circuit.optimized()
}

fn build_mix_fold_circuit(payload_len_bytes: usize, domain: u64) -> Circuit {
    let n_inputs = payload_len_bytes * 8;
    let mut circuit = Circuit::new(n_inputs);
    let (zero, one) = const_zero_one(&mut circuit);
    let bits = input_bits(0, payload_len_bytes);
    let out_bits = mix_fold_bits(&mut circuit, zero, one, domain, payload_len_bytes, &bits);
    circuit.set_outputs(&out_bits);
    circuit.optimized()
}

fn const_zero_one(circuit: &mut Circuit) -> (WireId, WireId) {
    // x ^ x == 0 for any input bit x.
    let zero = circuit.add_xor(0, 0);
    let one = circuit.add_not(zero);
    (zero, one)
}

fn input_bits(bit_offset: usize, len_bytes: usize) -> Vec<WireId> {
    (bit_offset..bit_offset + len_bytes * 8).collect()
}

fn const_word(zero: WireId, one: WireId, value: u64) -> Word {
    core::array::from_fn(|i| if ((value >> i) & 1) == 1 { one } else { zero })
}

fn word_from_bits(bits: &[WireId], word_index: usize) -> Word {
    let base = word_index * 64;
    core::array::from_fn(|i| bits[base + i])
}

fn xor_word(circuit: &mut Circuit, a: &Word, b: &Word) -> Word {
    core::array::from_fn(|i| circuit.add_xor(a[i], b[i]))
}

fn and_word(circuit: &mut Circuit, a: &Word, b: &Word) -> Word {
    core::array::from_fn(|i| circuit.add_and(a[i], b[i]))
}

fn not_word(circuit: &mut Circuit, a: &Word) -> Word {
    core::array::from_fn(|i| circuit.add_not(a[i]))
}

fn rotr_word(a: &Word, n: usize) -> Word {
    core::array::from_fn(|i| a[(i + n) & 63])
}

fn ascon_round(circuit: &mut Circuit, state: &mut [Word; 5], rc: u8) {
    // add round constant into state[2] (LSB byte)
    for bit in 0..8 {
        if ((rc >> bit) & 1) == 1 {
            state[2][bit] = circuit.add_not(state[2][bit]);
        }
    }

    // substitution layer
    state[0] = xor_word(circuit, &state[0], &state[4]);
    state[4] = xor_word(circuit, &state[4], &state[3]);
    state[2] = xor_word(circuit, &state[2], &state[1]);

    let not0 = not_word(circuit, &state[0]);
    let not1 = not_word(circuit, &state[1]);
    let not2 = not_word(circuit, &state[2]);
    let not3 = not_word(circuit, &state[3]);
    let not4 = not_word(circuit, &state[4]);

    let t0 = and_word(circuit, &not0, &state[1]);
    let t1 = and_word(circuit, &not1, &state[2]);
    let t2 = and_word(circuit, &not2, &state[3]);
    let t3 = and_word(circuit, &not3, &state[4]);
    let t4 = and_word(circuit, &not4, &state[0]);

    state[0] = xor_word(circuit, &state[0], &t1);
    state[1] = xor_word(circuit, &state[1], &t2);
    state[2] = xor_word(circuit, &state[2], &t3);
    state[3] = xor_word(circuit, &state[3], &t4);
    state[4] = xor_word(circuit, &state[4], &t0);

    state[1] = xor_word(circuit, &state[1], &state[0]);
    state[0] = xor_word(circuit, &state[0], &state[4]);
    state[3] = xor_word(circuit, &state[3], &state[2]);
    state[2] = not_word(circuit, &state[2]);

    // linear diffusion
    let d0 = xor_word(
        circuit,
        &rotr_word(&state[0], 19),
        &rotr_word(&state[0], 28),
    );
    state[0] = xor_word(circuit, &state[0], &d0);
    let d1 = xor_word(
        circuit,
        &rotr_word(&state[1], 61),
        &rotr_word(&state[1], 39),
    );
    state[1] = xor_word(circuit, &state[1], &d1);
    let d2 = xor_word(circuit, &rotr_word(&state[2], 1), &rotr_word(&state[2], 6));
    state[2] = xor_word(circuit, &state[2], &d2);
    let d3 = xor_word(
        circuit,
        &rotr_word(&state[3], 10),
        &rotr_word(&state[3], 17),
    );
    state[3] = xor_word(circuit, &state[3], &d3);
    let d4 = xor_word(circuit, &rotr_word(&state[4], 7), &rotr_word(&state[4], 41));
    state[4] = xor_word(circuit, &state[4], &d4);
}

fn permute12(circuit: &mut Circuit, state: &mut [Word; 5]) {
    for &rc in &ROUND_CONSTANTS {
        ascon_round(circuit, state, rc);
    }
}

fn mix_fold_bits(
    circuit: &mut Circuit,
    zero: WireId,
    one: WireId,
    domain: u64,
    payload_len_bytes: usize,
    payload_bits: &[WireId],
) -> Vec<WireId> {
    // Initial state matches `crypto::ascon::mix_fold`.
    let state0 = const_word(zero, one, HASH_IV ^ domain);
    let state1 = const_word(zero, one, 0);
    let state2 = const_word(zero, one, 0);
    let state3 = const_word(zero, one, 0);
    let state4 = const_word(zero, one, payload_len_bytes as u64);
    let mut state = [state0, state1, state2, state3, state4];

    let word_count = (payload_len_bytes + 7) / 8;
    for word_index in 0..word_count {
        let word = word_from_bits(payload_bits, word_index);
        let slot = word_index % 5;
        state[slot] = xor_word(circuit, &state[slot], &word);
    }

    permute12(circuit, &mut state);

    let mut out = Vec::with_capacity(32 * 8);
    out.extend_from_slice(&state[0]);
    out.extend_from_slice(&state[1]);
    out.extend_from_slice(&state[2]);
    out.extend_from_slice(&state[3]);
    out
}

fn eq_bytes(
    circuit: &mut Circuit,
    one: WireId,
    bits: &[WireId],
    byte_offset: usize,
    expected: &[u8],
) -> WireId {
    let mut acc = one;
    for (idx, &byte) in expected.iter().enumerate() {
        for bit in 0..8usize {
            let in_wire = bits[(byte_offset + idx) * 8 + bit];
            let expected_bit = (byte >> bit) & 1;
            let eq_wire = if expected_bit == 1 {
                in_wire
            } else {
                circuit.add_not(in_wire)
            };
            acc = circuit.add_and(acc, eq_wire);
        }
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ascon::mix_fold;

    fn bytes_to_bits_lsb(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(bytes.len() * 8);
        for &b in bytes {
            for bit in 0..8u8 {
                out.push(((b >> bit) & 1) as u8);
            }
        }
        out
    }

    fn bits_to_bytes_lsb(bits: &[u8]) -> Vec<u8> {
        assert!(bits.len() % 8 == 0);
        let mut out = Vec::with_capacity(bits.len() / 8);
        for chunk in bits.chunks_exact(8) {
            let mut byte = 0u8;
            for (bit_idx, &bit) in chunk.iter().enumerate() {
                byte |= (bit & 1) << (bit_idx as u8);
            }
            out.push(byte);
        }
        out
    }

    #[test]
    fn keybinding_circuit_matches_mix_fold() {
        let circuit = build_keybinding_circuit(32);
        let secret: Vec<u8> = (0u8..32u8).collect();
        let input = bytes_to_bits_lsb(&secret);
        let out_bits = circuit.eval(&input).expect("eval");
        let out_bytes = bits_to_bytes_lsb(&out_bits);
        assert_eq!(out_bytes.len(), 32);
        assert_eq!(
            out_bytes.as_slice(),
            mix_fold(MIX_DOMAIN_KEYBIND, &secret).as_slice()
        );
    }

    #[test]
    fn policy_circuit_outputs_payload_hash_and_allow_bit() {
        let host = "example.com";
        let payload = (b"GET / HTTP/1.1\r\n\
Host: example.com\r\n\
User-Agent: hornet\r\n\
Accept: */*\r\n\
X: ab\r\n\
Connection: close\r\n\
\r\n")
            .to_vec();
        assert_eq!(payload.len(), 96);
        let circuit = build_policy_allow_host_circuit(96, 16, host);
        let input = bytes_to_bits_lsb(&payload);
        let out_bits = circuit.eval(&input).expect("eval");
        assert_eq!(out_bits.len(), 32 * 8 + 1);
        let (hash_bits, allow_bits) = out_bits.split_at(32 * 8);
        assert_eq!(allow_bits, &[1u8]);
        let hash_bytes = bits_to_bytes_lsb(hash_bits);
        assert_eq!(
            hash_bytes.as_slice(),
            mix_fold(MIX_DOMAIN_PAYLOAD, &payload).as_slice()
        );
    }
}
