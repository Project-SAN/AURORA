use alloc::vec;
use alloc::vec::Vec;

use crate::crypto::ascon::AsconHash256;
use crate::crypto::zkp::circuit::{Circuit, Gate};
use crate::crypto::zkp::merkle::MerkleTree;
use crate::crypto::zkp::seed_tree::{SeedDeriver, SeedRevealSet, SeedTree};
use crate::types::{Error, Result};
use rand_core::{CryptoRng, RngCore};

const SEED_LEN: usize = 32;
const TAPE_DOMAIN: &[u8] = b"AURORA-ZKBOO-TAPE";
const COMMIT_DOMAIN: &[u8] = b"AURORA-ZKBOO-VIEW";
const CHAL_DOMAIN: &[u8] = b"AURORA-ZKBOO-CHAL";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    pub rounds: u16,
    pub commit_root: [u8; 32],
    pub openings: Vec<RoundOpening>,
    pub seed_reveals: Vec<SeedRevealSet>,
}

impl Proof {
    pub fn encoded_len(&self) -> Result<usize> {
        let mut total = 0usize;
        add_len(&mut total, 2 + 1 + 1 + 32 + 4)?;
        for opening in &self.openings {
            add_len(&mut total, 1)?;
            add_len(&mut total, view_len(&opening.view_e)?)?;
            add_len(&mut total, view_len(&opening.view_e1)?)?;
        }
        add_len(&mut total, 1)?;
        for reveal in &self.seed_reveals {
            add_len(&mut total, 4 + 4 + 4)?;
            for _ in &reveal.nodes {
                add_len(&mut total, 4 + 32)?;
            }
        }
        Ok(total)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let len = self.encoded_len()?;
        let mut out = Vec::with_capacity(len);
        encode_u16(&mut out, self.rounds);
        out.push(0);
        out.push(0);
        out.extend_from_slice(&self.commit_root);
        encode_u32(&mut out, self.openings.len() as u32);
        for opening in &self.openings {
            out.push(opening.e);
            encode_view(&mut out, &opening.view_e)?;
            encode_view(&mut out, &opening.view_e1)?;
        }
        out.push(self.seed_reveals.len() as u8);
        for reveal in &self.seed_reveals {
            encode_u32(&mut out, reveal.leaf_count);
            encode_u32(&mut out, reveal.rounds);
            encode_u32(&mut out, reveal.nodes.len() as u32);
            for node in &reveal.nodes {
                encode_u32(&mut out, node.node);
                out.extend_from_slice(&node.seed);
            }
        }
        Ok(out)
    }

    pub fn decode(buf: &[u8]) -> Result<(Proof, usize)> {
        let mut cursor = 0usize;
        let rounds = read_u16(buf, &mut cursor)?;
        let _version = read_u8(buf, &mut cursor)?;
        let _flags = read_u8(buf, &mut cursor)?;
        let commit_root = read_fixed(buf, &mut cursor)?;
        let opening_count = read_u32(buf, &mut cursor)? as usize;
        let mut openings = Vec::with_capacity(opening_count);
        for _ in 0..opening_count {
            let e = read_u8(buf, &mut cursor)?;
            let view_e = decode_view(buf, &mut cursor)?;
            let view_e1 = decode_view(buf, &mut cursor)?;
            openings.push(RoundOpening { e, view_e, view_e1 });
        }
        let seed_count = read_u8(buf, &mut cursor)? as usize;
        let mut seed_reveals = Vec::with_capacity(seed_count);
        for _ in 0..seed_count {
            let leaf_count = read_u32(buf, &mut cursor)?;
            let rounds_count = read_u32(buf, &mut cursor)?;
            let node_count = read_u32(buf, &mut cursor)? as usize;
            let mut nodes = Vec::with_capacity(node_count);
            for _ in 0..node_count {
                let node = read_u32(buf, &mut cursor)?;
                let seed = read_fixed(buf, &mut cursor)?;
                nodes.push(crate::crypto::zkp::seed_tree::SeedReveal { node, seed });
            }
            seed_reveals.push(SeedRevealSet {
                leaf_count,
                rounds: rounds_count,
                nodes,
            });
        }
        Ok((
            Proof {
                rounds,
                commit_root,
                openings,
                seed_reveals,
            },
            cursor,
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoundOpening {
    pub e: u8,
    pub view_e: ViewOpening,
    pub view_e1: ViewOpening,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ViewOpening {
    pub party: u8,
    pub wires: Vec<u8>,
    pub merkle_path: Vec<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProverConfig {
    pub rounds: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifierConfig {
    pub rounds: u16,
}

pub struct ZkBooEngine;

impl ZkBooEngine {
    pub fn prove_circuit_with_rng<R: RngCore + CryptoRng>(
        &self,
        circuit: &Circuit,
        input_bits: &[u8],
        public_output: &[u8],
        cfg: ProverConfig,
        rng: &mut R,
    ) -> Result<Proof> {
        if input_bits.len() != circuit.n_inputs || public_output.len() != circuit.outputs.len() {
            return Err(Error::Length);
        }
        let rounds = cfg.rounds as usize;
        let mut root_seeds = [[0u8; SEED_LEN]; 3];
        for seed in &mut root_seeds {
            rng.fill_bytes(seed);
        }
        let seed_trees = [
            SeedTree::new(root_seeds[0], rounds),
            SeedTree::new(root_seeds[1], rounds),
            SeedTree::new(root_seeds[2], rounds),
        ];

        let mut round_states = Vec::with_capacity(rounds);
        let mut commitments = Vec::with_capacity(rounds * 3);

        for round in 0..rounds {
            let seeds = [
                seed_trees[0]
                    .seed_for_round(round)
                    .ok_or(Error::Length)?,
                seed_trees[1]
                    .seed_for_round(round)
                    .ok_or(Error::Length)?,
                seed_trees[2]
                    .seed_for_round(round)
                    .ok_or(Error::Length)?,
            ];
            let state = simulate_round(circuit, input_bits, public_output, seeds)?;
            commitments.extend_from_slice(&state.commitments);
            round_states.push(state);
        }

        let merkle = MerkleTree::build(&commitments);
        let root = merkle.root();

        let mut openings = Vec::with_capacity(rounds);
        let mut opened_by_party = vec![vec![false; rounds]; 3];
        for round in 0..rounds {
            let e = derive_challenge(public_output, root, round);
            let e1 = (e + 1) % 3;
            let view_e = &round_states[round].views[e as usize];
            let view_e1 = &round_states[round].views[e1 as usize];
            let leaf_e = round * 3 + e as usize;
            let leaf_e1 = round * 3 + e1 as usize;
            openings.push(RoundOpening {
                e,
                view_e: ViewOpening {
                    party: e,
                    wires: view_e.clone(),
                    merkle_path: merkle.open(leaf_e),
                },
                view_e1: ViewOpening {
                    party: e1,
                    wires: view_e1.clone(),
                    merkle_path: merkle.open(leaf_e1),
                },
            });
            opened_by_party[e as usize][round] = true;
            opened_by_party[e1 as usize][round] = true;
        }

        let mut seed_reveals = Vec::with_capacity(3);
        for (party, tree) in seed_trees.iter().enumerate() {
            seed_reveals.push(tree.reveal_for_opened(&opened_by_party[party]));
        }

        Ok(Proof {
            rounds: cfg.rounds,
            commit_root: root,
            openings,
            seed_reveals,
        })
    }

    pub fn verify_circuit(
        &self,
        circuit: &Circuit,
        public_output: &[u8],
        proof: &Proof,
        cfg: VerifierConfig,
    ) -> Result<()> {
        if proof.rounds != cfg.rounds {
            return Err(Error::Length);
        }
        if public_output.len() != circuit.outputs.len() {
            return Err(Error::Length);
        }
        let rounds = proof.rounds as usize;
        if proof.openings.len() != rounds || proof.seed_reveals.len() != 3
        {
            return Err(Error::Length);
        }

        let seed_derivers = [
            SeedDeriver::new(&proof.seed_reveals[0]),
            SeedDeriver::new(&proof.seed_reveals[1]),
            SeedDeriver::new(&proof.seed_reveals[2]),
        ];

        for round in 0..rounds {
            let expected_e = derive_challenge(public_output, proof.commit_root, round);
            let opening = &proof.openings[round];
            if opening.e != expected_e {
                return Err(Error::Crypto);
            }
            let e = opening.e as usize;
            let e1 = (e + 1) % 3;
            if opening.view_e.party as usize != e || opening.view_e1.party as usize != e1 {
                return Err(Error::Crypto);
            }

            let seed_e = seed_derivers[e]
                .seed_for_round(round)
                .ok_or(Error::Crypto)?;
            let seed_e1 = seed_derivers[e1]
                .seed_for_round(round)
                .ok_or(Error::Crypto)?;

            let com_e = commit_view(&seed_e, &opening.view_e.wires);
            let com_e1 = commit_view(&seed_e1, &opening.view_e1.wires);
            let leaf_e = round * 3 + e;
            let leaf_e1 = round * 3 + e1;
            if !MerkleTree::verify(
                proof.commit_root,
                com_e,
                leaf_e,
                &opening.view_e.merkle_path,
            ) {
                return Err(Error::Crypto);
            }
            if !MerkleTree::verify(
                proof.commit_root,
                com_e1,
                leaf_e1,
                &opening.view_e1.merkle_path,
            ) {
                return Err(Error::Crypto);
            }

            let out_e = extract_outputs(circuit, &opening.view_e.wires)?;
            let out_e1 = extract_outputs(circuit, &opening.view_e1.wires)?;
            for (idx, &bit) in public_output.iter().enumerate() {
                let recombined = (out_e[idx] ^ out_e1[idx] ^ bit) & 1;
                if recombined > 1 {
                    return Err(Error::Crypto);
                }
            }

            if !check_branch(
                circuit,
                e,
                &opening.view_e.wires,
                &opening.view_e1.wires,
                &seed_e,
                &seed_e1,
            )? {
                return Err(Error::Crypto);
            }
        }

        Ok(())
    }
}

struct RoundState {
    views: Vec<Vec<u8>>,
    commitments: [[u8; 32]; 3],
}

fn simulate_round(
    circuit: &Circuit,
    input_bits: &[u8],
    public_output: &[u8],
    seeds: [[u8; SEED_LEN]; 3],
) -> Result<RoundState> {
    let n_wires = circuit.wire_count();
    let mut views = vec![vec![0u8; n_wires], vec![0u8; n_wires], vec![0u8; n_wires]];
    let mut tapes = vec![
        Tape::new(seeds[0]),
        Tape::new(seeds[1]),
        Tape::new(seeds[2]),
    ];

    for idx in 0..circuit.n_inputs {
        let s0 = tapes[0].next_bit();
        let s1 = tapes[1].next_bit();
        let _ = tapes[2].next_bit();
        let s2 = (input_bits[idx] & 1) ^ s0 ^ s1;
        views[0][idx] = s0;
        views[1][idx] = s1;
        views[2][idx] = s2;
    }

    for (g_idx, gate) in circuit.gates.iter().enumerate() {
        let out = circuit.n_inputs + g_idx;
        match *gate {
            Gate::Xor { a, b } => {
                for i in 0..3 {
                    views[i][out] = views[i][a] ^ views[i][b];
                }
            }
            Gate::Not { a } => {
                views[0][out] = views[0][a] ^ 1;
                views[1][out] = views[1][a];
                views[2][out] = views[2][a];
            }
            Gate::And { a, b } => {
                let r0 = tapes[0].next_bit();
                let r1 = tapes[1].next_bit();
                let r2 = tapes[2].next_bit();
                views[0][out] = (views[0][a] & views[0][b])
                    ^ (views[1][a] & views[0][b])
                    ^ (views[0][a] & views[1][b])
                    ^ r0
                    ^ r1;
                views[1][out] = (views[1][a] & views[1][b])
                    ^ (views[2][a] & views[1][b])
                    ^ (views[1][a] & views[2][b])
                    ^ r1
                    ^ r2;
                views[2][out] = (views[2][a] & views[2][b])
                    ^ (views[0][a] & views[2][b])
                    ^ (views[2][a] & views[0][b])
                    ^ r2
                    ^ r0;
            }
        }
    }

    let out0 = extract_outputs(circuit, &views[0])?;
    let out1 = extract_outputs(circuit, &views[1])?;
    let out2 = extract_outputs(circuit, &views[2])?;
    for (idx, &bit) in public_output.iter().enumerate() {
        let recombined = (out0[idx] ^ out1[idx] ^ out2[idx]) & 1;
        if recombined != (bit & 1) {
            return Err(Error::Crypto);
        }
    }

    let mut commitments = [[0u8; 32]; 3];
    for i in 0..3 {
        commitments[i] = commit_view(&seeds[i], &views[i]);
    }

    Ok(RoundState {
        views,
        commitments,
    })
}

fn extract_outputs(circuit: &Circuit, wires: &[u8]) -> Result<Vec<u8>> {
    if wires.len() != circuit.wire_count() {
        return Err(Error::Length);
    }
    let mut out = Vec::with_capacity(circuit.outputs.len());
    for &wire in &circuit.outputs {
        if wire >= wires.len() {
            return Err(Error::Length);
        }
        out.push(wires[wire] & 1);
    }
    Ok(out)
}

fn check_branch(
    circuit: &Circuit,
    branch: usize,
    view_i: &[u8],
    view_i1: &[u8],
    seed_i: &[u8; SEED_LEN],
    seed_i1: &[u8; SEED_LEN],
) -> Result<bool> {
    if view_i.len() != circuit.wire_count() || view_i1.len() != circuit.wire_count() {
        return Err(Error::Length);
    }
    let mut tape_i = Tape::new(*seed_i);
    let mut tape_i1 = Tape::new(*seed_i1);
    tape_i.skip_bits(circuit.n_inputs);
    tape_i1.skip_bits(circuit.n_inputs);

    let mut calc = vec![0u8; circuit.wire_count()];
    calc[..circuit.n_inputs].copy_from_slice(&view_i[..circuit.n_inputs]);

    for (g_idx, gate) in circuit.gates.iter().enumerate() {
        let out = circuit.n_inputs + g_idx;
        let expected = match *gate {
            Gate::Xor { a, b } => calc[a] ^ calc[b],
            Gate::Not { a } => {
                if branch == 0 {
                    calc[a] ^ 1
                } else {
                    calc[a]
                }
            }
            Gate::And { a, b } => {
                let r_i = tape_i.next_bit();
                let r_i1 = tape_i1.next_bit();
                (calc[a] & calc[b])
                    ^ (view_i1[a] & calc[b])
                    ^ (calc[a] & view_i1[b])
                    ^ r_i
                    ^ r_i1
            }
        };
        if (view_i[out] & 1) != (expected & 1) {
            return Ok(false);
        }
        calc[out] = expected & 1;
    }

    Ok(true)
}

fn derive_challenge(public_output: &[u8], root: [u8; 32], round: usize) -> u8 {
    let mut hasher = AsconHash256::new();
    hasher.update(CHAL_DOMAIN);
    hasher.update(&(round as u64).to_be_bytes());
    hasher.update(&root);
    hasher.update(public_output);
    let digest = hasher.finalize();
    digest[0] % 3
}

fn commit_view(seed: &[u8; SEED_LEN], wires: &[u8]) -> [u8; 32] {
    let mut hasher = AsconHash256::new();
    hasher.update(COMMIT_DOMAIN);
    hasher.update(seed);
    hasher.update(&(wires.len() as u32).to_be_bytes());
    hasher.update(wires);
    hasher.finalize()
}

fn view_len(view: &ViewOpening) -> Result<usize> {
    if view.merkle_path.len() > u16::MAX as usize {
        return Err(Error::Length);
    }
    let mut total = 0usize;
    add_len(&mut total, 1 + 4)?;
    add_len(&mut total, view.wires.len())?;
    add_len(&mut total, 2)?;
    add_len(&mut total, view.merkle_path.len() * 32)?;
    Ok(total)
}

fn encode_view(out: &mut Vec<u8>, view: &ViewOpening) -> Result<()> {
    if view.merkle_path.len() > u16::MAX as usize {
        return Err(Error::Length);
    }
    out.push(view.party);
    encode_u32(out, view.wires.len() as u32);
    out.extend_from_slice(&view.wires);
    encode_u16(out, view.merkle_path.len() as u16);
    for node in &view.merkle_path {
        out.extend_from_slice(node);
    }
    Ok(())
}

fn decode_view(buf: &[u8], cursor: &mut usize) -> Result<ViewOpening> {
    let party = read_u8(buf, cursor)?;
    let wires_len = read_u32(buf, cursor)? as usize;
    let wires = read_bytes(buf, cursor, wires_len)?;
    let path_len = read_u16(buf, cursor)? as usize;
    let mut merkle_path = Vec::with_capacity(path_len);
    for _ in 0..path_len {
        let node = read_fixed(buf, cursor)?;
        merkle_path.push(node);
    }
    Ok(ViewOpening {
        party,
        wires,
        merkle_path,
    })
}

fn add_len(total: &mut usize, add: usize) -> Result<()> {
    *total = total.checked_add(add).ok_or(Error::Length)?;
    Ok(())
}

fn encode_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn encode_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn read_u8(buf: &[u8], cursor: &mut usize) -> Result<u8> {
    if *cursor + 1 > buf.len() {
        return Err(Error::Length);
    }
    let val = buf[*cursor];
    *cursor += 1;
    Ok(val)
}

fn read_u16(buf: &[u8], cursor: &mut usize) -> Result<u16> {
    if *cursor + 2 > buf.len() {
        return Err(Error::Length);
    }
    let mut tmp = [0u8; 2];
    tmp.copy_from_slice(&buf[*cursor..*cursor + 2]);
    *cursor += 2;
    Ok(u16::from_be_bytes(tmp))
}

fn read_u32(buf: &[u8], cursor: &mut usize) -> Result<u32> {
    if *cursor + 4 > buf.len() {
        return Err(Error::Length);
    }
    let mut tmp = [0u8; 4];
    tmp.copy_from_slice(&buf[*cursor..*cursor + 4]);
    *cursor += 4;
    Ok(u32::from_be_bytes(tmp))
}

fn read_fixed<const N: usize>(buf: &[u8], cursor: &mut usize) -> Result<[u8; N]> {
    if *cursor + N > buf.len() {
        return Err(Error::Length);
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&buf[*cursor..*cursor + N]);
    *cursor += N;
    Ok(out)
}

fn read_bytes(buf: &[u8], cursor: &mut usize, len: usize) -> Result<Vec<u8>> {
    if *cursor + len > buf.len() {
        return Err(Error::Length);
    }
    let out = buf[*cursor..*cursor + len].to_vec();
    *cursor += len;
    Ok(out)
}

struct Tape {
    seed: [u8; SEED_LEN],
    block: [u8; 32],
    bit_pos: usize,
    counter: u64,
}

impl Tape {
    fn new(seed: [u8; SEED_LEN]) -> Self {
        Self {
            seed,
            block: [0u8; 32],
            bit_pos: 256,
            counter: 0,
        }
    }

    fn next_bit(&mut self) -> u8 {
        if self.bit_pos >= 256 {
            self.refill();
        }
        let byte = self.block[self.bit_pos / 8];
        let bit = (byte >> (self.bit_pos % 8)) & 1;
        self.bit_pos += 1;
        bit
    }

    fn skip_bits(&mut self, mut count: usize) {
        while count > 0 {
            let remaining = 256 - self.bit_pos;
            if remaining == 0 {
                self.refill();
                continue;
            }
            let step = core::cmp::min(count, remaining);
            self.bit_pos += step;
            count -= step;
        }
    }

    fn refill(&mut self) {
        let mut hasher = AsconHash256::new();
        hasher.update(TAPE_DOMAIN);
        hasher.update(&self.seed);
        hasher.update(&self.counter.to_be_bytes());
        self.block = hasher.finalize();
        self.bit_pos = 0;
        self.counter = self.counter.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::{Proof, ProverConfig, VerifierConfig, ZkBooEngine};
    use crate::crypto::zkp::circuit::Circuit;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn prove_and_verify_single_and() {
        let mut circuit = Circuit::new(2);
        let w = circuit.add_and(0, 1);
        circuit.set_outputs(&[w]);
        let input = [1u8, 1u8];
        let output = [1u8];
        let cfg = ProverConfig { rounds: 8 };
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let engine = ZkBooEngine;
        let proof = engine
            .prove_circuit_with_rng(&circuit, &input, &output, cfg, &mut rng)
            .expect("prove");
        engine
            .verify_circuit(&circuit, &output, &proof, VerifierConfig { rounds: 8 })
            .expect("verify");
    }

    #[test]
    fn verify_rejects_wrong_output() {
        let mut circuit = Circuit::new(2);
        let w = circuit.add_xor(0, 1);
        circuit.set_outputs(&[w]);
        let input = [1u8, 0u8];
        let output = [1u8];
        let cfg = ProverConfig { rounds: 6 };
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let engine = ZkBooEngine;
        let proof = engine
            .prove_circuit_with_rng(&circuit, &input, &output, cfg, &mut rng)
            .expect("prove");
        let bad_output = [0u8];
        let res = engine.verify_circuit(
            &circuit,
            &bad_output,
            &proof,
            VerifierConfig { rounds: 6 },
        );
        assert!(res.is_err());
    }

    #[test]
    fn proof_roundtrip_encode_decode() {
        let mut circuit = Circuit::new(3);
        let w0 = circuit.add_xor(0, 1);
        let w1 = circuit.add_and(w0, 2);
        circuit.set_outputs(&[w1]);
        let input = [1u8, 1u8, 1u8];
        let output = [0u8];
        let cfg = ProverConfig { rounds: 4 };
        let mut rng = ChaCha20Rng::seed_from_u64(9);
        let engine = ZkBooEngine;
        let proof = engine
            .prove_circuit_with_rng(&circuit, &input, &output, cfg, &mut rng)
            .expect("prove");
        let encoded = proof.encode().expect("encode");
        let (decoded, consumed) = Proof::decode(&encoded).expect("decode");
        assert_eq!(consumed, encoded.len());
        engine
            .verify_circuit(&circuit, &output, &decoded, VerifierConfig { rounds: 4 })
            .expect("verify");
    }
}
