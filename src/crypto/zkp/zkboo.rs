use alloc::vec;
use alloc::vec::Vec;

use crate::core::policy::{ProofKind, ProofPart};
use crate::crypto::ascon::AsconHash256;
use crate::crypto::zkp::circuit::{Circuit, Gate};
use crate::crypto::zkp::merkle::MerkleTree;
use crate::types::Error;
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;

const SEED_LEN: usize = 32;
const TAPE_DOMAIN: &[u8] = b"TAPE";
const COMMIT_DOMAIN: &[u8] = b"VIEW";
const CHAL_DOMAIN: &[u8] = b"CHAL";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    pub rounds: u16,
    pub commit_root: [u8; 32],
    pub openings: Vec<RoundOpening>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalizedProof {
    rounds: u16,
    commit_root: [u8; 32],
    shape: ProofShape,
    openings: Vec<NormalizedRoundOpening>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProofShape {
    rounds: usize,
    wire_count: usize,
    merkle_depth: usize,
}

impl ProofShape {
    fn new(circuit: &Circuit, rounds: u16) -> Self {
        let rounds = rounds as usize;
        Self {
            rounds,
            wire_count: circuit.wire_count(),
            merkle_depth: MerkleTree::depth_for_leaves(rounds.saturating_mul(3)),
        }
    }
}

impl Proof {
    pub fn encoded_len(&self) -> core::result::Result<usize, Error> {
        if self.openings.len() != self.rounds as usize {
            return Err(Error::Length);
        }
        let mut total = 0usize;
        add_len(&mut total, 2 + 1 + 1 + 32)?;
        for opening in &self.openings {
            add_len(&mut total, 2 * SEED_LEN)?;
            add_len(&mut total, fixed_view_len(&opening.view_e)?)?;
            add_len(&mut total, fixed_view_len(&opening.view_e1)?)?;
        }
        Ok(total)
    }

    pub fn encode(&self) -> core::result::Result<Vec<u8>, Error> {
        let len = self.encoded_len()?;
        let mut out = Vec::with_capacity(len);
        encode_u16(&mut out, self.rounds);
        out.push(0);
        out.push(0);
        out.extend_from_slice(&self.commit_root);
        for opening in &self.openings {
            out.extend_from_slice(&opening.seed_e);
            out.extend_from_slice(&opening.seed_e1);
            encode_view_fixed(&mut out, &opening.view_e)?;
            encode_view_fixed(&mut out, &opening.view_e1)?;
        }
        Ok(out)
    }

    pub fn to_part(&self, kind: ProofKind) -> core::result::Result<ProofPart, Error> {
        let encoded = self.encode()?;
        Ok(ProofPart {
            kind,
            proof: encoded,
            commitment: self.commit_root,
            aux: Vec::new(),
        })
    }

    pub fn normalize(
        &self,
        circuit: &Circuit,
        cfg: VerifierConfig,
    ) -> core::result::Result<NormalizedProof, Error> {
        let shape = ProofShape::new(circuit, cfg.rounds);
        if self.rounds != cfg.rounds || self.openings.len() != shape.rounds {
            return Err(Error::Length);
        }
        let mut openings = Vec::with_capacity(shape.rounds);
        for opening in &self.openings {
            openings.push(NormalizedRoundOpening {
                seed_e: opening.seed_e,
                seed_e1: opening.seed_e1,
                view_e: normalize_view(&opening.view_e, shape.wire_count, shape.merkle_depth)?,
                view_e1: normalize_view(&opening.view_e1, shape.wire_count, shape.merkle_depth)?,
            });
        }
        Ok(NormalizedProof {
            rounds: self.rounds,
            commit_root: self.commit_root,
            shape,
            openings,
        })
    }
}

impl NormalizedProof {
    pub fn rounds(&self) -> u16 {
        self.rounds
    }

    pub fn decode_with_circuit(
        circuit: &Circuit,
        buf: &[u8],
    ) -> core::result::Result<(Self, usize), Error> {
        let mut cursor = 0usize;
        let rounds = read_u16(buf, &mut cursor)?;
        let _version = read_u8(buf, &mut cursor)?;
        let _flags = read_u8(buf, &mut cursor)?;
        let commit_root = read_fixed(buf, &mut cursor)?;
        let shape = ProofShape::new(circuit, rounds);
        let mut openings = Vec::with_capacity(shape.rounds);
        for _ in 0..shape.rounds {
            let seed_e = read_fixed(buf, &mut cursor)?;
            let seed_e1 = read_fixed(buf, &mut cursor)?;
            let view_e = decode_view_fixed(buf, &mut cursor, shape.wire_count, shape.merkle_depth)?;
            let view_e1 =
                decode_view_fixed(buf, &mut cursor, shape.wire_count, shape.merkle_depth)?;
            openings.push(NormalizedRoundOpening {
                seed_e,
                seed_e1,
                view_e,
                view_e1,
            });
        }
        Ok((
            Self {
                rounds,
                commit_root,
                shape,
                openings,
            },
            cursor,
        ))
    }

    pub fn from_part(part: &ProofPart, circuit: &Circuit) -> core::result::Result<Self, Error> {
        let (proof, consumed) = Self::decode_with_circuit(circuit, &part.proof)?;
        if consumed != part.proof.len() {
            return Err(Error::Length);
        }
        if proof.commit_root != part.commitment {
            return Err(Error::Crypto);
        }
        Ok(proof)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoundOpening {
    pub seed_e: [u8; SEED_LEN],
    pub seed_e1: [u8; SEED_LEN],
    pub view_e: ViewOpening,
    pub view_e1: ViewOpening,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ViewOpening {
    pub wires: Vec<u8>,
    pub merkle_path: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NormalizedRoundOpening {
    seed_e: [u8; SEED_LEN],
    seed_e1: [u8; SEED_LEN],
    view_e: NormalizedViewOpening,
    view_e1: NormalizedViewOpening,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NormalizedViewOpening {
    wires: Vec<u8>,
    merkle_path: Vec<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProverConfig {
    pub rounds: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifierConfig {
    pub rounds: u16,
}

pub struct Engine;

impl Engine {
    pub fn prove<R: RngCore + CryptoRng>(
        &self,
        circuit: &Circuit,
        input_bits: &[u8],
        public_output: &[u8],
        cfg: ProverConfig,
        rng: &mut R,
    ) -> core::result::Result<Proof, Error> {
        if input_bits.len() != circuit.n_inputs || public_output.len() != circuit.outputs.len() {
            return Err(Error::Length);
        }
        let rounds = cfg.rounds as usize;
        let mut round_states = Vec::with_capacity(rounds);
        let mut commitments = Vec::with_capacity(rounds * 3);

        for _round in 0..rounds {
            let mut seeds = [[0u8; SEED_LEN]; 3];
            for seed in &mut seeds {
                rng.fill_bytes(seed);
            }
            let state = simulate_round(circuit, input_bits, public_output, seeds)?;
            commitments.extend_from_slice(&state.commitments);
            round_states.push(state);
        }

        let merkle = MerkleTree::build(&commitments);
        let root = merkle.root();

        let mut openings = Vec::with_capacity(rounds);
        for round in 0..rounds {
            let e = derive_challenge(public_output, root, round);
            let e1 = (e + 1) % 3;
            let state = &round_states[round];
            let view_e = &state.views[e as usize];
            let view_e1 = &state.views[e1 as usize];
            let leaf_e = round * 3 + e as usize;
            let leaf_e1 = round * 3 + e1 as usize;
            openings.push(RoundOpening {
                seed_e: state.seeds[e as usize],
                seed_e1: state.seeds[e1 as usize],
                view_e: ViewOpening {
                    wires: view_e.clone(),
                    merkle_path: merkle.open(leaf_e),
                },
                view_e1: ViewOpening {
                    wires: view_e1.clone(),
                    merkle_path: merkle.open(leaf_e1),
                },
            });
        }

        Ok(Proof {
            rounds: cfg.rounds,
            commit_root: root,
            openings,
        })
    }

    pub fn verify(
        &self,
        circuit: &Circuit,
        public_output: &[u8],
        proof: &NormalizedProof,
        cfg: VerifierConfig,
    ) -> core::result::Result<(), Error> {
        if public_output.len() != circuit.outputs.len() {
            return Err(Error::Length);
        }
        let shape = ProofShape::new(circuit, cfg.rounds);
        if proof.rounds != cfg.rounds || proof.shape != shape {
            return Err(Error::Length);
        }
        let mut branch_calc = vec![0u8; shape.wire_count];
        let mut crypto_bad = 0u8;

        for round in 0..shape.rounds {
            let expected_e = derive_challenge(public_output, proof.commit_root, round);
            let opening = &proof.openings[round];
            let e = expected_e as usize;
            let e1 = (e + 1) % 3;

            let com_e = commit_view(&opening.seed_e, &opening.view_e.wires);
            let com_e1 = commit_view(&opening.seed_e1, &opening.view_e1.wires);
            let leaf_e = round * 3 + e;
            let leaf_e1 = round * 3 + e1;
            crypto_bad |= u8::from(!MerkleTree::verify(
                proof.commit_root,
                com_e,
                leaf_e,
                &opening.view_e.merkle_path,
            ));
            crypto_bad |= u8::from(!MerkleTree::verify(
                proof.commit_root,
                com_e1,
                leaf_e1,
                &opening.view_e1.merkle_path,
            ));
            for (idx, &bit) in public_output.iter().enumerate() {
                let wire = circuit.outputs[idx];
                crypto_bad |= u8::from((opening.view_e.wires[wire] & !1) != 0);
                crypto_bad |= u8::from((opening.view_e1.wires[wire] & !1) != 0);
                let _recombined =
                    (opening.view_e.wires[wire] ^ opening.view_e1.wires[wire] ^ bit) & 1;
            }

            crypto_bad |= u8::from(!check_branch_constant_work(
                circuit,
                e,
                &opening.view_e.wires,
                &opening.view_e1.wires,
                &opening.seed_e,
                &opening.seed_e1,
                &mut branch_calc,
            ));
        }

        if crypto_bad != 0 {
            Err(Error::Crypto)
        } else {
            Ok(())
        }
    }
}

struct RoundState {
    seeds: [[u8; SEED_LEN]; 3],
    views: [Vec<u8>; 3],
    commitments: [[u8; 32]; 3],
}

fn simulate_round(
    circuit: &Circuit,
    input_bits: &[u8],
    public_output: &[u8],
    seeds: [[u8; SEED_LEN]; 3],
) -> core::result::Result<RoundState, Error> {
    let n_wires = circuit.wire_count();
    let mut views = [vec![0u8; n_wires], vec![0u8; n_wires], vec![0u8; n_wires]];
    let mut tapes = [
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

    for (idx, &bit) in public_output.iter().enumerate() {
        let wire = circuit.outputs[idx];
        if wire >= n_wires {
            return Err(Error::Length);
        }
        let recombined = (views[0][wire] ^ views[1][wire] ^ views[2][wire]) & 1;
        if recombined != (bit & 1) {
            return Err(Error::Crypto);
        }
    }

    let mut commitments = [[0u8; 32]; 3];
    for i in 0..3 {
        commitments[i] = commit_view(&seeds[i], &views[i]);
    }

    Ok(RoundState {
        seeds,
        views,
        commitments,
    })
}

fn check_branch_constant_work(
    circuit: &Circuit,
    branch: usize,
    view_i: &[u8],
    view_i1: &[u8],
    seed_i: &[u8; SEED_LEN],
    seed_i1: &[u8; SEED_LEN],
    calc: &mut [u8],
) -> bool {
    let mut tape_i = Tape::new(*seed_i);
    let mut tape_i1 = Tape::new(*seed_i1);
    tape_i.skip_bits(circuit.n_inputs);
    tape_i1.skip_bits(circuit.n_inputs);

    calc[..circuit.n_inputs].copy_from_slice(&view_i[..circuit.n_inputs]);
    let mut ok = true;
    let branch_is_zero = (branch as u8).ct_eq(&0).unwrap_u8();

    for (g_idx, gate) in circuit.gates.iter().enumerate() {
        let out = circuit.n_inputs + g_idx;
        let expected = match *gate {
            Gate::Xor { a, b } => calc[a] ^ calc[b],
            Gate::Not { a } => calc[a] ^ branch_is_zero,
            Gate::And { a, b } => {
                let r_i = tape_i.next_bit();
                let r_i1 = tape_i1.next_bit();
                (calc[a] & calc[b]) ^ (view_i1[a] & calc[b]) ^ (calc[a] & view_i1[b]) ^ r_i ^ r_i1
            }
        };
        ok &= (view_i[out] & 1) == (expected & 1);
        calc[out] = expected & 1;
    }

    ok
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

fn fixed_view_len(view: &ViewOpening) -> core::result::Result<usize, Error> {
    if view.merkle_path.len() > u16::MAX as usize {
        return Err(Error::Length);
    }
    let mut total = 0usize;
    add_len(&mut total, view.wires.len())?;
    add_len(&mut total, view.merkle_path.len() * 32)?;
    Ok(total)
}

fn encode_view_fixed(out: &mut Vec<u8>, view: &ViewOpening) -> core::result::Result<(), Error> {
    out.extend_from_slice(&view.wires);
    for node in &view.merkle_path {
        out.extend_from_slice(node);
    }
    Ok(())
}

fn decode_view_fixed(
    buf: &[u8],
    cursor: &mut usize,
    wire_count: usize,
    merkle_depth: usize,
) -> core::result::Result<NormalizedViewOpening, Error> {
    let wires = read_bytes(buf, cursor, wire_count)?;
    let mut merkle_path = Vec::with_capacity(merkle_depth);
    for _ in 0..merkle_depth {
        let node = read_fixed(buf, cursor)?;
        merkle_path.push(node);
    }
    Ok(NormalizedViewOpening { wires, merkle_path })
}

fn normalize_view(
    view: &ViewOpening,
    wire_count: usize,
    merkle_depth: usize,
) -> core::result::Result<NormalizedViewOpening, Error> {
    if view.wires.len() != wire_count || view.merkle_path.len() != merkle_depth {
        return Err(Error::Length);
    }
    Ok(NormalizedViewOpening {
        wires: view.wires.clone(),
        merkle_path: view.merkle_path.clone(),
    })
}

fn add_len(total: &mut usize, add: usize) -> core::result::Result<(), Error> {
    *total = total.checked_add(add).ok_or(Error::Length)?;
    Ok(())
}

fn encode_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn read_u8(buf: &[u8], cursor: &mut usize) -> core::result::Result<u8, Error> {
    if *cursor + 1 > buf.len() {
        return Err(Error::Length);
    }
    let val = buf[*cursor];
    *cursor += 1;
    Ok(val)
}

fn read_u16(buf: &[u8], cursor: &mut usize) -> core::result::Result<u16, Error> {
    if *cursor + 2 > buf.len() {
        return Err(Error::Length);
    }
    let mut tmp = [0u8; 2];
    tmp.copy_from_slice(&buf[*cursor..*cursor + 2]);
    *cursor += 2;
    Ok(u16::from_be_bytes(tmp))
}

fn read_fixed<const N: usize>(
    buf: &[u8],
    cursor: &mut usize,
) -> core::result::Result<[u8; N], Error> {
    if *cursor + N > buf.len() {
        return Err(Error::Length);
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&buf[*cursor..*cursor + N]);
    *cursor += N;
    Ok(out)
}

fn read_bytes(buf: &[u8], cursor: &mut usize, len: usize) -> core::result::Result<Vec<u8>, Error> {
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
    use super::{Engine, NormalizedProof, ProverConfig, VerifierConfig};
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
        let engine = Engine;
        let proof = engine
            .prove(&circuit, &input, &output, cfg, &mut rng)
            .expect("prove");
        let normalized = proof
            .normalize(&circuit, VerifierConfig { rounds: 8 })
            .expect("normalize");
        engine
            .verify(&circuit, &output, &normalized, VerifierConfig { rounds: 8 })
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
        let engine = Engine;
        let proof = engine
            .prove(&circuit, &input, &output, cfg, &mut rng)
            .expect("prove");
        let bad_output = [0u8];
        let normalized = proof
            .normalize(&circuit, VerifierConfig { rounds: 6 })
            .expect("normalize");
        let res = engine.verify(
            &circuit,
            &bad_output,
            &normalized,
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
        let engine = Engine;
        let proof = engine
            .prove(&circuit, &input, &output, cfg, &mut rng)
            .expect("prove");
        let encoded = proof.encode().expect("encode");
        let (decoded, consumed) =
            NormalizedProof::decode_with_circuit(&circuit, &encoded).expect("decode");
        assert_eq!(consumed, encoded.len());
        engine
            .verify(&circuit, &output, &decoded, VerifierConfig { rounds: 4 })
            .expect("verify");
    }

    #[test]
    fn proof_roundtrip_part_encoding() {
        let mut circuit = Circuit::new(2);
        let w = circuit.add_and(0, 1);
        circuit.set_outputs(&[w]);
        let input = [1u8, 0u8];
        let output = [0u8];
        let cfg = ProverConfig { rounds: 5 };
        let mut rng = ChaCha20Rng::seed_from_u64(11);
        let engine = Engine;
        let proof = engine
            .prove(&circuit, &input, &output, cfg, &mut rng)
            .expect("prove");
        let part = proof
            .to_part(crate::core::policy::ProofKind::Policy)
            .expect("to part");
        let decoded = NormalizedProof::from_part(&part, &circuit).expect("from part");
        engine
            .verify(&circuit, &output, &decoded, VerifierConfig { rounds: 5 })
            .expect("verify");
    }

    #[test]
    fn verify_rejects_malformed_shape_without_panicking() {
        let mut circuit = Circuit::new(2);
        let w = circuit.add_and(0, 1);
        circuit.set_outputs(&[w]);
        let input = [1u8, 1u8];
        let output = [1u8];
        let cfg = ProverConfig { rounds: 4 };
        let mut rng = ChaCha20Rng::seed_from_u64(99);
        let engine = Engine;
        let mut proof = engine
            .prove(&circuit, &input, &output, cfg, &mut rng)
            .expect("prove");
        proof.openings[1].view_e.wires.pop();

        let res = proof.normalize(&circuit, VerifierConfig { rounds: 4 });
        assert!(matches!(res, Err(crate::types::Error::Length)));
    }
}
