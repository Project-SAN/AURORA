use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use crate::types::{Error, Result};

pub type WireId = usize;

const CIRCUIT_MAGIC: &[u8; 4] = b"ZKBC";
const CIRCUIT_VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    Xor { a: WireId, b: WireId },
    And { a: WireId, b: WireId },
    Not { a: WireId },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum GateKey {
    Xor(WireId, WireId),
    And(WireId, WireId),
    Not(WireId),
}

#[derive(Clone, Debug)]
pub struct Circuit {
    pub n_inputs: usize,
    pub gates: Vec<Gate>,
    pub outputs: Vec<WireId>,
}

impl Circuit {
    pub fn new(n_inputs: usize) -> Self {
        Self {
            n_inputs,
            gates: Vec::new(),
            outputs: Vec::new(),
        }
    }

    pub fn add_gate(&mut self, gate: Gate) -> WireId {
        let id = self.n_inputs + self.gates.len();
        self.gates.push(gate);
        id
    }

    pub fn add_xor(&mut self, a: WireId, b: WireId) -> WireId {
        self.add_gate(Gate::Xor { a, b })
    }

    pub fn add_and(&mut self, a: WireId, b: WireId) -> WireId {
        self.add_gate(Gate::And { a, b })
    }

    pub fn add_not(&mut self, a: WireId) -> WireId {
        self.add_gate(Gate::Not { a })
    }

    pub fn set_outputs(&mut self, outputs: &[WireId]) {
        self.outputs.clear();
        self.outputs.extend_from_slice(outputs);
    }

    pub fn wire_count(&self) -> usize {
        self.n_inputs + self.gates.len()
    }

    pub fn optimized(&self) -> Self {
        let Some(live_wires) = self.live_wires() else {
            // Keep malformed circuits untouched.
            return self.clone();
        };

        let mut optimizer = CircuitOptimizer::new(self.n_inputs);
        let mut wire_map = vec![None; self.wire_count()];
        for input in 0..self.n_inputs {
            wire_map[input] = Some(input);
        }

        for (g_idx, gate) in self.gates.iter().enumerate() {
            let old_out = self.n_inputs + g_idx;
            if !live_wires[old_out] {
                continue;
            }
            let mapped = match *gate {
                Gate::Xor { a, b } => {
                    let Some(a_mapped) = wire_map[a] else {
                        return self.clone();
                    };
                    let Some(b_mapped) = wire_map[b] else {
                        return self.clone();
                    };
                    optimizer.intern_xor(a_mapped, b_mapped)
                }
                Gate::And { a, b } => {
                    let Some(a_mapped) = wire_map[a] else {
                        return self.clone();
                    };
                    let Some(b_mapped) = wire_map[b] else {
                        return self.clone();
                    };
                    optimizer.intern_and(a_mapped, b_mapped)
                }
                Gate::Not { a } => {
                    let Some(a_mapped) = wire_map[a] else {
                        return self.clone();
                    };
                    optimizer.intern_not(a_mapped)
                }
            };
            wire_map[old_out] = Some(mapped);
        }

        let mut outputs = Vec::with_capacity(self.outputs.len());
        for &wire in &self.outputs {
            let Some(mapped) = wire_map[wire] else {
                return self.clone();
            };
            outputs.push(mapped);
        }
        optimizer.finish(outputs)
    }

    pub fn eval(&self, inputs: &[u8]) -> Result<Vec<u8>> {
        if inputs.len() != self.n_inputs {
            return Err(Error::Length);
        }
        let mut wires = vec![0u8; self.wire_count()];
        for (idx, &bit) in inputs.iter().enumerate() {
            wires[idx] = bit & 1;
        }
        for (g_idx, gate) in self.gates.iter().enumerate() {
            let out = self.n_inputs + g_idx;
            let val = match *gate {
                Gate::Xor { a, b } => wires[a] ^ wires[b],
                Gate::And { a, b } => (wires[a] & wires[b]) & 1,
                Gate::Not { a } => wires[a] ^ 1,
            };
            wires[out] = val & 1;
        }
        if self.outputs.is_empty() {
            return Ok(Vec::new());
        }
        let mut out = Vec::with_capacity(self.outputs.len());
        for &wire in &self.outputs {
            if wire >= wires.len() {
                return Err(Error::Length);
            }
            out.push(wires[wire] & 1);
        }
        Ok(out)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(CIRCUIT_MAGIC);
        out.push(CIRCUIT_VERSION);
        out.extend_from_slice(&(self.n_inputs as u32).to_be_bytes());
        out.extend_from_slice(&(self.gates.len() as u32).to_be_bytes());
        out.extend_from_slice(&(self.outputs.len() as u32).to_be_bytes());
        for gate in &self.gates {
            match *gate {
                Gate::Xor { a, b } => {
                    out.push(0);
                    out.extend_from_slice(&(a as u32).to_be_bytes());
                    out.extend_from_slice(&(b as u32).to_be_bytes());
                }
                Gate::And { a, b } => {
                    out.push(1);
                    out.extend_from_slice(&(a as u32).to_be_bytes());
                    out.extend_from_slice(&(b as u32).to_be_bytes());
                }
                Gate::Not { a } => {
                    out.push(2);
                    out.extend_from_slice(&(a as u32).to_be_bytes());
                    out.extend_from_slice(&0u32.to_be_bytes());
                }
            }
        }
        for &wire in &self.outputs {
            out.extend_from_slice(&(wire as u32).to_be_bytes());
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut cursor = 0usize;
        if bytes.len() < 5 {
            return Err(Error::Length);
        }
        if &bytes[..4] != CIRCUIT_MAGIC {
            return Err(Error::Length);
        }
        cursor += 4;
        let version = bytes[cursor];
        cursor += 1;
        if version != CIRCUIT_VERSION {
            return Err(Error::Length);
        }
        let n_inputs = read_u32(bytes, &mut cursor)? as usize;
        let gate_count = read_u32(bytes, &mut cursor)? as usize;
        let output_count = read_u32(bytes, &mut cursor)? as usize;
        let mut gates = Vec::with_capacity(gate_count);
        for g_idx in 0..gate_count {
            if cursor + 9 > bytes.len() {
                return Err(Error::Length);
            }
            let op = bytes[cursor];
            cursor += 1;
            let a = read_u32(bytes, &mut cursor)? as usize;
            let b = read_u32(bytes, &mut cursor)? as usize;
            let max_wire = n_inputs + g_idx;
            if a > max_wire || b > max_wire {
                return Err(Error::Length);
            }
            let gate = match op {
                0 => Gate::Xor { a, b },
                1 => Gate::And { a, b },
                2 => Gate::Not { a },
                _ => return Err(Error::Length),
            };
            gates.push(gate);
        }
        let mut outputs = Vec::with_capacity(output_count);
        let wire_count = n_inputs + gates.len();
        for _ in 0..output_count {
            let wire = read_u32(bytes, &mut cursor)? as usize;
            if wire >= wire_count {
                return Err(Error::Length);
            }
            outputs.push(wire);
        }
        Ok(Circuit {
            n_inputs,
            gates,
            outputs,
        })
    }

    fn live_wires(&self) -> Option<Vec<bool>> {
        let wire_count = self.wire_count();
        let mut live = vec![false; wire_count];
        let mut stack = Vec::with_capacity(self.outputs.len());

        for &wire in &self.outputs {
            if wire >= wire_count {
                return None;
            }
            if !live[wire] {
                live[wire] = true;
                stack.push(wire);
            }
        }

        while let Some(wire) = stack.pop() {
            if wire < self.n_inputs {
                continue;
            }
            let g_idx = wire - self.n_inputs;
            if g_idx >= self.gates.len() {
                return None;
            }
            match self.gates[g_idx] {
                Gate::Xor { a, b } | Gate::And { a, b } => {
                    if a >= wire || b >= wire || a >= wire_count || b >= wire_count {
                        return None;
                    }
                    if !live[a] {
                        live[a] = true;
                        stack.push(a);
                    }
                    if !live[b] {
                        live[b] = true;
                        stack.push(b);
                    }
                }
                Gate::Not { a } => {
                    if a >= wire || a >= wire_count {
                        return None;
                    }
                    if !live[a] {
                        live[a] = true;
                        stack.push(a);
                    }
                }
            }
        }

        Some(live)
    }
}

struct CircuitOptimizer {
    circuit: Circuit,
    known_consts: Vec<Option<u8>>,
    cache: BTreeMap<GateKey, WireId>,
    not_parent: BTreeMap<WireId, WireId>,
    zero_wire: Option<WireId>,
    one_wire: Option<WireId>,
}

impl CircuitOptimizer {
    fn new(n_inputs: usize) -> Self {
        Self {
            circuit: Circuit::new(n_inputs),
            known_consts: vec![None; n_inputs],
            cache: BTreeMap::new(),
            not_parent: BTreeMap::new(),
            zero_wire: None,
            one_wire: None,
        }
    }

    fn finish(mut self, outputs: Vec<WireId>) -> Circuit {
        self.circuit.set_outputs(&outputs);
        self.circuit
    }

    fn const_value(&self, wire: WireId) -> Option<u8> {
        self.known_consts.get(wire).copied().flatten()
    }

    fn set_const(&mut self, wire: WireId, value: u8) {
        if wire >= self.known_consts.len() {
            return;
        }
        let bit = value & 1;
        self.known_consts[wire] = Some(bit);
        if bit == 0 && self.zero_wire.is_none() {
            self.zero_wire = Some(wire);
        }
        if bit == 1 && self.one_wire.is_none() {
            self.one_wire = Some(wire);
        }
    }

    fn push_gate(&mut self, gate: Gate) -> WireId {
        let out = self.circuit.n_inputs + self.circuit.gates.len();
        self.circuit.gates.push(gate);
        self.known_consts.push(None);
        out
    }

    fn const_wire(&mut self, value: u8) -> Option<WireId> {
        if (value & 1) == 0 {
            self.ensure_zero_wire()
        } else {
            self.ensure_one_wire()
        }
    }

    fn ensure_zero_wire(&mut self) -> Option<WireId> {
        if let Some(z) = self.zero_wire {
            return Some(z);
        }
        if self.circuit.wire_count() == 0 {
            return None;
        }
        let key = GateKey::Xor(0, 0);
        if let Some(&wire) = self.cache.get(&key) {
            self.zero_wire = Some(wire);
            return Some(wire);
        }
        let wire = self.push_gate(Gate::Xor { a: 0, b: 0 });
        self.cache.insert(key, wire);
        self.set_const(wire, 0);
        Some(wire)
    }

    fn ensure_one_wire(&mut self) -> Option<WireId> {
        if let Some(one) = self.one_wire {
            return Some(one);
        }
        let zero = self.ensure_zero_wire()?;
        let key = GateKey::Not(zero);
        if let Some(&wire) = self.cache.get(&key) {
            self.one_wire = Some(wire);
            return Some(wire);
        }
        let wire = self.push_gate(Gate::Not { a: zero });
        self.cache.insert(key, wire);
        self.not_parent.insert(wire, zero);
        self.set_const(wire, 1);
        Some(wire)
    }

    fn intern_xor(&mut self, a: WireId, b: WireId) -> WireId {
        if a == b {
            if let Some(zero) = self.const_wire(0) {
                return zero;
            }
        }

        let a_const = self.const_value(a);
        let b_const = self.const_value(b);
        match (a_const, b_const) {
            (Some(0), _) => return b,
            (_, Some(0)) => return a,
            (Some(1), _) => return self.intern_not(b),
            (_, Some(1)) => return self.intern_not(a),
            _ => {}
        }

        let (x, y) = ordered_pair(a, b);
        let key = GateKey::Xor(x, y);
        if let Some(&wire) = self.cache.get(&key) {
            return wire;
        }
        let wire = self.push_gate(Gate::Xor { a: x, b: y });
        self.cache.insert(key, wire);
        if let (Some(av), Some(bv)) = (a_const, b_const) {
            self.set_const(wire, av ^ bv);
        }
        wire
    }

    fn intern_and(&mut self, a: WireId, b: WireId) -> WireId {
        if a == b {
            return a;
        }

        let a_const = self.const_value(a);
        let b_const = self.const_value(b);
        match (a_const, b_const) {
            (Some(0), _) | (_, Some(0)) => {
                if let Some(zero) = self.const_wire(0) {
                    return zero;
                }
            }
            (Some(1), _) => return b,
            (_, Some(1)) => return a,
            _ => {}
        }

        let (x, y) = ordered_pair(a, b);
        let key = GateKey::And(x, y);
        if let Some(&wire) = self.cache.get(&key) {
            return wire;
        }
        let wire = self.push_gate(Gate::And { a: x, b: y });
        self.cache.insert(key, wire);
        if let (Some(av), Some(bv)) = (a_const, b_const) {
            self.set_const(wire, av & bv);
        }
        wire
    }

    fn intern_not(&mut self, a: WireId) -> WireId {
        if let Some(&wire) = self.cache.get(&GateKey::Not(a)) {
            return wire;
        }
        if let Some(&parent) = self.not_parent.get(&a) {
            return parent;
        }
        if let Some(bit) = self.const_value(a) {
            if let Some(wire) = self.const_wire(bit ^ 1) {
                return wire;
            }
        }

        let wire = self.push_gate(Gate::Not { a });
        self.cache.insert(GateKey::Not(a), wire);
        self.not_parent.insert(wire, a);
        if let Some(bit) = self.const_value(a) {
            self.set_const(wire, bit ^ 1);
        }
        wire
    }
}

fn ordered_pair(a: WireId, b: WireId) -> (WireId, WireId) {
    if a <= b {
        (a, b)
    } else {
        (b, a)
    }
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

#[cfg(test)]
mod tests {
    use super::Circuit;

    #[test]
    fn optimize_preserves_eval_and_reduces_redundant_work() {
        let mut circuit = Circuit::new(2);
        let zero = circuit.add_xor(0, 0);
        let one = circuit.add_not(zero);
        let x = circuit.add_xor(0, zero);
        let y = circuit.add_xor(one, 1);
        let out = circuit.add_and(x, y);

        // dead subgraph
        let dead0 = circuit.add_xor(0, 1);
        let _dead1 = circuit.add_and(dead0, one);

        circuit.set_outputs(&[out]);

        let optimized = circuit.optimized();
        assert!(optimized.gates.len() < circuit.gates.len());

        let cases = [[0u8, 0u8], [0u8, 1u8], [1u8, 0u8], [1u8, 1u8]];
        for input in &cases {
            let lhs = circuit.eval(input).expect("eval original");
            let rhs = optimized.eval(input).expect("eval optimized");
            assert_eq!(lhs, rhs);
        }
    }
}
