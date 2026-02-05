use alloc::vec;
use alloc::vec::Vec;

use crate::types::{Error, Result};

pub type WireId = usize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    Xor { a: WireId, b: WireId },
    And { a: WireId, b: WireId },
    Not { a: WireId },
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
}
