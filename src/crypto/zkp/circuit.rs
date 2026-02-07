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
