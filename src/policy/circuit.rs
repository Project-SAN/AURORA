use alloc::vec::Vec;

use ark_bls12_381::Fr;

use groth16::r1cs::gadgets::{
    decompose_to_bits_le,
    enforce_equal,
    enforce_prefix_match,
    enforce_value_in_range,
};
use groth16::r1cs::poseidon::{
    enforce_poseidon_merkle_path,
    poseidon_hash_two,
    poseidon_hash_sequence,
};
use groth16::r1cs::{ConstraintSystem, LinearCombination, Variable};

use crate::policy::manifest::PoseidonMerkleSibling;
use crate::policy::witness::{PAYLOAD_SLICE_LEN, ProofMaterial, TLS_HASH_LEN, WitnessInputs};

#[derive(Clone, Debug)]
pub struct CircuitWitness<'a> {
    pub material: &'a ProofMaterial,
    pub tau_bits: Vec<bool>,
    pub payload_bits: Vec<bool>,
    pub prefix_bits: Vec<bool>,
}

pub fn synthesize(cs: &mut ConstraintSystem<Fr>, witness: &CircuitWitness) {
    let w = &witness.material.witness;
    let public = &witness.material.public_inputs;

    // 公開入力を回路内変数として固定
    let public_vars = PublicVars::alloc(cs, public);

    // Witness 変数
    let tau_var = alloc_bytes(cs, &w.tau);
    let payload_var = alloc_bytes(cs, &w.payload_slice);
    let client_nonce_var = alloc_bytes(cs, &w.client_nonce);

    // Poseidon リーフ計算: rule_descriptor が witness と一致すること
    enforce_rule_descriptor(cs, &w.rule, public_vars.policy_id, w.descriptor, tau_var);

    // RID ハッシュを再計算
    enforce_rid(cs, &public_vars, client_nonce_var, w.rid);

    // c_payload, c_token, c_req ハッシュ整合
    enforce_commitments(
        cs,
        payload_var,
        client_nonce_var,
        tau_var,
        w.rid,
        w.c_req,
        &public_vars,
    );

    // プレフィックスマッチング
    enforce_prefix(cs, &witness.prefix_bits, &public_vars, w.rule.prefix_len as usize);

    // ポート範囲チェック
    enforce_port_range(cs, &public_vars, &w.rule);

    // Merkle パス検証
    enforce_merkle_path(cs, w, public_vars.h_policy);
}

struct PublicVars {
    policy_id: Fr,
    h_policy: Fr,
    dst_ip_bits: Vec<Variable>,
    dst_port: Variable,
    proto_id: Variable,
    epoch: Variable,
    hop_index: Variable,
    c_payload: Variable,
    c_token: Variable,
}

impl PublicVars {
    fn alloc(cs: &mut ConstraintSystem<Fr>, public: &crate::policy::witness::PublicInputs) -> Self {
        let policy_id = cs.alloc_input(Fr::from(public.policy_id as u64));
        let h_policy = cs.alloc_input(public.h_policy);
        let dst_ip_bits = bytes_to_bits(cs, &public.dst_ip);
        let dst_port = cs.alloc_input(Fr::from(public.dst_port as u64));
        let proto_id = cs.alloc_input(Fr::from(public.proto_id as u64));
        let epoch = cs.alloc_input(Fr::from(public.epoch as u64));
        let hop_index = cs.alloc_input(Fr::from(public.hop_index as u64));
        let c_payload = cs.alloc_input(public.c_payload);
        let c_token = cs.alloc_input(public.c_token);

        Self {
            policy_id: public.h_policy,
            h_policy: public.h_policy,
            dst_ip_bits,
            dst_port,
            proto_id,
            epoch,
            hop_index,
            c_payload,
            c_token,
        }
    }
}

fn alloc_bytes(cs: &mut ConstraintSystem<Fr>, bytes: &[u8]) -> Vec<Variable> {
    bytes.iter().map(|b| cs.alloc_aux(Fr::from(*b as u64))).collect()
}

fn bytes_to_bits(cs: &mut ConstraintSystem<Fr>, bytes: &[u8; 16]) -> Vec<Variable> {
    let mut bits = Vec::with_capacity(128);
    for byte in bytes {
        let value = Fr::from(*byte as u64);
        let var = cs.alloc_input(value);
        let decomposed = decompose_to_bits_le(cs, var, value, 8);
        bits.extend(decomposed);
    }
    bits
}

fn enforce_rule_descriptor(
    cs: &mut ConstraintSystem<Fr>,
    rule: &crate::policy::manifest::Rule,
    policy_id: Fr,
    descriptor: Fr,
    tau: Vec<Variable>,
) {
    let prefix = bytes_to_bits(cs, &rule.prefix);
    let prefix_len = rule.prefix_len as usize;
    let leaf = compute_rule_descriptor(cs, &prefix, prefix_len, rule);
    let descriptor_var = cs.alloc_aux(descriptor);
    enforce_equal(cs, leaf, descriptor_var); // descriptor 一致
}

fn compute_rule_descriptor(
    cs: &mut ConstraintSystem<Fr>,
    prefix_bits: &[Variable],
    prefix_len: usize,
    rule: &crate::policy::manifest::Rule,
) -> Variable {
    // rule descriptor は (prefix_len, prefix_bits(prefix_len分), port_start, port_end, proto_mask, classification_tag) をハッシュ
    let mut elems_vars: Vec<Variable> = Vec::new();
    let mut elems_vals: Vec<Fr> = Vec::new();
    let len_var = cs.alloc_aux(Fr::from(prefix_len as u64));
    elems_vars.push(len_var); elems_vals.push(Fr::from(prefix_len as u64));
    for i in 0..prefix_len {
        elems_vars.push(prefix_bits[i]);
        // prefix_bits[i] の値は公開入力ではないので 0/1 仮定; 値は witness 側で既知ではないため 0/1 variable の値は後で再計算できないが
        // ここでは制約内計算のみで使うため Fr::from( (prefix_bits[i] variable の割当値) ) を得るには一旦 0/1 仮定で ok
        // (ConstraintSystem 内部では値は格納されている想定)
        elems_vals.push(Fr::from(0u64)); // ダミー (後でCSの割当値と一致させたい場合は API 拡張が必要)
    }
    let port_start_fr = Fr::from(rule.port_start as u64);
    let port_end_fr = Fr::from(rule.port_end as u64);
    let proto_mask_fr = Fr::from(rule.proto_mask as u64);
    let class_tag_fr = Fr::from(rule.classification_tag as u64);
    let port_start_var = cs.alloc_aux(port_start_fr);
    let port_end_var = cs.alloc_aux(port_end_fr);
    let proto_mask_var = cs.alloc_aux(proto_mask_fr);
    let class_tag_var = cs.alloc_aux(class_tag_fr);
    elems_vars.extend([port_start_var, port_end_var, proto_mask_var, class_tag_var]);
    elems_vals.extend([port_start_fr, port_end_fr, proto_mask_fr, class_tag_fr]);

    let (hash_var, _hash_val) = poseidon_hash_sequence(cs, Fr::from(1000u64), &elems_vars, &elems_vals);
    hash_var
}

fn enforce_rid(
    cs: &mut ConstraintSystem<Fr>,
    public: &PublicVars,
    client_nonce: Vec<Variable>,
    rid: Fr,
) {
    // RID = H(label=1, dst_ip(128bits->1field), dst_port, proto_id, epoch, client_nonce[16])
    let mut elems_vars: Vec<Variable> = Vec::new();
    let mut elems_vals: Vec<Fr> = Vec::new();
    // dst_ip bits (128) を 16bytes -> 1 field ではなく bits 表現でそのまま: ここでは bytes->bits 既に public.dst_ip_bits (128)
    // 単純化のため 16 bytes を再 pack せず各 bit を直接吸収 (長くなるが簡易)。
    // ただし poseidon_hash_sequence は要素毎に field を吸収するため bit ごと field へ。
    // 公開IPビット値は 0/1 である前提。
    elems_vars.extend(public.dst_ip_bits.iter());
    elems_vals.extend(core::iter::repeat(Fr::from(0u64)).take(public.dst_ip_bits.len()));
    let dst_port_val = Fr::from(0u64); // dummy
    elems_vars.push(public.dst_port); elems_vals.push(dst_port_val);
    elems_vars.push(public.proto_id); elems_vals.push(Fr::from(0u64));
    elems_vars.push(public.epoch); elems_vals.push(Fr::from(0u64));
    // client_nonce
    for v in client_nonce {
        elems_vars.push(v);
        elems_vals.push(Fr::from(0u64));
    }
    let (calc_var, _calc_val) = poseidon_hash_sequence(cs, Fr::from(1u64), &elems_vars, &elems_vals);
    let rid_var = cs.alloc_aux(rid);
    enforce_equal(cs, calc_var, rid_var);
}

fn enforce_commitments(
    cs: &mut ConstraintSystem<Fr>,
    payload: Vec<Variable>,
    client_nonce: Vec<Variable>,
    tau: Vec<Variable>,
    rid: Fr,
    c_req: Fr,
    public: &PublicVars,
) {
    // c_payload = H(label=2, payload_slice(64), chdr_nonce? (ここでは client_nonce で代替), hop_index
    // 簡易: label と length を含め単純シーケンス
    let mut elems_vars: Vec<Variable> = Vec::new();
    let mut elems_vals: Vec<Fr> = Vec::new();
    for v in &payload { elems_vars.push(*v); elems_vals.push(Fr::from(0u64)); }
    for v in &client_nonce { elems_vars.push(*v); elems_vals.push(Fr::from(0u64)); }
    elems_vars.push(public.hop_index); elems_vals.push(Fr::from(0u64));
    let (c_payload_var, _c_payload_val) = poseidon_hash_sequence(cs, Fr::from(2u64), &elems_vars, &elems_vals);
    enforce_equal(cs, c_payload_var, public.c_payload);

    // c_token = H(label=3, tau[32])
    let mut tau_vals = vec![Fr::from(0u64); tau.len()];
    let (c_token_var, _c_token_val) = poseidon_hash_sequence(cs, Fr::from(3u64), &tau, &tau_vals);
    enforce_equal(cs, c_token_var, public.c_token);

    // c_req = H(label=4, rid, tls_hash?) 簡易: rid のみ（実際は tls transcript hash も含む想定）
    let rid_var = cs.alloc_aux(rid);
    let (c_req_calc_var, _v) = poseidon_hash_sequence(cs, Fr::from(4u64), &[rid_var], &[rid]);
    let c_req_var = cs.alloc_aux(c_req);
    enforce_equal(cs, c_req_calc_var, c_req_var);
}

fn enforce_prefix(
    cs: &mut ConstraintSystem<Fr>,
    prefix_bits: &[bool],
    public: &PublicVars,
    prefix_len: usize,
) {
    let prefix_vars: Vec<Variable> = prefix_bits
        .iter()
        .map(|bit| cs.alloc_aux(Fr::from(*bit as u64)))
        .collect();
    enforce_prefix_match(cs, &public.dst_ip_bits, &prefix_vars, prefix_len);
}

fn enforce_port_range(
    cs: &mut ConstraintSystem<Fr>,
    public: &PublicVars,
    rule: &crate::policy::manifest::Rule,
) {
    let min = cs.alloc_aux(Fr::from(rule.port_start as u64));
    let max = cs.alloc_aux(Fr::from(rule.port_end as u64));
    enforce_value_in_range(
        cs,
        public.dst_port,
        Fr::from(0u64),
        min,
        Fr::from(rule.port_start as u64),
        max,
        Fr::from(rule.port_end as u64),
        16,
    );
}

fn enforce_merkle_path(cs: &mut ConstraintSystem<Fr>, w: &WitnessInputs, h_policy: Fr) {
    let leaf = cs.alloc_aux(w.descriptor);
    let sibling_vars: Vec<Variable> = w
        .merkle_path
        .iter()
        .map(|sib| cs.alloc_aux(sib.sibling))
        .collect();
    let sibling_vals: Vec<Fr> = w.merkle_path.iter().map(|sib| sib.sibling).collect();
    let flag_vars: Vec<Variable> = w
        .merkle_path
        .iter()
        .map(|sib| cs.alloc_aux(if sib.sibling_is_left { Fr::from(1u64) } else { Fr::from(0u64) }))
        .collect();
    let flag_vals: Vec<Fr> = w
        .merkle_path
        .iter()
        .map(|sib| if sib.sibling_is_left { Fr::from(1u64) } else { Fr::from(0u64) })
        .collect();

    let (root_var, _root_val) = enforce_poseidon_merkle_path(
        cs,
        leaf,
        w.descriptor,
        &crate::policy::manifest::PoseidonMerklePath { siblings: w.merkle_path.clone() },
        &sibling_vars,
        &sibling_vals,
        &flag_vars,
        &flag_vals,
    );

    let h_policy_var = cs.alloc_input(h_policy);
    enforce_equal(cs, root_var, h_policy_var);
}
