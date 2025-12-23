use crate::application::setup::SetupPipeline;
use crate::packet::{core, payload};
use crate::policy::PolicyMetadata;
use crate::sphinx;
use crate::types::{Chdr, Exp, Result, RoutingSegment, Si, Sv};
use rand_core::RngCore;

pub mod directory;
pub mod wire;

// Sphinx-based setup packet carrying FS payload per HORNET setup.
pub struct SetupPacket {
    pub chdr: Chdr,
    pub shdr: sphinx::Header,
    pub payload: payload::Payload,
    pub rmax: usize,
    pub tlvs: alloc::vec::Vec<alloc::vec::Vec<u8>>,
}

pub struct SourceSetupState {
    pub packet: SetupPacket,
    pub keys_f: alloc::vec::Vec<Si>,
    pub eph_pub: [u8; 32],
    pub seed: [u8; 16],
}

// Source initializes the setup packet (Sphinx): builds header and randomized FS payload.
pub fn source_init(
    x_s: &[u8; 32],
    node_pubs: &[[u8; 32]],
    rmax: usize,
    exp: Exp,
    rng: &mut dyn RngCore,
) -> SourceSetupState {
    let (shdr, keys_f, eph_pub) =
        sphinx::source_create_forward(x_s, node_pubs, rmax).expect("sphinx header generation");
    // Initialize FS payload with random seed
    let mut seed = [0u8; 16];
    rng.fill_bytes(&mut seed);
    let payload = payload::Payload::new_with_seed(rmax, &seed);
    let chdr = crate::packet::chdr::setup_header(node_pubs.len() as u8, exp);
    let packet = SetupPacket {
        chdr,
        shdr,
        payload,
        rmax,
        tlvs: alloc::vec::Vec::new(),
    };
    SourceSetupState {
        packet,
        keys_f,
        eph_pub,
        seed,
    }
}

impl SourceSetupState {
    pub fn attach_policy_metadata(&mut self, meta: &PolicyMetadata) {
        self.packet
            .tlvs
            .push(crate::policy::encode_metadata_tlv(meta));
    }
}

// A hop processes setup: verifies/advances Sphinx header, creates FS from CHDR, and inserts into payload.
pub fn node_process(
    pkt: &mut SetupPacket,
    node_secret: &[u8; 32],
    sv: &Sv,
    rseg: &RoutingSegment,
) -> Result<Si> {
    node_process_with_policy(pkt, node_secret, sv, rseg, None)
}

pub fn node_process_with_policy(
    pkt: &mut SetupPacket,
    node_secret: &[u8; 32],
    sv: &Sv,
    rseg: &RoutingSegment,
    policy: Option<&mut dyn SetupPipeline>,
) -> Result<Si> {
    let si = sphinx::node_process_forward(&mut pkt.shdr, node_secret)?;
    let fs = core::create_from_chdr(sv, &si, rseg, &pkt.chdr)?;
    let _alpha = payload::add_fs_into_payload(&si, &fs, &mut pkt.payload)?;
    if let Some(installer) = policy {
        install_policy_metadata(pkt, installer)?;
    }
    Ok(si)
}

pub fn install_policy_metadata(pkt: &SetupPacket, installer: &mut dyn SetupPipeline) -> Result<()> {
    for tlv in &pkt.tlvs {
        if tlv.first().copied() == Some(crate::policy::POLICY_METADATA_TLV) {
            let meta = crate::policy::decode_metadata_tlv(tlv)?;
            installer.install(meta)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use rand_core::{CryptoRng, RngCore};

    struct XorShift64(u64);
    impl RngCore for XorShift64 {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.try_fill_bytes(dest).unwrap()
        }
        fn try_fill_bytes(
            &mut self,
            dest: &mut [u8],
        ) -> core::result::Result<(), rand_core::Error> {
            let mut n = 0;
            while n < dest.len() {
                let v = self.next_u64().to_le_bytes();
                let take = core::cmp::min(8, dest.len() - n);
                dest[n..n + take].copy_from_slice(&v[..take]);
                n += take;
            }
            Ok(())
        }
    }
    impl CryptoRng for XorShift64 {}

    #[test]
    fn setup_strict_end_to_end_fs_collection() {
        use crate::types::{Exp, Fs, RoutingSegment, Sv, C_BLOCK};
        let mut rng = XorShift64(0x1111_aaaa_2222_bbbb);
        let lf = 3usize;
        let rmax = lf;
        let _sp_len = rmax * C_BLOCK;
        fn gen_node(seed: u64) -> ([u8; 32], [u8; 32], Sv) {
            let mut sk = [0u8; 32];
            let mut tmp = [0u8; 32];
            XorShift64(seed).try_fill_bytes(&mut tmp).unwrap();
            sk.copy_from_slice(&tmp);
            sk[0] &= 248;
            sk[31] &= 127;
            sk[31] |= 64;
            let pk = x25519_dalek::x25519(sk, x25519_dalek::X25519_BASEPOINT_BYTES);
            let mut svb = [0u8; 16];
            XorShift64(seed ^ 0x9e37_79b9)
                .try_fill_bytes(&mut svb)
                .unwrap();
            (sk, pk, Sv(svb))
        }
        let mut nodes = alloc::vec::Vec::new();
        for i in 0..lf {
            nodes.push(gen_node(0x7000 + i as u64));
        }
        let pubs: alloc::vec::Vec<[u8; 32]> = nodes.iter().map(|n| n.1).collect();
        let rs: alloc::vec::Vec<RoutingSegment> = (0..lf)
            .map(|i| RoutingSegment(alloc::vec![i as u8; 8]))
            .collect();
        let exp = Exp(5_500_000);
        let mut x_s = [0u8; 32];
        rng.fill_bytes(&mut x_s);
        x_s[0] &= 248;
        x_s[31] &= 127;
        x_s[31] |= 64;
        let mut st = crate::setup::source_init(&x_s, &pubs, rmax, exp, &mut rng);
        let mut fses_created: alloc::vec::Vec<Fs> = alloc::vec::Vec::new();
        for i in 0..lf {
            let si_i = crate::setup::node_process(&mut st.packet, &nodes[i].0, &nodes[i].2, &rs[i])
                .expect("setup hop");
            let fs_i =
                crate::packet::core::create_from_chdr(&nodes[i].2, &si_i, &rs[i], &st.packet.chdr)
                    .expect("fs local");
            fses_created.push(fs_i);
        }
        let pf_recv = crate::packet::payload::Payload {
            bytes: st.packet.payload.bytes.clone(),
            rmax,
        };
        let fses = crate::packet::payload::retrieve_fses(&st.keys_f, &st.seed, &pf_recv)
            .expect("retrieve fses");
        assert_eq!(fses.len(), fses_created.len());
        for (a, b) in fses.iter().zip(fses_created.iter()) {
            assert_eq!(a.0, b.0);
        }
    }

    #[test]
    fn policy_metadata_registers_during_setup() {
        use crate::policy::{PolicyMetadata, PolicyRegistry};
        use crate::types::{Exp, RoutingSegment, Sv};

        let mut rng = XorShift64(0xA1B2_C3D4_E5F6_7788);
        let lf = 2usize;
        let rmax = lf;

        fn gen_node(seed: u64) -> ([u8; 32], [u8; 32], Sv) {
            let mut sk = [0u8; 32];
            let mut tmp = [0u8; 32];
            XorShift64(seed).try_fill_bytes(&mut tmp).unwrap();
            sk.copy_from_slice(&tmp);
            sk[0] &= 248;
            sk[31] &= 127;
            sk[31] |= 64;
            let pk = x25519_dalek::x25519(sk, x25519_dalek::X25519_BASEPOINT_BYTES);
            let mut svb = [0u8; 16];
            XorShift64(seed ^ 0x4444_5555)
                .try_fill_bytes(&mut svb)
                .unwrap();
            (sk, pk, Sv(svb))
        }

        let mut nodes = alloc::vec::Vec::new();
        for i in 0..lf {
            nodes.push(gen_node(0x9900 + i as u64));
        }
        let pubs: alloc::vec::Vec<[u8; 32]> = nodes.iter().map(|n| n.1).collect();
        let rs: alloc::vec::Vec<RoutingSegment> = (0..lf)
            .map(|i| RoutingSegment(alloc::vec![i as u8; 8]))
            .collect();
        let exp = Exp(1_234_567);

        let mut x_s = [0u8; 32];
        rng.fill_bytes(&mut x_s);
        x_s[0] &= 248;
        x_s[31] &= 127;
        x_s[31] |= 64;

        let mut st = crate::setup::source_init(&x_s, &pubs, rmax, exp, &mut rng);
        let policy = PolicyMetadata {
            policy_id: [0x77; 32],
            version: 1,
            expiry: exp.0,
            flags: 0,
            verifier_blob: alloc::vec![0xAA, 0xBB],
        };
        st.attach_policy_metadata(&policy);
        assert_eq!(st.packet.tlvs.len(), 1);
        assert!(crate::policy::decode_metadata_tlv(&st.packet.tlvs[0]).is_ok());

        let mut registry = PolicyRegistry::new();
        for i in 0..lf {
            let mut installer =
                crate::application::setup::RegistrySetupPipeline::new(&mut registry);
            let _ = crate::setup::node_process_with_policy(
                &mut st.packet,
                &nodes[i].0,
                &nodes[i].2,
                &rs[i],
                Some(&mut installer),
            )
            .expect("setup hop");
        }
        assert!(registry.get(&policy.policy_id).is_some());
    }

    #[test]
    fn backward_setup_finish_first_data_carries_ahdrb() {
        use crate::types::{Ahdr, Exp, Fs, Nonce, RoutingSegment, Sv, C_BLOCK};
        let mut rng = XorShift64(0x2222_bbbb_3333_cccc);
        let lf = 3usize;
        let lb = 3usize;
        let rmax = core::cmp::max(lf, lb);
        let sp_len = rmax * C_BLOCK;
        fn gen_node(seed: u64) -> ([u8; 32], [u8; 32], Sv) {
            let mut sk = [0u8; 32];
            let mut tmp = [0u8; 32];
            XorShift64(seed).try_fill_bytes(&mut tmp).unwrap();
            sk.copy_from_slice(&tmp);
            sk[0] &= 248;
            sk[31] &= 127;
            sk[31] |= 64;
            let pk = x25519_dalek::x25519(sk, x25519_dalek::X25519_BASEPOINT_BYTES);
            let mut svb = [0u8; 16];
            XorShift64(seed ^ 0x1357_9bdf)
                .try_fill_bytes(&mut svb)
                .unwrap();
            (sk, pk, Sv(svb))
        }
        let mut nodes_f = alloc::vec::Vec::new();
        for i in 0..lf {
            nodes_f.push(gen_node(0x8100 + i as u64));
        }
        let rs_f: alloc::vec::Vec<RoutingSegment> = (0..lf)
            .map(|i| RoutingSegment(alloc::vec![i as u8; 8]))
            .collect();
        let exp_f = Exp(7_000_000);
        let pubs_f: alloc::vec::Vec<[u8; 32]> = nodes_f.iter().map(|n| n.1).collect();
        let mut nodes_b = alloc::vec::Vec::new();
        for i in 0..lb {
            nodes_b.push(gen_node(0x9100 + i as u64));
        }
        let rs_b: alloc::vec::Vec<RoutingSegment> = (0..lb)
            .map(|i| RoutingSegment(alloc::vec![0x80 | (i as u8); 8]))
            .collect();
        let exp_b = Exp(7_100_000);
        let pubs_b: alloc::vec::Vec<[u8; 32]> = nodes_b.iter().map(|n| n.1).collect();
        let mut x_s = [0u8; 32];
        rng.fill_bytes(&mut x_s);
        x_s[0] &= 248;
        x_s[31] &= 127;
        x_s[31] |= 64;
        let mut st = crate::setup::source_init(&x_s, &pubs_f, rmax, exp_f, &mut rng);
        for i in 0..lf {
            let _ =
                crate::setup::node_process(&mut st.packet, &nodes_f[i].0, &nodes_f[i].2, &rs_f[i])
                    .expect("setup hop f");
        }
        // SPb formation step omitted
        let (_sh_b, keys_b, _eph_pub_b) =
            crate::sphinx::source_create_forward(&x_s, &pubs_b, rmax).expect("backward header");
        let mut keys_b_rev = keys_b.clone();
        keys_b_rev.reverse();
        let mut svs_b_rev: alloc::vec::Vec<Sv> = nodes_b.iter().map(|n| n.2).collect();
        svs_b_rev.reverse();
        let mut rs_b_rev = rs_b.clone();
        rs_b_rev.reverse();
        let mut rng2 = XorShift64(0xaaaa_bbbb_cccc_dddd);
        let fses_b: alloc::vec::Vec<Fs> = (0..lb)
            .map(|i| {
                crate::packet::core::create(&svs_b_rev[i], &keys_b_rev[i], &rs_b_rev[i], exp_b)
                    .unwrap()
            })
            .collect();
        let ahdr_b =
            crate::packet::ahdr::create_ahdr(&keys_b_rev, &fses_b, rmax, &mut rng2).unwrap();
        let mut chdr = crate::packet::chdr::data_header(lf as u8, Nonce([0u8; 16]));
        let mut iv0 = Nonce([0u8; 16]);
        rng.fill_bytes(&mut iv0.0);
        let mut payload = alloc::vec![0u8; sp_len.max(ahdr_b.bytes.len())];
        let need = rmax * C_BLOCK;
        payload[0..need].copy_from_slice(&ahdr_b.bytes[0..need]);
        crate::source::build(
            &mut chdr,
            &Ahdr {
                bytes: alloc::vec::Vec::new(),
            },
            &st.keys_f,
            &mut iv0,
            &mut payload,
        )
        .expect("build first data");
        let mut iv = chdr.specific;
        for i in 0..lf {
            crate::packet::onion::remove_layer(&st.keys_f[i], &mut iv, &mut payload)
                .expect("remove");
        }
        let got_ahdr_b = Ahdr {
            bytes: alloc::vec::Vec::from(&payload[0..need]),
        };
        assert_eq!(got_ahdr_b.bytes, ahdr_b.bytes);
        let mut msg = alloc::vec![0u8; 64];
        for i in 0..msg.len() {
            msg[i] = (0x55 ^ (i as u8)).wrapping_add(3);
        }
        let mut ivb = [0u8; 16];
        rng.fill_bytes(&mut ivb);
        let mut data_b = msg.clone();
        let mut ah_cur = got_ahdr_b;
        for hop in (0..lb).rev() {
            let pr =
                crate::packet::ahdr::proc_ahdr(&nodes_b[hop].2, &ah_cur, Exp(0)).expect("proc b");
            crate::packet::onion::add_layer(&pr.s, &mut ivb, &mut data_b).expect("add");
            ah_cur = pr.ahdr_next;
        }
        let mut ivb_src = ivb;
        for i in (0..lb).rev() {
            crate::packet::onion::remove_layer(&keys_b_rev[i], &mut ivb_src, &mut data_b)
                .expect("un");
        }
        assert_eq!(data_b, msg);
    }
}
