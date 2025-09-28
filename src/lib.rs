#![no_std]

extern crate alloc;

pub mod crypto;
pub mod node;
pub mod packet;
pub mod source;
pub mod sphinx;
pub mod time;
pub mod types;
pub mod setup;

pub use time::*;
pub use types::*;

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{CryptoRng, RngCore};
    // no direct `use` of Scalar; tests use fully-qualified path

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
    fn e2e_setup_and_data_forward() {
        let mut rng = XorShift64(0xdead_beef_cafe_babe);
        let lf = 3usize;
        let lb = 3usize;
        let rmax = lf;
        let beta_len = rmax * C_BLOCK;
        let sp_len = rmax * C_BLOCK;

        fn gen_node() -> ([u8; 32], [u8; 32], Sv) {
            let mut sk = [0u8; 32];
            let mut tmp = [0u8; 32];
            XorShift64(0x1111_2222_3333_4444)
                .try_fill_bytes(&mut tmp)
                .unwrap();
            sk.copy_from_slice(&tmp);
            sk[0] &= 248;
            sk[31] &= 127;
            sk[31] |= 64;
            let pk = x25519_dalek::x25519(sk, x25519_dalek::X25519_BASEPOINT_BYTES);
            let mut svb = [0u8; 16];
            XorShift64(0x5555_6666_7777_8888)
                .try_fill_bytes(&mut svb)
                .unwrap();
            (sk, pk, Sv(svb))
        }
        let mut nodes_f = alloc::vec::Vec::new();
        for _ in 0..lf {
            nodes_f.push(gen_node());
        }
        let mut nodes_b = alloc::vec::Vec::new();
        for _ in 0..lb {
            nodes_b.push(gen_node());
        }

        let rs_f: alloc::vec::Vec<RoutingSegment> = (0..lf)
            .map(|i| RoutingSegment(alloc::vec![i as u8; 8]))
            .collect();
        let rs_b: alloc::vec::Vec<RoutingSegment> = (0..lb)
            .map(|i| RoutingSegment(alloc::vec![0x80 | (i as u8); 8]))
            .collect();
        let exp = Exp(1_000_000);

        let mut x_s = [0u8; 32];
        rng.fill_bytes(&mut x_s);
        x_s[0] &= 248;
        x_s[31] &= 127;
        x_s[31] |= 64;

        let pubkeys_f: alloc::vec::Vec<[u8; 32]> = nodes_f.iter().map(|n| n.1).collect();
        let (mut shdr_f, mut sp_f, keys_f, _eph_pub_f) =
            crate::sphinx::source_create_forward(&x_s, &pubkeys_f, beta_len, sp_len);

        let pubkeys_b: alloc::vec::Vec<[u8; 32]> = nodes_b.iter().map(|n| n.1).collect();
        let (mut shdr_b, _sp_dummy, keys_b, eph_pub_b) =
            crate::sphinx::source_create_forward(&x_s, &pubkeys_b, beta_len, sp_len);
        // For backward, keep y as eph_pub so nodes derive the same shared as the source
        shdr_b.y = eph_pub_b;

        let seed_f = {
            let mut s = [0u8; 16];
            rng.fill_bytes(&mut s);
            s
        };
        let mut p_f = crate::packet::FsPayload::new_with_seed(rmax, &seed_f);
        let mut fses_f_vec = alloc::vec::Vec::new();
        for i in 0..lf {
            let (sk_i, _pk_i, sv_i) = nodes_f[i];
            let _si_node =
                crate::sphinx::node_process_forward(&mut shdr_f, &mut sp_f, &sk_i, beta_len)
                    .expect("sphinx f");
            let fs_i = crate::packet::create(&sv_i, &keys_f[i], &rs_f[i], exp).expect("fs f");
            let _ =
                crate::packet::add_fs_into_payload(&keys_f[i], &fs_i, &mut p_f).expect("add fs f");
            fses_f_vec.push(fs_i);
        }
        let mut sp_b = crate::sphinx::dest_create_backward_sp(&p_f.bytes, sp_len);
        let seed_b = {
            let mut s = [0u8; 16];
            rng.fill_bytes(&mut s);
            s
        };
        let mut p_b = crate::packet::FsPayload::new_with_seed(rmax, &seed_b);
        let mut fses_b_vec = alloc::vec::Vec::new();
        for j in 0..lb {
            let (sk_j, _pk_j, sv_j) = nodes_b[j];
            let _sj_node =
                crate::sphinx::node_process_backward(&shdr_b, &mut sp_b, &sk_j).expect("sphinx b");
            let fs_j = crate::packet::create(&sv_j, &keys_b[j], &rs_b[j], exp).expect("fs b");
            let _ =
                crate::packet::add_fs_into_payload(&keys_b[j], &fs_j, &mut p_b).expect("add fs b");
            fses_b_vec.push(fs_j);
        }
        let _pf_bytes = crate::sphinx::source_unwrap_backward(&keys_b, &sp_b);
        // Unwrap SPb to get Pf and retrieve FSes per Alg.2
        // Unwrap SPb to get Pf and retrieve FSes per Alg.2
        let pf_bytes = crate::sphinx::source_unwrap_backward(&keys_b, &sp_b);
        let pf_recv = crate::packet::FsPayload {
            bytes: pf_bytes,
            rmax,
        };
        let fses_f = crate::packet::retrieve_fses(&keys_f, &seed_f, &pf_recv).expect("ret fs f");
        let fses_b = crate::packet::retrieve_fses(&keys_b, &seed_b, &p_b).expect("ret fs b");

        let mut rng2 = XorShift64(0x9999_aaaa_bbbb_cccc);
        let ahdr_f =
            crate::packet::ahdr::create_ahdr(&keys_f, &fses_f, rmax, &mut rng2).expect("ahdr f");
        let _ahdr_b =
            crate::packet::ahdr::create_ahdr(&keys_b, &fses_b, rmax, &mut rng2).expect("ahdr b");

        let mut payload = alloc::vec![0u8; 64];
        for i in 0..payload.len() {
            payload[i] = (i as u8) ^ 0x5a;
        }
        let mut iv0 = [0u8; 16];
        rng.fill_bytes(&mut iv0);
        let orig = payload.clone();
        crate::source::encrypt_forward_payload(&keys_f, &mut iv0, &mut payload).expect("enc f");

        // Forward process with AHDR at each hop
        let mut iv = iv0;
        let mut ah = ahdr_f;
        for i in 0..lf {
            let pr = crate::packet::ahdr::proc_ahdr(&nodes_f[i].2, &ah, Exp(0)).expect("proc ahdr");
            crate::packet::onion::remove_layer(&pr.s, &mut iv, &mut payload).expect("remove");
            ah = pr.ahdr_next;
        }
        assert_eq!(&payload, &orig);
    }

    #[test]
    fn fs_retrieve_padding_r_gt_l() {
        let mut rng = XorShift64(0x1234_5678_9abc_def0);
        let rmax = 4usize;
        let lf = 3usize;
        let lb = 3usize;
        let beta_len = rmax * C_BLOCK;
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
            XorShift64(seed ^ 0x9e37_79b9)
                .try_fill_bytes(&mut svb)
                .unwrap();
            (sk, pk, Sv(svb))
        }
        let mut nodes_f = alloc::vec::Vec::new();
        for i in 0..lf {
            nodes_f.push(gen_node(0x1000 + i as u64));
        }
        let mut nodes_b = alloc::vec::Vec::new();
        for i in 0..lb {
            nodes_b.push(gen_node(0x2000 + i as u64));
        }

        let rs_f: alloc::vec::Vec<RoutingSegment> = (0..lf)
            .map(|i| RoutingSegment(alloc::vec![i as u8; 8]))
            .collect();
        let rs_b: alloc::vec::Vec<RoutingSegment> = (0..lb)
            .map(|i| RoutingSegment(alloc::vec![0x80 | (i as u8); 8]))
            .collect();
        let exp = Exp(2_000_000);

        let mut x_s = [0u8; 32];
        rng.fill_bytes(&mut x_s);
        x_s[0] &= 248;
        x_s[31] &= 127;
        x_s[31] |= 64;
        let pubkeys_f: alloc::vec::Vec<[u8; 32]> = nodes_f.iter().map(|n| n.1).collect();
        let (mut shdr_f, mut sp_f, keys_f, _eph_pub_f) =
            crate::sphinx::source_create_forward(&x_s, &pubkeys_f, beta_len, sp_len);
        let pubkeys_b: alloc::vec::Vec<[u8; 32]> = nodes_b.iter().map(|n| n.1).collect();
        let (mut shdr_b, _sp_dummy, keys_b, eph_pub_b) =
            crate::sphinx::source_create_forward(&x_s, &pubkeys_b, beta_len, sp_len);
        shdr_b.y = eph_pub_b;

        let seed_f = {
            let mut s = [0u8; 16];
            rng.fill_bytes(&mut s);
            s
        };
        let mut p_f = crate::packet::FsPayload::new_with_seed(rmax, &seed_f);
        for i in 0..lf {
            let (sk_i, _pk_i, sv_i) = nodes_f[i];
            let _ = crate::sphinx::node_process_forward(&mut shdr_f, &mut sp_f, &sk_i, beta_len)
                .expect("sphinx f");
            let fs_i = crate::packet::create(&sv_i, &keys_f[i], &rs_f[i], exp).expect("fs f");
            let _ =
                crate::packet::add_fs_into_payload(&keys_f[i], &fs_i, &mut p_f).expect("add fs f");
        }
        let mut sp_b = crate::sphinx::dest_create_backward_sp(&p_f.bytes, sp_len);
        let seed_b = {
            let mut s = [0u8; 16];
            rng.fill_bytes(&mut s);
            s
        };
        let mut p_b = crate::packet::FsPayload::new_with_seed(rmax, &seed_b);
        for j in 0..lb {
            let (sk_j, _pk_j, sv_j) = nodes_b[j];
            let _ =
                crate::sphinx::node_process_backward(&shdr_b, &mut sp_b, &sk_j).expect("sphinx b");
            let fs_j = crate::packet::create(&sv_j, &keys_b[j], &rs_b[j], exp).expect("fs b");
            let _ =
                crate::packet::add_fs_into_payload(&keys_b[j], &fs_j, &mut p_b).expect("add fs b");
        }
        let pf_bytes = crate::sphinx::source_unwrap_backward(&keys_b, &sp_b);
        let pf_recv = crate::packet::FsPayload {
            bytes: pf_bytes,
            rmax,
        };
        let _fses_f =
            crate::packet::retrieve_fses(&keys_f, &seed_f, &pf_recv).expect("ret fs f (r>l)");
        let _fses_b = crate::packet::retrieve_fses(&keys_b, &seed_b, &p_b).expect("ret fs b (r>l)");
    }

    #[test]
    fn e2e_backward_ahdr_and_data() {
        let mut rng = XorShift64(0xa1a2_a3a4_a5a6_a7a8);
        let lf = 3usize;
        let lb = 3usize;
        let rmax = lb;
        let beta_len = rmax * C_BLOCK;
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
            XorShift64(seed ^ 0x5555_aaaa_dead_beef)
                .try_fill_bytes(&mut svb)
                .unwrap();
            (sk, pk, Sv(svb))
        }
        let mut nodes_f = alloc::vec::Vec::new();
        for i in 0..lf {
            nodes_f.push(gen_node(0x3000 + i as u64));
        }
        let mut nodes_b = alloc::vec::Vec::new();
        for i in 0..lb {
            nodes_b.push(gen_node(0x4000 + i as u64));
        }
        let rs_f: alloc::vec::Vec<RoutingSegment> = (0..lf)
            .map(|i| RoutingSegment(alloc::vec![i as u8; 8]))
            .collect();
        let rs_b: alloc::vec::Vec<RoutingSegment> = (0..lb)
            .map(|i| RoutingSegment(alloc::vec![0x80 | (i as u8); 8]))
            .collect();
        let exp = Exp(3_000_000);

        // Source ephemeral secret
        let mut x_s = [0u8; 32];
        rng.fill_bytes(&mut x_s);
        x_s[0] &= 248;
        x_s[31] &= 127;
        x_s[31] |= 64;
        // Forward build to collect FS forward (not used directly here)
        let pubkeys_f: alloc::vec::Vec<[u8; 32]> = nodes_f.iter().map(|n| n.1).collect();
        let (mut shdr_f, mut sp_f, keys_f, _eph_pub_f) =
            crate::sphinx::source_create_forward(&x_s, &pubkeys_f, beta_len, sp_len);
        let seed_f = {
            let mut s = [0u8; 16];
            rng.fill_bytes(&mut s);
            s
        };
        let mut p_f = crate::packet::FsPayload::new_with_seed(rmax, &seed_f);
        for i in 0..lf {
            let (sk_i, _pk_i, sv_i) = nodes_f[i];
            let _ = crate::sphinx::node_process_forward(&mut shdr_f, &mut sp_f, &sk_i, beta_len)
                .expect("sphinx f");
            let fs_i = crate::packet::create(&sv_i, &keys_f[i], &rs_f[i], exp).expect("fs f");
            let _ =
                crate::packet::add_fs_into_payload(&keys_f[i], &fs_i, &mut p_f).expect("add fs f");
        }
        // Backward build
        let pubkeys_b: alloc::vec::Vec<[u8; 32]> = nodes_b.iter().map(|n| n.1).collect();
        let (mut shdr_b, _sp_dummy, keys_b, eph_pub_b) =
            crate::sphinx::source_create_forward(&x_s, &pubkeys_b, beta_len, sp_len);
        shdr_b.y = eph_pub_b;
        let seed_b = {
            let mut s = [0u8; 16];
            rng.fill_bytes(&mut s);
            s
        };
        let mut p_b = crate::packet::FsPayload::new_with_seed(rmax, &seed_b);
        for j in 0..lb {
            let (sk_j, _pk_j, sv_j) = nodes_b[j];
            let _ = crate::sphinx::node_process_backward(
                &shdr_b,
                &mut crate::sphinx::dest_create_backward_sp(&p_f.bytes, sp_len),
                &sk_j,
            )
            .expect("sphinx b");
            let fs_j = crate::packet::create(&sv_j, &keys_b[j], &rs_b[j], exp).expect("fs b");
            let _ =
                crate::packet::add_fs_into_payload(&keys_b[j], &fs_j, &mut p_b).expect("add fs b");
        }
        // Retrieve FS for backward path
        let fses_b = crate::packet::retrieve_fses(&keys_b, &seed_b, &p_b).expect("ret fs b");
        // Build backward AHDR with reversed order (first hop from destination is last in keys_b)
        let mut rng2 = XorShift64(0x7777_8888_9999_aaaa);
        let mut keys_b_rev = keys_b.clone();
        keys_b_rev.reverse();
        let mut fses_b_rev = fses_b.clone();
        fses_b_rev.reverse();
        let ahdr_b = crate::packet::ahdr::create_ahdr(&keys_b_rev, &fses_b_rev, rmax, &mut rng2)
            .expect("ahdr b");

        // Destination encrypts payload and each node adds a layer while processing AHDR
        let mut payload = alloc::vec![0u8; 96];
        for i in 0..payload.len() {
            payload[i] = (0x30 + (i as u8)) ^ 0x33;
        }
        let mut iv = {
            let mut v = [0u8; 16];
            rng.fill_bytes(&mut v);
            v
        };
        // Destination adds first layer using last key (keys_b_rev[0]) via proc_ahdr at node nodes_b[lb-1]
        let mut ah = ahdr_b;
        for hop in (0..lb).rev() {
            // nodes from far (lb-1) to near (0)
            let pr =
                crate::packet::ahdr::proc_ahdr(&nodes_b[hop].2, &ah, Exp(0)).expect("proc ahdr b");
            crate::packet::onion::add_layer(&pr.s, &mut iv, &mut payload).expect("add layer b");
            ah = pr.ahdr_next;
        }
        // Decrypt by replaying layers removal in reverse add order (keys_b_rev) with matching IV evolution
        let mut iv3 = iv;
        let mut data2 = payload.clone();
        for k in (0..lb).rev() {
            crate::packet::onion::remove_layer(&keys_b_rev[k], &mut iv3, &mut data2)
                .expect("rem b");
        }
        // The resulting plaintext must match the original destination payload
        let mut orig = alloc::vec![0u8; 96];
        for i in 0..orig.len() {
            orig[i] = (0x30 + (i as u8)) ^ 0x33;
        }
        assert_eq!(data2, orig);
    }

    #[cfg(feature = "strict_sphinx")]
    #[test]
    fn strict_sphinx_hop0_boundary() {
        // Boundary test for hop0: verify that header state seen by hop0 matches one
        // of the two canonical constructions (mu over masked beta with mu-slot zeroed
        // vs mu over masked beta), then ensure node accepts and advances state.
        let mut rng = XorShift64(0x1010_2020_3030_4040);
        let r = 3usize;
        let beta_len = r * C_BLOCK;
        // Build node keys
        let mut nodes = alloc::vec::Vec::new();
        for _ in 0..r {
            let mut sk = [0u8; 32];
            rng.fill_bytes(&mut sk);
            sk[0] &= 248;
            sk[31] &= 127;
            sk[31] |= 64;
            let pk = x25519_dalek::x25519(sk, x25519_dalek::X25519_BASEPOINT_BYTES);
            nodes.push((sk, pk));
        }
        let mut x_s = [0u8; 32];
        rng.fill_bytes(&mut x_s);
        x_s[0] &= 248;
        x_s[31] &= 127;
        x_s[31] |= 64;
        let pubs: alloc::vec::Vec<[u8; 32]> = nodes.iter().map(|n| n.1).collect();
        let (mut h, _sis, _eph_pub, snaps) =
            crate::sphinx::strict::source_create_forward_strict_trace(&x_s, &pubs, beta_len);
        // Hop0 should see snaps[0]
        assert_eq!(h.beta, snaps[0]);
        // Compute hop0 shared and two candidate MAC targets
        let sk0 = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(nodes[0].0);
        let alpha0 = curve25519_dalek::montgomery::MontgomeryPoint(h.alpha);
        let shared0 = (&sk0 * &alpha0).to_bytes();
        let mut k_mu0 = [0u8; 16];
        crate::crypto::kdf::hop_key(&shared0, crate::crypto::kdf::OpLabel::Mac, &mut k_mu0);
        // masked beta is just snaps[0]; zero mu-slot for MAC
        let mut masked_zero = snaps[0].clone();
        for b in &mut masked_zero[0..crate::sphinx::MU_LEN] {
            *b = 0;
        }
        let mac_zero = crate::crypto::mac::mac_trunc16(&k_mu0, &masked_zero);
        // also try MAC over entire masked beta (without zeroing)
        let mac_full = crate::crypto::mac::mac_trunc16(&k_mu0, &snaps[0]);
        // One of them should match the embedded mu at front
        let mu_front = &snaps[0][0..crate::sphinx::MU_LEN];
        assert!(mu_front == &mac_zero.0 || mu_front == &mac_full.0);
        // And node should accept and advance state
        let _ = crate::sphinx::strict::node_process_forward_strict(&mut h, &nodes[0].0)
            .expect("hop0 accepts");
    }

    #[cfg(feature = "strict_sphinx")]
    #[test]
    fn strict_sphinx_header_chain_and_tamper() {
        let mut rng = XorShift64(0xabc1_def2_3456_7890);
        let r = 3usize;
        let beta_len = r * C_BLOCK;
        // Build node keys
        let mut nodes = alloc::vec::Vec::new();
        for _ in 0..r {
            let mut sk = [0u8; 32];
            rng.fill_bytes(&mut sk);
            sk[0] &= 248;
            sk[31] &= 127;
            sk[31] |= 64;
            let pk = x25519_dalek::x25519(sk, x25519_dalek::X25519_BASEPOINT_BYTES);
            nodes.push((sk, pk));
        }
        // Source ephemeral
        let mut x_s = [0u8; 32];
        rng.fill_bytes(&mut x_s);
        x_s[0] &= 248;
        x_s[31] &= 127;
        x_s[31] |= 64;
        let pubs: alloc::vec::Vec<[u8; 32]> = nodes.iter().map(|n| n.1).collect();
        let (mut h, _sis, _eph_pub) =
            crate::sphinx::strict::source_create_forward_strict(&x_s, &pubs, beta_len);
        // Ensure hop0 accepts the fresh header
        let _ = crate::sphinx::strict::node_process_forward_strict(&mut h, &nodes[0].0)
            .expect("hop0 accept");
        // Tamper test: rebuild header and flip one bit in beta, first hop should reject
        let (mut h2, _sis2, _eph_pub2) =
            crate::sphinx::strict::source_create_forward_strict(&x_s, &pubs, beta_len);
        h2.beta[0] ^= 1;
        let res = crate::sphinx::strict::node_process_forward_strict(&mut h2, &nodes[0].0);
        assert!(res.is_err());
    }

    #[cfg(feature = "strict_sphinx")]
    #[test]
    fn strict_sphinx_step_by_step_states() {
        let mut rng = XorShift64(0x5555_2222_9999_dddd);
        let r = 3usize;
        let beta_len = r * C_BLOCK;
        // Build node keys
        let mut nodes = alloc::vec::Vec::new();
        for _ in 0..r {
            let mut sk = [0u8; 32];
            rng.fill_bytes(&mut sk);
            sk[0] &= 248;
            sk[31] &= 127;
            sk[31] |= 64;
            let pk = x25519_dalek::x25519(sk, x25519_dalek::X25519_BASEPOINT_BYTES);
            nodes.push((sk, pk));
        }
        let mut x_s = [0u8; 32];
        rng.fill_bytes(&mut x_s);
        x_s[0] &= 248;
        x_s[31] &= 127;
        x_s[31] |= 64;
        let pubs: alloc::vec::Vec<[u8; 32]> = nodes.iter().map(|n| n.1).collect();
        let (mut h, _sis, _eph_pub, _snaps) =
            crate::sphinx::strict::source_create_forward_strict_trace(&x_s, &pubs, beta_len);
        // Node 0 accepts
        let _ =
            crate::sphinx::strict::node_process_forward_strict(&mut h, &nodes[0].0).expect("hop0");
        // Node 1 accepts
        let _ =
            crate::sphinx::strict::node_process_forward_strict(&mut h, &nodes[1].0).expect("hop1");
        // Node 2 accepts
        let _ =
            crate::sphinx::strict::node_process_forward_strict(&mut h, &nodes[2].0).expect("hop2");
    }

    #[test]
    fn ahdr_expiry_check() {
        // Single-hop AHDR with a fixed EXP; proc_ahdr should pass when now < EXP and fail when now >= EXP.
        let mut rng = XorShift64(0x0f0e_0d0c_0b0a_0908);
        let rmax = 1usize;
        // Generate one node context
        let mut svb = [0u8; 16];
        rng.fill_bytes(&mut svb);
        let sv = Sv(svb);
        let mut key = [0u8; 16];
        rng.fill_bytes(&mut key);
        let si = Si(key);
        let rseg = RoutingSegment(alloc::vec![0u8; 8]);
        let exp = Exp(1_234_567);
        let fs = crate::packet::create(&sv, &si, &rseg, exp).expect("fs");
        let mut rng2 = XorShift64(0x0102_0304_0506_0708);
        let ahdr = crate::packet::ahdr::create_ahdr(&[si], &[fs], rmax, &mut rng2).expect("ahdr");
        // now < EXP → OK
        let _pr =
            crate::packet::ahdr::proc_ahdr(&sv, &ahdr, Exp(exp.0 - 1)).expect("proc ok before exp");
        // now >= EXP → Expired
        let err = crate::packet::ahdr::proc_ahdr(&sv, &ahdr, Exp(exp.0))
            .err()
            .expect("must error at exp");
        assert!(matches!(err, Error::Expired));
    }

    #[test]
    fn build_data_packet_forward_end_to_end() {
        let mut rng = XorShift64(0xdead_beef_c0de_ca1f);
        let lf = 3usize;
        let rmax = lf;
        let beta_len = rmax * C_BLOCK;
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
            XorShift64(seed ^ 0x1122_3344_5566_7788)
                .try_fill_bytes(&mut svb)
                .unwrap();
            (sk, pk, Sv(svb))
        }

        // Build forward path nodes and segments
        let mut nodes_f = alloc::vec::Vec::new();
        for i in 0..lf {
            nodes_f.push(gen_node(0x5000 + i as u64));
        }
        let rs_f: alloc::vec::Vec<RoutingSegment> =
            (0..lf).map(|i| RoutingSegment(alloc::vec![i as u8; 8])).collect();
        let exp = Exp(4_200_000);

        // Source ephemeral and keys for forward path
        let mut x_s = [0u8; 32];
        rng.fill_bytes(&mut x_s);
        x_s[0] &= 248;
        x_s[31] &= 127;
        x_s[31] |= 64;
        let pubkeys_f: alloc::vec::Vec<[u8; 32]> = nodes_f.iter().map(|n| n.1).collect();
        let (_shdr_f, _sp_f, keys_f, _eph_pub_f) =
            crate::sphinx::source_create_forward(&x_s, &pubkeys_f, beta_len, sp_len);

        // Create FSes and AHDR for forward
        let fses_f: alloc::vec::Vec<Fs> = (0..lf)
            .map(|i| crate::packet::create(&nodes_f[i].2, &keys_f[i], &rs_f[i], exp).unwrap())
            .collect();
        let mut rng2 = XorShift64(0x0bad_cafe_dead_beef);
        let ahdr_f = crate::packet::ahdr::create_ahdr(&keys_f, &fses_f, rmax, &mut rng2).unwrap();

        // Build CHDR and plaintext payload
        let mut chdr = crate::packet::chdr::data_header(lf as u8, Nonce([0u8; 16]));
        let mut iv0 = Nonce([0u8; 16]);
        rng.fill_bytes(&mut iv0.0);
        let mut payload = alloc::vec![0u8; 80];
        for i in 0..payload.len() {
            payload[i] = (0xa0 ^ (i as u8)).wrapping_add(7);
        }
        let orig = payload.clone();

        // Build data packet: apply onion layers and set CHDR nonce to final IV
        crate::source::build_data_packet(&mut chdr, &ahdr_f, &keys_f, &mut iv0, &mut payload)
            .expect("build data packet");

        // Forward path processing at each hop: AHDR processing + remove one layer
        let mut ah = ahdr_f;
        let mut iv = chdr.specific;
        for i in 0..lf {
            let pr = crate::packet::ahdr::proc_ahdr(&nodes_f[i].2, &ah, Exp(0)).expect("proc");
            crate::packet::onion::remove_layer(&pr.s, &mut iv, &mut payload).expect("rem");
            ah = pr.ahdr_next;
        }
        assert_eq!(payload, orig);
    }

    #[test]
    fn setup_strict_end_to_end_fs_collection() {
        // Simulate strict setup: source builds setup packet; each hop processes it, creates FS,
        // and inserts into payload. Finally, source retrieves FSes from the resulting payload.
        let mut rng = XorShift64(0x1111_aaaa_2222_bbbb);
        let lf = 3usize;
        let rmax = lf;
        let beta_len = rmax * C_BLOCK;
        let _sp_len = rmax * C_BLOCK; // not used directly in strict setup

        // Node materials (sk, pk, sv) and routing segments
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
            XorShift64(seed ^ 0x9e37_79b9).try_fill_bytes(&mut svb).unwrap();
            (sk, pk, Sv(svb))
        }
        let mut nodes = alloc::vec::Vec::new();
        for i in 0..lf {
            nodes.push(gen_node(0x7000 + i as u64));
        }
        let pubs: alloc::vec::Vec<[u8; 32]> = nodes.iter().map(|n| n.1).collect();
        let rs: alloc::vec::Vec<RoutingSegment> =
            (0..lf).map(|i| RoutingSegment(alloc::vec![i as u8; 8])).collect();
        let exp = Exp(5_500_000);

        // Source ephemeral secret
        let mut x_s = [0u8; 32];
        rng.fill_bytes(&mut x_s);
        x_s[0] &= 248;
        x_s[31] &= 127;
        x_s[31] |= 64;

        // Initialize setup packet at source
        let mut st = crate::setup::source_init_strict(&x_s, &pubs, rmax, exp, &mut rng);
        // Process at each hop; collect the FS list created by nodes for later comparison
        let mut fses_created: alloc::vec::Vec<Fs> = alloc::vec::Vec::new();
        for i in 0..lf {
            // node i processes header -> si, and inserts FS(si,EXP,RS)
            let si_i = crate::setup::node_process_strict(
                &mut st.packet,
                &nodes[i].0,
                &nodes[i].2,
                &rs[i],
            )
            .expect("setup hop");
            // Build the same FS locally to compare later
            let fs_i = crate::packet::create_from_chdr(&nodes[i].2, &si_i, &rs[i], &st.packet.chdr)
                .expect("fs local");
            fses_created.push(fs_i);
        }

        // At source, retrieve FSes from payload using keys_f and seed
        let pf_recv = crate::packet::FsPayload { bytes: st.packet.payload.bytes.clone(), rmax };
        let fses = crate::packet::retrieve_fses(&st.keys_f, &st.seed, &pf_recv).expect("retrieve fses");
        assert_eq!(fses.len(), fses_created.len());
        for (a, b) in fses.iter().zip(fses_created.iter()) {
            assert_eq!(a.0, b.0);
        }
    }

    #[test]
    fn backward_setup_finish_first_data_carries_ahdrb() {
        // End-to-end: perform strict forward setup to collect FS_f. Destination prepares AHDRb,
        // embeds it into the first data payload, sends it forward; source extracts AHDRb and
        // then uses it to process a backward data message successfully.
        let mut rng = XorShift64(0x2222_bbbb_3333_cccc);
        let lf = 3usize;
        let lb = 3usize;
        let rmax = core::cmp::max(lf, lb);
        let beta_len = rmax * C_BLOCK;
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
            XorShift64(seed ^ 0x1357_9bdf).try_fill_bytes(&mut svb).unwrap();
            (sk, pk, Sv(svb))
        }

        // Forward nodes and routing
        let mut nodes_f = alloc::vec::Vec::new();
        for i in 0..lf { nodes_f.push(gen_node(0x8100 + i as u64)); }
        let rs_f: alloc::vec::Vec<RoutingSegment> = (0..lf).map(|i| RoutingSegment(alloc::vec![i as u8; 8])).collect();
        let exp_f = Exp(7_000_000);
        let pubs_f: alloc::vec::Vec<[u8; 32]> = nodes_f.iter().map(|n| n.1).collect();

        // Backward nodes and routing
        let mut nodes_b = alloc::vec::Vec::new();
        for i in 0..lb { nodes_b.push(gen_node(0x9100 + i as u64)); }
        let rs_b: alloc::vec::Vec<RoutingSegment> = (0..lb).map(|i| RoutingSegment(alloc::vec![0x80 | (i as u8); 8])).collect();
        let exp_b = Exp(7_100_000);
        let pubs_b: alloc::vec::Vec<[u8; 32]> = nodes_b.iter().map(|n| n.1).collect();

        // Source ephemeral secret
        let mut x_s = [0u8; 32];
        rng.fill_bytes(&mut x_s);
        x_s[0] &= 248; x_s[31] &= 127; x_s[31] |= 64;

        // Forward setup initialize
        let mut st = crate::setup::source_init_strict(&x_s, &pubs_f, rmax, exp_f, &mut rng);
        // Each forward hop processes setup and adds FS
        for i in 0..lf {
            let _ = crate::setup::node_process_strict(&mut st.packet, &nodes_f[i].0, &nodes_f[i].2, &rs_f[i]).expect("setup hop f");
        }
        // Destination forms SPb from Pf (not used directly below, but models paper step)
        let _sp_b = crate::sphinx::dest_create_backward_sp(&st.packet.payload.bytes, sp_len);

        // Destination prepares backward keys via strict path build (same x_s used here for test)
        let (_sh_b, keys_b, _eph_pub_b) =
            crate::sphinx::strict::source_create_forward_strict(&x_s, &pubs_b, beta_len);
        // Build AHDRb at destination in traversal order (dest -> ... -> source)
        // Our nodes_b/keys_b are in source->dest order, so reverse to get traversal order.
        let mut keys_b_rev = keys_b.clone();
        keys_b_rev.reverse();
        let mut svs_b_rev: alloc::vec::Vec<Sv> = nodes_b.iter().map(|n| n.2).collect();
        svs_b_rev.reverse();
        let mut rs_b_rev = rs_b.clone();
        rs_b_rev.reverse();
        let mut rng2 = XorShift64(0xaaaa_bbbb_cccc_dddd);
        // Inline build of AHDRb: create FS list then create_ahdr
        let fses_b: alloc::vec::Vec<Fs> = (0..lb)
            .map(|i| crate::packet::create(&svs_b_rev[i], &keys_b_rev[i], &rs_b_rev[i], exp_b).unwrap())
            .collect();
        let ahdr_b = crate::packet::ahdr::create_ahdr(&keys_b_rev, &fses_b, rmax, &mut rng2).unwrap();

        // First data packet: payload carries AHDRb
        let mut chdr = crate::packet::chdr::data_header(lf as u8, Nonce([0u8; 16]));
        let mut iv0 = Nonce([0u8; 16]); rng.fill_bytes(&mut iv0.0);
        let mut payload = alloc::vec![0u8; sp_len.max(ahdr_b.bytes.len())];
        // Embed AHDRb at start of payload
        let need = rmax * C_BLOCK;
        payload[0..need].copy_from_slice(&ahdr_b.bytes[0..need]);
        crate::source::build_data_packet(&mut chdr, &Ahdr { bytes: alloc::vec::Vec::new() }, &st.keys_f, &mut iv0, &mut payload).expect("build first data");

        // Send forward: nodes remove layers and advance AHDRf (we do not use AHDRf here)
        let mut iv = chdr.specific;
        for i in 0..lf {
            // In a real flow we would also process AHDRf; here we just remove onion layer with Si
            // derived from forward setup keys
            crate::packet::onion::remove_layer(&st.keys_f[i], &mut iv, &mut payload).expect("remove");
        }

        // Source receives and extracts AHDRb from payload
        // Extract AHDRb from payload at source
        let got_ahdr_b = Ahdr { bytes: alloc::vec::Vec::from(&payload[0..need]) };
        assert_eq!(got_ahdr_b.bytes, ahdr_b.bytes);

        // Now validate backward data flow using the received AHDRb
        let mut msg = alloc::vec![0u8; 64];
        for i in 0..msg.len() { msg[i] = (0x55 ^ (i as u8)).wrapping_add(3); }
        // Destination encrypts by adding layers from farthest to nearest hop (reverse order)
        let mut ivb = [0u8; 16]; rng.fill_bytes(&mut ivb);
        let mut data_b = msg.clone();
        let mut ah_cur = got_ahdr_b;
        for hop in (0..lb).rev() {
            // Simulate traversal: at each hop, process AHDR to obtain s, then add a layer
            let pr = crate::packet::ahdr::proc_ahdr(&nodes_b[hop].2, &ah_cur, Exp(0)).expect("proc b");
            crate::packet::onion::add_layer(&pr.s, &mut ivb, &mut data_b).expect("add");
            ah_cur = pr.ahdr_next;
        }
        // Source removes layers mirroring main.rs demo order
        let mut ivb_src = ivb;
        for i in (0..lb).rev() {
            crate::packet::onion::remove_layer(&keys_b_rev[i], &mut ivb_src, &mut data_b).expect("un");
        }
        assert_eq!(data_b, msg);
    }
}
