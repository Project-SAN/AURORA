// Run an end-to-end flow using the paper-compliant (strict) Sphinx header
// plus FS payload construction and AHDR/onion data, from setup to completion.
fn main() {
    use hornet::{
        packet::{ahdr, fs, onion},
        sphinx, sphinx::strict,
        types::{Exp, RoutingSegment, Sv, C_BLOCK},
    };
    use rand_core::{CryptoRng, RngCore};

    // Simple deterministic RNG for reproducibility
    struct XorShift64(u64);
    impl RngCore for XorShift64 {
        fn next_u32(&mut self) -> u32 { self.next_u64() as u32 }
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13; x ^= x >> 7; x ^= x << 17; self.0 = x; x
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) { let _ = self.try_fill_bytes(dest); }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand_core::Error> {
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

    fn clamp_scalar(x: &mut [u8; 32]) {
        x[0] &= 248; x[31] &= 127; x[31] |= 64;
    }

    fn gen_node(seed: u64) -> ([u8; 32], [u8; 32], Sv) {
        let mut sk = [0u8; 32]; let mut tmp = [0u8; 32];
        XorShift64(seed).try_fill_bytes(&mut tmp).unwrap();
        sk.copy_from_slice(&tmp); clamp_scalar(&mut sk);
        let pk = x25519_dalek::x25519(sk, x25519_dalek::X25519_BASEPOINT_BYTES);
        let mut svb = [0u8; 16]; XorShift64(seed ^ 0x55aa_aa55_dead_beef).try_fill_bytes(&mut svb).unwrap();
        (sk, pk, Sv(svb))
    }

    // Topology parameters
    let lf = 3usize; // forward hops
    let lb = 3usize; // backward hops
    let rmax = core::cmp::max(lf, lb);
    let beta_len = rmax * C_BLOCK; // strict header beta length
    let sp_len = rmax * C_BLOCK;   // fixed-length payload onion size

    // Build nodes
    let mut nodes_f = Vec::new();
    for i in 0..lf { nodes_f.push(gen_node(0x1000 + i as u64)); }
    let mut nodes_b = Vec::new();
    for i in 0..lb { nodes_b.push(gen_node(0x2000 + i as u64)); }

    // Routing segments and expiry
    let rs_f: Vec<RoutingSegment> = (0..lf).map(|i| RoutingSegment(vec![i as u8; 8])).collect();
    let rs_b: Vec<RoutingSegment> = (0..lb).map(|i| RoutingSegment(vec![0x80 | (i as u8); 8])).collect();
    let exp_f = Exp(1_000_000);
    let exp_b = Exp(2_000_000);

    // Source ephemeral secret (shared between forward/backward strict headers)
    let mut rng = XorShift64(0xdead_beef_cafe_babe);
    let mut x_s = [0u8; 32]; rng.fill_bytes(&mut x_s); clamp_scalar(&mut x_s);

    // Collect forward public keys and build strict Sphinx forward header
    let pubs_f: Vec<[u8; 32]> = nodes_f.iter().map(|n| n.1).collect();
    let (mut shdr_f, keys_f, _eph_pub_f) = strict::source_create_forward_strict(&x_s, &pubs_f, beta_len);

    // Build forward payload onion SPf by layering PRG1(Si) from last to first
    let mut sp_f = vec![0u8; sp_len];
    for i in (0..lf).rev() {
        let mut mask = vec![0u8; sp_len];
        hornet::crypto::prg::prg1(&keys_f[i].0, &mut mask);
        for (b, m) in sp_f.iter_mut().zip(mask.iter()) { *b ^= *m; }
    }

    // Forward path simulation: each hop processes strict header, peels one SPf layer,
    // and we create its FS and insert into forward FS payload P_f
    let seed_f = { let mut s = [0u8; 16]; rng.fill_bytes(&mut s); s };
    let mut p_f = fs::FsPayload::new_with_seed(rmax, &seed_f);
    let mut fses_f_vec = Vec::new();
    for i in 0..lf {
        let (sk_i, _pk_i, sv_i) = nodes_f[i];
        let si_node = strict::node_process_forward_strict(&mut shdr_f, &sk_i).expect("strict forward hop");
        // Peel SPf layer with Si
        let mut mask = vec![0u8; sp_len];
        hornet::crypto::prg::prg1(&si_node.0, &mut mask);
        for (b, m) in sp_f.iter_mut().zip(mask.iter()) { *b ^= *m; }
        // FS creation and insert into payload
        let fs_i = fs::fs_create(&sv_i, &keys_f[i], &rs_f[i], exp_f).expect("fs forward");
        fs::add_fs_into_payload(&keys_f[i], &fs_i, &mut p_f).expect("add fs forward");
        fses_f_vec.push(fs_i);
    }
    // After all forward hops, SPf should unwrap to all-zero
    assert!(sp_f.iter().all(|&b| b == 0));

    // Destination creates backward payload SPb from P_f
    let mut sp_b = sphinx::dest_create_backward_sp(&p_f.bytes, sp_len);

    // Build strict forward header for backward path to derive backward keys
    let pubs_b: Vec<[u8; 32]> = nodes_b.iter().map(|n| n.1).collect();
    let (mut shdr_b, keys_b, _eph_pub_b) = strict::source_create_forward_strict(&x_s, &pubs_b, beta_len);

    // Backward path simulation: each hop validates header and adds one layer using Si
    let seed_b = { let mut s = [0u8; 16]; rng.fill_bytes(&mut s); s };
    let mut p_b = fs::FsPayload::new_with_seed(rmax, &seed_b);
    let mut fses_b_vec = Vec::new();
    for j in 0..lb {
        let (sk_j, _pk_j, sv_j) = nodes_b[j];
        let si_j = strict::node_process_forward_strict(&mut shdr_b, &sk_j).expect("strict backward hop header");
        // Add SPb layer with PRG1(Si)
        let mut mask = vec![0u8; sp_b.0.len()];
        hornet::crypto::prg::prg1(&si_j.0, &mut mask);
        for (b, m) in sp_b.0.iter_mut().zip(mask.iter()) { *b ^= *m; }
        // Create FS for backward path and accumulate
        let fs_j = fs::fs_create(&sv_j, &keys_b[j], &rs_b[j], exp_b).expect("fs backward");
        fs::add_fs_into_payload(&keys_b[j], &fs_j, &mut p_b).expect("add fs backward");
        fses_b_vec.push(fs_j);
    }

    // Source unwraps SPb using backward keys → recovers forward P_f bytes
    let pf_bytes = sphinx::source_unwrap_backward(&keys_b, &sp_b);
    assert_eq!(pf_bytes, p_f.bytes, "Recovered Pf must match at source");

    // Retrieve FSes from payloads (both directions) per Alg.2
    let pf_recv = fs::FsPayload { bytes: pf_bytes.clone(), rmax };
    let fses_f = fs::retrieve_fses(&keys_f, &seed_f, &pf_recv).expect("retrieve fs forward");
    let fses_b = fs::retrieve_fses(&keys_b, &seed_b, &p_b).expect("retrieve fs backward");
    assert!(fses_f.len() == fses_f_vec.len() && fses_f.iter().zip(fses_f_vec.iter()).all(|(a,b)| a.0 == b.0), "Forward FS list round-trips");
    assert!(fses_b.len() == fses_b_vec.len() && fses_b.iter().zip(fses_b_vec.iter()).all(|(a,b)| a.0 == b.0), "Backward FS list round-trips");

    // Build backward AHDR (dest→source) and onion-encrypt a sample payload at the destination
    let mut rng2 = XorShift64(0x7777_8888_9999_aaaa);
    let mut keys_b_rev = keys_b.clone(); keys_b_rev.reverse();
    let mut fses_b_rev = fses_b.clone(); fses_b_rev.reverse();
    let mut ah = ahdr::create_ahdr(&keys_b_rev, &fses_b_rev, rmax, &mut rng2).expect("create ahdr");

    // Destination prepares data and IV, and each hop processes AHDR and adds a layer
    let mut payload = vec![0u8; 96];
    for i in 0..payload.len() { payload[i] = (0x30 + (i as u8)) ^ 0x33; }
    let mut iv = { let mut v = [0u8; 16]; rng.fill_bytes(&mut v); v };
    for hop in (0..lb).rev() { // farthest to nearest
        let pr = ahdr::proc_ahdr(&nodes_b[hop].2, &ah, Exp(0)).expect("proc ahdr");
        onion::add_layer(&pr.s, &mut iv, &mut payload).expect("add layer");
        ah = pr.ahdr_next;
    }

    // Source removes layers to recover original data
    let mut orig = vec![0u8; 96]; for i in 0..orig.len() { orig[i] = (0x30 + (i as u8)) ^ 0x33; }
    let mut iv2 = iv; let mut data2 = payload.clone();
    for k in (0..lb).rev() { onion::remove_layer(&keys_b_rev[k], &mut iv2, &mut data2).expect("remove layer"); }
    assert_eq!(data2, orig);

    println!("Strict Sphinx E2E completed: FS and AHDR flows verified.");
}
