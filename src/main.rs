use rand::RngCore;
use rand::SeedableRng;
use std::env;
use std::fs::File;
use std::io::{Read, Write};

fn print_usage() {
    let usage = r#"HORNET CLI

Usage:
  hornet help
  hornet gen-x25519 [--seed <hex32>]
  hornet route-encode <elem> [...]
  hornet route-decode <hex>
  hornet wire-encode <setup|data> <hops> <specific_hex> <ahdr_hex> <payload_hex>
  hornet wire-decode <hex>
  hornet demo-setup <hops>
  hornet demo-forward <hops> <payload_len>

Examples:
  hornet gen-x25519
  hornet route-encode nh4:192.0.2.1:9000 exit4:93.184.216.34:443:tls
  hornet route-decode 0110c000020100230711015db8d82201bb
  hornet wire-decode 01... (hex)
  hornet demo-setup 3
  hornet demo-forward 3 64
"#;
    eprintln!("{}", usage);
}

fn hex_to_bytes(s: &str) -> Result<Vec<u8>, String> {
    let t = s.trim();
    if t.len() % 2 != 0 {
        return Err("HEX must have even length".into());
    }
    let mut out = Vec::with_capacity(t.len() / 2);
    let bytes = t.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let h = (bytes[i] as char)
            .to_digit(16)
            .ok_or_else(|| "invalid HEX".to_string())?;
        let l = (bytes[i + 1] as char)
            .to_digit(16)
            .ok_or_else(|| "invalid HEX".to_string())?;
        out.push(((h << 4) | l) as u8);
        i += 2;
    }
    Ok(out)
}

fn bytes_to_hex(b: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = Vec::with_capacity(b.len() * 2);
    for &x in b {
        out.push(HEX[(x >> 4) as usize]);
        out.push(HEX[(x & 0x0f) as usize]);
    }
    String::from_utf8(out).unwrap()
}

fn os_random(buf: &mut [u8]) -> std::io::Result<()> {
    // Best-effort: read from /dev/urandom (may fail on non-Unix)
    if let Ok(mut f) = File::open("/dev/urandom") {
        let mut read = 0usize;
        while read < buf.len() {
            let n = f.read(&mut buf[read..])?;
            if n == 0 {
                break;
            }
            read += n;
        }
        if read == buf.len() {
            return Ok(());
        }
    }
    // Fallback: time-based weak seeding (demo-only)
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    let mut x = t.as_nanos() as u64;
    for b in buf.iter_mut() {
        // xorshift64*
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        let z = x.wrapping_mul(0x2545F4914F6CDD1D);
        *b = (z & 0xff) as u8;
    }
    Ok(())
}

fn parse_ipv4(s: &str) -> Result<[u8; 4], String> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return Err("IPv4 required (e.g., 192.0.2.1)".into());
    }
    let mut ip = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        let v: u8 = p
            .parse::<u8>()
            .map_err(|_| "invalid IPv4 octet".to_string())?;
        ip[i] = v;
    }
    Ok(ip)
}

fn parse_ipv6(s: &str) -> Result<[u8; 16], String> {
    // Parse via std and return 16-byte octets
    let addr: std::net::Ipv6Addr = s.parse().map_err(|_| "invalid IPv6".to_string())?;
    Ok(addr.octets())
}

fn cmd_gen_x25519(args: &[String]) -> Result<(), String> {
    let mut sk = [0u8; 32];
    let mut seed_opt: Option<[u8; 32]> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--seed" => {
                if i + 1 >= args.len() {
                    return Err("--seed requires 32-byte HEX".into());
                }
                let v = hex_to_bytes(&args[i + 1])?;
                if v.len() != 32 {
                    return Err("seed must be 32-byte HEX".into());
                }
                let mut s = [0u8; 32];
                s.copy_from_slice(&v);
                seed_opt = Some(s);
                i += 2;
                continue;
            }
            _ => return Err("unknown option".into()),
        }
    }
    if let Some(s) = seed_opt {
        sk = s;
    } else {
        os_random(&mut sk).map_err(|e| e.to_string())?;
    }
    // X25519 secret clamping
    sk[0] &= 248;
    sk[31] &= 127;
    sk[31] |= 64;
    let pk = x25519_dalek::x25519(sk, x25519_dalek::X25519_BASEPOINT_BYTES);
    println!("sk={}\npk={}", bytes_to_hex(&sk), bytes_to_hex(&pk));
    Ok(())
}

fn cmd_route_encode(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("provide at least one element".into());
    }
    let mut elems: Vec<hornet::routing::RouteElem> = Vec::new();
    for a in args {
        // Format: nh4:ip:port | nh6:ip:port | exit4:ip:port[:tls] | exit6:ip:port[:tls]
        let parts: Vec<&str> = a.split(':').collect();
        if parts.len() < 3 {
            return Err(format!("invalid element: {}", a));
        }
        match parts[0] {
            "nh4" => {
                let ip = parse_ipv4(parts[1])?;
                let port: u16 = parts[2].parse().map_err(|_| "invalid port".to_string())?;
                elems.push(hornet::routing::RouteElem::NextHop {
                    addr: hornet::routing::IpAddr::V4(ip),
                    port,
                });
            }
            "nh6" => {
                let ip = parse_ipv6(parts[1])?;
                let port: u16 = parts[2].parse().map_err(|_| "invalid port".to_string())?;
                elems.push(hornet::routing::RouteElem::NextHop {
                    addr: hornet::routing::IpAddr::V6(ip),
                    port,
                });
            }
            "exit4" => {
                let ip = parse_ipv4(parts[1])?;
                let port: u16 = parts[2].parse().map_err(|_| "invalid port".to_string())?;
                let tls = parts
                    .get(3)
                    .map(|v| v.to_ascii_lowercase() == "tls")
                    .unwrap_or(false);
                elems.push(hornet::routing::RouteElem::ExitTcp {
                    addr: hornet::routing::IpAddr::V4(ip),
                    port,
                    tls,
                });
            }
            "exit6" => {
                let ip = parse_ipv6(parts[1])?;
                let port: u16 = parts[2].parse().map_err(|_| "invalid port".to_string())?;
                let tls = parts
                    .get(3)
                    .map(|v| v.to_ascii_lowercase() == "tls")
                    .unwrap_or(false);
                elems.push(hornet::routing::RouteElem::ExitTcp {
                    addr: hornet::routing::IpAddr::V6(ip),
                    port,
                    tls,
                });
            }
            _ => return Err(format!("unknown kind: {}", parts[0])),
        }
    }
    let seg = hornet::routing::segment_from_elems(&elems);
    println!("{}", bytes_to_hex(&seg.0));
    Ok(())
}

fn cmd_route_decode(args: &[String]) -> Result<(), String> {
    if args.len() != 1 {
        return Err("provide exactly one HEX string".into());
    }
    let bytes = hex_to_bytes(&args[0])?;
    let seg = hornet::types::RoutingSegment(bytes);
    let elems =
        hornet::routing::elems_from_segment(&seg).map_err(|e| format!("decode failed: {:?}", e))?;
    for e in elems {
        match e {
            hornet::routing::RouteElem::NextHop {
                addr: hornet::routing::IpAddr::V4(ip),
                port,
            } => {
                println!(
                    "nh4:{}:{}",
                    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
                    port
                );
            }
            hornet::routing::RouteElem::NextHop {
                addr: hornet::routing::IpAddr::V6(ip),
                port,
            } => {
                let addr = std::net::Ipv6Addr::from(ip);
                println!("nh6:{}:{}", addr, port);
            }
            hornet::routing::RouteElem::ExitTcp {
                addr: hornet::routing::IpAddr::V4(ip),
                port,
                tls,
            } => {
                println!(
                    "exit4:{}:{}:{}",
                    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
                    port,
                    if tls { "tls" } else { "plain" }
                );
            }
            hornet::routing::RouteElem::ExitTcp {
                addr: hornet::routing::IpAddr::V6(ip),
                port,
                tls,
            } => {
                let addr = std::net::Ipv6Addr::from(ip);
                println!(
                    "exit6:{}:{}:{}",
                    addr,
                    port,
                    if tls { "tls" } else { "plain" }
                );
            }
        }
    }
    Ok(())
}

fn cmd_wire_encode(args: &[String]) -> Result<(), String> {
    if args.len() != 5 {
        return Err("<setup|data> <hops> <specific_hex> <ahdr_hex> <payload_hex>".into());
    }
    let typ_s = &args[0];
    let hops: u8 = args[1]
        .parse()
        .map_err(|_| "hops must be 0..255".to_string())?;
    let mut specific = [0u8; 16];
    let sp = hex_to_bytes(&args[2])?;
    if sp.len() != 16 {
        return Err("specific must be 16-byte HEX".into());
    }
    specific.copy_from_slice(&sp);
    let ah_bytes = hex_to_bytes(&args[3])?;
    let payload = hex_to_bytes(&args[4])?;
    let chdr = match typ_s.as_str() {
        "setup" => hornet::types::Chdr {
            typ: hornet::types::PacketType::Setup,
            hops,
            specific,
        },
        "data" => hornet::types::Chdr {
            typ: hornet::types::PacketType::Data,
            hops,
            specific,
        },
        _ => return Err("kind must be 'setup' or 'data'".into()),
    };
    let ahdr = hornet::types::Ahdr { bytes: ah_bytes };
    let bytes = hornet::wire::encode(&chdr, &ahdr, &payload);
    println!("{}", bytes_to_hex(&bytes));
    Ok(())
}

fn cmd_wire_decode(args: &[String]) -> Result<(), String> {
    if args.len() != 1 {
        return Err("provide exactly one HEX string".into());
    }
    let buf = hex_to_bytes(&args[0])?;
    let (ch, ah, pl) = hornet::wire::decode(&buf).map_err(|e| format!("decode failed: {:?}", e))?;
    let typ = match ch.typ {
        hornet::types::PacketType::Setup => "Setup",
        hornet::types::PacketType::Data => "Data",
    };
    println!(
        "type={} hops={} specific={} ahdr_len={} payload_len={}",
        typ,
        ch.hops,
        bytes_to_hex(&ch.specific),
        ah.bytes.len(),
        pl.len()
    );
    Ok(())
}

fn cmd_demo_setup(args: &[String]) -> Result<(), String> {
    if args.len() != 1 {
        return Err("specify <hops>".into());
    }
    let hops: usize = args[0].parse().map_err(|_| "invalid hops".to_string())?;
    if hops == 0 {
        return Err("hops must be >= 1".into());
    }
    let rmax = hops;
    // Pseudo-generate node public keys
    let mut pubs: Vec<[u8; 32]> = Vec::with_capacity(hops);
    let mut rng_seed = [0u8; 32];
    os_random(&mut rng_seed).map_err(|e| e.to_string())?;
    let mut rng = rand::rngs::SmallRng::from_seed(rng_seed);
    for _ in 0..hops {
        let mut sk = [0u8; 32];
        rng.fill_bytes(&mut sk);
        sk[0] &= 248;
        sk[31] &= 127;
        sk[31] |= 64;
        let pk = x25519_dalek::x25519(sk, x25519_dalek::X25519_BASEPOINT_BYTES);
        pubs.push(pk);
    }
    let mut x_s = [0u8; 32];
    os_random(&mut x_s).map_err(|e| e.to_string())?;
    x_s[0] &= 248;
    x_s[31] &= 127;
    x_s[31] |= 64;
    let exp = hornet::types::Exp(60); // demo: 60s
    let mut rng2 = rand::rngs::SmallRng::from_seed(rng_seed);
    let st = hornet::setup::source_init_strict(&x_s, &pubs, rmax, exp, &mut rng2);
    let sp_len = st.packet.payload.bytes.len();
    println!(
        "ephemeral_pub={} rmax={} fs_payload_len={} (c*r)",
        bytes_to_hex(&st.eph_pub),
        rmax,
        sp_len
    );
    println!(
        "chdr: type=Setup hops={} exp={} specific={}",
        st.packet.chdr.hops,
        exp.0,
        bytes_to_hex(&st.packet.chdr.specific)
    );
    println!("sphinx.beta_len={}", st.packet.shdr.beta.len());
    Ok(())
}

fn cmd_demo_forward(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        return Err("specify <hops> <payload_len>".into());
    }
    let hops: usize = args[0].parse().map_err(|_| "invalid hops".to_string())?;
    let plen: usize = args[1]
        .parse()
        .map_err(|_| "invalid payload_len".to_string())?;
    if hops == 0 {
        return Err("hops must be >= 1".into());
    }
    let mut pubs = Vec::with_capacity(hops);
    let mut rng_seed = [0u8; 32];
    os_random(&mut rng_seed).map_err(|e| e.to_string())?;
    let mut rng = rand::rngs::SmallRng::from_seed(rng_seed);
    for _ in 0..hops {
        let mut sk = [0u8; 32];
        rng.fill_bytes(&mut sk);
        sk[0] &= 248;
        sk[31] &= 127;
        sk[31] |= 64;
        let pk = x25519_dalek::x25519(sk, x25519_dalek::X25519_BASEPOINT_BYTES);
        pubs.push(pk);
    }
    let mut x_s = [0u8; 32];
    os_random(&mut x_s).map_err(|e| e.to_string())?;
    x_s[0] &= 248;
    x_s[31] &= 127;
    x_s[31] |= 64;
    let exp = hornet::types::Exp(60);
    let rmax = hops;
    let mut rng2 = rand::rngs::SmallRng::from_seed(rng_seed);
    let st = hornet::setup::source_init_strict(&x_s, &pubs, rmax, exp, &mut rng2);
    let mut chdr = hornet::packet::chdr::data_header(hops as u8, hornet::types::Nonce([0u8; 16]));
    let ahdr = hornet::types::Ahdr {
        bytes: vec![0u8; rmax * hornet::types::C_BLOCK],
    }; // not used in this demo
    let mut iv0 = hornet::types::Nonce([0u8; 16]);
    os_random(&mut iv0.0).map_err(|e| e.to_string())?;
    let mut payload = vec![0u8; plen];
    for i in 0..plen {
        payload[i] = (i as u8).wrapping_mul(3).wrapping_add(5);
    }
    let plain = payload.clone();
    hornet::source::build_data_packet(&mut chdr, &ahdr, &st.keys_f, &mut iv0, &mut payload)
        .map_err(|e| format!("build failed: {:?}", e))?;
    println!(
        "iv_on_wire={} cipher={}... (len={})",
        bytes_to_hex(&chdr.specific),
        bytes_to_hex(&payload[..std::cmp::min(32, payload.len())]),
        payload.len()
    );
    // Decrypt at source: peel all layers
    let mut iv = chdr.specific;
    for i in 0..st.keys_f.len() {
        hornet::packet::onion::remove_layer(&st.keys_f[i], &mut iv, &mut payload)
            .map_err(|e| format!("onion failed: {:?}", e))?;
    }
    println!("recovered_match={}", (payload == plain) as u8);
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        print_usage();
        return;
    }
    let (cmd, rest) = (&args[0], &args[1..]);
    let res = match cmd.as_str() {
        "help" | "-h" | "--help" => {
            print_usage();
            Ok(())
        }
        "gen-x25519" => cmd_gen_x25519(rest),
        "route-encode" => cmd_route_encode(rest),
        "route-decode" => cmd_route_decode(rest),
        "wire-encode" => cmd_wire_encode(rest),
        "wire-decode" => cmd_wire_decode(rest),
        "demo-setup" => cmd_demo_setup(rest),
        "demo-forward" => cmd_demo_forward(rest),
        _ => {
            eprintln!("unknown command: {}", cmd);
            print_usage();
            Ok(())
        }
    };
    if let Err(e) = res {
        let _ = writeln!(std::io::stderr(), "error: {}", e);
        std::process::exit(1);
    }
}
