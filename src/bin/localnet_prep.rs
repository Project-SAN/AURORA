use hornet::crypto::zkp::Circuit;
use hornet::policy::zkboo::ZkBooPolicy;
use hornet::routing::{self, IpAddr, RouteElem};
use hornet::setup::directory::{from_signed_json, public_key_from_seed, to_signed_json};
use hornet::setup::directory::{DirectoryAnnouncement, RouteAnnouncement};
use hornet::utils::encode_hex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::net::Ipv4Addr;

const LOCAL_SECRET: &str = "localnet-secret";
const DIRECTORY_EPOCH: u64 = 1_700_000_000;

fn main() {
    if let Err(err) = run() {
        eprintln!("localnet prep failed: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let qemu = args.iter().any(|arg| arg == "--qemu");
    let qemu_from_localnet = args.iter().any(|arg| arg == "--qemu-from-localnet");
    if qemu_from_localnet {
        return run_qemu_from_localnet();
    }
    let out_dir = if qemu {
        "config/qemu"
    } else {
        "config/localnet"
    };
    let storage_dir = if qemu {
        "target/qemu"
    } else {
        "target/localnet"
    };

    let path = env::var("LOCALNET_ZKBOO_CIRCUIT_PATH")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or("ZKBoo-only: set LOCALNET_ZKBOO_CIRCUIT_PATH to a ZKBC circuit file")?;
    let bytes = fs::read(&path)?;
    let circuit = Circuit::decode(&bytes)
        .map_err(|err| format!("failed to decode ZKBoo circuit ({path}): {err:?}"))?;
    let policy = ZkBooPolicy::new(circuit);
    let metadata = policy.metadata(900, 0);
    fs::create_dir_all(out_dir)?;
    fs::create_dir_all(storage_dir)?;

    let routers = if qemu {
        let host = "10.0.2.2";
        vec![
            RouterSpec {
                name: "router-entry",
                bind: format!("{host}:17011"),
                storage_path: format!("{storage_dir}/router-entry-state.json"),
                route: RouteElem::NextHop {
                    addr: IpAddr::V4(parse_ipv4(host)),
                    port: 17012,
                },
            },
            RouterSpec {
                name: "router-middle",
                bind: format!("{host}:17012"),
                storage_path: format!("{storage_dir}/router-middle-state.json"),
                route: RouteElem::NextHop {
                    addr: IpAddr::V4(parse_ipv4(host)),
                    port: 17013,
                },
            },
            RouterSpec {
                name: "router-exit",
                bind: format!("{host}:17013"),
                storage_path: format!("{storage_dir}/router-exit-state.json"),
                route: RouteElem::ExitTcp {
                    addr: IpAddr::V4(parse_ipv4(host)),
                    port: 8080,
                    tls: false,
                },
            },
        ]
    } else {
        vec![
            RouterSpec {
                name: "router-entry",
                bind: "127.0.0.1:7101".to_string(),
                storage_path: format!("{storage_dir}/router-entry-state.json"),
                route: RouteElem::NextHop {
                    addr: IpAddr::V4(parse_ipv4("127.0.0.1")),
                    port: 7102,
                },
            },
            RouterSpec {
                name: "router-middle",
                bind: "127.0.0.1:7102".to_string(),
                storage_path: format!("{storage_dir}/router-middle-state.json"),
                route: RouteElem::NextHop {
                    addr: IpAddr::V4(parse_ipv4("127.0.0.1")),
                    port: 7103,
                },
            },
            RouterSpec {
                name: "router-exit",
                bind: "127.0.0.1:7103".to_string(),
                storage_path: format!("{storage_dir}/router-exit-state.json"),
                route: RouteElem::ExitTcp {
                    addr: IpAddr::V4(parse_ipv4("127.0.0.1")),
                    port: 7200,
                    tls: false,
                },
            },
        ]
    };

    for spec in routers.iter() {
        write_directory(spec, &metadata, out_dir)?;
        write_router_config(spec, out_dir)?;
        if !qemu {
            write_env(spec, out_dir)?;
        }
    }
    let policy_info = PolicyInfo {
        policy_id: encode_hex(&metadata.policy_id),
        directory_public_key: encode_hex(&local_public_key()),
        routers: routers
            .iter()
            .map(|spec| RouterInfo {
                name: spec.name.to_string(),
                bind: spec.bind.to_string(),
                directory_path: format!("{out_dir}/{}.directory.json", spec.name),
                storage_path: spec.storage_path.to_string(),
                env_file: if qemu {
                    String::new()
                } else {
                    format!("{out_dir}/{}.env", spec.name)
                },
            })
            .collect(),
    };
    let policy_json = serde_json::to_string_pretty(&policy_info)?;
    let policy_path = format!("{out_dir}/policy-info.json");
    fs::write(policy_path, policy_json)?;
    println!("generated {out_dir} for 3-router demo");
    Ok(())
}

fn run_qemu_from_localnet() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = "config/qemu";
    let storage_dir = "target/qemu";
    fs::create_dir_all(out_dir)?;
    fs::create_dir_all(storage_dir)?;

    let host = "10.0.2.2";
    let routers = [
        RouterSpec {
            name: "router-entry",
            bind: format!("{host}:17011"),
            storage_path: format!("{storage_dir}/router-entry-state.json"),
            route: RouteElem::NextHop {
                addr: IpAddr::V4(parse_ipv4(host)),
                port: 17012,
            },
        },
        RouterSpec {
            name: "router-middle",
            bind: format!("{host}:17012"),
            storage_path: format!("{storage_dir}/router-middle-state.json"),
            route: RouteElem::NextHop {
                addr: IpAddr::V4(parse_ipv4(host)),
                port: 17013,
            },
        },
        RouterSpec {
            name: "router-exit",
            bind: format!("{host}:17013"),
            storage_path: format!("{storage_dir}/router-exit-state.json"),
            route: RouteElem::ExitTcp {
                addr: IpAddr::V4(parse_ipv4(host)),
                port: 8080,
                tls: false,
            },
        },
    ];

    let local_info: PolicyInfo =
        serde_json::from_str(&fs::read_to_string("config/localnet/policy-info.json")?)?;
    for spec in routers.iter() {
        let local_path = format!("config/localnet/{}.directory.json", spec.name);
        let signed = fs::read_to_string(local_path)?;
        let announcement = from_signed_json(&signed, &local_public_key())
            .map_err(|err| format!("invalid localnet directory: {err:?}"))?;
        let mut directory = DirectoryAnnouncement::new();
        for policy in announcement.policies() {
            directory.push_policy(policy.clone());
        }
        let policy_id = announcement
            .policies()
            .first()
            .ok_or("no policies in localnet directory")?
            .policy_id;
        let segment = routing::segment_from_elems(std::slice::from_ref(&spec.route));
        directory.push_route(RouteAnnouncement {
            policy_id,
            segment,
            interface: Some(spec.name.to_string()),
        });
        let signed = to_signed_json(&directory, &local_private_key(), DIRECTORY_EPOCH)
            .map_err(|err| format!("directory signing failed: {err:?}"))?;
        let path = format!("{out_dir}/{}.directory.json", spec.name);
        fs::write(path, signed)?;
        write_router_config(spec, out_dir)?;
    }

    let policy_info = PolicyInfo {
        policy_id: local_info.policy_id,
        directory_public_key: encode_hex(&local_public_key()),
        routers: routers
            .iter()
            .map(|spec| RouterInfo {
                name: spec.name.to_string(),
                bind: spec.bind.to_string(),
                directory_path: format!("{out_dir}/{}.directory.json", spec.name),
                storage_path: spec.storage_path.to_string(),
                env_file: String::new(),
            })
            .collect(),
    };
    let policy_json = serde_json::to_string_pretty(&policy_info)?;
    let policy_path = format!("{out_dir}/policy-info.json");
    fs::write(policy_path, policy_json)?;
    println!("generated {out_dir} for qemu (from localnet)");
    Ok(())
}

fn write_directory(
    spec: &RouterSpec,
    metadata: &hornet::policy::PolicyMetadata,
    out_dir: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut directory = DirectoryAnnouncement::new();
    directory.push_policy(metadata.clone());
    let segment = routing::segment_from_elems(std::slice::from_ref(&spec.route));
    directory.push_route(RouteAnnouncement {
        policy_id: metadata.policy_id,
        segment,
        interface: Some(spec.name.to_string()),
    });
    let signed = to_signed_json(&directory, &local_private_key(), DIRECTORY_EPOCH)
        .map_err(|err| format!("directory signing failed for {}: {err:?}", spec.name))?;
    let path = format!("{out_dir}/{}.directory.json", spec.name);
    fs::write(path, signed)?;
    Ok(())
}

fn write_env(spec: &RouterSpec, out_dir: &str) -> Result<(), Box<dyn std::error::Error>> {
    let env_contents = format!(
        "HORNET_DIR_URL=https://localnet.invalid/{name}\n\
HORNET_DIR_PUBKEY={pubkey}\n\
HORNET_ROUTER_ID={name}\n\
HORNET_ROUTER_BIND={bind}\n\
HORNET_STORAGE_PATH={storage}\n\
HORNET_DIRECTORY_PATH={out_dir}/{name}.directory.json\n\
HORNET_DIR_INTERVAL=5\n",
        name = spec.name,
        pubkey = encode_hex(&local_public_key()),
        bind = spec.bind,
        storage = spec.storage_path,
        out_dir = out_dir,
    );
    let path = format!("{out_dir}/{}.env", spec.name);
    fs::write(path, env_contents)?;
    Ok(())
}

fn write_router_config(spec: &RouterSpec, out_dir: &str) -> Result<(), Box<dyn std::error::Error>> {
    let config = RouterConfigFile {
        listen_port: 7000,
        cli_port: 7001,
        storage_path: "/router_state.json".to_string(),
        directory_path: "/directory.json".to_string(),
        directory_public_key: encode_hex(&local_public_key()),
        router_id: spec.name.to_string(),
    };
    let json = serde_json::to_string_pretty(&config)?;
    let path = format!("{out_dir}/{}.router_config.json", spec.name);
    fs::write(path, json)?;
    Ok(())
}

fn parse_ipv4(addr: &str) -> [u8; 4] {
    let parsed = addr
        .parse::<Ipv4Addr>()
        .unwrap_or(Ipv4Addr::new(127, 0, 0, 1));
    parsed.octets()
}

fn local_private_key() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(LOCAL_SECRET.as_bytes());
    let hash = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&hash[..32]);
    seed
}

fn local_public_key() -> [u8; 32] {
    let seed = local_private_key();
    public_key_from_seed(&seed)
}

#[derive(Clone)]
struct RouterSpec {
    name: &'static str,
    bind: String,
    storage_path: String,
    route: RouteElem,
}

#[derive(Serialize, Deserialize)]
struct RouterInfo {
    name: String,
    bind: String,
    directory_path: String,
    storage_path: String,
    env_file: String,
}

#[derive(Serialize, Deserialize)]
struct PolicyInfo {
    policy_id: String,
    directory_public_key: String,
    routers: Vec<RouterInfo>,
}

#[derive(Serialize)]
struct RouterConfigFile {
    listen_port: u16,
    cli_port: u16,
    storage_path: String,
    directory_path: String,
    directory_public_key: String,
    router_id: String,
}
