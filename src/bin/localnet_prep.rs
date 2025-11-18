use hornet::policy::plonk::PlonkPolicy;
use hornet::policy::Blocklist;
use hornet::routing::{self, IpAddr, RouteElem};
use hornet::setup::directory::to_signed_json;
use hornet::setup::directory::{DirectoryAnnouncement, RouteAnnouncement};
use hornet::utils::encode_hex;
use serde::Serialize;
use std::env;
use std::fs;
use std::net::Ipv4Addr;

const DEFAULT_BLOCKLIST: &str = "config/blocklist.json";
const LOCAL_SECRET: &str = "localnet-secret";
const DIRECTORY_EPOCH: u64 = 1_700_000_000;

fn main() {
    if let Err(err) = run() {
        eprintln!("localnet prep failed: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let blocklist_path =
        env::var("LOCALNET_BLOCKLIST").unwrap_or_else(|_| DEFAULT_BLOCKLIST.to_string());
    let block_json = fs::read_to_string(&blocklist_path)?;
    let blocklist =
        Blocklist::from_json(&block_json).map_err(|err| format!("blocklist error: {err:?}"))?;
    let policy = PlonkPolicy::new_from_blocklist(b"localnet-demo", &blocklist)
        .map_err(|err| format!("policy init failed: {err:?}"))?;
    let metadata = policy.metadata(900, 0);
    fs::create_dir_all("config/localnet")?;

    let routers = [
        RouterSpec {
            name: "router-entry",
            bind: "127.0.0.1:7101",
            storage_path: "target/localnet/router-entry-state.json",
            route: RouteElem::NextHop {
                addr: IpAddr::V4(parse_ipv4("127.0.0.1")),
                port: 7102,
            },
        },
        RouterSpec {
            name: "router-middle",
            bind: "127.0.0.1:7102",
            storage_path: "target/localnet/router-middle-state.json",
            route: RouteElem::NextHop {
                addr: IpAddr::V4(parse_ipv4("127.0.0.1")),
                port: 7103,
            },
        },
        RouterSpec {
            name: "router-exit",
            bind: "127.0.0.1:7103",
            storage_path: "target/localnet/router-exit-state.json",
            route: RouteElem::ExitTcp {
                addr: IpAddr::V4(parse_ipv4("127.0.0.1")),
                port: 7200,
                tls: false,
            },
        },
    ];

    for spec in routers.iter() {
        write_directory(spec, &metadata)?;
        write_env(spec)?;
    }
    let policy_info = PolicyInfo {
        policy_id: encode_hex(&metadata.policy_id),
        directory_secret: LOCAL_SECRET.to_string(),
        routers: routers
            .iter()
            .map(|spec| RouterInfo {
                name: spec.name.to_string(),
                bind: spec.bind.to_string(),
                directory_path: format!("config/localnet/{}.directory.json", spec.name),
                storage_path: spec.storage_path.to_string(),
                env_file: format!("config/localnet/{}.env", spec.name),
            })
            .collect(),
    };
    let policy_json = serde_json::to_string_pretty(&policy_info)?;
    fs::write("config/localnet/policy-info.json", policy_json)?;
    println!("generated config/localnet for 3-router demo");
    Ok(())
}

fn write_directory(
    spec: &RouterSpec,
    metadata: &hornet::policy::PolicyMetadata,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut directory = DirectoryAnnouncement::new();
    directory.push_policy(metadata.clone());
    let segment = routing::segment_from_elems(&[spec.route.clone()]);
    directory.push_route(RouteAnnouncement {
        policy_id: metadata.policy_id,
        segment,
        interface: Some(spec.name.to_string()),
    });
    let signed = to_signed_json(&directory, LOCAL_SECRET.as_bytes(), DIRECTORY_EPOCH)
        .map_err(|err| format!("directory signing failed for {}: {err:?}", spec.name))?;
    let path = format!("config/localnet/{}.directory.json", spec.name);
    fs::write(path, signed)?;
    Ok(())
}

fn write_env(spec: &RouterSpec) -> Result<(), Box<dyn std::error::Error>> {
    let env_contents = format!(
        "HORNET_DIR_URL=https://localnet.invalid/{name}\n\
HORNET_DIR_SECRET={secret}\n\
HORNET_ROUTER_BIND={bind}\n\
HORNET_STORAGE_PATH={storage}\n\
HORNET_DIRECTORY_PATH=config/localnet/{name}.directory.json\n\
HORNET_DIR_INTERVAL=5\n",
        name = spec.name,
        secret = LOCAL_SECRET,
        bind = spec.bind,
        storage = spec.storage_path,
    );
    let path = format!("config/localnet/{}.env", spec.name);
    fs::create_dir_all("target/localnet")?;
    fs::write(path, env_contents)?;
    Ok(())
}

fn parse_ipv4(addr: &str) -> [u8; 4] {
    let parsed = addr
        .parse::<Ipv4Addr>()
        .unwrap_or(Ipv4Addr::new(127, 0, 0, 1));
    parsed.octets()
}

#[derive(Clone)]
struct RouterSpec {
    name: &'static str,
    bind: &'static str,
    storage_path: &'static str,
    route: RouteElem,
}

#[derive(Serialize)]
struct RouterInfo {
    name: String,
    bind: String,
    directory_path: String,
    storage_path: String,
    env_file: String,
}

#[derive(Serialize)]
struct PolicyInfo {
    policy_id: String,
    directory_secret: String,
    routers: Vec<RouterInfo>,
}
