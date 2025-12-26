use hornet::policy::plonk::{PlonkPolicy, PolicyRole};
use hornet::policy::Blocklist;
use hornet::policy::oprf;
use hornet::routing::{self, IpAddr, RouteElem};
use hornet::setup::directory::to_signed_json;
use hornet::setup::directory::{DirectoryAnnouncement, RouteAnnouncement};
use hornet::utils::encode_hex;
use hornet::utils::decode_hex;
use serde::Serialize;
use std::env;
use std::fs;
use std::net::Ipv4Addr;

const DEFAULT_BLOCKLIST: &str = "config/blocklist.json";
const LOCAL_SECRET: &str = "localnet-secret";
const DIRECTORY_EPOCH: u64 = 1_700_000_000;
const DEFAULT_POLICY_LABEL: &str = "localnet-demo";

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
    let policy_label = policy_label_from_env();
    let oprf_key = oprf_key_from_env_or_label(policy_label.as_bytes())?;
    let oprf_blocklist = oprf_blocklist_from(&blocklist, &oprf_key);
    let (open_meta, parse_meta, check_meta) =
        build_policies(&policy_label, &oprf_blocklist)?;
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

    let hop_policies = vec![
        ("router-entry".to_string(), open_meta.policy_id),
        ("router-middle".to_string(), parse_meta.policy_id),
        ("router-exit".to_string(), check_meta.policy_id),
    ];
    let all_meta = vec![open_meta.clone(), parse_meta.clone(), check_meta.clone()];
    for spec in routers.iter() {
        write_directory(spec, &all_meta, &hop_policies)?;
        write_env(spec)?;
    }
    let policy_info = PolicyInfo {
        policy_id: encode_hex(&open_meta.policy_id),
        policy_id_open: Some(encode_hex(&open_meta.policy_id)),
        policy_id_parse: Some(encode_hex(&parse_meta.policy_id)),
        policy_id_check: Some(encode_hex(&check_meta.policy_id)),
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

fn oprf_key_from_env_or_label(label: &[u8]) -> Result<curve25519_dalek::scalar::Scalar, Box<dyn std::error::Error>> {
    match env::var("POLICY_OPRF_KEY_HEX") {
        Ok(hex) => {
            let seed = decode_hex(hex.as_str())
                .map_err(|err| format!("OPRF key hex error: {err}"))?;
            Ok(oprf::derive_key_from_seed(&seed))
        }
        Err(_) => Ok(oprf::derive_key_from_seed(label)),
    }
}

fn policy_label_from_env() -> String {
    env::var("POLICY_LABEL").unwrap_or_else(|_| DEFAULT_POLICY_LABEL.to_string())
}

fn build_policies(
    base_label: &str,
    blocklist: &Blocklist,
) -> Result<
    (
        hornet::policy::PolicyMetadata,
        hornet::policy::PolicyMetadata,
        hornet::policy::PolicyMetadata,
    ),
    Box<dyn std::error::Error>,
> {
    let open_label = format!("{base_label}-open");
    let parse_label = format!("{base_label}-parse");
    let check_label = format!("{base_label}-check");
    let open_policy =
        PlonkPolicy::new_from_blocklist_with_role(open_label.as_bytes(), blocklist, PolicyRole::Open)
        .map_err(|err| format!("policy init failed (open): {err:?}"))?;
    let parse_policy =
        PlonkPolicy::new_from_blocklist_with_role(parse_label.as_bytes(), blocklist, PolicyRole::Parse)
        .map_err(|err| format!("policy init failed (parse): {err:?}"))?;
    let check_policy =
        PlonkPolicy::new_from_blocklist_with_role(check_label.as_bytes(), blocklist, PolicyRole::Check)
        .map_err(|err| format!("policy init failed (check): {err:?}"))?;
    Ok((
        open_policy.metadata_for_role(900, PolicyRole::Open),
        parse_policy.metadata_for_role(900, PolicyRole::Parse),
        check_policy.metadata_for_role(900, PolicyRole::Check),
    ))
}

fn oprf_blocklist_from(
    blocklist: &Blocklist,
    key: &curve25519_dalek::scalar::Scalar,
) -> Blocklist {
    let mut leaves = Vec::with_capacity(blocklist.len());
    for entry in blocklist.entries() {
        let leaf = entry.leaf_bytes();
        let evaluated = oprf::eval_unblinded(key, &leaf);
        leaves.push(evaluated.to_vec());
    }
    Blocklist::from_canonical_bytes(leaves)
}

fn write_directory(
    spec: &RouterSpec,
    metadata: &[hornet::policy::PolicyMetadata],
    hop_policies: &[(String, hornet::policy::PolicyId)],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut directory = DirectoryAnnouncement::new();
    for meta in metadata {
        directory.push_policy(meta.clone());
    }
    for (name, policy_id) in hop_policies {
        directory.push_hop_policy(name.as_str(), *policy_id);
    }
    let segment = routing::segment_from_elems(&[spec.route.clone()]);
    directory.push_route(RouteAnnouncement {
        policy_id: metadata
            .first()
            .ok_or("missing policy metadata")?
            .policy_id,
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
HORNET_ROUTER_NAME={name}\n\
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
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_id_open: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_id_parse: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_id_check: Option<String>,
    directory_secret: String,
    routers: Vec<RouterInfo>,
}
