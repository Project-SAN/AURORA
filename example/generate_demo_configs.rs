use std::fs;
use std::path::{Path, PathBuf};

use aurora::demo::{
    demo_policy_metadata_from_blocklist_json, DEFAULT_DEMO_HOST_HEADER_OFFSET,
    DEFAULT_DEMO_POLICY_EXPIRY, DEFAULT_DEMO_POLICY_PAYLOAD_LEN, DEMO_DIRECTORY_SEED,
};
use aurora::routing::{self, IpAddr, RouteElem};
use aurora::setup::directory::{
    public_key_from_seed, to_signed_json, DirectoryAnnouncement, RouteAnnouncement,
};

fn main() {
    if let Err(err) = run() {
        eprintln!("generate_demo_configs error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let blocklist_json = fs::read_to_string(root.join("config/blocklist.json"))
        .map_err(|err| format!("read config/blocklist.json: {err}"))?;
    let metadata = demo_policy_metadata_from_blocklist_json(
        &blocklist_json,
        DEFAULT_DEMO_POLICY_EXPIRY,
        DEFAULT_DEMO_POLICY_PAYLOAD_LEN,
        DEFAULT_DEMO_HOST_HEADER_OFFSET,
    )
    .map_err(|err| format!("build policy metadata: {err:?}"))?;

    let public_key = public_key_from_seed(&DEMO_DIRECTORY_SEED);
    let public_key_hex = hex_encode(&public_key);
    let policy_id_hex = hex_encode(&metadata.policy_id);

    write_directory_group(
        &root,
        &[
            "config/localnet/router-entry.directory.json",
            "config/localnet/router-middle.directory.json",
            "config/localnet/router-exit.directory.json",
        ],
        &metadata,
        &[
            route("router-entry", [127, 0, 0, 1], 7102, false),
            route("router-middle", [127, 0, 0, 1], 7103, false),
            route("router-exit", [127, 0, 0, 1], 7200, true),
        ],
    )?;
    write_directory_group(
        &root,
        &[
            "config/qemu/router-entry.directory.json",
            "config/qemu/router-middle.directory.json",
            "config/qemu/router-exit.directory.json",
        ],
        &metadata,
        &[
            route("router-entry", [10, 0, 2, 2], 18112, false),
            route("router-middle", [10, 0, 2, 2], 18113, false),
            route("router-exit", [10, 0, 2, 2], 8080, true),
        ],
    )?;

    write_policy_info(
        &root.join("config/localnet/policy-info.json"),
        &policy_id_hex,
        &public_key_hex,
        &[
            RouterPolicyInfo::new(
                "router-entry",
                "127.0.0.1:7101",
                "config/localnet/router-entry.directory.json",
                "target/localnet/router-entry-state.json",
                "config/localnet/router-entry.env",
            ),
            RouterPolicyInfo::new(
                "router-middle",
                "127.0.0.1:7102",
                "config/localnet/router-middle.directory.json",
                "target/localnet/router-middle-state.json",
                "config/localnet/router-middle.env",
            ),
            RouterPolicyInfo::new(
                "router-exit",
                "127.0.0.1:7103",
                "config/localnet/router-exit.directory.json",
                "target/localnet/router-exit-state.json",
                "config/localnet/router-exit.env",
            ),
        ],
    )?;
    write_policy_info(
        &root.join("config/qemu/policy-info.json"),
        &policy_id_hex,
        &public_key_hex,
        &[
            RouterPolicyInfo::new(
                "router-entry",
                "10.0.2.2:18111",
                "config/qemu/router-entry.directory.json",
                "target/qemu/router-entry-state.json",
                "",
            ),
            RouterPolicyInfo::new(
                "router-middle",
                "10.0.2.2:18112",
                "config/qemu/router-middle.directory.json",
                "target/qemu/router-middle-state.json",
                "",
            ),
            RouterPolicyInfo::new(
                "router-exit",
                "10.0.2.2:18113",
                "config/qemu/router-exit.directory.json",
                "target/qemu/router-exit-state.json",
                "",
            ),
        ],
    )?;
    write_policy_info(
        &root.join("config/qemu/policy-info.host.json"),
        &policy_id_hex,
        &public_key_hex,
        &[
            RouterPolicyInfo::new(
                "router-entry",
                "127.0.0.1:18111",
                "config/qemu/router-entry.directory.json",
                "target/qemu/router-entry-state.json",
                "config/qemu/router-entry.host.env",
            ),
            RouterPolicyInfo::new(
                "router-middle",
                "127.0.0.1:18112",
                "config/qemu/router-middle.directory.json",
                "target/qemu/router-middle-state.json",
                "config/qemu/router-middle.host.env",
            ),
            RouterPolicyInfo::new(
                "router-exit",
                "127.0.0.1:18113",
                "config/qemu/router-exit.directory.json",
                "target/qemu/router-exit-state.json",
                "config/qemu/router-exit.host.env",
            ),
        ],
    )?;

    for (path, router_id) in [
        ("config/localnet/router-entry.env", "router-entry"),
        ("config/localnet/router-middle.env", "router-middle"),
        ("config/localnet/router-exit.env", "router-exit"),
        ("config/qemu/router-entry.host.env", "router-entry"),
        ("config/qemu/router-middle.host.env", "router-middle"),
        ("config/qemu/router-exit.host.env", "router-exit"),
    ] {
        rewrite_env_public_key(&root.join(path), &public_key_hex, router_id)?;
    }

    for path in [
        "config/localnet/router-entry.router_config.json",
        "config/localnet/router-middle.router_config.json",
        "config/localnet/router-exit.router_config.json",
        "config/qemu/router-entry.router_config.json",
        "config/qemu/router-middle.router_config.json",
        "config/qemu/router-exit.router_config.json",
    ] {
        rewrite_router_config_public_key(&root.join(path), &public_key_hex)?;
    }

    println!("policy_id={policy_id_hex}");
    println!("directory_public_key={public_key_hex}");
    Ok(())
}

fn route(interface: &str, ip: [u8; 4], port: u16, exit: bool) -> RouteAnnouncement {
    let elem = if exit {
        RouteElem::ExitTcp {
            addr: IpAddr::V4(ip),
            port,
        }
    } else {
        RouteElem::NextHop {
            addr: IpAddr::V4(ip),
            port,
        }
    };
    RouteAnnouncement {
        policy_id: [0u8; 32],
        segment: routing::segment_from_elems(&[elem]),
        interface: Some(interface.to_string()),
    }
}

fn write_directory_group(
    root: &Path,
    files: &[&str],
    metadata: &aurora::policy::PolicyMetadata,
    routes: &[RouteAnnouncement],
) -> Result<(), String> {
    let mut directory = DirectoryAnnouncement::with_policy(metadata.clone());
    for route in routes {
        directory.push_route(RouteAnnouncement {
            policy_id: metadata.policy_id,
            segment: route.segment.clone(),
            interface: route.interface.clone(),
        });
    }
    let body = to_signed_json(&directory, &DEMO_DIRECTORY_SEED, 1_700_000_000)
        .map_err(|err| format!("sign directory: {err:?}"))?;
    for file in files {
        fs::write(root.join(file), &body).map_err(|err| format!("write {file}: {err}"))?;
    }
    Ok(())
}

#[derive(serde::Serialize)]
struct PolicyInfo<'a> {
    policy_id: &'a str,
    directory_public_key: &'a str,
    routers: &'a [RouterPolicyInfo<'a>],
}

#[derive(serde::Serialize)]
struct RouterPolicyInfo<'a> {
    name: &'a str,
    bind: &'a str,
    directory_path: &'a str,
    storage_path: &'a str,
    env_file: &'a str,
}

impl<'a> RouterPolicyInfo<'a> {
    const fn new(
        name: &'a str,
        bind: &'a str,
        directory_path: &'a str,
        storage_path: &'a str,
        env_file: &'a str,
    ) -> Self {
        Self {
            name,
            bind,
            directory_path,
            storage_path,
            env_file,
        }
    }
}

fn write_policy_info(
    path: &Path,
    policy_id: &str,
    public_key: &str,
    routers: &[RouterPolicyInfo<'_>],
) -> Result<(), String> {
    let body = serde_json::to_string_pretty(&PolicyInfo {
        policy_id,
        directory_public_key: public_key,
        routers,
    })
    .map_err(|err| format!("serialize {}: {err}", path.display()))?;
    fs::write(path, format!("{body}\n")).map_err(|err| format!("write {}: {err}", path.display()))
}

fn rewrite_env_public_key(path: &Path, public_key: &str, router_id: &str) -> Result<(), String> {
    let body = fs::read_to_string(path).map_err(|err| format!("read {}: {err}", path.display()))?;
    let mut out = String::new();
    for line in body.lines() {
        if let Some((_key, _value)) = line.split_once("HORNET_DIR_PUBKEY=") {
            out.push_str("HORNET_DIR_PUBKEY=");
            out.push_str(public_key);
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    if !out.contains(&format!("HORNET_ROUTER_ID={router_id}")) {
        return Err(format!("unexpected env file shape: {}", path.display()));
    }
    fs::write(path, out).map_err(|err| format!("write {}: {err}", path.display()))
}

fn rewrite_router_config_public_key(path: &Path, public_key: &str) -> Result<(), String> {
    let mut value: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(path).map_err(|err| format!("read {}: {err}", path.display()))?,
    )
    .map_err(|err| format!("parse {}: {err}", path.display()))?;
    value["directory_public_key"] = serde_json::Value::String(public_key.to_string());
    let body = serde_json::to_string_pretty(&value)
        .map_err(|err| format!("serialize {}: {err}", path.display()))?;
    fs::write(path, format!("{body}\n")).map_err(|err| format!("write {}: {err}", path.display()))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}
