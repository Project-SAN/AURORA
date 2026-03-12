use serde_json::Value;
use std::fs;

fn read_json(path: &str) -> Value {
    let body = fs::read_to_string(path).expect("read config");
    serde_json::from_str(&body).expect("parse json")
}

#[test]
fn qemu_policy_info_matches_expected_ports() {
    let doc = read_json("config/qemu/policy-info.host.json");
    let routers = doc["routers"].as_array().expect("routers array");
    assert_eq!(routers.len(), 3);
    assert_eq!(routers[0]["bind"], "127.0.0.1:18111");
    assert_eq!(routers[1]["bind"], "127.0.0.1:18112");
    assert_eq!(routers[2]["bind"], "127.0.0.1:18113");
}

#[test]
fn qemu_router_configs_keep_policy_enabled() {
    for name in ["entry", "middle", "exit"] {
        let path = format!("config/qemu/router-{name}.router_config.json");
        let doc = read_json(&path);
        assert_eq!(doc["skip_policy"], false);
        assert_eq!(doc["storage_path"], "/router_state.json");
        assert_eq!(doc["directory_path"], "/directory.json");
    }
}

#[test]
fn localnet_policy_info_matches_expected_ports() {
    let doc = read_json("config/localnet/policy-info.json");
    let routers = doc["routers"].as_array().expect("routers array");
    assert_eq!(routers.len(), 3);
    assert_eq!(routers[0]["bind"], "127.0.0.1:7101");
    assert_eq!(routers[1]["bind"], "127.0.0.1:7102");
    assert_eq!(routers[2]["bind"], "127.0.0.1:7103");
}
