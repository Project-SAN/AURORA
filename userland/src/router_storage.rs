extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use crate::fs;
use aurora::router::storage::{RouterStorage, StoredState};
#[cfg(target_arch = "aarch64")]
use aurora::setup::directory::RouteAnnouncement;
#[cfg(not(target_arch = "aarch64"))]
use aurora::types::Error;
#[cfg(target_arch = "aarch64")]
use aurora::types::{Error, RoutingSegment, Sv};
#[cfg(target_arch = "aarch64")]
use serde::Deserialize;

const ROUTER_STATE_FALLBACKS: &[&str] = &[
    "/ROUTER_S.JSO",
    "ROUTER_S.JSO",
    "/ROUTER~2.JSO",
    "ROUTER~2.JSO",
];

pub struct UserlandRouterStorage {
    path: String,
}

impl UserlandRouterStorage {
    pub fn new(path: impl Into<String>) -> Self {
        Self { path: path.into() }
    }
}

impl RouterStorage for UserlandRouterStorage {
    fn load(&self) -> core::result::Result<StoredState, Error> {
        let data = read_state_with_fallbacks(&self.path)?;
        #[cfg(target_arch = "aarch64")]
        {
            read_route_only_state(&data)
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            serde_json::from_slice(&data).map_err(|_| Error::Crypto)
        }
    }

    fn save(&self, state: &StoredState) -> core::result::Result<(), Error> {
        let data = serde_json::to_vec_pretty(state).map_err(|_| Error::Crypto)?;
        write_all(&self.path, &data)
    }
}

#[cfg(target_arch = "aarch64")]
#[derive(Deserialize)]
struct RouteOnlyState {
    #[serde(default)]
    _policies: Option<serde::de::IgnoredAny>,
    routes: Vec<RouteOnlyRoute>,
    sv: [u8; 16],
    node_secret: [u8; 32],
}

#[cfg(target_arch = "aarch64")]
#[derive(Deserialize)]
struct RouteOnlyRoute {
    policy_id: [u8; 32],
    segment: Vec<u8>,
    interface: String,
}

#[cfg(target_arch = "aarch64")]
fn read_route_only_state(data: &[u8]) -> core::result::Result<StoredState, Error> {
    let parsed: RouteOnlyState = serde_json::from_slice(data).map_err(|_| Error::Crypto)?;
    let routes = parsed
        .routes
        .into_iter()
        .map(|route| RouteAnnouncement {
            policy_id: route.policy_id,
            segment: RoutingSegment(route.segment),
            interface: route.interface,
        })
        .collect();
    Ok(StoredState::new(
        Vec::new(),
        routes,
        Sv(parsed.sv),
        parsed.node_secret,
    ))
}

fn read_state_with_fallbacks(path: &str) -> core::result::Result<Vec<u8>, Error> {
    match read_all(path) {
        Ok(data) => return Ok(data),
        Err(first_err) => {
            for fallback in ROUTER_STATE_FALLBACKS {
                if *fallback == path {
                    continue;
                }
                if let Ok(data) = read_all(fallback) {
                    return Ok(data);
                }
            }
            Err(first_err)
        }
    }
}

fn read_all(path: &str) -> core::result::Result<Vec<u8>, Error> {
    let handle = fs::open(path, fs::O_READ).ok_or(Error::Crypto)?;
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match fs::read(handle, &mut buf) {
            Some(0) => break,
            Some(n) => out.extend_from_slice(&buf[..n]),
            None => {
                let _ = fs::close(handle);
                return Err(Error::Crypto);
            }
        }
    }
    if !fs::close(handle) {
        return Err(Error::Crypto);
    }
    Ok(out)
}

fn write_all(path: &str, data: &[u8]) -> core::result::Result<(), Error> {
    let handle = fs::open(path, fs::O_CREATE | fs::O_WRITE | fs::O_TRUNC).ok_or(Error::Crypto)?;
    let mut offset = 0usize;
    while offset < data.len() {
        match fs::write(handle, &data[offset..]) {
            Some(0) | None => {
                let _ = fs::close(handle);
                return Err(Error::Crypto);
            }
            Some(n) => offset += n,
        }
    }
    if !fs::close(handle) {
        return Err(Error::Crypto);
    }
    if !fs::sync() {
        return Err(Error::Crypto);
    }
    Ok(())
}
