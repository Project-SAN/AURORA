use crate::policy::PolicyMetadata;
use crate::setup::directory::RouteAnnouncement;
use crate::types::{Result, RoutingSegment, Sv};
use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct StoredState {
    policies: Vec<PolicyMetadata>,
    routes: Vec<StoredRoute>,
    sv: [u8; 16],
    node_secret: [u8; 32],
}

#[derive(Serialize, Deserialize, Clone)]
struct StoredRoute {
    policy_id: [u8; 32],
    segment: Vec<u8>,
    interface: Option<String>,
}

pub trait RouterStorage {
    fn load(&self) -> Result<StoredState>;
    fn save(&self, state: &StoredState) -> Result<()>;
}

#[cfg(feature = "std")]
#[path = "storage_std.rs"]
mod storage_std;
#[cfg(feature = "std")]
pub use storage_std::FileRouterStorage;

impl StoredState {
    pub fn new(
        policies: Vec<PolicyMetadata>,
        routes: Vec<RouteAnnouncement>,
        sv: Sv,
        node_secret: [u8; 32],
    ) -> Self {
        let stored_routes = routes.iter().map(StoredRoute::from_announcement).collect();
        Self {
            policies,
            routes: stored_routes,
            sv: sv.0,
            node_secret,
        }
    }

    pub fn policies(&self) -> &[PolicyMetadata] {
        &self.policies
    }

    pub fn routes(&self) -> Vec<RouteAnnouncement> {
        self.routes
            .iter()
            .cloned()
            .map(StoredRoute::into_announcement)
            .collect()
    }

    pub fn sv(&self) -> Sv {
        Sv(self.sv)
    }

    pub fn node_secret(&self) -> [u8; 32] {
        self.node_secret
    }

    pub fn into_parts(self) -> (Vec<PolicyMetadata>, Vec<RouteAnnouncement>, Sv, [u8; 32]) {
        (
            self.policies,
            self.routes
                .into_iter()
                .map(StoredRoute::into_announcement)
                .collect(),
            Sv(self.sv),
            self.node_secret,
        )
    }
}

impl StoredRoute {
    fn from_announcement(route: &RouteAnnouncement) -> Self {
        Self {
            policy_id: route.policy_id,
            segment: route.segment.0.clone(),
            interface: route.interface.clone(),
        }
    }

    fn into_announcement(self) -> RouteAnnouncement {
        RouteAnnouncement {
            policy_id: self.policy_id,
            segment: RoutingSegment(self.segment),
            interface: self.interface,
        }
    }
}
