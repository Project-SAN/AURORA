use crate::policy::{PolicyMetadata, decode_metadata_tlv, encode_metadata_tlv};
use crate::types::Result;
use alloc::{vec, vec::Vec};

pub struct DirectoryAnnouncement {
    policy_entries: Vec<PolicyMetadata>,
}

impl DirectoryAnnouncement {
    pub fn new() -> Self {
        Self {
            policy_entries: Vec::new(),
        }
    }

    pub fn with_policy(meta: PolicyMetadata) -> Self {
        Self {
            policy_entries: vec![meta],
        }
    }

    pub fn push_policy(&mut self, meta: PolicyMetadata) {
        self.policy_entries.push(meta);
    }

    pub fn policies(&self) -> &[PolicyMetadata] {
        &self.policy_entries
    }

    pub fn to_tlvs(&self) -> Vec<Vec<u8>> {
        self.policy_entries
            .iter()
            .map(encode_metadata_tlv)
            .collect()
    }

    pub fn from_tlvs(tlvs: &[Vec<u8>]) -> Result<Self> {
        let mut metas = Vec::new();
        for tlv in tlvs {
            if tlv.first().copied() == Some(crate::policy::POLICY_METADATA_TLV) {
                metas.push(decode_metadata_tlv(tlv)?);
            }
        }
        Ok(Self {
            policy_entries: metas,
        })
    }
}

impl Default for DirectoryAnnouncement {
    fn default() -> Self {
        Self::new()
    }
}

pub fn apply_to_source_state(
    state: &mut crate::setup::SourceSetupState,
    directory: &DirectoryAnnouncement,
) {
    for policy in &directory.policy_entries {
        state.attach_policy_metadata(policy);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn roundtrip_directory_tlvs() {
        let meta = PolicyMetadata {
            policy_id: [0xAA; 32],
            version: 1,
            expiry: 123,
            flags: 0,
            verifier_blob: vec![0x10, 0x20],
        };
        let directory = DirectoryAnnouncement::with_policy(meta.clone());
        let tlvs = directory.to_tlvs();
        assert_eq!(tlvs.len(), 1);
        let parsed = DirectoryAnnouncement::from_tlvs(&tlvs).expect("directory");
        assert_eq!(parsed.policies().len(), 1);
        assert_eq!(parsed.policies()[0], meta);
    }
}
