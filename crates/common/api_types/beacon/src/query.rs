use alloy_primitives::B256;
use ream_peer::{ConnectionState, Direction};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{DeserializeOwned, value::StrDeserializer},
};

use super::id::ValidatorID;
use crate::validator::ValidatorStatus;

#[derive(Debug, Serialize, Deserialize)]
pub struct EpochQuery {
    pub epoch: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct SlotQuery {
    pub slot: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct IndexQuery {
    pub index: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct RootQuery {
    pub root: Option<B256>,
}

#[derive(Debug, Deserialize)]
pub struct ParentRootQuery {
    pub parent_root: Option<B256>,
}

/// Reads a list given as `?key=a,b`, `?key=a&key=b`, or both. Use with
/// `actix_web_lab::extract::Query`, which accepts repeated keys.
fn comma_separated<'de, D, T>(deserializer: D) -> Result<Option<Vec<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializeOwned,
{
    let Some(values) = Option::<Vec<String>>::deserialize(deserializer)? else {
        return Ok(None);
    };
    values
        .iter()
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| T::deserialize(StrDeserializer::<D::Error>::new(value)))
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

#[derive(Default, Debug, Deserialize)]
pub struct IdQuery {
    #[serde(default, deserialize_with = "comma_separated")]
    pub id: Option<Vec<ValidatorID>>,
}

#[derive(Default, Debug, Deserialize)]
pub struct BlobSidecarQuery {
    pub indices: Option<Vec<u64>>,
}

#[derive(Default, Debug, Deserialize)]
pub struct StatusQuery {
    #[serde(default, deserialize_with = "comma_separated")]
    pub status: Option<Vec<ValidatorStatus>>,
}

#[derive(Default, Debug, Deserialize)]
pub struct AttestationQuery {
    pub slot: u64,
    pub committee_index: Option<u64>,
    pub attestation_data_root: Option<B256>,
}

#[derive(Debug, Deserialize)]
pub struct SyncCommitteeContributionQuery {
    pub slot: u64,
    pub subcommittee_index: u64,
    pub beacon_block_root: B256,
}

#[derive(Debug, Deserialize)]
pub struct ConnectionStateQuery {
    pub state: Option<Vec<ConnectionState>>,
}

#[derive(Debug, Deserialize)]
pub struct HealthQuery {
    pub syncing_status: Option<u16>,
}

#[derive(Debug, Deserialize)]
pub struct DirectionQuery {
    pub direction: Option<Vec<Direction>>,
}

impl StatusQuery {
    pub fn has_status(&self) -> bool {
        match &self.status {
            Some(statuses) => !statuses.is_empty(),
            None => false,
        }
    }

    pub fn contains_status(&self, status: &ValidatorStatus) -> bool {
        match &self.status {
            Some(statuses) => statuses.contains(status),
            None => true, // If no statuses specified, accept all
        }
    }
}
