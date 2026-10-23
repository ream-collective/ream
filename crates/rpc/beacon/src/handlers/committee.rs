use std::vec;

use actix_web::{
    HttpResponse, Responder, get,
    web::{Data, Path, Query},
};
use ream_api_types_beacon::{
    query::{EpochQuery, IndexQuery, SlotQuery},
    responses::BeaconResponse,
};
use ream_api_types_common::{error::ApiError, id::ID};
use ream_consensus_beacon::electra::beacon_state::{
    BeaconState, committee_count_per_slot, committee_in_shuffling,
};
use ream_consensus_misc::{
    constants::beacon::SLOTS_PER_EPOCH,
    misc::{compute_epoch_at_slot, compute_start_slot_at_epoch},
};
use ream_storage::db::beacon::BeaconDB;
use serde::Serialize;

use super::state::get_state_from_id;

#[derive(Debug, Serialize, Clone)]
pub struct CommitteeData {
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: u64,
    #[serde(with = "serde_utils::quoted_u64_vec")]
    pub validators: Vec<u64>,
}

impl CommitteeData {
    pub fn new(index: u64, slot: u64, validators: Vec<u64>) -> Self {
        Self {
            index,
            slot,
            validators,
        }
    }
}

/// Called by `/states/<state_id>/committees` to get the Committee Data of state.
/// Optional `epoch`, `index` or `slot` can be provided.
#[get("/beacon/states/{state_id}/committees")]
pub async fn get_committees(
    state_id: Path<ID>,
    epoch: Query<EpochQuery>,
    index: Query<IndexQuery>,
    slot: Query<SlotQuery>,
    db: Data<BeaconDB>,
) -> Result<impl Responder, ApiError> {
    let state = get_state_from_id(state_id.into_inner(), &db).await?;
    let result = committees(&state, epoch.epoch, slot.slot, index.index)?;
    Ok(HttpResponse::Ok().json(BeaconResponse::new(result)))
}

fn committees(
    state: &BeaconState,
    epoch: Option<u64>,
    slot: Option<u64>,
    index: Option<u64>,
) -> Result<Vec<CommitteeData>, ApiError> {
    let epoch = epoch.unwrap_or(state.get_current_epoch());
    // Shuffle the epoch once for the whole request: epochs past the next one are not cached.
    let shuffled = state.get_shuffled_active_validator_indices(epoch);
    let committees_per_slot = committee_count_per_slot(shuffled.len());

    let slots: Vec<u64> = match slot {
        Some(slot) => vec![slot],
        None => {
            let start_slot = compute_start_slot_at_epoch(epoch);
            (start_slot..(start_slot + SLOTS_PER_EPOCH)).collect()
        }
    };

    // Committee indices restart at 0 in every slot.
    let indices: Vec<u64> = match index {
        Some(index) => vec![index],
        None => (0..committees_per_slot).collect(),
    };

    let mut result: Vec<CommitteeData> = Vec::with_capacity(slots.len() * indices.len());

    for slot in &slots {
        for index in &indices {
            let committee = if compute_epoch_at_slot(*slot) == epoch {
                committee_in_shuffling(&shuffled, *slot, *index)
            } else {
                state.get_beacon_committee(*slot, *index)
            }
            .map_err(|err| {
                ApiError::NotFound(format!(
                    "Committee with slot: {slot} and index: {index} not found {err:?}"
                ))
            })?;
            result.push(CommitteeData {
                index: *index,
                slot: *slot,
                validators: committee,
            });
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use ssz::Decode;

    use super::*;

    fn sepolia_state() -> BeaconState {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
            "../../../testing/gossip-validation/tests/assets/sepolia/states/\
             grandparent_state_9552074.ssz_snappy",
        );
        let bytes = snap::raw::Decoder::new()
            .decompress_vec(&std::fs::read(path).unwrap())
            .unwrap();
        BeaconState::from_ssz_bytes(&bytes).unwrap()
    }

    #[test]
    fn committees_without_an_index_list_every_committee_of_each_slot() {
        let state = sepolia_state();
        let epoch = state.get_current_epoch();
        let per_slot =
            committee_count_per_slot(state.get_shuffled_active_validator_indices(epoch).len());
        let slot = compute_start_slot_at_epoch(epoch) + 5;

        let one_slot = committees(&state, None, Some(slot), None).unwrap();
        assert_eq!(one_slot.len() as u64, per_slot);
        assert!(one_slot.iter().all(|committee| committee.slot == slot));
        assert_eq!(
            one_slot
                .iter()
                .map(|committee| committee.index)
                .collect::<Vec<_>>(),
            (0..per_slot).collect::<Vec<_>>()
        );

        let whole_epoch = committees(&state, Some(epoch), None, None).unwrap();
        assert_eq!(whole_epoch.len() as u64, per_slot * SLOTS_PER_EPOCH);
        let validators: usize = whole_epoch.iter().map(|c| c.validators.len()).sum();
        assert_eq!(
            validators,
            state.get_shuffled_active_validator_indices(epoch).len()
        );
    }
}
