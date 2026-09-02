use std::sync::Arc;

use actix_web::{
    HttpResponse, Responder, get, post,
    web::{Data, Json, Path},
};
use alloy_primitives::B256;
use ream_api_types_beacon::{
    duties::{AttesterDuty, ProposerDuty, SyncCommitteeDuty},
    responses::DutiesResponse,
};
use ream_api_types_common::error::ApiError;
use ream_consensus_beacon::electra::beacon_state::BeaconState;
use ream_consensus_misc::{
    constants::beacon::{MIN_SEED_LOOKAHEAD, SLOTS_PER_EPOCH},
    misc::{compute_epoch_at_slot, compute_start_slot_at_epoch},
};
use ream_fork_choice_beacon::store::Store;
use ream_network_spec::networks::beacon_network_spec;
use ream_operation_pool::OperationPool;
use ream_storage::{db::beacon::BeaconDB, tables::table::REDBTable};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(untagged)]
enum ValidatorIndexRequest {
    Number(u64),
    String(String),
}

/// The slot whose block root the proposer shuffling for `epoch` is decided by.
///
/// Fulu made the proposer shuffling deterministic a whole `MIN_SEED_LOOKAHEAD` earlier, so from
/// then on the decision moves back to the end of epoch `N - 2`. The fork epoch itself is still
/// decided the old way, which is why the fork is tested one epoch below the request.
fn proposer_shuffling_decision_slot(epoch: u64) -> u64 {
    if epoch.saturating_sub(1) >= beacon_network_spec().fulu_fork_epoch {
        compute_start_slot_at_epoch(epoch.saturating_sub(MIN_SEED_LOOKAHEAD)).saturating_sub(1)
    } else {
        compute_start_slot_at_epoch(epoch).saturating_sub(1)
    }
}

/// The furthest epoch whose proposer shuffling is already decided, and so the furthest one this
/// endpoint will answer for.
///
/// Without this an arbitrarily large epoch is turned straight into a slot and walked back one
/// slot at a time, so a single request can spend the node in database lookups. The multiplication
/// into slots would overflow long before that, wrapping a nonsense epoch onto a real one and
/// answering 200 with genesis duties instead of rejecting it.
fn current_epoch(db: &BeaconDB) -> Result<u64, ApiError> {
    let slot = Store::new(db.clone(), Arc::new(OperationPool::default()), None)
        .get_current_slot()
        .map_err(|err| ApiError::InternalError(format!("Failed to get current slot: {err:?}")))?;

    Ok(compute_epoch_at_slot(slot))
}

/// Which block root a client is told the shuffling depends on. v1 always reports the end of
/// epoch `N - 1`; v2 reports the slot that actually decides it.
enum DependentRoot {
    Legacy,
    ForkAware,
}

async fn proposer_duties(
    db: &BeaconDB,
    epoch: u64,
    dependent_root_kind: DependentRoot,
) -> Result<HttpResponse, ApiError> {
    let current_epoch = current_epoch(db)?;
    if epoch > current_epoch + 1 {
        return Err(ApiError::BadRequest(format!(
            "Request epoch {epoch} is more than one epoch past the current epoch {current_epoch}"
        )));
    }

    // Only past the bound check is turning the epoch into slots safe from overflow.
    let decision_slot = match dependent_root_kind {
        DependentRoot::Legacy => compute_start_slot_at_epoch(epoch).saturating_sub(1),
        DependentRoot::ForkAware => proposer_shuffling_decision_slot(epoch),
    };
    let start_slot = compute_start_slot_at_epoch(epoch);
    let (state, state_block_root) =
        get_state_and_block_root_at_or_before_slot(db, start_slot).await?;
    // Walk the state's own history rather than the global slot index. That index maps a slot to
    // whichever block was imported for it last, including one from a branch fork choice discarded,
    // so it can name a root the returned duties were never derived from. It also only holds blocks
    // this node imported, so after a checkpoint sync it answers 404 for a decision slot the state
    // still remembers.
    let dependent_root = if state.slot <= decision_slot {
        state_block_root
    } else {
        state
            .get_block_root_at_slot(decision_slot)
            .map_err(|err| ApiError::NotFound(format!(
                "Failed to find the block root deciding the proposer shuffling for epoch {epoch}: {err}"
            )))?
    };
    let end_slot = start_slot + SLOTS_PER_EPOCH;
    let mut duties = vec![];
    for slot in start_slot..end_slot {
        let validator_index = state
            .get_beacon_proposer_index(Some(slot))
            .map_err(|err| ApiError::BadRequest(err.to_string()))?;
        let Some(validator) = state.validators.get(validator_index as usize) else {
            return Err(ApiError::ValidatorNotFound(format!("{validator_index}")));
        };
        duties.push(ProposerDuty {
            public_key: validator.public_key.clone(),
            validator_index,
            slot,
        });
    }
    Ok(HttpResponse::Ok().json(DutiesResponse::new(Some(dependent_root), duties)))
}

/// Reports the legacy dependent root — the block root at the end of epoch `N - 1` — whatever the
/// fork. Kept for clients that have not moved to v2.
#[get("/validator/duties/proposer/{epoch}")]
pub async fn get_proposer_duties(
    db: Data<BeaconDB>,
    epoch: Path<u64>,
) -> Result<impl Responder, ApiError> {
    let epoch = epoch.into_inner();
    proposer_duties(&db, epoch, DependentRoot::Legacy).await
}

/// Reports the fork-aware dependent root. Identical to v1 before Fulu; after it the shuffling is
/// decided a `MIN_SEED_LOOKAHEAD` earlier, so a validator client polling v1 would re-fetch duties
/// against a root that no longer decides them.
#[get("/validator/duties/proposer/{epoch}")]
pub async fn get_proposer_duties_v2(
    db: Data<BeaconDB>,
    epoch: Path<u64>,
) -> Result<impl Responder, ApiError> {
    let epoch = epoch.into_inner();
    proposer_duties(&db, epoch, DependentRoot::ForkAware).await
}

#[post("/validator/duties/attester/{epoch}")]
pub async fn get_attester_duties(
    db: Data<BeaconDB>,
    epoch: Path<u64>,
    validator_indices: Json<Vec<ValidatorIndexRequest>>,
) -> Result<impl Responder, ApiError> {
    let epoch = epoch.into_inner();
    let start_slot = compute_start_slot_at_epoch(epoch);
    let state = get_state_at_or_before_slot(&db, start_slot).await?;
    let dependent_root = if epoch == 0 {
        get_block_root_at_or_before_slot(&db, 0)?
    } else {
        get_block_root_at_or_before_slot(&db, start_slot - 1)?
    };
    let validator_indices = parse_validator_indices(validator_indices.into_inner())?;
    let committees_at_slot = state.get_committee_count_per_slot(epoch);
    let mut duties = vec![];

    for validator_index in validator_indices {
        let Some(validator) = state.validators.get(validator_index as usize) else {
            return Err(ApiError::ValidatorNotFound(format!(
                "Validator with index {validator_index} not found in state at epoch {epoch}"
            )));
        };

        if let Some((committee, committee_index, slot)) = state
            .get_committee_assignment(epoch, validator_index)
            .map_err(|err| {
                ApiError::BadRequest(format!(
                    "Failed to get committee assignment for validator {validator_index}: {err}"
                ))
            })?
        {
            let validator_committee_index = committee
                .iter()
                .position(|&index| index == validator_index)
                .ok_or_else(|| {
                    ApiError::BadRequest("Validator not found in assigned committee".to_string())
                })?;

            duties.push(AttesterDuty {
                public_key: validator.public_key.clone(),
                validator_index,
                committee_index,
                committees_at_slot,
                validator_committee_index: validator_committee_index as u64,
                slot,
            });
        }
    }
    Ok(HttpResponse::Ok().json(DutiesResponse::new(Some(dependent_root), duties)))
}

#[post("/validator/duties/sync/{epoch}")]
pub async fn get_sync_committee_duties(
    db: Data<BeaconDB>,
    epoch: Path<u64>,
    validator_indices: Json<Vec<ValidatorIndexRequest>>,
) -> Result<impl Responder, ApiError> {
    let epoch = epoch.into_inner();
    let state = get_state_at_or_before_slot(&db, compute_start_slot_at_epoch(epoch)).await?;
    let validator_indices = parse_validator_indices(validator_indices.into_inner())?;

    let mut duties = vec![];
    for validator_index in validator_indices {
        let Some(validator) = state.validators.get(validator_index as usize) else {
            return Err(ApiError::ValidatorNotFound(format!(
                "Validator with index {validator_index} not found in state at epoch {epoch}"
            )));
        };

        let sync_committee_indices = state
            .get_sync_committee_indices(&state.current_sync_committee)
            .map_err(|err| {
                ApiError::BadRequest(format!("Failed to get sync committee indices {err:?}"))
            })?;

        let validator_sync_committee_indices = sync_committee_indices
            .iter()
            .enumerate()
            .filter_map(|(index, &committee_index)| {
                if validator_index == committee_index as u64 {
                    Some(index as u64)
                } else {
                    None
                }
            })
            .collect();

        duties.push(SyncCommitteeDuty {
            public_key: validator.public_key.clone(),
            validator_index,
            validator_sync_committee_indices,
        });
    }
    Ok(HttpResponse::Ok().json(DutiesResponse::new(None, duties)))
}

fn parse_validator_indices(
    validator_indices: Vec<ValidatorIndexRequest>,
) -> Result<Vec<u64>, ApiError> {
    validator_indices
        .into_iter()
        .map(|index| match index {
            ValidatorIndexRequest::Number(index) => Ok(index),
            ValidatorIndexRequest::String(index) => index.parse::<u64>().map_err(|err| {
                ApiError::BadRequest(format!("Invalid validator index `{index}`: {err}"))
            }),
        })
        .collect()
}

/// Returns the state at `slot` alongside the root of the block it was built on, which callers
/// need to name the state's own branch.
async fn get_state_and_block_root_at_or_before_slot(
    db: &BeaconDB,
    slot: u64,
) -> Result<(BeaconState, B256), ApiError> {
    let block_root = get_block_root_at_or_before_slot(db, slot)?;
    let mut state = db
        .state_provider()
        .get(block_root)
        .map_err(|err| {
            ApiError::InternalError(format!(
                "Failed to get beacon state by block root, error: {err:?}"
            ))
        })?
        .ok_or_else(|| {
            ApiError::NotFound(format!("Failed to find beacon state for slot {slot}"))
        })?;
    if state.slot < slot {
        state
            .process_slots(slot)
            .map_err(|err| ApiError::BadRequest(err.to_string()))?;
    }
    Ok((state, block_root))
}

async fn get_state_at_or_before_slot(db: &BeaconDB, slot: u64) -> Result<BeaconState, ApiError> {
    Ok(get_state_and_block_root_at_or_before_slot(db, slot)
        .await?
        .0)
}

fn get_block_root_at_or_before_slot(db: &BeaconDB, slot: u64) -> Result<B256, ApiError> {
    for candidate_slot in (0..=slot).rev() {
        match db
            .slot_index_provider()
            .get(candidate_slot)
            .map_err(|err| {
                ApiError::InternalError(format!(
                    "Failed to get block root for slot {candidate_slot}, error: {err:?}"
                ))
            })? {
            Some(block_root) => return Ok(block_root),
            None => continue,
        }
    }

    Err(ApiError::NotFound(format!(
        "Failed to find block root at or before slot {slot}"
    )))
}
