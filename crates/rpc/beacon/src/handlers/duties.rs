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
use ream_chain_beacon::beacon_chain::{BeaconChain, CachedHead};
use ream_consensus_beacon::electra::beacon_state::BeaconState;
use ream_consensus_misc::{
    constants::beacon::{
        EPOCHS_PER_SYNC_COMMITTEE_PERIOD, MIN_SEED_LOOKAHEAD, SLOTS_PER_EPOCH,
        SLOTS_PER_HISTORICAL_ROOT,
    },
    misc::{compute_epoch_at_slot, compute_start_slot_at_epoch, compute_sync_committee_period},
};
use ream_fork_choice_beacon::store::get_ancestor_from_db;
use ream_network_spec::networks::beacon_network_spec;
use ream_storage::{db::beacon::BeaconDB, tables::table::REDBTable};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(untagged)]
enum ValidatorIndexRequest {
    Number(u64),
    String(String),
}

/// Returns the slot whose block root fixes the proposer shuffling for `epoch`.
/// Fulu moves it from the end of `N - 1` to `N - 2`; checking `epoch - 1` keeps the fork epoch on
/// the legacy boundary.
fn proposer_shuffling_decision_slot(epoch: u64, fulu_fork_epoch: u64) -> u64 {
    if epoch.saturating_sub(1) >= fulu_fork_epoch {
        compute_start_slot_at_epoch(epoch.saturating_sub(MIN_SEED_LOOKAHEAD)).saturating_sub(1)
    } else {
        compute_start_slot_at_epoch(epoch).saturating_sub(1)
    }
}

/// Returns the slot whose block root fixes the attester shuffling for `epoch`: the last slot of
/// `epoch - 2`, or genesis for the first two epochs.
fn attester_shuffling_decision_slot(epoch: u64) -> u64 {
    compute_start_slot_at_epoch(epoch.saturating_sub(1)).saturating_sub(1)
}

/// The later of the store's slot and the wall-clock slot, read `disparity_ms` early as Lighthouse
/// does. At a slot start the store's tick can wait for the store lock, so a validator client that
/// asks for the next epoch's proposers right at an epoch start would get 400.
fn tolerant_current_slot(
    store_slot: u64,
    genesis_time: u64,
    now_ms: u64,
    slot_duration_ms: u64,
    disparity_ms: u64,
) -> u64 {
    let wall_slot = now_ms
        .saturating_add(disparity_ms)
        .saturating_sub(genesis_time.saturating_mul(1000))
        / slot_duration_ms;
    store_slot.max(wall_slot)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or_default()
}

fn validate_proposer_duties_epoch(epoch: u64, current_epoch: u64) -> Result<(), ApiError> {
    if epoch > current_epoch.saturating_add(1) {
        return Err(ApiError::BadRequest(format!(
            "Request epoch {epoch} is more than one epoch past the current epoch {current_epoch}"
        )));
    }

    Ok(())
}

/// Selects the dependent-root semantics returned by v1 and v2.
enum DependentRoot {
    Legacy,
    ForkAware,
}

async fn proposer_duties(
    beacon_chain: &BeaconChain,
    epoch: u64,
    dependent_root_kind: DependentRoot,
) -> Result<HttpResponse, ApiError> {
    let head = beacon_chain
        .head()
        .map_err(|err| ApiError::InternalError(format!("Failed to get head root: {err:?}")))?;
    let spec = beacon_network_spec();
    let current_slot = tolerant_current_slot(
        head.current_slot,
        head.state.genesis_time,
        now_ms(),
        spec.slot_duration_ms,
        spec.maximum_gossip_clock_disparity,
    );
    validate_proposer_duties_epoch(epoch, compute_epoch_at_slot(current_slot))?;

    // Convert only after the guard because epoch-to-slot multiplication is unchecked.
    let decision_slot = match dependent_root_kind {
        DependentRoot::Legacy => compute_start_slot_at_epoch(epoch).saturating_sub(1),
        DependentRoot::ForkAware => {
            proposer_shuffling_decision_slot(epoch, beacon_network_spec().fulu_fork_epoch)
        }
    };
    let start_slot = compute_start_slot_at_epoch(epoch);
    let (state, state_block_root) = duties_state(
        beacon_chain.db(),
        &head,
        start_slot,
        head.state.determines_proposers_of(epoch),
    )
    .await?;
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

/// Serves v1 proposer duties with the legacy end-of-`N - 1` dependent root.
#[get("/validator/duties/proposer/{epoch}")]
pub async fn get_proposer_duties(
    beacon_chain: Data<Arc<BeaconChain>>,
    epoch: Path<u64>,
) -> Result<impl Responder, ApiError> {
    let epoch = epoch.into_inner();
    proposer_duties(&beacon_chain, epoch, DependentRoot::Legacy).await
}

/// Serves v2 proposer duties with the fork-aware dependent root.
#[get("/validator/duties/proposer/{epoch}")]
pub async fn get_proposer_duties_v2(
    beacon_chain: Data<Arc<BeaconChain>>,
    epoch: Path<u64>,
) -> Result<impl Responder, ApiError> {
    let epoch = epoch.into_inner();
    proposer_duties(&beacon_chain, epoch, DependentRoot::ForkAware).await
}

#[post("/validator/duties/attester/{epoch}")]
pub async fn get_attester_duties(
    beacon_chain: Data<Arc<BeaconChain>>,
    epoch: Path<u64>,
    validator_indices: Json<Vec<ValidatorIndexRequest>>,
) -> Result<impl Responder, ApiError> {
    let epoch = epoch.into_inner();
    let head = beacon_chain
        .head()
        .map_err(|err| ApiError::InternalError(format!("Failed to get head root: {err:?}")))?;
    let (state, _) = duties_state(
        beacon_chain.db(),
        &head,
        compute_start_slot_at_epoch(epoch),
        head.state.determines_committees_of(epoch),
    )
    .await?;
    let dependent_root =
        attester_dependent_root(beacon_chain.db(), head.head_root, &head.state, epoch)?;
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
                committee_length: committee.len() as u64,
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
    beacon_chain: Data<Arc<BeaconChain>>,
    db: Data<BeaconDB>,
    epoch: Path<u64>,
    validator_indices: Json<Vec<ValidatorIndexRequest>>,
) -> Result<impl Responder, ApiError> {
    let epoch = epoch.into_inner();
    let head = beacon_chain
        .head()
        .map_err(|err| ApiError::InternalError(format!("Failed to get head root: {err:?}")))?;
    // A state holds the current and next committees, so the head state serves both without
    // loading a stored state.
    let head_epoch = head.state.get_current_epoch();
    let state = if sync_committee_for_epoch(head_epoch, epoch).is_some() {
        head.state.clone()
    } else if compute_sync_committee_period(epoch) > compute_sync_committee_period(head_epoch) {
        let spec = beacon_network_spec();
        let current_slot = tolerant_current_slot(
            head.current_slot,
            head.state.genesis_time,
            now_ms(),
            spec.slot_duration_ms,
            spec.maximum_gossip_clock_disparity,
        );
        let Some(advance_to) =
            sync_duties_advance_epoch(head_epoch, compute_epoch_at_slot(current_slot), epoch)
        else {
            return Err(ApiError::BadRequest(format!(
                "Epoch {epoch} is past the next sync committee period"
            )));
        };
        let head_state = head.state.clone();
        let state = tokio::task::spawn_blocking(move || {
            let mut state = Arc::unwrap_or_clone(head_state);
            state
                .process_slots(compute_start_slot_at_epoch(advance_to))
                .map(|()| state)
        })
        .await
        .map_err(|err| ApiError::InternalError(format!("State advance task failed: {err}")))?
        .map_err(|err| ApiError::InternalError(format!("Failed to advance the state: {err}")))?;
        Arc::new(state)
    } else {
        let block_root = head_chain_block_root(
            &db,
            head.head_root,
            &head.state,
            compute_start_slot_at_epoch(epoch),
        )?;
        Arc::new(
            db.state_provider()
                .get(block_root)
                .map_err(|err| {
                    ApiError::InternalError(format!(
                        "Failed to get beacon state by block root, error: {err:?}"
                    ))
                })?
                .ok_or_else(|| {
                    ApiError::NotFound(format!("Failed to find beacon state for epoch {epoch}"))
                })?,
        )
    };
    let sync_committee = match sync_committee_for_epoch(state.get_current_epoch(), epoch) {
        Some(SyncCommitteePeriod::Current) => &state.current_sync_committee,
        Some(SyncCommitteePeriod::Next) => &state.next_sync_committee,
        None => {
            return Err(ApiError::BadRequest(format!(
                "Epoch {epoch} is past the next sync committee period"
            )));
        }
    };
    let sync_committee_indices =
        state
            .get_sync_committee_indices(sync_committee)
            .map_err(|err| {
                ApiError::BadRequest(format!("Failed to get sync committee indices {err:?}"))
            })?;
    let validator_indices = parse_validator_indices(validator_indices.into_inner())?;

    let mut duties = vec![];
    for validator_index in validator_indices {
        let Some(validator) = state.validators.get(validator_index as usize) else {
            return Err(ApiError::ValidatorNotFound(format!(
                "Validator with index {validator_index} not found in state at epoch {epoch}"
            )));
        };

        let validator_sync_committee_indices: Vec<u64> = sync_committee_indices
            .iter()
            .enumerate()
            .filter_map(|(index, &committee_index)| {
                (validator_index == committee_index as u64).then_some(index as u64)
            })
            .collect();
        if validator_sync_committee_indices.is_empty() {
            continue;
        }

        duties.push(SyncCommitteeDuty {
            public_key: validator.public_key.clone(),
            validator_index,
            validator_sync_committee_indices,
        });
    }
    Ok(HttpResponse::Ok().json(DutiesResponse::new(None, duties)))
}

#[derive(Debug, PartialEq, Eq)]
enum SyncCommitteePeriod {
    Current,
    Next,
}

/// The epoch to advance the head state to for the duties of `epoch`, when the head is still in
/// the period before the wall clock's, as when the first blocks of a period are missing, and
/// `epoch` is in the period after the wall clock's. Only that state holds its committee.
fn sync_duties_advance_epoch(head_epoch: u64, current_epoch: u64, epoch: u64) -> Option<u64> {
    let head_period = compute_sync_committee_period(head_epoch);
    (compute_sync_committee_period(current_epoch) == head_period + 1
        && compute_sync_committee_period(epoch) == head_period + 2)
        .then_some((head_period + 1) * EPOCHS_PER_SYNC_COMMITTEE_PERIOD)
}

/// Which committee of a state in `state_epoch` serves `epoch`.
fn sync_committee_for_epoch(state_epoch: u64, epoch: u64) -> Option<SyncCommitteePeriod> {
    let state_period = compute_sync_committee_period(state_epoch);
    match compute_sync_committee_period(epoch).checked_sub(state_period) {
        Some(0) => Some(SyncCommitteePeriod::Current),
        Some(1) => Some(SyncCommitteePeriod::Next),
        _ => None,
    }
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

/// The head state when it fixes the duties (its current and next epoch); loading another state
/// clones the whole registry, about 0.5 s on Hoodi.
async fn duties_state(
    db: &BeaconDB,
    head: &CachedHead,
    start_slot: u64,
    head_state_fixes_duties: bool,
) -> Result<(Arc<BeaconState>, B256), ApiError> {
    if head_state_fixes_duties {
        return Ok((head.state.clone(), head.head_root));
    }
    // Resolved on the head chain: the slot index can hold a block a reorg left out.
    let block_root = head_chain_block_root(db, head.head_root, &head.state, start_slot)?;
    let (state, block_root) = get_state_and_block_root(db, block_root, start_slot).await?;
    Ok((Arc::new(state), block_root))
}

/// The head chain's block at the attester shuffling decision slot. The slot index keeps a
/// reorged-out block when the slot is empty on the head chain, so it is not used here.
fn attester_dependent_root(
    db: &BeaconDB,
    head_root: B256,
    head_state: &BeaconState,
    epoch: u64,
) -> Result<B256, ApiError> {
    head_chain_block_root(
        db,
        head_root,
        head_state,
        attester_shuffling_decision_slot(epoch),
    )
}

/// The block at or before `slot` on the chain of `head_root`, whose post-state is `head_state`.
/// The state's `block_roots` cover the last 8192 slots, also those before a checkpoint sync
/// anchor whose blocks are not stored yet. Older slots are walked back from the oldest of them,
/// but not past the finalized slot: the states before it are pruned, so no duties can be computed
/// there, and the walk would read every block back to genesis.
pub(crate) fn head_chain_block_root(
    db: &BeaconDB,
    head_root: B256,
    head_state: &BeaconState,
    slot: u64,
) -> Result<B256, ApiError> {
    if slot >= head_state.slot {
        return Ok(head_root);
    }
    if let Ok(root) = head_state.get_block_root_at_slot(slot) {
        return Ok(root);
    }
    let finalized_slot = compute_start_slot_at_epoch(head_state.finalized_checkpoint.epoch);
    if slot < finalized_slot {
        return Err(ApiError::NotFound(format!(
            "Slot {slot} is before the finalized slot {finalized_slot} and the head state's block roots"
        )));
    }
    let oldest_root = head_state
        .get_block_root_at_slot(head_state.slot - SLOTS_PER_HISTORICAL_ROOT)
        .map_err(|err| ApiError::InternalError(format!("Failed to read block roots: {err}")))?;
    get_ancestor_from_db(db, oldest_root, slot).map_err(|err| {
        ApiError::InternalError(format!(
            "Failed to find canonical block root at or before slot {slot}: {err:?}"
        ))
    })
}

async fn get_state_and_block_root(
    db: &BeaconDB,
    block_root: B256,
    slot: u64,
) -> Result<(BeaconState, B256), ApiError> {
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

#[cfg(test)]
mod tests {
    use ream_bls::BLSSignature;
    use ream_consensus_beacon::electra::beacon_block::{BeaconBlock, SignedBeaconBlock};
    use ream_storage::db::ReamDB;
    use ssz::Decode;
    use tempdir::TempDir;
    use tree_hash::TreeHash;

    use super::*;

    #[test]
    fn attester_dependent_root_is_last_slot_of_epoch_minus_two() {
        assert_eq!(attester_shuffling_decision_slot(0), 0);
        assert_eq!(attester_shuffling_decision_slot(1), 0);
        assert_eq!(attester_shuffling_decision_slot(2), SLOTS_PER_EPOCH - 1);
        assert_eq!(
            attester_shuffling_decision_slot(130_615),
            130_614 * SLOTS_PER_EPOCH - 1
        );
    }

    #[test]
    fn current_slot_follows_the_wall_clock_when_the_store_lags() {
        let genesis_time = 1_000;
        let slot_start_ms = |slot: u64| (genesis_time + slot * 12) * 1000;

        // The store has not ticked into slot 64, the first of epoch 2.
        assert_eq!(
            tolerant_current_slot(63, genesis_time, slot_start_ms(64) + 100, 12_000, 500),
            64
        );
        // Up to 500 ms early counts as the next slot.
        assert_eq!(
            tolerant_current_slot(63, genesis_time, slot_start_ms(64) - 400, 12_000, 500),
            64
        );
        assert_eq!(
            tolerant_current_slot(63, genesis_time, slot_start_ms(64) - 600, 12_000, 500),
            63
        );
        // A store ahead of the wall clock wins.
        assert_eq!(
            tolerant_current_slot(65, genesis_time, slot_start_ms(64), 12_000, 500),
            65
        );
    }

    #[test]
    fn sync_duties_advance_the_head_state_only_across_the_current_boundary() {
        let period = EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
        let head_epoch = 510 * period - 1;
        // The wall clock is in period 510, the head still in 509.
        assert_eq!(
            sync_duties_advance_epoch(head_epoch, 510 * period, 511 * period + 3),
            Some(510 * period)
        );
        // The head state already holds the next committee.
        assert_eq!(
            sync_duties_advance_epoch(head_epoch, 510 * period, 510 * period),
            None
        );
        // Further periods and a head in the wall clock's period are not advanced.
        assert_eq!(
            sync_duties_advance_epoch(head_epoch, 510 * period, 512 * period),
            None
        );
        assert_eq!(
            sync_duties_advance_epoch(head_epoch, 509 * period + 5, 511 * period),
            None
        );
    }

    #[test]
    fn sync_duties_use_next_committee_without_advancing_state() {
        let period = EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
        assert_eq!(
            sync_committee_for_epoch(510 * period + 3, 510 * period),
            Some(SyncCommitteePeriod::Current)
        );
        assert_eq!(
            sync_committee_for_epoch(510 * period + 3, 511 * period),
            Some(SyncCommitteePeriod::Next)
        );
        assert_eq!(
            sync_committee_for_epoch(510 * period + 3, 512 * period),
            None
        );
        // The latest block can sit in the previous period when the boundary slots were empty.
        assert_eq!(
            sync_committee_for_epoch(510 * period - 1, 510 * period),
            Some(SyncCommitteePeriod::Next)
        );
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

    fn test_db() -> (BeaconDB, TempDir) {
        let temp_dir = TempDir::new("ream_rpc_beacon_duties").expect("creates temp directory");
        let db = ReamDB::new(temp_dir.path().to_path_buf())
            .expect("creates database")
            .init_beacon_db()
            .expect("initializes beacon database");
        (db, temp_dir)
    }

    fn block(slot: u64, parent_root: B256, state_root: B256) -> SignedBeaconBlock {
        SignedBeaconBlock {
            message: BeaconBlock {
                slot,
                parent_root,
                state_root,
                ..Default::default()
            },
            signature: BLSSignature::default(),
        }
    }

    #[test]
    fn proposer_decision_slot_preserves_the_fulu_boundary() {
        let fulu_fork_epoch = 5;

        assert_eq!(
            proposer_shuffling_decision_slot(4, fulu_fork_epoch),
            4 * SLOTS_PER_EPOCH - 1
        );
        assert_eq!(
            proposer_shuffling_decision_slot(5, fulu_fork_epoch),
            5 * SLOTS_PER_EPOCH - 1
        );
        assert_eq!(
            proposer_shuffling_decision_slot(6, fulu_fork_epoch),
            5 * SLOTS_PER_EPOCH - 1
        );
    }

    #[test]
    fn proposer_decision_slot_saturates_at_genesis() {
        assert_eq!(proposer_shuffling_decision_slot(0, 0), 0);
        assert_eq!(proposer_shuffling_decision_slot(1, 0), 0);
        assert_eq!(proposer_shuffling_decision_slot(2, 0), SLOTS_PER_EPOCH - 1);
    }

    #[test]
    fn proposer_duties_reject_epochs_beyond_the_lookahead() {
        assert!(validate_proposer_duties_epoch(10, 10).is_ok());
        assert!(validate_proposer_duties_epoch(11, 10).is_ok());
        assert!(matches!(
            validate_proposer_duties_epoch(12, 10),
            Err(ApiError::BadRequest(_))
        ));
        assert!(matches!(
            validate_proposer_duties_epoch(u64::MAX, 10),
            Err(ApiError::BadRequest(_))
        ));
    }

    /// A head state at `slot`, from a real state: only its slot, finalized checkpoint and
    /// block roots matter here.
    fn head_state(slot: u64, finalized_epoch: u64) -> BeaconState {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
            "../../../testing/gossip-validation/tests/assets/sepolia/states/\
             grandparent_state_9552074.ssz_snappy",
        );
        let bytes = snap::raw::Decoder::new()
            .decompress_vec(&std::fs::read(path).expect("reads fixture state"))
            .expect("decompresses fixture state");
        let mut state = BeaconState::from_ssz_bytes(&bytes).expect("decodes fixture state");
        state.slot = slot;
        state.finalized_checkpoint.epoch = finalized_epoch;
        state
    }

    fn set_block_root(state: &mut BeaconState, slot: u64, root: B256) {
        state.block_roots[(slot % SLOTS_PER_HISTORICAL_ROOT) as usize] = root;
    }

    #[test]
    fn canonical_lookup_ignores_a_later_side_fork_at_the_same_slot() {
        let (db, _temp_dir) = test_db();
        let anchor = block(0, B256::ZERO, B256::repeat_byte(1));
        let anchor_root = anchor.message.tree_hash_root();
        let canonical = block(100, anchor_root, B256::repeat_byte(2));
        let canonical_root = canonical.message.tree_hash_root();
        let side_fork = block(100, anchor_root, B256::repeat_byte(3));
        let side_fork_root = side_fork.message.tree_hash_root();

        db.block_provider()
            .insert(anchor_root, anchor)
            .expect("stores anchor block");
        db.block_provider()
            .insert(canonical_root, canonical)
            .expect("stores canonical block");
        db.block_provider()
            .insert(side_fork_root, side_fork)
            .expect("stores side-fork block");

        assert_eq!(
            db.slot_index_provider().get(100).expect("reads slot index"),
            Some(side_fork_root)
        );

        // Slot 100 is older than the head state's block roots, so it is found by walking back
        // from the oldest of them, at slot 150, where the head chain still had block 100.
        let mut state = head_state(150 + SLOTS_PER_HISTORICAL_ROOT, 0);
        set_block_root(&mut state, 150, canonical_root);
        assert_eq!(
            head_chain_block_root(&db, B256::repeat_byte(9), &state, 100)
                .expect("resolves canonical ancestor"),
            canonical_root
        );
    }

    #[test]
    fn attester_dependent_root_skips_a_reorged_block_at_an_empty_slot() {
        let (db, _temp_dir) = test_db();
        let anchor = block(0, B256::ZERO, B256::repeat_byte(1));
        let anchor_root = anchor.message.tree_hash_root();
        // The block at the decision slot of epoch 2 lost a reorg; the head chain skips the slot.
        let reorged = block(SLOTS_PER_EPOCH - 1, anchor_root, B256::repeat_byte(2));
        let reorged_root = reorged.message.tree_hash_root();
        let head = block(SLOTS_PER_EPOCH, anchor_root, B256::repeat_byte(3));
        let head_root = head.message.tree_hash_root();
        for (root, block) in [
            (anchor_root, anchor),
            (reorged_root, reorged),
            (head_root, head),
        ] {
            db.block_provider()
                .insert(root, block)
                .expect("stores block");
        }
        assert_eq!(
            get_block_root_at_or_before_slot(&db, SLOTS_PER_EPOCH - 1).expect("reads slot index"),
            reorged_root
        );

        let mut state = head_state(SLOTS_PER_EPOCH, 0);
        set_block_root(&mut state, SLOTS_PER_EPOCH - 1, anchor_root);
        assert_eq!(
            attester_dependent_root(&db, head_root, &state, 2).expect("resolves dependent root"),
            anchor_root
        );
    }

    #[test]
    fn head_chain_lookup_uses_block_roots_and_stops_at_the_finalized_slot() {
        // No blocks are stored, as right after a checkpoint sync.
        let (db, _temp_dir) = test_db();
        let mut state = head_state(20_000, 400);
        set_block_root(&mut state, 19_000, B256::repeat_byte(7));
        assert_eq!(
            head_chain_block_root(&db, B256::repeat_byte(9), &state, 19_000)
                .expect("reads the head state's block roots"),
            B256::repeat_byte(7)
        );
        assert_eq!(
            head_chain_block_root(&db, B256::repeat_byte(9), &state, 20_000)
                .expect("the head itself"),
            B256::repeat_byte(9)
        );
        // Before the finalized slot and the block roots: refused without reading any block.
        assert!(matches!(
            head_chain_block_root(&db, B256::repeat_byte(9), &state, 0),
            Err(ApiError::NotFound(_))
        ));
    }
}
