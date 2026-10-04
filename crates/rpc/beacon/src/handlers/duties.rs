use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use actix_web::{
    HttpResponse, Responder, get, post,
    web::{Data, Json, Path},
};
use alloy_primitives::B256;
use ream_api_types_beacon::{
    duties::{AttesterDuty, ProposerDuty, SyncCommitteeDuty},
    responses::{DutiesResponse, SyncCommitteeDutiesResponse},
};
use ream_api_types_common::error::ApiError;
use ream_chain_beacon::beacon_chain::BeaconChain;
use ream_consensus_beacon::{electra::beacon_state::BeaconState, sync_committee::SyncCommittee};
use ream_consensus_misc::{
    constants::beacon::{EPOCHS_PER_SYNC_COMMITTEE_PERIOD, MIN_SEED_LOOKAHEAD, SLOTS_PER_EPOCH},
    misc::{compute_epoch_at_slot, compute_start_slot_at_epoch, compute_sync_committee_period},
};
use ream_fork_choice_beacon::store::get_ancestor_from_db;
use ream_network_spec::networks::beacon_network_spec;
use ream_storage::{
    db::beacon::BeaconDB,
    tables::{field::REDBField, table::REDBTable},
};
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
/// `epoch - 2`, or genesis for the first two epochs. Using the end of `epoch - 1` instead makes the
/// root of next-epoch duties follow the head, so validator clients refetch duties every slot.
fn attester_shuffling_decision_slot(epoch: u64) -> u64 {
    compute_start_slot_at_epoch(epoch.saturating_sub(1)).saturating_sub(1)
}

/// Proposer and attester duties are known at most one epoch ahead.
fn validate_duties_epoch(epoch: u64, current_epoch: u64) -> Result<(), ApiError> {
    if epoch > current_epoch.saturating_add(1) {
        return Err(ApiError::BadRequest(format!(
            "Request epoch {epoch} is more than one epoch past the current epoch {current_epoch}"
        )));
    }

    Ok(())
}

/// Reads the current epoch so future requests can be rejected before epoch-to-slot conversion.
///
/// Uses the wall clock with gossip clock disparity rather than the store's tick time: validator
/// clients ask for the next epoch's duties right at the boundary, before the store has ticked.
pub(super) fn current_epoch(db: &BeaconDB) -> Result<u64, ApiError> {
    let genesis_time = db
        .genesis_time_provider()
        .get()
        .map_err(|err| ApiError::InternalError(format!("Failed to get genesis time: {err:?}")))?;
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| ApiError::InternalError(format!("System time before Unix epoch: {err}")))?
        .as_millis() as u64;
    let spec = beacon_network_spec();

    Ok(epoch_at_time(
        genesis_time,
        now_ms.saturating_add(spec.maximum_gossip_clock_disparity),
        spec.slot_duration_ms,
    ))
}

fn epoch_at_time(genesis_time: u64, time_ms: u64, slot_duration_ms: u64) -> u64 {
    let slot = time_ms.saturating_sub(genesis_time.saturating_mul(1000)) / slot_duration_ms;
    compute_epoch_at_slot(slot)
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
    let db = beacon_chain.db();
    let current_epoch = current_epoch(db)?;
    validate_duties_epoch(epoch, current_epoch)?;

    // Convert only after the guard because epoch-to-slot multiplication is unchecked.
    let decision_slot = match dependent_root_kind {
        DependentRoot::Legacy => compute_start_slot_at_epoch(epoch).saturating_sub(1),
        DependentRoot::ForkAware => {
            proposer_shuffling_decision_slot(epoch, beacon_network_spec().fulu_fork_epoch)
        }
    };
    let start_slot = compute_start_slot_at_epoch(epoch);
    let head_root = canonical_head_root(beacon_chain)?;
    let (state, state_block_root) =
        get_canonical_state_and_block_root_at_or_before_slot(db, head_root, start_slot).await?;
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
    let db = beacon_chain.db();
    validate_duties_epoch(epoch, current_epoch(db)?)?;
    let start_slot = compute_start_slot_at_epoch(epoch);
    // Resolve the state and the dependent root from one head so both describe the same chain.
    let head_root = canonical_head_root(&beacon_chain)?;
    let (state, _) =
        get_canonical_state_and_block_root_at_or_before_slot(db, head_root, start_slot).await?;
    let dependent_root = get_canonical_block_root_at_or_before_slot(
        db,
        head_root,
        attester_shuffling_decision_slot(epoch),
    )?;
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

/// Sync committee duties are known for the current and the next sync committee period.
fn validate_sync_duties_epoch(epoch: u64, current_epoch: u64) -> Result<(), ApiError> {
    let max_period = compute_sync_committee_period(current_epoch).saturating_add(1);
    if compute_sync_committee_period(epoch) > max_period {
        return Err(ApiError::BadRequest(format!(
            "Request epoch {epoch} is beyond the next sync committee period of current epoch \
             {current_epoch}"
        )));
    }

    Ok(())
}

/// The committee `state` holds for `epoch`: its current committee for its own period and its next
/// committee for the period after. Any other period is unknown to this state.
fn sync_committee_for_epoch(state: &BeaconState, epoch: u64) -> Option<&SyncCommittee> {
    let state_period = compute_sync_committee_period(state.get_current_epoch());
    let period = compute_sync_committee_period(epoch);
    if period == state_period {
        Some(&state.current_sync_committee)
    } else if period == state_period.saturating_add(1) {
        Some(&state.next_sync_committee)
    } else {
        None
    }
}

/// Sync committee positions held by each requested validator. Validators outside the committee
/// get no duty, because validator clients treat every returned duty as membership and sign sync
/// committee messages for it.
fn sync_committee_duties(
    state: &BeaconState,
    sync_committee_indices: &[usize],
    validator_indices: &[u64],
    epoch: u64,
) -> Result<Vec<SyncCommitteeDuty>, ApiError> {
    let mut duties = vec![];
    for &validator_index in validator_indices {
        let Some(validator) = state.validators.get(validator_index as usize) else {
            return Err(ApiError::ValidatorNotFound(format!(
                "Validator with index {validator_index} not found in state at epoch {epoch}"
            )));
        };

        let validator_sync_committee_indices: Vec<u64> = sync_committee_indices
            .iter()
            .enumerate()
            .filter(|(_, member)| **member as u64 == validator_index)
            .map(|(position, _)| position as u64)
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
    Ok(duties)
}

#[post("/validator/duties/sync/{epoch}")]
pub async fn get_sync_committee_duties(
    beacon_chain: Data<Arc<BeaconChain>>,
    epoch: Path<u64>,
    validator_indices: Json<Vec<ValidatorIndexRequest>>,
) -> Result<impl Responder, ApiError> {
    let epoch = epoch.into_inner();
    let db = beacon_chain.db();
    validate_sync_duties_epoch(epoch, current_epoch(db)?)?;
    let validator_indices = parse_validator_indices(validator_indices.into_inner())?;

    // The head state holds the committees for its own and the next period, which covers what
    // validator clients ask for. Advancing a state to a future epoch instead would replay up to a
    // whole period of epoch transitions.
    let head = beacon_chain
        .head()
        .map_err(|err| ApiError::InternalError(format!("Failed to get head snapshot: {err:?}")))?;
    let state = if sync_committee_for_epoch(&head.state, epoch).is_some() {
        head.state
    } else {
        // An older period is read from a canonical state inside it. A head more than one period
        // behind is advanced to the period before the request, whose next committee is the one
        // requested.
        let period = compute_sync_committee_period(epoch);
        let load_epoch = if period < compute_sync_committee_period(head.state.get_current_epoch()) {
            epoch
        } else {
            (period - 1) * EPOCHS_PER_SYNC_COMMITTEE_PERIOD
        };
        let (state, _) = get_canonical_state_and_block_root_at_or_before_slot(
            db,
            head.head_root,
            compute_start_slot_at_epoch(load_epoch),
        )
        .await?;
        Arc::new(state)
    };
    let sync_committee = sync_committee_for_epoch(&state, epoch).ok_or_else(|| {
        ApiError::InternalError(format!("No sync committee known for epoch {epoch}"))
    })?;
    let sync_committee_indices =
        state
            .get_sync_committee_indices(sync_committee)
            .map_err(|err| {
                ApiError::InternalError(format!("Failed to get sync committee indices {err:?}"))
            })?;

    let duties = sync_committee_duties(&state, &sync_committee_indices, &validator_indices, epoch)?;
    Ok(HttpResponse::Ok().json(SyncCommitteeDutiesResponse::new(duties)))
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

/// Root of the fork-choice head from the published snapshot. Reading it does not take the store
/// lock and does not recompute LMD-GHOST from the database.
fn canonical_head_root(beacon_chain: &BeaconChain) -> Result<B256, ApiError> {
    beacon_chain
        .head()
        .map(|head| head.head_root)
        .map_err(|err| ApiError::InternalError(format!("Failed to get head snapshot: {err:?}")))
}

/// Root of the canonical block at or before `slot`, found by walking parents from `head_root`.
/// The slot index is never consulted: a later side-fork block at the same slot overwrites it.
fn get_canonical_block_root_at_or_before_slot(
    db: &BeaconDB,
    head_root: B256,
    slot: u64,
) -> Result<B256, ApiError> {
    get_ancestor_from_db(db, head_root, slot).map_err(|err| {
        ApiError::InternalError(format!(
            "Failed to find canonical block root at or before slot {slot}: {err:?}"
        ))
    })
}

/// Loads the canonical state at `slot` and the root of the block it was built on.
async fn get_canonical_state_and_block_root_at_or_before_slot(
    db: &BeaconDB,
    head_root: B256,
    slot: u64,
) -> Result<(BeaconState, B256), ApiError> {
    let block_root = get_canonical_block_root_at_or_before_slot(db, head_root, slot)?;
    get_state_and_block_root(db, block_root, slot).await
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
    use tempdir::TempDir;
    use tree_hash::TreeHash;

    use super::*;

    #[test]
    fn attester_duty_includes_quoted_committee_length() {
        let duty = AttesterDuty {
            public_key: Default::default(),
            validator_index: 7,
            committee_index: 0,
            committee_length: 3,
            committees_at_slot: 1,
            validator_committee_index: 2,
            slot: 5,
        };
        let json = serde_json::to_value(duty).unwrap();
        assert_eq!(json["committee_length"], "3");
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
    fn attester_dependent_root_is_fixed_two_epochs_ahead() {
        assert_eq!(attester_shuffling_decision_slot(0), 0);
        assert_eq!(attester_shuffling_decision_slot(1), 0);
        assert_eq!(attester_shuffling_decision_slot(2), SLOTS_PER_EPOCH - 1);
        // Duties for epoch 5 depend on the end of epoch 3, which is final once epoch 4 starts.
        assert_eq!(attester_shuffling_decision_slot(5), 4 * SLOTS_PER_EPOCH - 1);
    }

    #[test]
    fn epoch_at_time_counts_the_boundary_as_the_new_epoch() {
        let genesis = 1_000;
        let epoch_ms = 12_000 * SLOTS_PER_EPOCH;
        let boundary_ms = genesis * 1000 + 2 * epoch_ms;
        assert_eq!(epoch_at_time(genesis, boundary_ms - 1, 12_000), 1);
        assert_eq!(epoch_at_time(genesis, boundary_ms, 12_000), 2);
        // A request 400 ms early, within the 500 ms disparity, already sees the next epoch.
        assert_eq!(epoch_at_time(genesis, boundary_ms - 400 + 500, 12_000), 2);
        assert_eq!(epoch_at_time(genesis, 0, 12_000), 0);
    }

    /// A real Sepolia state, so its sync committees resolve to validators in the registry.
    fn sepolia_state() -> BeaconState {
        use ssz::Decode;

        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
            "../../../testing/gossip-validation/tests/assets/sepolia/states/grandparent_state_9552074.ssz_snappy",
        );
        let compressed = std::fs::read(path).expect("test beacon state should be readable");
        let bytes = snap::raw::Decoder::new()
            .decompress_vec(&compressed)
            .expect("test beacon state should decompress");
        BeaconState::from_ssz_bytes(&bytes).expect("test beacon state should decode")
    }

    #[test]
    fn sync_duties_reject_epochs_beyond_the_next_period() {
        let period = EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
        assert!(validate_sync_duties_epoch(0, 3).is_ok());
        assert!(validate_sync_duties_epoch(2 * period - 1, 3).is_ok());
        for epoch in [2 * period, u64::MAX] {
            assert!(matches!(
                validate_sync_duties_epoch(epoch, 3),
                Err(ApiError::BadRequest(_))
            ));
        }
    }

    #[test]
    fn sync_committee_is_chosen_by_the_state_period() {
        let state = sepolia_state();
        let period_start = compute_sync_committee_period(state.get_current_epoch())
            * EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
        let period = EPOCHS_PER_SYNC_COMMITTEE_PERIOD;

        assert_eq!(
            sync_committee_for_epoch(&state, period_start),
            Some(&*state.current_sync_committee)
        );
        // Validator clients fetch next-period duties at the first epoch of that period.
        assert_eq!(
            sync_committee_for_epoch(&state, period_start + period),
            Some(&*state.next_sync_committee)
        );
        assert_eq!(
            sync_committee_for_epoch(&state, period_start + 2 * period),
            None
        );
        assert_eq!(sync_committee_for_epoch(&state, period_start - 1), None);
    }

    #[test]
    fn sync_duties_list_only_committee_members() {
        let state = sepolia_state();
        let epoch = state.get_current_epoch();
        let committee_indices = state
            .get_sync_committee_indices(&state.current_sync_committee)
            .expect("committee members are registered validators");
        let member = committee_indices[0] as u64;
        let member_positions: Vec<u64> = committee_indices
            .iter()
            .enumerate()
            .filter(|(_, index)| **index as u64 == member)
            .map(|(position, _)| position as u64)
            .collect();
        let non_member = (0..state.validators.len() as u64)
            .find(|index| !committee_indices.contains(&(*index as usize)))
            .expect("the registry is larger than the committee");

        let duties =
            sync_committee_duties(&state, &committee_indices, &[non_member, member], epoch)
                .expect("both validators exist");

        assert_eq!(duties.len(), 1);
        assert_eq!(duties[0].validator_index, member);
        assert_eq!(duties[0].validator_sync_committee_indices, member_positions);
        let json = serde_json::to_value(&duties[0]).unwrap();
        assert_eq!(
            json["validator_sync_committee_indices"][0],
            member_positions[0].to_string()
        );
        assert!(matches!(
            sync_committee_duties(&state, &committee_indices, &[u64::MAX], epoch),
            Err(ApiError::ValidatorNotFound(_))
        ));
    }

    #[test]
    fn duties_reject_epochs_beyond_the_lookahead() {
        assert!(validate_duties_epoch(10, 10).is_ok());
        assert!(validate_duties_epoch(11, 10).is_ok());
        assert!(matches!(
            validate_duties_epoch(12, 10),
            Err(ApiError::BadRequest(_))
        ));
        assert!(matches!(
            validate_duties_epoch(u64::MAX, 10),
            Err(ApiError::BadRequest(_))
        ));
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

        // Attester duties, sync duties and the attester dependent root all resolve through this
        // helper, so none of them can select the side fork.
        assert_eq!(
            get_canonical_block_root_at_or_before_slot(&db, canonical_root, 100)
                .expect("resolves canonical ancestor"),
            canonical_root
        );
        // A skipped slot resolves to the canonical block before it, not to the side fork.
        assert_eq!(
            get_canonical_block_root_at_or_before_slot(&db, canonical_root, 101)
                .expect("resolves canonical ancestor"),
            canonical_root
        );
        assert_eq!(
            get_canonical_block_root_at_or_before_slot(&db, canonical_root, 99)
                .expect("resolves canonical ancestor"),
            anchor_root
        );
    }
}
