use actix_web::{
    HttpResponse, Responder, post,
    web::{Data, Json, Path},
};
use alloy_primitives::B256;
use ream_api_types_beacon::{
    id::ValidatorID,
    rewards::{AttestationRewardsData, AttestationRewardsResponse, IdealReward, TotalReward},
};
use ream_api_types_common::error::ApiError;
use ream_consensus_beacon::electra::beacon_state::BeaconState;
use ream_consensus_misc::constants::beacon::{
    EFFECTIVE_BALANCE_INCREMENT, GENESIS_EPOCH, PARTICIPATION_FLAG_WEIGHTS, SLOTS_PER_EPOCH,
    TIMELY_HEAD_FLAG_INDEX, TIMELY_SOURCE_FLAG_INDEX, TIMELY_TARGET_FLAG_INDEX, WEIGHT_DENOMINATOR,
};
use ream_storage::{
    db::beacon::BeaconDB,
    tables::{field::REDBField, table::REDBTable},
};

use crate::handlers::run_blocking;

fn compute_ideal_attestation_rewards(state: &BeaconState) -> Result<Vec<IdealReward>, ApiError> {
    let base_reward_per_increment = state.get_base_reward_per_increment();
    let active_increments = state.get_total_active_balance() / EFFECTIVE_BALANCE_INCREMENT;
    let previous_epoch = state.get_previous_epoch();
    let is_inactivity_leak = state.is_in_inactivity_leak();

    // Get unslashed participating balances for each flag
    let unslashed_participating_indices_source = state
        .get_unslashed_participating_indices(TIMELY_SOURCE_FLAG_INDEX, previous_epoch)
        .map_err(|err| {
            ApiError::InternalError(format!(
                "Failed to get source participating indices: {err:?}"
            ))
        })?;
    let unslashed_participating_indices_target = state
        .get_unslashed_participating_indices(TIMELY_TARGET_FLAG_INDEX, previous_epoch)
        .map_err(|err| {
            ApiError::InternalError(format!(
                "Failed to get target participating indices: {err:?}"
            ))
        })?;
    let unslashed_participating_indices_head = state
        .get_unslashed_participating_indices(TIMELY_HEAD_FLAG_INDEX, previous_epoch)
        .map_err(|err| {
            ApiError::InternalError(format!("Failed to get head participating indices: {err:?}"))
        })?;

    let unslashed_participating_increments_source = state
        .get_total_balance(unslashed_participating_indices_source)
        / EFFECTIVE_BALANCE_INCREMENT;
    let unslashed_participating_increments_target = state
        .get_total_balance(unslashed_participating_indices_target)
        / EFFECTIVE_BALANCE_INCREMENT;
    let unslashed_participating_increments_head =
        state.get_total_balance(unslashed_participating_indices_head) / EFFECTIVE_BALANCE_INCREMENT;

    // Collect all unique effective balances from validators
    let mut unique_effective_balances: Vec<u64> = state
        .validators
        .iter()
        .map(|v| v.effective_balance)
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    unique_effective_balances.sort_unstable();

    // Calculate ideal rewards for each effective balance
    let mut ideal_rewards = Vec::new();
    for effective_balance in unique_effective_balances {
        let effective_balance_increments = effective_balance / EFFECTIVE_BALANCE_INCREMENT;
        let base_reward = effective_balance_increments * base_reward_per_increment;

        // Calculate ideal reward for each flag (assuming perfect participation, no inactivity leak)
        let ideal_source = if !is_inactivity_leak {
            let reward_numerator = base_reward
                * PARTICIPATION_FLAG_WEIGHTS[TIMELY_SOURCE_FLAG_INDEX as usize]
                * unslashed_participating_increments_source;
            reward_numerator / (active_increments * WEIGHT_DENOMINATOR)
        } else {
            0
        };

        let ideal_target = if !is_inactivity_leak {
            let reward_numerator = base_reward
                * PARTICIPATION_FLAG_WEIGHTS[TIMELY_TARGET_FLAG_INDEX as usize]
                * unslashed_participating_increments_target;
            reward_numerator / (active_increments * WEIGHT_DENOMINATOR)
        } else {
            0
        };

        let ideal_head = if !is_inactivity_leak {
            let reward_numerator = base_reward
                * PARTICIPATION_FLAG_WEIGHTS[TIMELY_HEAD_FLAG_INDEX as usize]
                * unslashed_participating_increments_head;
            reward_numerator / (active_increments * WEIGHT_DENOMINATOR)
        } else {
            0
        };

        ideal_rewards.push(IdealReward {
            effective_balance,
            head: ideal_head,
            target: ideal_target,
            source: ideal_source,
            // Inclusion delay was removed after Altair fork, always 0
            inclusion_delay: 0,
            // Ideal case assumes perfect participation, so no inactivity penalty
            inactivity: 0,
        });
    }

    Ok(ideal_rewards)
}

struct AttestationDeltas {
    source_rewards: Vec<u64>,
    source_penalties: Vec<u64>,
    target_rewards: Vec<u64>,
    target_penalties: Vec<u64>,
    head_rewards: Vec<u64>,
    head_penalties: Vec<u64>,
    inactivity_penalties: Vec<u64>,
}

fn compute_total_attestation_rewards(
    state: &BeaconState,
    deltas: &AttestationDeltas,
    validator_ids: Option<&Vec<ValidatorID>>,
) -> Result<Vec<TotalReward>, ApiError> {
    let eligible_indices = state.get_eligible_validator_indices().map_err(|err| {
        ApiError::InternalError(format!("Failed to get eligible validator indices: {err:?}"))
    })?;

    let mut total_rewards = Vec::new();

    for &validator_index in &eligible_indices {
        // Filter by validator_ids if provided
        if let Some(ids) = validator_ids
            && !ids.is_empty()
        {
            let matches = ids.iter().any(|id| match id {
                ValidatorID::Index(index) => *index == validator_index,
                ValidatorID::Address(pubkey) => {
                    if let Some(validator) = state.validators.get(validator_index as usize) {
                        validator.public_key == *pubkey
                    } else {
                        false
                    }
                }
            });
            if !matches {
                continue;
            }
        }

        let idx = validator_index as usize;

        // Calculate actual rewards/penalties for this validator
        let source = deltas.source_rewards[idx] as i64 - deltas.source_penalties[idx] as i64;
        let target = deltas.target_rewards[idx] as i64 - deltas.target_penalties[idx] as i64;
        let head = deltas.head_rewards[idx] as i64 - deltas.head_penalties[idx] as i64;
        let inactivity = -(deltas.inactivity_penalties[idx] as i64);

        total_rewards.push(TotalReward {
            validator_index,
            head,
            target,
            source,
            inclusion_delay: 0, // Inclusion delay removed after Altair fork
            inactivity,
        });
    }

    Ok(total_rewards)
}

/// Root of the last block in `epoch`. Its last slots can be empty.
fn latest_block_root_in_epoch(db: &BeaconDB, epoch: u64) -> Result<B256, ApiError> {
    let start_slot = epoch * SLOTS_PER_EPOCH;
    for slot in (start_slot..start_slot + SLOTS_PER_EPOCH).rev() {
        if let Some(block_root) = db.slot_index_provider().get(slot).map_err(|err| {
            ApiError::InternalError(format!("Failed to get block root for slot {slot}: {err:?}"))
        })? {
            return Ok(block_root);
        }
    }
    Err(ApiError::NotFound(format!(
        "No block found in epoch {epoch}"
    )))
}

#[post("/beacon/rewards/attestations/{epoch}")]
pub async fn post_attestation_rewards(
    db: Data<BeaconDB>,
    epoch: Path<u64>,
    validator_ids: Json<Option<Vec<ValidatorID>>>,
) -> Result<impl Responder, ApiError> {
    let epoch_value = epoch.into_inner();

    // Genesis epoch has no rewards
    if epoch_value == GENESIS_EPOCH {
        return Err(ApiError::BadRequest(
            "No rewards are applied at the end of genesis epoch".to_string(),
        ));
    }

    let db = db.get_ref().clone();
    let validator_ids = validator_ids.into_inner();
    let response =
        run_blocking(move || attestation_rewards(&db, epoch_value, validator_ids.as_ref())).await?;
    Ok(HttpResponse::Ok().json(response))
}

fn attestation_rewards(
    db: &BeaconDB,
    epoch_value: u64,
    validator_ids: Option<&Vec<ValidatorID>>,
) -> Result<AttestationRewardsResponse, ApiError> {
    // The state at the end of epoch + 1 holds every attestation for the epoch, including late ones.
    let block_root = latest_block_root_in_epoch(db, epoch_value + 1)?;
    let state = db
        .state_provider()
        .get(block_root)
        .map_err(|err| ApiError::InternalError(format!("Failed to get state: {err:?}")))?
        .ok_or_else(|| {
            ApiError::NotFound(format!("Failed to find state for block {block_root}"))
        })?;

    // Check if the epoch is finalized
    let finalized_checkpoint = db.finalized_checkpoint_provider().get().map_err(|err| {
        ApiError::InternalError(format!("Failed to get finalized checkpoint: {err:?}"))
    })?;
    let is_finalized = epoch_value <= finalized_checkpoint.epoch;

    // Calculate rewards for all participation flags
    let (source_rewards, source_penalties) = state
        .get_flag_index_deltas(TIMELY_SOURCE_FLAG_INDEX)
        .map_err(|err| {
            ApiError::InternalError(format!("Failed to calculate source rewards: {err:?}"))
        })?;

    let (target_rewards, target_penalties) = state
        .get_flag_index_deltas(TIMELY_TARGET_FLAG_INDEX)
        .map_err(|err| {
            ApiError::InternalError(format!("Failed to calculate target rewards: {err:?}"))
        })?;

    let (head_rewards, head_penalties) = state
        .get_flag_index_deltas(TIMELY_HEAD_FLAG_INDEX)
        .map_err(|err| {
            ApiError::InternalError(format!("Failed to calculate head rewards: {err:?}"))
        })?;

    let (_, inactivity_penalties) = state.get_inactivity_penalty_deltas().map_err(|err| {
        ApiError::InternalError(format!("Failed to calculate inactivity penalties: {err:?}"))
    })?;

    // Compute ideal rewards for all unique effective balances
    let ideal_rewards = compute_ideal_attestation_rewards(&state)?;

    // Group deltas for cleaner function call
    let deltas = AttestationDeltas {
        source_rewards,
        source_penalties,
        target_rewards,
        target_penalties,
        head_rewards,
        head_penalties,
        inactivity_penalties,
    };

    // Compute total rewards for all eligible validators (with optional filtering)
    let total_rewards = compute_total_attestation_rewards(&state, &deltas, validator_ids)?;

    Ok(AttestationRewardsResponse {
        execution_optimistic: false,
        finalized: is_finalized,
        data: AttestationRewardsData {
            ideal_rewards,
            total_rewards,
        },
    })
}

#[cfg(test)]
mod tests {
    use ream_consensus_beacon::electra::beacon_block::{BeaconBlock, SignedBeaconBlock};
    use ream_storage::db::ReamDB;
    use tempdir::TempDir;
    use tree_hash::TreeHash;

    use super::*;

    #[test]
    fn rewards_state_skips_empty_slots_at_the_end_of_the_epoch() {
        let temp_dir = TempDir::new("ream_rpc_beacon_rewards").expect("creates temp directory");
        let db = ReamDB::new(temp_dir.path().to_path_buf())
            .expect("creates database")
            .init_beacon_db()
            .expect("initializes beacon database");
        let mut roots = vec![];
        for slot in [SLOTS_PER_EPOCH + 1, SLOTS_PER_EPOCH + 8] {
            let block = SignedBeaconBlock {
                message: BeaconBlock {
                    slot,
                    ..Default::default()
                },
                signature: Default::default(),
            };
            let root = block.message.tree_hash_root();
            db.block_provider().insert(root, block).unwrap();
            roots.push(root);
        }

        assert_eq!(latest_block_root_in_epoch(&db, 1).unwrap(), roots[1]);
        assert!(latest_block_root_in_epoch(&db, 2).is_err());
    }
}
