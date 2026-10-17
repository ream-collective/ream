use std::{
    collections::{HashMap, hash_map::Entry},
    sync::Arc,
};

use alloy_primitives::{B256, map::HashSet};
use anyhow::{anyhow, ensure};
use ream_consensus_beacon::{
    attestation::Attestation,
    attester_slashing::AttesterSlashing,
    electra::{beacon_block::SignedBeaconBlock, beacon_state::BeaconState},
    predicates::is_slashable_attestation_data,
};
use ream_consensus_misc::{
    checkpoint::Checkpoint,
    constants::beacon::INTERVALS_PER_SLOT,
    misc::{compute_epoch_at_slot, compute_start_slot_at_epoch},
};
use ream_data_availability::PendingBlock;
use ream_execution_engine::engine_trait::ExecutionApi;
use ream_metrics::{
    BEACON_BLOCK_STATE_TRANSITION_SECONDS, BEACON_CURRENT_ACTIVE_VALIDATORS,
    BEACON_PROCESSED_DEPOSITS_TOTAL,
};
use ream_network_spec::networks::beacon_network_spec;
use ream_storage::{
    db::beacon::{BlockImportData, ForkChoiceRecord},
    errors::StoreError,
    tables::{
        field::{CustomField, REDBField},
        table::REDBTable,
    },
};
use tree_hash::TreeHash;

use crate::store::{Store, StoreCheckpoints};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnBlockOutcome {
    Imported,
    PendingAvailability,
}

/// Run ``on_block`` upon receiving a new block.
pub async fn on_block(
    store: &mut Store,
    signed_block: &SignedBeaconBlock,
    execution_engine: &Option<impl ExecutionApi>,
    verify_data_availability: bool,
) -> anyhow::Result<OnBlockOutcome> {
    let block_root = signed_block.message.tree_hash_root();
    on_block_with_root(
        store,
        signed_block,
        block_root,
        execution_engine,
        verify_data_availability,
    )
    .await
}

/// ``on_block`` for a block whose root the caller already computed. Hashing a mainnet block
/// hashes its whole execution payload, a few milliseconds each time.
pub async fn on_block_with_root(
    store: &mut Store,
    signed_block: &SignedBeaconBlock,
    block_root: B256,
    execution_engine: &Option<impl ExecutionApi>,
    verify_data_availability: bool,
) -> anyhow::Result<OnBlockOutcome> {
    let block = &signed_block.message;
    let parent_root = block.parent_root;
    let block_slot = block.slot;
    let started = std::time::Instant::now();

    // Parent block must be known
    ensure!(
        store.db.state_provider().contains_key(parent_root)?,
        "Missing parent block state for parent_root: {parent_root:x}",
    );

    // Blocks cannot be in the future. If they are, their consideration must be delayed until they
    // are in the past.
    let current_slot = store.get_current_slot()?;
    ensure!(
        current_slot >= block_slot,
        "Block slot is ahead of current slot: block.slot = {block_slot}, store.get_current_slot() = {current_slot}",
    );

    // Check that block is later than the finalized epoch slot (optimization to reduce calls to
    // get_ancestor)
    let finalized_slot =
        compute_start_slot_at_epoch(store.db.finalized_checkpoint_provider().get()?.epoch);
    ensure!(
        block_slot > finalized_slot,
        "Block slot must be greater than finalized slot: block.slot = {block_slot}, finalized_slot = {finalized_slot}",
    );

    // Check block is a descendant of the finalized block at the checkpoint finalized slot
    let finalized_checkpoint_block = store.get_checkpoint_block(
        parent_root,
        store.db.finalized_checkpoint_provider().get()?.epoch,
    )?;
    ensure!(store.db.finalized_checkpoint_provider().get()?.root == finalized_checkpoint_block);
    // Check the block is valid and compute the post-state
    // Make a copy of the state to avoid mutability issues
    let mut state = Arc::unwrap_or_clone(
        store
            .db
            .state_provider()
            .get_shared(parent_root)?
            .ok_or_else(|| anyhow!("beacon state not found"))?,
    );
    // The parent state is the parent block's post-state, and the parent block commits to its root,
    // which was checked when the parent was imported.
    let parent_state_root = store
        .db
        .block_provider()
        .get(parent_root)?
        .ok_or_else(|| anyhow!("parent block not found"))?
        .message
        .state_root;
    let state_loaded = started.elapsed();
    let state_transition_timer = BEACON_BLOCK_STATE_TRANSITION_SECONDS.start_timer();
    let epoch_start_state = state
        .state_transition_keeping_epoch_start(
            signed_block,
            true,
            execution_engine,
            Some(parent_state_root),
        )
        .await?;
    state_transition_timer.observe_duration();
    let transitioned = started.elapsed();
    tracing::info!(
        slot = block_slot,
        checks_and_state_load_ms = state_loaded.as_millis() as u64,
        state_transition_ms = (transitioned - state_loaded).as_millis() as u64,
        "timing: on_block"
    );
    if let Some(epoch_start_state) = epoch_start_state {
        store.db.checkpoint_states_provider().insert_shared(
            Checkpoint {
                epoch: compute_epoch_at_slot(block_slot),
                root: parent_root,
            },
            Arc::new(epoch_start_state),
        );
    }

    let pending = PendingBlock {
        signed_block: signed_block.clone(),
        post_state: state,
    };

    // If no data availability check is required, process the block immediately.
    if !verify_data_availability {
        process_available_block(store, pending, block_root)?;
        return Ok(OnBlockOutcome::Imported);
    }

    store.data_availability_checker.insert_pending(
        block_root,
        pending.signed_block,
        pending.post_state,
    );
    let available = store.data_availability_checker.take_if_complete(block_root);
    // The backfill here is the case when data columns come before the arrival of this block.
    // Then we have to backfill the availability columns for this block.
    // This is a rare case - but can still happen.
    let available = match available {
        Some(available) => Some(available),
        None => store.backfill_data_availability_columns(block_root)?,
    };

    match available {
        Some(available) => {
            process_available_block(store, available, block_root)?;
            Ok(OnBlockOutcome::Imported)
        }
        None => Ok(OnBlockOutcome::PendingAvailability),
    }
}

/// Imports `pending`, the block at `block_root`, once its data is available.
pub fn process_available_block(
    store: &mut Store,
    pending: PendingBlock,
    block_root: B256,
) -> anyhow::Result<()> {
    let signed_block = pending.signed_block;
    let block_slot = signed_block.message.slot;
    let parent_root = signed_block.message.parent_root;
    let state = Arc::new(pending.post_state);

    // Complete every fallible read and consensus calculation before publishing the import.
    let time_into_slot = (store.db.time_provider().get()?
        - store.db.genesis_time_provider().get()?)
        % beacon_network_spec().seconds_per_slot();
    let is_before_attesting_interval =
        time_into_slot < beacon_network_spec().seconds_per_slot() / INTERVALS_PER_SLOT;
    let is_timely = store.get_current_slot()? == block_slot && is_before_attesting_interval;
    let proposer_boost_root = (is_timely
        && store.db.proposer_boost_root_provider().get()? == B256::ZERO)
        .then_some(block_root);
    let pulled_up = state.compute_justification_and_finalization()?;
    let current_epoch = store.get_current_store_epoch()?;

    let mut checkpoints = StoreCheckpoints::read(&store.db)?;
    checkpoints.realize(
        state.current_justified_checkpoint,
        state.finalized_checkpoint,
        state.previous_justified_checkpoint,
    );
    checkpoints.pull_up(
        pulled_up.current_justified_checkpoint,
        pulled_up.finalized_checkpoint,
    );
    // A block from a prior epoch has its pulled-up checkpoints realized immediately.
    if compute_epoch_at_slot(state.slot) < current_epoch {
        checkpoints.realize(
            pulled_up.current_justified_checkpoint,
            pulled_up.finalized_checkpoint,
            pulled_up.previous_justified_checkpoint,
        );
    }
    let writes = checkpoints.writes();

    let commit_started = std::time::Instant::now();
    store.db.commit_block_import(BlockImportData {
        block_root,
        block: signed_block,
        state: state.clone(),
        record: ForkChoiceRecord {
            is_timely,
            proposer_boost_root,
            unrealized_justification: pulled_up.current_justified_checkpoint,
            checkpoints: writes,
        },
    })?;
    tracing::info!(
        slot = block_slot,
        commit_ms = commit_started.elapsed().as_millis() as u64,
        "timing: block commit"
    );

    BEACON_PROCESSED_DEPOSITS_TOTAL.set(state.eth1_deposit_index as i64);
    BEACON_CURRENT_ACTIVE_VALIDATORS.set(
        state
            .get_shuffled_active_validator_indices(state.get_current_epoch())
            .len() as i64,
    );
    // `realize` always sets the previous justified checkpoint.
    if let Some(previous_justified) = checkpoints.previous_justified {
        store.publish_checkpoint_writes(&writes, previous_justified);
    }
    state.prepare_next_epoch_shuffling();

    // Fork choice tree maintenance is the last step, once the store mutation is committed.
    store.fork_choice_insert_block(
        block_root,
        parent_root,
        block_slot,
        state.current_justified_checkpoint,
    );
    store.refresh_fork_choice();

    Ok(())
}

/// Runs ``on_attestation`` with ``is_from_block`` for the attestations of a block whose
/// ``state_transition`` succeeded, returning one result per attestation.
///
/// ``state_transition`` already verified each attestation's signature against the same committees
/// the target state yields, so the signature is not verified again here. Each target checkpoint
/// state is read once per block: decoding it costs as much as the rest of the work for one
/// attestation.
pub fn on_block_attestations(
    store: &mut Store,
    attestations: &[Attestation],
) -> Vec<anyhow::Result<()>> {
    let mut target_states: HashMap<Checkpoint, Arc<BeaconState>> = HashMap::new();
    let mut votes = Vec::new();
    let mut results = Vec::with_capacity(attestations.len());
    for attestation in attestations {
        let attesting_indices = (|| {
            store.validate_on_attestation(attestation, true)?;
            let target = attestation.data.target;
            let target_state = match target_states.entry(target) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => entry.insert(
                    store
                        .db
                        .checkpoint_states_provider()
                        .get_shared(target)?
                        .ok_or_else(|| anyhow!("checkpoint_states not found"))?,
                ),
            };
            anyhow::Ok(
                target_state
                    .get_indexed_attestation(attestation)?
                    .attesting_indices,
            )
        })();
        results.push(attesting_indices.map(|indices| {
            votes.push((indices.to_vec(), attestation.clone()));
        }));
    }

    // One write covers every valid attestation, so its failure fails each of them.
    if let Err(err) = store.update_latest_messages_batch(votes) {
        for result in results.iter_mut().filter(|result| result.is_ok()) {
            *result = Err(anyhow!("failed to update latest messages: {err:#}"));
        }
    }
    results
}

/// Run ``on_attester_slashing`` immediately upon receiving a new ``AttesterSlashing``
/// from either within a block or directly on the wire.
pub fn on_attester_slashing(
    store: &mut Store,
    attester_slashing: AttesterSlashing,
) -> anyhow::Result<()> {
    let attestation_1 = attester_slashing.attestation_1;
    let attestation_2 = attester_slashing.attestation_2;

    ensure!(is_slashable_attestation_data(
        &attestation_1.data,
        &attestation_2.data
    ));

    let state = store
        .db
        .state_provider()
        .get_shared(store.db.justified_checkpoint_provider().get()?.root)?
        .ok_or_else(|| anyhow!("beacon state not found"))?;

    ensure!(state.is_valid_indexed_attestation(&attestation_1)?);
    ensure!(state.is_valid_indexed_attestation(&attestation_2)?);

    let attestation_1_indices = attestation_1
        .attesting_indices
        .into_iter()
        .collect::<HashSet<_>>();

    let attestation_2_indices = attestation_2
        .attesting_indices
        .into_iter()
        .collect::<HashSet<_>>();

    let mut equivocating = match store.db.equivocating_indices_provider().get() {
        Ok(set) => set,
        Err(StoreError::FieldNotInitilized) => HashSet::default(),
        Err(err) => return Err(err.into()),
    };

    let newly_equivocating = attestation_1_indices
        .intersection(&attestation_2_indices)
        .copied()
        .collect::<Vec<_>>();
    for index in &newly_equivocating {
        equivocating.insert(*index);
    }

    store
        .db
        .equivocating_indices_provider()
        .insert(equivocating)?;
    store.fork_choice_mark_equivocating(newly_equivocating);

    Ok(())
}

pub fn on_tick(store: &mut Store, time: u64) -> anyhow::Result<()> {
    // If the ``store.time`` falls behind, while loop catches up slot by slot
    // to ensure that every previous slot is processed with ``on_tick_per_slot``
    // A node started ahead of genesis ticks with a `time` below it. Subtracting would wrap,
    // making `tick_slot` ~u64::MAX and turning the catch-up below into a loop that never
    // ends, hanging whichever task called us. There is no slot to advance to yet either, and
    // storing the pre-genesis `time` would walk the store's slot backwards, so do nothing.
    let genesis_time = store.db.genesis_time_provider().get()?;
    if time < genesis_time {
        return Ok(());
    }

    let tick_slot = (time - genesis_time) / beacon_network_spec().seconds_per_slot();
    while store.get_current_slot()? < tick_slot {
        let previous_time = store.db.genesis_time_provider().get()?
            + (store.get_current_slot()? + 1) * beacon_network_spec().seconds_per_slot();
        store.on_tick_per_slot(previous_time)?;
    }
    store.on_tick_per_slot(time)?;

    Ok(())
}

/// Run ``on_attestation`` upon receiving a new ``attestation`` from either within a block or
/// directly on the wire.
///
/// An ``attestation`` that is asserted as invalid may be valid at a later time,
/// consider scheduling it for later processing in such case.
pub fn on_attestation(
    store: &mut Store,
    attestation: Attestation,
    is_from_block: bool,
) -> anyhow::Result<()> {
    store.validate_on_attestation(&attestation, is_from_block)?;

    // Get state at the `target` to fully validate attestation. The checkpoint states table
    // computes it when missing; sharing it avoids copying a state per attestation.
    let target_state = store
        .db
        .checkpoint_states_provider()
        .get_shared(attestation.data.target)?
        .ok_or_else(|| anyhow!("checkpoint_states not found"))?;
    let indexed_attestation = target_state.get_indexed_attestation(&attestation)?;
    ensure!(target_state.is_valid_indexed_attestation(&indexed_attestation)?);
    // Update latest messages for attesting indices
    store.update_latest_messages(indexed_attestation.attesting_indices.to_vec(), attestation)?;

    Ok(())
}

/// ``on_attestation`` for a gossip attestation whose single attester's signature gossip validation
/// already verified, so it is not verified again here. That check only covers
/// ``verified_attester``, so the target state's committee must name exactly that validator: under
/// a different shuffling the attestation's bit would belong to someone else.
pub fn on_gossip_attestation(
    store: &mut Store,
    attestation: Attestation,
    verified_attester: u64,
) -> anyhow::Result<()> {
    store.validate_on_attestation(&attestation, false)?;

    let target_state = store
        .db
        .checkpoint_states_provider()
        .get_shared(attestation.data.target)?
        .ok_or_else(|| anyhow!("checkpoint_states not found"))?;
    let indexed_attestation = target_state.get_indexed_attestation(&attestation)?;
    ensure_only_attester(&indexed_attestation.attesting_indices, verified_attester)?;
    store.update_latest_messages(vec![verified_attester], attestation)?;

    Ok(())
}

fn ensure_only_attester(attesting_indices: &[u64], verified_attester: u64) -> anyhow::Result<()> {
    ensure!(
        attesting_indices == [verified_attester],
        "target committee names {attesting_indices:?}, not the verified attester {verified_attester}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::ensure_only_attester;

    #[test]
    fn a_gossip_vote_counts_only_for_the_verified_attester() {
        assert!(ensure_only_attester(&[7], 7).is_ok());
        assert!(ensure_only_attester(&[8], 7).is_err());
        assert!(ensure_only_attester(&[7, 8], 7).is_err());
        assert!(ensure_only_attester(&[], 7).is_err());
    }
}
