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
    constants::beacon::MIN_SEED_LOOKAHEAD,
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

use crate::store::{
    Store, StoreCheckpoints, get_slot_component_duration_ms, get_slots_since_genesis_at,
    get_time_at_slot, seconds_to_milliseconds,
};

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
    // The parent state is the parent block's post-state, and the parent block commits to its root,
    // which was checked when the parent was imported.
    let parent_block = store
        .db
        .block_provider()
        .get(parent_root)?
        .ok_or_else(|| anyhow!("parent block not found"))?
        .message;
    let block_epoch = compute_epoch_at_slot(block_slot);
    let epoch_start_checkpoint = Checkpoint {
        epoch: block_epoch,
        root: parent_root,
    };
    // The parent state advanced to this epoch's first slot, when it was built before the block
    // came: by the state advance at the end of the previous epoch, or for an attestation target.
    // Starting from it skips the epoch processing, about 1 s on mainnet.
    let advanced_parent_state = if compute_epoch_at_slot(parent_block.slot) < block_epoch {
        store
            .db
            .checkpoint_states_provider()
            .in_memory(epoch_start_checkpoint)
    } else {
        None
    };
    let advanced_pre_state = advanced_parent_state.is_some();
    let (mut state, epoch_start_state) = match advanced_parent_state {
        Some(epoch_start_state) => (
            Arc::unwrap_or_clone(epoch_start_state.clone()),
            Some(epoch_start_state),
        ),
        None => (
            Arc::unwrap_or_clone(
                store
                    .db
                    .state_provider()
                    .get_shared(parent_root)?
                    .ok_or_else(|| anyhow!("beacon state not found"))?,
            ),
            None,
        ),
    };
    let state_loaded = started.elapsed();
    let state_transition_timer = BEACON_BLOCK_STATE_TRANSITION_SECONDS.start_timer();
    let epoch_start_state = if advanced_pre_state {
        state
            .state_transition_from_epoch_start(signed_block, true, execution_engine)
            .await?;
        epoch_start_state
    } else {
        state
            .state_transition_keeping_epoch_start(
                signed_block,
                true,
                execution_engine,
                Some(parent_block.state_root),
            )
            .await?
            .map(Arc::new)
    };
    state_transition_timer.observe_duration();
    let transitioned = started.elapsed();
    tracing::debug!(
        target: "ream::timing",
        slot = block_slot,
        checks_and_state_load_ms = state_loaded.as_millis() as u64,
        state_transition_ms = (transitioned - state_loaded).as_millis() as u64,
        advanced_pre_state,
        "timing: on_block"
    );
    // The checkpoint state of the block's epoch is at hand in two cases: the block is at the
    // epoch's first slot, and then its post-state is that checkpoint state; or the first slot was
    // skipped, and then the epoch-start state is the parent's checkpoint state. Its fork choice
    // balances are cached for when the checkpoint becomes justified.
    if block_slot == compute_start_slot_at_epoch(block_epoch) {
        store.cache_fork_choice_balances(
            Checkpoint {
                epoch: block_epoch,
                root: block_root,
            },
            &state,
        );
    } else if let Some(epoch_start_state) = &epoch_start_state {
        store.cache_fork_choice_balances(epoch_start_checkpoint, epoch_start_state);
    }
    // An advanced parent state is in memory already.
    if let Some(epoch_start_state) = epoch_start_state
        && !advanced_pre_state
    {
        store
            .db
            .checkpoint_states_provider()
            .insert_shared(epoch_start_checkpoint, epoch_start_state);
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
    let seconds_since_genesis = store
        .db
        .time_provider()
        .get()?
        .saturating_sub(store.db.genesis_time_provider().get()?);
    let time_into_slot_ms =
        seconds_to_milliseconds(seconds_since_genesis) % beacon_network_spec().slot_duration_ms;
    let attestation_threshold_ms =
        get_slot_component_duration_ms(beacon_network_spec().attestation_due_bps);
    let is_before_attesting_interval = time_into_slot_ms < attestation_threshold_ms;
    let is_timely = store.get_current_slot()? == block_slot && is_before_attesting_interval;
    let proposer_boost_root =
        get_proposer_boost_root(store, block_root, block_slot, parent_root, is_timely)?;
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
    tracing::debug!(
        target: "ream::timing",
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

fn get_dependent_root(store: &Store, root: B256) -> anyhow::Result<B256> {
    let epoch = store.get_current_store_epoch()?;
    if epoch <= MIN_SEED_LOOKAHEAD {
        return Ok(B256::ZERO);
    }

    let dependent_slot = compute_start_slot_at_epoch(epoch - MIN_SEED_LOOKAHEAD) - 1;
    store.get_ancestor(root, dependent_slot)
}

/// Computes the candidate block's dependent root before the block is committed. This is
/// equivalent to inserting the block and calling `get_dependent_root`: if the block is newer than
/// the dependent slot, the lookup immediately continues from its already-stored parent.
fn get_candidate_dependent_root(
    store: &Store,
    block_root: B256,
    block_slot: u64,
    parent_root: B256,
) -> anyhow::Result<B256> {
    let epoch = store.get_current_store_epoch()?;
    if epoch <= MIN_SEED_LOOKAHEAD {
        return Ok(B256::ZERO);
    }

    let dependent_slot = compute_start_slot_at_epoch(epoch - MIN_SEED_LOOKAHEAD) - 1;
    if block_slot > dependent_slot {
        store.get_ancestor(parent_root, dependent_slot)
    } else {
        Ok(block_root)
    }
}

/// The spec's `update_proposer_boost_root` for a block that is not committed yet.
///
/// Only the first timely block of a slot can be boosted, so every other block returns before the
/// head and ancestor lookups, as in Lighthouse. The spec computes the head on every import but
/// uses it only here. Without the fork choice tree that head is a full fork choice run over the
/// database.
fn get_proposer_boost_root(
    store: &Store,
    block_root: B256,
    block_slot: u64,
    parent_root: B256,
    is_timely: bool,
) -> anyhow::Result<Option<B256>> {
    let is_first_block = store.db.proposer_boost_root_provider().get()? == B256::ZERO;
    if !is_timely || !is_first_block {
        return Ok(None);
    }

    // The spec computes the head after the state transition and data-availability check, but
    // before publishing this block to fork choice.
    let head_root = store.get_head()?;
    let is_same_dependent_root =
        is_same_dependent_root(store, head_root, block_root, block_slot, parent_root)?;
    Ok(is_same_dependent_root.then_some(block_root))
}

fn is_same_dependent_root(
    store: &Store,
    head_root: B256,
    block_root: B256,
    block_slot: u64,
    parent_root: B256,
) -> anyhow::Result<bool> {
    Ok(
        get_candidate_dependent_root(store, block_root, block_slot, parent_root)?
            == get_dependent_root(store, head_root)?,
    )
}

/// Runs ``on_attestation`` with ``is_from_block`` for the attestations of a block whose
/// ``state_transition`` succeeded, returning one result per attestation.
///
/// ``state_transition`` already verified each attestation's signature with the committees of the
/// block's own chain. A target whose checkpoint state has the same shuffling has the same
/// committees, so they are read from the block's post-state and the signature is not verified
/// again, as Prysm's `handleBlockAttestations` does; building that checkpoint state can mean
/// epoch processing. This covers targets on the block's chain and, when an epoch's first block
/// came late, targets naming an earlier block of that chain. A target on a fork that split before
/// the shuffling decision slot can have other committees, so its committee comes from its
/// checkpoint state and the signature is verified against it, as the spec does. Each such
/// checkpoint state is read once per block.
pub fn on_block_attestations(
    store: &mut Store,
    block_root: B256,
    attestations: &[Attestation],
) -> Vec<anyhow::Result<()>> {
    let block_state = store
        .db
        .state_provider()
        .get_shared(block_root)
        .ok()
        .flatten();
    let mut target_states: HashMap<Checkpoint, Arc<BeaconState>> = HashMap::new();
    let mut votes = Vec::new();
    let mut results = Vec::with_capacity(attestations.len());
    for attestation in attestations {
        let attesting_indices = (|| {
            store.validate_on_attestation(attestation, true)?;
            let target = attestation.data.target;
            if let Some(block_state) = block_state.as_ref()
                && shares_target_shuffling(
                    store,
                    block_state.get_current_epoch(),
                    block_root,
                    target,
                )?
            {
                return anyhow::Ok(
                    block_state
                        .get_indexed_attestation(attestation)?
                        .attesting_indices,
                );
            }
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
            let indexed_attestation = target_state.get_indexed_attestation(attestation)?;
            if !is_on_chain_of(store, block_root, target)? {
                ensure!(
                    target_state.is_valid_indexed_attestation(&indexed_attestation)?,
                    "Attestation signature must be valid for the target state"
                );
            }
            anyhow::Ok(indexed_attestation.attesting_indices)
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

/// Whether `target` is the checkpoint of the chain ending at `block_root`: its block is that
/// chain's ancestor at the target epoch's start slot.
pub fn is_on_chain_of(store: &Store, block_root: B256, target: Checkpoint) -> anyhow::Result<bool> {
    Ok(store.get_ancestor(block_root, compute_start_slot_at_epoch(target.epoch))? == target.root)
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

    let tick_slot = get_slots_since_genesis_at(time, genesis_time);
    while store.get_current_slot()? < tick_slot {
        let previous_time = get_time_at_slot(genesis_time, store.get_current_slot()? + 1);
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

/// Whether the post-state of block `state_block_root`, at `state_epoch`, has the same shuffling
/// for `target.epoch` as the target checkpoint state, so committees can be read from it without
/// building that checkpoint state.
///
/// Committees of epoch E depend on the RANDAO mix of epoch E - 2 and on the validators active in
/// E, and activations and exits are scheduled at least five epochs ahead. Two chains that share
/// the block at the last slot of epoch E - 2 therefore share E's committees. This is Lighthouse's
/// shuffling decision root and Prysm's `getRecentPreState` check. The state must also hold that
/// data, which it does for its previous, current and next epoch
/// (`BeaconState::determines_committees_of`).
pub fn shares_target_shuffling(
    store: &Store,
    state_epoch: u64,
    state_block_root: B256,
    target: Checkpoint,
) -> anyhow::Result<bool> {
    let held_by_state = target.epoch + 1 >= state_epoch && target.epoch <= state_epoch + 1;
    if target.epoch <= MIN_SEED_LOOKAHEAD || !held_by_state {
        return Ok(false);
    }
    let decision_slot = compute_start_slot_at_epoch(target.epoch - MIN_SEED_LOOKAHEAD) - 1;
    Ok(store.get_ancestor(state_block_root, decision_slot)?
        == store.get_ancestor(target.root, decision_slot)?)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use alloy_primitives::B256;
    use ream_consensus_beacon::electra::beacon_block::{BeaconBlock, SignedBeaconBlock};
    use ream_consensus_misc::checkpoint::Checkpoint;
    use ream_network_spec::networks::initialize_test_network_spec;
    use ream_operation_pool::OperationPool;
    use ream_storage::{
        db::ReamDB,
        tables::{field::REDBField, table::REDBTable},
    };
    use tempdir::TempDir;

    use super::{
        Store, get_proposer_boost_root, get_time_at_slot, is_on_chain_of, is_same_dependent_root,
        shares_target_shuffling,
    };

    fn block(slot: u64, parent_root: B256) -> SignedBeaconBlock {
        SignedBeaconBlock {
            message: BeaconBlock {
                slot,
                parent_root,
                ..Default::default()
            },
            signature: Default::default(),
        }
    }

    #[test]
    fn proposer_boost_is_withheld_for_a_different_dependent_root() {
        initialize_test_network_spec();
        let temp_dir = TempDir::new("ream_proposer_boost_dependent_root").unwrap();
        let db = ReamDB::new(temp_dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        let genesis_time = 1_000;
        let current_slot = 2 * ream_consensus_misc::constants::beacon::SLOTS_PER_EPOCH;
        db.genesis_time_provider().insert(genesis_time).unwrap();
        db.time_provider()
            .insert(get_time_at_slot(genesis_time, current_slot))
            .unwrap();
        db.proposer_boost_root_provider()
            .insert(B256::ZERO)
            .unwrap();

        let head_dependent_root = B256::repeat_byte(0x11);
        let head_root = B256::repeat_byte(0x12);
        let candidate_dependent_root = B256::repeat_byte(0x21);
        let candidate_parent_root = B256::repeat_byte(0x22);
        let candidate_root = B256::repeat_byte(0x23);
        let dependent_slot = ream_consensus_misc::constants::beacon::SLOTS_PER_EPOCH - 1;

        for (root, signed_block) in [
            (head_dependent_root, block(dependent_slot, B256::ZERO)),
            (head_root, block(current_slot - 1, head_dependent_root)),
            (candidate_dependent_root, block(dependent_slot, B256::ZERO)),
            (
                candidate_parent_root,
                block(current_slot - 1, candidate_dependent_root),
            ),
        ] {
            db.block_provider().insert(root, signed_block).unwrap();
        }

        let store = Store::new(db, Arc::new(OperationPool::default()), None);
        assert!(
            !is_same_dependent_root(
                &store,
                head_root,
                candidate_root,
                current_slot,
                candidate_parent_root,
            )
            .unwrap()
        );
        assert!(
            is_same_dependent_root(&store, head_root, candidate_root, current_slot, head_root)
                .unwrap()
        );
    }

    #[test]
    fn block_attestation_targets_are_matched_to_the_block_chain() {
        initialize_test_network_spec();
        let temp_dir = TempDir::new("ream_block_attestation_targets").unwrap();
        let db = ReamDB::new(temp_dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        let slots_per_epoch = ream_consensus_misc::constants::beacon::SLOTS_PER_EPOCH;
        let checkpoint_root = B256::repeat_byte(0x11);
        let block_root = B256::repeat_byte(0x12);
        let fork_checkpoint_root = B256::repeat_byte(0x21);
        for (root, signed_block) in [
            (checkpoint_root, block(slots_per_epoch, B256::ZERO)),
            (block_root, block(slots_per_epoch + 5, checkpoint_root)),
            (fork_checkpoint_root, block(slots_per_epoch, B256::ZERO)),
        ] {
            db.block_provider().insert(root, signed_block).unwrap();
        }
        let store = Store::new(db, Arc::new(OperationPool::default()), None);
        let target = |root| Checkpoint { epoch: 1, root };

        // The block's chain has `checkpoint_root` at epoch 1's start slot.
        assert!(is_on_chain_of(&store, block_root, target(checkpoint_root)).unwrap());
        assert!(!is_on_chain_of(&store, block_root, target(fork_checkpoint_root)).unwrap());
    }

    #[test]
    fn a_target_before_a_late_first_block_shares_the_block_shuffling() {
        initialize_test_network_spec();
        let temp_dir = TempDir::new("ream_late_first_block_target").unwrap();
        let db = ReamDB::new(temp_dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        let slots_per_epoch = ream_consensus_misc::constants::beacon::SLOTS_PER_EPOCH;
        // Epoch 2's shuffling is decided at slot 31. Some attesters missed epoch 2's first block
        // and named the last block of epoch 1 as their target.
        let decision_root = B256::repeat_byte(0x11);
        let last_epoch_one_root = B256::repeat_byte(0x12);
        let first_epoch_two_root = B256::repeat_byte(0x13);
        let block_root = B256::repeat_byte(0x14);
        for (root, signed_block) in [
            (decision_root, block(slots_per_epoch - 1, B256::ZERO)),
            (
                last_epoch_one_root,
                block(2 * slots_per_epoch - 1, decision_root),
            ),
            (
                first_epoch_two_root,
                block(2 * slots_per_epoch, last_epoch_one_root),
            ),
            (
                block_root,
                block(2 * slots_per_epoch + 6, first_epoch_two_root),
            ),
        ] {
            db.block_provider().insert(root, signed_block).unwrap();
        }
        let store = Store::new(db, Arc::new(OperationPool::default()), None);
        let late_target = Checkpoint {
            epoch: 2,
            root: last_epoch_one_root,
        };

        // Not the block chain's checkpoint, yet the same shuffling.
        assert!(!is_on_chain_of(&store, block_root, late_target).unwrap());
        assert!(shares_target_shuffling(&store, 2, block_root, late_target).unwrap());
    }

    #[test]
    fn head_state_is_used_only_for_targets_sharing_its_shuffling() {
        initialize_test_network_spec();
        let temp_dir = TempDir::new("ream_target_committees").unwrap();
        let db = ReamDB::new(temp_dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        let slots_per_epoch = ream_consensus_misc::constants::beacon::SLOTS_PER_EPOCH;
        // Committees of epoch 2 are decided by the block at slot 31, the last slot of epoch 0.
        let decision_slot = slots_per_epoch - 1;
        let decision_root = B256::repeat_byte(0x11);
        let head_root = B256::repeat_byte(0x12);
        let fork_decision_root = B256::repeat_byte(0x21);
        let fork_root = B256::repeat_byte(0x22);
        for (root, signed_block) in [
            (decision_root, block(decision_slot, B256::ZERO)),
            (head_root, block(2 * slots_per_epoch, decision_root)),
            (fork_decision_root, block(decision_slot, B256::ZERO)),
            (fork_root, block(2 * slots_per_epoch, fork_decision_root)),
        ] {
            db.block_provider().insert(root, signed_block).unwrap();
        }
        let store = Store::new(db, Arc::new(OperationPool::default()), None);
        let head_epoch = 2;
        let target = |epoch, root| Checkpoint { epoch, root };

        assert!(
            shares_target_shuffling(&store, head_epoch, head_root, target(2, head_root)).unwrap()
        );
        // A target on a fork with another block at the decision slot has other committees.
        assert!(
            !shares_target_shuffling(&store, head_epoch, head_root, target(2, fork_root)).unwrap()
        );
        // The head state does not hold the data for epochs beyond its next one, and committees
        // of the first epochs are not looked up this way.
        assert!(
            !shares_target_shuffling(&store, head_epoch, head_root, target(4, head_root)).unwrap()
        );
        assert!(
            !shares_target_shuffling(&store, head_epoch, head_root, target(1, head_root)).unwrap()
        );
    }

    #[test]
    fn proposer_boost_skips_head_lookup_unless_first_timely_block() {
        initialize_test_network_spec();
        let temp_dir = TempDir::new("ream_proposer_boost_gate").unwrap();
        let db = ReamDB::new(temp_dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        let genesis_time = 1_000;
        let current_slot = 2 * ream_consensus_misc::constants::beacon::SLOTS_PER_EPOCH;
        db.genesis_time_provider().insert(genesis_time).unwrap();
        db.time_provider()
            .insert(get_time_at_slot(genesis_time, current_slot))
            .unwrap();
        db.proposer_boost_root_provider()
            .insert(B256::ZERO)
            .unwrap();
        // No checkpoints or blocks are stored, so a head or ancestor lookup would fail.
        let store = Store::new(db, Arc::new(OperationPool::default()), None);
        let candidate_root = B256::repeat_byte(0x23);
        let parent_root = B256::repeat_byte(0x22);

        assert_eq!(
            get_proposer_boost_root(&store, candidate_root, current_slot, parent_root, false)
                .unwrap(),
            None
        );
        assert!(
            get_proposer_boost_root(&store, candidate_root, current_slot, parent_root, true)
                .is_err()
        );

        store
            .db
            .proposer_boost_root_provider()
            .insert(B256::repeat_byte(0x99))
            .unwrap();
        assert_eq!(
            get_proposer_boost_root(&store, candidate_root, current_slot, parent_root, true)
                .unwrap(),
            None
        );
    }
}
