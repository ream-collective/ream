use std::sync::Arc;

use anyhow::anyhow;
use ream_chain_beacon::beacon_chain::BeaconChain;
use ream_consensus_beacon::electra::{beacon_block::SignedBeaconBlock, beacon_state::BeaconState};
use ream_consensus_misc::{
    blob_parameters::{BlobParameters, get_blob_parameters},
    misc::{compute_epoch_at_slot, compute_start_slot_at_epoch},
};
#[cfg(not(feature = "disable_ancestor_validation"))]
use ream_fork_choice_beacon::store::get_checkpoint_block_from_db;
use ream_fork_choice_beacon::store::get_current_slot_from_db;
use ream_network_spec::networks::beacon_network_spec;
use ream_storage::{
    cache::{AddressSlotIdentifier, BeaconCacheDB},
    tables::field::REDBField,
};

use super::{
    parent::{ParentBlock, find_parent},
    result::{DependencyValidationResult, ValidationResult},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GossipValidatedBlock {
    block: Box<SignedBeaconBlock>,
}

impl GossipValidatedBlock {
    fn new(block: SignedBeaconBlock) -> Self {
        Self {
            block: Box::new(block),
        }
    }

    pub(crate) fn block(&self) -> &SignedBeaconBlock {
        &self.block
    }

    pub(crate) fn into_inner(self) -> SignedBeaconBlock {
        *self.block
    }
}

struct ParentContext {
    block: SignedBeaconBlock,
    state: Arc<BeaconState>,
    pending_availability: bool,
}

pub async fn validate_gossip_beacon_block(
    beacon_chain: &BeaconChain,
    cached_db: &BeaconCacheDB,
    block: &SignedBeaconBlock,
) -> anyhow::Result<DependencyValidationResult<GossipValidatedBlock>> {
    validate_block_with_parent(beacon_chain, cached_db, block, true).await
}

/// ``validate_gossip_beacon_block`` for a block an unknown-parent lookup releases once its parent
/// is known. The "first block with a valid signature for the proposer and slot" rule only decides
/// what gossip propagates: this block may have recorded its own signature when it first arrived,
/// and importing it now is not a second propagation.
pub async fn validate_lookup_beacon_block(
    beacon_chain: &BeaconChain,
    cached_db: &BeaconCacheDB,
    block: &SignedBeaconBlock,
) -> anyhow::Result<DependencyValidationResult<GossipValidatedBlock>> {
    validate_block_with_parent(beacon_chain, cached_db, block, false).await
}

async fn validate_block_with_parent(
    beacon_chain: &BeaconChain,
    cached_db: &BeaconCacheDB,
    block: &SignedBeaconBlock,
    enforce_first_seen: bool,
) -> anyhow::Result<DependencyValidationResult<GossipValidatedBlock>> {
    let db = beacon_chain.db();

    if block.message.slot > get_current_slot_from_db(db)? {
        return Ok(DependencyValidationResult::Ignore(
            "Block is from a future slot".to_string(),
        ));
    }

    let finalized_checkpoint = db.finalized_checkpoint_provider().get()?;
    if block.message.slot <= compute_start_slot_at_epoch(finalized_checkpoint.epoch) {
        return Ok(DependencyValidationResult::Ignore(
            "Block is not from a slot greater than the latest finalized slot".to_string(),
        ));
    }

    // Database reads do not need the store lock; `find_parent` takes it briefly, and only when the
    // parent is not imported, to consult the pending-availability set.
    let parent = match find_parent(beacon_chain, block.message.parent_root).await? {
        Some(ParentBlock::Imported { block, state }) => {
            let Some(parent_state) = state else {
                return Err(anyhow!(
                    "failed to get state for known parent block {}",
                    block.message.parent_root
                ));
            };
            Some(ParentContext {
                block,
                state: parent_state,
                pending_availability: false,
            })
        }
        Some(ParentBlock::PendingAvailability { block, state }) => Some(ParentContext {
            block,
            state,
            pending_availability: true,
        }),
        None => None,
    };

    let Some(parent) = parent else {
        // Return unknown parent type for `execute_unknown_parent_action` to handle.
        return Ok(DependencyValidationResult::UnknownParent {
            parent_root: block.message.parent_root,
        });
    };

    match validate_beacon_block(
        beacon_chain,
        cached_db,
        block,
        &parent.state,
        &parent,
        enforce_first_seen,
    )
    .await?
    {
        ValidationResult::Accept => {}
        ValidationResult::Ignore(reason) => {
            return Ok(DependencyValidationResult::Ignore(reason));
        }
        ValidationResult::Reject(reason) => {
            return Ok(DependencyValidationResult::Reject(reason));
        }
    }

    if parent.pending_availability {
        Ok(DependencyValidationResult::ParentPendingAvailability {
            parent_root: block.message.parent_root,
            validated: GossipValidatedBlock::new(block.clone()),
        })
    } else {
        Ok(DependencyValidationResult::Accept)
    }
}

/// Whether `parent_state` can check `block` without advancing to the block's slot. From Fulu the
/// state's proposer lookahead holds the proposers of its epoch and the next one (EIP-7917), so a
/// block in either epoch needs no epoch processing to find its proposer. The proposer's key, the
/// payload timestamp and the blob limit do not depend on the advance.
fn parent_state_serves_block(parent_state: &BeaconState, block: &SignedBeaconBlock) -> bool {
    parent_state_serves_block_from(parent_state, block, beacon_network_spec().fulu_fork_epoch)
}

fn parent_state_serves_block_from(
    parent_state: &BeaconState,
    block: &SignedBeaconBlock,
    fulu_fork_epoch: u64,
) -> bool {
    let parent_epoch = parent_state.get_current_epoch();
    parent_epoch >= fulu_fork_epoch
        && block.message.slot >= parent_state.slot
        && compute_epoch_at_slot(block.message.slot) <= parent_epoch + 1
        && block.message.body.bls_to_execution_changes.is_empty()
}

async fn validate_beacon_block(
    beacon_chain: &BeaconChain,
    cached_db: &BeaconCacheDB,
    block: &SignedBeaconBlock,
    state: &BeaconState,
    parent: &ParentContext,
    enforce_first_seen: bool,
) -> anyhow::Result<ValidationResult> {
    let db = beacon_chain.db();

    // [IGNORE] The block is not from a future slot.
    if block.message.slot > get_current_slot_from_db(db)? {
        return Ok(ValidationResult::Ignore(
            "Block is from a future slot".to_string(),
        ));
    }

    // [IGNORE] The block is from a slot greater than the latest finalized slot.
    let finalized_checkpoint = db.finalized_checkpoint_provider().get()?;
    if block.message.slot <= compute_start_slot_at_epoch(finalized_checkpoint.epoch) {
        return Ok(ValidationResult::Ignore(
            "Block is not from a slot greater than the latest finalized slot".to_string(),
        ));
    }

    let Some(validator) = state.validators.get(block.message.proposer_index as usize) else {
        return Ok(ValidationResult::Reject("Validator not found".to_string()));
    };

    // [IGNORE] The block is the first block with valid signature received for the proposer for the
    // slot.
    if enforce_first_seen
        && cached_db
            .seen_proposer_signature
            .read()
            .await
            .contains(&AddressSlotIdentifier {
                address: validator.public_key.clone(),
                slot: block.message.slot,
            })
    {
        return Ok(ValidationResult::Ignore(
            "Signature already received".to_string(),
        ));
    }

    // [REJECT] The proposer signature is valid with respect to the proposer_index pubkey.
    match state.verify_block_header_signature(&block.signed_header()) {
        Ok(true) => {}
        Ok(false) => {
            return Ok(ValidationResult::Reject("Invalid signature".to_string()));
        }
        Err(err) => {
            return Ok(ValidationResult::Reject(format!(
                "Signature verification failed: {err}"
            )));
        }
    }

    // [REJECT] The block is from a higher slot than its parent.
    if block.message.slot <= parent.block.message.slot {
        return Ok(ValidationResult::Reject(
            "Block is not from a higher slot".to_string(),
        ));
    }

    #[cfg(not(feature = "disable_ancestor_validation"))]
    if !parent.pending_availability
        && get_checkpoint_block_from_db(db, block.message.parent_root, finalized_checkpoint.epoch)?
            != finalized_checkpoint.root
    {
        return Ok(ValidationResult::Reject(
            "Finalized checkpoint is not an ancestor".to_string(),
        ));
    }

    // A pending parent is not in the block DB, so an ancestry walk cannot cross it. At arrival we
    // can only check that the child is newer than finality and points to that exact pending block.
    // Finality can advance while it waits; release repeats the normal walk after parent import.

    // The parent state serves as is when its proposer lookahead covers the block's slot. Advancing
    // it copies the whole state and, for the first block of an epoch, runs epoch processing (~0.5 s
    // on mainnet). BLS-to-execution changes still use the advanced state, since epoch processing
    // can add the validators they name.
    let advanced_state;
    let state = if parent_state_serves_block(state, block) {
        state
    } else {
        let mut advanced = state.clone();
        if let Err(err) = advanced.process_slots(block.message.slot) {
            return Ok(ValidationResult::Ignore(format!(
                "Could not advance parent state to block slot: {err:?}"
            )));
        }
        advanced_state = advanced;
        &advanced_state
    };

    // [REJECT] The block is proposed by the expected proposer_index for the block's slot.
    if state.get_beacon_proposer_index(Some(block.message.slot))? != block.message.proposer_index {
        return Ok(ValidationResult::Reject(
            "Proposer index is incorrect".to_string(),
        ));
    }

    // [REJECT] The block's execution payload timestamp is correct with respect to the slot.
    if block.message.body.execution_payload.timestamp
        != state.compute_timestamp_at_slot(block.message.slot)
    {
        return Ok(ValidationResult::Reject(
            "Execution payload timestamp is incorrect".to_string(),
        ));
    }

    // [IGNORE] Every BLS-to-execution change is the first seen for its validator and this slot.
    for signed_bls_execution_change in &block.message.body.bls_to_execution_changes {
        let Some(change_validator) = state
            .validators
            .get(signed_bls_execution_change.message.validator_index as usize)
        else {
            return Ok(ValidationResult::Reject(
                "BLS to execution change validator not found".to_string(),
            ));
        };
        if cached_db
            .seen_bls_to_execution_signature
            .read()
            .await
            .contains(&AddressSlotIdentifier {
                address: change_validator.public_key.clone(),
                slot: block.message.slot,
            })
        {
            return Ok(ValidationResult::Ignore(
                "BLS to execution change already received".to_string(),
            ));
        }
    }

    // [REJECT] All process_bls_to_execution_change conditions pass validation.
    for signed_bls_execution_change in &block.message.body.bls_to_execution_changes {
        if state
            .validate_bls_to_execution_change(signed_bls_execution_change)
            .is_err()
        {
            return Ok(ValidationResult::Reject(
                "BLS to execution change is invalid".to_string(),
            ));
        }
    }

    // [REJECT] The length of KZG commitments is less than or equal to the limitation.
    if !blob_commitment_count_is_valid(block, &beacon_network_spec().blob_schedule) {
        return Ok(ValidationResult::Reject(
            "Length of KZG commitments is greater than the limit".to_string(),
        ));
    }

    // Epoch processing can extend the validator registry, so cache against the block-slot state.
    let validator = &state.validators[block.message.proposer_index as usize];
    let proposer_slot = AddressSlotIdentifier {
        address: validator.public_key.clone(),
        slot: block.message.slot,
    };
    let mut seen_proposer_signatures = cached_db.seen_proposer_signature.write().await;
    if enforce_first_seen && seen_proposer_signatures.contains(&proposer_slot) {
        return Ok(ValidationResult::Ignore(
            "Signature already received".to_string(),
        ));
    }
    seen_proposer_signatures.put(proposer_slot, block.signature.clone());
    drop(seen_proposer_signatures);

    for signed_bls_execution_change in &block.message.body.bls_to_execution_changes {
        let validator =
            &state.validators[signed_bls_execution_change.message.validator_index as usize];
        cached_db.seen_bls_to_execution_signature.write().await.put(
            AddressSlotIdentifier {
                address: validator.public_key.clone(),
                slot: block.message.slot,
            },
            signed_bls_execution_change.message.clone(),
        );
    }

    Ok(ValidationResult::Accept)
}

fn blob_commitment_count_is_valid(block: &SignedBeaconBlock, schedule: &[BlobParameters]) -> bool {
    block.message.body.blob_kzg_commitments.len()
        <= get_blob_parameters(schedule, compute_epoch_at_slot(block.message.slot))
            .max_blobs_per_block as usize
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use ream_consensus_beacon::{
        bls_to_execution_change::{BLSToExecutionChange, SignedBLSToExecutionChange},
        electra::beacon_block::BeaconBlock,
    };
    use ream_consensus_misc::{
        constants::beacon::SLOTS_PER_EPOCH, polynomial_commitments::kzg_commitment::KZGCommitment,
    };
    use ream_network_spec::networks::initialize_test_network_spec;
    use ssz::Decode;

    use super::*;

    #[test]
    fn gossip_blob_limit_follows_block_epoch_schedule() {
        let schedule = vec![
            BlobParameters {
                epoch: 0,
                max_blobs_per_block: 15,
            },
            BlobParameters {
                epoch: 2,
                max_blobs_per_block: 21,
            },
        ];
        let mut block = SignedBeaconBlock {
            message: Default::default(),
            signature: Default::default(),
        };
        for (epoch, count, expected) in [
            (0, 10, true),
            (0, 15, true),
            (0, 16, false),
            (1, 21, false),
            (2, 21, true),
            (2, 22, false),
        ] {
            block.message.slot = epoch * SLOTS_PER_EPOCH;
            block.message.body.blob_kzg_commitments =
                vec![KZGCommitment::empty_for_testing(); count]
                    .try_into()
                    .expect("test commitments fit the SSZ bound");
            assert_eq!(
                blob_commitment_count_is_valid(&block, &schedule),
                expected,
                "epoch {epoch}, commitments {count}"
            );
        }
        block.message.body.blob_kzg_commitments = vec![KZGCommitment::empty_for_testing(); 10]
            .try_into()
            .expect("test commitments fit the SSZ bound");
        assert!(!blob_commitment_count_is_valid(&block, &[]));
    }

    fn parent_state() -> BeaconState {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
            "../../../testing/gossip-validation/tests/assets/sepolia/states/\
             parent_state_9552075.ssz_snappy",
        );
        let bytes = snap::raw::Decoder::new()
            .decompress_vec(&std::fs::read(path).unwrap())
            .unwrap();
        BeaconState::from_ssz_bytes(&bytes).unwrap()
    }

    fn block_at(slot: u64) -> SignedBeaconBlock {
        SignedBeaconBlock {
            message: BeaconBlock {
                slot,
                ..Default::default()
            },
            signature: Default::default(),
        }
    }

    #[test]
    fn the_parent_lookahead_names_the_proposer_of_the_next_epoch() {
        initialize_test_network_spec();
        let parent = parent_state();
        let epoch = parent.get_current_epoch();
        let next_epoch_start = compute_start_slot_at_epoch(epoch + 1);
        for slot in [parent.slot + 1, next_epoch_start, next_epoch_start + 31] {
            let block = block_at(slot);
            assert!(parent_state_serves_block_from(&parent, &block, 0));
            let mut advanced = parent.clone();
            advanced.process_slots(slot).unwrap();
            assert_eq!(
                parent.get_beacon_proposer_index(Some(slot)).unwrap(),
                advanced.get_beacon_proposer_index(None).unwrap(),
                "slot {slot}"
            );
        }

        // Two epochs ahead is outside the lookahead, so the state is advanced.
        assert!(!parent_state_serves_block_from(
            &parent,
            &block_at(compute_start_slot_at_epoch(epoch + 2)),
            0
        ));
        // Before Fulu the lookahead is not kept.
        assert!(!parent_state_serves_block_from(
            &parent,
            &block_at(parent.slot + 1),
            epoch + 1
        ));
        // A BLS-to-execution change can name a validator that epoch processing adds.
        let mut with_change = block_at(parent.slot + 1);
        with_change
            .message
            .body
            .bls_to_execution_changes
            .push(SignedBLSToExecutionChange {
                message: BLSToExecutionChange {
                    validator_index: 0,
                    from_bls_public_key: Default::default(),
                    to_execution_address: Default::default(),
                },
                signature: Default::default(),
            })
            .unwrap();
        assert!(!parent_state_serves_block_from(&parent, &with_change, 0));
    }
}
