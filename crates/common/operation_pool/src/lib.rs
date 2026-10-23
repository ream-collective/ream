use std::collections::HashMap;

use alloy_primitives::{Address, B256, map::HashSet};
use parking_lot::RwLock;
use ream_bls::{BLSSignature, traits::Aggregatable};
use ream_consensus_beacon::{
    attestation::Attestation, attester_slashing::AttesterSlashing,
    bls_to_execution_change::SignedBLSToExecutionChange, electra::beacon_state::BeaconState,
    proposer_slashing::ProposerSlashing, sync_aggregate::SyncAggregate,
    voluntary_exit::SignedVoluntaryExit,
};
use ream_consensus_misc::{
    attestation_data::AttestationData,
    checkpoint::Checkpoint,
    constants::beacon::{MIN_ATTESTATION_INCLUSION_DELAY, SYNC_COMMITTEE_SIZE},
    deposit::Deposit,
    misc::{compute_epoch_at_slot, get_committee_indices},
};
use ssz_types::{BitVector, typenum::U128};
use tree_hash::TreeHash;

/// Electra's `MAX_ATTESTATIONS_ELECTRA`: the most attestations a block body can carry.
const MAX_ATTESTATIONS_ELECTRA: usize = 8;

const SYNC_COMMITTEE_SUBNET_COUNT: usize = 4;
const SYNC_SUBCOMMITTEE_SIZE: usize = SYNC_COMMITTEE_SIZE as usize / SYNC_COMMITTEE_SUBNET_COUNT;

/// The best contribution seen for one sync subcommittee.
#[derive(Debug, Clone)]
struct SyncContribution {
    aggregation_bits: BitVector<U128>,
    signature: BLSSignature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposerPreparation {
    pub fee_recipient: Address,
    pub submission_epoch: u64,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct AttestationKey {
    slot: u64,
    attestation_data_root: B256,
    committee_index: u64,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct SyncAggregateKey {
    slot: u64,
    beacon_block_root: B256,
}

#[derive(Debug, Default)]
pub struct OperationPool {
    signed_voluntary_exits: RwLock<HashMap<u64, SignedVoluntaryExit>>,
    signed_bls_to_execution_changes: RwLock<HashMap<B256, SignedBLSToExecutionChange>>,
    proposer_preparations: RwLock<HashMap<u64, ProposerPreparation>>,
    attester_slashings: RwLock<HashSet<AttesterSlashing>>,
    proposer_slashings: RwLock<HashSet<ProposerSlashing>>,
    attestations: RwLock<HashMap<AttestationKey, Vec<Attestation>>>,
    included_attestation_bits: RwLock<HashMap<AttestationKey, HashSet<usize>>>,
    sync_contributions:
        RwLock<HashMap<SyncAggregateKey, [Option<SyncContribution>; SYNC_COMMITTEE_SUBNET_COUNT]>>,
    deposits: RwLock<HashSet<Deposit>>,
}

impl OperationPool {
    pub fn insert_signed_voluntary_exit(&self, signed_voluntary_exit: SignedVoluntaryExit) {
        self.signed_voluntary_exits.write().insert(
            signed_voluntary_exit.message.validator_index,
            signed_voluntary_exit,
        );
    }

    pub fn get_signed_voluntary_exits(&self) -> Vec<SignedVoluntaryExit> {
        self.signed_voluntary_exits
            .read()
            .values()
            .cloned()
            .collect()
    }

    pub fn clean_signed_voluntary_exits(&self, beacon_state: &BeaconState) {
        self.signed_voluntary_exits
            .write()
            .retain(|&validator_index, _| {
                beacon_state.validators[validator_index as usize].exit_epoch
                    >= beacon_state.finalized_checkpoint.epoch
            });
    }

    pub fn insert_signed_bls_to_execution_change(
        &self,
        signed_bls_to_execution_change: SignedBLSToExecutionChange,
    ) {
        self.signed_bls_to_execution_changes.write().insert(
            signed_bls_to_execution_change.tree_hash_root(),
            signed_bls_to_execution_change,
        );
    }

    pub fn get_signed_bls_to_execution_changes(&self) -> Vec<SignedBLSToExecutionChange> {
        self.signed_bls_to_execution_changes
            .read()
            .values()
            .cloned()
            .collect()
    }

    pub fn remove_signed_bls_to_execution_change(&self, root: B256) {
        self.signed_bls_to_execution_changes.write().remove(&root);
    }

    pub fn insert_proposer_preparation(
        &self,
        validator_index: u64,
        fee_recipient: Address,
        submission_epoch: u64,
    ) {
        self.proposer_preparations.write().insert(
            validator_index,
            ProposerPreparation {
                fee_recipient,
                submission_epoch,
            },
        );
    }

    pub fn get_proposer_preparation(&self, validator_index: u64) -> Option<Address> {
        self.proposer_preparations
            .read()
            .get(&validator_index)
            .map(|preparation| preparation.fee_recipient)
    }

    pub fn get_all_proposer_preparations(&self) -> HashMap<u64, Address> {
        self.proposer_preparations
            .read()
            .iter()
            .map(|(&index, preparation)| (index, preparation.fee_recipient))
            .collect()
    }

    pub fn clean_proposer_preparations(&self, current_epoch: u64) {
        self.proposer_preparations.write().retain(|_, preparation| {
            // Keep preparations that are still valid
            // They persist through the epoch of submission and for 2 more epochs after that
            current_epoch <= preparation.submission_epoch + 2
        });
    }

    pub fn insert_attester_slashing(&self, slashing: AttesterSlashing) {
        self.attester_slashings.write().insert(slashing);
    }

    pub fn get_all_attester_slashings(&self) -> Vec<AttesterSlashing> {
        self.attester_slashings.read().iter().cloned().collect()
    }

    pub fn get_all_proposer_slahsings(&self) -> Vec<ProposerSlashing> {
        self.proposer_slashings.read().iter().cloned().collect()
    }

    pub fn insert_proposer_slashing(&self, slashing: ProposerSlashing) {
        self.proposer_slashings.write().insert(slashing);
    }

    pub fn get_attestations(
        &self,
        slot: u64,
        committee_index: Option<u64>,
        attestation_data_root: Option<B256>,
    ) -> Vec<Attestation> {
        self.attestations
            .read()
            .iter()
            .filter(|(key, _)| {
                if key.slot != slot {
                    return false;
                }

                if let Some(c_index) = committee_index
                    && key.committee_index != c_index
                {
                    return false;
                }

                if let Some(data_root) = attestation_data_root
                    && key.attestation_data_root != data_root
                {
                    return false;
                }

                true
            })
            .flat_map(|(_, attestations)| attestations.iter().cloned())
            .collect()
    }

    /// The aggregate an aggregator publishes for one committee: the largest attestations first,
    /// then every vote that does not overlap them.
    pub fn get_aggregate_attestation(
        &self,
        slot: u64,
        committee_index: u64,
        attestation_data_root: B256,
    ) -> Option<Attestation> {
        let key = AttestationKey {
            slot,
            attestation_data_root,
            committee_index,
        };
        let mut group = self.attestations.read().get(&key)?.clone();
        group.sort_by_key(|attestation| {
            std::cmp::Reverse(attestation.aggregation_bits.num_set_bits())
        });
        aggregate_attestation_group(&group, &HashSet::default())
    }

    pub fn get_all_attestations(&self) -> Vec<Attestation> {
        self.attestations
            .read()
            .values()
            .flat_map(|attestations| attestations.clone())
            .collect()
    }

    pub fn insert_attestation(&self, attestation: Attestation, committee_index: u64) {
        let key = AttestationKey {
            slot: attestation.data.slot,
            attestation_data_root: attestation.data.tree_hash_root(),
            committee_index,
        };
        let mut map = self.attestations.write();
        if let Some(attestations) = map.get_mut(&key) {
            attestations.push(attestation);
        } else {
            map.insert(key, vec![attestation]);
        }
    }

    /// Select attestations that can be included in the block.
    ///
    /// Only keep attestations whose target epoch is current or previous, whose minimum inclusion
    /// delay has passed and whose source is the state's justified checkpoint for that epoch, and
    /// aggregate non-overlapping votes by key. One attestation with another source would make
    /// `process_attestation` fail the whole block.
    pub fn get_attestations_for_block(&self, state: &BeaconState) -> Vec<Attestation> {
        let current_epoch = state.get_current_epoch();
        let previous_epoch = state.get_previous_epoch();
        let attestations = self.attestations.read();
        let included_attestation_bits = self.included_attestation_bits.read();

        let mut keys: Vec<&AttestationKey> = attestations
            .keys()
            .filter(|key| {
                let target_epoch = compute_epoch_at_slot(key.slot);
                (target_epoch == current_epoch || target_epoch == previous_epoch)
                    && key.slot + MIN_ATTESTATION_INCLUSION_DELAY <= state.slot
            })
            .collect();
        keys.sort_by_key(|key| std::cmp::Reverse(key.slot));

        keys.into_iter()
            .filter(|key| {
                attestations[key].first().is_some_and(|attestation| {
                    source_is_justified(
                        &attestation.data,
                        current_epoch,
                        &state.current_justified_checkpoint,
                        &state.previous_justified_checkpoint,
                    )
                })
            })
            .filter_map(|key| {
                let already_included = included_attestation_bits
                    .get(key)
                    .cloned()
                    .unwrap_or_default();
                aggregate_attestation_group(&attestations[key], &already_included)
            })
            .take(MAX_ATTESTATIONS_ELECTRA)
            .collect()
    }

    /// Record aggregation-bit positions from attestations that have been included in an
    /// imported block so attestations without new votes can be skipped during future packing.
    pub fn mark_attestations_included(&self, attestations: &[Attestation]) {
        let mut included_attestation_bits = self.included_attestation_bits.write();
        for attestation in attestations {
            let committee_indices = get_committee_indices(&attestation.committee_bits);
            let [committee_index] = committee_indices.as_slice() else {
                continue;
            };

            let key = AttestationKey {
                slot: attestation.data.slot,
                attestation_data_root: attestation.data.tree_hash_root(),
                committee_index: *committee_index,
            };

            let set_bits = (0..attestation.aggregation_bits.len())
                .filter(|&index| attestation.aggregation_bits.get(index).unwrap_or(false));

            included_attestation_bits
                .entry(key)
                .or_default()
                .extend(set_bits);
        }
    }

    /// Keep only attestations (and their inclusion-tracking bits) from the current or previous
    /// epoch.
    pub fn clean_attestations(&self, current_epoch: u64) {
        let is_live = |key: &AttestationKey| {
            let target_epoch = compute_epoch_at_slot(key.slot);
            target_epoch + 1 >= current_epoch
        };
        self.attestations.write().retain(|key, _| is_live(key));
        self.included_attestation_bits
            .write()
            .retain(|key, _| is_live(key));
    }

    /// Builds the block's sync aggregate from the best contribution of each subcommittee for
    /// ``beacon_block_root`` at ``slot``.
    pub fn get_sync_aggregate(&self, slot: u64, beacon_block_root: B256) -> Option<SyncAggregate> {
        let key = SyncAggregateKey {
            slot,
            beacon_block_root,
        };
        let contributions = self.sync_contributions.read();
        let contributions = contributions.get(&key)?;

        let mut sync_committee_bits = BitVector::default();
        let mut signatures = vec![];
        for (subcommittee_index, contribution) in contributions.iter().enumerate() {
            let Some(contribution) = contribution else {
                continue;
            };
            for (position, bit) in contribution.aggregation_bits.iter().enumerate() {
                if bit {
                    sync_committee_bits
                        .set(subcommittee_index * SYNC_SUBCOMMITTEE_SIZE + position, true)
                        .ok()?;
                }
            }
            signatures.push(&contribution.signature);
        }
        if signatures.is_empty() {
            return None;
        }

        Some(SyncAggregate {
            sync_committee_bits,
            sync_committee_signature: BLSSignature::aggregate(&signatures).ok()?,
        })
    }

    /// Keeps a validated sync committee contribution if it has more participants than the one
    /// held for its subcommittee.
    pub fn insert_sync_contribution(
        &self,
        slot: u64,
        beacon_block_root: B256,
        subcommittee_index: u64,
        aggregation_bits: BitVector<U128>,
        signature: BLSSignature,
    ) {
        let Some(index) = usize::try_from(subcommittee_index)
            .ok()
            .filter(|index| *index < SYNC_COMMITTEE_SUBNET_COUNT)
        else {
            return;
        };
        let key = SyncAggregateKey {
            slot,
            beacon_block_root,
        };
        let mut contributions = self.sync_contributions.write();
        let best = &mut contributions.entry(key).or_default()[index];
        let participants = aggregation_bits.num_set_bits();
        if best
            .as_ref()
            .is_none_or(|best| best.aggregation_bits.num_set_bits() < participants)
        {
            *best = Some(SyncContribution {
                aggregation_bits,
                signature,
            });
        }
    }

    /// Keeps contributions a block at ``current_slot`` or later can still include.
    pub fn clean_sync_contributions(&self, current_slot: u64) {
        self.sync_contributions
            .write()
            .retain(|key, _| key.slot + 2 >= current_slot);
    }

    pub fn get_all_deposits(&self) -> Vec<Deposit> {
        self.deposits.read().iter().cloned().collect()
    }

    pub fn insert_deposit(&self, deposit: Deposit) {
        self.deposits.write().insert(deposit);
    }
}

/// Aggregates non-overlapping attestations that contain votes not present in `already_included`.
/// The selected attestations retain every signed bit so their aggregate signature stays valid.
fn aggregate_attestation_group(
    group: &[Attestation],
    already_included: &HashSet<usize>,
) -> Option<Attestation> {
    let mut aggregate = group.first()?.clone();
    let mut aggregation_bits = aggregate.aggregation_bits.clone();
    let mut seen = HashSet::<usize>::default();
    let mut signatures = Vec::new();

    for index in 0..aggregation_bits.len() {
        aggregation_bits.set(index, false).ok()?;
    }

    for attestation in group {
        if attestation.committee_bits != aggregate.committee_bits {
            continue;
        }

        let set_bits: Vec<usize> = (0..attestation.aggregation_bits.len())
            .filter(|&index| attestation.aggregation_bits.get(index).unwrap_or(false))
            .collect();

        if set_bits.is_empty()
            || set_bits
                .iter()
                .any(|position| *position >= aggregation_bits.len())
            || set_bits.iter().any(|position| seen.contains(position))
            || set_bits
                .iter()
                .all(|position| already_included.contains(position))
        {
            continue;
        }

        for position in &set_bits {
            seen.insert(*position);
            aggregation_bits.set(*position, true).ok()?;
        }

        signatures.push(&attestation.signature);
    }

    if signatures.is_empty() {
        return None;
    }

    aggregate.aggregation_bits = aggregation_bits;
    aggregate.signature = BLSSignature::aggregate(&signatures).ok()?;
    Some(aggregate)
}

/// Whether `data.source` is the justified checkpoint `process_attestation` requires: the current
/// one for a current epoch target, the previous one otherwise.
fn source_is_justified(
    data: &AttestationData,
    current_epoch: u64,
    current_justified: &Checkpoint,
    previous_justified: &Checkpoint,
) -> bool {
    let justified = if data.target.epoch == current_epoch {
        current_justified
    } else {
        previous_justified
    };
    data.source == *justified
}

#[cfg(test)]
mod tests {
    use alloy_primitives::map::{DefaultHashBuilder, HashSet};
    use ssz_types::{BitList, BitVector};

    use super::*;

    /// Build an `Attestation` for committee `committee_index` at `slot`, with `set_bit_indices`
    /// set within a `bitlist_len`-bit aggregation bitfield. `target_epoch` only needs to be
    /// distinct per test scenario; it feeds into `attestation_data_root` via the rest of the
    /// (otherwise-fixed) `AttestationData`, so distinct `target_epoch`/`slot` pairs produce
    /// distinct `AttestationKey`s.
    fn make_attestation(
        slot: u64,
        committee_index: u64,
        target_epoch: u64,
        bitlist_len: usize,
        set_bit_indices: &[usize],
    ) -> Attestation {
        let mut aggregation_bits =
            BitList::<ssz_types::typenum::U131072>::with_capacity(bitlist_len)
                .expect("valid bitlist capacity");
        for &index in set_bit_indices {
            aggregation_bits
                .set(index, true)
                .expect("index within bitlist capacity");
        }

        let mut committee_bits = BitVector::<ssz_types::typenum::U64>::default();
        committee_bits
            .set(committee_index as usize, true)
            .expect("committee index within bitvector capacity");

        Attestation {
            aggregation_bits,
            data: AttestationData {
                slot,
                index: 0,
                beacon_block_root: B256::repeat_byte(0xAB),
                source: Checkpoint::default(),
                target: Checkpoint {
                    epoch: target_epoch,
                    root: B256::repeat_byte(0xCD),
                },
            },
            signature: BLSSignature::infinity(),
            committee_bits,
        }
    }

    #[test]
    fn block_attestations_need_the_justified_source_of_their_target_epoch() {
        let checkpoint = |epoch: u64, byte: u8| Checkpoint {
            epoch,
            root: B256::repeat_byte(byte),
        };
        let current_justified = checkpoint(9, 1);
        let previous_justified = checkpoint(8, 2);
        let data = |target_epoch: u64, source: Checkpoint| AttestationData {
            source,
            ..make_attestation(target_epoch * 32, 0, target_epoch, 4, &[0]).data
        };
        let matches = |data: &AttestationData| {
            source_is_justified(data, 10, &current_justified, &previous_justified)
        };

        assert!(matches(&data(10, current_justified)));
        assert!(matches(&data(9, previous_justified)));
        assert!(!matches(&data(10, previous_justified)));
        assert!(!matches(&data(9, current_justified)));
        assert!(!matches(&data(10, checkpoint(9, 3))));
    }

    #[test]
    fn aggregate_attestation_group_preserves_signed_bits_for_partial_overlap() {
        // Two validators (bits 0 and 1) attested for the same data; bit 0 already landed
        // on-chain in an earlier block.
        let attestation = make_attestation(10, 0, 1, 4, &[0, 1]);
        let mut already_included = HashSet::with_hasher(DefaultHashBuilder::default());
        already_included.insert(0);

        let aggregate = aggregate_attestation_group(&[attestation], &already_included)
            .expect("bit 1 is new and should still be aggregated");

        assert!(aggregate.aggregation_bits.get(0).unwrap());
        assert!(aggregate.aggregation_bits.get(1).unwrap());
    }

    #[test]
    fn aggregate_attestation_group_returns_none_when_fully_included() {
        // Single attester (bit 0), and that bit has already landed on-chain: nothing new to
        // offer, so the group should not consume a block-attestation slot.
        let attestation = make_attestation(10, 0, 1, 4, &[0]);
        let mut already_included = HashSet::with_hasher(DefaultHashBuilder::default());
        already_included.insert(0);

        assert!(aggregate_attestation_group(&[attestation], &already_included).is_none());
    }

    #[test]
    fn aggregate_attestation_group_with_no_exclusions_matches_prior_behavior() {
        let attestation = make_attestation(10, 0, 1, 4, &[0, 2]);

        let aggregate = aggregate_attestation_group(
            &[attestation],
            &HashSet::with_hasher(DefaultHashBuilder::default()),
        )
        .expect("no exclusions, both bits should be aggregated");

        assert!(aggregate.aggregation_bits.get(0).unwrap());
        assert!(aggregate.aggregation_bits.get(2).unwrap());
    }

    #[test]
    fn aggregate_attestation_takes_the_largest_votes_first() {
        let pool = OperationPool::default();
        let small = make_attestation(10, 3, 1, 8, &[0]);
        let large = make_attestation(10, 3, 1, 8, &[0, 1, 2]);
        let other = make_attestation(10, 3, 1, 8, &[5]);
        let root = small.data.tree_hash_root();
        for attestation in [small, large, other] {
            pool.insert_attestation(attestation, 3);
        }

        let aggregate = pool.get_aggregate_attestation(10, 3, root).unwrap();
        let set_bits: Vec<usize> = (0..aggregate.aggregation_bits.len())
            .filter(|&index| aggregate.aggregation_bits.get(index).unwrap())
            .collect();
        assert_eq!(set_bits, vec![0, 1, 2, 5]);
        assert_eq!(aggregate.aggregation_bits.len(), 8);
        assert!(pool.get_aggregate_attestation(10, 4, root).is_none());
    }

    #[test]
    fn mark_attestations_included_records_bit_positions_per_key() {
        let operation_pool = OperationPool::default();
        let included_in_block = make_attestation(10, 3, 1, 4, &[1, 2]);

        operation_pool.mark_attestations_included(std::slice::from_ref(&included_in_block));

        let key = AttestationKey {
            slot: included_in_block.data.slot,
            attestation_data_root: included_in_block.data.tree_hash_root(),
            committee_index: 3,
        };
        let recorded = operation_pool
            .included_attestation_bits
            .read()
            .get(&key)
            .cloned()
            .unwrap_or_default();

        assert_eq!(recorded, HashSet::from_iter([1, 2]));
    }

    #[test]
    fn mark_attestations_included_ignores_multi_committee_attestations() {
        // An attestation whose committee_bits spans more than one committee doesn't match the
        // single-committee shape this pool ever produces itself; it should be left alone rather
        // than mis-recorded under an arbitrary committee index.
        let mut multi_committee = make_attestation(10, 0, 1, 4, &[0]);
        multi_committee
            .committee_bits
            .set(1, true)
            .expect("committee index within bitvector capacity");

        let operation_pool = OperationPool::default();
        operation_pool.mark_attestations_included(&[multi_committee]);

        assert!(operation_pool.included_attestation_bits.read().is_empty());
    }

    #[test]
    fn repeated_inclusion_of_same_bits_does_not_starve_new_votes() {
        let operation_pool = OperationPool::default();
        let key = AttestationKey {
            slot: 10,
            attestation_data_root: make_attestation(10, 0, 1, 4, &[]).data.tree_hash_root(),
            committee_index: 0,
        };

        // First validator's vote lands on-chain.
        let first_voter = make_attestation(10, 0, 1, 4, &[0]);
        operation_pool.mark_attestations_included(std::slice::from_ref(&first_voter));

        // A second validator's vote for the same attestation data arrives late and is still in
        // the pool alongside a duplicate of the first (as would happen via gossip).
        let second_voter = make_attestation(10, 0, 1, 4, &[1]);
        let group = vec![first_voter, second_voter];

        let already_included = operation_pool
            .included_attestation_bits
            .read()
            .get(&key)
            .cloned()
            .unwrap_or_default();
        let aggregate = aggregate_attestation_group(&group, &already_included)
            .expect("second voter's bit is new and must still be selectable");

        assert!(!aggregate.aggregation_bits.get(0).unwrap());
        assert!(aggregate.aggregation_bits.get(1).unwrap());
    }

    #[test]
    fn clean_attestations_also_prunes_included_bits_for_expired_keys() {
        let operation_pool = OperationPool::default();
        let old_attestation = make_attestation(0, 0, 0, 4, &[0]);
        operation_pool.mark_attestations_included(std::slice::from_ref(&old_attestation));

        assert!(!operation_pool.included_attestation_bits.read().is_empty());

        // Far enough in the future that epoch 0's target is no longer current/previous.
        operation_pool.clean_attestations(1_000);

        assert!(operation_pool.included_attestation_bits.read().is_empty());
    }

    #[test]
    fn test_proposer_preparation_operations() {
        let operation_pool = OperationPool::default();
        let fee_recipient1 = Address::from([0x11; 20]);
        let fee_recipient2 = Address::from([0x22; 20]);

        assert_eq!(operation_pool.get_proposer_preparation(1), None);

        operation_pool.insert_proposer_preparation(1, fee_recipient1, 100);
        assert_eq!(
            operation_pool.get_proposer_preparation(1),
            Some(fee_recipient1)
        );

        operation_pool.insert_proposer_preparation(2, fee_recipient2, 100);
        let all_preparations = operation_pool.get_all_proposer_preparations();
        assert_eq!(all_preparations.len(), 2);
        assert_eq!(all_preparations.get(&1), Some(&fee_recipient1));
        assert_eq!(all_preparations.get(&2), Some(&fee_recipient2));

        operation_pool.insert_proposer_preparation(1, fee_recipient2, 101);
        assert_eq!(
            operation_pool.get_proposer_preparation(1),
            Some(fee_recipient2)
        );
    }

    #[test]
    fn test_proposer_preparation_expiration() {
        let operation_pool = OperationPool::default();
        let fee_recipient1 = Address::from([0x11; 20]);
        let fee_recipient2 = Address::from([0x22; 20]);
        let fee_recipient3 = Address::from([0x33; 20]);

        // Insert preparations at different epochs
        operation_pool.insert_proposer_preparation(1, fee_recipient1, 100);
        operation_pool.insert_proposer_preparation(2, fee_recipient2, 101);
        operation_pool.insert_proposer_preparation(3, fee_recipient3, 102);

        // All should be present initially
        assert_eq!(operation_pool.get_all_proposer_preparations().len(), 3);

        // Clean at epoch 102 - all should still be valid
        operation_pool.clean_proposer_preparations(102);
        assert_eq!(operation_pool.get_all_proposer_preparations().len(), 3);

        // Clean at epoch 103 - validator 1 (epoch 100) should be expired
        operation_pool.clean_proposer_preparations(103);
        let remaining = operation_pool.get_all_proposer_preparations();
        assert_eq!(remaining.len(), 2);
        assert_eq!(remaining.get(&1), None);
        assert_eq!(remaining.get(&2), Some(&fee_recipient2));
        assert_eq!(remaining.get(&3), Some(&fee_recipient3));

        // Clean at epoch 104 - validators 1 and 2 should be expired
        operation_pool.clean_proposer_preparations(104);
        let remaining = operation_pool.get_all_proposer_preparations();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining.get(&3), Some(&fee_recipient3));

        // Clean at epoch 105 - all should be expired
        operation_pool.clean_proposer_preparations(105);
        assert_eq!(operation_pool.get_all_proposer_preparations().len(), 0);
    }

    #[test]
    fn test_proposer_preparation_edge_cases() {
        let operation_pool = OperationPool::default();
        let fee_recipient = Address::from([0x11; 20]);

        // Test exact boundary - submission at epoch 100 is valid through epoch 102
        operation_pool.insert_proposer_preparation(1, fee_recipient, 100);

        // Should be valid at epoch 102
        operation_pool.clean_proposer_preparations(102);
        assert_eq!(
            operation_pool.get_proposer_preparation(1),
            Some(fee_recipient)
        );

        // Should be expired at epoch 103
        operation_pool.clean_proposer_preparations(103);
        assert_eq!(operation_pool.get_proposer_preparation(1), None);
    }

    #[test]
    fn sync_aggregate_combines_the_best_contribution_per_subcommittee() {
        let pool = OperationPool::default();
        let root = B256::repeat_byte(7);
        let bits = |positions: &[usize]| {
            let mut bits = BitVector::<U128>::default();
            for &position in positions {
                bits.set(position, true).unwrap();
            }
            bits
        };

        assert!(pool.get_sync_aggregate(10, root).is_none());

        pool.insert_sync_contribution(10, root, 0, bits(&[1, 2]), BLSSignature::infinity());
        pool.insert_sync_contribution(10, root, 0, bits(&[5]), BLSSignature::infinity());
        pool.insert_sync_contribution(10, root, 2, bits(&[0, 127]), BLSSignature::infinity());
        pool.insert_sync_contribution(10, root, 4, bits(&[3]), BLSSignature::infinity());

        let aggregate = pool.get_sync_aggregate(10, root).unwrap();
        let set: Vec<usize> = aggregate
            .sync_committee_bits
            .iter()
            .enumerate()
            .filter_map(|(index, bit)| bit.then_some(index))
            .collect();
        assert_eq!(set, vec![1, 2, 256, 383]);
        assert!(pool.get_sync_aggregate(10, B256::ZERO).is_none());

        pool.clean_sync_contributions(13);
        assert!(pool.get_sync_aggregate(10, root).is_none());
    }
}
