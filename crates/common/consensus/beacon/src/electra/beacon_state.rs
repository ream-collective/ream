use std::{
    cmp::{max, min},
    collections::{HashMap, HashSet},
    mem::take,
    ops::Deref,
    slice,
    sync::Arc,
};

use alloy_primitives::{Address, B256, aliases::B32};
use anyhow::{anyhow, bail, ensure};
use ethereum_hashing::{hash, hash_fixed};
use itertools::Itertools;
use ream_bls::{
    BLSSignature, PublicKey,
    traits::{Aggregatable, Verifiable},
};
use ream_consensus_misc::{
    attestation_data::AttestationData,
    beacon_block_header::{BeaconBlockHeader, SignedBeaconBlockHeader},
    checkpoint::Checkpoint,
    consolidation_request::ConsolidationRequest,
    constants::beacon::{
        BASE_REWARD_FACTOR, BEACON_STATE_MERKLE_DEPTH, BLS_WITHDRAWAL_PREFIX, CHURN_LIMIT_QUOTIENT,
        COMPOUNDING_WITHDRAWAL_PREFIX, CURRENT_SYNC_COMMITTEE_INDEX, DEPOSIT_CONTRACT_TREE_DEPTH,
        DOMAIN_BEACON_ATTESTER, DOMAIN_BEACON_PROPOSER, DOMAIN_BLS_TO_EXECUTION_CHANGE,
        DOMAIN_DEPOSIT, DOMAIN_RANDAO, DOMAIN_SYNC_COMMITTEE, DOMAIN_VOLUNTARY_EXIT,
        EFFECTIVE_BALANCE_INCREMENT, EJECTION_BALANCE, EPOCHS_PER_ETH1_VOTING_PERIOD,
        EPOCHS_PER_HISTORICAL_VECTOR, EPOCHS_PER_SLASHINGS_VECTOR,
        EPOCHS_PER_SYNC_COMMITTEE_PERIOD, ETH1_ADDRESS_WITHDRAWAL_PREFIX, FAR_FUTURE_EPOCH,
        FINALIZED_CHECKPOINT_INDEX, FULL_EXIT_REQUEST_AMOUNT, GENESIS_EPOCH, GENESIS_SLOT,
        HYSTERESIS_DOWNWARD_MULTIPLIER, HYSTERESIS_QUOTIENT, HYSTERESIS_UPWARD_MULTIPLIER,
        INACTIVITY_PENALTY_QUOTIENT_BELLATRIX, INACTIVITY_SCORE_BIAS,
        INACTIVITY_SCORE_RECOVERY_RATE, JUSTIFICATION_BITS_LENGTH, MAX_COMMITTEES_PER_SLOT,
        MAX_DEPOSITS, MAX_EFFECTIVE_BALANCE_ELECTRA, MAX_PENDING_DEPOSITS_PER_EPOCH,
        MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP, MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT,
        MAX_PER_EPOCH_ACTIVATION_EXIT_CHURN_LIMIT, MAX_RANDOM_VALUE,
        MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP, MAX_WITHDRAWALS_PER_PAYLOAD, MIN_ACTIVATION_BALANCE,
        MIN_ATTESTATION_INCLUSION_DELAY, MIN_EPOCHS_TO_INACTIVITY_PENALTY,
        MIN_GENESIS_ACTIVE_VALIDATOR_COUNT, MIN_GENESIS_TIME, MIN_PER_EPOCH_CHURN_LIMIT,
        MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA, MIN_SEED_LOOKAHEAD,
        MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA, MIN_VALIDATOR_WITHDRAWABILITY_DELAY,
        NEXT_SYNC_COMMITTEE_INDEX, PARTICIPATION_FLAG_WEIGHTS, PENDING_CONSOLIDATIONS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT, PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX,
        PROPOSER_REWARD_QUOTIENT, PROPOSER_WEIGHT, SAFETY_DECAY, SHARD_COMMITTEE_PERIOD,
        SLOTS_PER_EPOCH, SLOTS_PER_HISTORICAL_ROOT, SYNC_COMMITTEE_SIZE, SYNC_REWARD_WEIGHT,
        TARGET_COMMITTEE_SIZE, TIMELY_HEAD_FLAG_INDEX, TIMELY_SOURCE_FLAG_INDEX,
        TIMELY_TARGET_FLAG_INDEX, UINT64_MAX, UINT64_MAX_SQRT, UNSET_DEPOSIT_REQUESTS_START_INDEX,
        WEIGHT_DENOMINATOR, WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA,
    },
    deposit::Deposit,
    deposit_message::DepositMessage,
    deposit_request::DepositRequest,
    eth_1_data::Eth1Data,
    fork::Fork,
    fork_name::ForkName,
    indexed_attestation::IndexedAttestation,
    misc::{
        bytes_to_int64, compute_activation_exit_epoch, compute_domain, compute_epoch_at_slot,
        compute_shuffled_index, compute_shuffled_list, compute_signing_root,
        compute_start_slot_at_epoch, get_committee_indices, is_sorted_and_unique,
    },
    validator::Validator,
    withdrawal::Withdrawal,
    withdrawal_request::WithdrawalRequest,
};
use ream_execution_engine::{engine_trait::ExecutionApi, new_payload_request::NewPayloadRequest};
use ream_execution_rpc_types::electra::{
    execution_payload::ExecutionPayload, execution_payload_header::ExecutionPayloadHeader,
};
use ream_merkle::{generate_proof, is_valid_merkle_branch, merkle_tree};
use ream_metrics::{
    BEACON_BLOCK_STATE_ROOT_SECONDS, BEACON_ENGINE_NEW_PAYLOAD_REQUEST_DURATION_SECONDS,
    BEACON_SHUFFLING_CACHE_MISSES_TOTAL,
};
use ream_network_spec::networks::beacon_network_spec;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ssz_derive::{Decode, Encode};
use ssz_types::{
    BitVector, FixedVector, VariableList,
    serde_utils::{quoted_u64_fixed_vec, quoted_u64_var_list},
    typenum::{U4, U32, U64, U2048, U8192, U65536, U262144, U16777216, U134217728},
};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

use super::{
    beacon_block::{BeaconBlock, SignedBeaconBlock},
    beacon_block_body::BeaconBlockBody,
    zkvm_types::ValidatorRegistryLimit,
};
use crate::{
    attestation::Attestation,
    attester_slashing::AttesterSlashing,
    bls_to_execution_change::SignedBLSToExecutionChange,
    chunked_list::{CHUNK_SIZE, ChunkedList},
    eth_1_block::Eth1Block,
    helpers::xor,
    historical_summary::HistoricalSummary,
    merkle_tree_cache::StateFieldRootCaches,
    parallel::parallel_map,
    pending_consolidation::PendingConsolidation,
    pending_deposit::PendingDeposit,
    pending_partial_withdrawal::PendingPartialWithdrawal,
    predicates::is_slashable_attestation_data,
    proposer_slashing::ProposerSlashing,
    shuffling_cache::ShufflingCache,
    sync_aggregate::SyncAggregate,
    sync_committee::SyncCommittee,
    sync_committee_indices_cache::SyncCommitteeIndicesCache,
    total_active_balance_cache::TotalActiveBalanceCache,
    validators_root_cache::ValidatorsRootCache,
    voluntary_exit::SignedVoluntaryExit,
};

pub mod quoted_u8_var_list {
    use super::{
        Deserialize, Deserializer, Serialize, Serializer, ValidatorRegistryLimit, VariableList,
    };

    pub fn serialize<S>(
        value: &VariableList<u8, ValidatorRegistryLimit>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let string_vec: Vec<String> = value.iter().map(|v| v.to_string()).collect();
        string_vec.serialize(serializer)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<VariableList<u8, ValidatorRegistryLimit>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string_vec: Vec<String> = Vec::deserialize(deserializer)?;
        let bytes = string_vec
            .into_iter()
            .map(|s| s.parse::<u8>().map_err(serde::de::Error::custom))
            .collect::<Result<Vec<_>, _>>()?;
        VariableList::new(bytes).map_err(|err| {
            serde::de::Error::custom(format!("Cannot create VariableList from bytes: {err:?}"))
        })
    }
}

/// The BeaconState contains some "zkvm" features that addresses where 32-bit zkVMs would fail
/// on constructing a VariableList larger than 2^32 size (i.e. 2^40). When "zkvm" feature
/// is enabled, it would construct the BeaconState with 2^29 list instead.
///
/// This "zkvm" feature needs to be used with the modified ssz_types crate at
/// https://github.com/ReamLabs/ssz_types/tree/magic-extended-list
/// where the crate would detect 2^29 as a magic number when computing the root hash,
/// and it will compute as a 2^40 list root instead.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct BeaconState {
    // Versioning
    #[serde(with = "serde_utils::quoted_u64")]
    pub genesis_time: u64,
    pub genesis_validators_root: B256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: u64,
    pub fork: Fork,

    // History
    pub latest_block_header: BeaconBlockHeader,
    pub block_roots: FixedVector<B256, U8192>,
    pub state_roots: FixedVector<B256, U8192>,
    /// Frozen in Capella, replaced by historical_summaries
    pub historical_roots: VariableList<B256, U16777216>,

    // Eth1
    pub eth1_data: Eth1Data,
    pub eth1_data_votes: VariableList<Eth1Data, U2048>,
    #[serde(with = "serde_utils::quoted_u64")]
    pub eth1_deposit_index: u64,

    // Registry
    /// Shared chunk by chunk between a state and its copies, so copying a state does not copy the
    /// registry, about 300 MB on mainnet; see `ChunkedList`.
    pub validators: ChunkedList<Validator, ValidatorRegistryLimit>,
    #[serde(with = "quoted_u64_var_list")]
    pub balances: VariableList<u64, ValidatorRegistryLimit>,

    // Randomness
    pub randao_mixes: FixedVector<B256, U65536>,

    // Slashings
    #[serde(with = "quoted_u64_fixed_vec")]
    pub slashings: FixedVector<u64, U8192>,

    // Participation
    #[serde(with = "quoted_u8_var_list")]
    pub previous_epoch_participation: VariableList<u8, ValidatorRegistryLimit>,
    #[serde(with = "quoted_u8_var_list")]
    pub current_epoch_participation: VariableList<u8, ValidatorRegistryLimit>,

    // Finality
    pub justification_bits: BitVector<U4>,
    pub previous_justified_checkpoint: Checkpoint,
    pub current_justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,

    // Inactivity
    #[serde(with = "quoted_u64_var_list")]
    pub inactivity_scores: VariableList<u64, ValidatorRegistryLimit>,

    // Sync
    pub current_sync_committee: Arc<SyncCommittee>,
    pub next_sync_committee: Arc<SyncCommittee>,

    // Execution
    pub latest_execution_payload_header: ExecutionPayloadHeader,

    // Withdrawals
    #[serde(with = "serde_utils::quoted_u64")]
    pub next_withdrawal_index: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub next_withdrawal_validator_index: u64,

    // Deep history valid from Capella onwards.
    pub historical_summaries: VariableList<HistoricalSummary, U16777216>,

    // Electra
    #[serde(with = "serde_utils::quoted_u64")]
    pub deposit_requests_start_index: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub deposit_balance_to_consume: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub exit_balance_to_consume: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub earliest_exit_epoch: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub consolidation_balance_to_consume: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub earliest_consolidation_epoch: u64,
    pub pending_deposits: VariableList<PendingDeposit, U134217728>,
    pub pending_partial_withdrawals: VariableList<PendingPartialWithdrawal, U134217728>,
    pub pending_consolidations: VariableList<PendingConsolidation, U262144>,

    // Fulu
    #[serde(with = "quoted_u64_fixed_vec")]
    pub proposer_lookahead: FixedVector<u64, U64>,

    /// Not part of the consensus state: it is never serialized, hashed or compared.
    #[serde(skip)]
    #[ssz(skip_serializing, skip_deserializing)]
    #[tree_hash(skip_hashing)]
    pub caches: StateCaches,
}

/// Values derived from the consensus fields of a `BeaconState` and kept to avoid recomputing them.
/// A copy of the state shares or copies them as each cache's `Clone` decides.
#[derive(Debug, Default, Clone)]
pub struct StateCaches {
    pub shuffling: ShufflingCache,
    pub validators_root: ValidatorsRootCache,
    pub total_active_balance: TotalActiveBalanceCache,
    pub field_roots: StateFieldRootCaches,
    pub sync_committee_indices: SyncCommitteeIndicesCache,
}

/// The caches are derived data, so they never make two states differ.
impl PartialEq for StateCaches {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

/// What every validator's rewards and penalties for the previous epoch depend on.
struct EpochRewards {
    base_reward_per_increment: u64,
    active_increments: u64,
    is_in_inactivity_leak: bool,
    /// For each participation flag: who took part, and their total in effective balance
    /// increments.
    flags: Vec<(Vec<bool>, u64)>,
}

/// Whether ``validator`` gets rewards and penalties for ``previous_epoch``, as in
/// ``get_eligible_validator_indices``.
fn is_eligible_for_rewards(validator: &Validator, previous_epoch: u64) -> bool {
    validator.is_active_validator(previous_epoch)
        || (validator.slashed && previous_epoch + 1 < validator.withdrawable_epoch)
}

/// Depth of the Merkle tree of a list whose limit is the power of two ``N``.
#[cfg(not(feature = "zkvm"))]
fn depth<N: ssz_types::typenum::Unsigned>() -> usize {
    N::to_u64().trailing_zeros() as usize
}

/// Committee ``index`` at ``slot``, taken from ``shuffled``, the output of
/// ``get_shuffled_active_validator_indices`` for the slot's epoch. The bounds are those of
/// ``compute_committee``.
pub fn committee_in_shuffling(shuffled: &[u64], slot: u64, index: u64) -> anyhow::Result<Vec<u64>> {
    let committees_per_slot = committee_count_per_slot(shuffled.len());
    let count = committees_per_slot * SLOTS_PER_EPOCH;
    let committee = (slot % SLOTS_PER_EPOCH) * committees_per_slot + index;
    ensure!(
        committee < count,
        "Committee index {index} is out of range for {committees_per_slot} committees per slot"
    );
    let length = shuffled.len() as u64;
    let start = (length * committee / count) as usize;
    let end = (length * (committee + 1) / count) as usize;
    Ok(shuffled[start..end].to_vec())
}

/// Committees per slot for an epoch with ``active_validator_count`` active validators.
pub fn committee_count_per_slot(active_validator_count: usize) -> u64 {
    (active_validator_count as u64 / SLOTS_PER_EPOCH / TARGET_COMMITTEE_SIZE)
        .clamp(1, MAX_COMMITTEES_PER_SLOT)
}

/// The first 8 bytes of a public key as an integer, for comparing keys quickly before comparing
/// them whole.
fn public_key_prefix(public_key: &PublicKey) -> u64 {
    u64::from_le_bytes(
        public_key.inner[..8]
            .try_into()
            .expect("a public key has 48 bytes"),
    )
}

/// The fields that justification and finalization update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JustificationAndFinalization {
    pub justification_bits: BitVector<U4>,
    pub previous_justified_checkpoint: Checkpoint,
    pub current_justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,
}

impl BeaconState {
    /// Return the current epoch.
    pub fn get_current_epoch(&self) -> u64 {
        compute_epoch_at_slot(self.slot)
    }

    pub fn get_eth1_vote(&self, eth1_chain: &[&Eth1Block]) -> Eth1Data {
        if self.eth1_deposit_index == self.deposit_requests_start_index {
            return self.eth1_data.clone();
        }
        let period_start = self.voting_period_start_time();
        let votes_to_consider = eth1_chain
            .iter()
            .filter(|block| {
                block.is_candidate_block(period_start)
                    && block.deposit_count >= self.eth1_data.deposit_count
            })
            .map(|block| block.eth1_data())
            .collect::<Vec<_>>();
        let valid_votes = self
            .eth1_data_votes
            .iter()
            .filter(|vote| votes_to_consider.contains(vote))
            .collect::<Vec<_>>();
        let vote_counts = valid_votes.iter().fold(HashMap::new(), |mut map, vote| {
            map.entry(*vote)
                .and_modify(|count| *count += 1)
                .or_insert(1);
            map
        });
        valid_votes
            .into_iter()
            .enumerate()
            .max_by_key(|(index, vote)| (vote_counts[*vote], -(*index as i64)))
            .map(|(_, vote)| vote.clone())
            .unwrap_or(match votes_to_consider.last() {
                Some(vote) => (*vote).clone(),
                None => self.eth1_data.clone(),
            })
    }

    pub fn voting_period_start_time(&self) -> u64 {
        let eth1_voting_period_start_slot =
            self.slot - self.slot % (EPOCHS_PER_ETH1_VOTING_PERIOD * SLOTS_PER_EPOCH);
        self.compute_timestamp_at_slot(eth1_voting_period_start_slot)
    }

    pub fn get_eth1_pending_deposit_count(&self) -> u64 {
        let eth1_deposit_index_limit = min(
            self.eth1_data.deposit_count,
            self.deposit_requests_start_index,
        );
        if self.eth1_deposit_index < eth1_deposit_index_limit {
            min(
                MAX_DEPOSITS,
                eth1_deposit_index_limit - self.eth1_deposit_index,
            )
        } else {
            0
        }
    }

    /// Return the previous epoch (unless the current epoch is ``GENESIS_EPOCH``).
    pub fn get_previous_epoch(&self) -> u64 {
        let current_epoch = self.get_current_epoch();
        if current_epoch == GENESIS_EPOCH {
            GENESIS_EPOCH
        } else {
            current_epoch - 1
        }
    }

    /// Return the block root at the start of a recent ``epoch``.
    pub fn get_block_root(&self, epoch: u64) -> anyhow::Result<B256> {
        self.get_block_root_at_slot(compute_start_slot_at_epoch(epoch))
    }

    /// Return the block root at a recent ``slot``.
    pub fn get_block_root_at_slot(&self, slot: u64) -> anyhow::Result<B256> {
        ensure!(
            slot < self.slot && self.slot <= slot + SLOTS_PER_HISTORICAL_ROOT,
            "slot given was outside of block_roots range"
        );
        Ok(self.block_roots[(slot % SLOTS_PER_HISTORICAL_ROOT) as usize])
    }

    /// Return the randao mix at a recent ``epoch``.
    pub fn get_randao_mix(&self, epoch: u64) -> B256 {
        self.randao_mixes[(epoch % EPOCHS_PER_HISTORICAL_VECTOR) as usize]
    }

    /// Return the sequence of active validator indices at ``epoch``.
    pub fn get_active_validator_indices(&self, epoch: u64) -> Vec<u64> {
        self.validators
            .iter()
            .enumerate()
            .filter_map(|(i, validator)| {
                if validator.is_active_validator(epoch) {
                    Some(i as u64)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Return the validator churn limit for the current epoch.
    pub fn get_validator_churn_limit(&self) -> u64 {
        let active_validator_indices = self.get_active_validator_indices(self.get_current_epoch());
        max(
            MIN_PER_EPOCH_CHURN_LIMIT,
            active_validator_indices.len() as u64 / CHURN_LIMIT_QUOTIENT,
        )
    }

    /// Return the seed at ``epoch``.
    pub fn get_seed(&self, epoch: u64, domain_type: B32) -> B256 {
        let mix =
            self.get_randao_mix(epoch + EPOCHS_PER_HISTORICAL_VECTOR - MIN_SEED_LOOKAHEAD - 1);
        let epoch_with_index =
            [domain_type.as_slice(), &epoch.to_le_bytes(), mix.as_slice()].concat();
        B256::from(hash_fixed(&epoch_with_index))
    }

    /// Return the number of committees in each slot for the given ``epoch``.
    pub fn get_committee_count_per_slot(&self, epoch: u64) -> u64 {
        committee_count_per_slot(self.get_shuffled_active_validator_indices(epoch).len())
    }

    /// Active validator indices of ``epoch`` in committee order: the committees of the epoch are
    /// consecutive slices of this list. It is cached per epoch and deciding block, because
    /// recomputing it costs a scan of the whole registry plus a shuffle.
    pub fn get_shuffled_active_validator_indices(&self, epoch: u64) -> Arc<Vec<u64>> {
        let compute = || {
            BEACON_SHUFFLING_CACHE_MISSES_TOTAL.inc();
            let seed = self.get_seed(epoch, DOMAIN_BEACON_ATTESTER);
            compute_shuffled_list(&self.get_active_validator_indices(epoch), seed)
        };
        match self.shuffling_decision_root(epoch) {
            Some(decision_root) => {
                self.caches
                    .shuffling
                    .get_or_insert_with(epoch, decision_root, compute)
            }
            None => Arc::new(compute()),
        }
    }

    /// Root of the block that decides the attester shuffling of ``epoch``: the last block of epoch
    /// ``epoch - 2`` on this state's chain. The seed uses that epoch's RANDAO mix, and activations
    /// and exits take effect at least five epochs after they are processed, so states whose chains
    /// share that block share the shuffling. ``None`` past the next epoch, whose deciding block
    /// this state does not have yet.
    fn shuffling_decision_root(&self, epoch: u64) -> Option<B256> {
        if epoch > self.get_current_epoch() + 1 {
            return None;
        }
        // Before epoch 2 the decision lies at genesis, which every chain shares.
        if epoch < 2 {
            return Some(B256::ZERO);
        }
        self.get_block_root_at_slot(compute_start_slot_at_epoch(epoch - 1) - 1)
            .ok()
    }

    /// Computes the next epoch's attester shuffling on another thread, unless a state sharing this
    /// one's caches has it or is computing it. This takes the shuffling, about 120 ms on mainnet,
    /// off the import of the next epoch's first block. The state is copied for the thread only when
    /// there is something to compute.
    pub fn prepare_next_epoch_shuffling(&self) {
        // zkVM guests have no threads to run it on.
        if cfg!(target_os = "zkvm") {
            return;
        }
        let next_epoch = self.get_current_epoch() + 1;
        let Some(decision_root) = self.shuffling_decision_root(next_epoch) else {
            return;
        };
        if self.caches.shuffling.contains(next_epoch, decision_root) {
            return;
        }
        // The copy shares the registry and these caches with this state.
        let state = self.clone();
        std::thread::spawn(move || {
            state.get_shuffled_active_validator_indices(next_epoch);
        });
    }

    /// Return from ``indices`` a random index sampled by effective balance
    pub fn compute_proposer_index(&self, indices: &[u64], seed: B256) -> anyhow::Result<u64> {
        ensure!(!indices.is_empty(), "Index must be less than index_count");

        let mut i: usize = 0;
        let total = indices.len();

        loop {
            let candidate_index = indices[compute_shuffled_index(i % total, total, seed)?];

            let random_bytes = hash(&[seed.as_slice(), &((i / 16) as u64).to_le_bytes()].concat());
            let offset = i % 16 * 2;
            let random_value = bytes_to_int64(&random_bytes[offset..offset + 2]);

            let effective_balance = self.validators[candidate_index as usize].effective_balance;

            if (effective_balance * MAX_RANDOM_VALUE)
                >= (MAX_EFFECTIVE_BALANCE_ELECTRA * random_value as u64)
            {
                return Ok(candidate_index);
            }

            i += 1;
        }
    }

    /// Whether this state already determines the committees of ``epoch``, the previous, current or
    /// next epoch, so they can be read without advancing a copy of the state. An epoch's attester
    /// seed uses the RANDAO mix from two epochs before it, and activations and exits take effect
    /// at least four epochs after they are processed.
    pub fn determines_committees_of(&self, epoch: u64) -> bool {
        let current_epoch = self.get_current_epoch();
        epoch + 1 >= current_epoch && epoch <= current_epoch + 1
    }

    /// Whether this state already determines the proposers of ``epoch``: the current or next
    /// epoch, which ``proposer_lookahead`` holds.
    pub fn determines_proposers_of(&self, epoch: u64) -> bool {
        let current_epoch = self.get_current_epoch();
        current_epoch <= epoch && epoch <= current_epoch + 1
    }

    /// Return the beacon proposer index at the current slot or a given slot.
    ///
    /// Use `None` when requesting for current slot and `Some(slot)` when requesting for a given
    /// slot.
    pub fn get_beacon_proposer_index(&self, slot: Option<u64>) -> anyhow::Result<u64> {
        let (epoch, slot) = match slot {
            Some(slot) => (compute_epoch_at_slot(slot), slot),
            None => (self.get_current_epoch(), self.slot),
        };

        // Fulu: Use proposer_lookahead if possible
        let start_slot = compute_start_slot_at_epoch(self.get_current_epoch());
        if slot >= start_slot {
            let index = (slot - start_slot) as usize;
            if let Some(proposer_index) = self.proposer_lookahead.get(index) {
                return Ok(*proposer_index);
            }
        }

        // Fallback for slots outside lookahead (or before current epoch)
        let seed = B256::from(hash_fixed(
            &[
                self.get_seed(epoch, DOMAIN_BEACON_PROPOSER).as_slice(),
                &slot.to_le_bytes(),
            ]
            .concat(),
        ));
        let indices = self.get_active_validator_indices(epoch);
        self.compute_proposer_index(&indices, seed)
    }

    pub fn compute_proposer_indices(
        &self,
        epoch: u64,
        seed: B256,
        indices: &[u64],
    ) -> anyhow::Result<FixedVector<u64, U32>> {
        let start_slot = compute_start_slot_at_epoch(epoch);
        let mut proposer_indices = Vec::with_capacity(SLOTS_PER_EPOCH as usize);
        for i in 0..SLOTS_PER_EPOCH {
            let slot = start_slot + i;
            let seed_for_slot =
                B256::from(hash_fixed(&[seed.as_slice(), &slot.to_le_bytes()].concat()));
            proposer_indices.push(self.compute_proposer_index(indices, seed_for_slot)?);
        }
        FixedVector::new(proposer_indices)
            .map_err(|err| anyhow!("Failed to create FixedVector: {err:?}"))
    }

    pub fn get_beacon_proposer_indices(&self, epoch: u64) -> anyhow::Result<FixedVector<u64, U32>> {
        let indices = self.get_active_validator_indices(epoch);
        let seed = self.get_seed(epoch, DOMAIN_BEACON_PROPOSER);
        self.compute_proposer_indices(epoch, seed, &indices)
    }

    pub fn process_proposer_lookahead(&mut self) -> anyhow::Result<()> {
        let len = self.proposer_lookahead.len();
        let slots_per_epoch = SLOTS_PER_EPOCH as usize;

        // Shift out proposers in the first epoch
        let mut new_vec = Vec::with_capacity(len);
        new_vec.extend_from_slice(&self.proposer_lookahead[slots_per_epoch..]);

        // Fill in the last epoch with new proposer indices
        let next_epoch = self.get_current_epoch() + MIN_SEED_LOOKAHEAD + 1;
        let new_indices = self.get_beacon_proposer_indices(next_epoch)?;

        new_vec.extend(new_indices.iter());

        self.proposer_lookahead = FixedVector::new(new_vec)
            .map_err(|err| anyhow!("Failed to update proposer_lookahead: {err:?}"))?;
        Ok(())
    }

    /// Return the combined effective balance of the ``indices``.
    /// ``EFFECTIVE_BALANCE_INCREMENT`` Gwei minimum to avoid divisions by zero.
    /// Math safe up to ~10B ETH, after which this overflows uint64.
    pub fn get_total_balance(&self, indices: HashSet<u64>) -> u64 {
        max(
            EFFECTIVE_BALANCE_INCREMENT,
            indices
                .iter()
                .map(|index| self.validators[*index as usize].effective_balance)
                .sum(),
        )
    }

    /// Return the combined effective balance of the active validators.
    /// Note: ``get_total_balance`` returns ``EFFECTIVE_BALANCE_INCREMENT`` Gwei minimum to avoid
    /// divisions by zero.
    pub fn get_total_active_balance(&self) -> u64 {
        let epoch = self.get_current_epoch();
        self.caches
            .total_active_balance
            .get_or_insert_with(epoch, || {
                self.get_total_balance(
                    self.get_active_validator_indices(epoch)
                        .into_iter()
                        .collect::<HashSet<_>>(),
                )
            })
    }

    /// Return the signature domain (fork version concatenated with domain type) of a message.
    pub fn get_domain(&self, domain_type: B32, epoch: Option<u64>) -> B256 {
        let epoch = match epoch {
            Some(epoch) => epoch,
            None => self.get_current_epoch(),
        };
        let fork_version = if epoch < self.fork.epoch {
            self.fork.previous_version
        } else {
            self.fork.current_version
        };
        compute_domain(
            domain_type,
            Some(fork_version),
            Some(self.genesis_validators_root),
        )
    }

    /// Return the beacon committee at ``slot`` for ``index``.
    pub fn get_beacon_committee(&self, slot: u64, index: u64) -> anyhow::Result<Vec<u64>> {
        let shuffled = self.get_shuffled_active_validator_indices(compute_epoch_at_slot(slot));
        committee_in_shuffling(&shuffled, slot, index)
    }

    /// Return the committee assignment in the ``epoch`` for ``validator_index``.
    /// ``assignment`` returned is a tuple of the following form:
    ///     * ``assignment[0]`` is the list of validators in the committee
    ///     * ``assignment[1]`` is the index to which the committee is assigned
    ///     * ``assignment[2]`` is the slot at which the committee is assigned
    /// Return None if no assignment.
    pub fn get_committee_assignment(
        &self,
        epoch: u64,
        validator_index: u64,
    ) -> anyhow::Result<Option<(Vec<u64>, u64, u64)>> {
        let next_epoch = self.get_current_epoch() + 1;
        ensure!(
            epoch <= next_epoch,
            "Requested epoch {epoch} is beyond the allowed maximum (next epoch: {next_epoch})",
        );
        let start_slot = compute_start_slot_at_epoch(epoch);
        let committee_count_per_slot = self.get_committee_count_per_slot(epoch);
        for slot in start_slot..start_slot + SLOTS_PER_EPOCH {
            for index in 0..committee_count_per_slot {
                let committee = self.get_beacon_committee(slot, index)?;
                if committee.contains(&validator_index) {
                    return Ok(Some((committee, index, slot)));
                }
            }
        }
        Ok(None)
    }

    /// Check if ``indexed_attestation`` is not empty, has sorted and unique indices and has a valid
    /// aggregate signature.
    pub fn is_valid_indexed_attestation(
        &self,
        indexed_attestation: &IndexedAttestation,
    ) -> anyhow::Result<bool> {
        let indices: Vec<usize> = indexed_attestation
            .attesting_indices
            .iter()
            .map(|&i| i as usize)
            .collect();
        // Verify indices are sorted and unique
        if indices.is_empty() || !is_sorted_and_unique(&indices) {
            return Ok(false);
        }

        let domain = self.get_domain(
            DOMAIN_BEACON_ATTESTER,
            Some(indexed_attestation.data.target.epoch),
        );
        let signing_root = compute_signing_root(&indexed_attestation.data, domain);

        indexed_attestation
            .signature
            .fast_aggregate_verify(
                indices
                    .iter()
                    .map(|&index| {
                        self.validators
                            .get(index)
                            .map(|validator| &validator.public_key)
                            .ok_or(anyhow!("Invalid index"))
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?,
                signing_root.as_ref(),
            )
            .map_err(|err| anyhow!("Invalid indexed attestation: {err}"))
    }

    /// Return the set of attesting indices corresponding to ``aggregation_bits`` and
    /// ``committee_bits``.
    pub fn get_attesting_indices(&self, attestation: &Attestation) -> anyhow::Result<HashSet<u64>> {
        // Collect every committee's attesters into one set.
        let mut output = HashSet::new();
        let mut committee_offset = 0;
        for committee_index in get_committee_indices(&attestation.committee_bits) {
            let committee = self.get_beacon_committee(attestation.data.slot, committee_index)?;

            for (i, attester_index) in committee.iter().enumerate() {
                if attestation
                    .aggregation_bits
                    .get(committee_offset + i)
                    .map_err(|err| anyhow!("Failed to get aggregation_bit {err:?}"))?
                {
                    output.insert(*attester_index);
                }
            }

            committee_offset += committee.len();
        }
        Ok(output)
    }

    /// Return the indexed attestation corresponding to ``attestation``.
    pub fn get_indexed_attestation(
        &self,
        attestation: &Attestation,
    ) -> anyhow::Result<IndexedAttestation> {
        let attesting_indices = self
            .get_attesting_indices(attestation)?
            .into_iter()
            .sorted()
            .collect::<Vec<_>>();
        Ok(IndexedAttestation {
            attesting_indices: attesting_indices.try_into().map_err(|err| {
                anyhow!("Failed to convert attesting_indices to VariableList: {err:?}")
            })?,
            data: attestation.data.clone(),
            signature: attestation.signature.clone(),
        })
    }

    /// Increase the validator balance at index ``index`` by ``delta``.
    pub fn increase_balance(&mut self, index: u64, delta: u64) -> anyhow::Result<()> {
        if let Some(balance) = self.balances.get_mut(index as usize) {
            *balance += delta;
            Ok(())
        } else {
            Err(anyhow!("failed to increase balance"))
        }
    }

    /// Decrease the validator balance at index ``index`` by ``delta`` with underflow protection.
    pub fn decrease_balance(&mut self, index: u64, delta: u64) -> anyhow::Result<()> {
        if let Some(balance) = self.balances.get_mut(index as usize) {
            *balance = balance.saturating_sub(delta);
            Ok(())
        } else {
            Err(anyhow!("failed to decrease balance"))
        }
    }

    /// Initiate the exit of the validator with index ``index``.
    pub fn initiate_validator_exit(&mut self, index: u64) -> anyhow::Result<()> {
        // Return if validator already initiated exit
        let Some(validator) = self.validators.get(index as usize) else {
            bail!("could not get validator")
        };
        if validator.exit_epoch != FAR_FUTURE_EPOCH {
            return Ok(());
        }

        // Compute exit queue epoch
        let exit_queue_epoch =
            self.compute_exit_epoch_and_update_churn(validator.effective_balance);

        let Some(validator) = self.validators.get_mut(index as usize) else {
            bail!("could not get validator")
        };

        // Set validator exit epoch and withdrawable epoch
        validator.exit_epoch = exit_queue_epoch;
        validator.withdrawable_epoch = validator
            .exit_epoch
            .checked_add(MIN_VALIDATOR_WITHDRAWABILITY_DELAY)
            .ok_or(anyhow!("Failed to set withdrawable epoch"))?;

        Ok(())
    }

    /// Slash the validator with index ``slashed_index``
    pub fn slash_validator(
        &mut self,
        slashed_index: u64,
        whistleblower_index: Option<u64>,
    ) -> anyhow::Result<()> {
        let epoch = self.get_current_epoch();

        // Initiate validator exit
        self.initiate_validator_exit(slashed_index)?;

        let validator_effective_balance =
            if let Some(validator) = self.validators.get_mut(slashed_index as usize) {
                validator.slashed = true;
                validator.withdrawable_epoch = std::cmp::max(
                    validator.withdrawable_epoch,
                    epoch + EPOCHS_PER_SLASHINGS_VECTOR,
                );
                validator.effective_balance
            } else {
                bail!("Validator at index {slashed_index} not found")
            };
        // Add slashed effective balance to the slashings vector
        self.slashings[(epoch % EPOCHS_PER_SLASHINGS_VECTOR) as usize] +=
            validator_effective_balance;
        // Decrease validator balance
        self.decrease_balance(
            slashed_index,
            validator_effective_balance / MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA,
        )?;

        // Apply proposer and whistleblower rewards
        let proposer_index = self.get_beacon_proposer_index(None)?;
        let whistleblower_index = whistleblower_index.unwrap_or(proposer_index);

        let whistleblower_reward =
            validator_effective_balance / WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA;
        let proposer_reward = whistleblower_reward * PROPOSER_WEIGHT / WEIGHT_DENOMINATOR;
        self.increase_balance(proposer_index, proposer_reward)?;
        self.increase_balance(whistleblower_index, whistleblower_reward - proposer_reward)?;

        Ok(())
    }

    pub fn is_valid_genesis_state(&self) -> bool {
        if self.genesis_time < MIN_GENESIS_TIME {
            return false;
        }
        if self.get_active_validator_indices(GENESIS_EPOCH).len()
            < MIN_GENESIS_ACTIVE_VALIDATOR_COUNT as usize
        {
            return false;
        }
        true
    }

    /// Return a new ``ParticipationFlags`` adding ``flag_index`` to ``flags``.
    pub fn add_flag(flags: u8, flag_index: u8) -> u8 {
        let flag = 1 << flag_index;
        flags | flag
    }

    /// Return whether ``flags`` has ``flag_index`` set.
    pub fn has_flag(flags: u8, flag_index: u8) -> bool {
        let flag = 1 << flag_index;
        flags & flag == flag
    }

    /// Return the set of validator indices that are both active and unslashed for the given
    /// ``flag_index`` and ``epoch``.
    pub fn get_unslashed_participating_indices(
        &self,
        flag_index: u8,
        epoch: u64,
    ) -> anyhow::Result<HashSet<u64>> {
        ensure!(
            epoch == self.get_previous_epoch() || epoch == self.get_current_epoch(),
            "Epoch must be either the previous or current epoch"
        );
        let epoch_participation = if epoch == self.get_current_epoch() {
            &self.current_epoch_participation
        } else {
            &self.previous_epoch_participation
        };
        let active_validator_indices = self.get_active_validator_indices(epoch);
        let mut participating_indices = vec![];
        for i in active_validator_indices {
            if Self::has_flag(epoch_participation[i as usize], flag_index) {
                participating_indices.push(i);
            }
        }
        let filtered_indices: HashSet<u64> = participating_indices
            .into_iter()
            .filter(|&index| !self.validators[index as usize].slashed)
            .collect();
        Ok(filtered_indices)
    }

    /// Membership in ``get_unslashed_participating_indices(flag_index, epoch)`` by validator
    /// index, with the members' ``get_total_balance``. Epoch processing asks whether each of about
    /// 870,000 validators participated, and a vector answers that without building a hash set.
    pub fn get_unslashed_participating_mask(
        &self,
        flag_index: u8,
        epoch: u64,
    ) -> anyhow::Result<(Vec<bool>, u64)> {
        ensure!(
            epoch == self.get_previous_epoch() || epoch == self.get_current_epoch(),
            "Epoch must be either the previous or current epoch"
        );
        let epoch_participation = if epoch == self.get_current_epoch() {
            &self.current_epoch_participation
        } else {
            &self.previous_epoch_participation
        };
        let mut balance = 0;
        let mask = self
            .validators
            .iter()
            .zip(epoch_participation.iter())
            .map(|(validator, flags)| {
                let participating = validator.is_active_validator(epoch)
                    && !validator.slashed
                    && Self::has_flag(*flags, flag_index);
                if participating {
                    balance += validator.effective_balance;
                }
                participating
            })
            .collect();
        Ok((mask, max(EFFECTIVE_BALANCE_INCREMENT, balance)))
    }

    /// ``get_total_balance(get_unslashed_participating_indices(flag_index, epoch))`` for the
    /// previous and the current epoch, without building the index sets, which hold most of the
    /// validator registry. The registry is scanned once, its chunks split across threads.
    pub fn get_unslashed_participating_balances(&self, flag_index: u8) -> (u64, u64) {
        let previous_epoch = self.get_previous_epoch();
        let current_epoch = self.get_current_epoch();
        let sum = |validators: &[Validator], previous: &[u8], current: &[u8]| {
            let mut balances = (0u64, 0u64);
            for ((validator, previous_flags), current_flags) in
                validators.iter().zip(previous).zip(current)
            {
                if validator.slashed {
                    continue;
                }
                if validator.is_active_validator(previous_epoch)
                    && Self::has_flag(*previous_flags, flag_index)
                {
                    balances.0 += validator.effective_balance;
                }
                if validator.is_active_validator(current_epoch)
                    && Self::has_flag(*current_flags, flag_index)
                {
                    balances.1 += validator.effective_balance;
                }
            }
            balances
        };

        let registry_chunks = self.validators.chunks();
        let previous = &self.previous_epoch_participation[..];
        let current = &self.current_epoch_participation[..];
        // One registry chunk, with the participation flags of the same validators.
        let sum_chunk = |&chunk: &usize| {
            let validators = registry_chunks[chunk].as_slice();
            let start = chunk * CHUNK_SIZE;
            let end = start + validators.len();
            let previous_flags = &previous[start.min(previous.len())..end.min(previous.len())];
            let current_flags = &current[start.min(current.len())..end.min(current.len())];
            sum(validators, previous_flags, current_flags)
        };
        let chunk_indices: Vec<usize> = (0..registry_chunks.len()).collect();
        let (previous_balance, current_balance) = parallel_map(&chunk_indices, 2, sum_chunk)
            .into_iter()
            .fold((0, 0), |total, part| (total.0 + part.0, total.1 + part.1));
        (
            max(EFFECTIVE_BALANCE_INCREMENT, previous_balance),
            max(EFFECTIVE_BALANCE_INCREMENT, current_balance),
        )
    }

    pub fn process_inactivity_updates(&mut self) -> anyhow::Result<()> {
        // Skip the genesis epoch as score updates are based on the previous epoch participation
        if self.get_current_epoch() == GENESIS_EPOCH {
            return Ok(());
        }
        let (unslashed_participating, _) = self.get_unslashed_participating_mask(
            TIMELY_TARGET_FLAG_INDEX,
            self.get_previous_epoch(),
        )?;
        let is_in_inactivity_leak = self.is_in_inactivity_leak();
        for index in self.get_eligible_validator_indices()? {
            // Increase the inactivity score of inactive validators
            if unslashed_participating[index as usize] {
                self.inactivity_scores[index as usize] -=
                    min(1, self.inactivity_scores[index as usize])
            } else {
                self.inactivity_scores[index as usize] += INACTIVITY_SCORE_BIAS
            }

            // Decrease the inactivity score of all eligible validators during a leak-free epoch
            if !is_in_inactivity_leak {
                self.inactivity_scores[index as usize] -= min(
                    INACTIVITY_SCORE_RECOVERY_RATE,
                    self.inactivity_scores[index as usize],
                )
            }
        }

        Ok(())
    }

    pub fn get_base_reward_per_increment(&self) -> u64 {
        EFFECTIVE_BALANCE_INCREMENT * BASE_REWARD_FACTOR
            / integer_squareroot(self.get_total_active_balance())
    }

    /// Return the base reward for the validator defined by ``index`` with respect to the current
    /// ``state``.
    pub fn get_base_reward(&self, index: u64, base_reward_per_increment: u64) -> u64 {
        let increments =
            self.validators[index as usize].effective_balance / EFFECTIVE_BALANCE_INCREMENT;
        increments * base_reward_per_increment
    }

    pub fn get_proposer_reward(&self, attesting_index: u64) -> u64 {
        self.get_base_reward(attesting_index, self.get_base_reward_per_increment())
            / PROPOSER_REWARD_QUOTIENT
    }

    pub fn get_finality_delay(&self) -> u64 {
        self.get_previous_epoch() - self.finalized_checkpoint.epoch
    }

    pub fn is_in_inactivity_leak(&self) -> bool {
        self.get_finality_delay() > MIN_EPOCHS_TO_INACTIVITY_PENALTY
    }

    pub fn get_eligible_validator_indices(&self) -> anyhow::Result<Vec<u64>> {
        let previous_epoch = self.get_previous_epoch();
        let mut validator_indices = vec![];
        for (index, validator) in self.validators.iter().enumerate() {
            if is_eligible_for_rewards(validator, previous_epoch) {
                validator_indices.push(index as u64)
            }
        }
        Ok(validator_indices)
    }

    /// What every validator's rewards and penalties for the previous epoch depend on.
    fn epoch_rewards(&self) -> anyhow::Result<EpochRewards> {
        let previous_epoch = self.get_previous_epoch();
        let mut flags = Vec::with_capacity(PARTICIPATION_FLAG_WEIGHTS.len());
        for flag_index in 0..PARTICIPATION_FLAG_WEIGHTS.len() {
            let (participating, participating_balance) =
                self.get_unslashed_participating_mask(flag_index as u8, previous_epoch)?;
            flags.push((
                participating,
                participating_balance / EFFECTIVE_BALANCE_INCREMENT,
            ));
        }
        Ok(EpochRewards {
            base_reward_per_increment: self.get_base_reward_per_increment(),
            active_increments: self.get_total_active_balance() / EFFECTIVE_BALANCE_INCREMENT,
            is_in_inactivity_leak: self.is_in_inactivity_leak(),
            flags,
        })
    }

    /// One validator's ``(reward, penalty)`` in ``get_flag_index_deltas``.
    fn flag_index_delta(
        &self,
        epoch_rewards: &EpochRewards,
        index: usize,
        flag_index: usize,
    ) -> (u64, u64) {
        let base_reward =
            self.get_base_reward(index as u64, epoch_rewards.base_reward_per_increment);
        let weight = PARTICIPATION_FLAG_WEIGHTS[flag_index];
        let (participating, participating_increments) = &epoch_rewards.flags[flag_index];
        if participating[index] {
            if epoch_rewards.is_in_inactivity_leak {
                return (0, 0);
            }
            let reward = base_reward * weight * participating_increments
                / (epoch_rewards.active_increments * WEIGHT_DENOMINATOR);
            (reward, 0)
        } else if flag_index == TIMELY_HEAD_FLAG_INDEX as usize {
            (0, 0)
        } else {
            (0, base_reward * weight / WEIGHT_DENOMINATOR)
        }
    }

    /// One validator's penalty in ``get_inactivity_penalty_deltas``.
    fn inactivity_penalty(&self, epoch_rewards: &EpochRewards, index: usize) -> u64 {
        if epoch_rewards.flags[TIMELY_TARGET_FLAG_INDEX as usize].0[index] {
            return 0;
        }
        self.validators[index].effective_balance * self.inactivity_scores[index]
            / (INACTIVITY_SCORE_BIAS * INACTIVITY_PENALTY_QUOTIENT_BELLATRIX)
    }

    pub fn get_index_for_new_validator(&self) -> u64 {
        self.validators.len() as u64
    }

    /// Return the flag indices that are satisfied by an attestation.
    pub fn get_attestation_participation_flag_indices(
        &self,
        data: &AttestationData,
        inclusion_delay: u64,
    ) -> anyhow::Result<Vec<u8>> {
        let justified_checkpoint = if data.target.epoch == self.get_current_epoch() {
            self.current_justified_checkpoint
        } else {
            self.previous_justified_checkpoint
        };
        let is_matching_source = data.source == justified_checkpoint;
        let is_matching_target =
            is_matching_source && data.target.root == self.get_block_root(data.target.epoch)?;
        let is_matching_head = is_matching_target
            && data.beacon_block_root == self.get_block_root_at_slot(data.slot)?;
        ensure!(is_matching_source);

        let mut participation_flag_indices = vec![];

        if is_matching_source && inclusion_delay <= integer_squareroot(SLOTS_PER_EPOCH) {
            participation_flag_indices.push(TIMELY_SOURCE_FLAG_INDEX);
        }
        if is_matching_target {
            participation_flag_indices.push(TIMELY_TARGET_FLAG_INDEX);
        }
        if is_matching_head && inclusion_delay == MIN_ATTESTATION_INCLUSION_DELAY {
            participation_flag_indices.push(TIMELY_HEAD_FLAG_INDEX);
        }

        Ok(participation_flag_indices)
    }

    /// Return the inactivity penalty deltas by considering timely target participation flags and
    /// inactivity scores.
    pub fn get_inactivity_penalty_deltas(&self) -> anyhow::Result<(Vec<u64>, Vec<u64>)> {
        let rewards = vec![0; self.validators.len()];
        let mut penalties = vec![0; self.validators.len()];
        let epoch_rewards = self.epoch_rewards()?;
        for index in self.get_eligible_validator_indices()? {
            penalties[index as usize] += self.inactivity_penalty(&epoch_rewards, index as usize);
        }

        Ok((rewards, penalties))
    }

    pub fn process_block_header(&mut self, block: &BeaconBlock) -> anyhow::Result<()> {
        // Verify that the slots match
        ensure!(
            self.slot == block.slot,
            "State slot must be equal to block slot"
        );
        // Verify that the block is newer than latest block header
        ensure!(
            block.slot > self.latest_block_header.slot,
            "Block slot must be greater than latest block header slot of state"
        );
        // Verify that proposer index is the correct index
        ensure!(
            block.proposer_index == self.get_beacon_proposer_index(None)?,
            "Block proposer index must be equal to beacon proposer index"
        );
        // Verify that the parent matches
        ensure!(
            block.parent_root == self.latest_block_header.tree_hash_root(),
            "Block Parent Root must be equal root of latest block header"
        );

        // Cache current block as the new latest block
        self.latest_block_header = BeaconBlockHeader {
            slot: block.slot,
            proposer_index: block.proposer_index,
            parent_root: block.parent_root,
            state_root: B256::default(), // Overwritten in the next process_slot call
            body_root: block.body.tree_hash_root(),
        };

        // Verify proposer is not slashed
        let proposer = &self.validators[block.proposer_index as usize];
        ensure!(!proposer.slashed, "Block proposer must not be slashed");

        Ok(())
    }

    pub fn get_expected_withdrawals(&self) -> anyhow::Result<(Vec<Withdrawal>, u64)> {
        let epoch = self.get_current_epoch();
        let mut withdrawal_index = self.next_withdrawal_index;
        let mut validator_index = self.next_withdrawal_validator_index;
        let mut withdrawals: Vec<Withdrawal> = vec![];
        let mut processed_partial_withdrawals_count = 0;

        // Consume pending partial withdrawals
        for withdrawal in self.pending_partial_withdrawals.iter() {
            if withdrawal.withdrawable_epoch > epoch
                || withdrawals.len() as u64 == MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP
            {
                break;
            }

            let Some(validator) = self.validators.get(withdrawal.validator_index as usize) else {
                bail!(
                    "Validator index out of bounds: {}",
                    withdrawal.validator_index
                );
            };
            let total_withdrawn = withdrawals
                .iter()
                .filter(|w| w.validator_index == withdrawal.validator_index)
                .map(|w| w.amount)
                .sum::<u64>();
            let balance = *self
                .balances
                .get(withdrawal.validator_index as usize)
                .ok_or(anyhow!(
                    "Balance index out of bounds: {}",
                    withdrawal.validator_index
                ))?
                - total_withdrawn;
            if validator.exit_epoch == FAR_FUTURE_EPOCH
                && validator.effective_balance >= MIN_ACTIVATION_BALANCE
                && balance > MIN_ACTIVATION_BALANCE
            {
                let withdrawable_balance = min(balance - MIN_ACTIVATION_BALANCE, withdrawal.amount);
                withdrawals.push(Withdrawal {
                    index: withdrawal_index,
                    validator_index: withdrawal.validator_index,
                    address: Address::from_slice(&validator.withdrawal_credentials[12..]),
                    amount: withdrawable_balance,
                });
                withdrawal_index += 1;
            }
            processed_partial_withdrawals_count += 1;
        }

        // Sweep for remaining.
        let bound = min(self.validators.len(), MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP);
        for _ in 0..bound {
            let validator = &self
                .validators
                .get(validator_index as usize)
                .ok_or(anyhow!("Validator index out of bounds: {validator_index}"))?;
            let partially_withdrawn_balance = withdrawals
                .iter()
                .filter(|withdrawal| withdrawal.validator_index == validator_index)
                .map(|withdrawal| withdrawal.amount)
                .sum::<u64>();
            let balance = *self
                .balances
                .get(validator_index as usize)
                .ok_or(anyhow!("Balance index out of bounds: {validator_index}"))?
                - partially_withdrawn_balance;
            if validator.is_fully_withdrawable_validator(balance, epoch) {
                withdrawals.push(Withdrawal {
                    index: withdrawal_index,
                    validator_index,
                    address: Address::from_slice(&validator.withdrawal_credentials[12..]),
                    amount: balance,
                });
                withdrawal_index += 1
            } else if validator.is_partially_withdrawable_validator(balance) {
                withdrawals.push(Withdrawal {
                    index: withdrawal_index,
                    validator_index,
                    address: Address::from_slice(&validator.withdrawal_credentials[12..]),
                    amount: balance - validator.get_max_effective_balance(),
                });
                withdrawal_index += 1
            }
            if withdrawals.len() == MAX_WITHDRAWALS_PER_PAYLOAD as usize {
                break;
            }
            validator_index = (validator_index + 1) % self.validators.len() as u64
        }

        Ok((withdrawals, processed_partial_withdrawals_count))
    }

    pub fn process_withdrawals(&mut self, payload: &ExecutionPayload) -> anyhow::Result<()> {
        let (expected_withdrawals, processed_partial_withdrawals_count) =
            self.get_expected_withdrawals()?;
        ensure!(
            payload.withdrawals.deref() == expected_withdrawals,
            "Withdrawals do not match expected withdrawals",
        );

        for withdrawal in &expected_withdrawals {
            self.decrease_balance(withdrawal.validator_index, withdrawal.amount)?;
        }

        let remaining_partial_withdrawals = Vec::from(take(&mut self.pending_partial_withdrawals));
        for partial_withdrawal in remaining_partial_withdrawals
            .into_iter()
            .skip(processed_partial_withdrawals_count as usize)
        {
            self.pending_partial_withdrawals
                .push(partial_withdrawal)
                .map_err(|err| {
                    anyhow!(
                        "Failed to push partial_withdrawal to pending_partial_withdrawals: {err:?}"
                    )
                })?;
        }

        // Update the next withdrawal index if this block contained withdrawals
        if !expected_withdrawals.is_empty() {
            let latest_withdrawal = &expected_withdrawals[expected_withdrawals.len() - 1];
            self.next_withdrawal_index = latest_withdrawal.index + 1
        }

        // Update the next validator index to start the next withdrawal sweep
        if expected_withdrawals.len() == MAX_WITHDRAWALS_PER_PAYLOAD as usize {
            // Next sweep starts after the latest withdrawal's validator index
            let next_validator_index =
                (expected_withdrawals[expected_withdrawals.len() - 1].validator_index + 1)
                    % self.validators.len() as u64;
            self.next_withdrawal_validator_index = next_validator_index
        } else {
            // Advance sweep by the max length of the sweep if there was not a full set of
            // withdrawals
            let next_index =
                self.next_withdrawal_validator_index + MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP as u64;
            let next_validator_index = next_index % self.validators.len() as u64;
            self.next_withdrawal_validator_index = next_validator_index
        }

        Ok(())
    }

    pub fn add_validator_to_registry(
        &mut self,
        public_key: PublicKey,
        withdrawal_credentials: B256,
        amount: u64,
    ) -> anyhow::Result<()> {
        self.validators
            .push(get_validator_from_deposit(
                public_key,
                withdrawal_credentials,
                amount,
            ))
            .map_err(|err| anyhow!("Couldn't push to validators {err:?}"))?;
        self.balances
            .push(amount)
            .map_err(|err| anyhow!("Couldn't push to balances {err:?}"))?;
        self.previous_epoch_participation
            .push(0)
            .map_err(|err| anyhow!("Couldn't push to previous_epoch_participation {err:?}"))?;
        self.current_epoch_participation
            .push(0)
            .map_err(|err| anyhow!("Couldn't push to current_epoch_participation {err:?}"))?;
        self.inactivity_scores
            .push(0)
            .map_err(|err| anyhow!("Couldn't push to inactivity_scores {err:?}"))?;

        Ok(())
    }

    pub fn apply_deposit(
        &mut self,
        public_key: PublicKey,
        withdrawal_credentials: B256,
        amount: u64,
        signature: BLSSignature,
    ) -> anyhow::Result<()> {
        if self.find_validator_index(&public_key).is_none() {
            // Verify the deposit signature (proof of possession) which is not checked by the
            // deposit contract
            match is_valid_deposit_signature(
                &public_key,
                withdrawal_credentials,
                amount,
                &signature,
            ) {
                Ok(true) => {
                    self.add_validator_to_registry(public_key.clone(), withdrawal_credentials, 0)?
                }
                _ => return Ok(()),
            }
        }

        // Increase balance by deposit amount
        self.pending_deposits
            .push(PendingDeposit {
                public_key,
                withdrawal_credentials,
                amount,
                signature,
                // Use GENESIS_SLOT to distinguish from a pending deposit request
                slot: GENESIS_SLOT,
            })
            .map_err(|err| anyhow!("Couldn't push to pending_deposits {err:?}"))?;

        Ok(())
    }

    pub fn process_deposit(&mut self, deposit: &Deposit) -> anyhow::Result<()> {
        // Verify the Merkle branch
        ensure!(is_valid_merkle_branch(
            deposit.data.tree_hash_root(),
            &deposit.proof,
            // Add 1 for the List length mix-in
            DEPOSIT_CONTRACT_TREE_DEPTH + 1,
            self.eth1_deposit_index,
            self.eth1_data.deposit_root,
        ));

        // Deposits must be processed in order
        self.eth1_deposit_index += 1;

        self.apply_deposit(
            deposit.data.public_key.clone(),
            deposit.data.withdrawal_credentials,
            deposit.data.amount,
            deposit.data.signature.clone(),
        )
    }

    pub fn validate_bls_to_execution_change(
        &self,
        signed_bls_to_execution_change: &SignedBLSToExecutionChange,
    ) -> anyhow::Result<()> {
        let bls_to_execution_change = &signed_bls_to_execution_change.message;

        ensure!(bls_to_execution_change.validator_index < self.validators.len() as u64);

        let validator: &Validator =
            &self.validators[bls_to_execution_change.validator_index as usize];

        ensure!(&validator.withdrawal_credentials[..1] == BLS_WITHDRAWAL_PREFIX);
        ensure!(
            validator.withdrawal_credentials[1..]
                == hash(bls_to_execution_change.from_bls_public_key.to_bytes())[1..]
        );

        // Fork-agnostic domain since address changes are valid across forks
        let domain = compute_domain(
            DOMAIN_BLS_TO_EXECUTION_CHANGE,
            Some(beacon_network_spec().genesis_fork_version),
            Some(self.genesis_validators_root),
        );

        let signing_root = compute_signing_root(bls_to_execution_change, domain);
        ensure!(
            signed_bls_to_execution_change.signature.verify(
                &bls_to_execution_change.from_bls_public_key,
                signing_root.as_ref()
            )?,
            "BLS Signature verification failed!"
        );

        Ok(())
    }

    pub fn process_bls_to_execution_change(
        &mut self,
        signed_bls_to_execution_change: &SignedBLSToExecutionChange,
    ) -> anyhow::Result<()> {
        self.validate_bls_to_execution_change(signed_bls_to_execution_change)?;

        let bls_to_execution_change = &signed_bls_to_execution_change.message;

        let withdrawal_credentials = [
            ETH1_ADDRESS_WITHDRAWAL_PREFIX,
            vec![0x00; 11].as_slice(),
            bls_to_execution_change.to_execution_address.as_slice(),
        ]
        .concat();
        self.validators[bls_to_execution_change.validator_index as usize].withdrawal_credentials =
            B256::from_slice(&withdrawal_credentials);

        Ok(())
    }

    pub fn compute_timestamp_at_slot(&self, slot: u64) -> u64 {
        let slots_since_genesis = slot - GENESIS_SLOT;
        self.genesis_time + slots_since_genesis * beacon_network_spec().seconds_per_slot()
    }

    pub fn validate_voluntary_exit(
        &self,
        signed_voluntary_exit: &SignedVoluntaryExit,
    ) -> anyhow::Result<()> {
        let voluntary_exit = &signed_voluntary_exit.message;
        let validator_index = voluntary_exit.validator_index as usize;

        let validator = self
            .validators
            .get(validator_index)
            .ok_or(anyhow!("Invalid validator index"))?;

        // Verify the validator is active
        ensure!(
            validator.is_active_validator(self.get_current_epoch()),
            "Validator is not active"
        );

        // Verify exit has not been initiated
        ensure!(
            validator.exit_epoch == FAR_FUTURE_EPOCH,
            "Exit has already been initiated"
        );

        // Exits must specify an epoch when they become valid; they are not valid before then
        ensure!(
            self.get_current_epoch() >= voluntary_exit.epoch,
            "Exit is not yet valid"
        );

        // Only exit validator if it has no pending withdrawals in the queue
        ensure!(
            self.get_pending_balance_to_withdraw(voluntary_exit.validator_index) == 0,
            "Validator has pending withdrawals"
        );

        // Verify the validator has been active long enough
        let earlist_exit_epoch = validator
            .activation_epoch
            .checked_add(SHARD_COMMITTEE_PERIOD)
            .ok_or(anyhow!("Failed to calculate earliest exit epoch"))?;
        ensure!(
            self.get_current_epoch() >= earlist_exit_epoch,
            "Validator has not been active long enough"
        );

        let domain = voluntary_exit_domain(self.genesis_validators_root);
        let signing_root = compute_signing_root(voluntary_exit, domain);

        ensure!(
            signed_voluntary_exit
                .signature
                .verify(&validator.public_key, signing_root.as_ref())?,
            "BLS Signature verification failed!"
        );

        Ok(())
    }

    pub fn process_voluntary_exit(
        &mut self,
        signed_voluntary_exit: &SignedVoluntaryExit,
    ) -> anyhow::Result<()> {
        self.validate_voluntary_exit(signed_voluntary_exit)?;

        // Initiate exit
        self.initiate_validator_exit(signed_voluntary_exit.message.validator_index)?;

        Ok(())
    }

    pub fn process_withdrawal_request(
        &mut self,
        withdrawal_request: &WithdrawalRequest,
    ) -> anyhow::Result<()> {
        let amount = withdrawal_request.amount;
        let is_full_exit_request = amount == FULL_EXIT_REQUEST_AMOUNT;

        // If partial withdrawal queue is full, only full exits are processed
        if self.pending_partial_withdrawals.len() as u64 == PENDING_PARTIAL_WITHDRAWALS_LIMIT
            && !is_full_exit_request
        {
            return Ok(());
        }

        // Verify public_key exists
        let Some(index) = self.find_validator_index(&withdrawal_request.validator_public_key)
        else {
            return Ok(());
        };
        let validator = &self.validators[index];

        // Verify withdrawal credentials
        let has_correct_credentials = validator.has_execution_withdrawal_credential();
        let is_correct_source_address =
            validator.withdrawal_credentials[12..] == withdrawal_request.source_address;

        if !(has_correct_credentials && is_correct_source_address) {
            return Ok(());
        }

        // Verify the validator is active
        if !validator.is_active_validator(self.get_current_epoch()) {
            return Ok(());
        }

        // Verify exit has not been initiated
        if validator.exit_epoch != FAR_FUTURE_EPOCH {
            return Ok(());
        }

        // Verify the validator has been active long enough
        if self.get_current_epoch() < validator.activation_epoch + SHARD_COMMITTEE_PERIOD {
            return Ok(());
        }

        let pending_balance_to_withdraw = self.get_pending_balance_to_withdraw(index as u64);

        if is_full_exit_request {
            // Only exit validator if it has no pending withdrawals in the queue
            if pending_balance_to_withdraw == 0 {
                self.initiate_validator_exit(index as u64)?;
            }
            return Ok(());
        }

        let has_sufficient_effective_balance =
            validator.effective_balance >= MIN_ACTIVATION_BALANCE;
        let balance = *self
            .balances
            .get(index)
            .ok_or(anyhow!("Failed to get balance"))?;
        let has_excess_balance = balance > MIN_ACTIVATION_BALANCE + pending_balance_to_withdraw;

        // Only allow partial withdrawals with compounding withdrawal credentials
        if validator.has_compounding_withdrawal_credential()
            && has_sufficient_effective_balance
            && has_excess_balance
        {
            let to_withdraw = min(
                balance - MIN_ACTIVATION_BALANCE - pending_balance_to_withdraw,
                amount,
            );
            let exit_queue_epoch = self.compute_exit_epoch_and_update_churn(to_withdraw);
            let withdrawable_epoch = exit_queue_epoch + MIN_VALIDATOR_WITHDRAWABILITY_DELAY;
            self.pending_partial_withdrawals
                .push(PendingPartialWithdrawal {
                    validator_index: index as u64,
                    amount: to_withdraw,
                    withdrawable_epoch,
                }).map_err(|err| anyhow!("Failed to push PendingPartialWithdrawal to pending_partial_withdrawals {err:?}"))?;
        }

        Ok(())
    }

    pub fn process_deposit_request(
        &mut self,
        deposit_request: &DepositRequest,
    ) -> anyhow::Result<()> {
        // Set deposit request start index
        if self.deposit_requests_start_index == UNSET_DEPOSIT_REQUESTS_START_INDEX {
            self.deposit_requests_start_index = deposit_request.index;
        }

        // Create pending deposit
        self.pending_deposits
            .push(PendingDeposit {
                public_key: deposit_request.public_key.clone(),
                withdrawal_credentials: deposit_request.withdrawal_credentials,
                amount: deposit_request.amount,
                signature: deposit_request.signature.clone(),
                slot: self.slot,
            })
            .map_err(|err| anyhow!("Failed to push PendingDeposit to pending_deposits {err:?}"))?;

        Ok(())
    }

    /// ``is_valid_switch_to_compounding_request`` for a request whose source validator, if any,
    /// is at ``source_index``.
    fn is_valid_switch_with_source(
        &self,
        consolidation_request: &ConsolidationRequest,
        source_index: Option<usize>,
    ) -> bool {
        // Switch to compounding requires source and target be equal
        if consolidation_request.source_public_key != consolidation_request.target_public_key {
            return false;
        }

        // Verify public_key exists
        let Some(source_validator) = source_index.map(|index| &self.validators[index]) else {
            return false;
        };

        // Verify request has been authorized
        if source_validator.withdrawal_credentials[12..] != consolidation_request.source_address {
            return false;
        }

        // Verify source withdrawal credentials
        if !source_validator.has_eth1_withdrawal_credential() {
            return false;
        }

        // Verify the source is active
        if !source_validator.is_active_validator(self.get_current_epoch()) {
            return false;
        }

        // Verify exit for source has not been initiated
        if source_validator.exit_epoch != FAR_FUTURE_EPOCH {
            return false;
        }

        true
    }

    pub fn process_consolidation_request(
        &mut self,
        consolidation_request: &ConsolidationRequest,
    ) -> anyhow::Result<()> {
        // A request with the same source and target can only switch the validator to compounding,
        // and a consolidation cannot be used as an exit.
        if consolidation_request.source_public_key == consolidation_request.target_public_key {
            let source_index = self.find_validator_index(&consolidation_request.source_public_key);
            if self.is_valid_switch_with_source(consolidation_request, source_index) {
                let Some(index) = source_index else {
                    bail!("Validator not found");
                };
                self.switch_to_compounding_validator(index as u64)?;
            }
            return Ok(());
        }

        // If the pending consolidations queue is full, consolidation requests are ignored
        if self.pending_consolidations.len() as u64 == PENDING_CONSOLIDATIONS_LIMIT {
            return Ok(());
        }

        // If there is too little available consolidation churn limit, consolidation requests are
        // ignored
        if self.get_consolidation_churn_limit() <= MIN_ACTIVATION_BALANCE {
            return Ok(());
        }

        // Both validators are found in one pass over the registry.
        let indices = self.find_validator_indices(&[
            consolidation_request.source_public_key.clone(),
            consolidation_request.target_public_key.clone(),
        ]);
        let (Some(&source_index), Some(&target_index)) = (
            indices.get(&consolidation_request.source_public_key),
            indices.get(&consolidation_request.target_public_key),
        ) else {
            return Ok(());
        };
        let source_validator = &self.validators[source_index];
        let target_validator = &self.validators[target_index];

        // Verify source withdrawal credentials
        let has_correct_credential = source_validator.has_execution_withdrawal_credential();
        let is_correct_source_address =
            source_validator.withdrawal_credentials[12..] == consolidation_request.source_address;
        if !(has_correct_credential && is_correct_source_address) {
            return Ok(());
        }

        // Verify that target has compounding withdrawal credentials
        if !target_validator.has_compounding_withdrawal_credential() {
            return Ok(());
        }

        // Verify the source and the target are active
        let current_epoch = self.get_current_epoch();
        if !source_validator.is_active_validator(current_epoch)
            || !target_validator.is_active_validator(current_epoch)
        {
            return Ok(());
        }

        // Verify exits for source and target have not been initiated
        if source_validator.exit_epoch != FAR_FUTURE_EPOCH
            || target_validator.exit_epoch != FAR_FUTURE_EPOCH
        {
            return Ok(());
        }

        // Verify the source has been active long enough
        if current_epoch < source_validator.activation_epoch + SHARD_COMMITTEE_PERIOD {
            return Ok(());
        }

        // Verify the source has no pending withdrawals in the queue
        if self.get_pending_balance_to_withdraw(source_index as u64) > 0 {
            return Ok(());
        }

        // Initiate source validator exit and append pending consolidation
        let exit_epoch =
            self.compute_consolidation_epoch_and_update_churn(source_validator.effective_balance);
        let Some(source_validator) = self.validators.get_mut(source_index) else {
            bail!("Validator not found");
        };
        source_validator.exit_epoch = exit_epoch;
        source_validator.withdrawable_epoch =
            source_validator.exit_epoch + MIN_VALIDATOR_WITHDRAWABILITY_DELAY;

        self.pending_consolidations
            .push(PendingConsolidation {
                source_index: source_index as u64,
                target_index: target_index as u64,
            })
            .map_err(|err| {
                anyhow!("Failed to push PendingConsolidation to pending_consolidations {err:?}")
            })?;

        Ok(())
    }

    pub fn get_sync_committee_indices(
        &self,
        sync_committee: &SyncCommittee,
    ) -> anyhow::Result<Vec<usize>> {
        let key = &sync_committee.aggregate_public_key;
        if let Some(indices) = self.caches.sync_committee_indices.get(key)
            && self.indices_hold_keys(&indices, sync_committee)
        {
            return Ok(indices.to_vec());
        }
        let indices = self.compute_sync_committee_indices(sync_committee)?;
        self.caches
            .sync_committee_indices
            .insert(key.clone(), Arc::new(indices.clone()));
        Ok(indices)
    }

    /// Whether each of `indices` is the registry index of the committee member at its position.
    fn indices_hold_keys(&self, indices: &[usize], sync_committee: &SyncCommittee) -> bool {
        indices.len() == sync_committee.public_keys.len()
            && indices
                .iter()
                .zip(sync_committee.public_keys.iter())
                .all(|(&index, public_key)| {
                    self.validators
                        .get(index)
                        .is_some_and(|validator| validator.public_key == *public_key)
                })
    }

    fn compute_sync_committee_indices(
        &self,
        sync_committee: &SyncCommittee,
    ) -> anyhow::Result<Vec<usize>> {
        let pubkey_to_index: HashMap<_, _> = self
            .validators
            .iter()
            .enumerate()
            .map(|(i, v)| (&v.public_key, i))
            .collect();

        let mut indices = Vec::with_capacity(sync_committee.public_keys.len());

        for pubkey in &sync_committee.public_keys {
            let index = pubkey_to_index
                .get(pubkey)
                .ok_or_else(|| anyhow!("Pubkey not found in validator set."))?;
            indices.push(*index);
        }

        Ok(indices)
    }

    pub fn get_proposer_and_participant_rewards(&self) -> (u64, u64) {
        let total_active_balance = self.get_total_active_balance();
        let total_active_increments = total_active_balance / EFFECTIVE_BALANCE_INCREMENT;
        let total_base_rewards = self.get_base_reward_per_increment() * total_active_increments;
        let max_participant_rewards =
            total_base_rewards * SYNC_REWARD_WEIGHT / WEIGHT_DENOMINATOR / SLOTS_PER_EPOCH;
        let participant_reward = max_participant_rewards / SYNC_COMMITTEE_SIZE;
        let proposer_reward =
            participant_reward * PROPOSER_WEIGHT / (WEIGHT_DENOMINATOR - PROPOSER_WEIGHT);

        (participant_reward, proposer_reward)
    }

    /// Return the sync committee indices, with possible duplicates, for the next sync committee.
    pub fn get_next_sync_committee_indices(&self) -> anyhow::Result<Vec<u64>> {
        let epoch = self.get_current_epoch() + 1;
        let active_validator_indices = self.get_active_validator_indices(epoch);
        let active_validator_count = active_validator_indices.len();
        let seed = self.get_seed(epoch, DOMAIN_SYNC_COMMITTEE);
        let mut i = 0;
        let mut sync_committee_indices: Vec<u64> = vec![];
        while sync_committee_indices.len() < SYNC_COMMITTEE_SIZE as usize {
            let shuffled_index =
                compute_shuffled_index(i % active_validator_count, active_validator_count, seed)?;
            let candidate_index = active_validator_indices[shuffled_index];

            let random_bytes = hash(&[seed.as_slice(), &(i / 16).to_le_bytes()].concat());
            let offset = i % 16 * 2;
            let random_value = bytes_to_int64(&random_bytes[offset..offset + 2]);
            let effective_balance = self.validators[candidate_index as usize].effective_balance;
            if effective_balance * MAX_RANDOM_VALUE
                >= MAX_EFFECTIVE_BALANCE_ELECTRA * random_value as u64
            {
                sync_committee_indices.push(candidate_index)
            }
            i += 1
        }

        Ok(sync_committee_indices)
    }

    /// check if the given proposer slashing is valid and returns the index of proposer to
    /// slashed
    pub fn validate_proposer_slashing(
        &self,
        proposer_slashing: &ProposerSlashing,
    ) -> anyhow::Result<u64> {
        let header_1 = &proposer_slashing.signed_header_1.message;
        let header_2 = &proposer_slashing.signed_header_2.message;

        // Verify header slots match
        ensure!(header_1.slot == header_2.slot, "Header slots must match");

        // Verify header proposer indices match
        ensure!(
            header_1.proposer_index == header_2.proposer_index,
            "Proposer indices must match"
        );

        // Verify the headers are different
        ensure!(header_1 != header_2, "Headers must be different");

        // Get the proposer and verify they are slashable
        let proposer_index = header_1.proposer_index;
        let proposer = self
            .validators
            .get(proposer_index as usize)
            .ok_or_else(|| anyhow!("Invalid proposer index"))?;

        ensure!(
            proposer.is_slashable_validator(self.get_current_epoch()),
            "Proposer is not slashable"
        );

        // Verify signatures
        for signed_header in [
            &proposer_slashing.signed_header_1,
            &proposer_slashing.signed_header_2,
        ] {
            let domain = self.get_domain(
                DOMAIN_BEACON_PROPOSER,
                Some(compute_epoch_at_slot(signed_header.message.slot)),
            );

            let signing_root = compute_signing_root(&signed_header.message, domain);

            ensure!(
                signed_header
                    .signature
                    .verify(&proposer.public_key, signing_root.as_ref())?,
                "BLS Signature verification failed!"
            );
        }

        Ok(proposer_index)
    }

    pub fn process_proposer_slashing(
        &mut self,
        proposer_slashing: &ProposerSlashing,
    ) -> anyhow::Result<()> {
        let proposer_index = self.validate_proposer_slashing(proposer_slashing)?;
        // Slash the validator
        self.slash_validator(proposer_index, None)
    }

    pub fn process_historical_summaries_update(&mut self) -> anyhow::Result<()> {
        // Set historical block root accumulator.
        let next_epoch = self.get_current_epoch() + 1;
        if next_epoch.is_multiple_of(SLOTS_PER_HISTORICAL_ROOT / SLOTS_PER_EPOCH) {
            let historical_summary = HistoricalSummary {
                block_summary_root: self.block_roots.tree_hash_root(),
                state_summary_root: self.state_roots.tree_hash_root(),
            };
            self.historical_summaries
                .push(historical_summary)
                .map_err(|err| anyhow!("Failed to push historical summary: {err:?}"))?;
        }

        Ok(())
    }

    pub fn get_slashable_attester_indices(
        &self,
        attester_shashing: &AttesterSlashing,
    ) -> anyhow::Result<(HashSet<u64>, HashSet<u64>)> {
        let attestation_1 = &attester_shashing.attestation_1;
        let attestation_2 = &attester_shashing.attestation_2;

        // Ensure the two attestations are slashable
        ensure!(
            is_slashable_attestation_data(&attestation_1.data, &attestation_2.data),
            "Attestations are not slashable"
        );

        // Validate both attestations
        ensure!(
            self.is_valid_indexed_attestation(attestation_1)?,
            "First attestation is invalid"
        );
        ensure!(
            self.is_valid_indexed_attestation(attestation_2)?,
            "Second attestation is invalid"
        );

        let attestation_indices_1 = attestation_1
            .attesting_indices
            .iter()
            .cloned()
            .collect::<HashSet<_>>();
        let attestation_indices_2 = attestation_2
            .attesting_indices
            .iter()
            .cloned()
            .collect::<HashSet<_>>();

        Ok((attestation_indices_1, attestation_indices_2))
    }

    pub fn process_attester_slashing(
        &mut self,
        attester_slashing: &AttesterSlashing,
    ) -> anyhow::Result<()> {
        let (indices_1, indices_2) = self.get_slashable_attester_indices(attester_slashing)?;
        let current_epoch = self.get_current_epoch();
        let mut slashed_any = false;

        // Find common attesting indices and process slashing
        for &index in indices_1.intersection(&indices_2).sorted() {
            if self.validators[index as usize].is_slashable_validator(current_epoch) {
                self.slash_validator(index, None)?;
                slashed_any = true;
            }
        }

        ensure!(slashed_any, "No validator was slashed");

        Ok(())
    }

    fn calculate_sync_committee_balance_change(
        committee_indices: &[usize],
        sync_committee_bits: impl Iterator<Item = bool>,
        participant_reward: u64,
    ) -> Vec<(u64, i64, bool)> {
        let mut changes = Vec::new();

        for (validator_index, participation_bit) in
            committee_indices.iter().zip(sync_committee_bits)
        {
            let validator_index = *validator_index as u64;

            if participation_bit {
                changes.push((validator_index, participant_reward as i64, true));
            } else {
                changes.push((validator_index, -(participant_reward as i64), false));
            }
        }
        changes
    }

    pub fn process_sync_aggregate(&mut self, sync_aggregate: &SyncAggregate) -> anyhow::Result<()> {
        self.process_sync_aggregate_with(sync_aggregate, true)
    }

    fn process_sync_aggregate_with(
        &mut self,
        sync_aggregate: &SyncAggregate,
        verify_signatures: bool,
    ) -> anyhow::Result<()> {
        if verify_signatures {
            let committee_public_keys = &self.current_sync_committee.public_keys;
            let mut participant_public_keys = vec![];

            for (public_key, bit) in committee_public_keys
                .iter()
                .zip(sync_aggregate.sync_committee_bits.iter())
            {
                if bit {
                    participant_public_keys.push(public_key);
                }
            }

            let previous_slot = max(self.slot, 1) - 1;
            let domain = self.get_domain(
                DOMAIN_SYNC_COMMITTEE,
                Some(compute_epoch_at_slot(previous_slot)),
            );
            let signing_root =
                compute_signing_root(self.get_block_root_at_slot(previous_slot)?, domain);

            ensure!(
                eth_fast_aggregate_verify(
                    &participant_public_keys,
                    signing_root,
                    &sync_aggregate.sync_committee_signature,
                )?,
                "Sync aggregate signature verification failed."
            );
        }

        let committee_indices = self.get_sync_committee_indices(&self.current_sync_committee)?;
        let (participant_reward, proposer_reward) = self.get_proposer_and_participant_rewards();
        let proposer_index = self.get_beacon_proposer_index(None)?;

        let changes = Self::calculate_sync_committee_balance_change(
            &committee_indices,
            sync_aggregate.sync_committee_bits.iter(),
            participant_reward,
        );

        for (validator_index, change, is_participant) in changes {
            if change > 0 {
                self.increase_balance(validator_index, change as u64)?;
            } else {
                self.decrease_balance(validator_index, change.unsigned_abs())?;
            }

            if is_participant {
                self.increase_balance(proposer_index, proposer_reward)?;
            }
        }
        Ok(())
    }

    pub fn compute_sync_committee_rewards(
        &self,
        beacon_block: &SignedBeaconBlock,
    ) -> anyhow::Result<HashMap<u64, u64>> {
        let sync_aggregate = &beacon_block.message.body.sync_aggregate;
        let sync_committee = &self.current_sync_committee;

        let sync_committee_indices = self.get_sync_committee_indices(sync_committee)?;
        let (participant_reward, proposer_reward) = self.get_proposer_and_participant_rewards();
        let proposer_index = beacon_block.message.proposer_index as usize;

        let mut balances = HashMap::<usize, u64>::new();

        for validator_index in &sync_committee_indices {
            balances.insert(
                *validator_index,
                *self
                    .balances
                    .get(*validator_index)
                    .ok_or(anyhow!("Sync Committee Rewards Sync Error"))?,
            );
        }

        balances.insert(
            proposer_index,
            *self
                .balances
                .get(proposer_index)
                .ok_or(anyhow!("Sync Committee Rewards Sync Error"))?,
        );

        let changes = Self::calculate_sync_committee_balance_change(
            &sync_committee_indices,
            sync_aggregate.sync_committee_bits.iter(),
            participant_reward,
        );

        let mut total_proposer_reward = 0u64;
        for (validator_index, change, is_participant) in changes {
            let participant_balance = balances
                .get_mut(&(validator_index as usize))
                .ok_or(anyhow!("Sync Committee Rewards Sync Error"))?;

            if change > 0 {
                *participant_balance += change as u64;
            } else {
                *participant_balance = participant_balance.saturating_sub(change.unsigned_abs());
            }

            if is_participant {
                total_proposer_reward += proposer_reward;
            }
        }

        *balances
            .get_mut(&proposer_index)
            .ok_or(anyhow!("Sync Committee Rewards Sync Error"))? += total_proposer_reward;

        let rewards: HashMap<u64, u64> = balances
            .iter()
            .filter_map(|(&index, &new_balance)| {
                let initial_balance = *self.balances.get(index)? as i64;
                let reward = new_balance as i64 - initial_balance;

                if reward > 0 {
                    Some((index as u64, reward as u64))
                } else {
                    None
                }
            })
            .collect();

        Ok(rewards)
    }

    pub fn process_justification_and_finalization(&mut self) -> anyhow::Result<()> {
        let outcome = self.compute_justification_and_finalization()?;
        self.apply_justification_and_finalization(outcome);
        Ok(())
    }

    /// The justification bits and checkpoints that ``process_justification_and_finalization``
    /// would produce, leaving the state unchanged. Fork choice pulls up every imported block's
    /// checkpoints this way.
    pub fn compute_justification_and_finalization(
        &self,
    ) -> anyhow::Result<JustificationAndFinalization> {
        // Initial FFG checkpoint values have a `0x00` stub for `root`.
        // Skip FFG updates in the first two epochs to avoid corner cases that might result in
        // modifying this stub.
        if self.get_current_epoch() <= GENESIS_EPOCH + 1 {
            return Ok(self.current_justification());
        }

        let total_active_balance = self.get_total_active_balance();
        let (previous_target_balance, current_target_balance) =
            self.get_unslashed_participating_balances(TIMELY_TARGET_FLAG_INDEX);

        self.justification_outcome(
            total_active_balance,
            previous_target_balance,
            current_target_balance,
        )
    }

    pub fn weigh_justification_and_finalization(
        &mut self,
        total_active_balance: u64,
        previous_epoch_target_balance: u64,
        current_epoch_target_balance: u64,
    ) -> anyhow::Result<()> {
        let outcome = self.justification_outcome(
            total_active_balance,
            previous_epoch_target_balance,
            current_epoch_target_balance,
        )?;
        self.apply_justification_and_finalization(outcome);
        Ok(())
    }

    fn current_justification(&self) -> JustificationAndFinalization {
        JustificationAndFinalization {
            justification_bits: self.justification_bits.clone(),
            previous_justified_checkpoint: self.previous_justified_checkpoint,
            current_justified_checkpoint: self.current_justified_checkpoint,
            finalized_checkpoint: self.finalized_checkpoint,
        }
    }

    fn apply_justification_and_finalization(&mut self, outcome: JustificationAndFinalization) {
        self.justification_bits = outcome.justification_bits;
        self.previous_justified_checkpoint = outcome.previous_justified_checkpoint;
        self.current_justified_checkpoint = outcome.current_justified_checkpoint;
        self.finalized_checkpoint = outcome.finalized_checkpoint;
    }

    /// ``weigh_justification_and_finalization`` computed into a new value instead of the state.
    fn justification_outcome(
        &self,
        total_active_balance: u64,
        previous_epoch_target_balance: u64,
        current_epoch_target_balance: u64,
    ) -> anyhow::Result<JustificationAndFinalization> {
        let previous_epoch = self.get_previous_epoch();
        let current_epoch = self.get_current_epoch();
        let old_previous_justified_checkpoint = self.previous_justified_checkpoint;
        let old_current_justified_checkpoint = self.current_justified_checkpoint;
        let mut outcome = self.current_justification();

        outcome.previous_justified_checkpoint = self.current_justified_checkpoint;

        for i in (1..JUSTIFICATION_BITS_LENGTH).rev() {
            let bit = outcome
                .justification_bits
                .get(i - 1)
                .map_err(|err| anyhow!("Failed to get justification bit {err:?}"))?;
            outcome
                .justification_bits
                .set(i, bit)
                .map_err(|err| anyhow!("Failed to set justification bit {err:?}"))?;
        }

        outcome
            .justification_bits
            .set(0, false)
            .map_err(|err| anyhow!("Failed to set justification bit 0: {err:?}"))?;

        if previous_epoch_target_balance * 3 >= total_active_balance * 2 {
            outcome.current_justified_checkpoint = Checkpoint {
                epoch: previous_epoch,
                root: self.get_block_root(previous_epoch)?,
            };
            outcome
                .justification_bits
                .set(1, true)
                .map_err(|err| anyhow!("Failed to set justification bit 1: {err:?}"))?;
        }

        if current_epoch_target_balance * 3 >= total_active_balance * 2 {
            outcome.current_justified_checkpoint = Checkpoint {
                epoch: current_epoch,
                root: self.get_block_root(current_epoch)?,
            };
            outcome
                .justification_bits
                .set(0, true)
                .map_err(|err| anyhow!("Failed to set justification bit 0: {err:?}"))?;
        }

        // Process finalizations
        let bits: Vec<bool> = outcome.justification_bits.iter().collect();

        // The 2nd/3rd/4th most recent epochs are justified, the 2nd using the 4th as source
        if bits[1..4].iter().all(|&b| b)
            && old_previous_justified_checkpoint.epoch + 3 == current_epoch
        {
            outcome.finalized_checkpoint = old_previous_justified_checkpoint;
        }

        // The 2nd/3rd most recent epochs are justified, the 2nd using the 3rd as source
        if bits[1..3].iter().all(|&b| b)
            && old_previous_justified_checkpoint.epoch + 2 == current_epoch
        {
            outcome.finalized_checkpoint = old_previous_justified_checkpoint;
        }

        // The 1st/2nd/3rd most recent epochs are justified, the 1st using the 3rd as source
        if bits[0..3].iter().all(|&b| b)
            && old_current_justified_checkpoint.epoch + 2 == current_epoch
        {
            outcome.finalized_checkpoint = old_current_justified_checkpoint;
        }

        // The 1st/2nd most recent epochs are justified, the 1st using the 2nd as source
        if bits[0..2].iter().all(|&b| b)
            && old_current_justified_checkpoint.epoch + 1 == current_epoch
        {
            outcome.finalized_checkpoint = old_current_justified_checkpoint;
        }

        Ok(outcome)
    }

    pub fn process_eth1_data_reset(&mut self) -> anyhow::Result<()> {
        let next_epoch = self.get_current_epoch() + 1;

        // Reset eth1 data votes
        if next_epoch.is_multiple_of(EPOCHS_PER_ETH1_VOTING_PERIOD) {
            self.eth1_data_votes = VariableList::default();
        }

        Ok(())
    }

    pub fn process_effective_balance_updates(&mut self) -> anyhow::Result<()> {
        // Update effective balances with hysteresis. Only the validators that cross a threshold
        // are written: writing every validator would copy every registry chunk.
        let hysteresis_increment = EFFECTIVE_BALANCE_INCREMENT / HYSTERESIS_QUOTIENT;
        let downward_threshold = hysteresis_increment * HYSTERESIS_DOWNWARD_MULTIPLIER;
        let upward_threshold = hysteresis_increment * HYSTERESIS_UPWARD_MULTIPLIER;
        let updates: Vec<(usize, u64)> = self
            .validators
            .iter()
            .zip(self.balances.iter())
            .enumerate()
            .filter(|(_, (validator, balance))| {
                **balance + downward_threshold < validator.effective_balance
                    || validator.effective_balance + upward_threshold < **balance
            })
            .map(|(index, (validator, balance))| {
                (
                    index,
                    (balance - balance % EFFECTIVE_BALANCE_INCREMENT)
                        .min(validator.get_max_effective_balance()),
                )
            })
            .collect();
        for (index, effective_balance) in updates {
            self.validators[index].effective_balance = effective_balance;
        }
        // The total active balance of this epoch was summed over the old effective balances.
        self.caches.total_active_balance.clear();

        Ok(())
    }

    pub fn process_randao(&mut self, body: &BeaconBlockBody) -> anyhow::Result<()> {
        self.process_randao_inner(body, true)
    }

    fn process_randao_inner(
        &mut self,
        body: &BeaconBlockBody,
        verify_signature: bool,
    ) -> anyhow::Result<()> {
        let epoch = self.get_current_epoch();

        // Verify RANDAO reveal
        if let Some(proposer) = self
            .validators
            .get(self.get_beacon_proposer_index(None)? as usize)
        {
            if verify_signature {
                let signing_root =
                    compute_signing_root(epoch, self.get_domain(DOMAIN_RANDAO, Some(epoch)));
                ensure!(
                    body.randao_reveal
                        .verify(&proposer.public_key, signing_root.as_ref())?,
                    "BLS Signature verification failed!"
                );
            }

            // Mix in RANDAO reveal
            let mix = xor(
                self.get_randao_mix(epoch).as_slice(),
                hash(body.randao_reveal.to_slice()).as_slice(),
            );
            self.randao_mixes[(epoch % EPOCHS_PER_HISTORICAL_VECTOR) as usize] = mix;
        }

        Ok(())
    }

    pub fn process_eth1_data(&mut self, body: &BeaconBlockBody) -> anyhow::Result<()> {
        self.eth1_data_votes
            .push(body.eth1_data.clone())
            .map_err(|err| anyhow!("Can't push eth1_data {err:?}"))?;

        let count = self
            .eth1_data_votes
            .iter()
            .filter(|data| **data == body.eth1_data)
            .count() as u64;

        if count * 2 > (EPOCHS_PER_ETH1_VOTING_PERIOD * SLOTS_PER_EPOCH) {
            self.eth1_data = body.eth1_data.clone();
        }

        Ok(())
    }

    pub fn process_attestation(&mut self, attestation: &Attestation) -> anyhow::Result<()> {
        self.process_attestation_with(attestation, true)
    }

    fn process_attestation_with(
        &mut self,
        attestation: &Attestation,
        verify_signatures: bool,
    ) -> anyhow::Result<()> {
        let data = &attestation.data;
        ensure!(
            data.target.epoch == self.get_previous_epoch()
                || data.target.epoch == self.get_current_epoch(),
            "Target epoch must be the previous or current epoch"
        );

        ensure!(
            data.target.epoch == compute_epoch_at_slot(data.slot),
            "Target epoch must match the computed epoch at slot"
        );

        ensure!(
            data.slot + MIN_ATTESTATION_INCLUSION_DELAY <= self.slot,
            "Attestation must be included after the minimum delay"
        );

        ensure!(
            data.index < self.get_committee_count_per_slot(data.target.epoch),
            "Committee index must be within bounds"
        );

        ensure!(data.index == 0);
        let committee_indices = get_committee_indices(&attestation.committee_bits);
        let mut committee_offset = 0;
        for committee_index in committee_indices {
            ensure!(committee_index < self.get_committee_count_per_slot(data.target.epoch));
            let committee = self.get_beacon_committee(data.slot, committee_index)?;
            let mut has_attester = false;
            for i in 0..committee.len() {
                has_attester |= attestation
                    .aggregation_bits
                    .get(committee_offset + i)
                    .map_err(|err| anyhow!("Failed to get aggregation bit {err:?}"))?;
            }
            ensure!(has_attester, "Committee attesters must not be empty");
            committee_offset += committee.len();
        }
        // Bitfield length matches total number of participants
        ensure!(
            attestation.aggregation_bits.len() == committee_offset,
            "Aggregation bits length must match committee size {} != {committee_offset}",
            attestation.aggregation_bits.len(),
        );

        // Participation flag indices
        let participation_flag_indices =
            self.get_attestation_participation_flag_indices(data, self.slot - data.slot)?;
        // Verify signature. The indexed attestation holds the attesting indices, so it also
        // drives the participation updates below.
        let indexed_attestation = self.get_indexed_attestation(attestation)?;
        ensure!(
            !verify_signatures || self.is_valid_indexed_attestation(&indexed_attestation)?,
            "Attestation signature must be valid"
        );

        let is_current = data.target.epoch == self.get_current_epoch();
        let mut participation = if is_current {
            std::mem::take(&mut self.current_epoch_participation)
        } else {
            std::mem::take(&mut self.previous_epoch_participation)
        };
        let proposer_reward = self.mark_participation(
            &mut participation,
            indexed_attestation.attesting_indices.iter().copied(),
            &participation_flag_indices,
        );
        if is_current {
            self.current_epoch_participation = participation;
        } else {
            self.previous_epoch_participation = participation;
        }
        self.increase_balance(self.get_beacon_proposer_index(None)?, proposer_reward?)?;
        Ok(())
    }

    /// Sets `flag_indices` for `attesting_indices` and returns the proposer reward for the flags
    /// that were not set yet.
    fn mark_participation(
        &self,
        participation: &mut VariableList<u8, ValidatorRegistryLimit>,
        attesting_indices: impl Iterator<Item = u64>,
        flag_indices: &[u8],
    ) -> anyhow::Result<u64> {
        let base_reward_per_increment = self.get_base_reward_per_increment();
        let mut proposer_reward_numerator = 0;
        for index in attesting_indices {
            let epoch_part = participation.get_mut(index as usize).ok_or_else(|| {
                anyhow!("Validator index {index} out of bounds in epoch_participation")
            })?;
            for (flag_index, &weight) in PARTICIPATION_FLAG_WEIGHTS.iter().enumerate() {
                let flag_index = flag_index as u8;
                if flag_indices.contains(&flag_index) && !Self::has_flag(*epoch_part, flag_index) {
                    *epoch_part = Self::add_flag(*epoch_part, flag_index);
                    proposer_reward_numerator +=
                        self.get_base_reward(index, base_reward_per_increment) * weight;
                }
            }
        }
        let proposer_reward_denominator =
            (WEIGHT_DENOMINATOR - PROPOSER_WEIGHT) * WEIGHT_DENOMINATOR / PROPOSER_WEIGHT;
        Ok(proposer_reward_numerator / proposer_reward_denominator)
    }

    /// What including `attestations` pays the proposer, on the block's pre-state.
    pub fn attestations_proposer_reward(
        &self,
        attestations: &[Attestation],
    ) -> anyhow::Result<u64> {
        let mut current = self.current_epoch_participation.clone();
        let mut previous = self.previous_epoch_participation.clone();
        let mut reward = 0;
        for attestation in attestations {
            let data = &attestation.data;
            let flag_indices = self.get_attestation_participation_flag_indices(
                data,
                self.slot.saturating_sub(data.slot),
            )?;
            let participation = if data.target.epoch == self.get_current_epoch() {
                &mut current
            } else {
                &mut previous
            };
            let attesting_indices = self.get_attesting_indices(attestation)?;
            reward += self.mark_participation(
                participation,
                attesting_indices.into_iter(),
                &flag_indices,
            )?;
        }
        Ok(reward)
    }

    pub fn process_randao_mixes_reset(&mut self) -> anyhow::Result<()> {
        let current_epoch = self.get_current_epoch();
        let next_epoch = current_epoch + 1;
        // Set randao mix
        self.randao_mixes[(next_epoch % EPOCHS_PER_HISTORICAL_VECTOR) as usize] =
            self.get_randao_mix(current_epoch);

        Ok(())
    }

    pub fn process_slashings_reset(&mut self) -> anyhow::Result<()> {
        let next_epoch = self.get_current_epoch() + 1;
        // Reset slashings
        self.slashings[(next_epoch % EPOCHS_PER_SLASHINGS_VECTOR) as usize] = 0;

        Ok(())
    }

    pub fn process_slashings(&mut self) -> anyhow::Result<()> {
        let epoch = self.get_current_epoch();
        let total_balance = self.get_total_active_balance();
        let adjusted_total_slashing_balance = (self.slashings.iter().sum::<u64>()
            * PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX)
            .min(total_balance);

        // Factored out from penalty numerator to avoid uint64 overflow
        let increment = EFFECTIVE_BALANCE_INCREMENT;
        let penalty_per_effective_balance_increment =
            adjusted_total_slashing_balance / (total_balance / increment);
        for index in 0..self.validators.len() {
            let validator = &self
                .validators
                .get(index)
                .ok_or_else(|| anyhow!("Invalid validator index: {index}"))?;
            if validator.slashed
                && epoch + EPOCHS_PER_SLASHINGS_VECTOR / 2 == validator.withdrawable_epoch
            {
                let effective_balance_increments = validator.effective_balance / increment;
                let penalty =
                    penalty_per_effective_balance_increment * effective_balance_increments;

                self.decrease_balance(index as u64, penalty)?;
            }
        }

        Ok(())
    }

    /// Applies ``deposit`` to the ``state``.
    pub fn apply_pending_deposit(&mut self, deposit: &PendingDeposit) -> anyhow::Result<()> {
        let validator_index = self.find_validator_index(&deposit.public_key);
        self.apply_pending_deposit_to(deposit, validator_index)?;
        Ok(())
    }

    /// ``apply_pending_deposit`` for a deposit whose validator, if it has one, is at
    /// ``validator_index``. Returns the index of the validator it added, if any.
    fn apply_pending_deposit_to(
        &mut self,
        deposit: &PendingDeposit,
        validator_index: Option<usize>,
    ) -> anyhow::Result<Option<usize>> {
        if let Some(index) = validator_index {
            self.increase_balance(index as u64, deposit.amount)?;
            return Ok(None);
        }
        // Verify the deposit signature (proof of possession) which is not checked by the
        // deposit contract
        if !is_valid_deposit_signature(
            &deposit.public_key,
            deposit.withdrawal_credentials,
            deposit.amount,
            &deposit.signature,
        )
        .unwrap_or_default()
        {
            return Ok(None);
        }
        self.add_validator_to_registry(
            deposit.public_key.clone(),
            deposit.withdrawal_credentials,
            deposit.amount,
        )?;
        Ok(Some(self.validators.len() - 1))
    }

    /// Registry index of the first validator with ``public_key``.
    pub fn find_validator_index(&self, public_key: &PublicKey) -> Option<usize> {
        self.find_validator_indices(slice::from_ref(public_key))
            .remove(public_key)
    }

    /// Registry indices of ``public_keys``, found in one pass over the registry split across
    /// cores. A key held by more than one validator maps to the first, as a search from the start
    /// finds. Each key's first 8 bytes are compared as one integer before all 48.
    fn find_validator_indices(&self, public_keys: &[PublicKey]) -> HashMap<PublicKey, usize> {
        if public_keys.is_empty() {
            return HashMap::new();
        }
        let prefixes: Vec<u64> = public_keys.iter().map(public_key_prefix).collect();
        let chunks = self.validators.chunks();
        // Matches in one registry chunk, in ascending order of index.
        let scan_chunk = |&chunk: &usize| {
            chunks[chunk]
                .iter()
                .enumerate()
                .filter(|(_, validator)| {
                    prefixes.contains(&public_key_prefix(&validator.public_key))
                        && public_keys.contains(&validator.public_key)
                })
                .map(|(offset, validator)| (chunk * CHUNK_SIZE + offset, &validator.public_key))
                .collect::<Vec<_>>()
        };
        let chunk_indices: Vec<usize> = (0..chunks.len()).collect();
        let matches = parallel_map(&chunk_indices, 2, scan_chunk)
            .into_iter()
            .flatten();
        let mut indices = HashMap::new();
        for (index, public_key) in matches {
            indices.entry(public_key.clone()).or_insert(index);
        }
        indices
    }

    pub fn process_pending_deposits(&mut self) -> anyhow::Result<()> {
        let next_epoch = self.get_current_epoch() + 1;
        let available_for_processing =
            self.deposit_balance_to_consume + self.get_activation_exit_churn_limit();
        let mut processed_amount = 0;
        let mut next_deposit_index = 0;
        let mut deposits_to_postpone = vec![];
        let mut is_churn_limit_reached = false;
        let finalized_slot = compute_start_slot_at_epoch(self.finalized_checkpoint.epoch);
        // Fulu removes support for the former Eth1 bridge deposit transition. The network spec is
        // read last, only when it matters.
        let is_bridge_pending = !self.pending_deposits.is_empty()
            && self.eth1_deposit_index < self.deposit_requests_start_index
            && self.get_current_epoch() < beacon_network_spec().fulu_fork_epoch;
        // Processing stops at the first deposit that is not finalized, or, while Eth1 bridge
        // deposits are pending, at the first deposit request.
        let stops_at = |deposit: &PendingDeposit| {
            (is_bridge_pending && deposit.slot > GENESIS_SLOT) || deposit.slot > finalized_slot
        };
        // At most MAX_PENDING_DEPOSITS_PER_EPOCH deposits before the first stop are processed, so
        // their validators are looked up together in one registry pass.
        let batch: Vec<PublicKey> = self
            .pending_deposits
            .iter()
            .take_while(|deposit| !stops_at(deposit))
            .take(MAX_PENDING_DEPOSITS_PER_EPOCH as usize)
            .map(|deposit| deposit.public_key.clone())
            .collect();
        let mut validator_indices = self.find_validator_indices(&batch);

        for index in 0..self.pending_deposits.len() {
            let Some(deposit) = self.pending_deposits.get(index).cloned() else {
                bail!("Pending deposit not found");
            };
            if stops_at(&deposit) {
                break;
            }

            // Check if number of processed deposits has not reached the limit, otherwise, stop
            // processing.
            if next_deposit_index >= MAX_PENDING_DEPOSITS_PER_EPOCH {
                break;
            }

            // Read validator state
            let validator_index = validator_indices.get(&deposit.public_key).copied();
            let (is_validator_exited, is_validator_withdrawn) =
                match validator_index.and_then(|index| self.validators.get(index)) {
                    Some(validator) => (
                        validator.exit_epoch < FAR_FUTURE_EPOCH,
                        validator.withdrawable_epoch < next_epoch,
                    ),
                    None => (false, false),
                };

            if is_validator_withdrawn {
                // Deposited balance will never become active. Increase balance but do not consume
                // churn
                self.apply_pending_deposit_to(&deposit, validator_index)?;
            } else if is_validator_exited {
                // Validator is exiting, postpone the deposit until after withdrawable epoch
                deposits_to_postpone.push(deposit.clone());
            } else {
                // Check if deposit fits in the churn, otherwise, do no more deposit processing in
                // this epoch.
                is_churn_limit_reached =
                    processed_amount + deposit.amount > available_for_processing;
                if is_churn_limit_reached {
                    break;
                }

                // Consume churn and apply deposit.
                processed_amount += deposit.amount;
                if let Some(added) = self.apply_pending_deposit_to(&deposit, validator_index)? {
                    validator_indices.insert(deposit.public_key.clone(), added);
                }
            }

            // Regardless of how the deposit was handled, we move on in the queue.
            next_deposit_index += 1;
        }

        let remaining_deposits = Vec::from(take(&mut self.pending_deposits));
        for deposit in remaining_deposits
            .into_iter()
            .skip(next_deposit_index as usize)
            .chain(deposits_to_postpone)
        {
            self.pending_deposits
                .push(deposit)
                .map_err(|err| anyhow!("Failed to push deposit to pending deposits: {err:?}"))?;
        }

        // Accumulate churn only if the churn limit has been hit.
        self.deposit_balance_to_consume = if is_churn_limit_reached {
            available_for_processing - processed_amount
        } else {
            0
        };

        Ok(())
    }

    pub fn process_pending_consolidations(&mut self) -> anyhow::Result<()> {
        let next_epoch = self.get_current_epoch() + 1;
        let mut next_pending_consolidation = 0;
        for index in 0..self.pending_consolidations.len() {
            let Some(pending_consolidation) = self.pending_consolidations.get(index).cloned()
            else {
                bail!("Pending consolidation not found");
            };
            let Some(source_validator) = self
                .validators
                .get(pending_consolidation.source_index as usize)
            else {
                return Err(anyhow!("Validator not found"));
            };

            if source_validator.slashed {
                next_pending_consolidation += 1;
                continue;
            }
            if source_validator.withdrawable_epoch > next_epoch {
                break;
            }

            // Calculate the consolidated balance
            let source_effective_balance = min(
                *self
                    .balances
                    .get(pending_consolidation.source_index as usize)
                    .ok_or(anyhow!("Failed to get balance"))?,
                source_validator.effective_balance,
            );

            // Move active balance to target. Excess balance is withdrawable.
            self.decrease_balance(pending_consolidation.source_index, source_effective_balance)?;
            self.increase_balance(pending_consolidation.target_index, source_effective_balance)?;
            next_pending_consolidation += 1;
        }

        let remaining_consolidations = Vec::from(take(&mut self.pending_consolidations));
        for pending_consolidation in remaining_consolidations
            .into_iter()
            .skip(next_pending_consolidation)
        {
            self.pending_consolidations
                .push(pending_consolidation)
                .map_err(|err| anyhow!("Failed to push pending_consolidation: {err:?}"))?;
        }

        Ok(())
    }

    pub fn process_operations(&mut self, body: &BeaconBlockBody) -> anyhow::Result<()> {
        self.process_operations_with(body, true)
    }

    fn process_operations_with(
        &mut self,
        body: &BeaconBlockBody,
        verify_signatures: bool,
    ) -> anyhow::Result<()> {
        // Disable former deposit mechanism once all prior deposits are processed
        let eth1_deposit_index_limit = min(
            self.eth1_data.deposit_count,
            self.deposit_requests_start_index,
        );
        if self.eth1_deposit_index < eth1_deposit_index_limit {
            ensure!(
                body.deposits.len() as u64
                    == MAX_DEPOSITS.min(eth1_deposit_index_limit - self.eth1_deposit_index,),
            );
        } else {
            ensure!(body.deposits.is_empty());
        }

        for proposer_slashing in body.proposer_slashings.iter() {
            self.process_proposer_slashing(proposer_slashing)?;
        }
        for attester_slashing in body.attester_slashings.iter() {
            self.process_attester_slashing(attester_slashing)?;
        }
        for attestation in body.attestations.iter() {
            self.process_attestation_with(attestation, verify_signatures)?;
        }
        for deposit in body.deposits.iter() {
            self.process_deposit(deposit)?;
        }
        for voluntary_exit in body.voluntary_exits.iter() {
            self.process_voluntary_exit(voluntary_exit)?;
        }
        for bls_to_execution_change in body.bls_to_execution_changes.iter() {
            self.process_bls_to_execution_change(bls_to_execution_change)?;
        }
        for deposit in body.execution_requests.deposits.iter() {
            self.process_deposit_request(deposit)?;
        }
        for withdrawal in body.execution_requests.withdrawals.iter() {
            self.process_withdrawal_request(withdrawal)?;
        }
        for consolidation in body.execution_requests.consolidations.iter() {
            self.process_consolidation_request(consolidation)?;
        }

        Ok(())
    }

    pub fn verify_block_header_signature(
        &self,
        signed_block: &SignedBeaconBlockHeader,
    ) -> anyhow::Result<bool> {
        let proposer = self
            .validators
            .get(signed_block.message.proposer_index as usize)
            .ok_or(anyhow!("Invalid block proposer index"))?;
        let signing_root = compute_signing_root(
            signed_block.message.clone(),
            self.get_domain(
                DOMAIN_BEACON_PROPOSER,
                Some(compute_epoch_at_slot(signed_block.message.slot)),
            ),
        );

        signed_block
            .signature
            .verify(&proposer.public_key, signing_root.as_ref())
            .map_err(|err| anyhow!("Invalid block signature: {err}"))
    }

    /// Check if ``validator`` is eligible for activation.
    pub fn is_eligible_for_activation(
        finalized_checkpoint_epoch: u64,
        validator: &Validator,
    ) -> bool {
        // Placement in queue is finalized
        validator.activation_eligibility_epoch <= finalized_checkpoint_epoch
            && validator.activation_epoch == FAR_FUTURE_EPOCH
    }

    /// Return the validator activation churn limit for the current epoch.
    pub fn get_validator_activation_churn_limit(&self) -> u64 {
        min(
            MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT,
            self.get_validator_churn_limit(),
        )
    }

    pub fn process_registry_updates(&mut self) -> anyhow::Result<()> {
        let current_epoch = self.get_current_epoch();
        let activation_epoch = compute_activation_exit_epoch(current_epoch);

        // Process activation eligibility, ejections, and activations. Each validator's update
        // depends only on itself, so the registry is read first and only the validators that
        // change are written: writing every validator would copy every registry chunk.
        let eligibility_epoch = current_epoch
            .checked_add(1)
            .ok_or_else(|| anyhow!("Epoch overflow when setting activation eligibility epoch"))?;
        let mut initiate_validator = vec![];
        let mut queued = vec![];
        let mut activated = vec![];
        let finalized_checkpoint_epoch = self.finalized_checkpoint.epoch;
        for (index, validator) in self.validators.iter().enumerate() {
            if validator.is_eligible_for_activation_queue() {
                queued.push(index);
            } else if validator.is_active_validator(current_epoch)
                && validator.effective_balance <= EJECTION_BALANCE
            {
                initiate_validator.push(index as u64);
            } else if Self::is_eligible_for_activation(finalized_checkpoint_epoch, validator) {
                activated.push(index);
            }
        }
        for index in queued {
            self.validators[index].activation_eligibility_epoch = eligibility_epoch;
        }
        for index in activated {
            self.validators[index].activation_epoch = activation_epoch;
        }

        for index in initiate_validator {
            self.initiate_validator_exit(index)?;
        }

        Ok(())
    }

    /// Return the deltas for a given ``flag_index`` by scanning through the participation flags.
    pub fn get_flag_index_deltas(&self, flag_index: u8) -> anyhow::Result<(Vec<u64>, Vec<u64>)> {
        let mut rewards = vec![0; self.validators.len()];
        let mut penalties = vec![0; self.validators.len()];
        let epoch_rewards = self.epoch_rewards()?;
        for index in self.get_eligible_validator_indices()? {
            let (reward, penalty) =
                self.flag_index_delta(&epoch_rewards, index as usize, flag_index as usize);
            rewards[index as usize] += reward;
            penalties[index as usize] += penalty;
        }

        Ok((rewards, penalties))
    }

    pub fn process_rewards_and_penalties(&mut self) -> anyhow::Result<()> {
        // No rewards are applied at the end of `GENESIS_EPOCH` because rewards are for work done in
        // the previous epoch
        if self.get_current_epoch() == GENESIS_EPOCH {
            return Ok(());
        }
        ensure!(
            self.balances.len() >= self.validators.len(),
            "failed to apply rewards and penalties: fewer balances than validators"
        );

        // The deltas of ``get_flag_index_deltas`` for each flag and then of
        // ``get_inactivity_penalty_deltas``, applied one validator at a time. They depend on
        // effective balances, participation and inactivity scores, never on balances, so the
        // result is the same as applying each registry-sized list in turn.
        let epoch_rewards = self.epoch_rewards()?;
        let previous_epoch = self.get_previous_epoch();
        for index in 0..self.validators.len() {
            if !is_eligible_for_rewards(&self.validators[index], previous_epoch) {
                continue;
            }
            for flag_index in 0..PARTICIPATION_FLAG_WEIGHTS.len() {
                let (reward, penalty) = self.flag_index_delta(&epoch_rewards, index, flag_index);
                self.balances[index] = (self.balances[index] + reward).saturating_sub(penalty);
            }
            let penalty = self.inactivity_penalty(&epoch_rewards, index);
            self.balances[index] = self.balances[index].saturating_sub(penalty);
        }

        Ok(())
    }

    /// Return the next sync committee, with possible public_key duplicates.
    pub fn get_next_sync_committee(&self) -> anyhow::Result<SyncCommittee> {
        let indices = self.get_next_sync_committee_indices()?;
        let mut public_keys = vec![];

        for index in indices {
            public_keys.push(self.validators[index as usize].public_key.clone());
        }

        let aggregate_public_key =
            eth_aggregate_public_keys(&public_keys.iter().collect::<Vec<_>>())?;

        Ok(SyncCommittee {
            public_keys: FixedVector::try_from(public_keys)
                .map_err(|err| anyhow!("Failed to convert public_keys to FixedVector: {err:?}"))?,
            aggregate_public_key,
        })
    }

    pub fn process_sync_committee_updates(&mut self) -> anyhow::Result<()> {
        let next_epoch = self.get_current_epoch() + 1;
        if next_epoch.is_multiple_of(EPOCHS_PER_SYNC_COMMITTEE_PERIOD) {
            self.current_sync_committee = self.next_sync_committee.clone();
            self.next_sync_committee = Arc::new(self.get_next_sync_committee()?);
        }

        Ok(())
    }

    pub fn process_participation_flag_updates(&mut self) -> anyhow::Result<()> {
        self.previous_epoch_participation = self.current_epoch_participation.clone();
        self.current_epoch_participation = vec![0; self.validators.len()]
            .try_into()
            .map_err(|err| anyhow!("Failed to convert validators list to VariableList: {err:?}"))?;

        Ok(())
    }

    pub fn process_epoch(&mut self) -> anyhow::Result<()> {
        self.process_justification_and_finalization()?;
        self.process_inactivity_updates()?;
        self.process_rewards_and_penalties()?;
        self.process_registry_updates()?;
        self.process_slashings()?;
        self.process_eth1_data_reset()?;
        self.process_pending_deposits()?;
        self.process_pending_consolidations()?;
        self.process_effective_balance_updates()?;
        self.process_slashings_reset()?;
        self.process_randao_mixes_reset()?;
        self.process_historical_summaries_update()?;
        self.process_participation_flag_updates()?;
        self.process_sync_committee_updates()?;
        self.process_proposer_lookahead()?;

        Ok(())
    }

    pub fn process_slots(&mut self, slot: u64) -> anyhow::Result<()> {
        self.process_slots_from_root(slot, None)
    }

    /// ``process_slots`` for a state whose ``hash_tree_root`` the caller already knows. The first
    /// slot records that root instead of hashing the whole state; later slots hash as usual,
    /// because processing a slot changes the state.
    fn process_slots_from_root(
        &mut self,
        slot: u64,
        mut known_state_root: Option<B256>,
    ) -> anyhow::Result<()> {
        ensure!(self.slot < slot);

        while self.slot < slot {
            self.process_slot_with_root(known_state_root.take())?;
            // Process epoch on the start slot of the next epoch
            if (self.slot + 1).is_multiple_of(SLOTS_PER_EPOCH) {
                self.process_epoch()?;
            }

            self.slot += 1
        }

        Ok(())
    }

    pub fn process_slot(&mut self) -> anyhow::Result<()> {
        self.process_slot_with_root(None)
    }

    fn process_slot_with_root(&mut self, known_state_root: Option<B256>) -> anyhow::Result<()> {
        // Cache state root
        let previous_state_root = known_state_root.unwrap_or_else(|| self.state_root());
        self.state_roots[(self.slot % SLOTS_PER_HISTORICAL_ROOT) as usize] = previous_state_root;

        // Cache latest block header state root
        if self.latest_block_header.state_root == B256::default() {
            self.latest_block_header.state_root = previous_state_root;
        }

        // Cache block root
        let previous_block_root = self.latest_block_header.tree_hash_root();
        self.block_roots[(self.slot % SLOTS_PER_HISTORICAL_ROOT) as usize] = previous_block_root;

        Ok(())
    }

    pub async fn process_execution_payload(
        &mut self,
        body: &BeaconBlockBody,
        execution_engine: &Option<impl ExecutionApi>,
    ) -> anyhow::Result<()> {
        let payload = &body.execution_payload;
        self.verify_execution_payload_consistency(body)?;

        // Verify the execution payload is valid
        if let Some(execution_engine) = execution_engine {
            ensure!(
                notify_new_payload(
                    execution_engine,
                    body,
                    self.latest_block_header.parent_root,
                    self.slot
                )
                .await?
            );
        }

        // Cache execution payload header
        self.latest_execution_payload_header = payload.to_execution_payload_header();

        Ok(())
    }

    /// The checks of ``process_execution_payload`` that need no execution engine.
    fn verify_execution_payload_consistency(&self, body: &BeaconBlockBody) -> anyhow::Result<()> {
        let payload = &body.execution_payload;

        // Verify consistency of the parent hash with respect to the previous execution payload
        // header
        ensure!(payload.parent_hash == self.latest_execution_payload_header.block_hash);
        // Verify prev_randao
        ensure!(payload.prev_randao == self.get_randao_mix(self.get_current_epoch()));
        // Verify timestamp
        ensure!(payload.timestamp == self.compute_timestamp_at_slot(self.slot));
        // Verify commitments are under limit
        ensure!(
            body.blob_kzg_commitments.len()
                <= beacon_network_spec()
                    .blob_parameters(self.get_current_epoch())
                    .max_blobs_per_block as usize
        );
        Ok(())
    }

    pub async fn process_block(
        &mut self,
        block: &BeaconBlock,
        execution_engine: &Option<impl ExecutionApi>,
    ) -> anyhow::Result<()> {
        self.process_proposed_block(block, execution_engine, true)
            .await
    }

    /// ``process_block`` for a block being produced. Without ``verify_randao`` the reveal is
    /// mixed in unchecked, as ``skip_randao_verification`` requires.
    pub async fn process_proposed_block(
        &mut self,
        block: &BeaconBlock,
        execution_engine: &Option<impl ExecutionApi>,
        verify_randao: bool,
    ) -> anyhow::Result<()> {
        self.process_block_header(block)?;
        self.process_withdrawals(&block.body.execution_payload)?;
        self.process_execution_payload(&block.body, execution_engine)
            .await?;
        self.process_block_after_execution_payload(&block.body, verify_randao, true)
    }

    fn process_block_after_execution_payload(
        &mut self,
        body: &BeaconBlockBody,
        verify_randao: bool,
        verify_signatures: bool,
    ) -> anyhow::Result<()> {
        self.process_randao_inner(body, verify_randao)?;
        self.process_eth1_data(body)?;
        self.process_operations_with(body, verify_signatures)?;
        self.process_sync_aggregate_with(&body.sync_aggregate, verify_signatures)?;

        Ok(())
    }

    /// Applies a block that was already imported onto its parent's post-state, to rebuild a state
    /// that was not stored. The block was fully checked when it was imported, so its payload,
    /// state root and its randao, attestation and sync aggregate signatures are not checked again.
    /// ``pre_state_root`` is the parent block's state root, which saves hashing the state.
    pub fn replay_block(
        &mut self,
        signed_block: &SignedBeaconBlock,
        pre_state_root: Option<B256>,
    ) -> anyhow::Result<()> {
        let block = &signed_block.message;
        self.process_slots_from_root(block.slot, pre_state_root)?;
        self.process_block_header(block)?;
        self.process_withdrawals(&block.body.execution_payload)?;
        self.verify_execution_payload_consistency(&block.body)?;
        self.latest_execution_payload_header =
            block.body.execution_payload.to_execution_payload_header();
        self.process_block_after_execution_payload(&block.body, false, false)
    }

    pub async fn state_transition(
        &mut self,
        signed_block: &SignedBeaconBlock,
        validate_result: bool,
        execution_engine: &Option<impl ExecutionApi>,
    ) -> anyhow::Result<()> {
        self.state_transition_from_root(signed_block, validate_result, execution_engine, None)
            .await
    }

    /// ``state_transition`` for a pre-state whose root is already known, typically the parent
    /// block's ``state_root``, so the first slot records it instead of computing it. A wrong root
    /// corrupts ``state_roots``, so with ``validate_result`` the block then fails the state root
    /// check.
    pub async fn state_transition_from_root(
        &mut self,
        signed_block: &SignedBeaconBlock,
        validate_result: bool,
        execution_engine: &Option<impl ExecutionApi>,
        pre_state_root: Option<B256>,
    ) -> anyhow::Result<()> {
        // Process slots (including those with no blocks) since block
        self.process_slots_from_root(signed_block.message.slot, pre_state_root)?;
        self.process_signed_block(signed_block, validate_result, execution_engine)
            .await
    }

    /// ``state_transition_from_root`` that also returns the pre-state advanced to the first slot
    /// of the block's epoch, when the block is in a later epoch than the pre-state. That state is
    /// the checkpoint state of the block's epoch for the parent block, which fork choice needs
    /// when attestations target the parent; computing it again repeats a whole epoch processing.
    pub async fn state_transition_keeping_epoch_start(
        &mut self,
        signed_block: &SignedBeaconBlock,
        validate_result: bool,
        execution_engine: &Option<impl ExecutionApi>,
        pre_state_root: Option<B256>,
    ) -> anyhow::Result<Option<BeaconState>> {
        let block_slot = signed_block.message.slot;
        let block_epoch = compute_epoch_at_slot(block_slot);
        if self.get_current_epoch() >= block_epoch {
            self.state_transition_from_root(
                signed_block,
                validate_result,
                execution_engine,
                pre_state_root,
            )
            .await?;
            return Ok(None);
        }

        self.process_slots_from_root(compute_start_slot_at_epoch(block_epoch), pre_state_root)?;
        let epoch_start_state = self.clone();
        self.state_transition_from_epoch_start(signed_block, validate_result, execution_engine)
            .await?;
        Ok(Some(epoch_start_state))
    }

    /// ``state_transition`` for a pre-state already advanced to the first slot of the block's
    /// epoch, such as a checkpoint state built before the block arrived. The epoch processing is
    /// then already done.
    pub async fn state_transition_from_epoch_start(
        &mut self,
        signed_block: &SignedBeaconBlock,
        validate_result: bool,
        execution_engine: &Option<impl ExecutionApi>,
    ) -> anyhow::Result<()> {
        let block_slot = signed_block.message.slot;
        ensure!(
            self.slot == compute_start_slot_at_epoch(compute_epoch_at_slot(block_slot)),
            "pre-state slot {} is not the first slot of block slot {block_slot}'s epoch",
            self.slot
        );
        if self.slot < block_slot {
            self.process_slots(block_slot)?;
        }
        self.process_signed_block(signed_block, validate_result, execution_engine)
            .await
    }

    /// The part of ``state_transition`` after ``process_slots``.
    async fn process_signed_block(
        &mut self,
        signed_block: &SignedBeaconBlock,
        validate_result: bool,
        execution_engine: &Option<impl ExecutionApi>,
    ) -> anyhow::Result<()> {
        let block = &signed_block.message;

        // Verify block signature
        if validate_result {
            ensure!(self.verify_block_header_signature(&signed_block.signed_header())?)
        }

        self.process_block(block, execution_engine).await?;

        // Verify state root
        if validate_result {
            let state_root_timer = BEACON_BLOCK_STATE_ROOT_SECONDS.start_timer();
            let computed_state_root = self.state_root();
            state_root_timer.observe_duration();
            ensure!(block.state_root == computed_state_root)
        }

        Ok(())
    }

    /// Return the churn limit for the current epoch.
    pub fn get_balance_churn_limit(&self) -> u64 {
        let churn = max(
            MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA,
            self.get_total_active_balance() / CHURN_LIMIT_QUOTIENT,
        );
        churn - churn % EFFECTIVE_BALANCE_INCREMENT
    }

    /// Return the churn limit for the current epoch dedicated to activations and exits.
    pub fn get_activation_exit_churn_limit(&self) -> u64 {
        min(
            MAX_PER_EPOCH_ACTIVATION_EXIT_CHURN_LIMIT,
            self.get_balance_churn_limit(),
        )
    }

    pub fn get_consolidation_churn_limit(&self) -> u64 {
        self.get_balance_churn_limit() - self.get_activation_exit_churn_limit()
    }

    pub fn get_pending_balance_to_withdraw(&self, validator_index: u64) -> u64 {
        self.pending_partial_withdrawals
            .iter()
            .filter(|withdrawal| withdrawal.validator_index == validator_index)
            .map(|withdrawal| withdrawal.amount)
            .sum()
    }

    pub fn switch_to_compounding_validator(&mut self, index: u64) -> anyhow::Result<()> {
        let Some(validator) = self.validators.get_mut(index as usize) else {
            return Err(anyhow!("Validator index out of bounds"));
        };

        validator.withdrawal_credentials = B256::from_slice(
            &[
                COMPOUNDING_WITHDRAWAL_PREFIX,
                &validator.withdrawal_credentials[1..],
            ]
            .concat(),
        );
        self.queue_excess_active_balance(index)?;

        Ok(())
    }

    pub fn queue_excess_active_balance(&mut self, index: u64) -> anyhow::Result<()> {
        let Some(balance) = self.balances.get(index as usize) else {
            bail!("Balance index out of bounds");
        };

        if balance > &MIN_ACTIVATION_BALANCE {
            let excess_balance = balance - MIN_ACTIVATION_BALANCE;
            *self
                .balances
                .get_mut(index as usize)
                .ok_or(anyhow!("Balance index out of bounds"))? = MIN_ACTIVATION_BALANCE;

            let Some(validator) = self.validators.get(index as usize) else {
                return Err(anyhow!("Validator index out of bounds"));
            };

            // Use bls.G2_POINT_AT_INFINITY as a signature field placeholder
            // and GENESIS_SLOT to distinguish from a pending deposit request
            self.pending_deposits
                .push(PendingDeposit {
                    public_key: validator.public_key.clone(),
                    withdrawal_credentials: validator.withdrawal_credentials,
                    amount: excess_balance,
                    signature: BLSSignature::infinity(),
                    slot: GENESIS_SLOT,
                })
                .map_err(|err| {
                    anyhow!("Failed to push excess active balance to pending deposits: {err:?}")
                })?;
        }

        Ok(())
    }

    pub fn compute_exit_epoch_and_update_churn(&mut self, exit_balance: u64) -> u64 {
        let mut earliest_exit_epoch = max(
            self.earliest_exit_epoch,
            compute_activation_exit_epoch(self.get_current_epoch()),
        );
        let per_epoch_churn = self.get_activation_exit_churn_limit();

        // New epoch for exits.
        let mut exit_balance_to_consume = if self.earliest_exit_epoch < earliest_exit_epoch {
            per_epoch_churn
        } else {
            self.exit_balance_to_consume
        };

        // Exit doesn't fit in the current earliest epoch.
        if exit_balance > exit_balance_to_consume {
            let balance_to_process = exit_balance - exit_balance_to_consume;
            let additional_epochs = (balance_to_process - 1) / per_epoch_churn + 1;
            earliest_exit_epoch += additional_epochs;
            exit_balance_to_consume += additional_epochs * per_epoch_churn;
        }

        // Consume the balance and update the state variables.
        self.exit_balance_to_consume = exit_balance_to_consume - exit_balance;
        self.earliest_exit_epoch = earliest_exit_epoch;

        self.earliest_exit_epoch
    }

    pub fn compute_consolidation_epoch_and_update_churn(
        &mut self,
        consolidation_balance: u64,
    ) -> u64 {
        let mut earliest_consolidation_epoch = max(
            self.earliest_consolidation_epoch,
            compute_activation_exit_epoch(self.get_current_epoch()),
        );
        let per_epoch_churn = self.get_consolidation_churn_limit();

        // New epoch for consolidations.
        let mut consolidation_balance_to_consume =
            if self.earliest_consolidation_epoch < earliest_consolidation_epoch {
                per_epoch_churn
            } else {
                self.consolidation_balance_to_consume
            };

        // Exit doesn't fit in the current earliest epoch.
        if consolidation_balance > consolidation_balance_to_consume {
            let balance_to_process = consolidation_balance - consolidation_balance_to_consume;
            let additional_epochs = (balance_to_process - 1) / per_epoch_churn + 1;
            earliest_consolidation_epoch += additional_epochs;
            consolidation_balance_to_consume += additional_epochs * per_epoch_churn;
        }

        // Consume the balance and update the state variables.
        self.consolidation_balance_to_consume =
            consolidation_balance_to_consume - consolidation_balance;
        self.earliest_consolidation_epoch = earliest_consolidation_epoch;

        self.earliest_consolidation_epoch
    }

    /// Returns the weak subjectivity period for the current ``state``.
    /// This computation takes into account the effect of:
    /// - validator set churn (bounded by ``get_balance_churn_limit()`` per epoch).
    pub fn compute_weak_subjectivity_period(&self) -> u64 {
        let active_balance_eth = self.get_total_active_balance();
        let delta = self.get_balance_churn_limit();
        let epochs_for_validator_set_churn = SAFETY_DECAY * active_balance_eth / (2 * delta * 100);
        MIN_VALIDATOR_WITHDRAWABILITY_DELAY + epochs_for_validator_set_churn
    }

    pub fn merkle_leaves(&self) -> Vec<B256> {
        vec![
            self.genesis_time.to_le_bytes().tree_hash_root(),
            self.genesis_validators_root.tree_hash_root(),
            self.slot.to_le_bytes().tree_hash_root(),
            self.fork.tree_hash_root(),
            self.latest_block_header.tree_hash_root(),
            self.block_roots.tree_hash_root(),
            self.state_roots.tree_hash_root(),
            self.historical_roots.tree_hash_root(),
            self.eth1_data.tree_hash_root(),
            self.eth1_data_votes.tree_hash_root(),
            self.eth1_deposit_index.to_le_bytes().tree_hash_root(),
            self.validators.tree_hash_root(),
            self.balances.tree_hash_root(),
            self.randao_mixes.tree_hash_root(),
            self.slashings.tree_hash_root(),
            self.previous_epoch_participation.tree_hash_root(),
            self.current_epoch_participation.tree_hash_root(),
            self.justification_bits.tree_hash_root(),
            self.previous_justified_checkpoint.tree_hash_root(),
            self.current_justified_checkpoint.tree_hash_root(),
            self.finalized_checkpoint.tree_hash_root(),
            self.inactivity_scores.tree_hash_root(),
            self.current_sync_committee.tree_hash_root(),
            self.next_sync_committee.tree_hash_root(),
            self.latest_execution_payload_header.tree_hash_root(),
            self.next_withdrawal_index.to_le_bytes().tree_hash_root(),
            self.next_withdrawal_validator_index
                .to_le_bytes()
                .tree_hash_root(),
            self.historical_summaries.tree_hash_root(),
            self.deposit_requests_start_index
                .to_le_bytes()
                .tree_hash_root(),
            self.deposit_balance_to_consume
                .to_le_bytes()
                .tree_hash_root(),
            self.exit_balance_to_consume.to_le_bytes().tree_hash_root(),
            self.earliest_exit_epoch.to_le_bytes().tree_hash_root(),
            self.consolidation_balance_to_consume
                .to_le_bytes()
                .tree_hash_root(),
            self.earliest_consolidation_epoch
                .to_le_bytes()
                .tree_hash_root(),
            self.pending_deposits.tree_hash_root(),
            self.pending_partial_withdrawals.tree_hash_root(),
            self.pending_consolidations.tree_hash_root(),
            self.proposer_lookahead.tree_hash_root(),
        ]
    }

    pub fn data_inclusion_proof(&self, index: u64) -> anyhow::Result<Vec<B256>> {
        let tree = merkle_tree(&self.merkle_leaves(), BEACON_STATE_MERKLE_DEPTH)?;
        generate_proof(&tree, index, BEACON_STATE_MERKLE_DEPTH)
    }

    pub fn current_sync_committee_inclusion_proof(&self) -> anyhow::Result<Vec<B256>> {
        self.data_inclusion_proof(CURRENT_SYNC_COMMITTEE_INDEX)
    }

    pub fn next_sync_committee_inclusion_proof(&self) -> anyhow::Result<Vec<B256>> {
        self.data_inclusion_proof(NEXT_SYNC_COMMITTEE_INDEX)
    }

    pub fn finalized_root_inclusion_proof(&self) -> anyhow::Result<Vec<B256>> {
        let root_to_finalized_checkpoint_proof = vec![
            self.finalized_checkpoint
                .epoch
                .to_le_bytes()
                .tree_hash_root(),
        ];
        let finalized_checkpoint_to_beacon_state_proof =
            self.data_inclusion_proof(FINALIZED_CHECKPOINT_INDEX)?;
        Ok([
            root_to_finalized_checkpoint_proof,
            finalized_checkpoint_to_beacon_state_proof,
        ]
        .concat())
    }

    /// ``hash_tree_root`` of the state. The roots of the validator registry, the lists sized by
    /// it and the other large fields come from caches that rehash only what changed, which is
    /// most of the cost on mainnet.
    #[cfg(not(feature = "zkvm"))]
    pub fn state_root(&self) -> B256 {
        let limit_depth = depth::<ValidatorRegistryLimit>();
        // Leaf chunks hold four `u64`s or 32 `u8`s, so those lists' trees are 2 and 5 levels
        // shallower than the registry limit.
        let (u64_list_depth, u8_list_depth) = (limit_depth - 2, limit_depth - 5);
        let caches = &self.caches.field_roots;
        let field_roots = [
            self.genesis_time.tree_hash_root(),
            self.genesis_validators_root.tree_hash_root(),
            self.slot.tree_hash_root(),
            self.fork.tree_hash_root(),
            self.latest_block_header.tree_hash_root(),
            caches.block_roots.b256_vector_root(&self.block_roots),
            caches.state_roots.b256_vector_root(&self.state_roots),
            caches
                .historical_roots
                .root(&self.historical_roots, depth::<U16777216>()),
            self.eth1_data.tree_hash_root(),
            self.eth1_data_votes.tree_hash_root(),
            self.eth1_deposit_index.tree_hash_root(),
            self.caches
                .validators_root
                .root(&self.validators, limit_depth),
            caches
                .balances
                .u64_list_root(&self.balances, u64_list_depth),
            caches.randao_mixes.b256_vector_root(&self.randao_mixes),
            caches.slashings.u64_vector_root(&self.slashings),
            caches
                .previous_epoch_participation
                .u8_list_root(&self.previous_epoch_participation, u8_list_depth),
            caches
                .current_epoch_participation
                .u8_list_root(&self.current_epoch_participation, u8_list_depth),
            self.justification_bits.tree_hash_root(),
            self.previous_justified_checkpoint.tree_hash_root(),
            self.current_justified_checkpoint.tree_hash_root(),
            self.finalized_checkpoint.tree_hash_root(),
            caches
                .inactivity_scores
                .u64_list_root(&self.inactivity_scores, u64_list_depth),
            caches.sync_committees.root(&self.current_sync_committee),
            caches.sync_committees.root(&self.next_sync_committee),
            self.latest_execution_payload_header.tree_hash_root(),
            self.next_withdrawal_index.tree_hash_root(),
            self.next_withdrawal_validator_index.tree_hash_root(),
            caches
                .historical_summaries
                .root(&self.historical_summaries, depth::<U16777216>()),
            self.deposit_requests_start_index.tree_hash_root(),
            self.deposit_balance_to_consume.tree_hash_root(),
            self.exit_balance_to_consume.tree_hash_root(),
            self.earliest_exit_epoch.tree_hash_root(),
            self.consolidation_balance_to_consume.tree_hash_root(),
            self.earliest_consolidation_epoch.tree_hash_root(),
            caches
                .pending_deposits
                .root(&self.pending_deposits, depth::<U134217728>()),
            caches
                .pending_partial_withdrawals
                .root(&self.pending_partial_withdrawals, depth::<U134217728>()),
            caches
                .pending_consolidations
                .root(&self.pending_consolidations, depth::<U262144>()),
            self.proposer_lookahead.tree_hash_root(),
        ];
        tree_hash::merkle_root(field_roots.concat().as_slice(), field_roots.len())
    }

    /// zkVM builds hash through a patched ``VariableList`` that treats its 2^29 limit as 2^40,
    /// which the caches do not model, so they keep the derived root.
    #[cfg(feature = "zkvm")]
    pub fn state_root(&self) -> B256 {
        self.tree_hash_root()
    }
}

pub fn get_validator_from_deposit(
    public_key: PublicKey,
    withdrawal_credentials: B256,
    amount: u64,
) -> Validator {
    let mut validator = Validator {
        public_key,
        withdrawal_credentials,
        effective_balance: 0,
        slashed: false,
        activation_eligibility_epoch: FAR_FUTURE_EPOCH,
        activation_epoch: FAR_FUTURE_EPOCH,
        exit_epoch: FAR_FUTURE_EPOCH,
        withdrawable_epoch: FAR_FUTURE_EPOCH,
    };

    let max_effective_balance = validator.get_max_effective_balance();
    validator.effective_balance = min(
        amount - amount % EFFECTIVE_BALANCE_INCREMENT,
        max_effective_balance,
    );
    validator
}

/// Wrapper to ``bls.FastAggregateVerify`` accepting the ``G2_POINT_AT_INFINITY`` signature when
/// ``public_keys`` is empty.
pub fn eth_fast_aggregate_verify(
    public_keys: &[&PublicKey],
    message: B256,
    signature: &BLSSignature,
) -> anyhow::Result<bool> {
    if public_keys.is_empty() && *signature == BLSSignature::infinity() {
        return Ok(true);
    }

    signature
        .fast_aggregate_verify(public_keys, message.as_ref())
        .map_err(|err| anyhow!("Failed to verify fast aggregate: {err}"))
}

/// Return the aggregate public key for the public keys in ``public_keys``.
/// NOTE: the ``+`` operation should be interpreted as elliptic curve point addition, which takes as
/// input elliptic curve points that must be decoded from the input ``BLSPublicKey``s.
/// This implementation is for demonstrative purposes only and ignores encoding/decoding concerns.
/// Refer to the BLS signature draft standard for more information.
pub fn eth_aggregate_public_keys(public_keys: &[&PublicKey]) -> anyhow::Result<PublicKey> {
    ensure!(!public_keys.is_empty(), "Public keys list cannot be empty");
    Ok(PublicKey::aggregate(public_keys)?)
}

/// Return the largest integer ``x`` such that ``x**2 <= n``.
pub fn integer_squareroot(n: u64) -> u64 {
    if n == UINT64_MAX {
        return UINT64_MAX_SQRT;
    }

    let mut x = n;
    let mut y = x.div_ceil(2);
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

/// EIP-7044: voluntary exits are signed with the network's Capella fork version.
pub fn voluntary_exit_domain(genesis_validators_root: B256) -> B256 {
    compute_domain(
        DOMAIN_VOLUNTARY_EXIT,
        Some(beacon_network_spec().capella_fork_version),
        Some(genesis_validators_root),
    )
}

pub fn is_valid_deposit_signature(
    public_key: &PublicKey,
    withdrawal_credentials: B256,
    amount: u64,
    signature: &BLSSignature,
) -> anyhow::Result<bool> {
    let deposit_message = DepositMessage {
        public_key: public_key.clone(),
        withdrawal_credentials,
        amount,
    };
    // Fork-agnostic domain since deposits are valid across forks
    let domain = compute_domain(
        DOMAIN_DEPOSIT,
        Some(beacon_network_spec().genesis_fork_version),
        None,
    );
    let signing_root = compute_signing_root(deposit_message, domain);

    signature
        .verify(public_key, signing_root.as_ref())
        .map_err(|err| anyhow!("Invalid deposit signature: {err:?}"))
}

pub fn fork_name_at_epoch(epoch: u64) -> ForkName {
    if epoch >= beacon_network_spec().fulu_fork_epoch {
        ForkName::Fulu
    } else if epoch >= beacon_network_spec().electra_fork_epoch {
        ForkName::Electra
    } else if epoch >= beacon_network_spec().deneb_fork_epoch {
        ForkName::Deneb
    } else if epoch >= beacon_network_spec().capella_fork_epoch {
        ForkName::Capella
    } else if epoch >= beacon_network_spec().bellatrix_fork_epoch {
        ForkName::Bellatrix
    } else if epoch >= beacon_network_spec().altair_fork_epoch {
        ForkName::Altair
    } else {
        ForkName::Base
    }
}

pub fn fork_name_from_version(version: [u8; 4]) -> ForkName {
    match version {
        _ if version == beacon_network_spec().electra_fork_version => ForkName::Electra,
        _ if version == beacon_network_spec().fulu_fork_version => ForkName::Fulu,
        _ if version == beacon_network_spec().deneb_fork_version => ForkName::Deneb,
        _ if version == beacon_network_spec().capella_fork_version => ForkName::Capella,
        _ if version == beacon_network_spec().bellatrix_fork_version => ForkName::Bellatrix,
        _ if version == beacon_network_spec().altair_fork_version => ForkName::Altair,
        _ => ForkName::Base,
    }
}

/// ``verify_and_notify_new_payload`` for a block's payload, timed.
pub async fn notify_new_payload(
    execution_engine: &impl ExecutionApi,
    body: &BeaconBlockBody,
    parent_beacon_block_root: B256,
    slot: u64,
) -> anyhow::Result<bool> {
    let versioned_hashes = body
        .blob_kzg_commitments
        .iter()
        .map(|commitment| commitment.calculate_versioned_hash())
        .collect();
    let timer = BEACON_ENGINE_NEW_PAYLOAD_REQUEST_DURATION_SECONDS.start_timer();
    let result = execution_engine
        .verify_and_notify_new_payload(NewPayloadRequest {
            execution_payload: body.execution_payload.clone(),
            versioned_hashes,
            parent_beacon_block_root,
            execution_requests: body.execution_requests.clone(),
        })
        .await;
    let seconds = timer.stop_and_record();
    tracing::debug!(
        target: "ream::timing",
        slot,
        new_payload_ms = (seconds * 1000.0) as u64,
        "timing: newPayload"
    );
    result
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use snap::raw::Decoder;
    use ssz::Decode;

    use super::*;

    fn sepolia_state() -> BeaconState {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
            "../../../../testing/gossip-validation/tests/assets/sepolia/states/grandparent_state_9552074.ssz_snappy",
        );
        let bytes = Decoder::new()
            .decompress_vec(&std::fs::read(path).unwrap())
            .unwrap();
        BeaconState::from_ssz_bytes(&bytes).unwrap()
    }

    #[test]
    fn randao_reveal_is_mixed_in_unchecked_when_verification_is_skipped() {
        let state = sepolia_state();
        let epoch = state.get_current_epoch();
        let body = BeaconBlockBody {
            randao_reveal: BLSSignature::infinity(),
            ..Default::default()
        };

        assert!(state.clone().process_randao(&body).is_err());

        let mut skipped = state.clone();
        skipped.process_randao_inner(&body, false).unwrap();
        let expected = xor(
            state.get_randao_mix(epoch).as_slice(),
            hash(body.randao_reveal.to_slice()).as_slice(),
        );
        assert_eq!(skipped.get_randao_mix(epoch), expected);
    }

    fn sepolia_asset<T: Decode>(path: &str) -> T {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../testing/gossip-validation/tests/assets/sepolia")
            .join(path);
        let bytes = Decoder::new()
            .decompress_vec(&std::fs::read(path).unwrap())
            .unwrap();
        T::from_ssz_bytes(&bytes).unwrap()
    }

    /// The proposer is paid only for flags a block sets for the first time, as the post-state
    /// shows. Sums of per-attestation rewards round down once per attestation.
    #[test]
    fn attestations_proposer_reward_pays_only_new_participation_flags() {
        let mut pre_state = sepolia_state();
        let block: crate::electra::beacon_block::SignedBeaconBlock =
            sepolia_asset("blocks/parent_9552075.ssz_snappy");
        let post_state: BeaconState = sepolia_asset("states/parent_state_9552075.ssz_snappy");
        pre_state.process_slots(block.message.slot).unwrap();

        let attestations = &block.message.body.attestations;
        let reward = pre_state
            .attestations_proposer_reward(attestations)
            .unwrap();

        let base_reward_per_increment = pre_state.get_base_reward_per_increment();
        let mut numerator = 0;
        for (before, after) in [
            (
                &pre_state.previous_epoch_participation,
                &post_state.previous_epoch_participation,
            ),
            (
                &pre_state.current_epoch_participation,
                &post_state.current_epoch_participation,
            ),
        ] {
            for (index, (before, after)) in before.iter().zip(after.iter()).enumerate() {
                for (flag_index, weight) in PARTICIPATION_FLAG_WEIGHTS.iter().enumerate() {
                    let flag_index = flag_index as u8;
                    if !BeaconState::has_flag(*before, flag_index)
                        && BeaconState::has_flag(*after, flag_index)
                    {
                        numerator += pre_state
                            .get_base_reward(index as u64, base_reward_per_increment)
                            * weight;
                    }
                }
            }
        }
        let denominator =
            (WEIGHT_DENOMINATOR - PROPOSER_WEIGHT) * WEIGHT_DENOMINATOR / PROPOSER_WEIGHT;
        let expected = numerator / denominator;
        assert!(reward > 0);
        assert!(reward <= expected && expected - reward < attestations.len() as u64);

        // Including the same votes twice pays nothing more.
        let doubled: Vec<_> = attestations
            .iter()
            .chain(attestations.iter())
            .cloned()
            .collect();
        assert_eq!(
            pre_state.attestations_proposer_reward(&doubled).unwrap(),
            reward
        );
    }

    /// Two sibling blocks from the same proposer carry the same RANDAO reveal. If one of them
    /// schedules an exit, both chains keep the same seeds but the exit changes the active set of
    /// the epoch it takes effect in. The two states share their caches, so the shuffling must be
    /// keyed by the block that decides it, not by the seed.
    #[test]
    fn sibling_forks_with_the_same_seed_do_not_share_shufflings() {
        let state = sepolia_state();
        let current_epoch = state.get_current_epoch();
        let exit_epoch = current_epoch + 5;
        let exiting = (0..state.validators.len())
            .find(|&index| state.validators[index].is_active_validator(exit_epoch))
            .unwrap();
        let mut sibling = state.clone();
        let mut other_sibling = state.clone();
        other_sibling.latest_block_header.body_root = B256::repeat_byte(1);
        other_sibling.validators[exiting].exit_epoch = exit_epoch;

        let start = compute_start_slot_at_epoch(exit_epoch - 1);
        sibling.process_slots(start).unwrap();
        other_sibling.process_slots(start).unwrap();
        assert_eq!(
            sibling.get_seed(exit_epoch, DOMAIN_BEACON_ATTESTER),
            other_sibling.get_seed(exit_epoch, DOMAIN_BEACON_ATTESTER)
        );

        let exiting = exiting as u64;
        assert!(
            sibling
                .get_shuffled_active_validator_indices(exit_epoch)
                .contains(&exiting)
        );
        assert!(
            !other_sibling
                .get_shuffled_active_validator_indices(exit_epoch)
                .contains(&exiting)
        );
    }

    /// The cached state root must equal the derived ``hash_tree_root`` after changes, and for a
    /// state with a shorter registry that shares the same caches.
    #[test]
    fn cached_state_root_matches_tree_hash_root() {
        let mut state = sepolia_state();
        assert_eq!(state.state_root(), state.tree_hash_root());

        state.slot += 1;
        state.validators[0].effective_balance -= EFFECTIVE_BALANCE_INCREMENT;
        state.balances[1] += 1;
        state.randao_mixes[2] = B256::repeat_byte(7);
        state.inactivity_scores[3] += 1;
        let deposits = state.pending_deposits.iter().skip(1).cloned().collect();
        state.pending_deposits = VariableList::new(deposits).unwrap();
        assert_eq!(state.state_root(), state.tree_hash_root());

        let mut shorter = state.clone();
        let registry_len = shorter.validators.len();
        shorter.validators =
            ChunkedList::new(shorter.validators.to_vec()[..registry_len - 1].to_vec()).unwrap();
        assert_eq!(shorter.state_root(), shorter.tree_hash_root());
        assert_eq!(state.state_root(), state.tree_hash_root());
    }

    /// Gossip validation reads committees and proposers of the next epoch from an unadvanced
    /// state; they must equal those of the state advanced through the epoch transition.
    #[test]
    fn next_epoch_duties_match_the_advanced_state() {
        let state = sepolia_state();
        let current_epoch = state.get_current_epoch();
        let next_epoch = current_epoch + 1;
        assert!(state.determines_committees_of(current_epoch - 1));
        assert!(state.determines_committees_of(next_epoch));
        assert!(!state.determines_committees_of(next_epoch + 1));
        assert!(!state.determines_proposers_of(current_epoch - 1));
        assert!(state.determines_proposers_of(next_epoch));
        assert!(!state.determines_proposers_of(next_epoch + 1));
        let next_epoch_start = compute_start_slot_at_epoch(next_epoch);
        let mut advanced = state.clone();
        // A clone shares the caches; start from empty ones so the advanced state computes its
        // committees itself.
        advanced.caches = StateCaches::default();
        advanced.process_slots(next_epoch_start + 1).unwrap();

        assert_eq!(
            state.get_committee_count_per_slot(next_epoch),
            advanced.get_committee_count_per_slot(next_epoch)
        );
        for slot in next_epoch_start..next_epoch_start + SLOTS_PER_EPOCH {
            for index in 0..state.get_committee_count_per_slot(next_epoch) {
                assert_eq!(
                    state.get_beacon_committee(slot, index).unwrap(),
                    advanced.get_beacon_committee(slot, index).unwrap(),
                    "committee {index} at slot {slot}"
                );
            }
            assert_eq!(
                state.get_beacon_proposer_index(Some(slot)).unwrap(),
                advanced.get_beacon_proposer_index(Some(slot)).unwrap(),
                "proposer at slot {slot}"
            );
        }
        // Later slots of the state's own epoch too.
        for slot in state.slot + 1..next_epoch_start {
            let mut at_slot = state.clone();
            at_slot.process_slots(slot).unwrap();
            assert_eq!(
                state.get_beacon_proposer_index(Some(slot)).unwrap(),
                at_slot.get_beacon_proposer_index(None).unwrap(),
                "proposer at slot {slot}"
            );
        }
    }
}
