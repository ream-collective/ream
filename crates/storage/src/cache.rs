use std::{
    collections::HashMap,
    num::NonZeroUsize,
    sync::{Arc, Mutex, MutexGuard, RwLock as StorageRwLock, RwLockReadGuard, atomic::AtomicBool},
    thread::{self, JoinHandle},
    time::Instant,
};

use alloy_primitives::{B256, FixedBytes};
use lru::LruCache;
use ream_bls::{BLSSignature, PublicKey};
use ream_consensus_beacon::{
    bls_to_execution_change::BLSToExecutionChange,
    data_column_sidecar::NUMBER_OF_COLUMNS,
    electra::{beacon_block::SignedBeaconBlock, beacon_state::BeaconState},
    fork_choice::latest_message::LatestMessage,
};
use ream_consensus_lean::{block::SignedBlock, state::LeanState};
use ream_consensus_misc::{
    checkpoint::Checkpoint,
    constants::beacon::{SLOTS_PER_EPOCH, SYNC_COMMITTEE_SIZE},
};
use ream_light_client::finality_update::LightClientFinalityUpdate;
use tokio::sync::RwLock;
const LRU_CACHE_SIZE: usize = 64;
// Every block carries a sidecar per column, so the seen set must hold at least a full block's
// worth of indices or duplicates of its earlier columns are validated and imported again.
const DATA_COLUMN_SIDECAR_CACHE_SIZE: usize = NUMBER_OF_COLUMNS as usize * SLOTS_PER_EPOCH as usize;
const BLOCK_CACHE_SIZE: usize = 128;
const STATE_CACHE_SIZE: usize = 8;
// Fork choice reads the checkpoint states that blocks' attestations target, usually the current
// and previous epoch, plus the justified and finalized ones.
const CHECKPOINT_STATE_CACHE_SIZE: usize = 4;

#[derive(Debug, Hash, PartialEq, Eq, Default, Clone)]
pub struct AddressSlotIdentifier {
    pub address: PublicKey,
    pub slot: u64,
}

#[derive(Debug, Hash, Eq, PartialEq, Default)]
pub struct AtestationKey {
    pub attestation_subnet_id: u64,
    pub target_epoch: u64,
    pub participating_validator_index: u64,
}

#[derive(Debug, Hash, Eq, PartialEq, Default)]
pub struct AddressValidaterIndexIdentifier {
    pub address: PublicKey,
    pub validator_index: u64,
}

#[derive(Debug, Hash, Eq, PartialEq, Default, Clone)]
pub struct SyncCommitteeKey {
    pub subnet_id: u64,
    pub slot: u64,
    pub validator_index: u64,
}

#[derive(Debug, Hash, Eq, PartialEq, Default, Clone)]
pub struct CacheSyncCommitteeContribution {
    pub slot: u64,
    pub beacon_block_root: FixedBytes<32>,
    pub subcommittee_index: u64,
}

#[derive(Debug, Hash, Eq, PartialEq, Default, Clone)]
pub struct AggregateAndProofKey {
    pub aggregator_index: u64,
    pub target_epoch: u64,
}

/// A signed block header whose header-derived data column gossip checks all passed, keyed by the
/// header root. The result only holds for the same signature and finalized checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedDataColumnHeader {
    pub signature: BLSSignature,
    pub finalized_checkpoint: Checkpoint,
}

/// Latest messages not yet written to the database, whether a write is running, and when the
/// last write finished.
#[derive(Debug, Default)]
pub struct PendingLatestMessages {
    pub messages: HashMap<u64, LatestMessage>,
    pub flushing: bool,
    pub last_flush: Option<Instant>,
}

/// In-memory LRU cache for beacon node (gossip validation + beacon storage).
#[derive(Debug)]
pub struct BeaconCacheDB {
    // Gossip validation caches
    pub seen_proposer_signature: RwLock<LruCache<AddressSlotIdentifier, BLSSignature>>,
    pub seen_bls_to_execution_signature:
        RwLock<LruCache<AddressSlotIdentifier, BLSToExecutionChange>>,
    pub seen_blob_sidecars: RwLock<LruCache<(u64, u64, u64), ()>>,
    pub seen_data_column_sidecars: RwLock<LruCache<(u64, u64, u64), ()>>,
    pub validated_data_column_headers: RwLock<LruCache<B256, ValidatedDataColumnHeader>>,
    pub seen_attestations: RwLock<LruCache<AtestationKey, ()>>,
    pub seen_bls_to_execution_change: RwLock<LruCache<AddressValidaterIndexIdentifier, ()>>,
    pub seen_sync_messages: RwLock<LruCache<SyncCommitteeKey, ()>>,
    pub seen_sync_committee_contributions: RwLock<LruCache<CacheSyncCommitteeContribution, ()>>,
    pub seen_forwarded_finality_update_slot: RwLock<Option<(u64, bool)>>,
    pub seen_voluntary_exit: RwLock<LruCache<u64, ()>>,
    pub seen_proposer_slashings: RwLock<LruCache<u64, ()>>,
    pub prior_seen_attester_slashing_indices: RwLock<LruCache<u64, ()>>,
    pub forwarded_optimistic_update_slot: RwLock<Option<u64>>,
    pub forwarded_light_client_finality_update: RwLock<Option<LightClientFinalityUpdate>>,
    pub seen_aggregate_and_proof: RwLock<LruCache<AggregateAndProofKey, ()>>,
    // Beacon storage caches
    pub blocks: Mutex<LruCache<B256, SignedBeaconBlock>>,
    pub states: Mutex<LruCache<B256, Arc<BeaconState>>>,
    /// States being stored whole on another thread, readable here until the write commits.
    pub pending_state_snapshots: Mutex<HashMap<B256, Arc<BeaconState>>>,
    pub checkpoint_states: Mutex<LruCache<Checkpoint, Arc<BeaconState>>>,
    pub pending_latest_messages: Mutex<PendingLatestMessages>,
    /// Serializes vote flushes and removals without blocking readers on a DB write.
    pub(crate) latest_messages_write_lock: Mutex<()>,
    storage_tasks: Mutex<Vec<JoinHandle<()>>>,
    accepting_storage_writes: StorageRwLock<bool>,
    /// Whether finalized states are being pruned on another thread.
    pub pruning_states: AtomicBool,
}

/// Records `key` in `seen` and returns whether it was not there yet. Gossip messages are
/// validated concurrently and an early `contains` check holds no lock through the validation, so
/// the record step checks again under the write lock.
pub async fn insert_if_unseen<K: std::hash::Hash + Eq>(
    seen: &RwLock<LruCache<K, ()>>,
    key: K,
) -> bool {
    let mut seen = seen.write().await;
    if seen.contains(&key) {
        return false;
    }
    seen.put(key, ());
    true
}

impl BeaconCacheDB {
    pub fn new() -> Self {
        Self {
            seen_proposer_signature: LruCache::new(
                NonZeroUsize::new(LRU_CACHE_SIZE).expect("Invalid cache size"),
            )
            .into(),
            seen_bls_to_execution_signature: LruCache::new(
                NonZeroUsize::new(LRU_CACHE_SIZE).expect("Invalid cache size"),
            )
            .into(),
            seen_blob_sidecars: LruCache::new(
                NonZeroUsize::new(LRU_CACHE_SIZE).expect("Invalid cache size"),
            )
            .into(),
            seen_data_column_sidecars: LruCache::new(
                NonZeroUsize::new(DATA_COLUMN_SIDECAR_CACHE_SIZE).expect("Invalid cache size"),
            )
            .into(),
            validated_data_column_headers: LruCache::new(
                NonZeroUsize::new(LRU_CACHE_SIZE).expect("Invalid cache size"),
            )
            .into(),
            seen_attestations: LruCache::new(
                NonZeroUsize::new(LRU_CACHE_SIZE).expect("Invalid cache size"),
            )
            .into(),
            seen_bls_to_execution_change: LruCache::new(
                NonZeroUsize::new(LRU_CACHE_SIZE).expect("Invalid cache size"),
            )
            .into(),
            seen_sync_messages: LruCache::new(
                NonZeroUsize::new(LRU_CACHE_SIZE).expect("Invalid cache size"),
            )
            .into(),
            seen_voluntary_exit: LruCache::new(
                NonZeroUsize::new(LRU_CACHE_SIZE).expect("Invalid cache size"),
            )
            .into(),
            seen_proposer_slashings: LruCache::new(
                NonZeroUsize::new(LRU_CACHE_SIZE).expect("Invalid cache size"),
            )
            .into(),
            prior_seen_attester_slashing_indices: LruCache::new(
                NonZeroUsize::new(LRU_CACHE_SIZE).expect("Invalid cache size"),
            )
            .into(),
            seen_sync_committee_contributions: LruCache::new(
                NonZeroUsize::new(SYNC_COMMITTEE_SIZE as usize).expect("Invalid cache size"),
            )
            .into(),
            seen_forwarded_finality_update_slot: RwLock::new(None),
            forwarded_optimistic_update_slot: None.into(),
            forwarded_light_client_finality_update: None.into(),
            seen_aggregate_and_proof: LruCache::new(
                NonZeroUsize::new(LRU_CACHE_SIZE).expect("Invalid cache size"),
            )
            .into(),
            blocks: Mutex::new(LruCache::new(
                NonZeroUsize::new(BLOCK_CACHE_SIZE).expect("Invalid cache size"),
            )),
            states: Mutex::new(LruCache::new(
                NonZeroUsize::new(STATE_CACHE_SIZE).expect("Invalid cache size"),
            )),
            pending_state_snapshots: Mutex::default(),
            pruning_states: AtomicBool::new(false),
            pending_latest_messages: Mutex::default(),
            latest_messages_write_lock: Mutex::default(),
            storage_tasks: Mutex::default(),
            accepting_storage_writes: StorageRwLock::new(true),
            checkpoint_states: Mutex::new(LruCache::new(
                NonZeroUsize::new(CHECKPOINT_STATE_CACHE_SIZE).expect("Invalid cache size"),
            )),
        }
    }

    pub(crate) fn spawn_storage_task(
        &self,
        task: impl FnOnce() + Send + 'static,
    ) -> std::io::Result<()> {
        #[cfg(test)]
        if FAIL_NEXT_STORAGE_SPAWN.with(|fail| fail.replace(false)) {
            return Err(std::io::Error::other(
                "injected storage worker spawn failure",
            ));
        }
        let mut tasks = self
            .storage_tasks
            .lock()
            .expect("storage tasks lock is not poisoned");
        // Finished workers no longer own data or a DB handle.
        let mut index = 0;
        while index < tasks.len() {
            if tasks[index].is_finished() {
                if tasks.swap_remove(index).join().is_err() {
                    return Err(std::io::Error::other("storage worker panicked"));
                }
            } else {
                index += 1;
            }
        }
        tasks.push(thread::Builder::new().spawn(task)?);
        Ok(())
    }

    /// The pending vote overlay, locked.
    pub(crate) fn pending_votes(&self) -> MutexGuard<'_, PendingLatestMessages> {
        self.pending_latest_messages
            .lock()
            .expect("pending latest messages lock is not poisoned")
    }

    /// The write gate guard for a cached database. Without a cache there are no background
    /// writers to drain at shutdown, so writes are always accepted.
    pub(crate) fn accept_writes(
        cache: Option<&Arc<Self>>,
    ) -> Result<Option<RwLockReadGuard<'_, bool>>, crate::errors::StoreError> {
        cache.map(|cache| cache.storage_write_guard()).transpose()
    }

    pub(crate) fn storage_write_guard(
        &self,
    ) -> Result<RwLockReadGuard<'_, bool>, crate::errors::StoreError> {
        let guard = self
            .accepting_storage_writes
            .read()
            .expect("storage write gate is not poisoned");
        if !*guard {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "beacon storage is shutting down",
            )
            .into());
        }
        Ok(guard)
    }

    pub(crate) fn stop_storage_writes(&self) {
        *self
            .accepting_storage_writes
            .write()
            .expect("storage write gate is not poisoned") = false;
    }

    /// Call after stopping producers. Do not hold a pending/cache lock while joining workers.
    pub(crate) fn join_storage_tasks(&self) -> Result<(), crate::errors::StoreError> {
        let tasks = std::mem::take(
            &mut *self
                .storage_tasks
                .lock()
                .expect("storage tasks lock is not poisoned"),
        );
        let mut panicked = false;
        for task in tasks {
            panicked |= task.join().is_err();
        }
        if panicked {
            return Err(std::io::Error::other("storage worker panicked").into());
        }
        Ok(())
    }
}

#[cfg(test)]
thread_local! {
    pub(crate) static FAIL_NEXT_STORAGE_SPAWN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

impl Default for BeaconCacheDB {
    fn default() -> Self {
        Self::new()
    }
}

/// In-memory LRU cache for lean node (lean storage only).
#[derive(Debug)]
pub struct LeanCacheDB {
    // Lean storage caches
    pub blocks: Mutex<LruCache<B256, SignedBlock>>,
    pub states: Mutex<LruCache<B256, LeanState>>,
}

impl LeanCacheDB {
    pub fn new() -> Self {
        Self {
            blocks: Mutex::new(LruCache::new(
                NonZeroUsize::new(BLOCK_CACHE_SIZE).expect("Invalid cache size"),
            )),
            states: Mutex::new(LruCache::new(
                NonZeroUsize::new(STATE_CACHE_SIZE).expect("Invalid cache size"),
            )),
        }
    }
}

impl Default for LeanCacheDB {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod insert_if_unseen_tests {
    use std::num::NonZeroUsize;

    use lru::LruCache;
    use tokio::sync::RwLock;

    use super::insert_if_unseen;

    #[tokio::test]
    async fn only_the_first_insert_of_a_key_succeeds() {
        let seen = RwLock::new(LruCache::new(NonZeroUsize::new(4).unwrap()));
        assert!(insert_if_unseen(&seen, 1u64).await);
        assert!(!insert_if_unseen(&seen, 1u64).await);
        assert!(insert_if_unseen(&seen, 2u64).await);
    }
}
