use std::{
    collections::{HashMap, VecDeque},
    num::NonZeroUsize,
    sync::{
        Arc, Condvar, Mutex, MutexGuard, RwLock as StorageRwLock, RwLockReadGuard,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
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
/// Includes the state being written and every queued state.
pub(crate) const STATE_SNAPSHOT_PENDING_LIMIT: usize = 3;
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

/// Latest messages not yet written to the database, and whether a write is running.
#[derive(Debug, Default)]
pub struct PendingLatestMessages {
    pub messages: HashMap<u64, LatestMessage>,
    pub flushing: bool,
}

type StateSnapshotTask = Box<dyn FnOnce() -> bool + Send + 'static>;

struct StateSnapshotQueueState {
    tasks: VecDeque<StateSnapshotTask>,
    in_flight: usize,
    accepting: bool,
}

struct StateSnapshotQueue {
    state: Mutex<StateSnapshotQueueState>,
    changed: Condvar,
}

impl StateSnapshotQueue {
    fn new() -> Self {
        Self {
            state: Mutex::new(StateSnapshotQueueState {
                tasks: VecDeque::new(),
                in_flight: 0,
                accepting: true,
            }),
            changed: Condvar::new(),
        }
    }

    fn enqueue(
        &self,
        before_enqueue: impl FnOnce(),
        task: StateSnapshotTask,
    ) -> std::io::Result<()> {
        let mut state = self
            .state
            .lock()
            .expect("state snapshot queue lock is not poisoned");
        while state.accepting && state.in_flight == STATE_SNAPSHOT_PENDING_LIMIT {
            state = self
                .changed
                .wait(state)
                .expect("state snapshot queue lock is not poisoned");
        }
        if !state.accepting {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "state snapshot writer is shutting down",
            ));
        }

        // The task cannot be observed until this lock is released, so publish the in-memory
        // state before making its write runnable.
        before_enqueue();
        state.in_flight += 1;
        state.tasks.push_back(task);
        self.changed.notify_all();
        Ok(())
    }

    fn next(&self) -> Option<StateSnapshotTask> {
        let mut state = self
            .state
            .lock()
            .expect("state snapshot queue lock is not poisoned");
        while state.accepting && state.tasks.is_empty() {
            state = self
                .changed
                .wait(state)
                .expect("state snapshot queue lock is not poisoned");
        }
        state.tasks.pop_front()
    }

    fn complete(&self) {
        let mut state = self
            .state
            .lock()
            .expect("state snapshot queue lock is not poisoned");
        state.in_flight -= 1;
        self.changed.notify_all();
    }

    fn close(&self) {
        let mut state = self
            .state
            .lock()
            .expect("state snapshot queue lock is not poisoned");
        state.accepting = false;
        self.changed.notify_all();
    }
}

struct ActiveStateSnapshotTask(Arc<AtomicUsize>);

impl Drop for ActiveStateSnapshotTask {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

struct StateSnapshotWriter {
    queue: Arc<StateSnapshotQueue>,
    worker: Option<JoinHandle<()>>,
}

impl StateSnapshotWriter {
    fn is_finished(&self) -> bool {
        self.worker.as_ref().is_some_and(JoinHandle::is_finished)
    }

    fn join(mut self) -> thread::Result<()> {
        self.queue.close();
        self.worker
            .take()
            .expect("state snapshot worker exists")
            .join()
    }
}

impl Drop for StateSnapshotWriter {
    fn drop(&mut self) {
        // A cache can be dropped without an explicit storage shutdown. Wake the worker so its
        // detached handle cannot leave a persistent thread blocked on an empty queue.
        self.queue.close();
    }
}

impl std::fmt::Debug for StateSnapshotWriter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StateSnapshotWriter")
            .field("worker", &self.worker)
            .finish_non_exhaustive()
    }
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
    state_snapshot_writer: Mutex<Option<StateSnapshotWriter>>,
    active_state_snapshot_tasks: Arc<AtomicUsize>,
    accepting_storage_writes: StorageRwLock<bool>,
    /// Whether finalized states are being pruned on another thread.
    pub pruning_states: AtomicBool,
    #[cfg(test)]
    state_snapshot_test_gate: Arc<(Mutex<bool>, Condvar)>,
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
            state_snapshot_writer: Mutex::default(),
            active_state_snapshot_tasks: Arc::new(AtomicUsize::new(0)),
            accepting_storage_writes: StorageRwLock::new(true),
            checkpoint_states: Mutex::new(LruCache::new(
                NonZeroUsize::new(CHECKPOINT_STATE_CACHE_SIZE).expect("Invalid cache size"),
            )),
            #[cfg(test)]
            state_snapshot_test_gate: Arc::new((Mutex::new(false), Condvar::new())),
        }
    }

    fn start_state_snapshot_writer(&self) -> std::io::Result<Arc<StateSnapshotQueue>> {
        let mut writer = self
            .state_snapshot_writer
            .lock()
            .expect("state snapshot writer lock is not poisoned");
        if writer
            .as_ref()
            .is_some_and(StateSnapshotWriter::is_finished)
        {
            let finished = writer.take().expect("finished writer exists");
            finished.join().map_err(|err| {
                std::io::Error::other(format!("state snapshot worker panicked: {err:?}"))
            })?;
        }
        if let Some(writer) = writer.as_ref() {
            return Ok(writer.queue.clone());
        }

        let queue = Arc::new(StateSnapshotQueue::new());
        let worker_queue = queue.clone();
        let active = self.active_state_snapshot_tasks.clone();
        let worker = thread::Builder::new()
            .name("state-snapshot-writer".to_string())
            .spawn(move || {
                while let Some(task) = worker_queue.next() {
                    active.fetch_add(1, Ordering::AcqRel);
                    let _active = ActiveStateSnapshotTask(active.clone());
                    if task() {
                        worker_queue.complete();
                    }
                }
            })?;
        *writer = Some(StateSnapshotWriter {
            queue: queue.clone(),
            worker: Some(worker),
        });
        Ok(queue)
    }

    /// Enqueues one state snapshot with backpressure. `before_enqueue` publishes the state to the
    /// pending overlay while the queue is locked, before the worker can start the task.
    pub(crate) fn enqueue_state_snapshot(
        &self,
        before_enqueue: impl FnOnce(),
        task: impl FnOnce() -> bool + Send + 'static,
    ) -> std::io::Result<()> {
        let queue = match self.start_state_snapshot_writer() {
            Ok(queue) => queue,
            Err(err) => {
                before_enqueue();
                return Err(err);
            }
        };
        queue.enqueue(before_enqueue, Box::new(task))
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
        let snapshot_writer = self
            .state_snapshot_writer
            .lock()
            .expect("state snapshot writer lock is not poisoned")
            .take();
        let mut panicked = false;
        if let Some(writer) = snapshot_writer {
            panicked |= writer.join().is_err();
        }
        let tasks = std::mem::take(
            &mut *self
                .storage_tasks
                .lock()
                .expect("storage tasks lock is not poisoned"),
        );
        for task in tasks {
            panicked |= task.join().is_err();
        }
        if panicked {
            return Err(std::io::Error::other("storage worker panicked").into());
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn block_state_snapshot_writes(&self) {
        *self
            .state_snapshot_test_gate
            .0
            .lock()
            .expect("state snapshot test gate is not poisoned") = true;
    }

    #[cfg(test)]
    pub(crate) fn release_state_snapshot_writes(&self) {
        let (blocked, changed) = &*self.state_snapshot_test_gate;
        *blocked
            .lock()
            .expect("state snapshot test gate is not poisoned") = false;
        changed.notify_all();
    }

    #[cfg(test)]
    pub(crate) fn wait_for_state_snapshot_test_gate(&self) {
        let (blocked, changed) = &*self.state_snapshot_test_gate;
        let mut blocked = blocked
            .lock()
            .expect("state snapshot test gate is not poisoned");
        while *blocked {
            blocked = changed
                .wait(blocked)
                .expect("state snapshot test gate is not poisoned");
        }
    }

    #[cfg(test)]
    pub(crate) fn active_state_snapshot_tasks(&self) -> usize {
        self.active_state_snapshot_tasks.load(Ordering::Acquire)
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
