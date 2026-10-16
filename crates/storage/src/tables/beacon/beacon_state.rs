use std::{
    collections::HashSet,
    fs,
    io::{ErrorKind, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, atomic::Ordering},
    thread,
};

use alloy_primitives::B256;
use ream_consensus_beacon::electra::beacon_state::BeaconState;
use ream_consensus_misc::misc::compute_epoch_at_slot;
use redb::{
    Database, Durability, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition,
};
use snap::raw::{Decoder, Encoder};
use ssz::{Decode, Encode};
use tracing::{info, warn};
use tree_hash::TreeHash;

use crate::{
    cache::BeaconCacheDB,
    errors::StoreError,
    tables::{
        beacon::{
            beacon_block::BeaconBlockTable,
            state_summaries::{BeaconStateSummariesTable, StateSummary},
        },
        ssz_encoder::SSZEncoding,
        table::REDBTable,
    },
};

pub(crate) const STATE_FOLDER_NAME: &str = "beacon_states";

/// Post-states of imported blocks.
///
/// Writing a whole mainnet state takes about a second, so only some states are stored whole: the
/// first state of each epoch on a chain, and a state whose parent's state is not recorded. Every
/// other state is recorded in the state summaries table and rebuilt on demand by replaying blocks
/// onto the nearest ancestor whose state is stored whole. Recent states stay in memory, so block
/// import and fork choice rarely rebuild one.
///
/// Whole states are files in the data directory rather than redb values: redb reads a value's
/// bytes whenever it reaches the value's page, so deleting, iterating or even checking for a
/// 250 MB state read all of it, and writing one held the database's only write lock.
pub struct BeaconStateTable {
    pub db: Arc<Database>,
    pub data_dir: PathBuf,
    pub cache: Option<Arc<BeaconCacheDB>>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct PreparedStateImport {
    pub(crate) summary: StateSummary,
    snapshot_after_commit: bool,
    wrote_state_file: bool,
}

/// Table definition for the Beacon State table, which held whole states before they moved to
/// files. Its states are still read, and deleted once finalized.
///
/// Key: block_root
/// Value: BeaconState
impl REDBTable for BeaconStateTable {
    const TABLE_DEFINITION: TableDefinition<'_, SSZEncoding<B256>, SSZEncoding<BeaconState>> =
        TableDefinition::new("beacon_state");

    type Key = B256;

    type KeyTableDefinition = SSZEncoding<B256>;

    type Value = BeaconState;

    type ValueTableDefinition = SSZEncoding<BeaconState>;

    fn database(&self) -> Arc<Database> {
        self.db.clone()
    }

    fn get<'a>(
        &self,
        key: <Self::KeyTableDefinition as redb::Value>::SelfType<'a>,
    ) -> Result<Option<Self::Value>, StoreError> {
        Ok(self.get_shared(key)?.map(Arc::unwrap_or_clone))
    }

    fn contains_key<'a>(
        &self,
        key: <Self::KeyTableDefinition as redb::Value>::SelfType<'a>,
    ) -> Result<bool, StoreError> {
        if self.in_memory(key).is_some() || self.summaries().contains_key(key)? {
            return Ok(true);
        }
        let read_txn = self.database().begin_read()?;
        let table = read_txn.open_table(Self::TABLE_DEFINITION)?;
        Ok(table.get(key)?.is_some())
    }

    fn insert<'a>(
        &self,
        key: <Self::KeyTableDefinition as redb::Value>::SelfType<'a>,
        value: <Self::ValueTableDefinition as redb::Value>::SelfType<'a>,
    ) -> Result<(), StoreError> {
        self.insert_shared(key, Arc::new(value))
    }

    fn remove<'a>(
        &self,
        key: <Self::KeyTableDefinition as redb::Value>::SelfType<'a>,
    ) -> Result<Option<Self::Value>, StoreError> {
        let state = self.get(key)?;
        if let Some(cache) = &self.cache {
            if let Ok(mut states) = cache.states.lock() {
                states.pop(&key);
            }
            if let Ok(mut pending) = cache.pending_state_snapshots.lock() {
                pending.remove(&key);
            }
        }

        let write_txn = self.database().begin_write()?;
        {
            write_txn
                .open_table(BeaconStateSummariesTable::TABLE_DEFINITION)?
                .remove(key)?;
            write_txn.open_table(Self::TABLE_DEFINITION)?.remove(key)?;
        }
        write_txn.commit()?;
        remove_state_file(&self.data_dir, key)?;
        Ok(state)
    }
}

impl BeaconStateTable {
    /// Prepare a block-import state for the database transaction without publishing it to caches.
    /// Whole state files are written first and removed if the transaction aborts; replay summaries
    /// are inserted by the caller in the same transaction as the block.
    pub(crate) fn prepare_import(
        &self,
        block_root: B256,
        state: &Arc<BeaconState>,
    ) -> Result<PreparedStateImport, StoreError> {
        let parent = self
            .summaries()
            .get(state.latest_block_header.parent_root)?;
        let snapshot_after_commit = parent.is_some_and(|parent| {
            compute_epoch_at_slot(state.slot) > compute_epoch_at_slot(parent.slot)
        });
        // Without a cache there is no background writer or pending overlay, so epoch snapshots
        // must be complete before the database publishes a stored-whole summary.
        let wrote_state_file = parent.is_none() || (snapshot_after_commit && self.cache.is_none());
        if wrote_state_file {
            self.set_pending(block_root, state);
            if let Err(err) = write_state_file(&self.data_dir, block_root, state) {
                self.clear_pending(block_root, state);
                return Err(err);
            }
        }
        Ok(PreparedStateImport {
            summary: StateSummary {
                slot: state.slot,
                stored_whole: wrote_state_file,
            },
            snapshot_after_commit,
            wrote_state_file,
        })
    }

    /// Publish a state only after its block and summary transaction committed.
    pub(crate) fn finish_import(
        &self,
        block_root: B256,
        state: Arc<BeaconState>,
        prepared: PreparedStateImport,
    ) {
        self.cache_state(block_root, state.clone());
        if prepared.wrote_state_file {
            self.clear_pending(block_root, &state);
        } else if prepared.snapshot_after_commit {
            // A cached table retains the state if spawning or writing fails, and shutdown retries
            // it. The no-cache case was written synchronously in `prepare_import`.
            let _ = self.store_whole_in_background(block_root, state);
        }
    }

    /// Remove a whole state file prepared for a transaction that did not commit.
    pub(crate) fn abort_import(
        &self,
        block_root: B256,
        state: &Arc<BeaconState>,
        prepared: PreparedStateImport,
    ) -> Result<(), StoreError> {
        self.clear_pending(block_root, state);
        // A committed summary may already point at this root's file when the block is imported
        // again; that file must stay.
        if prepared.wrote_state_file && !self.is_stored_whole(block_root)? {
            remove_state_file(&self.data_dir, block_root)?;
        }
        Ok(())
    }

    /// The state after the block at `block_root`, shared with the in-memory cache instead of
    /// copied. Callers that only read the state should use this over `get`.
    pub fn get_shared(&self, block_root: B256) -> Result<Option<Arc<BeaconState>>, StoreError> {
        if let Some(state) = self.in_memory(block_root) {
            return Ok(Some(state));
        }
        let summary = self.summaries().get(block_root)?;
        if let Some(state) = self.read_stored(block_root, summary)? {
            return Ok(Some(state));
        }
        if summary.is_none() {
            return Ok(None);
        }
        let Some(state) = self.rebuild(block_root)? else {
            return Ok(None);
        };
        let state = Arc::new(state);
        self.cache_state(block_root, state.clone());
        Ok(Some(state))
    }

    /// Records `state` as the state after the block at `block_root`.
    pub fn insert_shared(
        &self,
        block_root: B256,
        state: Arc<BeaconState>,
    ) -> Result<(), StoreError> {
        let _accepting = BeaconCacheDB::accept_writes(self.cache.as_ref())?;
        let prepared = self.prepare_import(block_root, &state)?;
        if let Err(err) = self.summaries().insert(block_root, prepared.summary) {
            let _ = self
                .abort_import(block_root, &state, prepared)
                .inspect_err(|err| {
                    warn!("Failed to remove state file of aborted insert {block_root}: {err:?}")
                });
            return Err(err);
        }
        self.finish_import(block_root, state, prepared);
        Ok(())
    }

    /// Whether the state after the block at `block_root` is stored whole.
    pub fn is_stored_whole(&self, block_root: B256) -> Result<bool, StoreError> {
        Ok(self
            .summaries()
            .get(block_root)?
            .is_some_and(|summary| summary.stored_whole))
    }

    /// Deletes, on another thread, the states of blocks before the finalized block, which nothing
    /// can import onto or vote for any more. The finalized state is stored whole first, so the
    /// states after it can still be rebuilt; that can mean replaying an epoch of blocks, which
    /// block import should not wait for. Without a cache the pruning runs on this thread.
    pub fn prune_finalized_in_background(&self, finalized_root: B256) {
        let Some(cache) = self.cache.clone() else {
            if let Err(err) = self.prune_finalized(finalized_root) {
                warn!("Failed to prune finalized states: {err:?}");
            }
            return;
        };
        let Ok(_accepting) = cache.storage_write_guard() else {
            return;
        };
        if cache.pruning_states.swap(true, Ordering::AcqRel) {
            // The running pruning covers this block's ancestors; the next finalization catches up.
            return;
        }
        let table = Self {
            db: self.db.clone(),
            data_dir: self.data_dir.clone(),
            cache: Some(cache.clone()),
        };
        let worker_cache = cache.clone();
        if let Err(err) = cache.spawn_storage_task(move || {
            match table.prune_finalized(finalized_root) {
                Ok(0) => {}
                Ok(pruned) => info!("Pruned {pruned} finalized states"),
                Err(err) => warn!("Failed to prune finalized states: {err:?}"),
            }
            worker_cache.pruning_states.store(false, Ordering::Release);
        }) {
            cache.pruning_states.store(false, Ordering::Release);
            warn!("Failed to start state pruning: {err:?}");
        }
    }

    /// Deletes the states of blocks before the finalized block and returns how many it deleted.
    pub fn prune_finalized(&self, finalized_root: B256) -> Result<usize, StoreError> {
        let Some(finalized) = self.summaries().get(finalized_root)? else {
            return Ok(0);
        };
        if !finalized.stored_whole {
            if self.is_pending(finalized_root) {
                // Its write is still running; prune at the next finalization instead.
                return Ok(0);
            }
            let state = self.get_shared(finalized_root)?.ok_or_else(|| {
                StoreError::StateRebuild(format!("finalized state {finalized_root} is missing"))
            })?;
            self.store_whole(finalized_root, &state)?;
        }

        let mut whole_roots = Vec::new();
        let write_txn = self.database().begin_write()?;
        let pruned = {
            let mut summaries =
                write_txn.open_table(BeaconStateSummariesTable::TABLE_DEFINITION)?;
            let mut old_roots = HashSet::new();
            for entry in summaries.iter()? {
                let (root, summary) = entry?;
                let summary = summary.value();
                if summary.slot < finalized.slot {
                    let root = root.value();
                    if summary.stored_whole {
                        whole_roots.push(root);
                    }
                    old_roots.insert(root);
                }
            }
            for root in &old_roots {
                summaries.remove(*root)?;
            }

            // States stored in redb before whole states moved to files have no summary. Scan the
            // block table because it retains every fork root, unlike the one-root-per-slot index.
            // The legacy state values are large, so never iterate that table directly.
            let mut legacy_states = write_txn.open_table(Self::TABLE_DEFINITION)?;
            if !legacy_states.is_empty()? {
                let blocks = write_txn.open_table(BeaconBlockTable::TABLE_DEFINITION)?;
                for entry in blocks.iter()? {
                    let (root, block) = entry?;
                    if block.value().message.slot < finalized.slot {
                        let root = root.value();
                        if legacy_states.remove(root)?.is_some() {
                            old_roots.insert(root);
                        }
                    }
                }
            }
            old_roots.len()
        };
        write_txn.commit()?;

        for root in whole_roots {
            remove_state_file(&self.data_dir, root)?;
        }
        self.remove_unrecorded_state_files()?;
        Ok(pruned)
    }

    /// Deletes state files that no summary records as stored whole, which a crash during a write
    /// leaves behind. A write marks its state pending before creating any file and stops only after
    /// recording it, so each file is checked and deleted with the pending states locked: a
    /// temporary file found while nothing is pending, or a state file that is neither pending nor
    /// recorded, belongs to no running write.
    ///
    /// The state directory is synced at the end even when nothing was deleted here, so the
    /// deletions `prune_finalized` makes just before calling this are durable too. Without the
    /// sync a power loss could bring deleted files back.
    pub(crate) fn remove_unrecorded_state_files(&self) -> Result<(), StoreError> {
        let no_pending = Mutex::default();
        let pending = self
            .cache
            .as_ref()
            .map_or(&no_pending, |cache| &cache.pending_state_snapshots);
        for entry in fs::read_dir(self.data_dir.join(STATE_FOLDER_NAME))? {
            let path = entry?.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let root = name
                .strip_suffix(".ssz_snappy")
                .and_then(|root| root.parse::<B256>().ok());
            let pending = pending
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let unused = match root {
                Some(root) => !pending.contains_key(&root) && !self.is_stored_whole(root)?,
                None => pending.is_empty(),
            };
            if unused {
                fs::remove_file(&path)?;
            }
        }
        fs::File::open(self.data_dir.join(STATE_FOLDER_NAME))?.sync_all()?;
        Ok(())
    }

    fn summaries(&self) -> BeaconStateSummariesTable {
        BeaconStateSummariesTable {
            db: self.db.clone(),
        }
    }

    fn in_memory(&self, block_root: B256) -> Option<Arc<BeaconState>> {
        let cache = self.cache.as_ref()?;
        // LruCache::get requires mutable access to update LRU order
        if let Ok(mut states) = cache.states.lock()
            && let Some(state) = states.get(&block_root)
        {
            return Some(state.clone());
        }
        cache
            .pending_state_snapshots
            .lock()
            .ok()?
            .get(&block_root)
            .cloned()
    }

    /// The state if it is stored whole: in a file when its summary says so, or in the legacy redb
    /// table when it has no summary.
    fn read_stored(
        &self,
        block_root: B256,
        summary: Option<StateSummary>,
    ) -> Result<Option<Arc<BeaconState>>, StoreError> {
        // A checkpoint at its block's slot shares the block's post-state. It may still be
        // cached after the smaller block-state LRU evicted it. Advanced checkpoint states
        // cannot be used here: their skipped slots have already changed the state.
        if let (Some(summary), Some(cache)) = (summary, &self.cache) {
            let state = cache.checkpoint_states.lock().ok().and_then(|states| {
                states.iter().find_map(|(checkpoint, state)| {
                    (checkpoint.root == block_root && state.slot == summary.slot)
                        .then(|| state.clone())
                })
            });
            if let Some(state) = state {
                self.cache_state(block_root, state.clone());
                return Ok(Some(state));
            }
        }
        let state = match summary {
            Some(summary) if summary.stored_whole => {
                let state = read_state_file(&self.data_dir, block_root)?;
                self.verify_state_root(block_root, &state)?;
                Some(state)
            }
            Some(_) => None,
            None => {
                let read_txn = self.database().begin_read()?;
                let table = read_txn.open_table(Self::TABLE_DEFINITION)?;
                table.get(block_root)?.map(|value| value.value())
            }
        };
        let Some(state) = state.map(Arc::new) else {
            return Ok(None);
        };
        self.cache_state(block_root, state.clone());
        Ok(Some(state))
    }

    fn is_pending(&self, block_root: B256) -> bool {
        self.cache.as_ref().is_some_and(|cache| {
            cache
                .pending_state_snapshots
                .lock()
                .is_ok_and(|pending| pending.contains_key(&block_root))
        })
    }

    fn cache_state(&self, block_root: B256, state: Arc<BeaconState>) {
        let Some(cache) = &self.cache else {
            return;
        };
        let evicted = cache
            .states
            .lock()
            .ok()
            .and_then(|mut states| states.push(block_root, state));
        if let Some((_, evicted)) = evicted {
            drop_state_in_background(evicted);
        }
    }

    /// Replays the blocks from the nearest ancestor whose state is in memory or stored whole.
    /// Returns `None` when that ancestor was pruned, which happens to a fork that finalization
    /// left behind.
    fn rebuild(&self, block_root: B256) -> Result<Option<BeaconState>, StoreError> {
        let blocks = BeaconBlockTable {
            db: self.db.clone(),
            cache: self.cache.clone(),
        };
        let mut to_replay = Vec::new();
        let mut root = block_root;
        let (ancestor_root, ancestor_state) = loop {
            let block = blocks.get(root)?.ok_or_else(|| {
                StoreError::StateRebuild(format!("block {root} to replay is missing"))
            })?;
            let parent_root = block.message.parent_root;
            to_replay.push(block);
            if let Some(state) = self.in_memory(parent_root) {
                break (parent_root, state);
            }
            let parent = self.summaries().get(parent_root)?;
            if let Some(state) = self.read_stored(parent_root, parent)? {
                break (parent_root, state);
            }
            if parent.is_none() {
                return Ok(None);
            }
            root = parent_root;
        };

        // Each replayed block's pre-state root is its parent block's state root, so replaying
        // hashes no state.
        let mut pre_state_root = blocks
            .get(ancestor_root)?
            .map(|block| block.message.state_root);
        let mut state = Arc::unwrap_or_clone(ancestor_state);
        for block in to_replay.iter().rev() {
            state.replay_block(block, pre_state_root).map_err(|err| {
                StoreError::StateRebuild(format!(
                    "replaying block at slot {}: {err:?}",
                    block.message.slot
                ))
            })?;
            pre_state_root = Some(block.message.state_root);
        }
        let expected = to_replay
            .first()
            .expect("a rebuild always has at least the requested block")
            .message
            .state_root;
        let actual = state.tree_hash_root();
        if actual != expected {
            return Err(StoreError::StateCorruption(format!(
                "replayed state {block_root} has root {actual}, expected {expected}"
            )));
        }
        Ok(Some(state))
    }

    fn verify_state_root(&self, block_root: B256, state: &BeaconState) -> Result<(), StoreError> {
        let block = BeaconBlockTable {
            db: self.db.clone(),
            cache: self.cache.clone(),
        }
        .get(block_root)?
        .ok_or_else(|| {
            StoreError::StateCorruption(format!(
                "whole state {block_root} has no corresponding block"
            ))
        })?;
        let expected = block.message.state_root;
        let actual = state.tree_hash_root();
        if actual != expected {
            return Err(StoreError::StateCorruption(format!(
                "whole state {block_root} has root {actual}, expected {expected}"
            )));
        }
        Ok(())
    }

    /// Stores `state` whole and records it in its summary. While the write runs the state is
    /// pending: readable from memory, and its file is kept by `remove_unrecorded_state_files`.
    fn store_whole(&self, block_root: B256, state: &Arc<BeaconState>) -> Result<(), StoreError> {
        self.set_pending(block_root, state);
        let stored = write_state_file(&self.data_dir, block_root, state).and_then(|()| {
            let mut write_txn = self.database().begin_write()?;
            write_txn.set_durability(Durability::Immediate)?;
            write_txn
                .open_table(BeaconStateSummariesTable::TABLE_DEFINITION)?
                .insert(
                    block_root,
                    StateSummary {
                        slot: state.slot,
                        stored_whole: true,
                    },
                )?;
            write_txn.commit()?;
            Ok(())
        });
        // A synchronous insertion reports failure to its caller and must not publish an
        // unrecorded anchor as an accepted state in the pending overlay.
        self.clear_pending(block_root, state);
        stored
    }

    fn clear_pending(&self, block_root: B256, state: &Arc<BeaconState>) {
        if let Some(cache) = &self.cache
            && let Ok(mut pending) = cache.pending_state_snapshots.lock()
            && pending
                .get(&block_root)
                .is_some_and(|current| Arc::ptr_eq(current, state))
        {
            pending.remove(&block_root);
        }
    }

    /// Retry snapshots retained after a write/enqueue failure, once workers have stopped.
    pub(crate) fn flush(&self) -> Result<(), StoreError> {
        let Some(cache) = &self.cache else {
            return Ok(());
        };
        let snapshots: Vec<_> = cache
            .pending_state_snapshots
            .lock()
            .expect("pending state snapshots lock is not poisoned")
            .iter()
            .map(|(root, state)| (*root, state.clone()))
            .collect();
        for (root, state) in snapshots {
            self.store_whole_if_recorded(root, &state)?;
            self.clear_pending(root, &state);
        }
        Ok(())
    }

    fn set_pending(&self, block_root: B256, state: &Arc<BeaconState>) {
        if let Some(cache) = &self.cache
            && let Ok(mut pending) = cache.pending_state_snapshots.lock()
        {
            pending.insert(block_root, state.clone());
        }
    }

    /// Stores `state` whole on another thread, keeping it readable from memory until the write
    /// commits. Its summary is already stored, and until then it is rebuilt from an older state.
    fn store_whole_in_background(
        &self,
        block_root: B256,
        state: Arc<BeaconState>,
    ) -> Result<(), StoreError> {
        let Some(cache) = self.cache.clone() else {
            return self.store_whole_if_recorded(block_root, &state);
        };
        let table = Self {
            db: self.db.clone(),
            data_dir: self.data_dir.clone(),
            cache: Some(cache.clone()),
        };
        let pending_cache = cache.clone();
        let pending_state = state.clone();
        #[cfg(test)]
        let worker_cache = cache.clone();
        if let Err(err) = cache.enqueue_state_snapshot(
            move || {
                pending_cache
                    .pending_state_snapshots
                    .lock()
                    .expect("pending state snapshots lock is not poisoned")
                    .insert(block_root, pending_state);
            },
            move || {
                #[cfg(test)]
                worker_cache.wait_for_state_snapshot_test_gate();
                if let Err(err) = table.store_whole_if_recorded(block_root, &state) {
                    warn!("Failed to store state {block_root}: {err:?}");
                    return false;
                }
                table.clear_pending(block_root, &state);
                true
            },
        ) {
            // The committed summary remains replayable if shutdown closed the queue before this
            // state was admitted. A writer-start failure retains the state in the pending overlay.
            warn!("Failed to enqueue state snapshot {block_root}: {err:?}");
        }
        Ok(())
    }

    /// `store_whole` for a state whose summary is already stored, unless the summary was removed
    /// or pruned meanwhile, so that no file outlives its summary.
    fn store_whole_if_recorded(
        &self,
        block_root: B256,
        state: &BeaconState,
    ) -> Result<(), StoreError> {
        write_state_file(&self.data_dir, block_root, state)?;
        let mut write_txn = self.database().begin_write()?;
        write_txn.set_durability(Durability::Immediate)?;
        let recorded = {
            let mut summaries =
                write_txn.open_table(BeaconStateSummariesTable::TABLE_DEFINITION)?;
            let summary = summaries.get(block_root)?.map(|summary| summary.value());
            if let Some(mut summary) = summary {
                summary.stored_whole = true;
                summaries.insert(block_root, summary)?;
            }
            summary.is_some()
        };
        write_txn.commit()?;
        if !recorded {
            remove_state_file(&self.data_dir, block_root)?;
        }
        Ok(())
    }
}

fn state_file_path(data_dir: &Path, block_root: B256) -> PathBuf {
    data_dir
        .join(STATE_FOLDER_NAME)
        .join(format!("{block_root}.ssz_snappy"))
}

/// Writes the state to a temporary file and renames it into place once it is on disk, so a state
/// file is either complete or absent.
fn write_state_file(
    data_dir: &Path,
    block_root: B256,
    state: &BeaconState,
) -> Result<(), StoreError> {
    let encoded = Encoder::new().compress_vec(&state.as_ssz_bytes())?;
    let mut file = tempfile::NamedTempFile::new_in(data_dir.join(STATE_FOLDER_NAME))?;
    file.write_all(&encoded)?;
    file.as_file().sync_all()?;
    file.persist(state_file_path(data_dir, block_root))
        .map_err(|err| err.error)?;
    // The rename is durable only once the directory is synced; the summary that names this file
    // is committed after this returns.
    fs::File::open(data_dir.join(STATE_FOLDER_NAME))?.sync_all()?;
    Ok(())
}

fn read_state_file(data_dir: &Path, block_root: B256) -> Result<BeaconState, StoreError> {
    let encoded = fs::read(state_file_path(data_dir, block_root))?;
    let bytes = Decoder::new().decompress_vec(&encoded)?;
    BeaconState::from_ssz_bytes(&bytes)
        .map_err(|err| StoreError::DecodeError(format!("state {block_root}: {err:?}")))
}

fn remove_state_file(data_dir: &Path, block_root: B256) -> Result<(), StoreError> {
    match fs::remove_file(state_file_path(data_dir, block_root)) {
        Err(err) if err.kind() != ErrorKind::NotFound => Err(err.into()),
        _ => Ok(()),
    }
}

/// Drops `state` on another thread when this is its last reference. Freeing the millions of
/// allocations in a mainnet state takes tens of milliseconds.
pub(crate) fn drop_state_in_background(state: Arc<BeaconState>) {
    if Arc::strong_count(&state) == 1 {
        thread::spawn(move || drop(state));
    }
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        thread,
        time::{Duration, Instant},
    };

    use ream_consensus_beacon::electra::beacon_block::{BeaconBlock, SignedBeaconBlock};
    use ream_consensus_misc::constants::beacon::SLOTS_PER_EPOCH;
    use ream_network_spec::networks::{SEPOLIA, set_beacon_network_spec};
    use tempdir::TempDir;

    use super::*;
    use crate::{
        cache::{BeaconCacheDB, STATE_SNAPSHOT_PENDING_LIMIT},
        db::{ReamDB, beacon::BeaconDB},
        test_utils::sepolia_state,
    };

    fn child_of(parent_root: B256, parent: &BeaconState, slot: u64) -> Arc<BeaconState> {
        let mut state = parent.clone();
        state.latest_block_header.parent_root = parent_root;
        state.slot = slot;
        Arc::new(state)
    }

    fn insert_block_for_state(db: &BeaconDB, root: B256, state: &BeaconState) {
        db.block_provider()
            .insert(
                root,
                SignedBeaconBlock {
                    message: BeaconBlock {
                        slot: state.slot,
                        parent_root: state.latest_block_header.parent_root,
                        state_root: state.tree_hash_root(),
                        ..Default::default()
                    },
                    signature: Default::default(),
                },
            )
            .unwrap();
    }

    fn sepolia_block(name: &str) -> SignedBeaconBlock {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
            "../../testing/gossip-validation/tests/assets/sepolia/blocks/{name}.ssz_snappy"
        ));
        let bytes = Decoder::new()
            .decompress_vec(&fs::read(path).unwrap())
            .unwrap();
        SignedBeaconBlock::from_ssz_bytes(&bytes).unwrap()
    }

    fn sepolia_state_file(name: &str) -> Arc<BeaconState> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
            "../../testing/gossip-validation/tests/assets/sepolia/states/{name}.ssz_snappy"
        ));
        let bytes = Decoder::new()
            .decompress_vec(&fs::read(path).unwrap())
            .unwrap();
        Arc::new(BeaconState::from_ssz_bytes(&bytes).unwrap())
    }

    /// The anchor has nothing to replay from and is stored whole; a child in the same epoch only
    /// gets a summary; a child in a later epoch is stored whole, synchronously without a cache.
    #[test]
    fn insert_shared_stores_anchors_and_epoch_starts_whole() {
        let dir = TempDir::new("ream_insert_shared").unwrap();
        let db = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        let states = db.state_provider();
        let anchor = sepolia_state();
        let anchor_root = B256::repeat_byte(1);
        let same_epoch_root = B256::repeat_byte(2);
        let next_epoch_root = B256::repeat_byte(3);
        let file = |root: B256| state_file_path(dir.path(), root);

        insert_block_for_state(&db, anchor_root, &anchor);
        states.insert_shared(anchor_root, anchor.clone()).unwrap();
        assert!(states.is_stored_whole(anchor_root).unwrap());
        assert!(file(anchor_root).exists());

        let same_epoch = child_of(anchor_root, &anchor, anchor.slot + 1);
        insert_block_for_state(&db, same_epoch_root, &same_epoch);
        states.insert_shared(same_epoch_root, same_epoch).unwrap();
        assert!(!states.is_stored_whole(same_epoch_root).unwrap());
        assert!(!file(same_epoch_root).exists());

        let next_epoch = child_of(anchor_root, &anchor, anchor.slot + SLOTS_PER_EPOCH);
        insert_block_for_state(&db, next_epoch_root, &next_epoch);
        states.insert_shared(next_epoch_root, next_epoch).unwrap();
        assert!(states.is_stored_whole(next_epoch_root).unwrap());
        assert!(file(next_epoch_root).exists());
        assert_eq!(
            states.get_shared(anchor_root).unwrap().as_deref(),
            Some(anchor.as_ref())
        );
    }

    /// With a cache, the inserted state is shared from memory and nothing stays pending once a
    /// synchronous write finishes.
    #[test]
    fn insert_shared_caches_the_inserted_state() {
        let dir = TempDir::new("ream_insert_shared_cached").unwrap();
        let cache = Arc::new(BeaconCacheDB::new());
        let db = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap()
            .with_cache(cache.clone());
        let anchor = sepolia_state();
        let root = B256::repeat_byte(1);

        insert_block_for_state(&db, root, &anchor);
        db.state_provider()
            .insert_shared(root, anchor.clone())
            .unwrap();
        let shared = db.state_provider().get_shared(root).unwrap().unwrap();
        assert!(Arc::ptr_eq(&shared, &anchor));
        assert!(cache.pending_state_snapshots.lock().unwrap().is_empty());
    }

    #[test]
    fn evicted_block_state_reuses_only_an_unadvanced_checkpoint_state() {
        let dir = TempDir::new("ream_checkpoint_block_state").unwrap();
        let cache = Arc::new(BeaconCacheDB::default());
        let db = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap()
            .with_cache(cache.clone());
        let state = sepolia_state();
        let root = B256::repeat_byte(1);
        db.state_provider()
            .insert_shared(root, state.clone())
            .unwrap();
        let checkpoint = ream_consensus_misc::checkpoint::Checkpoint {
            epoch: state.get_current_epoch(),
            root,
        };
        db.checkpoint_states_provider()
            .insert_shared(checkpoint, state.clone());
        cache.states.lock().unwrap().clear();

        let reused = db.state_provider().get_shared(root).unwrap().unwrap();
        assert!(Arc::ptr_eq(&reused, &state));
        assert!(cache.states.lock().unwrap().contains(&root));

        let mut advanced = (*state).clone();
        advanced.process_slots(state.slot + 1).unwrap();
        db.checkpoint_states_provider()
            .insert_shared(checkpoint, Arc::new(advanced));
        cache.states.lock().unwrap().clear();

        let loaded = db.state_provider().get_shared(root).unwrap().unwrap();
        assert!(!Arc::ptr_eq(&loaded, &state));
        assert_eq!(loaded.as_ref(), state.as_ref());
    }

    /// State write errors propagate, a failed anchor never becomes visible, and a failed
    /// background snapshot stays readable until a later drain stores it.
    #[test]
    fn state_write_failures_are_reported_and_retried() {
        let dir = TempDir::new("ream_state_write_failure").unwrap();
        let cache = Arc::new(BeaconCacheDB::new());
        let db = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap()
            .with_cache(cache.clone());
        // A file where the state directory should be makes every state file write fail.
        let mut bad_db = db.clone();
        bad_db.data_dir = dir.path().join("file_instead_of_directory");
        std::fs::write(&bad_db.data_dir, b"not a directory").unwrap();
        let root = B256::repeat_byte(0x71);
        let parent = B256::repeat_byte(0x72);
        let mut state = Arc::unwrap_or_clone(sepolia_state());
        state.slot = 32;

        // A failed anchor insertion must not remain visible through the state cache.
        let anchor = Arc::new(state.clone());
        assert!(bad_db.state_provider().insert_shared(root, anchor).is_err());
        assert!(db.state_provider().get_shared(root).unwrap().is_none());
        assert!(cache.pending_state_snapshots.lock().unwrap().is_empty());

        // An epoch start whose parent is recorded in an earlier epoch.
        db.state_provider()
            .summaries()
            .insert(
                parent,
                StateSummary {
                    slot: 0,
                    stored_whole: true,
                },
            )
            .unwrap();
        state.latest_block_header.parent_root = parent;
        let child = Arc::new(state);
        insert_block_for_state(&db, root, &child);

        // Without a cache, the epoch snapshot is written synchronously and its error returned.
        let mut uncached = bad_db.state_provider();
        uncached.cache = None;
        assert!(uncached.insert_shared(root, child.clone()).is_err());

        // A background failure keeps the accepted snapshot readable, even after LRU eviction.
        bad_db
            .state_provider()
            .insert_shared(root, child.clone())
            .unwrap();
        assert!(bad_db.flush_pending_writes().is_err());
        cache.states.lock().unwrap().clear();
        let shared = db.state_provider().get_shared(root).unwrap().unwrap();
        assert!(Arc::ptr_eq(&shared, &child));
        assert!(!db.state_provider().is_stored_whole(root).unwrap());

        // A drain with a working directory stores it, and a reopened database reads it.
        db.flush_pending_writes().unwrap();
        assert!(db.state_provider().is_stored_whole(root).unwrap());
        assert!(cache.pending_state_snapshots.lock().unwrap().is_empty());
        drop((uncached, bad_db, db, shared));
        let reopened = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        let stored = reopened.state_provider().get_shared(root).unwrap().unwrap();
        assert_eq!(stored.slot, 32);
    }

    #[test]
    fn rejects_ssz_valid_state_file_with_the_wrong_root() {
        let dir = TempDir::new("ream_corrupt_state_file").unwrap();
        let db = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        let root = B256::repeat_byte(0x81);
        let state = sepolia_state();
        insert_block_for_state(&db, root, &state);
        db.state_provider()
            .insert_shared(root, state.clone())
            .unwrap();

        let mut altered = Arc::unwrap_or_clone(state);
        altered.genesis_time += 1;
        write_state_file(dir.path(), root, &altered).unwrap();

        let err = db.state_provider().get_shared(root).unwrap_err();
        assert!(matches!(err, StoreError::StateCorruption(_)));
        assert!(err.to_string().contains("whole state"));
    }

    #[test]
    fn rejects_replay_result_with_the_wrong_root() {
        set_beacon_network_spec(SEPOLIA.clone());
        let dir = TempDir::new("ream_corrupt_state_replay").unwrap();
        let db = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        let grandparent_state = sepolia_state();
        let parent_state = sepolia_state_file("parent_state_9552075");
        let grandparent_block = sepolia_block("grandparent_9552074");
        let grandparent_root = grandparent_block.message.tree_hash_root();
        assert_eq!(
            grandparent_block.message.state_root,
            grandparent_state.tree_hash_root()
        );

        db.block_provider()
            .insert(grandparent_root, grandparent_block)
            .unwrap();
        db.state_provider()
            .insert_shared(grandparent_root, grandparent_state)
            .unwrap();

        let mut parent_block = sepolia_block("parent_9552075");
        assert_eq!(parent_block.message.parent_root, grandparent_root);
        assert_eq!(
            parent_block.message.state_root,
            parent_state.tree_hash_root()
        );
        parent_block.message.state_root = B256::repeat_byte(0x82);
        let parent_root = parent_block.message.tree_hash_root();
        db.block_provider()
            .insert(parent_root, parent_block)
            .unwrap();
        db.state_provider()
            .insert_shared(parent_root, parent_state)
            .unwrap();

        let err = db.state_provider().get_shared(parent_root).unwrap_err();
        assert!(matches!(err, StoreError::StateCorruption(_)));
        assert!(err.to_string().contains("replayed state"));
    }

    #[test]
    fn snapshot_writer_bounds_workers_and_pending_states() {
        let dir = TempDir::new("ream_bounded_state_snapshots").unwrap();
        let cache = Arc::new(BeaconCacheDB::new());
        cache.block_state_snapshot_writes();
        let db = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap()
            .with_cache(cache.clone());
        let states = db.state_provider();
        let state_count = STATE_SNAPSHOT_PENDING_LIMIT + 3;
        let mut expected = Vec::with_capacity(state_count);
        let mut schedulers = Vec::with_capacity(state_count);

        for index in 0..state_count {
            let root = B256::repeat_byte(index as u8 + 1);
            let mut state = Arc::unwrap_or_clone(sepolia_state());
            state.slot += index as u64;
            let state = Arc::new(state);
            states
                .summaries()
                .insert(
                    root,
                    StateSummary {
                        slot: state.slot,
                        stored_whole: false,
                    },
                )
                .unwrap();
            states.cache_state(root, state.clone());
            expected.push((root, state.clone()));

            let table = BeaconStateTable {
                db: states.db.clone(),
                data_dir: states.data_dir.clone(),
                cache: states.cache.clone(),
            };
            schedulers.push(thread::spawn(move || {
                table.store_whole_in_background(root, state)
            }));
        }

        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline
            && (cache.active_state_snapshot_tasks() != 1
                || cache.pending_state_snapshots.lock().unwrap().len()
                    != STATE_SNAPSHOT_PENDING_LIMIT)
        {
            thread::sleep(Duration::from_millis(5));
        }
        let active = cache.active_state_snapshot_tasks();
        let pending = cache.pending_state_snapshots.lock().unwrap().len();
        let all_replayable = expected
            .iter()
            .all(|(root, _)| !states.is_stored_whole(*root).unwrap());
        let all_readable = expected.iter().all(|(root, expected_state)| {
            states
                .get_shared(*root)
                .is_ok_and(|state| state.is_some_and(|state| Arc::ptr_eq(&state, expected_state)))
        });

        cache.release_state_snapshot_writes();
        let all_scheduled = schedulers
            .into_iter()
            .all(|scheduler| scheduler.join().is_ok_and(|result| result.is_ok()));
        db.flush_pending_writes().unwrap();

        assert_eq!(active, 1);
        assert_eq!(pending, STATE_SNAPSHOT_PENDING_LIMIT);
        assert!(all_replayable);
        assert!(all_readable);
        assert!(all_scheduled);
        assert_eq!(cache.active_state_snapshot_tasks(), 0);
        assert!(cache.pending_state_snapshots.lock().unwrap().is_empty());
        assert!(
            expected
                .iter()
                .all(|(root, _)| states.is_stored_whole(*root).unwrap())
        );
    }

    #[test]
    fn prunes_all_legacy_states_at_a_duplicate_slot() {
        let dir = TempDir::new("ream_legacy_fork_state_pruning").unwrap();
        let db = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        let states = db.state_provider();
        let state = sepolia_state();
        let first_root = B256::repeat_byte(0x91);
        let second_root = B256::repeat_byte(0x92);
        let finalized_root = B256::repeat_byte(0x93);

        insert_block_for_state(&db, first_root, &state);
        insert_block_for_state(&db, second_root, &state);
        assert_eq!(
            db.slot_index_provider().get(state.slot).unwrap(),
            Some(second_root)
        );

        let write = db.db.begin_write().unwrap();
        {
            let mut legacy = write
                .open_table(BeaconStateTable::TABLE_DEFINITION)
                .unwrap();
            legacy.insert(first_root, state.as_ref().clone()).unwrap();
            legacy.insert(second_root, state.as_ref().clone()).unwrap();
        }
        write.commit().unwrap();
        states
            .summaries()
            .insert(
                finalized_root,
                StateSummary {
                    slot: state.slot + 1,
                    stored_whole: true,
                },
            )
            .unwrap();

        assert_eq!(states.prune_finalized(finalized_root).unwrap(), 2);
        assert!(!states.contains_key(first_root).unwrap());
        assert!(!states.contains_key(second_root).unwrap());
    }
}
