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

use crate::{
    cache::BeaconCacheDB,
    errors::StoreError,
    tables::{
        beacon::{
            beacon_block::BeaconBlockTable,
            slot_index::BeaconSlotIndexTable,
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
        self.cache_state(block_root, state.clone());
        let parent = self
            .summaries()
            .get(state.latest_block_header.parent_root)?;
        let Some(parent) = parent else {
            // Nothing to replay from, as for the checkpoint sync anchor.
            return self.store_whole(block_root, &state);
        };

        self.summaries().insert(
            block_root,
            StateSummary {
                slot: state.slot,
                stored_whole: false,
            },
        )?;
        if compute_epoch_at_slot(state.slot) > compute_epoch_at_slot(parent.slot) {
            self.store_whole_in_background(block_root, state);
        }
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
        if cache.pruning_states.swap(true, Ordering::AcqRel) {
            // The running pruning covers this block's ancestors; the next finalization catches up.
            return;
        }
        let table = Self {
            db: self.db.clone(),
            data_dir: self.data_dir.clone(),
            cache: Some(cache.clone()),
        };
        thread::spawn(move || {
            match table.prune_finalized(finalized_root) {
                Ok(0) => {}
                Ok(pruned) => info!("Pruned {pruned} finalized states"),
                Err(err) => warn!("Failed to prune finalized states: {err:?}"),
            }
            cache.pruning_states.store(false, Ordering::Release);
        });
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

            // States stored in redb before whole states moved to files have no summary. Their
            // blocks are in the slot index, which holds small values and is cheap to scan.
            let mut legacy_states = write_txn.open_table(Self::TABLE_DEFINITION)?;
            if !legacy_states.is_empty()? {
                let slot_index = write_txn.open_table(BeaconSlotIndexTable::TABLE_DEFINITION)?;
                for entry in slot_index.range(..finalized.slot)? {
                    let root = entry?.1.value();
                    if legacy_states.remove(root)?.is_some() {
                        old_roots.insert(root);
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
    fn remove_unrecorded_state_files(&self) -> Result<(), StoreError> {
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
        let state = match summary {
            Some(summary) if summary.stored_whole => {
                Some(read_state_file(&self.data_dir, block_root)?)
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
        Ok(Some(state))
    }

    /// Stores `state` whole and records it in its summary. While the write runs the state is
    /// pending: readable from memory, and its file is kept by `remove_unrecorded_state_files`.
    fn store_whole(&self, block_root: B256, state: &Arc<BeaconState>) -> Result<(), StoreError> {
        self.set_pending(block_root, Some(state));
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
        self.set_pending(block_root, None);
        stored
    }

    fn set_pending(&self, block_root: B256, state: Option<&Arc<BeaconState>>) {
        if let Some(cache) = &self.cache
            && let Ok(mut pending) = cache.pending_state_snapshots.lock()
        {
            match state {
                Some(state) => pending.insert(block_root, state.clone()),
                None => pending.remove(&block_root),
            };
        }
    }

    /// Stores `state` whole on another thread, keeping it readable from memory until the write
    /// commits. Its summary is already stored, and until then it is rebuilt from an older state.
    fn store_whole_in_background(&self, block_root: B256, state: Arc<BeaconState>) {
        let Some(cache) = self.cache.clone() else {
            if let Err(err) = self.store_whole(block_root, &state) {
                warn!("Failed to store state {block_root}: {err:?}");
            }
            return;
        };
        self.set_pending(block_root, Some(&state));
        let table = Self {
            db: self.db.clone(),
            data_dir: self.data_dir.clone(),
            cache: Some(cache.clone()),
        };
        thread::spawn(move || {
            if let Err(err) = table.store_whole_if_recorded(block_root, &state) {
                warn!("Failed to store state {block_root}: {err:?}");
            }
            table.set_pending(block_root, None);
        });
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
