use std::{sync::Arc, thread};

use alloy_primitives::B256;
use ream_consensus_beacon::electra::beacon_state::BeaconState;
use ream_consensus_misc::misc::compute_epoch_at_slot;
use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};
use tracing::warn;

use crate::{
    cache::BeaconCacheDB,
    errors::StoreError,
    tables::{
        beacon::{beacon_block::BeaconBlockTable, state_summaries::BeaconStateSummariesTable},
        ssz_encoder::{SSZEncoded, SSZEncoding},
        table::REDBTable,
    },
};

const STATE_TABLE_NAME: &str = "beacon_state";

/// Post-states of imported blocks.
///
/// Writing a whole mainnet state takes about a second, so only some states are stored whole: the
/// first state of each epoch on a chain, and a state whose parent's state is not stored. Every
/// other state is recorded in the state summaries table and rebuilt on demand by replaying blocks
/// onto the nearest ancestor whose state is stored whole. Recent states stay in memory, so block
/// import and fork choice rarely rebuild one.
pub struct BeaconStateTable {
    pub db: Arc<Database>,
    pub cache: Option<Arc<BeaconCacheDB>>,
}

/// Table definition for the Beacon State table, which holds the states stored whole
///
/// Key: block_root
/// Value: BeaconState
impl REDBTable for BeaconStateTable {
    const TABLE_DEFINITION: TableDefinition<'_, SSZEncoding<B256>, SSZEncoding<BeaconState>> =
        TableDefinition::new(STATE_TABLE_NAME);

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
        if self.in_memory(key).is_some() {
            return Ok(true);
        }
        Ok(self.summaries().contains_key(key)? || self.is_stored_whole(key)?)
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
        Ok(state)
    }
}

impl BeaconStateTable {
    /// The state after the block at `block_root`, shared with the in-memory cache instead of
    /// copied. Callers that only read the state should use this over `get`.
    pub fn get_shared(&self, block_root: B256) -> Result<Option<Arc<BeaconState>>, StoreError> {
        if let Some(state) = self.in_memory_or_stored_whole(block_root)? {
            return Ok(Some(state));
        }
        if !self.summaries().contains_key(block_root)? {
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
        let parent_slot = self
            .summaries()
            .get(state.latest_block_header.parent_root)?;
        let Some(parent_slot) = parent_slot else {
            // Nothing to replay from, as for the checkpoint sync anchor.
            return self.store_whole(block_root, &state);
        };

        self.summaries().insert(block_root, state.slot)?;
        if compute_epoch_at_slot(state.slot) > compute_epoch_at_slot(parent_slot) {
            self.store_whole_in_background(block_root, state);
        }
        Ok(())
    }

    /// Deletes the states of blocks before the finalized block, which nothing can import onto or
    /// vote for any more. The finalized state is stored whole first, so the states after it can
    /// still be rebuilt. Returns how many states were deleted.
    pub fn prune_finalized(&self, finalized_root: B256) -> Result<usize, StoreError> {
        let Some(finalized_slot) = self.summaries().get(finalized_root)? else {
            return Ok(0);
        };
        if !self.is_stored_whole(finalized_root)? {
            if self.is_pending(finalized_root) {
                // Its write is still running; prune at the next finalization instead.
                return Ok(0);
            }
            let state = self.get_shared(finalized_root)?.ok_or_else(|| {
                StoreError::StateRebuild(format!("finalized state {finalized_root} is missing"))
            })?;
            self.store_whole(finalized_root, &state)?;
        }

        let block_slots = BeaconBlockTable {
            db: self.db.clone(),
            cache: None,
        };
        let write_txn = self.database().begin_write()?;
        let pruned = {
            let mut summaries =
                write_txn.open_table(BeaconStateSummariesTable::TABLE_DEFINITION)?;
            let mut states = write_txn.open_table(Self::TABLE_DEFINITION)?;
            let mut old_roots = Vec::new();
            for entry in summaries.iter()? {
                let (root, slot) = entry?;
                if slot.value() < finalized_slot {
                    old_roots.push(root.value());
                }
            }
            // States stored before summaries existed have no summary; their block gives the slot.
            for entry in states.iter()? {
                let (root, _) = entry?;
                let root = root.value();
                if summaries.get(root)?.is_none()
                    && block_slots
                        .get(root)?
                        .is_some_and(|block| block.message.slot < finalized_slot)
                {
                    old_roots.push(root);
                }
            }
            for root in &old_roots {
                summaries.remove(*root)?;
                states.remove(*root)?;
            }
            old_roots.len()
        };
        write_txn.commit()?;
        Ok(pruned)
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

    fn in_memory_or_stored_whole(
        &self,
        block_root: B256,
    ) -> Result<Option<Arc<BeaconState>>, StoreError> {
        if let Some(state) = self.in_memory(block_root) {
            return Ok(Some(state));
        }
        let read_txn = self.database().begin_read()?;
        let table = read_txn.open_table(Self::TABLE_DEFINITION)?;
        let Some(state) = table.get(block_root)?.map(|value| Arc::new(value.value())) else {
            return Ok(None);
        };
        self.cache_state(block_root, state.clone());
        Ok(Some(state))
    }

    /// Whether the state is in the state table. The value is not decoded.
    fn is_stored_whole(&self, block_root: B256) -> Result<bool, StoreError> {
        let read_txn = self.database().begin_read()?;
        let table = read_txn.open_table(Self::TABLE_DEFINITION)?;
        Ok(table.get(block_root)?.is_some())
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
            if let Some(state) = self.in_memory_or_stored_whole(parent_root)? {
                break (parent_root, state);
            }
            if !self.summaries().contains_key(parent_root)? {
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

    /// Stores `state` whole, with its summary, in one transaction.
    fn store_whole(&self, block_root: B256, state: &BeaconState) -> Result<(), StoreError> {
        write_whole_state(
            &self.db,
            block_root,
            state.slot,
            &SSZEncoded::<BeaconState>::encode(state),
            true,
        )
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
        if let Ok(mut pending) = cache.pending_state_snapshots.lock() {
            pending.insert(block_root, state.clone());
        }
        let db = self.db.clone();
        thread::spawn(move || {
            let encoded = SSZEncoded::<BeaconState>::encode(&state);
            if let Err(err) = write_whole_state(&db, block_root, state.slot, &encoded, false) {
                warn!("Failed to store state {block_root}: {err:?}");
            }
            if let Ok(mut pending) = cache.pending_state_snapshots.lock() {
                pending.remove(&block_root);
            }
        });
    }
}

/// Writes an encoded whole state. With `with_summary` the summary is written in the same
/// transaction; otherwise the state is written only while its summary still exists, so a state
/// removed or pruned during a background write is not left behind.
fn write_whole_state(
    db: &Database,
    block_root: B256,
    slot: u64,
    encoded: &[u8],
    with_summary: bool,
) -> Result<(), StoreError> {
    const ENCODED_STATES: TableDefinition<'_, SSZEncoding<B256>, SSZEncoded<BeaconState>> =
        TableDefinition::new(STATE_TABLE_NAME);

    let mut write_txn = db.begin_write()?;
    write_txn.set_durability(Durability::Immediate)?;
    {
        let mut summaries = write_txn.open_table(BeaconStateSummariesTable::TABLE_DEFINITION)?;
        if with_summary {
            summaries.insert(block_root, slot)?;
        } else if summaries.get(block_root)?.is_none() {
            return Ok(());
        }
        write_txn
            .open_table(ENCODED_STATES)?
            .insert(block_root, encoded)?;
    }
    write_txn.commit()?;
    Ok(())
}

/// Drops `state` on another thread when this is its last reference. Freeing the millions of
/// allocations in a mainnet state takes tens of milliseconds.
pub(crate) fn drop_state_in_background(state: Arc<BeaconState>) {
    if Arc::strong_count(&state) == 1 {
        thread::spawn(move || drop(state));
    }
}
