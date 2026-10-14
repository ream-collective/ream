use std::{path::PathBuf, sync::Arc};

use ream_consensus_beacon::electra::beacon_state::BeaconState;
use ream_consensus_misc::{checkpoint::Checkpoint, misc::compute_start_slot_at_epoch};
use redb::{Database, ReadableDatabase, ReadableTableMetadata, TableDefinition};

use crate::{
    cache::BeaconCacheDB,
    errors::StoreError,
    tables::{
        beacon::beacon_state::{BeaconStateTable, drop_state_in_background},
        ssz_encoder::SSZEncoding,
        table::REDBTable,
    },
};

/// Checkpoint states: the state of a checkpoint's block advanced to the checkpoint's epoch.
///
/// They are derived data, so they are kept in memory only and computed again from the block's
/// state when missing. Most checkpoint blocks are at their epoch's first slot, and then the
/// checkpoint state is the block's state itself and shares its memory. Storing them whole wrote
/// about 250 MB per epoch, and redb read all of a value's bytes to delete or even find it.
pub struct CheckpointStatesTable {
    pub db: Arc<Database>,
    pub data_dir: PathBuf,
    pub cache: Option<Arc<BeaconCacheDB>>,
}

/// Table definition for the Checkpoint States table, which held checkpoint states before they
/// were kept in memory only. Its entries are deleted once, at the first finalization.
///
/// Key: checkpoint_states
/// Value: BeaconState
impl REDBTable for CheckpointStatesTable {
    const TABLE_DEFINITION: TableDefinition<'_, SSZEncoding<Checkpoint>, SSZEncoding<BeaconState>> =
        TableDefinition::new("beacon_checkpoint_states");

    type Key = Checkpoint;

    type KeyTableDefinition = SSZEncoding<Checkpoint>;

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

    /// Whether the checkpoint state is in memory. A missing one can still be computed by `get`.
    fn contains_key<'a>(
        &self,
        key: <Self::KeyTableDefinition as redb::Value>::SelfType<'a>,
    ) -> Result<bool, StoreError> {
        Ok(self.in_memory(key).is_some())
    }

    fn insert<'a>(
        &self,
        key: <Self::KeyTableDefinition as redb::Value>::SelfType<'a>,
        value: <Self::ValueTableDefinition as redb::Value>::SelfType<'a>,
    ) -> Result<(), StoreError> {
        self.cache_state(key, Arc::new(value));
        Ok(())
    }

    fn remove<'a>(
        &self,
        key: <Self::KeyTableDefinition as redb::Value>::SelfType<'a>,
    ) -> Result<Option<Self::Value>, StoreError> {
        Ok(self
            .cache
            .as_ref()
            .and_then(|cache| cache.checkpoint_states.lock().ok()?.pop(&key))
            .map(Arc::unwrap_or_clone))
    }
}

impl CheckpointStatesTable {
    /// The checkpoint state, shared with the in-memory cache instead of copied, and computed from
    /// the checkpoint block's state when it is not in memory. Callers that only read the state
    /// should use this over `get`.
    pub fn get_shared(
        &self,
        checkpoint: Checkpoint,
    ) -> Result<Option<Arc<BeaconState>>, StoreError> {
        if let Some(state) = self.in_memory(checkpoint) {
            return Ok(Some(state));
        }

        let block_states = BeaconStateTable {
            db: self.db.clone(),
            data_dir: self.data_dir.clone(),
            cache: self.cache.clone(),
        };
        let Some(block_state) = block_states.get_shared(checkpoint.root)? else {
            return Ok(None);
        };
        let epoch_start_slot = compute_start_slot_at_epoch(checkpoint.epoch);
        let state = if block_state.slot < epoch_start_slot {
            let mut state = Arc::unwrap_or_clone(block_state);
            state.process_slots(epoch_start_slot).map_err(|err| {
                StoreError::StateRebuild(format!("checkpoint state {checkpoint:?}: {err:?}"))
            })?;
            Arc::new(state)
        } else {
            block_state
        };
        self.cache_state(checkpoint, state.clone());
        Ok(Some(state))
    }

    /// Forgets the checkpoint states of epochs before `epoch`. Fork choice reads checkpoint states
    /// only for attestation targets, which are never older than the finalized epoch. Checkpoint
    /// states stored in redb by earlier versions are deleted too.
    pub fn prune_before(&self, epoch: u64) -> Result<(), StoreError> {
        if let Some(cache) = &self.cache
            && let Ok(mut cache_lock) = cache.checkpoint_states.lock()
        {
            let old: Vec<Checkpoint> = cache_lock
                .iter()
                .map(|(checkpoint, _)| *checkpoint)
                .filter(|checkpoint| checkpoint.epoch < epoch)
                .collect();
            for checkpoint in &old {
                cache_lock.pop(checkpoint);
            }
        }

        let read_txn = self.database().begin_read()?;
        if read_txn.open_table(Self::TABLE_DEFINITION)?.is_empty()? {
            return Ok(());
        }
        drop(read_txn);
        // Deleting the table frees its pages without reading the states in them.
        let write_txn = self.database().begin_write()?;
        write_txn.delete_table(Self::TABLE_DEFINITION)?;
        write_txn.open_table(Self::TABLE_DEFINITION)?;
        write_txn.commit()?;
        Ok(())
    }

    fn in_memory(&self, checkpoint: Checkpoint) -> Option<Arc<BeaconState>> {
        self.cache
            .as_ref()?
            .checkpoint_states
            .lock()
            .ok()?
            .get(&checkpoint)
            .cloned()
    }

    fn cache_state(&self, checkpoint: Checkpoint, state: Arc<BeaconState>) {
        let evicted = self
            .cache
            .as_ref()
            .and_then(|cache| cache.checkpoint_states.lock().ok()?.push(checkpoint, state));
        if let Some((_, evicted)) = evicted {
            drop_state_in_background(evicted);
        }
    }
}
