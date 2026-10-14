use std::{sync::Arc, thread};

use ream_consensus_beacon::electra::beacon_state::BeaconState;
use ream_consensus_misc::checkpoint::Checkpoint;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use tracing::warn;

use crate::{
    cache::BeaconCacheDB,
    errors::StoreError,
    tables::{
        beacon::beacon_state::drop_state_in_background,
        ssz_encoder::{SSZEncoded, SSZEncoding},
        table::REDBTable,
    },
};

/// Checkpoint states, also kept in memory when a cache is attached. Fork choice reads the same few
/// for every block, and decoding one from disk costs as much as the rest of that work; a state
/// taken from memory also keeps its committee and tree hash caches. With a cache, writing a state
/// to disk happens on another thread, because writing a whole mainnet state takes about a second.
pub struct CheckpointStatesTable {
    pub db: Arc<Database>,
    pub cache: Option<Arc<BeaconCacheDB>>,
}

/// Table definition for the Checkpoint States table
///
/// Key: checkpoint_states
/// Value: BeaconState
impl REDBTable for CheckpointStatesTable {
    const TABLE_DEFINITION: TableDefinition<'_, SSZEncoding<Checkpoint>, SSZEncoding<BeaconState>> =
        TableDefinition::new(CHECKPOINT_STATES_TABLE_NAME);

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

    fn contains_key<'a>(
        &self,
        key: <Self::KeyTableDefinition as redb::Value>::SelfType<'a>,
    ) -> Result<bool, StoreError> {
        if self.in_memory(key).is_some() {
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
        let state = Arc::new(value);
        let Some(cache) = self.cache.clone() else {
            return write_checkpoint_state(&self.db, key, &SSZEncoded::encode(&state));
        };
        let evicted = cache
            .checkpoint_states
            .lock()
            .ok()
            .and_then(|mut cache_lock| cache_lock.push(key, state.clone()));
        if let Some((_, evicted)) = evicted {
            drop_state_in_background(evicted);
        }
        if let Ok(mut pending) = cache.pending_checkpoint_states.lock() {
            pending.insert(key, state.clone());
        }
        let db = self.db.clone();
        thread::spawn(move || {
            if let Err(err) = write_checkpoint_state(&db, key, &SSZEncoded::encode(&state)) {
                warn!("Failed to store checkpoint state {key:?}: {err:?}");
            }
            if let Ok(mut pending) = cache.pending_checkpoint_states.lock() {
                pending.remove(&key);
            }
        });
        Ok(())
    }

    fn remove<'a>(
        &self,
        key: <Self::KeyTableDefinition as redb::Value>::SelfType<'a>,
    ) -> Result<Option<Self::Value>, StoreError> {
        if let Some(cache) = &self.cache
            && let Ok(mut cache_lock) = cache.checkpoint_states.lock()
        {
            cache_lock.pop(&key);
        }

        let write_txn = self.database().begin_write()?;
        let value = {
            let mut table = write_txn.open_table(Self::TABLE_DEFINITION)?;
            table.remove(key)?.map(|value| value.value())
        };
        write_txn.commit()?;
        Ok(value)
    }
}

const CHECKPOINT_STATES_TABLE_NAME: &str = "beacon_checkpoint_states";

fn write_checkpoint_state(
    db: &Database,
    checkpoint: Checkpoint,
    encoded: &[u8],
) -> Result<(), StoreError> {
    const ENCODED_STATES: TableDefinition<'_, SSZEncoding<Checkpoint>, SSZEncoded<BeaconState>> =
        TableDefinition::new(CHECKPOINT_STATES_TABLE_NAME);

    let mut write_txn = db.begin_write()?;
    write_txn.set_durability(redb::Durability::Immediate)?;
    write_txn
        .open_table(ENCODED_STATES)?
        .insert(checkpoint, encoded)?;
    write_txn.commit()?;
    Ok(())
}

impl CheckpointStatesTable {
    /// The checkpoint state, shared with the in-memory cache instead of copied. Callers that only
    /// read the state should use this over `get`.
    pub fn get_shared(
        &self,
        checkpoint: Checkpoint,
    ) -> Result<Option<Arc<BeaconState>>, StoreError> {
        if let Some(state) = self.in_memory(checkpoint) {
            return Ok(Some(state));
        }

        let read_txn = self.database().begin_read()?;
        let table = read_txn.open_table(Self::TABLE_DEFINITION)?;
        let Some(state) = table.get(checkpoint)?.map(|value| Arc::new(value.value())) else {
            return Ok(None);
        };
        let evicted = self.cache.as_ref().and_then(|cache| {
            cache
                .checkpoint_states
                .lock()
                .ok()
                .and_then(|mut cache_lock| cache_lock.push(checkpoint, state.clone()))
        });
        if let Some((_, evicted)) = evicted {
            drop_state_in_background(evicted);
        }
        Ok(Some(state))
    }

    fn in_memory(&self, checkpoint: Checkpoint) -> Option<Arc<BeaconState>> {
        let cache = self.cache.as_ref()?;
        if let Ok(mut cache_lock) = cache.checkpoint_states.lock()
            && let Some(state) = cache_lock.get(&checkpoint)
        {
            return Some(state.clone());
        }
        cache
            .pending_checkpoint_states
            .lock()
            .ok()?
            .get(&checkpoint)
            .cloned()
    }

    /// Deletes the checkpoint states of epochs before `epoch`. Fork choice reads checkpoint states
    /// only for attestation targets, which are never older than the finalized epoch. Returns how
    /// many were deleted.
    pub fn prune_before(&self, epoch: u64) -> Result<usize, StoreError> {
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

        let write_txn = self.database().begin_write()?;
        let pruned = {
            let mut table = write_txn.open_table(Self::TABLE_DEFINITION)?;
            let mut old = Vec::new();
            for entry in table.iter()? {
                let checkpoint = entry?.0.value();
                if checkpoint.epoch < epoch {
                    old.push(checkpoint);
                }
            }
            for checkpoint in &old {
                table.remove(*checkpoint)?;
            }
            old.len()
        };
        write_txn.commit()?;
        Ok(pruned)
    }
}
