use std::sync::Arc;

use alloy_primitives::B256;
use ream_consensus_beacon::electra::beacon_block::SignedBeaconBlock;
use redb::{Database, Durability, ReadableDatabase, TableDefinition};

use super::parent_root_index::PARENT_ROOT_INDEX_MULTIMAP_TABLE;
use crate::{
    cache::BeaconCacheDB,
    errors::StoreError,
    tables::{
        beacon::{slot_index::BeaconSlotIndexTable, state_root_index::BeaconStateRootIndexTable},
        ssz_encoder::SSZEncoding,
        table::REDBTable,
    },
};

pub struct BeaconBlockTable {
    pub db: Arc<Database>,
    pub cache: Option<Arc<BeaconCacheDB>>,
}

/// Table definition for the Beacon Block table
///
/// Key: block_id
/// Value: BeaconBlock
impl REDBTable for BeaconBlockTable {
    const TABLE_DEFINITION: TableDefinition<'_, SSZEncoding<B256>, SSZEncoding<SignedBeaconBlock>> =
        TableDefinition::new("beacon_block");

    type Key = B256;

    type KeyTableDefinition = SSZEncoding<B256>;

    type Value = SignedBeaconBlock;

    type ValueTableDefinition = SSZEncoding<SignedBeaconBlock>;

    fn database(&self) -> Arc<Database> {
        self.db.clone()
    }

    fn contains_key<'a>(
        &self,
        key: <Self::KeyTableDefinition as redb::Value>::SelfType<'a>,
    ) -> Result<bool, StoreError> {
        if let Some(cache) = &self.cache
            && let Ok(cache_lock) = cache.blocks.lock()
            && cache_lock.contains(&key)
        {
            return Ok(true);
        }
        let read_txn = self.database().begin_read()?;
        let table = read_txn.open_table(Self::TABLE_DEFINITION)?;
        Ok(table.get(key)?.is_some())
    }

    fn get<'a>(
        &self,
        key: <Self::KeyTableDefinition as redb::Value>::SelfType<'a>,
    ) -> Result<Option<Self::Value>, StoreError> {
        // LruCache::get requires mutable access to update LRU order
        if let Some(cache) = &self.cache
            && let Ok(mut cache_lock) = cache.blocks.lock()
            && let Some(block) = cache_lock.get(&key)
        {
            return Ok(Some(block.clone()));
        }

        let read_txn = self.database().begin_read()?;
        let table = read_txn.open_table(Self::TABLE_DEFINITION)?;
        let result = table.get(key)?;
        let block = result.map(|res| res.value());

        if let (Some(cache), Some(block)) = (&self.cache, &block)
            && let Ok(mut cache_lock) = cache.blocks.lock()
        {
            cache_lock.put(key, block.clone());
        }

        Ok(block)
    }

    fn insert(&self, key: Self::Key, value: Self::Value) -> Result<(), StoreError> {
        // The key is the block root: indexing under it points every index entry at the key the
        // block is stored under, and hashing the block again costs a few milliseconds.
        let block_root = key;

        // The block and its slot, state root and parent root index entries commit together: one
        // disk sync instead of four, and no reader sees the block without its index entries.
        let mut write_txn = self.db.begin_write()?;
        write_txn.set_durability(Durability::Immediate)?;
        {
            write_txn
                .open_table(BeaconSlotIndexTable::TABLE_DEFINITION)?
                .insert(value.message.slot, block_root)?;
            write_txn
                .open_table(BeaconStateRootIndexTable::TABLE_DEFINITION)?
                .insert(value.message.state_root, block_root)?;
            write_txn
                .open_multimap_table(PARENT_ROOT_INDEX_MULTIMAP_TABLE)?
                .insert(value.message.parent_root, block_root)?;
            write_txn
                .open_table(Self::TABLE_DEFINITION)?
                .insert(key, value.clone())?;
        }
        write_txn.commit()?;
        self.cache_committed(key, value);
        Ok(())
    }

    fn remove(&self, key: Self::Key) -> Result<Option<Self::Value>, StoreError> {
        if let Some(cache) = &self.cache
            && let Ok(mut cache_lock) = cache.blocks.lock()
        {
            cache_lock.pop(&key);
        }

        let write_txn = self.db.begin_write()?;
        let mut table = write_txn.open_table(Self::TABLE_DEFINITION)?;
        let value = table.remove(key)?.map(|v| v.value());
        if let Some(block) = &value {
            let slot_index_table = BeaconSlotIndexTable {
                db: self.db.clone(),
            };
            slot_index_table.remove(block.message.slot)?;
            let state_root_index_table = BeaconStateRootIndexTable {
                db: self.db.clone(),
            };
            state_root_index_table.remove(block.message.state_root)?;
        }
        drop(table);
        write_txn.commit()?;
        Ok(value)
    }
}

impl BeaconBlockTable {
    /// The block's slot and parent root. A cached block is not cloned: gossip validation walks
    /// ancestors for every attestation, and a clone copies the whole execution payload.
    pub fn slot_and_parent_root(
        &self,
        block_root: B256,
    ) -> Result<Option<(u64, B256)>, StoreError> {
        if let Some(cache) = &self.cache
            && let Ok(mut cache_lock) = cache.blocks.lock()
            && let Some(block) = cache_lock.get(&block_root)
        {
            return Ok(Some((block.message.slot, block.message.parent_root)));
        }
        Ok(self
            .get(block_root)?
            .map(|block| (block.message.slot, block.message.parent_root)))
    }

    pub(crate) fn cache_committed(&self, block_root: B256, block: SignedBeaconBlock) {
        if let Some(cache) = &self.cache
            && let Ok(mut cache_lock) = cache.blocks.lock()
        {
            cache_lock.put(block_root, block);
        }
    }
}
