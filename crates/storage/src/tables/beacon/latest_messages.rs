use std::{collections::HashMap, sync::Arc, thread};

use ream_consensus_beacon::fork_choice::latest_message::LatestMessage;
use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};
use tracing::warn;

use crate::{
    cache::{BeaconCacheDB, PendingLatestMessages},
    errors::StoreError,
    tables::{ssz_encoder::SSZEncoding, table::REDBTable},
};

/// Messages written per transaction when pending messages are flushed. Small transactions let
/// block import write between them instead of waiting for the whole flush.
const FLUSH_CHUNK_SIZE: usize = 16_384;

/// Latest messages of validators.
///
/// A mainnet block carries votes from tens of thousands of validators at scattered indices, so
/// writing them rewrites most of the table's pages. With a cache attached, new messages are kept
/// in memory and written on another thread, which merges the messages of every block imported
/// while the previous write ran. Reads see the pending messages, so they always return the
/// latest message.
pub struct LatestMessagesTable {
    pub db: Arc<Database>,
    pub cache: Option<Arc<BeaconCacheDB>>,
}

impl LatestMessagesTable {
    /// Returns every stored latest message as `(validator_index, message)` from a single read
    /// transaction. Used to rebuild in-memory fork choice state on startup.
    pub fn get_all(&self) -> Result<Vec<(u64, LatestMessage)>, StoreError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(Self::TABLE_DEFINITION)?;

        let mut entries = HashMap::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            entries.insert(key.value(), value.value());
        }
        if let Some(pending) = self.pending() {
            entries.extend(
                pending
                    .messages
                    .iter()
                    .map(|(index, message)| (*index, message.clone())),
            );
        }
        let mut entries: Vec<_> = entries.into_iter().collect();
        entries.sort_unstable_by_key(|(index, _)| *index);
        Ok(entries)
    }

    /// The latest messages of `indices`, read in one transaction.
    pub fn get_many(
        &self,
        indices: impl IntoIterator<Item = u64>,
    ) -> Result<HashMap<u64, LatestMessage>, StoreError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(Self::TABLE_DEFINITION)?;
        let pending = self.pending();
        let mut messages = HashMap::new();
        for index in indices {
            if let Some(message) = pending
                .as_ref()
                .and_then(|pending| pending.messages.get(&index))
            {
                messages.insert(index, message.clone());
            } else if let Some(message) = table.get(index)? {
                messages.insert(index, message.value());
            }
        }
        Ok(messages)
    }

    pub fn insert_batch(
        &self,
        entries: impl IntoIterator<Item = (u64, LatestMessage)>,
    ) -> Result<(), StoreError> {
        let Some(cache) = &self.cache else {
            return write_messages(&self.db, entries, Durability::Immediate);
        };
        let start_flush = {
            let mut pending = cache
                .pending_latest_messages
                .lock()
                .expect("pending latest messages lock is not poisoned");
            pending.messages.extend(entries);
            !std::mem::replace(&mut pending.flushing, true)
        };
        if start_flush {
            let db = self.db.clone();
            let cache = cache.clone();
            thread::spawn(move || flush_pending_messages(&db, &cache));
        }
        Ok(())
    }

    fn pending(&self) -> Option<std::sync::MutexGuard<'_, PendingLatestMessages>> {
        self.cache.as_ref().map(|cache| {
            cache
                .pending_latest_messages
                .lock()
                .expect("pending latest messages lock is not poisoned")
        })
    }
}

/// Writes pending messages until none are left. A message stays pending until a write of that
/// same message commits, so a newer message that arrives during a write is written next.
fn flush_pending_messages(db: &Database, cache: &BeaconCacheDB) {
    loop {
        let batch: Vec<(u64, LatestMessage)> = {
            let mut pending = cache
                .pending_latest_messages
                .lock()
                .expect("pending latest messages lock is not poisoned");
            if pending.messages.is_empty() {
                pending.flushing = false;
                return;
            }
            pending
                .messages
                .iter()
                .map(|(index, message)| (*index, message.clone()))
                .collect()
        };

        for (position, chunk) in batch.chunks(FLUSH_CHUNK_SIZE).enumerate() {
            // Only the last chunk waits for the disk; it makes the earlier ones durable too.
            let durability = if (position + 1) * FLUSH_CHUNK_SIZE >= batch.len() {
                Durability::Immediate
            } else {
                Durability::None
            };
            if let Err(err) = write_messages(db, chunk.iter().cloned(), durability) {
                warn!("Failed to write latest messages: {err:?}");
                cache
                    .pending_latest_messages
                    .lock()
                    .expect("pending latest messages lock is not poisoned")
                    .flushing = false;
                return;
            }
        }

        let mut pending = cache
            .pending_latest_messages
            .lock()
            .expect("pending latest messages lock is not poisoned");
        for (index, message) in &batch {
            if pending.messages.get(index) == Some(message) {
                pending.messages.remove(index);
            }
        }
    }
}

fn write_messages(
    db: &Database,
    entries: impl IntoIterator<Item = (u64, LatestMessage)>,
    durability: Durability,
) -> Result<(), StoreError> {
    let mut write_txn = db.begin_write()?;
    write_txn.set_durability(durability)?;
    {
        let mut table = write_txn.open_table(LatestMessagesTable::TABLE_DEFINITION)?;
        for (index, message) in entries {
            table.insert(index, message)?;
        }
    }
    write_txn.commit()?;
    Ok(())
}

/// Table definition for the Latest Message table
///
/// Key: latest_messages
/// Value: LatestMessage
impl REDBTable for LatestMessagesTable {
    const TABLE_DEFINITION: TableDefinition<'_, u64, SSZEncoding<LatestMessage>> =
        TableDefinition::new("beacon_latest_messages");

    type Key = u64;

    type KeyTableDefinition = u64;

    type Value = LatestMessage;

    type ValueTableDefinition = SSZEncoding<LatestMessage>;

    fn database(&self) -> Arc<Database> {
        self.db.clone()
    }

    fn get<'a>(
        &self,
        key: <Self::KeyTableDefinition as redb::Value>::SelfType<'a>,
    ) -> Result<Option<Self::Value>, StoreError> {
        if let Some(message) = self
            .pending()
            .and_then(|pending| pending.messages.get(&key).cloned())
        {
            return Ok(Some(message));
        }
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(Self::TABLE_DEFINITION)?;
        Ok(table.get(key)?.map(|value| value.value()))
    }

    fn insert<'a>(
        &self,
        key: <Self::KeyTableDefinition as redb::Value>::SelfType<'a>,
        value: Self::Value,
    ) -> Result<(), StoreError> {
        self.insert_batch([(key, value)])
    }

    fn remove<'a>(
        &self,
        key: <Self::KeyTableDefinition as redb::Value>::SelfType<'a>,
    ) -> Result<Option<Self::Value>, StoreError> {
        let pending = self
            .pending()
            .and_then(|mut pending| pending.messages.remove(&key));
        let write_txn = self.db.begin_write()?;
        let stored = {
            let mut table = write_txn.open_table(Self::TABLE_DEFINITION)?;
            table.remove(key)?.map(|value| value.value())
        };
        write_txn.commit()?;
        Ok(pending.or(stored))
    }
}
