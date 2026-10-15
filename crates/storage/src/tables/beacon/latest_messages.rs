use std::{collections::HashMap, sync::Arc};

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
        // Pin the overlay before the DB snapshot: a flush may commit while this guard lives,
        // but cannot remove the messages that are missing from the older snapshot.
        let pending = self.pending();
        let read_txn = self.db.begin_read()?;
        #[cfg(test)]
        tests::after_snapshot();
        let table = read_txn.open_table(Self::TABLE_DEFINITION)?;

        let mut entries = HashMap::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            entries.insert(key.value(), value.value());
        }
        if let Some(pending) = pending {
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
        let pending = self.pending();
        let read_txn = self.db.begin_read()?;
        #[cfg(test)]
        tests::after_snapshot();
        let table = read_txn.open_table(Self::TABLE_DEFINITION)?;
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
        let _accepting = cache.storage_write_guard()?;
        let start_flush = {
            let mut pending = cache.pending_votes();
            pending.messages.extend(entries);
            !std::mem::replace(&mut pending.flushing, true)
        };
        if start_flush {
            let db = self.db.clone();
            let worker_cache = cache.clone();
            if let Err(err) = cache.spawn_storage_task(move || {
                if let Err(err) = flush_pending_messages(&db, &worker_cache) {
                    warn!("Failed to write latest messages: {err:?}");
                }
            }) {
                cache.pending_votes().flushing = false;
                // The update is already accepted into the overlay. Keep the success contract
                // so fork choice applies it too; a later insert or shutdown retries the flush.
                warn!("Failed to start latest messages writer: {err:?}");
            }
        }
        Ok(())
    }

    /// Flush any retained votes after background workers and producers have stopped.
    pub(crate) fn flush(&self) -> Result<(), StoreError> {
        if let Some(cache) = &self.cache {
            flush_pending_messages(&self.db, cache)?;
        }
        Ok(())
    }

    fn pending(&self) -> Option<std::sync::MutexGuard<'_, PendingLatestMessages>> {
        self.cache.as_ref().map(|cache| cache.pending_votes())
    }
}

/// Writes pending messages until none are left. A message stays pending until a write of that
/// same message commits, so a newer message that arrives during a write is written next.
fn flush_pending_messages(db: &Database, cache: &BeaconCacheDB) -> Result<(), StoreError> {
    // Order: write lock -> pending (released) -> DB write (released) -> pending.
    // Bulk readers hold pending across a read snapshot, which never takes the DB write lock.
    let _writer = cache
        .latest_messages_write_lock
        .lock()
        .expect("latest messages write lock is not poisoned");
    loop {
        let batch: Vec<(u64, LatestMessage)> = {
            let mut pending = cache.pending_votes();
            if pending.messages.is_empty() {
                pending.flushing = false;
                return Ok(());
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
                cache.pending_votes().flushing = false;
                return Err(err);
            }
        }

        let mut pending = cache.pending_votes();
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
    #[cfg(test)]
    tests::before_write()?;
    let started = std::time::Instant::now();
    let mut write_txn = db.begin_write()?;
    write_txn.set_durability(durability)?;
    let mut written = 0usize;
    {
        let mut table = write_txn.open_table(LatestMessagesTable::TABLE_DEFINITION)?;
        for (index, message) in entries {
            table.insert(index, message)?;
            written += 1;
        }
    }
    let inserted = started.elapsed();
    write_txn.commit()?;
    tracing::debug!(
        target: "ream::timing",
        votes = written,
        insert_ms = inserted.as_millis() as u64,
        commit_ms = (started.elapsed() - inserted).as_millis() as u64,
        "timing: vote write"
    );
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

    fn contains_key<'a>(
        &self,
        key: <Self::KeyTableDefinition as redb::Value>::SelfType<'a>,
    ) -> Result<bool, StoreError> {
        Ok(self.get(key)?.is_some())
    }

    fn remove<'a>(
        &self,
        key: <Self::KeyTableDefinition as redb::Value>::SelfType<'a>,
    ) -> Result<Option<Self::Value>, StoreError> {
        // A captured flush must finish before deletion, otherwise it could resurrect the vote.
        let _writer = self.cache.as_ref().map(|cache| {
            cache
                .latest_messages_write_lock
                .lock()
                .expect("latest messages write lock is not poisoned")
        });
        let mut pending = self.pending();
        let write_txn = self.db.begin_write()?;
        let stored = {
            let mut table = write_txn.open_table(Self::TABLE_DEFINITION)?;
            table.remove(key)?.map(|value| value.value())
        };
        write_txn.commit()?;
        let pending = pending
            .as_mut()
            .and_then(|pending| pending.messages.remove(&key));
        Ok(pending.or(stored))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::{cell::RefCell, sync::mpsc, thread, time::Duration};

    use alloy_primitives::B256;
    use tempdir::TempDir;

    use super::*;
    use crate::db::ReamDB;

    type WriteHook = Box<dyn FnMut() -> Result<(), StoreError>>;

    thread_local! {
        static AFTER_SNAPSHOT: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
        static BEFORE_WRITE: RefCell<Option<WriteHook>> = RefCell::new(None);
    }

    pub(super) fn before_write() -> Result<(), StoreError> {
        BEFORE_WRITE.with(|hook| match hook.borrow_mut().as_mut() {
            Some(hook) => hook(),
            None => Ok(()),
        })
    }

    pub(super) fn after_snapshot() {
        AFTER_SNAPSHOT.with(|hook| {
            if let Some(hook) = hook.borrow_mut().take() {
                hook();
            }
        });
    }

    fn message(epoch: u64) -> LatestMessage {
        LatestMessage {
            epoch,
            root: B256::repeat_byte(epoch as u8),
        }
    }

    fn bulk_read_during_flush(all: bool) {
        let dir = TempDir::new("ream_vote_snapshot").unwrap();
        let db = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        db.latest_messages_provider().insert(7, message(1)).unwrap();
        let cache = Arc::new(BeaconCacheDB::default());
        let db = db.with_cache(cache.clone());
        // An already queued update, with the worker paused before its commit.
        cache
            .pending_latest_messages
            .lock()
            .unwrap()
            .messages
            .insert(7, message(2));
        let (snapshot_tx, snapshot_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let table = db.latest_messages_provider();
        let reader = thread::spawn(move || {
            AFTER_SNAPSHOT.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move || {
                    snapshot_tx.send(()).unwrap();
                    resume_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                }))
            });
            if all {
                table
                    .get_all()
                    .unwrap()
                    .into_iter()
                    .collect::<HashMap<_, _>>()
            } else {
                table.get_many([7, 8]).unwrap()
            }
        });
        snapshot_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        // Commit while the reader's DB snapshot is old. Flush removal must wait for its overlay.
        write_messages(&db.votes_db, [(7, message(2))], Durability::Immediate).unwrap();
        if let Ok(mut pending) = cache.pending_latest_messages.try_lock() {
            pending.messages.remove(&7);
        }
        resume_tx.send(()).unwrap();
        let result = reader.join().unwrap();
        cache
            .pending_latest_messages
            .lock()
            .unwrap()
            .messages
            .remove(&7);
        assert_eq!(result.get(&7), Some(&message(2)));
        assert!(!result.contains_key(&8));
        assert_eq!(
            db.latest_messages_provider().get(7).unwrap(),
            Some(message(2))
        );
    }

    #[test]
    fn get_all_keeps_votes_visible_during_flush() {
        bulk_read_during_flush(true);
    }

    #[test]
    fn get_many_keeps_votes_visible_during_flush() {
        bulk_read_during_flush(false);
    }

    #[test]
    fn contains_key_sees_pending_votes() {
        let dir = TempDir::new("ream_vote_contains").unwrap();
        let db = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        let cache = Arc::new(BeaconCacheDB::default());
        cache
            .pending_latest_messages
            .lock()
            .unwrap()
            .messages
            .insert(7, message(2));
        let table = db.with_cache(cache).latest_messages_provider();
        assert!(table.contains_key(7).unwrap());
        assert!(!table.contains_key(8).unwrap());
    }

    #[test]
    fn flush_keeps_a_newer_update_and_retries_a_failed_final_chunk() {
        let dir = TempDir::new("ream_vote_failed_flush").unwrap();
        let db = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        let cache = Arc::new(BeaconCacheDB::default());
        let db = db.with_cache(cache.clone());
        {
            let mut pending = cache.pending_latest_messages.lock().unwrap();
            pending
                .messages
                .extend((0..=FLUSH_CHUNK_SIZE as u64).map(|index| (index, message(1))));
            pending.flushing = true;
        }
        let worker_cache = cache.clone();
        let mut writes = 0;
        BEFORE_WRITE.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                writes += 1;
                if writes == 2 {
                    worker_cache
                        .pending_latest_messages
                        .lock()
                        .unwrap()
                        .messages
                        .insert(7, message(2));
                    return Err(std::io::Error::other("injected final chunk write failure").into());
                }
                Ok(())
            }))
        });
        assert!(flush_pending_messages(&db.votes_db, &cache).is_err());
        BEFORE_WRITE.with(|hook| *hook.borrow_mut() = None);
        {
            let pending = cache.pending_latest_messages.lock().unwrap();
            assert!(!pending.flushing);
            assert_eq!(pending.messages.len(), FLUSH_CHUNK_SIZE + 1);
        }
        assert_eq!(
            db.latest_messages_provider().get(7).unwrap(),
            Some(message(2))
        );
        db.flush_pending_writes().unwrap();
        assert!(
            cache
                .pending_latest_messages
                .lock()
                .unwrap()
                .messages
                .is_empty()
        );
        drop(db);
        let reopened = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        assert_eq!(
            reopened.latest_messages_provider().get(7).unwrap(),
            Some(message(2))
        );
        assert_eq!(
            reopened.latest_messages_provider().get_all().unwrap().len(),
            FLUSH_CHUNK_SIZE + 1
        );
    }

    #[test]
    fn a_successful_flush_does_not_remove_a_newer_pending_vote() {
        let dir = TempDir::new("ream_vote_newer_pending").unwrap();
        let db = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        let cache = Arc::new(BeaconCacheDB::default());
        {
            let mut pending = cache.pending_latest_messages.lock().unwrap();
            pending.messages.insert(7, message(1));
            pending.flushing = true;
        }
        let worker_cache = cache.clone();
        let mut writes = 0;
        BEFORE_WRITE.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                writes += 1;
                let mut pending = worker_cache.pending_latest_messages.lock().unwrap();
                if writes == 1 {
                    pending.messages.insert(7, message(2));
                } else {
                    assert_eq!(pending.messages.get(&7), Some(&message(2)));
                }
                Ok(())
            }))
        });
        flush_pending_messages(&db.votes_db, &cache).unwrap();
        BEFORE_WRITE.with(|hook| *hook.borrow_mut() = None);
        assert!(
            cache
                .pending_latest_messages
                .lock()
                .unwrap()
                .messages
                .is_empty()
        );
        assert_eq!(
            db.latest_messages_provider().get(7).unwrap(),
            Some(message(2))
        );
    }

    #[test]
    fn remove_waits_for_a_captured_flush_and_does_not_resurrect_votes() {
        let dir = TempDir::new("ream_vote_remove").unwrap();
        let db = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        let cache = Arc::new(BeaconCacheDB::default());
        cache
            .pending_latest_messages
            .lock()
            .unwrap()
            .messages
            .insert(7, message(2));
        let db = db.with_cache(cache.clone());
        let (captured_tx, captured_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let votes_db = db.votes_db.clone();
        let writer = thread::spawn(move || {
            BEFORE_WRITE.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move || {
                    captured_tx.send(()).unwrap();
                    resume_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                    Ok(())
                }))
            });
            flush_pending_messages(&votes_db, &cache).unwrap();
        });
        captured_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let table = db.latest_messages_provider();
        let remover = thread::spawn(move || table.remove(7).unwrap());
        resume_tx.send(()).unwrap();
        writer.join().unwrap();
        assert_eq!(remover.join().unwrap(), Some(message(2)));
        assert_eq!(db.latest_messages_provider().get(7).unwrap(), None);
        assert!(db.latest_messages_provider().get_all().unwrap().is_empty());
    }

    #[test]
    fn drain_joins_the_background_flush_before_reopen() {
        let dir = TempDir::new("ream_vote_drain").unwrap();
        let cache = Arc::new(BeaconCacheDB::default());
        let db = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap()
            .with_cache(cache);
        db.latest_messages_provider().insert(7, message(2)).unwrap();
        db.flush_pending_writes().unwrap();
        drop(db);
        let db = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        assert_eq!(
            db.latest_messages_provider().get(7).unwrap(),
            Some(message(2))
        );
    }

    #[test]
    fn shutdown_rejects_new_votes_and_retries_accepted_votes() {
        let dir = TempDir::new("ream_vote_shutdown").unwrap();
        let db = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap()
            .with_cache(Arc::new(BeaconCacheDB::default()));
        db.latest_messages_provider().insert(7, message(2)).unwrap();
        db.shutdown_storage().unwrap();
        assert!(db.latest_messages_provider().insert(7, message(3)).is_err());
        assert_eq!(
            db.latest_messages_provider().get(7).unwrap(),
            Some(message(2))
        );
        db.shutdown_storage().unwrap();
        drop(db);
        let reopened = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        assert_eq!(
            reopened.latest_messages_provider().get(7).unwrap(),
            Some(message(2))
        );
    }

    #[test]
    fn enqueue_failure_keeps_votes_readable_and_retryable() {
        let dir = TempDir::new("ream_vote_enqueue_failure").unwrap();
        let cache = Arc::new(BeaconCacheDB::default());
        let db = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap()
            .with_cache(cache.clone());
        crate::cache::FAIL_NEXT_STORAGE_SPAWN.with(|fail| fail.set(true));
        assert!(db.latest_messages_provider().insert(7, message(2)).is_ok());
        assert!(!cache.pending_latest_messages.lock().unwrap().flushing);
        assert_eq!(
            db.latest_messages_provider().get(7).unwrap(),
            Some(message(2))
        );
        db.latest_messages_provider().insert(8, message(3)).unwrap();
        db.shutdown_storage().unwrap();
        drop(db);
        let reopened = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        assert_eq!(
            reopened.latest_messages_provider().get(7).unwrap(),
            Some(message(2))
        );
        assert_eq!(
            reopened.latest_messages_provider().get(8).unwrap(),
            Some(message(3))
        );
    }
}
