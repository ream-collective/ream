use std::{collections::HashSet, path::PathBuf, sync::Arc, time::Duration};

use anyhow::anyhow;
use ream_consensus_beacon::electra::{beacon_block::SignedBeaconBlock, beacon_state::BeaconState};
use ream_consensus_misc::{checkpoint::Checkpoint, constants::beacon::SLOTS_PER_EPOCH};
use redb::{Database, Durability, WriteTransaction};

use crate::{
    cache::BeaconCacheDB,
    tables::{
        beacon::{
            beacon_block::BeaconBlockTable,
            beacon_state::BeaconStateTable,
            blobs_and_proofs::BlobsAndProofsTable,
            block_timeliness::BlockTimelinessTable,
            checkpoint_states::CheckpointStatesTable,
            column_sidecars::ColumnSidecarsTable,
            equivocating_indices::EquivocatingIndicesField,
            finalized_checkpoint::FinalizedCheckpointField,
            genesis_time::GenesisTimeField,
            justified_checkpoint::JustifiedCheckpointField,
            latest_messages::LatestMessagesTable,
            parent_root_index::{PARENT_ROOT_INDEX_MULTIMAP_TABLE, ParentRootIndexMultimapTable},
            previous_justified_checkpoint::PreviousJustifiedCheckpointField,
            proposer_boost_root::ProposerBoostRootField,
            slot_index::BeaconSlotIndexTable,
            state_root_index::BeaconStateRootIndexTable,
            state_summaries::{BeaconStateSummariesTable, StateSummary},
            time::TimeField,
            unrealized_finalized_checkpoint::UnrealizedFinalizedCheckpointField,
            unrealized_justifications::UnrealizedJustificationsTable,
            unrealized_justified_checkpoint::UnrealizedJustifiedCheckpointField,
        },
        field::REDBField,
        table::REDBTable,
    },
};

/// A block to import, its post-state and the fork choice values committed with it.
#[derive(Debug)]
pub struct BlockImportData {
    pub block_root: alloy_primitives::B256,
    pub block: SignedBeaconBlock,
    pub state: Arc<BeaconState>,
    pub record: ForkChoiceRecord,
}

/// The fork choice values a block import writes.
#[derive(Debug, Default, Clone, Copy)]
pub struct ForkChoiceRecord {
    pub is_timely: bool,
    pub proposer_boost_root: Option<alloy_primitives::B256>,
    pub unrealized_justification: Checkpoint,
    pub checkpoints: CheckpointWrites,
}

/// The store checkpoints to overwrite. A `None` keeps the stored checkpoint.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointWrites {
    pub justified: Option<Checkpoint>,
    pub previous_justified: Option<Checkpoint>,
    pub finalized: Option<Checkpoint>,
    pub unrealized_justified: Option<Checkpoint>,
    pub unrealized_finalized: Option<Checkpoint>,
}

impl CheckpointWrites {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    fn write(&self, write_txn: &WriteTransaction) -> Result<(), crate::errors::StoreError> {
        if let Some(checkpoint) = self.justified {
            write_txn
                .open_table(JustifiedCheckpointField::FIELD_DEFINITION)?
                .insert(JustifiedCheckpointField::KEY, checkpoint)?;
        }
        if let Some(checkpoint) = self.previous_justified {
            write_txn
                .open_table(PreviousJustifiedCheckpointField::FIELD_DEFINITION)?
                .insert(PreviousJustifiedCheckpointField::KEY, checkpoint)?;
        }
        if let Some(checkpoint) = self.finalized {
            write_txn
                .open_table(FinalizedCheckpointField::FIELD_DEFINITION)?
                .insert(FinalizedCheckpointField::KEY, checkpoint)?;
        }
        if let Some(checkpoint) = self.unrealized_justified {
            write_txn
                .open_table(UnrealizedJustifiedCheckpointField::FIELD_DEFINITION)?
                .insert(UnrealizedJustifiedCheckpointField::KEY, checkpoint)?;
        }
        if let Some(checkpoint) = self.unrealized_finalized {
            write_txn
                .open_table(UnrealizedFinalizedCheckpointField::FIELD_DEFINITION)?
                .insert(UnrealizedFinalizedCheckpointField::KEY, checkpoint)?;
        }
        Ok(())
    }
}

/// How `BeaconDB::close` left a database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseClose {
    /// Its last handle was dropped: the database is closed.
    Closed(&'static str),
    /// Other handles were still held, so its allocator state was saved instead. The next open
    /// loads it and skips the repair.
    AllocatorStateSaved {
        name: &'static str,
        other_handles: usize,
    },
}

#[derive(Clone, Debug)]
pub struct BeaconDB {
    pub db: Arc<Database>,
    /// Validators' latest messages, in a database of their own; see `VOTES_REDB_FILE`.
    pub votes_db: Arc<Database>,
    pub data_dir: PathBuf,
    pub(crate) cache: Option<Arc<BeaconCacheDB>>,
    pub(crate) bootstrap_cache:
        Arc<std::sync::Mutex<Option<crate::tables::beacon::backfill::BackfillMode>>>,
}

impl BeaconDB {
    /// Commit the database portion of one block import atomically, then publish its caches.
    pub fn commit_block_import(
        &self,
        import: BlockImportData,
    ) -> Result<(), crate::errors::StoreError> {
        let _accepting = BeaconCacheDB::accept_writes(self.cache.as_ref())?;
        let state_table = self.state_provider();
        let prepared = state_table.prepare_import(import.block_root, &import.state)?;
        let committed = self.commit_block_import_transaction(
            import.block_root,
            &import.block,
            prepared.summary,
            &import.record,
        );
        if let Err(err) = committed {
            // The caller needs the commit error. A state file left behind has no summary, so the
            // next finalized-state pruning deletes it.
            let _ = state_table
                .abort_import(import.block_root, &import.state, prepared)
                .inspect_err(|err| {
                    tracing::warn!(
                        "Failed to remove state file of aborted import {}: {err:?}",
                        import.block_root
                    )
                });
            return Err(err);
        }

        self.block_provider()
            .cache_committed(import.block_root, import.block);
        state_table.finish_import(import.block_root, import.state, prepared);
        Ok(())
    }

    fn commit_block_import_transaction(
        &self,
        block_root: alloy_primitives::B256,
        signed_block: &SignedBeaconBlock,
        state_summary: StateSummary,
        record: &ForkChoiceRecord,
    ) -> Result<(), crate::errors::StoreError> {
        let block = &signed_block.message;
        let mut write_txn = self.db.begin_write()?;
        write_txn.set_durability(Durability::Immediate)?;
        {
            write_txn
                .open_table(BeaconSlotIndexTable::TABLE_DEFINITION)?
                .insert(block.slot, block_root)?;
            write_txn
                .open_table(BeaconStateRootIndexTable::TABLE_DEFINITION)?
                .insert(block.state_root, block_root)?;
            write_txn
                .open_multimap_table(PARENT_ROOT_INDEX_MULTIMAP_TABLE)?
                .insert(block.parent_root, block_root)?;
            write_txn
                .open_table(BeaconBlockTable::TABLE_DEFINITION)?
                .insert(block_root, signed_block.clone())?;
            write_txn
                .open_table(BeaconStateSummariesTable::TABLE_DEFINITION)?
                .insert(block_root, state_summary)?;
            write_txn
                .open_table(BlockTimelinessTable::TABLE_DEFINITION)?
                .insert(block_root, record.is_timely)?;
            write_txn
                .open_table(UnrealizedJustificationsTable::TABLE_DEFINITION)?
                .insert(block_root, record.unrealized_justification)?;

            if let Some(root) = record.proposer_boost_root {
                write_txn
                    .open_table(ProposerBoostRootField::FIELD_DEFINITION)?
                    .insert(ProposerBoostRootField::KEY, root)?;
            }
            record.checkpoints.write(&write_txn)?;
        }

        #[cfg(test)]
        if FAIL_NEXT_BLOCK_IMPORT_COMMIT.with(|fail| fail.replace(false)) {
            return Err(std::io::Error::other("injected block import commit failure").into());
        }
        if let Some(finalized) = record.checkpoints.finalized {
            super::beacon_canonical::record_finalized(&write_txn, finalized.root)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Writes `checkpoints` in one transaction, so readers never see a partial update.
    pub fn commit_checkpoints(
        &self,
        checkpoints: &CheckpointWrites,
    ) -> Result<(), crate::errors::StoreError> {
        if checkpoints.is_empty() {
            return Ok(());
        }
        let mut write_txn = self.db.begin_write()?;
        write_txn.set_durability(Durability::Immediate)?;
        checkpoints.write(&write_txn)?;
        if let Some(finalized) = checkpoints.finalized {
            super::beacon_canonical::record_finalized(&write_txn, finalized.root)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Attach a cache to this BeaconDB instance.
    /// This enables in-memory caching of blocks and states for improved performance.
    pub fn with_cache(mut self, cache: Arc<BeaconCacheDB>) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Drain storage workers and retry retained writes before closing or reopening the DB.
    /// Call only after stopping block/vote producers; this does not provide crash durability.
    pub fn flush_pending_writes(&self) -> Result<(), crate::errors::StoreError> {
        if let Some(cache) = &self.cache {
            cache.join_storage_tasks()?;
        }
        self.latest_messages_provider().flush()?;
        self.state_provider().flush()?;
        Ok(())
    }

    /// Reject new vote/state inserts, then drain all previously accepted writes.
    pub fn shutdown_storage(&self) -> Result<(), crate::errors::StoreError> {
        if let Some(cache) = &self.cache {
            cache.stop_storage_writes();
            cache.stop_vote_flush_timer()?;
        }
        self.flush_pending_writes()
    }

    /// Closes both databases, so the next start opens them without a repair, and returns how.
    ///
    /// A redb database is closed when its last handle is dropped: it then saves its allocator
    /// state and flushes the file. Otherwise the next open repairs it, reading the whole file,
    /// minutes on mainnet. Tasks that are still stopping can hold handles, so this waits up to
    /// `wait` for them. A database still held after that gets a last commit that saves its
    /// allocator state (a quick-repair commit). The next open loads that state instead of
    /// repairing, as long as nothing commits after it. Call it last, after `shutdown_storage`.
    pub fn close(self, wait: Duration) -> Result<Vec<DatabaseClose>, crate::errors::StoreError> {
        let BeaconDB { db, votes_db, .. } = self;
        let deadline = std::time::Instant::now() + wait;
        let mut closes = Vec::new();
        for (name, database) in [("ream.redb", db), ("fork_choice_votes.redb", votes_db)] {
            let mut database = database;
            let close = loop {
                match Arc::try_unwrap(database) {
                    Ok(database) => {
                        drop(database);
                        break DatabaseClose::Closed(name);
                    }
                    Err(err) if std::time::Instant::now() >= deadline => {
                        let mut write_txn = err.begin_write()?;
                        write_txn.set_quick_repair(true);
                        write_txn.commit()?;
                        break DatabaseClose::AllocatorStateSaved {
                            name,
                            other_handles: Arc::strong_count(&err) - 1,
                        };
                    }
                    Err(err) => {
                        database = err;
                        std::thread::sleep(Duration::from_millis(50));
                    }
                }
            };
            closes.push(close);
        }
        Ok(closes)
    }

    /// Writes pending votes at least once per `flush_interval` while any are pending, even when
    /// no inserts arrive to start the write. Inserts write at most once per `flush_interval` too.
    /// Pass one epoch of the network: a write costs about the same whether it carries one
    /// block's votes or an epoch's. `shutdown_storage` stops the timer. Without a cache, every
    /// insert is written immediately and no timer is needed.
    pub fn start_vote_flush_timer(
        &self,
        flush_interval: Duration,
    ) -> Result<(), crate::errors::StoreError> {
        let Some(cache) = &self.cache else {
            return Ok(());
        };
        cache.pending_votes().flush_interval = flush_interval;
        let (stop, stopped) = std::sync::mpsc::channel::<()>();
        // Weak handles: the cache owns the timer, which must not keep the cache or database open.
        let votes_db = Arc::downgrade(&self.votes_db);
        let weak_cache = Arc::downgrade(cache);
        let thread = std::thread::Builder::new()
            .name("vote-flush-timer".to_string())
            .spawn(move || {
                let mut wait = flush_interval;
                loop {
                    match stopped.recv_timeout(wait) {
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                        Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
                    }
                    let (Some(db), Some(cache)) = (votes_db.upgrade(), weak_cache.upgrade()) else {
                        return;
                    };
                    wait = LatestMessagesTable {
                        db,
                        cache: Some(cache),
                    }
                    .flush_if_due();
                }
            })?;
        let previous = cache
            .vote_flush_timer
            .lock()
            .expect("vote flush timer lock is not poisoned")
            .replace(crate::cache::VoteFlushTimer { stop, thread });
        if let Some(previous) = previous {
            drop(previous.stop);
            let _ = previous.thread.join();
        }
        Ok(())
    }

    pub fn block_provider(&self) -> BeaconBlockTable {
        BeaconBlockTable {
            db: self.db.clone(),
            cache: self.cache.clone(),
        }
    }
    pub fn state_provider(&self) -> BeaconStateTable {
        BeaconStateTable {
            db: self.db.clone(),
            data_dir: self.data_dir.clone(),
            cache: self.cache.clone(),
        }
    }

    pub fn blobs_and_proofs_provider(&self) -> BlobsAndProofsTable {
        BlobsAndProofsTable {
            data_dir: self.data_dir.clone(),
        }
    }

    pub fn column_sidecars_provider(&self) -> ColumnSidecarsTable {
        ColumnSidecarsTable {
            db: self.db.clone(),
            data_dir: self.data_dir.clone(),
        }
    }

    pub fn block_timeliness_provider(&self) -> BlockTimelinessTable {
        BlockTimelinessTable {
            db: self.db.clone(),
        }
    }

    pub fn checkpoint_states_provider(&self) -> CheckpointStatesTable {
        CheckpointStatesTable {
            db: self.db.clone(),
            data_dir: self.data_dir.clone(),
            cache: self.cache.clone(),
        }
    }

    pub fn latest_messages_provider(&self) -> LatestMessagesTable {
        LatestMessagesTable {
            db: self.votes_db.clone(),
            cache: self.cache.clone(),
        }
    }

    pub fn unrealized_justifications_provider(&self) -> UnrealizedJustificationsTable {
        UnrealizedJustificationsTable {
            db: self.db.clone(),
        }
    }

    pub fn parent_root_index_multimap_provider(&self) -> ParentRootIndexMultimapTable {
        ParentRootIndexMultimapTable {
            db: self.db.clone(),
        }
    }

    pub fn proposer_boost_root_provider(&self) -> ProposerBoostRootField {
        ProposerBoostRootField {
            db: self.db.clone(),
        }
    }

    pub fn previous_justified_checkpoint_provider(&self) -> PreviousJustifiedCheckpointField {
        PreviousJustifiedCheckpointField {
            db: self.db.clone(),
        }
    }

    pub fn unrealized_finalized_checkpoint_provider(&self) -> UnrealizedFinalizedCheckpointField {
        UnrealizedFinalizedCheckpointField {
            db: self.db.clone(),
        }
    }

    pub fn unrealized_justified_checkpoint_provider(&self) -> UnrealizedJustifiedCheckpointField {
        UnrealizedJustifiedCheckpointField {
            db: self.db.clone(),
        }
    }

    pub fn finalized_checkpoint_provider(&self) -> FinalizedCheckpointField {
        FinalizedCheckpointField {
            db: self.db.clone(),
        }
    }

    pub fn justified_checkpoint_provider(&self) -> JustifiedCheckpointField {
        JustifiedCheckpointField {
            db: self.db.clone(),
        }
    }

    pub fn genesis_time_provider(&self) -> GenesisTimeField {
        GenesisTimeField {
            db: self.db.clone(),
        }
    }

    pub fn time_provider(&self) -> TimeField {
        TimeField {
            db: self.db.clone(),
        }
    }

    pub fn equivocating_indices_provider(&self) -> EquivocatingIndicesField {
        EquivocatingIndicesField {
            db: self.db.clone(),
        }
    }

    pub fn slot_index_provider(&self) -> BeaconSlotIndexTable {
        BeaconSlotIndexTable {
            db: self.db.clone(),
        }
    }

    pub fn state_root_index_provider(&self) -> BeaconStateRootIndexTable {
        BeaconStateRootIndexTable {
            db: self.db.clone(),
        }
    }

    pub fn is_initialized(&self) -> bool {
        match self.slot_index_provider().get_highest_slot() {
            Ok(Some(_)) => !self.bootstrap_in_progress().unwrap_or(true),
            _ => false,
        }
    }

    pub fn get_latest_state(&self) -> anyhow::Result<BeaconState> {
        let highest_root = self
            .slot_index_provider()
            .get_highest_root()?
            .expect("No highest root found");

        let state = self
            .state_provider()
            .get(highest_root)?
            .ok_or_else(|| anyhow!("Unable to fetch latest state"))?;

        Ok(state)
    }

    /// Prune blobs older than the minimum retention period
    pub fn prune_old_blobs(
        &self,
        current_slot: u64,
        min_retention_epochs: u64,
    ) -> anyhow::Result<usize> {
        let min_retention_slots = min_retention_epochs.saturating_mul(SLOTS_PER_EPOCH);
        let finalized_slot = self
            .finalized_checkpoint_provider()
            .get()?
            .epoch
            .saturating_mul(SLOTS_PER_EPOCH);
        let cutoff = current_slot
            .saturating_sub(min_retention_slots)
            .min(finalized_slot);
        let mut expired = HashSet::new();
        // slot_index omits abandoned forks. Inspect only roots with blob files and delete only
        // those whose stored block is old, so recent forks, roots not imported yet and files
        // published during the scan survive.
        for entry in std::fs::read_dir(
            self.data_dir
                .join(crate::tables::beacon::blobs_and_proofs::BLOB_FOLDER_NAME),
        )? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(root) = name
                .to_str()
                .and_then(|name| name.split('_').next())
                .and_then(|root| root.parse::<alloy_primitives::B256>().ok())
            else {
                continue;
            };
            if self
                .block_provider()
                .get(root)?
                .is_some_and(|block| block.message.slot < cutoff)
            {
                expired.insert(root);
            }
        }

        let pruned_count = self.blobs_and_proofs_provider().prune_old_blobs(&expired)?;

        Ok(pruned_count)
    }
}

#[cfg(test)]
thread_local! {
    static FAIL_NEXT_BLOCK_IMPORT_COMMIT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
mod tests {
    use ream_consensus_beacon::electra::beacon_block::BeaconBlock;
    use tempdir::TempDir;
    use tree_hash::TreeHash;

    use super::*;
    use crate::{
        db::ReamDB,
        tables::{
            beacon::state_summaries::{BeaconStateSummariesTable, StateSummary},
            multimap_table::MultimapTable,
            table::REDBTable,
        },
        test_utils::sepolia_state,
    };

    fn signed_block() -> SignedBeaconBlock {
        SignedBeaconBlock {
            message: BeaconBlock::default(),
            signature: Default::default(),
        }
    }

    /// Commits `block` alone, without a state, as if its post-state were not stored whole.
    fn commit_block_rows(
        db: &BeaconDB,
        root: alloy_primitives::B256,
        block: &SignedBeaconBlock,
    ) -> Result<(), crate::errors::StoreError> {
        let summary = StateSummary {
            slot: block.message.slot,
            stored_whole: false,
        };
        db.commit_block_import_transaction(root, block, summary, &ForkChoiceRecord::default())
    }

    #[test]
    fn failed_block_import_transaction_writes_nothing() {
        let dir = TempDir::new("ream_atomic_block_import_failure").unwrap();
        let db = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        let root = alloy_primitives::B256::repeat_byte(0x42);
        let block = signed_block();

        FAIL_NEXT_BLOCK_IMPORT_COMMIT.with(|fail| fail.set(true));
        assert!(commit_block_rows(&db, root, &block).is_err());
        assert_eq!(db.block_provider().get(root).unwrap(), None);
        assert_eq!(
            BeaconStateSummariesTable { db: db.db.clone() }
                .get(root)
                .unwrap(),
            None
        );
        assert_eq!(db.slot_index_provider().get(0).unwrap(), None);
        assert_eq!(
            db.state_root_index_provider()
                .get(Default::default())
                .unwrap(),
            None
        );
        assert!(
            db.parent_root_index_multimap_provider()
                .get(Default::default())
                .unwrap()
                .unwrap_or_default()
                .is_empty()
        );

        drop(db);
        let reopened = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        assert_eq!(reopened.block_provider().get(root).unwrap(), None);
        assert_eq!(
            BeaconStateSummariesTable {
                db: reopened.db.clone()
            }
            .get(root)
            .unwrap(),
            None
        );
    }

    #[test]
    fn block_import_transaction_commits_all_tables_together() {
        let dir = TempDir::new("ream_atomic_block_import_success").unwrap();
        let db = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        let root = alloy_primitives::B256::repeat_byte(0x24);
        let block = signed_block();

        commit_block_rows(&db, root, &block).unwrap();
        assert!(db.block_provider().get(root).unwrap().is_some());
        assert!(
            BeaconStateSummariesTable { db: db.db.clone() }
                .get(root)
                .unwrap()
                .is_some()
        );

        drop(db);
        let reopened = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        assert!(reopened.block_provider().get(root).unwrap().is_some());
        assert!(
            BeaconStateSummariesTable {
                db: reopened.db.clone()
            }
            .get(root)
            .unwrap()
            .is_some()
        );
    }

    /// A block import whose transaction fails must leave no row, cache entry, pending state or
    /// state file behind, so the same import can run again and publish everything once.
    #[test]
    fn failed_block_import_publishes_nothing_and_can_be_retried() {
        let dir = TempDir::new("ream_atomic_block_import_retry").unwrap();
        let cache = Arc::new(BeaconCacheDB::new());
        let db = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap()
            .with_cache(cache.clone());
        let root = alloy_primitives::B256::repeat_byte(0x42);
        // The state's parent has no summary, so the import writes its state file before the
        // transaction, as for a checkpoint sync anchor.
        let state = sepolia_state();
        let state_file = dir
            .path()
            .join(crate::tables::beacon::beacon_state::STATE_FOLDER_NAME)
            .join(format!("{root}.ssz_snappy"));
        let import = || BlockImportData {
            block_root: root,
            block: {
                let mut block = signed_block();
                block.message.slot = state.slot;
                block.message.state_root = state.tree_hash_root();
                block
            },
            state: state.clone(),
            record: ForkChoiceRecord {
                is_timely: true,
                proposer_boost_root: Some(root),
                checkpoints: CheckpointWrites {
                    justified: Some(Checkpoint { epoch: 7, root }),
                    ..Default::default()
                },
                ..Default::default()
            },
        };
        let justified_before = db.justified_checkpoint_provider().get().ok();

        FAIL_NEXT_BLOCK_IMPORT_COMMIT.with(|fail| fail.set(true));
        assert!(db.commit_block_import(import()).is_err());
        assert!(!state_file.exists());
        assert!(cache.blocks.lock().unwrap().peek(&root).is_none());
        assert!(cache.states.lock().unwrap().peek(&root).is_none());
        assert!(cache.pending_state_snapshots.lock().unwrap().is_empty());
        assert_eq!(db.block_provider().get(root).unwrap(), None);
        assert!(db.state_provider().get_shared(root).unwrap().is_none());
        assert_eq!(db.block_timeliness_provider().get(root).unwrap(), None);
        assert_eq!(
            db.justified_checkpoint_provider().get().ok(),
            justified_before
        );

        db.commit_block_import(import()).unwrap();
        assert!(state_file.exists());
        assert!(db.state_provider().is_stored_whole(root).unwrap());
        assert!(cache.blocks.lock().unwrap().peek(&root).is_some());
        let cached = cache.states.lock().unwrap().peek(&root).cloned().unwrap();
        assert!(Arc::ptr_eq(&cached, &state));
        assert!(cache.pending_state_snapshots.lock().unwrap().is_empty());
        assert_eq!(
            db.block_timeliness_provider().get(root).unwrap(),
            Some(true)
        );
        assert_eq!(db.proposer_boost_root_provider().get().unwrap(), root);
        assert_eq!(
            db.justified_checkpoint_provider().get().unwrap(),
            Checkpoint { epoch: 7, root }
        );

        drop(db);
        let reopened = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        assert!(reopened.block_provider().get(root).unwrap().is_some());
        assert_eq!(
            reopened
                .state_provider()
                .get_shared(root)
                .unwrap()
                .as_deref(),
            Some(state.as_ref())
        );
    }
}
