//! Historical block commits. Blocks below the origin never pass through fork choice: they are
//! proven by hash linkage to the block frontier and written without states or fork-choice indexes.
use alloy_primitives::B256;
use anyhow::anyhow;
use ream_consensus_beacon::electra::beacon_block::SignedBeaconBlock;
use redb::{Durability, ReadableTable};
use ssz::{Decode, Encode};

use super::beacon::BeaconDB;
use crate::{
    errors::StoreError,
    tables::{
        beacon::{
            backfill::{
                BOOTSTRAP, BackfillMeta, BackfillMode, BlockBackfillState, Frontier, MARKER, META,
            },
            beacon_block::BeaconBlockTable,
            slot_index::BeaconSlotIndexTable,
        },
        table::REDBTable,
    },
};

#[derive(Debug, thiserror::Error)]
pub enum CommitError {
    /// Metadata moved since the caller read it. Re-read and re-evaluate; nothing was written.
    #[error("Backfill revision changed: expected {expected}, found {found}")]
    Conflict { expected: u64, found: u64 },
    /// The highest block is not the parent of the current block frontier. Nothing was written.
    #[error("Historical blocks do not connect to the block frontier")]
    NotConnected,
    #[error("Invalid historical commit: {0}")]
    Invalid(String),
    #[error(transparent)]
    Store(#[from] anyhow::Error),
}

impl BeaconDB {
    /// Extends the block frontier downwards in one durable transaction.
    ///
    /// `blocks` are `(hash_tree_root, block)` pairs in ascending slot order whose proposer
    /// signatures the caller has verified. The highest block must be the parent of the current
    /// frontier. The frontier becomes the lowest block, and the state becomes `BlocksComplete`
    /// once it is at or below `target_slot` or at genesis.
    pub fn commit_historical_blocks(
        &self,
        expected_revision: u64,
        blocks: &[(B256, SignedBeaconBlock)],
        target_slot: u64,
    ) -> Result<BackfillMeta, CommitError> {
        let (Some((lowest_root, lowest)), Some((highest_root, highest))) =
            (blocks.first(), blocks.last())
        else {
            return Err(CommitError::Invalid("no blocks to commit".to_string()));
        };
        for pair in blocks.windows(2) {
            let ((parent_root, parent), (_, child)) = (&pair[0], &pair[1]);
            if parent.message.slot >= child.message.slot
                || child.message.parent_root != *parent_root
            {
                return Err(CommitError::Invalid(
                    "blocks are not an ascending hash chain".to_string(),
                ));
            }
        }

        self.update_backfill_meta(expected_revision, |write, meta| {
            if meta.blocks.state != BlockBackfillState::InProgress {
                return Ok(Err(CommitError::Invalid(format!(
                    "block backfill already ended as {:?}",
                    meta.blocks.state
                ))));
            }
            let frontier = &meta.blocks.frontier;
            if *highest_root != frontier.oldest_block_parent {
                return Ok(Err(CommitError::NotConnected));
            }
            if highest.message.slot >= frontier.oldest_block_slot {
                return Ok(Err(CommitError::Invalid(
                    "parent of the frontier is not below it".to_string(),
                )));
            }

            let mut block_table = write
                .open_table(BeaconBlockTable::TABLE_DEFINITION)
                .map_err(StoreError::from)?;
            let mut slot_index = write
                .open_table(BeaconSlotIndexTable::TABLE_DEFINITION)
                .map_err(StoreError::from)?;
            for (root, block) in blocks {
                block_table
                    .insert(*root, block.clone())
                    .map_err(StoreError::from)?;
                slot_index
                    .insert(block.message.slot, *root)
                    .map_err(StoreError::from)?;
            }

            meta.blocks.frontier = Frontier {
                oldest_block_slot: lowest.message.slot,
                oldest_block_root: *lowest_root,
                oldest_block_parent: lowest.message.parent_root,
            };
            if lowest.message.slot == 0 || lowest.message.slot <= target_slot {
                meta.blocks.state = BlockBackfillState::BlocksComplete;
            }
            Ok(Ok(()))
        })
    }

    /// Records a terminal block backfill state without moving the frontier.
    pub fn set_block_backfill_state(
        &self,
        expected_revision: u64,
        state: BlockBackfillState,
    ) -> Result<BackfillMeta, CommitError> {
        if state == BlockBackfillState::InProgress {
            return Err(CommitError::Invalid(
                "block backfill cannot be reopened".to_string(),
            ));
        }
        self.update_backfill_meta(expected_revision, |_, meta| {
            if meta.blocks.state != BlockBackfillState::InProgress {
                return Ok(Err(CommitError::Invalid(format!(
                    "block backfill already ended as {:?}",
                    meta.blocks.state
                ))));
            }
            meta.blocks.state = state;
            Ok(Ok(()))
        })
    }

    /// The caller has verified and durably published every required column in the newly covered
    /// interval. This axis remains writable after block backfill has completed.
    pub fn commit_sidecar_coverage(
        &self,
        expected_revision: u64,
        new_frontier: u64,
    ) -> Result<BackfillMeta, CommitError> {
        self.update_backfill_meta(expected_revision, |_, meta| {
            let Some(previous) = meta.sidecars.frontier else {
                return Ok(Err(CommitError::Invalid(
                    "anchor sidecars are pending".to_string(),
                )));
            };
            if new_frontier >= previous || new_frontier < meta.blocks.frontier.oldest_block_slot {
                return Ok(Err(CommitError::Invalid(
                    "invalid sidecar frontier".to_string(),
                )));
            }
            meta.sidecars.frontier = Some(new_frontier);
            Ok(Ok(()))
        })
    }

    /// Forget coverage outside the moving retention window without changing advertised history.
    /// Coverage is bounded by the origin; a pending anchor belongs to anchor recovery.
    pub fn advance_sidecar_retention(
        &self,
        expected_revision: u64,
        da_start: u64,
    ) -> Result<BackfillMeta, CommitError> {
        self.update_backfill_meta(expected_revision, |_, meta| {
            if let Some(previous) = meta.sidecars.frontier {
                meta.sidecars.frontier = Some(previous.max(da_start.min(meta.origin.slot)));
            }
            Ok(Ok(()))
        })
    }

    /// Compare-and-swap on `revision`. `update` runs inside the write transaction and only its
    /// `Ok(Ok(()))` result is committed; the shared metadata cache changes after the commit.
    fn update_backfill_meta(
        &self,
        expected_revision: u64,
        update: impl FnOnce(
            &redb::WriteTransaction,
            &mut BackfillMeta,
        ) -> anyhow::Result<Result<(), CommitError>>,
    ) -> Result<BackfillMeta, CommitError> {
        let mut cache = self
            .bootstrap_cache
            .lock()
            .unwrap_or_else(|err| err.into_inner());

        let mut write = self.db.begin_write().map_err(StoreError::from)?;
        write
            .set_durability(Durability::Immediate)
            .map_err(StoreError::from)?;
        let mut meta = {
            let table = write.open_table(BOOTSTRAP).map_err(StoreError::from)?;
            if table
                .get(MARKER)
                .map_err(StoreError::from)?
                .is_none_or(|marker| marker.value() != [1])
            {
                return Err(CommitError::Invalid(
                    "database was not bootstrapped from a checkpoint".to_string(),
                ));
            }
            let raw = table
                .get(META)
                .map_err(StoreError::from)?
                .ok_or_else(|| anyhow!("Missing backfill metadata"))?;
            BackfillMeta::from_ssz_bytes(raw.value()).map_err(StoreError::from)?
        };
        if meta.revision != expected_revision {
            return Err(CommitError::Conflict {
                expected: expected_revision,
                found: meta.revision,
            });
        }

        update(&write, &mut meta)??;

        meta.revision = meta
            .revision
            .checked_add(1)
            .ok_or_else(|| anyhow!("Backfill revision overflow"))?;
        write
            .open_table(BOOTSTRAP)
            .map_err(StoreError::from)?
            .insert(META, meta.as_ssz_bytes().as_slice())
            .map_err(StoreError::from)?;
        write.commit().map_err(StoreError::from)?;

        *cache = Some(BackfillMode::Checkpoint(meta.clone()));
        Ok(meta)
    }
}

impl From<StoreError> for CommitError {
    fn from(err: StoreError) -> Self {
        CommitError::Store(err.into())
    }
}

#[cfg(test)]
mod tests {
    use tempdir::TempDir;
    use tree_hash::TreeHash;

    use super::*;
    use crate::{
        db::ReamDB,
        tables::{
            beacon::backfill::{BlockCoverage, GVR, Origin, SidecarCoverage},
            multimap_table::MultimapTable,
        },
    };

    fn block(slot: u64, parent_root: B256) -> (B256, SignedBeaconBlock) {
        let mut block = SignedBeaconBlock {
            message: Default::default(),
            signature: Default::default(),
        };
        block.message.slot = slot;
        block.message.parent_root = parent_root;
        (block.message.tree_hash_root(), block)
    }

    /// Hash chain over `slots` (ascending), rooted at `B256::ZERO`.
    fn chain(slots: &[u64]) -> Vec<(B256, SignedBeaconBlock)> {
        let mut parent_root = B256::ZERO;
        slots
            .iter()
            .map(|slot| {
                let entry = block(*slot, parent_root);
                parent_root = entry.0;
                entry
            })
            .collect()
    }

    /// A checkpoint database whose origin and block frontier are `anchor`.
    fn checkpoint_db(dir: &TempDir, anchor: &(B256, SignedBeaconBlock)) -> BeaconDB {
        let db = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        db.block_provider()
            .insert(anchor.0, anchor.1.clone())
            .unwrap();
        let meta = BackfillMeta {
            revision: 0,
            origin: Origin {
                slot: anchor.1.message.slot,
                root: anchor.0,
                state_root: anchor.1.message.state_root,
            },
            blocks: BlockCoverage {
                frontier: Frontier {
                    oldest_block_slot: anchor.1.message.slot,
                    oldest_block_root: anchor.0,
                    oldest_block_parent: anchor.1.message.parent_root,
                },
                state: BlockBackfillState::InProgress,
            },
            sidecars: SidecarCoverage { frontier: None },
        };
        let write = db.db.begin_write().unwrap();
        {
            let mut table = write.open_table(BOOTSTRAP).unwrap();
            table.insert(MARKER, &[1u8][..]).unwrap();
            table
                .insert(GVR, B256::ZERO.as_ssz_bytes().as_slice())
                .unwrap();
            table.insert(META, meta.as_ssz_bytes().as_slice()).unwrap();
        }
        write.commit().unwrap();
        db
    }

    fn meta(db: &BeaconDB) -> BackfillMeta {
        match db.backfill_mode().unwrap() {
            BackfillMode::Checkpoint(meta) => meta,
            mode => panic!("unexpected mode {mode:?}"),
        }
    }

    #[test]
    fn sidecar_progress_and_retention_remain_writable_after_block_completion() {
        let dir = TempDir::new("sidecar_commit").unwrap();
        let blocks = chain(&[10, 20]);
        let db = checkpoint_db(&dir, &blocks[1]);
        db.confirm_anchor_sidecars(blocks[1].0).unwrap();
        let meta = meta(&db);
        let done = db
            .commit_historical_blocks(meta.revision, &blocks[..1], 10)
            .unwrap();
        assert_eq!(done.blocks.state, BlockBackfillState::BlocksComplete);
        let covered = db.commit_sidecar_coverage(done.revision, 10).unwrap();
        assert!(matches!(
            db.commit_sidecar_coverage(done.revision, 10),
            Err(CommitError::Conflict { .. })
        ));
        let advertised = covered.earliest_available_slot(15);
        let pruned = db.advance_sidecar_retention(covered.revision, 15).unwrap();
        assert_eq!(pruned.sidecars.frontier, Some(15));
        assert_eq!(pruned.earliest_available_slot(15), advertised);
        let expired = db.advance_sidecar_retention(pruned.revision, 99).unwrap();
        assert_eq!(expired.sidecars.frontier, Some(20));
        db.backfill_mode().unwrap();
    }

    #[test]
    fn commit_moves_frontier_without_states_or_fork_choice_indexes() {
        let dir = TempDir::new("backfill_commit").unwrap();
        let blocks = chain(&[10, 11, 13, 20]);
        let db = checkpoint_db(&dir, &blocks[3]);
        assert_eq!(
            db.cached_backfill_mode().unwrap(),
            BackfillMode::Checkpoint(meta(&db))
        );

        let committed = db.commit_historical_blocks(0, &blocks[1..3], 0).unwrap();

        assert_eq!(committed.revision, 1);
        assert_eq!(committed.blocks.state, BlockBackfillState::InProgress);
        assert_eq!(
            committed.blocks.frontier,
            Frontier {
                oldest_block_slot: 11,
                oldest_block_root: blocks[1].0,
                oldest_block_parent: blocks[0].0,
            }
        );
        // Both the on-disk metadata (validated against the stored blocks) and the shared
        // runtime snapshot observe the commit.
        assert_eq!(meta(&db), committed);
        assert_eq!(
            db.cached_backfill_mode().unwrap(),
            BackfillMode::Checkpoint(committed)
        );
        for (root, block) in &blocks[1..3] {
            assert_eq!(
                db.block_provider().get(*root).unwrap().as_ref(),
                Some(block)
            );
            assert_eq!(
                db.slot_index_provider().get(block.message.slot).unwrap(),
                Some(*root)
            );
            assert!(db.state_provider().get(*root).unwrap().is_none());
            assert!(
                db.parent_root_index_multimap_provider()
                    .get(block.message.parent_root)
                    .unwrap()
                    .is_none_or(|children| children.is_empty())
            );
        }
        assert_eq!(db.slot_index_provider().get(12).unwrap(), None);
    }

    #[test]
    fn rejected_commits_leave_database_and_cache_unchanged() {
        let dir = TempDir::new("backfill_reject").unwrap();
        let blocks = chain(&[10, 11, 13, 20]);
        let db = checkpoint_db(&dir, &blocks[3]);
        let before = meta(&db);
        db.cached_backfill_mode().unwrap();

        // Stale revision.
        assert!(matches!(
            db.commit_historical_blocks(7, &blocks[1..3], 0),
            Err(CommitError::Conflict {
                expected: 7,
                found: 0
            })
        ));
        // Internally linked, but the top is not the parent of the frontier.
        assert!(matches!(
            db.commit_historical_blocks(0, &blocks[0..2], 0),
            Err(CommitError::NotConnected)
        ));
        // Not a hash chain.
        assert!(matches!(
            db.commit_historical_blocks(0, &[blocks[0].clone(), blocks[2].clone()], 0),
            Err(CommitError::Invalid(_))
        ));
        assert!(matches!(
            db.commit_historical_blocks(0, &[], 0),
            Err(CommitError::Invalid(_))
        ));

        assert_eq!(meta(&db), before);
        assert_eq!(
            db.cached_backfill_mode().unwrap(),
            BackfillMode::Checkpoint(before)
        );
        for (root, block) in &blocks[0..3] {
            assert!(db.block_provider().get(*root).unwrap().is_none());
            assert_eq!(
                db.slot_index_provider().get(block.message.slot).unwrap(),
                None
            );
        }
    }

    #[test]
    fn conflicting_revision_is_retried_without_new_data() {
        let dir = TempDir::new("backfill_cas").unwrap();
        let blocks = chain(&[10, 11, 20]);
        let db = checkpoint_db(&dir, &blocks[2]);

        // A sidecar-only commit bumps the revision while the block segment is being verified.
        db.confirm_anchor_sidecars(blocks[2].0).unwrap();
        let Err(CommitError::Conflict { found, .. }) =
            db.commit_historical_blocks(0, &blocks[0..2], 0)
        else {
            panic!("expected a revision conflict");
        };

        let committed = db
            .commit_historical_blocks(found, &blocks[0..2], 0)
            .unwrap();
        assert_eq!(committed.revision, 2);
        assert_eq!(committed.blocks.frontier.oldest_block_slot, 10);
        assert_eq!(committed.sidecars.frontier, Some(20));
    }

    #[test]
    fn reaching_target_or_genesis_completes_block_backfill() {
        let dir = TempDir::new("backfill_target").unwrap();
        let blocks = chain(&[0, 5, 9, 20]);
        let db = checkpoint_db(&dir, &blocks[3]);

        let above_target = db.commit_historical_blocks(0, &blocks[2..3], 6).unwrap();
        assert_eq!(above_target.blocks.state, BlockBackfillState::InProgress);
        let at_target = db.commit_historical_blocks(1, &blocks[1..2], 6).unwrap();
        assert_eq!(at_target.blocks.state, BlockBackfillState::BlocksComplete);
        // Finished backfill is not reopened, even though the genesis block still connects.
        assert!(matches!(
            db.commit_historical_blocks(2, &blocks[0..1], 0),
            Err(CommitError::Invalid(_))
        ));

        let dir = TempDir::new("backfill_genesis").unwrap();
        let db = checkpoint_db(&dir, &blocks[1]);
        let genesis = db.commit_historical_blocks(0, &blocks[0..1], 0).unwrap();
        assert_eq!(genesis.blocks.state, BlockBackfillState::BlocksComplete);
        assert_eq!(genesis.blocks.frontier.oldest_block_slot, 0);
    }

    #[test]
    fn terminal_state_is_recorded_once() {
        let dir = TempDir::new("backfill_state").unwrap();
        let blocks = chain(&[64, 70]);
        let db = checkpoint_db(&dir, &blocks[1]);
        let boundary = BlockBackfillState::UnsupportedForkBoundary { boundary_slot: 64 };

        assert!(matches!(
            db.set_block_backfill_state(0, BlockBackfillState::InProgress),
            Err(CommitError::Invalid(_))
        ));
        let updated = db.set_block_backfill_state(0, boundary.clone()).unwrap();
        assert_eq!(updated.blocks.state, boundary);
        assert_eq!(updated.blocks.frontier.oldest_block_slot, 70);
        assert_eq!(meta(&db), updated);
        assert!(matches!(
            db.set_block_backfill_state(1, BlockBackfillState::BlocksComplete),
            Err(CommitError::Invalid(_))
        ));
    }
}
