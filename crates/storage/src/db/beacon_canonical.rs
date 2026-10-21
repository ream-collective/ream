//! Finalized history is indexed separately from imports of competing forks.
use std::collections::BTreeMap;

use alloy_primitives::B256;
use redb::{ReadableDatabase, ReadableTable, TableDefinition, WriteTransaction};

use super::beacon::BeaconDB;
use crate::{
    errors::StoreError,
    tables::{beacon::beacon_block::BeaconBlockTable, ssz_encoder::SSZEncoding, table::REDBTable},
};

pub(crate) const CANONICAL_ROOTS: TableDefinition<u64, SSZEncoding<B256>> =
    TableDefinition::new("beacon_canonical_block_roots");

pub(crate) fn record_finalized(write: &WriteTransaction, mut root: B256) -> Result<(), StoreError> {
    let blocks = write.open_table(BeaconBlockTable::TABLE_DEFINITION)?;
    let mut canonical = write.open_table(CANONICAL_ROOTS)?;
    loop {
        let Some(block) = blocks.get(root)?.map(|block| block.value()) else {
            break;
        };
        let slot = block.message.slot;
        if canonical
            .get(slot)?
            .is_some_and(|stored| stored.value() == root)
        {
            break;
        }
        canonical.insert(slot, root)?;
        if slot == 0 {
            break;
        }
        let parent = block.message.parent_root;
        if let Some(block) = blocks.get(parent)?.map(|block| block.value())
            && block.message.slot >= slot
        {
            return Err(std::io::Error::other("Non-descending canonical ancestry").into());
        }
        root = parent;
    }
    Ok(())
}

impl BeaconDB {
    pub fn record_finalized_canonical(&self, root: B256) -> Result<(), StoreError> {
        let mut write = self.db.begin_write()?;
        write.set_durability(redb::Durability::Immediate)?;
        record_finalized(&write, root)?;
        write.commit()?;
        Ok(())
    }

    /// A consistent finalized snapshot plus the ancestry of the caller's head snapshot. Imported
    /// forks and skipped slots never appear in this range. Historical backfill fills the same
    /// canonical table by hash linkage to the checkpoint origin.
    ///
    /// The head ancestry is used only when it passes through the latest finalized block of this
    /// snapshot, so a stale head on an abandoned branch never mixes with finalized roots.
    pub fn canonical_roots_in_range(
        &self,
        mut head: B256,
        start: u64,
        end: u64,
    ) -> Result<Vec<(u64, B256)>, StoreError> {
        if start >= end {
            return Ok(Vec::new());
        }
        let read = self.db.begin_read()?;
        let canonical = read.open_table(CANONICAL_ROOTS)?;
        let mut result = BTreeMap::new();
        for entry in canonical.range(start..end)? {
            let (slot, root) = entry?;
            result.insert(slot.value(), root.value());
        }
        let tip = canonical
            .last()?
            .map(|(slot, root)| (slot.value(), root.value()));
        let blocks = read.open_table(BeaconBlockTable::TABLE_DEFINITION)?;
        let mut ancestry = Vec::new();
        let descends = loop {
            // Without finality the oldest stored block ends the chain; with it, a chain must
            // reach the finalized block.
            let Some(block) = blocks.get(head)?.map(|block| block.value()) else {
                break tip.is_none();
            };
            let slot = block.message.slot;
            if let Some((tip_slot, tip_root)) = tip
                && slot <= tip_slot
            {
                break head == tip_root;
            }
            if (start..end).contains(&slot) {
                ancestry.push((slot, head));
            }
            if slot == 0 {
                break true;
            }
            let parent = block.message.parent_root;
            if let Some(block) = blocks.get(parent)?.map(|block| block.value())
                && block.message.slot >= slot
            {
                return Err(std::io::Error::other("Non-descending head ancestry").into());
            }
            head = parent;
        };
        if descends {
            result.extend(ancestry);
        }
        Ok(result.into_iter().collect())
    }

    pub fn canonical_root_before(&self, slot: u64) -> Result<Option<B256>, StoreError> {
        let read = self.db.begin_read()?;
        let table = read.open_table(CANONICAL_ROOTS)?;
        table
            .range(..slot)?
            .next_back()
            .map(|entry| {
                entry
                    .map(|(_, root)| root.value())
                    .map_err(StoreError::from)
            })
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use ream_consensus_beacon::electra::beacon_block::{BeaconBlock, SignedBeaconBlock};
    use tree_hash::TreeHash;

    use super::*;
    use crate::db::ReamDB;

    #[test]
    fn ranges_ignore_imported_forks_and_follow_the_selected_head_across_skips() {
        let dir = tempfile::tempdir().unwrap();
        let db = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        let mut parent = B256::ZERO;
        let mut canonical = Vec::new();
        for slot in [0, 2, 5, 7] {
            let block = SignedBeaconBlock {
                message: BeaconBlock {
                    slot,
                    parent_root: parent,
                    ..Default::default()
                },
                signature: Default::default(),
            };
            parent = block.message.tree_hash_root();
            db.block_provider().insert(parent, block).unwrap();
            canonical.push((slot, parent));
        }
        db.record_finalized_canonical(canonical[1].1).unwrap();
        for slot in [1, 2, 5, 6] {
            let block = SignedBeaconBlock {
                message: BeaconBlock {
                    slot,
                    parent_root: canonical[0].1,
                    state_root: B256::repeat_byte(42),
                    ..Default::default()
                },
                signature: Default::default(),
            };
            db.block_provider()
                .insert(block.message.tree_hash_root(), block)
                .unwrap();
        }
        assert_eq!(
            db.canonical_roots_in_range(parent, 0, 8).unwrap(),
            canonical
        );
        db.record_finalized_canonical(parent).unwrap();
        assert_eq!(
            db.canonical_roots_in_range(parent, 1, 7).unwrap(),
            canonical[1..3]
        );
        assert_eq!(db.canonical_root_before(5).unwrap(), Some(canonical[1].1));
    }

    #[test]
    fn a_stale_head_off_the_finalized_chain_adds_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let db = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        let block = |slot, parent_root, tag| SignedBeaconBlock {
            message: BeaconBlock {
                slot,
                parent_root,
                state_root: B256::repeat_byte(tag),
                ..Default::default()
            },
            signature: Default::default(),
        };
        let insert = |block: SignedBeaconBlock| {
            let root = block.message.tree_hash_root();
            db.block_provider().insert(root, block).unwrap();
            root
        };
        let genesis = insert(block(0, B256::ZERO, 0));
        let finalized = insert(block(2, genesis, 0));
        let child = insert(block(4, finalized, 0));
        // A branch from genesis that skips the finalized block.
        let fork = insert(block(3, genesis, 1));
        let stale = insert(block(6, fork, 1));
        db.record_finalized_canonical(finalized).unwrap();
        assert_eq!(
            db.canonical_roots_in_range(stale, 0, 8).unwrap(),
            vec![(0, genesis), (2, finalized)]
        );
        assert_eq!(
            db.canonical_roots_in_range(child, 0, 8).unwrap(),
            vec![(0, genesis), (2, finalized), (4, child)]
        );
    }
}
