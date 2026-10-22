//! Column retention. File deletion precedes index deletion so interrupted pruning is retryable.
use std::{collections::HashSet, fs, path::PathBuf};

use alloy_primitives::B256;
use ream_consensus_beacon::data_column_sidecar::{ColumnIdentifier, NUMBER_OF_COLUMNS};
use redb::{Durability, ReadableDatabase, ReadableTable};
use tree_hash::TreeHash;

use super::beacon::BeaconDB;
use crate::{
    errors::StoreError,
    tables::{
        beacon::{
            column_roots_by_slot::{
                COLUMN_MAINTENANCE, COLUMN_ROOTS_BY_SLOT, COLUMN_WRITER, INDEX_VERSION,
                PRUNED_BEFORE,
            },
            column_sidecars::{
                COLUMN_FOLDER_NAME, check_block_dir, column_block_dir, column_file_path,
                is_block_dir_name, remove_block_dir,
            },
        },
        table::{CustomTable, REDBTable},
    },
};

impl BeaconDB {
    /// Runs before network writers start. The marker commits only after the entire directory has
    /// been indexed; repeating a partially completed migration is safe.
    pub(crate) fn migrate_column_index(&self) -> Result<(), StoreError> {
        let _writer = COLUMN_WRITER.lock().unwrap_or_else(|err| err.into_inner());
        if self
            .db
            .begin_read()?
            .open_table(COLUMN_MAINTENANCE)?
            .get(INDEX_VERSION)?
            .is_some()
        {
            return Ok(());
        }
        let mut roots = HashSet::new();
        for entry in fs::read_dir(self.data_dir.join(COLUMN_FOLDER_NAME))? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let root = entry
                .file_name()
                .to_str()
                .filter(|name| is_block_dir_name(name))
                .and_then(|name| name.parse::<B256>().ok())
                .ok_or_else(|| std::io::Error::other("Invalid column directory name"))?;
            roots.insert(root);
        }
        for root in roots {
            // Columns can be stored before their block, so a missing block takes the slot from a
            // sidecar's own header. A directory with no readable sidecar of that root is kept.
            let slot = match self.block_provider().get(root)? {
                Some(block) => Some(block.message.slot),
                None => self.stored_column_slot(root)?,
            };
            match slot {
                Some(slot) => {
                    let mut write = self.db.begin_write()?;
                    write.set_durability(Durability::Immediate)?;
                    write
                        .open_multimap_table(COLUMN_ROOTS_BY_SLOT)?
                        .insert(slot, root)?;
                    write.commit()?;
                }
                None => tracing::warn!(
                    "Kept unindexed column directory {}: no readable sidecar of its root",
                    column_block_dir(&self.data_dir, &root).display()
                ),
            }
        }
        let mut write = self.db.begin_write()?;
        write.set_durability(Durability::Immediate)?;
        write
            .open_table(COLUMN_MAINTENANCE)?
            .insert(INDEX_VERSION, 1)?;
        write.commit()?;
        Ok(())
    }

    /// The slot in the header of a stored column of `root`, if one is readable and signed for it.
    fn stored_column_slot(&self, root: B256) -> Result<Option<u64>, StoreError> {
        for index in 0..NUMBER_OF_COLUMNS {
            if let Ok(Some(column)) = self
                .column_sidecars_provider()
                .get(ColumnIdentifier::new(root, index))
                && column.signed_block_header.message.tree_hash_root() == root
            {
                return Ok(Some(column.signed_block_header.message.slot));
            }
        }
        Ok(None)
    }

    /// Removes a block's column files, then its directory. A directory holding anything else is
    /// kept.
    fn remove_column_files(&self, root: B256) -> Result<usize, StoreError> {
        let dir = column_block_dir(&self.data_dir, &root);
        match fs::symlink_metadata(&dir) {
            Ok(metadata) if !metadata.is_dir() => {
                tracing::warn!("Kept {}: not a directory", dir.display());
                return Ok(0);
            }
            Ok(_) => {
                if let Err(err) = check_block_dir(&dir) {
                    tracing::warn!("Kept column directory: {err}");
                    return Ok(0);
                }
            }
            // Removed already, before a crash kept its index entry.
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(err) => return Err(err.into()),
        }
        let removed =
            crate::tables::sidecar_file::remove_published_batch(&self.column_paths(root))?;
        if dir.exists() {
            remove_block_dir(&dir)?;
        }
        Ok(removed)
    }

    fn column_paths(&self, root: B256) -> Vec<PathBuf> {
        (0..NUMBER_OF_COLUMNS)
            .map(|index| column_file_path(&self.data_dir, &ColumnIdentifier::new(root, index)))
            .collect()
    }

    /// Prunes at most `max_roots` per invocation, taking the writer lock for one root at a time
    /// so a large backlog does not starve live column publication. Never crosses finality.
    pub fn prune_columns(
        &self,
        da_start: u64,
        finalized_slot: u64,
        max_roots: usize,
    ) -> Result<usize, StoreError> {
        let cutoff = da_start.min(finalized_slot);
        let roots = {
            let read = self.db.begin_read()?;
            let table = read.open_multimap_table(COLUMN_ROOTS_BY_SLOT)?;
            let mut roots = Vec::new();
            'slots: for entry in table.range(..cutoff)? {
                let (slot, values) = entry?;
                for root in values {
                    if roots.len() >= max_roots {
                        break 'slots;
                    }
                    roots.push((slot.value(), root?.value()));
                }
            }
            roots
        };
        {
            let _writer = COLUMN_WRITER.lock().unwrap_or_else(|err| err.into_inner());
            // Publish the watermark first: interrupted pruning leaves its index for retry.
            let mut write = self.db.begin_write()?;
            write.set_durability(Durability::Immediate)?;
            {
                let mut table = write.open_table(COLUMN_MAINTENANCE)?;
                let previous = table
                    .get(PRUNED_BEFORE)?
                    .map(|value| value.value())
                    .unwrap_or_default();
                table.insert(PRUNED_BEFORE, cutoff.max(previous))?;
            }
            write.commit()?;
        }
        let mut removed = 0;
        for (slot, root) in roots {
            let _writer = COLUMN_WRITER.lock().unwrap_or_else(|err| err.into_inner());
            removed += self.remove_column_files(root)?;
            let mut write = self.db.begin_write()?;
            write.set_durability(Durability::Immediate)?;
            write
                .open_multimap_table(COLUMN_ROOTS_BY_SLOT)?
                .remove(slot, root)?;
            write.commit()?;
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use ream_consensus_beacon::{
        data_column_sidecar::{ColumnIdentifier, DataColumnSidecar},
        electra::beacon_block::{BeaconBlock, SignedBeaconBlock},
    };

    use super::*;
    use crate::db::ReamDB;

    fn column(slot: u64) -> (B256, SignedBeaconBlock, DataColumnSidecar) {
        let block = SignedBeaconBlock {
            message: BeaconBlock {
                slot,
                ..Default::default()
            },
            signature: Default::default(),
        };
        let root = block.message.tree_hash_root();
        let column = DataColumnSidecar {
            index: 0,
            column: Default::default(),
            kzg_commitments: Default::default(),
            kzg_proofs: Default::default(),
            signed_block_header: block.signed_header(),
            kzg_commitments_inclusion_proof: Default::default(),
        };
        (root, block, column)
    }

    #[test]
    fn columns_of_the_flat_layout_move_into_subdirectories_at_startup() {
        let dir = tempfile::tempdir().unwrap();
        let column_dir = dir.path().join(COLUMN_FOLDER_NAME);
        let (root, block, sidecar) = column(9);
        {
            let db = ReamDB::new(dir.path().to_path_buf())
                .unwrap()
                .init_beacon_db()
                .unwrap();
            db.block_provider().insert(root, block).unwrap();
            db.column_sidecars_provider()
                .insert_batch(vec![sidecar.clone()])
                .unwrap();
        }
        let name = format!("{root}_0.ssz_snappy");
        let sharded = column_dir.join(root.to_string()).join("0.ssz_snappy");
        fs::rename(&sharded, column_dir.join(&name)).unwrap();
        fs::remove_dir(column_dir.join(root.to_string())).unwrap();
        fs::write(column_dir.join(".ream-sidecar-leftover"), b"partial").unwrap();

        let db = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        assert!(!column_dir.join(&name).exists());
        assert!(!column_dir.join(".ream-sidecar-leftover").exists());
        assert!(sharded.is_file());
        assert_eq!(
            db.column_sidecars_provider()
                .get(ColumnIdentifier::new(root, 0))
                .unwrap(),
            Some(sidecar)
        );
    }

    #[test]
    fn migration_never_overwrites_a_different_column_file() {
        let dir = tempfile::tempdir().unwrap();
        let column_dir = dir.path().join(COLUMN_FOLDER_NAME);
        let root = B256::repeat_byte(3);
        let block_dir = column_dir.join(root.to_string());
        fs::create_dir_all(&block_dir).unwrap();
        fs::write(block_dir.join("0.ssz_snappy"), b"new").unwrap();
        fs::write(column_dir.join(format!("{root}_0.ssz_snappy")), b"old").unwrap();

        ReamDB::new(dir.path().to_path_buf()).unwrap();
        assert_eq!(fs::read(block_dir.join("0.ssz_snappy")).unwrap(), b"new");
        assert!(column_dir.join(format!("{root}_0.ssz_snappy")).exists());
    }

    #[test]
    fn pruning_respects_retention_finality_and_rejects_late_republication() {
        let dir = tempfile::tempdir().unwrap();
        let db = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        for slot in [9, 10, 11] {
            let (_, _, column) = column(slot);
            db.column_sidecars_provider()
                .insert_batch(vec![column])
                .unwrap();
        }
        assert_eq!(db.prune_columns(11, 10, 256).unwrap(), 1);
        assert_eq!(db.prune_columns(10, 11, 256).unwrap(), 0);
        for slot in [10, 11] {
            assert!(
                db.column_sidecars_provider()
                    .get(ColumnIdentifier::new(column(slot).0, 0))
                    .unwrap()
                    .is_some()
            );
        }
        db.column_sidecars_provider()
            .insert_batch(vec![column(9).2])
            .unwrap();
        assert!(
            db.column_sidecars_provider()
                .get(ColumnIdentifier::new(column(9).0, 0))
                .unwrap()
                .is_none()
        );
        assert_eq!(db.prune_columns(12, 12, 1).unwrap(), 1);
        assert_eq!(db.prune_columns(12, 12, 1).unwrap(), 1);
    }

    #[test]
    fn migration_indexes_forks_and_removes_orphans_and_pruning_retries_missing_files() {
        let dir = tempfile::tempdir().unwrap();
        let db = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        let (root, block, sidecar) = column(9);
        db.block_provider().insert(root, block).unwrap();
        db.column_sidecars_provider()
            .insert_batch(vec![sidecar, column(10).2])
            .unwrap();
        let (_, mut fork, mut fork_sidecar) = column(9);
        fork.message.state_root = B256::repeat_byte(42);
        let fork_root = fork.message.tree_hash_root();
        fork_sidecar.signed_block_header = fork.signed_header();
        db.block_provider().insert(fork_root, fork).unwrap();
        db.column_sidecars_provider()
            .insert_batch(vec![fork_sidecar])
            .unwrap();
        // A directory without a readable sidecar of its root.
        let orphan = column_block_dir(dir.path(), &B256::repeat_byte(9));
        fs::create_dir(&orphan).unwrap();
        fs::write(orphan.join("0.ssz_snappy"), b"not a sidecar").unwrap();
        // Simulate an old database without an index.
        let write = db.db.begin_write().unwrap();
        write
            .open_multimap_table(COLUMN_ROOTS_BY_SLOT)
            .unwrap()
            .remove_all(9)
            .unwrap();
        write
            .open_multimap_table(COLUMN_ROOTS_BY_SLOT)
            .unwrap()
            .remove_all(10)
            .unwrap();
        write
            .open_table(COLUMN_MAINTENANCE)
            .unwrap()
            .remove(INDEX_VERSION)
            .unwrap();
        write.commit().unwrap();
        drop(db);
        let db = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        // Columns stored before their block are kept and indexed by their header's slot.
        assert!(
            db.column_sidecars_provider()
                .get(ColumnIdentifier::new(column(10).0, 0))
                .unwrap()
                .is_some()
        );
        assert!(orphan.join("0.ssz_snappy").is_file());
        assert!(
            db.column_sidecars_provider()
                .get(ColumnIdentifier::new(root, 0))
                .unwrap()
                .is_some()
        );
        // Simulate a crash after the files are removed but before the index transaction commits.
        fs::remove_dir_all(column_block_dir(&db.data_dir, &root)).unwrap();
        assert_eq!(db.prune_columns(10, 10, 256).unwrap(), 1);
        assert!(
            db.db
                .begin_read()
                .unwrap()
                .open_multimap_table(COLUMN_ROOTS_BY_SLOT)
                .unwrap()
                .get(9)
                .unwrap()
                .next()
                .is_none()
        );
    }
}
