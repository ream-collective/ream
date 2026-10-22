use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};

use alloy_primitives::B256;
use ream_consensus_beacon::data_column_sidecar::{
    ColumnIdentifier, DataColumnSidecar, NUMBER_OF_COLUMNS,
};
use redb::{Database, Durability, ReadableTable};
use snap::raw::{Decoder, Encoder};
use ssz::{Decode, Encode};
use tree_hash::TreeHash;

use super::column_roots_by_slot::{
    COLUMN_MAINTENANCE, COLUMN_ROOTS_BY_SLOT, COLUMN_WRITER, PRUNED_BEFORE,
};
use crate::{errors::StoreError, tables::table::CustomTable};

pub(crate) const COLUMN_FOLDER_NAME: &str = "beacon_columns";

const LAYOUT_MIGRATION_LOG_EVERY: usize = 500_000;

/// `beacon_columns/<block root>/<index>.ssz_snappy`: one flat directory overflows ext4's
/// directory index on a supernode.
pub(crate) fn column_file_path(data_dir: &Path, column_identifier: &ColumnIdentifier) -> PathBuf {
    column_block_dir(data_dir, &column_identifier.block_root)
        .join(format!("{}.ssz_snappy", column_identifier.index))
}

pub(crate) fn column_block_dir(data_dir: &Path, block_root: &B256) -> PathBuf {
    data_dir
        .join(COLUMN_FOLDER_NAME)
        .join(block_root.to_string())
}

/// Creates a block's column directory if it is missing, durably.
fn ensure_dir(dir: &Path) -> Result<(), StoreError> {
    match fs::create_dir(dir) {
        Ok(()) => {
            if let Some(parent) = dir.parent() {
                File::open(parent)?.sync_all()?;
            }
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(err) => Err(err.into()),
    }
}

/// Moves files of the old flat layout, `<root>_<index>.ssz_snappy`, into their block
/// directories. Startup only; an interrupted move resumes at the next start. A file whose
/// destination already exists is moved only if both are identical, and kept otherwise.
pub(crate) fn prepare_column_layout(column_dir: &Path) -> Result<(), StoreError> {
    fs::create_dir_all(column_dir)?;
    let started = std::time::Instant::now();
    let mut moved = 0;
    let mut touched = std::collections::HashSet::new();
    for entry in fs::read_dir(column_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name();
        let Some((root, index)) = name
            .to_str()
            .and_then(|name| name.strip_suffix(".ssz_snappy"))
            .and_then(|name| name.rsplit_once('_'))
            .and_then(|(root, index)| {
                let parsed = root.parse::<B256>().ok()?;
                let index = index.parse::<u64>().ok()?;
                (parsed.to_string() == root && index < NUMBER_OF_COLUMNS).then_some((parsed, index))
            })
        else {
            continue;
        };
        let block_dir = column_dir.join(root.to_string());
        if touched.insert(block_dir.clone()) && !block_dir.exists() {
            fs::create_dir(&block_dir)?;
        }
        let destination = block_dir.join(format!("{index}.ssz_snappy"));
        if destination.exists() {
            if fs::read(&destination)? == fs::read(entry.path())? {
                fs::remove_file(entry.path())?;
            } else {
                tracing::warn!(
                    ?destination,
                    "Kept an old column file that differs from its new copy"
                );
            }
            continue;
        }
        fs::rename(entry.path(), destination)?;
        moved += 1;
        if moved % LAYOUT_MIGRATION_LOG_EVERY == 0 {
            tracing::info!(
                moved,
                elapsed_s = started.elapsed().as_secs(),
                "Moving column files into block directories"
            );
        }
    }
    if !touched.is_empty() {
        for block_dir in touched {
            File::open(block_dir)?.sync_all()?;
        }
        File::open(column_dir)?.sync_all()?;
        tracing::info!(
            moved,
            elapsed_s = started.elapsed().as_secs(),
            "Moved column files into block directories"
        );
    }
    Ok(())
}

/// Whether `name` is a block directory of the column layout.
pub(crate) fn is_block_dir_name(name: &str) -> bool {
    name.parse::<B256>()
        .is_ok_and(|root| root.to_string() == name)
}

/// Checks that a block directory holds only column files and temporary files of a write.
pub(crate) fn check_block_dir(dir: &Path) -> Result<(), StoreError> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let known = entry.file_type()?.is_file()
            && name.to_str().is_some_and(|name| {
                name.starts_with(crate::tables::sidecar_file::TEMP_PREFIX)
                    || name
                        .strip_suffix(".ssz_snappy")
                        .and_then(|index| index.parse::<u64>().ok())
                        .is_some_and(|index| index < NUMBER_OF_COLUMNS)
            });
        if !known {
            return Err(std::io::Error::other(format!(
                "Unexpected entry {} in column directory {}",
                name.to_string_lossy(),
                dir.display()
            ))
            .into());
        }
    }
    Ok(())
}

/// Removes a block directory after `check_block_dir` accepted it.
pub(crate) fn remove_block_dir(dir: &Path) -> Result<(), StoreError> {
    for entry in fs::read_dir(dir)? {
        fs::remove_file(entry?.path())?;
    }
    fs::remove_dir(dir)?;
    Ok(())
}

pub struct ColumnSidecarsTable {
    pub data_dir: PathBuf,
    pub db: Arc<Database>,
}

impl ColumnSidecarsTable {
    pub(crate) fn prepare_insert(
        &self,
        key: ColumnIdentifier,
        value: DataColumnSidecar,
    ) -> Result<crate::tables::sidecar_file::PreparedSidecarFile, StoreError> {
        let bytes = Encoder::new().compress_vec(&value.as_ssz_bytes())?;
        ensure_dir(&column_block_dir(&self.data_dir, &key.block_root))?;
        crate::tables::sidecar_file::PreparedSidecarFile::new(self.column_file_path(&key), &bytes)
    }

    pub fn insert_batch(&self, columns: Vec<DataColumnSidecar>) -> Result<(), StoreError> {
        let started = std::time::Instant::now();
        let count = columns.len();
        let _writer = COLUMN_WRITER.lock().unwrap_or_else(|err| err.into_inner());
        let mut write = self.db.begin_write()?;
        write.set_durability(Durability::Immediate)?;
        let floor = write
            .open_table(COLUMN_MAINTENANCE)?
            .get(PRUNED_BEFORE)?
            .map(|value| value.value())
            .unwrap_or_default();
        let columns = columns
            .into_iter()
            .filter(|column| column.signed_block_header.message.slot >= floor)
            .collect::<Vec<_>>();
        {
            let mut index = write.open_multimap_table(COLUMN_ROOTS_BY_SLOT)?;
            for column in &columns {
                index.insert(
                    column.signed_block_header.message.slot,
                    column.signed_block_header.message.tree_hash_root(),
                )?;
            }
        }
        // Index first: a crash may leave an entry without files, never files invisible to prune.
        write.commit()?;
        let prepared = columns
            .into_iter()
            .map(|column| {
                let key = ColumnIdentifier::new(
                    column.signed_block_header.message.tree_hash_root(),
                    column.index,
                );
                self.prepare_insert(key, column)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let written = started.elapsed();
        crate::tables::sidecar_file::PreparedSidecarFile::publish_batch(prepared)?;
        tracing::debug!(
            target: "ream::timing",
            columns = count,
            write_ms = written.as_millis() as u64,
            publish_ms = (started.elapsed() - written).as_millis() as u64,
            "timing: column write"
        );
        Ok(())
    }

    fn column_file_path(&self, column_identifier: &ColumnIdentifier) -> PathBuf {
        column_file_path(&self.data_dir, column_identifier)
    }
}

impl CustomTable for ColumnSidecarsTable {
    type Key = ColumnIdentifier;
    type Value = DataColumnSidecar;

    fn get(&self, key: Self::Key) -> Result<Option<Self::Value>, StoreError> {
        let file_path = self.column_file_path(&key);

        let Some(mut file) = crate::tables::sidecar_file::open_published(&file_path)? else {
            return Ok(None);
        };
        let mut bytes = vec![];
        file.read_to_end(&mut bytes)?;
        let snappy_decoding = Decoder::new().decompress_vec(&bytes)?;
        Ok(Some(DataColumnSidecar::from_ssz_bytes(&snappy_decoding)?))
    }

    fn insert(&self, key: Self::Key, value: Self::Value) -> Result<(), StoreError> {
        if key.block_root != value.signed_block_header.message.tree_hash_root()
            || key.index != value.index
        {
            return Err(std::io::Error::other("Column identifier does not match sidecar").into());
        }
        self.insert_batch(vec![value])
    }

    fn remove(&self, key: Self::Key) -> Result<Option<Self::Value>, StoreError> {
        crate::tables::sidecar_file::remove_published(&self.column_file_path(&key), || {
            self.get(key)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use ream_consensus_beacon::data_column_sidecar::ColumnIdentifier;
    use tempdir::TempDir;

    use crate::{
        errors::StoreError,
        tables::{beacon::column_sidecars::COLUMN_FOLDER_NAME, table::CustomTable},
    };

    #[test]
    fn test_column_identifier_default() -> Result<(), StoreError> {
        let tmp_dir = TempDir::new("test_column_sidecar")?;

        let column_dir = tmp_dir.path().to_path_buf().join(COLUMN_FOLDER_NAME);
        fs::create_dir_all(&column_dir)?;

        let db = crate::db::ReamDB::new(tmp_dir.path().to_path_buf())?.init_beacon_db()?;
        let table = db.column_sidecars_provider();

        let key = ColumnIdentifier::default();

        let result = table.get(key)?;

        assert_eq!(result, None);

        Ok(())
    }
}
