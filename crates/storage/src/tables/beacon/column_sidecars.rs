use std::{io::Read, path::PathBuf, sync::Arc};

use ream_consensus_beacon::data_column_sidecar::{ColumnIdentifier, DataColumnSidecar};
use redb::{Database, Durability, ReadableTable};
use snap::raw::{Decoder, Encoder};
use ssz::{Decode, Encode};
use tree_hash::TreeHash;

use super::column_roots_by_slot::{
    COLUMN_MAINTENANCE, COLUMN_ROOTS_BY_SLOT, COLUMN_WRITER, PRUNED_BEFORE,
};
use crate::{errors::StoreError, tables::table::CustomTable};

pub(crate) const COLUMN_FOLDER_NAME: &str = "beacon_columns";

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
        self.data_dir.join(COLUMN_FOLDER_NAME).join(format!(
            "{}_{}.ssz_snappy",
            column_identifier.block_root, column_identifier.index
        ))
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
