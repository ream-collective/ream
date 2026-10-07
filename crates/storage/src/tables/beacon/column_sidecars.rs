use std::{fs::remove_file, io::Read, path::PathBuf};

use ream_consensus_beacon::data_column_sidecar::{ColumnIdentifier, DataColumnSidecar};
use snap::raw::{Decoder, Encoder};
use ssz::{Decode, Encode};

use crate::{errors::StoreError, tables::table::CustomTable};

pub(crate) const COLUMN_FOLDER_NAME: &str = "beacon_columns";

pub struct ColumnSidecarsTable {
    pub data_dir: PathBuf,
}

impl ColumnSidecarsTable {
    pub fn prepare_insert(
        &self,
        key: ColumnIdentifier,
        value: DataColumnSidecar,
    ) -> Result<crate::tables::sidecar_file::PreparedSidecarFile, StoreError> {
        let bytes = Encoder::new().compress_vec(&value.as_ssz_bytes())?;
        crate::tables::sidecar_file::PreparedSidecarFile::new(self.column_file_path(&key), &bytes)
    }

    pub fn insert_batch(&self, columns: Vec<DataColumnSidecar>) -> Result<(), StoreError> {
        use tree_hash::TreeHash;
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
        crate::tables::sidecar_file::PreparedSidecarFile::publish_batch(prepared)
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
        self.prepare_insert(key, value)?.publish()
    }

    fn remove(&self, key: Self::Key) -> Result<Option<Self::Value>, StoreError> {
        let column = self.get(key)?;
        remove_file(self.column_file_path(&key))?;
        Ok(column)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use ream_consensus_beacon::data_column_sidecar::ColumnIdentifier;
    use tempdir::TempDir;

    use crate::{
        errors::StoreError,
        tables::{
            beacon::column_sidecars::{COLUMN_FOLDER_NAME, ColumnSidecarsTable},
            table::CustomTable,
        },
    };

    #[test]
    fn test_column_identifier_default() -> Result<(), StoreError> {
        let tmp_dir = TempDir::new("test_column_sidecar")?;

        let column_dir = tmp_dir.path().to_path_buf().join(COLUMN_FOLDER_NAME);
        fs::create_dir_all(&column_dir)?;

        let table = ColumnSidecarsTable {
            data_dir: tmp_dir.path().to_path_buf(),
        };

        let key = ColumnIdentifier::default();

        let result = table.get(key)?;

        assert_eq!(result, None);

        Ok(())
    }
}
