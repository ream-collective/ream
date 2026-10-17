use std::{io::Read, path::PathBuf};

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
        value: &DataColumnSidecar,
    ) -> Result<crate::tables::sidecar_file::PreparedSidecarFile, StoreError> {
        let bytes = Encoder::new().compress_vec(&value.as_ssz_bytes())?;
        crate::tables::sidecar_file::PreparedSidecarFile::new(self.column_file_path(&key), &bytes)
    }

    pub fn insert_batch(&self, columns: Vec<DataColumnSidecar>) -> Result<(), StoreError> {
        self.insert_batch_inner(&columns, false)?;
        Ok(())
    }

    /// Stores the columns that are not stored yet and returns them, in input order.
    pub fn insert_batch_if_missing(
        &self,
        columns: Vec<DataColumnSidecar>,
    ) -> Result<Vec<DataColumnSidecar>, StoreError> {
        let published = self.insert_batch_inner(&columns, true)?;
        Ok(columns
            .into_iter()
            .zip(published)
            .filter_map(|(column, published)| published.then_some(column))
            .collect())
    }

    /// Returns one flag per column, true when this call stored it. Without `only_if_missing`
    /// every flag is true, since every column ends up stored.
    fn insert_batch_inner(
        &self,
        columns: &[DataColumnSidecar],
        only_if_missing: bool,
    ) -> Result<Vec<bool>, StoreError> {
        use tree_hash::TreeHash;
        let started = std::time::Instant::now();
        let count = columns.len();
        let prepared = columns
            .iter()
            .map(|column| {
                let key = ColumnIdentifier::new(
                    column.signed_block_header.message.tree_hash_root(),
                    column.index,
                );
                self.prepare_insert(key, column)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let written = started.elapsed();
        let published = if only_if_missing {
            crate::tables::sidecar_file::PreparedSidecarFile::publish_batch_if_missing(prepared)?
        } else {
            crate::tables::sidecar_file::PreparedSidecarFile::publish_batch(prepared)?;
            vec![true; count]
        };
        tracing::info!(
            columns = count,
            write_ms = written.as_millis() as u64,
            publish_ms = (started.elapsed() - written).as_millis() as u64,
            "timing: column write"
        );
        Ok(published)
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
        self.prepare_insert(key, &value)?.publish()
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

    use ream_consensus_beacon::data_column_sidecar::{ColumnIdentifier, DataColumnSidecar};
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

    #[test]
    fn insert_if_missing_returns_only_the_columns_it_stored() -> Result<(), StoreError> {
        let tmp_dir = TempDir::new("test_column_sidecar_if_missing")?;
        fs::create_dir_all(tmp_dir.path().join(COLUMN_FOLDER_NAME))?;
        let table = ColumnSidecarsTable {
            data_dir: tmp_dir.path().to_path_buf(),
        };
        let column = |index| DataColumnSidecar {
            index,
            column: Default::default(),
            kzg_commitments: Default::default(),
            kzg_proofs: Default::default(),
            signed_block_header: Default::default(),
            kzg_commitments_inclusion_proof: Default::default(),
        };
        table.insert_batch(vec![column(1)])?;

        let stored = table.insert_batch_if_missing(vec![column(0), column(1), column(2)])?;

        assert_eq!(stored, vec![column(0), column(2)]);
        assert!(table.insert_batch_if_missing(vec![column(0)])?.is_empty());
        Ok(())
    }
}
