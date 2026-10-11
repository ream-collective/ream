pub mod beacon;
pub mod lean;

use std::{
    fs, io,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use beacon::BeaconDB;
use lean::LeanDB;
use redb::{Builder, Database, ReadableDatabase, ReadableTable};
use tracing::info;

use crate::{
    errors::StoreError,
    tables::{
        beacon::{
            beacon_block::BeaconBlockTable,
            beacon_state::{BeaconStateTable, STATE_FOLDER_NAME},
            blobs_and_proofs::BLOB_FOLDER_NAME,
            block_timeliness::BlockTimelinessTable,
            checkpoint_states::CheckpointStatesTable,
            column_sidecars::COLUMN_FOLDER_NAME,
            equivocating_indices::EQUIVOCATING_INDICES_FIELD,
            finalized_checkpoint::FinalizedCheckpointField,
            genesis_time::GenesisTimeField,
            justified_checkpoint::JustifiedCheckpointField,
            latest_messages::LatestMessagesTable,
            parent_root_index::PARENT_ROOT_INDEX_MULTIMAP_TABLE,
            proposer_boost_root::ProposerBoostRootField,
            slot_index::BeaconSlotIndexTable,
            state_root_index::BeaconStateRootIndexTable,
            state_summaries::BeaconStateSummariesTable,
            time::TimeField,
            unrealized_finalized_checkpoint::UnrealizedFinalizedCheckpointField,
            unrealized_justifications::UnrealizedJustificationsTable,
            unrealized_justified_checkpoint::UnrealizedJustifiedCheckpointField,
        },
        field::REDBField,
        lean::{
            aggregated_payloads::AggregatedPayloadsTable,
            attestation_data_by_root::LeanAttestationDataByRootTable, block::LeanBlockTable,
            gossip_signatures::GossipSignaturesTable, head::LeanHeadField,
            latest_finalized::LatestFinalizedField, latest_justified::LatestJustifiedField,
            latest_known_aggregated_payloads::LeanLatestKnownAggregatedPayloadsTable,
            latest_known_attestation::LatestKnownAttestationTable,
            latest_new_aggregated_payloads::LeanLatestNewAggregatedPayloadsTable,
            latest_new_attestations::LeanLatestNewAttestationsTable,
            pending_blocks::LeanPendingBlocksTable, safe_target::LeanSafeTargetField,
            slot_index::LeanSlotIndexTable, state::LeanStateTable,
            state_root_index::LeanStateRootIndexTable, time::LeanTimeField,
            validator_id::LeanValidatorIdField,
        },
        table::REDBTable,
    },
};

pub const REDB_FILE: &str = "ream.redb";

/// Validators' latest messages, kept apart from `REDB_FILE`. A redb database has a single write
/// lock, and writing a block's tens of thousands of votes held it while block import waited.
pub const VOTES_REDB_FILE: &str = "fork_choice_votes.redb";

/// The size of the cache for the votes database
///
/// 256 MiB
pub const VOTES_REDB_CACHE_SIZE: usize = 256 * 1_024 * 1_024;

/// The size of the cache for the database
///
/// 1 GiB
pub const REDB_CACHE_SIZE: usize = 1_024 * 1_024 * 1_024;

#[derive(Clone, Debug)]
pub struct ReamDB {
    db: Arc<Database>,
    /// The votes database, opened by the first `init_beacon_db`.
    votes_db: Arc<Mutex<Option<Arc<Database>>>>,
    data_dir: PathBuf,
}

impl ReamDB {
    pub fn new(data_dir: PathBuf) -> Result<Self, StoreError> {
        let db = Builder::new()
            .set_cache_size(REDB_CACHE_SIZE)
            .create(data_dir.join(REDB_FILE))?;

        Ok(ReamDB {
            db: Arc::new(db),
            votes_db: Arc::default(),
            data_dir,
        })
    }

    pub fn init_beacon_db(&self) -> Result<BeaconDB, StoreError> {
        let write_txn = self.db.begin_write()?;

        write_txn.open_table(BeaconBlockTable::TABLE_DEFINITION)?;
        write_txn.open_table(BeaconStateTable::TABLE_DEFINITION)?;
        write_txn.open_table(BlockTimelinessTable::TABLE_DEFINITION)?;
        write_txn.open_table(CheckpointStatesTable::TABLE_DEFINITION)?;
        write_txn.open_table(EQUIVOCATING_INDICES_FIELD)?;
        write_txn.open_table(FinalizedCheckpointField::FIELD_DEFINITION)?;
        write_txn.open_table(GenesisTimeField::FIELD_DEFINITION)?;
        write_txn.open_table(JustifiedCheckpointField::FIELD_DEFINITION)?;
        write_txn.open_multimap_table(PARENT_ROOT_INDEX_MULTIMAP_TABLE)?;
        write_txn.open_table(ProposerBoostRootField::FIELD_DEFINITION)?;
        write_txn.open_table(BeaconSlotIndexTable::TABLE_DEFINITION)?;
        write_txn.open_table(BeaconStateRootIndexTable::TABLE_DEFINITION)?;
        write_txn.open_table(BeaconStateSummariesTable::TABLE_DEFINITION)?;
        write_txn.open_table(TimeField::FIELD_DEFINITION)?;
        write_txn.open_table(UnrealizedFinalizedCheckpointField::FIELD_DEFINITION)?;
        write_txn.open_table(UnrealizedJustificationsTable::TABLE_DEFINITION)?;
        write_txn.open_table(UnrealizedJustifiedCheckpointField::FIELD_DEFINITION)?;
        write_txn.commit()?;

        fs::create_dir_all(self.data_dir.join(BLOB_FOLDER_NAME))?;
        fs::create_dir_all(self.data_dir.join(COLUMN_FOLDER_NAME))?;
        fs::create_dir_all(self.data_dir.join(STATE_FOLDER_NAME))?;

        Ok(BeaconDB {
            db: self.db.clone(),
            votes_db: self.votes_db()?,
            data_dir: self.data_dir.clone(),
            cache: None,
        })
    }

    /// The votes database, opened on first use. Latest messages that earlier versions kept in
    /// `REDB_FILE` are moved into it once.
    fn votes_db(&self) -> Result<Arc<Database>, StoreError> {
        let mut votes_db = self
            .votes_db
            .lock()
            .expect("votes database lock is not poisoned");
        if let Some(votes_db) = votes_db.as_ref() {
            return Ok(votes_db.clone());
        }
        let opened = Arc::new(
            Builder::new()
                .set_cache_size(VOTES_REDB_CACHE_SIZE)
                .create(self.data_dir.join(VOTES_REDB_FILE))?,
        );
        let write_txn = opened.begin_write()?;
        write_txn.open_table(LatestMessagesTable::TABLE_DEFINITION)?;
        write_txn.commit()?;
        self.move_votes_from_main_database(&opened)?;
        *votes_db = Some(opened.clone());
        Ok(opened)
    }

    fn move_votes_from_main_database(&self, votes_db: &Database) -> Result<(), StoreError> {
        let messages = {
            let read_txn = self.db.begin_read()?;
            let table = match read_txn.open_table(LatestMessagesTable::TABLE_DEFINITION) {
                Ok(table) => table,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(()),
                Err(err) => return Err(err.into()),
            };
            let mut messages = Vec::new();
            for entry in table.iter()? {
                let (index, message) = entry?;
                messages.push((index.value(), message.value()));
            }
            messages
        };
        let write_txn = votes_db.begin_write()?;
        {
            let mut table = write_txn.open_table(LatestMessagesTable::TABLE_DEFINITION)?;
            for (index, message) in messages {
                table.insert(index, message)?;
            }
        }
        write_txn.commit()?;
        let write_txn = self.db.begin_write()?;
        write_txn.delete_table(LatestMessagesTable::TABLE_DEFINITION)?;
        write_txn.commit()?;
        Ok(())
    }

    pub fn init_lean_db(&self) -> Result<LeanDB, StoreError> {
        let write_txn = self.db.begin_write()?;

        write_txn.open_table(LatestFinalizedField::FIELD_DEFINITION)?;
        write_txn.open_table(LatestJustifiedField::FIELD_DEFINITION)?;
        write_txn.open_table(LeanBlockTable::TABLE_DEFINITION)?;
        write_txn.open_table(LeanStateTable::TABLE_DEFINITION)?;
        write_txn.open_table(LeanSlotIndexTable::TABLE_DEFINITION)?;
        write_txn.open_table(LeanStateRootIndexTable::TABLE_DEFINITION)?;
        write_txn.open_table(LeanTimeField::FIELD_DEFINITION)?;
        write_txn.open_table(LeanHeadField::FIELD_DEFINITION)?;
        write_txn.open_table(LeanSafeTargetField::FIELD_DEFINITION)?;
        write_txn.open_table(LeanLatestNewAttestationsTable::TABLE_DEFINITION)?;
        write_txn.open_table(LatestKnownAttestationTable::TABLE_DEFINITION)?;
        write_txn.open_table(LeanPendingBlocksTable::TABLE_DEFINITION)?;
        write_txn.open_table(AggregatedPayloadsTable::TABLE_DEFINITION)?;
        write_txn.open_table(GossipSignaturesTable::TABLE_DEFINITION)?;
        write_txn.open_table(LeanAttestationDataByRootTable::TABLE_DEFINITION)?;
        write_txn.open_table(LeanLatestNewAggregatedPayloadsTable::TABLE_DEFINITION)?;
        write_txn.open_table(LeanLatestKnownAggregatedPayloadsTable::TABLE_DEFINITION)?;
        write_txn.open_table(LeanValidatorIdField::FIELD_DEFINITION)?;
        write_txn.commit()?;

        Ok(LeanDB {
            db: self.db.clone(),
            cache: None,
        })
    }
}

pub fn reset_db(db_path: &PathBuf) -> anyhow::Result<()> {
    if fs::read_dir(db_path)?.next().is_none() {
        info!("Data directory at {db_path:?} is already empty.");
        return Ok(());
    }

    info!(
        "Are you sure you want to clear the contents of the data directory at {db_path:?}? (y/n):"
    );
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    if input.trim().eq_ignore_ascii_case("y") {
        for entry in fs::read_dir(db_path)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                fs::remove_dir_all(&path)?;
            } else {
                fs::remove_file(&path)?;
            }
        }
        info!("Database contents cleared successfully.");
    } else {
        info!("Operation canceled by user.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloy_primitives::B256;
    use ream_consensus_beacon::fork_choice::latest_message::LatestMessage;
    use tempdir::TempDir;

    use super::*;

    #[test]
    fn votes_in_the_main_database_move_to_their_own() {
        let dir = TempDir::new("ream_votes_db").unwrap();
        let message = LatestMessage {
            epoch: 7,
            root: B256::repeat_byte(3),
        };
        {
            // Earlier versions kept latest messages in the main database.
            let ream_db = ReamDB::new(dir.path().to_path_buf()).unwrap();
            let write_txn = ream_db.db.begin_write().unwrap();
            write_txn
                .open_table(LatestMessagesTable::TABLE_DEFINITION)
                .unwrap()
                .insert(5, message.clone())
                .unwrap();
            write_txn.commit().unwrap();
        }

        let ream_db = ReamDB::new(dir.path().to_path_buf()).unwrap();
        let db = ream_db.init_beacon_db().unwrap();
        assert_eq!(db.latest_messages_provider().get(5).unwrap(), Some(message));
        let read_txn = ream_db.db.begin_read().unwrap();
        assert!(matches!(
            read_txn.open_table(LatestMessagesTable::TABLE_DEFINITION),
            Err(redb::TableError::TableDoesNotExist(_))
        ));
        // A second handle shares the votes database that is already open.
        let again = ream_db.init_beacon_db().unwrap();
        assert!(Arc::ptr_eq(&again.votes_db, &db.votes_db));
    }

    #[test]
    fn interrupted_vote_migration_retries_before_removing_the_source() {
        let dir = TempDir::new("ream_vote_migration_retry").unwrap();
        let message = LatestMessage {
            epoch: 7,
            root: B256::repeat_byte(3),
        };
        {
            let ream_db = ReamDB::new(dir.path().to_path_buf()).unwrap();
            let write_txn = ream_db.db.begin_write().unwrap();
            {
                let mut table = write_txn
                    .open_table(LatestMessagesTable::TABLE_DEFINITION)
                    .unwrap();
                table.insert(5, message.clone()).unwrap();
                table.insert(6, message.clone()).unwrap();
            }
            write_txn.commit().unwrap();
            // Model restart after destination commit, before deleting the legacy table.
            let votes_db = Database::create(dir.path().join(VOTES_REDB_FILE)).unwrap();
            let write_txn = votes_db.begin_write().unwrap();
            {
                let mut table = write_txn
                    .open_table(LatestMessagesTable::TABLE_DEFINITION)
                    .unwrap();
                table.insert(5, message.clone()).unwrap();
                table.insert(6, message.clone()).unwrap();
                table.insert(9, message.clone()).unwrap();
            }
            write_txn.commit().unwrap();
        }
        {
            let ream_db = ReamDB::new(dir.path().to_path_buf()).unwrap();
            let db = ream_db.init_beacon_db().unwrap();
            assert_eq!(
                db.latest_messages_provider().get_all().unwrap(),
                vec![
                    (5, message.clone()),
                    (6, message.clone()),
                    (9, message.clone())
                ]
            );
            assert!(matches!(
                ream_db
                    .db
                    .begin_read()
                    .unwrap()
                    .open_table(LatestMessagesTable::TABLE_DEFINITION),
                Err(redb::TableError::TableDoesNotExist(_))
            ));
        }
        let db = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        assert_eq!(db.latest_messages_provider().get_all().unwrap().len(), 3);
    }
}
