use std::sync::Arc;

use alloy_primitives::B256;
use redb::{Database, TableDefinition};
use ssz_derive::{Decode, Encode};

use crate::tables::{ssz_encoder::SSZEncoding, table::REDBTable};

/// What is known about a block's post-state without reading the state itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub struct StateSummary {
    pub slot: u64,
    /// Whether the state table holds the state whole. Reading a whole state from redb, even to
    /// check that it exists, reads all of its bytes.
    pub stored_whole: bool,
}

/// Blocks whose post-state is available. Most of these states are not stored whole; the state
/// table rebuilds them from an ancestor's state.
pub struct BeaconStateSummariesTable {
    pub db: Arc<Database>,
}

/// Table definition for the Beacon State Summaries table
///
/// Key: block_root
/// Value: StateSummary
impl REDBTable for BeaconStateSummariesTable {
    const TABLE_DEFINITION: TableDefinition<'_, SSZEncoding<B256>, SSZEncoding<StateSummary>> =
        TableDefinition::new("beacon_state_summaries");

    type Key = B256;

    type KeyTableDefinition = SSZEncoding<B256>;

    type Value = StateSummary;

    type ValueTableDefinition = SSZEncoding<StateSummary>;

    fn database(&self) -> Arc<Database> {
        self.db.clone()
    }
}
