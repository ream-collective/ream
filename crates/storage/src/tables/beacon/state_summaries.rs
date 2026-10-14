use std::sync::Arc;

use alloy_primitives::B256;
use redb::{Database, TableDefinition};

use crate::tables::{ssz_encoder::SSZEncoding, table::REDBTable};

/// Blocks whose post-state is available, with the block's slot. Most of these states are not
/// stored whole; the state table rebuilds them from an ancestor's state.
pub struct BeaconStateSummariesTable {
    pub db: Arc<Database>,
}

/// Table definition for the Beacon State Summaries table
///
/// Key: block_root
/// Value: slot
impl REDBTable for BeaconStateSummariesTable {
    const TABLE_DEFINITION: TableDefinition<'_, SSZEncoding<B256>, u64> =
        TableDefinition::new("beacon_state_summaries");

    type Key = B256;

    type KeyTableDefinition = SSZEncoding<B256>;

    type Value = u64;

    type ValueTableDefinition = u64;

    fn database(&self) -> Arc<Database> {
        self.db.clone()
    }
}
