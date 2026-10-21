//! Includes canonical and fork roots: every published column must be discoverable for pruning.
use alloy_primitives::B256;
use redb::{MultimapTableDefinition, TableDefinition};

use crate::tables::ssz_encoder::SSZEncoding;

pub(crate) const COLUMN_ROOTS_BY_SLOT: MultimapTableDefinition<u64, SSZEncoding<B256>> =
    MultimapTableDefinition::new("beacon_column_roots_by_slot");
pub(crate) const COLUMN_MAINTENANCE: TableDefinition<&str, u64> =
    TableDefinition::new("beacon_column_maintenance");
pub(crate) const INDEX_VERSION: &str = "index_version";
pub(crate) const PRUNED_BEFORE: &str = "pruned_before";

// Publication and pruning of columns serialize, including their index writes. Keep the redb
// transaction outside sidecar_file's writer lock; all column writers take this lock first.
pub(crate) static COLUMN_WRITER: std::sync::Mutex<()> = std::sync::Mutex::new(());
