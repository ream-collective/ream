//! Gossip validation of Fulu partial data column messages.
//!
//! Spec: https://github.com/ethereum/consensus-specs/blob/master/specs/fulu/partial-columns/p2p-interface.md#new-data_column_sidecar_subnet_id-partial-messages

use alloy_primitives::B256;
use ream_chain_beacon::beacon_chain::BeaconChain;
use ream_consensus_beacon::{
    data_column_sidecar::Cell,
    partial_data_column_sidecar::{PartialDataColumnHeader, PartialDataColumnSidecar},
};
use ream_consensus_misc::{
    misc::{compute_epoch_at_slot, compute_start_slot_at_epoch},
    polynomial_commitments::kzg_proof::KZGProof,
};
use ream_metrics::{
    BEACON_PARTIAL_DATA_COLUMN_SIDECAR_HEADER_PROCESSING_REQUESTS_TOTAL,
    BEACON_PARTIAL_DATA_COLUMN_SIDECAR_HEADER_PROCESSING_SUCCESSES_TOTAL,
};
use ream_network_spec::networks::beacon_network_spec;
use ream_polynomial_commitments::handlers::verify_partial_column_cells_kzg_proofs;
use ream_storage::{cache::BeaconCacheDB, tables::field::REDBField};

use super::{
    data_column_sidecar::{HeaderVerdict, check_block_header, is_not_from_future_slot},
    result::DependencyValidationResult,
};

/// Rejects a message that carries neither a header nor cells, or whose cell and proof counts
/// differ from its bitmap.
pub fn check_partial_structure(sidecar: &PartialDataColumnSidecar) -> Option<String> {
    let cell_count = sidecar.cells_present_bitmap.num_set_bits();
    if sidecar.header.is_empty() && cell_count == 0 {
        return Some("Partial message is semantically empty".to_string());
    }
    if sidecar.partial_column.len() != cell_count {
        return Some("Number of cells does not match number of set bits".to_string());
    }
    if sidecar.kzg_proofs.len() != cell_count {
        return Some("Number of proofs does not match number of set bits".to_string());
    }
    None
}

/// Validates the header of a partial message for `block_root`, which no earlier message proved.
pub async fn validate_partial_data_column_header(
    header: &PartialDataColumnHeader,
    block_root: B256,
    beacon_chain: &BeaconChain,
    cached_db: &BeaconCacheDB,
    current_time_ms: u64,
) -> anyhow::Result<DependencyValidationResult<()>> {
    BEACON_PARTIAL_DATA_COLUMN_SIDECAR_HEADER_PROCESSING_REQUESTS_TOTAL.inc();
    let block_header = &header.signed_block_header.message;
    if header.block_root() != block_root {
        return Ok(DependencyValidationResult::Reject(
            "Header's block root does not match the group id".to_string(),
        ));
    }
    if header.kzg_commitments.is_empty() {
        return Ok(DependencyValidationResult::Reject(
            "Header's kzg_commitments is empty".to_string(),
        ));
    }
    let max_blobs = beacon_network_spec()
        .blob_parameters(compute_epoch_at_slot(block_header.slot))
        .max_blobs_per_block;
    if header.kzg_commitments.len() as u64 > max_blobs {
        return Ok(DependencyValidationResult::Reject(
            "Header's kzg_commitments is too long".to_string(),
        ));
    }
    if let Some(reason) = check_slot(header, beacon_chain, current_time_ms)? {
        return Ok(DependencyValidationResult::Ignore(reason));
    }

    let finalized_checkpoint = beacon_chain.db().finalized_checkpoint_provider().get()?;
    let checked = match check_block_header(
        beacon_chain,
        cached_db,
        &header.signed_block_header,
        block_root,
        finalized_checkpoint,
        || {
            (!header.verify_inclusion_proof())
                .then(|| "Invalid partial data column header inclusion proof".to_string())
        },
    )
    .await?
    {
        HeaderVerdict::Valid(checked) => checked,
        HeaderVerdict::Reject(reason) => return Ok(DependencyValidationResult::Reject(reason)),
        HeaderVerdict::Ignore(reason) => return Ok(DependencyValidationResult::Ignore(reason)),
    };
    let pending_availability = checked.pending_availability;
    checked
        .remember(
            cached_db,
            block_root,
            &header.signed_block_header,
            finalized_checkpoint,
        )
        .await;
    BEACON_PARTIAL_DATA_COLUMN_SIDECAR_HEADER_PROCESSING_SUCCESSES_TOTAL.inc();
    if pending_availability {
        return Ok(DependencyValidationResult::ParentPendingAvailability {
            parent_root: block_header.parent_root,
            validated: (),
        });
    }
    Ok(DependencyValidationResult::Accept)
}

/// Why cells or a header of this block are ignored: a future slot, or one at or before the
/// finalized slot.
pub fn check_slot(
    header: &PartialDataColumnHeader,
    beacon_chain: &BeaconChain,
    current_time_ms: u64,
) -> anyhow::Result<Option<String>> {
    let slot = header.signed_block_header.message.slot;
    let db = beacon_chain.db();
    if !is_not_from_future_slot(db.genesis_time_provider().get()?, slot, current_time_ms) {
        return Ok(Some("Header is from a future slot".to_string()));
    }
    let finalized_checkpoint = db.finalized_checkpoint_provider().get()?;
    if slot <= compute_start_slot_at_epoch(finalized_checkpoint.epoch) {
        return Ok(Some(
            "Header is not from a slot greater than the latest finalized slot".to_string(),
        ));
    }
    Ok(None)
}

/// Whether `cells` of column `column_index`, each with its blob index, match `header`'s
/// commitments.
pub fn verify_partial_cells(
    column_index: u64,
    header: &PartialDataColumnHeader,
    cells: &[(usize, Cell, KZGProof)],
) -> bool {
    matches!(
        verify_partial_column_cells_kzg_proofs(column_index, &header.kzg_commitments, cells),
        Ok(true)
    )
}
