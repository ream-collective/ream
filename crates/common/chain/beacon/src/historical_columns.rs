//! Authentication of historical RPC columns against already verified, stored blocks.
use alloy_primitives::B256;
use ream_consensus_beacon::data_column_sidecar::DataColumnSidecar;
use ream_consensus_misc::beacon_block_header::SignedBeaconBlockHeader;
use ream_polynomial_commitments::handlers::verify_data_column_sidecar_kzg_proofs;
use tree_hash::TreeHash;

pub fn is_valid_rpc_column(
    column: &DataColumnSidecar,
    root: B256,
    header: &SignedBeaconBlockHeader,
) -> bool {
    column.signed_block_header.message.tree_hash_root() == root
        && &column.signed_block_header == header
        && column.verify()
        && column.verify_inclusion_proof()
        && verify_data_column_sidecar_kzg_proofs(column).unwrap_or(false)
}
