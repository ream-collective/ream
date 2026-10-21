use std::borrow::Borrow;

use anyhow::{anyhow, bail};
use kzg::{DAS, Fr, G1, eip_4844::verify_blob_kzg_proof_batch_raw};
use ream_consensus_beacon::data_column_sidecar::{
    Cell, DataColumnSidecar, MaxBlobCommitmentsPerBlock,
};
use ream_consensus_misc::polynomial_commitments::{
    kzg_commitment::KZGCommitment, kzg_proof::KZGProof,
};
use ream_execution_rpc_types::get_blobs::Blob;
use ream_metrics::BEACON_KZG_VERIFICATION_DATA_COLUMN_BATCH_SECONDS;
use rust_kzg_blst::{
    eip_7594::BlstBackend,
    types::{fr::FsFr, g1::FsG1, kzg_settings::FsKZGSettings},
};
use ssz_types::VariableList;

use super::{error::KzgError, trusted_setup};

/// Given a list of blobs and blob KZG proofs, verify that they correspond to the provided
/// commitments. Will return True if there are zero blobs/commitments/proofs.
/// Public method.
pub fn verify_blob_kzg_proof_batch(
    blobs: &[Blob],
    commitments_bytes: &[KZGCommitment],
    proofs_bytes: &[KZGProof],
) -> anyhow::Result<bool> {
    let raw_blobs = blobs
        .iter()
        .map(|blob| blob.to_fixed_bytes())
        .collect::<Vec<_>>();

    let raw_commitments = commitments_bytes
        .iter()
        .map(|commitment| commitment.0)
        .collect::<Vec<_>>();

    let raw_proofs = proofs_bytes.iter().map(|proof| proof.0).collect::<Vec<_>>();

    let result = verify_blob_kzg_proof_batch_raw(
        &raw_blobs,
        &raw_commitments,
        &raw_proofs,
        trusted_setup::blst_settings(),
    );

    result.map_err(KzgError::KzgError).map_err(Into::into)
}

/// Verify that a set of cells belong to their corresponding commitments.
///
/// Spec: https://ethereum.github.io/consensus-specs/specs/fulu/polynomial-commitments-sampling/#verify_cell_kzg_proof_batch_impl
pub fn verify_cell_kzg_proof_batch(
    commitments_bytes: &VariableList<KZGCommitment, MaxBlobCommitmentsPerBlock>,
    cell_indices: &[u64],
    cells: &VariableList<Cell, MaxBlobCommitmentsPerBlock>,
    proofs_bytes: &VariableList<KZGProof, MaxBlobCommitmentsPerBlock>,
) -> anyhow::Result<bool> {
    let _timer = BEACON_KZG_VERIFICATION_DATA_COLUMN_BATCH_SECONDS.start_timer();

    if commitments_bytes.len() != cells.len()
        || cells.len() != proofs_bytes.len()
        || proofs_bytes.len() != cell_indices.len()
    {
        bail!(
            "Length mismatch: commitments, cells, proofs, and cell_indices must have same length"
        );
    }

    for commitment in commitments_bytes.iter() {
        if commitment.0.len() != 48 {
            bail!("Invalid commitment length: expected 48 bytes");
        }
    }

    const CELLS_PER_EXT_BLOB: u64 = 128;
    for &cell_index in cell_indices {
        if cell_index >= CELLS_PER_EXT_BLOB {
            bail!("Invalid cell index: {cell_index} >= CELLS_PER_EXT_BLOB (128)");
        }
    }

    for cell in cells.iter() {
        if cell.len() != 2048 {
            bail!("Invalid cell length: expected 2048 bytes");
        }
    }

    for proof in proofs_bytes.iter() {
        if proof.0.len() != 48 {
            bail!("Invalid proof length: expected 48 bytes");
        }
    }

    let commitments: Vec<FsG1> = commitments_bytes
        .iter()
        .map(|c| FsG1::from_bytes(&c.0).map_err(|err| anyhow!("Invalid commitment bytes: {err}")))
        .collect::<Result<Vec<_>, _>>()?;

    let cell_indices_usize: Vec<usize> = cell_indices.iter().map(|&i| i as usize).collect();

    let cosets_evals: Vec<FsFr> = cells
        .iter()
        .flat_map(|cell| {
            cell.chunks(32).map(|bytes| {
                FsFr::from_bytes(bytes).map_err(|err| anyhow!("Invalid cell field element: {err}"))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let proofs: Vec<FsG1> = proofs_bytes
        .iter()
        .map(|proof| {
            FsG1::from_bytes(&proof.0).map_err(|err| anyhow!("Invalid proof bytes: {err}"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let settings = trusted_setup::blst_settings();
    <FsKZGSettings as DAS<BlstBackend>>::verify_cell_kzg_proof_batch(
        settings,
        &commitments,
        &cell_indices_usize,
        &cosets_evals,
        &proofs,
    )
    .map_err(|err| anyhow!("Cell KZG proof batch verification failed: {err}"))
}

/// Verify if the KZG proofs are correct for a data column sidecar.
///
/// Spec: https://ethereum.github.io/consensus-specs/specs/fulu/p2p-interface/#verify_data_column_sidecar_kzg_proofs
pub fn verify_data_column_sidecar_kzg_proofs(sidecar: &DataColumnSidecar) -> anyhow::Result<bool> {
    // The column index also represents the cell index
    let cell_indices = vec![sidecar.index; sidecar.column.len()];

    // Batch verify that the cells match the corresponding commitments and proofs
    verify_cell_kzg_proof_batch(
        &sidecar.kzg_commitments,
        &cell_indices,
        &sidecar.column,
        &sidecar.kzg_proofs,
    )
}

/// Most cells in one call of `verify_cell_kzg_proof_batch`, the limit of its lists.
const MAX_CELLS_PER_KZG_BATCH: usize = 4096;

/// Verifies the KZG proofs of every cell of `sidecars`, in batches of at most
/// `MAX_CELLS_PER_KZG_BATCH` cells. One batch check of many cells costs far less than a check per
/// column, which range sync and column backfill would otherwise pay for each of a block's 128
/// columns. Takes sidecars or references to them, so callers need not copy their columns.
pub fn verify_data_column_sidecars_kzg_proofs<S: Borrow<DataColumnSidecar>>(
    sidecars: &[S],
) -> anyhow::Result<bool> {
    let mut offset = 0;
    while offset < sidecars.len() {
        let mut end = offset;
        let mut cell_count = 0;
        while end < sidecars.len()
            && cell_count + sidecars[end].borrow().column.len() <= MAX_CELLS_PER_KZG_BATCH
        {
            cell_count += sidecars[end].borrow().column.len();
            end += 1;
        }
        if end == offset {
            bail!("Column exceeds KZG batch cell limit");
        }
        let mut commitments = Vec::with_capacity(cell_count);
        let mut indices = Vec::with_capacity(cell_count);
        let mut cells = Vec::with_capacity(cell_count);
        let mut proofs = Vec::with_capacity(cell_count);
        for column in &sidecars[offset..end] {
            let column = column.borrow();
            // A column with more cells than commitments would shift every later cell onto the
            // wrong commitment.
            if column.column.len() != column.kzg_commitments.len()
                || column.column.len() != column.kzg_proofs.len()
            {
                bail!("Length mismatch in data column sidecar {}", column.index);
            }
            commitments.extend(column.kzg_commitments.iter().cloned());
            indices.extend(std::iter::repeat_n(column.index, column.column.len()));
            cells.extend(column.column.iter().cloned());
            proofs.extend(column.kzg_proofs.iter().cloned());
        }
        if !verify_cell_kzg_proof_batch(
            &VariableList::new(commitments)
                .map_err(|err| anyhow!("Invalid commitment batch: {err:?}"))?,
            &indices,
            &VariableList::new(cells).map_err(|err| anyhow!("Invalid cell batch: {err:?}"))?,
            &VariableList::new(proofs).map_err(|err| anyhow!("Invalid proof batch: {err:?}"))?,
        )? {
            return Ok(false);
        }
        offset = end;
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use ream_consensus_beacon::{
        data_column_sidecar::get_data_column_sidecars_from_block,
        electra::beacon_block::SignedBeaconBlock,
        matrix_entry::{compute_cells_and_kzg_proofs, das_context},
    };
    use ream_consensus_misc::polynomial_commitments::kzg_commitment::KZGCommitment;
    use ream_execution_rpc_types::get_blobs::Blob;

    use super::*;

    #[test]
    fn a_batch_of_columns_verifies_together_and_fails_on_one_bad_proof() {
        let blob = Blob::default();
        let mut block = SignedBeaconBlock {
            message: Default::default(),
            signature: Default::default(),
        };
        for _ in 0..2 {
            block
                .message
                .body
                .blob_kzg_commitments
                .push(KZGCommitment(
                    das_context()
                        .blob_to_kzg_commitment(&blob.to_fixed_bytes())
                        .unwrap(),
                ))
                .unwrap();
        }
        let cells_and_proofs = compute_cells_and_kzg_proofs(&blob, das_context()).unwrap();
        let mut columns = get_data_column_sidecars_from_block(
            &block,
            vec![cells_and_proofs.clone(), cells_and_proofs],
        )
        .unwrap();
        assert!(
            verify_data_column_sidecars_kzg_proofs(&columns.iter().collect::<Vec<_>>()).unwrap()
        );
        assert!(verify_data_column_sidecars_kzg_proofs::<DataColumnSidecar>(&[]).unwrap());

        columns[77].kzg_proofs[1][0] ^= 1;
        assert!(
            !verify_data_column_sidecars_kzg_proofs(&columns.iter().collect::<Vec<_>>())
                .unwrap_or(false)
        );
    }
}
