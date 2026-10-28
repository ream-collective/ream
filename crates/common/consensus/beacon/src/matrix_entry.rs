use std::sync::OnceLock;

use anyhow::{Ok, Result, anyhow, ensure};
use rayon::{
    ThreadPool, ThreadPoolBuilder,
    iter::{IntoParallelIterator, ParallelIterator},
};
use ream_consensus_misc::{
    constants::beacon::CELLS_PER_EXT_BLOB, polynomial_commitments::kzg_proof::KZGProof,
};
use ream_execution_rpc_types::get_blobs::{Blob, BlobAndProofV2};
use ream_metrics::{
    BEACON_DATA_AVAILABILITY_RECONSTRUCTED_COLUMNS_TOTAL,
    BEACON_DATA_AVAILABILITY_RECONSTRUCTION_TIME_SECONDS,
};
use rust_eth_kzg::{Cell as KZGCell, DASContext, KZGProof as Proof, TrustedSetup, UsePrecomp};
use ssz_types::FixedVector;

use crate::{
    data_column_sidecar::{
        Cell, DataColumnSidecar, NUMBER_OF_COLUMNS, get_data_column_sidecars_from_block,
        get_data_column_sidecars_from_column_sidecar,
    },
    electra::beacon_block::SignedBeaconBlock,
    partial_data_column_sidecar::PartialColumn,
};

// Gossip and range-sync callers share this pool. Using at most half of the available CPUs and no
// more than four workers leaves capacity for block processing and network tasks.
const MAX_RECONSTRUCTION_THREADS: usize = 4;

pub fn das_context() -> &'static DASContext {
    static DAS_CONTEXT: OnceLock<DASContext> = OnceLock::new();
    DAS_CONTEXT.get_or_init(|| DASContext::new(&TrustedSetup::default(), UsePrecomp::No))
}

fn reconstruction_pool() -> &'static ThreadPool {
    static RECONSTRUCTION_POOL: OnceLock<ThreadPool> = OnceLock::new();
    RECONSTRUCTION_POOL.get_or_init(|| {
        let available_threads = std::thread::available_parallelism()
            .map(|count| count.get())
            .unwrap_or(1);
        let thread_count = (available_threads / 2).clamp(1, MAX_RECONSTRUCTION_THREADS);
        ThreadPoolBuilder::new()
            .num_threads(thread_count)
            .thread_name(|index| format!("da-reconstruction-{index}"))
            .build()
            .expect("data column reconstruction thread pool should build")
    })
}

#[derive(Debug, Clone, PartialEq)]
pub struct MatrixEntry {
    cell: Cell,
    #[allow(dead_code)]
    kzg_proof: KZGProof,
    column_index: u64,
    row_index: u64,
}

pub fn compute_matrix(blobs: Vec<Blob>, das_context: &DASContext) -> Result<Vec<MatrixEntry>> {
    let mut matrix = Vec::new();

    for (blob_index, blob) in blobs.iter().enumerate() {
        let (cells, proofs) = compute_cells_and_kzg_proofs(blob, das_context)?;
        for (cell_index, (cell, kzg_proof)) in cells.into_iter().zip(proofs).enumerate() {
            matrix.push(MatrixEntry {
                cell,
                kzg_proof,
                column_index: cell_index as u64,
                row_index: blob_index as u64,
            });
        }
    }

    Ok(matrix)
}

pub fn recover_matrix(
    partial_matrix: Vec<MatrixEntry>,
    blob_count: u64,
    das_context: &DASContext,
) -> Result<Vec<MatrixEntry>> {
    let _timer = BEACON_DATA_AVAILABILITY_RECONSTRUCTION_TIME_SECONDS.start_timer();
    let mut matrix = Vec::new();
    let mut reconstructed_count: u64 = 0;

    for blob_index in 0..blob_count {
        let (cell_indices, cells): (Vec<u64>, Vec<Cell>) = partial_matrix
            .iter()
            .filter(|entry| entry.row_index == blob_index)
            .map(|entry| (entry.column_index, entry.cell.clone()))
            .unzip();

        let known_count = cell_indices.len() as u64;

        let (recovered_cells, recovered_proofs) =
            recover_cells_and_kzg_proofs(cell_indices, cells, das_context)?;

        let newly_reconstructed = recovered_cells.len() as u64 - known_count;
        reconstructed_count += newly_reconstructed;

        for (cell_index, (cell, kzg_proof)) in recovered_cells
            .into_iter()
            .zip(recovered_proofs)
            .enumerate()
        {
            matrix.push(MatrixEntry {
                cell,
                kzg_proof,
                column_index: cell_index as u64,
                row_index: blob_index,
            });
        }
    }

    BEACON_DATA_AVAILABILITY_RECONSTRUCTED_COLUMNS_TOTAL.inc_by(reconstructed_count);

    Ok(matrix)
}

pub fn compute_cells_and_kzg_proofs(
    blob: &Blob,
    das_context: &DASContext,
) -> Result<(Vec<Cell>, Vec<KZGProof>)> {
    let blob_data: Vec<u8> = blob.inner.clone().into();
    ensure!(
        blob_data.len() == 131072,
        "Blob inner length {}, expected 131072",
        blob_data.len()
    );
    let blob_bytes: &[u8; 131072] = blob_data
        .as_slice()
        .try_into()
        .map_err(|err| anyhow!("Failed to convert blob inner to &[u8; 131072]: {err}"))?;
    let (kzg_cells, kzg_proofs) = das_context
        .compute_cells_and_kzg_proofs(blob_bytes)
        .map_err(|err| anyhow!("KZG error: {err:?}"))?;

    let cells = kzg_cells.into_iter().map(convert_cell).collect();
    let proofs = kzg_proofs.into_iter().map(convert_kzg_proof).collect();

    Ok((cells, proofs))
}

pub fn recover_cells_and_kzg_proofs(
    cell_indices: Vec<u64>,
    cells: Vec<Cell>,
    das_context: &DASContext,
) -> Result<(Vec<Cell>, Vec<KZGProof>)> {
    let kzg_cells_result: Result<Vec<[u8; 2048]>> = cells
        .into_iter()
        .map(|cell_fixed_vector| {
            let cell_vec: Vec<u8> = cell_fixed_vector.into();
            ensure!(
                cell_vec.len() == 2048,
                "Cell length {}, expected 2048",
                cell_vec.len()
            );
            let cell_array: [u8; 2048] = cell_vec
                .try_into()
                .map_err(|err| anyhow!("Failed to convert Cell to [u8; 2048]: {err:?}"))?;
            Ok(cell_array)
        })
        .collect();

    let kzg_cells = kzg_cells_result?;
    let kzg_cells_refs = kzg_cells.iter().collect();
    let (new_kzg_cells, new_kzg_proofs) = das_context
        .recover_cells_and_kzg_proofs(cell_indices, kzg_cells_refs)
        .map_err(|err| anyhow!("KZG recovery error: {err:?}"))?;

    let cells = new_kzg_cells.into_iter().map(convert_cell).collect();
    let proofs = new_kzg_proofs.into_iter().map(convert_kzg_proof).collect();

    Ok((cells, proofs))
}

/// Rebuilds all `NUMBER_OF_COLUMNS` sidecars of a block from at least half of them.
///
/// The inputs must be verified sidecars of one block. Cells verified against the block's
/// commitments fix each blob polynomial, so the recovered cells and proofs match those
/// commitments as well; the header, commitments and inclusion proof are copied from an input.
pub fn reconstruct_data_column_sidecars(
    available: &[&DataColumnSidecar],
) -> Result<Vec<DataColumnSidecar>> {
    ensure!(
        available.len() as u64 >= NUMBER_OF_COLUMNS / 2,
        "reconstruction needs {} columns, got {}",
        NUMBER_OF_COLUMNS / 2,
        available.len()
    );
    let base = available[0];
    let mut seen = std::collections::HashSet::new();
    for sidecar in available {
        ensure!(
            sidecar.signed_block_header == base.signed_block_header,
            "column {} belongs to another block",
            sidecar.index
        );
        ensure!(
            seen.insert(sidecar.index),
            "column {} is given twice",
            sidecar.index
        );
        ensure!(
            sidecar.column.len() == base.kzg_commitments.len(),
            "column {} has {} cells for {} blobs",
            sidecar.index,
            sidecar.column.len(),
            base.kzg_commitments.len()
        );
    }

    let timer = BEACON_DATA_AVAILABILITY_RECONSTRUCTION_TIME_SECONDS.start_timer();
    let column_indices = available
        .iter()
        .map(|sidecar| sidecar.index)
        .collect::<Vec<_>>();
    let context = das_context();
    let recovered_rows = reconstruction_pool().install(|| {
        (0..base.kzg_commitments.len())
            .into_par_iter()
            .map(|blob_index| {
                let cells = available
                    .iter()
                    .map(|sidecar| sidecar.column[blob_index].clone())
                    .collect();
                recover_cells_and_kzg_proofs(column_indices.clone(), cells, context)
            })
            .collect::<Vec<_>>()
    });
    let cells_and_kzg_proofs = recovered_rows.into_iter().collect::<Result<Vec<_>>>()?;
    let reconstructed =
        get_data_column_sidecars_from_column_sidecar(base.clone(), cells_and_kzg_proofs)
            .map_err(|err| anyhow!("failed to assemble reconstructed columns: {err}"))?;
    timer.observe_duration();

    // Recovery keeps the cells it was given; a mismatch means the inputs disagree with each
    // other, so nothing reconstructed from them can be trusted.
    for sidecar in available {
        ensure!(
            reconstructed[sidecar.index as usize].column == sidecar.column,
            "recovered column {} differs from the column it was rebuilt from",
            sidecar.index
        );
    }
    BEACON_DATA_AVAILABILITY_RECONSTRUCTED_COLUMNS_TOTAL
        .inc_by((reconstructed.len() - available.len()) as u64);
    Ok(reconstructed)
}

/// Builds all `NUMBER_OF_COLUMNS` sidecars of `signed_block` from its blobs and their cell proofs,
/// as `engine_getBlobsV2` returns them, one per commitment and in commitment order.
///
/// Only the cells are computed. The proofs are taken as given: the execution client verified them
/// when the blob transactions entered its pool, and Lighthouse trusts them the same way.
pub fn data_column_sidecars_from_execution_blobs(
    signed_block: &SignedBeaconBlock,
    blobs_and_proofs: Vec<BlobAndProofV2>,
) -> Result<Vec<DataColumnSidecar>> {
    let commitment_count = signed_block.message.body.blob_kzg_commitments.len();
    ensure!(
        blobs_and_proofs.len() == commitment_count,
        "execution client returned {} blobs for {commitment_count} commitments",
        blobs_and_proofs.len()
    );
    let context = das_context();
    let cells_and_kzg_proofs = reconstruction_pool()
        .install(|| {
            blobs_and_proofs
                .into_par_iter()
                .map(|BlobAndProofV2 { blob, proofs }| {
                    let cells = compute_cells(blob, context)?;
                    Ok((cells.into_iter().collect(), proofs.to_vec()))
                })
                .collect::<Vec<_>>()
        })
        .into_iter()
        .collect::<Result<Vec<_>>>()?;
    get_data_column_sidecars_from_block(signed_block, cells_and_kzg_proofs)
        .map_err(|err| anyhow!("failed to assemble columns from execution blobs: {err}"))
}

/// Builds the cells of `columns` from the blobs the execution client returned, `None` for a blob
/// it lacks, with their proofs taken as given like [`data_column_sidecars_from_execution_blobs`].
pub fn partial_columns_from_execution_blobs(
    blobs_and_proofs: Vec<Option<BlobAndProofV2>>,
    columns: &[u64],
) -> Result<Vec<PartialColumn>> {
    let context = das_context();
    let blob_count = blobs_and_proofs.len();
    let cells_and_proofs = reconstruction_pool()
        .install(|| {
            blobs_and_proofs
                .into_par_iter()
                .map(|blob| {
                    blob.map(|BlobAndProofV2 { blob, proofs }| {
                        Ok((compute_cells(blob, context)?, proofs))
                    })
                    .transpose()
                })
                .collect::<Vec<_>>()
        })
        .into_iter()
        .collect::<Result<Vec<_>>>()?;
    let mut partial_columns = columns
        .iter()
        .map(|index| PartialColumn::empty(*index, blob_count))
        .collect::<Vec<_>>();
    for (blob_index, cells_and_proofs) in cells_and_proofs.into_iter().enumerate() {
        let Some((cells, proofs)) = cells_and_proofs else {
            continue;
        };
        for column in &mut partial_columns {
            let index = column.index as usize;
            column.cells[blob_index] = Some((cells[index].clone(), proofs[index]));
        }
    }
    Ok(partial_columns)
}

fn convert_cell(kzg_cell: KZGCell) -> Cell {
    FixedVector::try_from(kzg_cell.to_vec()).expect("Cell conversion failed")
}

fn convert_kzg_proof(kzg_proof: Proof) -> KZGProof {
    KZGProof::from(kzg_proof)
}

pub fn compute_cells(
    blob: Blob,
    das_context: &DASContext,
) -> anyhow::Result<[Cell; CELLS_PER_EXT_BLOB as usize]> {
    let blob_data: Vec<u8> = blob.inner.into();
    let blob_bytes: &[u8; 131072] = blob_data
        .as_slice()
        .try_into()
        .map_err(|err| anyhow!("Invalid blob size {err:?}"))?;

    let kzg_cells = das_context
        .compute_cells(blob_bytes)
        .map_err(|err| anyhow!("KZG error: {err:?}"))?;

    let cells: Vec<Cell> = kzg_cells.into_iter().map(convert_cell).collect();

    let final_cells: [Cell; CELLS_PER_EXT_BLOB as usize] = cells
        .try_into()
        .map_err(|err| anyhow!("Failed to convert to fixed array {err:?}"))?;

    Ok(final_cells)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        time::Instant,
    };

    use rand::{RngExt, SeedableRng, rngs::StdRng, seq::SliceRandom};
    use ream_consensus_misc::polynomial_commitments::kzg_commitment::KZGCommitment;
    use rust_eth_kzg::{DASContext, TrustedSetup, UsePrecomp};
    use ssz::Decode;

    use super::*;
    use crate::electra::beacon_block::BeaconBlock;

    const BYTES_PER_BLOB: usize = 131072;

    fn get_sample_blob(rng: &mut StdRng) -> Blob {
        let mut bytes = vec![0u8; BYTES_PER_BLOB];
        for chunk in bytes.chunks_mut(32) {
            rng.fill(&mut chunk[1..]);
        }
        Blob::from_ssz_bytes(&bytes).expect("constructed blob bytes should decode")
    }

    fn chunks<T: Clone>(items: &[T], size: usize) -> Vec<Vec<T>> {
        items.chunks(size).map(|chunk| chunk.to_vec()).collect()
    }

    #[test]
    fn test_compute_matrix() -> Result<()> {
        let mut rng = StdRng::seed_from_u64(5566);
        let context = DASContext::new(&TrustedSetup::default(), UsePrecomp::No);

        let blob_count = 2;
        let input_blobs: Vec<Blob> = (0..blob_count).map(|_| get_sample_blob(&mut rng)).collect();

        let matrix = compute_matrix(input_blobs.clone(), &context)?;
        assert_eq!(matrix.len(), CELLS_PER_EXT_BLOB as usize * blob_count);

        let rows = chunks(&matrix, CELLS_PER_EXT_BLOB as usize);
        assert_eq!(rows.len(), blob_count);
        for row in &rows {
            assert_eq!(row.len(), CELLS_PER_EXT_BLOB as usize);
        }

        for (blob_index, row) in rows.iter().enumerate() {
            let mut column_indices: Vec<u64> = row
                .iter()
                .map(|entry| {
                    assert_eq!(entry.row_index, blob_index as u64);
                    entry.column_index
                })
                .collect();
            column_indices.sort();
            assert_eq!(column_indices, (0..CELLS_PER_EXT_BLOB).collect::<Vec<_>>());

            let mut extended_blob = Vec::<u8>::new();
            for entry in row {
                extended_blob.extend::<Vec<u8>>(entry.cell.clone().into());
            }
            let blob_part = &extended_blob[..extended_blob.len() / 2];
            let original: Vec<u8> = input_blobs[blob_index].inner.clone().into();
            assert_eq!(blob_part, original.as_slice());
        }

        Ok(())
    }

    #[test]
    fn test_recover_matrix() -> Result<()> {
        let mut rng = StdRng::seed_from_u64(5566);
        let context = DASContext::new(&TrustedSetup::default(), UsePrecomp::No);

        let n_samples = (CELLS_PER_EXT_BLOB / 2) as usize;
        let blob_count = 2;

        let blobs: Vec<Blob> = (0..blob_count).map(|_| get_sample_blob(&mut rng)).collect();
        let matrix = compute_matrix(blobs, &context)?;

        let mut partial_matrix = Vec::new();
        for blob_entries in chunks(&matrix, CELLS_PER_EXT_BLOB as usize) {
            let mut indices: Vec<usize> = (0..blob_entries.len()).collect();

            indices.shuffle(&mut rng);
            let mut sampled = indices[..n_samples].to_vec();
            sampled.sort();
            partial_matrix.extend(sampled.into_iter().map(|i| blob_entries[i].clone()));
        }

        let recovered_matrix = recover_matrix(partial_matrix, blob_count as u64, &context)?;

        assert_eq!(recovered_matrix, matrix);

        Ok(())
    }

    fn sample_sidecars(rng: &mut StdRng, blob_count: usize) -> Result<Vec<DataColumnSidecar>> {
        let cells_and_kzg_proofs = (0..blob_count)
            .map(|_| compute_cells_and_kzg_proofs(&get_sample_blob(rng), das_context()))
            .collect::<Result<Vec<_>>>()?;
        let commitments = vec![
            ream_consensus_misc::polynomial_commitments::kzg_commitment::KZGCommitment([0u8; 48]);
            blob_count
        ];
        crate::data_column_sidecar::get_data_column_sidecars(
            Default::default(),
            ssz_types::VariableList::new(commitments).expect("commitments fit"),
            FixedVector::default(),
            cells_and_kzg_proofs,
        )
        .map_err(|err| anyhow!("{err}"))
    }

    #[test]
    fn half_the_columns_rebuild_every_column() -> Result<()> {
        let mut rng = StdRng::seed_from_u64(7788);
        let sidecars = sample_sidecars(&mut rng, 2)?;
        let mut indices: Vec<usize> = (0..sidecars.len()).collect();
        indices.shuffle(&mut rng);
        let half = indices[..(NUMBER_OF_COLUMNS / 2) as usize]
            .iter()
            .map(|index| &sidecars[*index])
            .collect::<Vec<_>>();

        let rebuilt = reconstruct_data_column_sidecars(&half)?;
        assert_eq!(rebuilt, sidecars);
        Ok(())
    }

    #[test]
    fn execution_blobs_build_the_columns_of_the_block() -> Result<()> {
        let mut rng = StdRng::seed_from_u64(4242);
        let blobs = (0..2)
            .map(|_| get_sample_blob(&mut rng))
            .collect::<Vec<_>>();
        let mut block = SignedBeaconBlock {
            message: BeaconBlock::default(),
            signature: Default::default(),
        };
        let mut cells_and_kzg_proofs = Vec::new();
        let mut blobs_and_proofs = Vec::new();
        for blob in blobs {
            let commitment = das_context()
                .blob_to_kzg_commitment(&blob.to_fixed_bytes())
                .map_err(|err| anyhow!("{err:?}"))?;
            block
                .message
                .body
                .blob_kzg_commitments
                .push(KZGCommitment(commitment))
                .map_err(|err| anyhow!("{err:?}"))?;
            let (cells, proofs) = compute_cells_and_kzg_proofs(&blob, das_context())?;
            blobs_and_proofs.push(BlobAndProofV2 {
                blob,
                proofs: FixedVector::new(proofs.clone()).map_err(|err| anyhow!("{err:?}"))?,
            });
            cells_and_kzg_proofs.push((cells, proofs));
        }

        let expected = get_data_column_sidecars_from_block(&block, cells_and_kzg_proofs)
            .map_err(|err| anyhow!("{err}"))?;
        assert_eq!(
            data_column_sidecars_from_execution_blobs(&block, blobs_and_proofs.clone())?,
            expected
        );
        assert!(
            expected
                .iter()
                .all(DataColumnSidecar::verify_inclusion_proof)
        );

        // A response for other blocks' blobs cannot be matched to the commitments.
        blobs_and_proofs.pop();
        assert!(data_column_sidecars_from_execution_blobs(&block, blobs_and_proofs).is_err());
        Ok(())
    }

    #[test]
    fn reconstruction_rejects_too_few_or_mixed_columns() -> Result<()> {
        let mut rng = StdRng::seed_from_u64(7789);
        let sidecars = sample_sidecars(&mut rng, 1)?;
        let short = sidecars[..(NUMBER_OF_COLUMNS / 2 - 1) as usize]
            .iter()
            .collect::<Vec<_>>();
        assert!(reconstruct_data_column_sidecars(&short).is_err());

        let mut other_block = sidecars[0].clone();
        other_block.signed_block_header.message.slot = 1;
        let mut mixed = sidecars[1..(NUMBER_OF_COLUMNS / 2) as usize]
            .iter()
            .collect::<Vec<_>>();
        mixed.push(&other_block);
        assert!(reconstruct_data_column_sidecars(&mixed).is_err());
        Ok(())
    }

    #[test]
    #[ignore = "needs REAM_BENCH_FIXTURE_DIR, the frozen mainnet fixture; reports timings"]
    fn benchmark_mainnet_data_column_reconstruction() -> Result<()> {
        const BLOCK_COUNT: usize = 3;
        const SAMPLE_COUNT: usize = 5;

        // The fixture written by the `mainnet_import_bench` tests in `bin/ream`.
        let fixture_root = std::env::var_os("REAM_BENCH_FIXTURE_DIR")
            .ok_or_else(|| anyhow!("REAM_BENCH_FIXTURE_DIR must be set"))?;
        let mut blocks = fixture_blocks_by_blob_count(Path::new(&fixture_root))?;
        ensure!(
            blocks.len() >= BLOCK_COUNT,
            "fixture has {} complete blocks, expected at least {BLOCK_COUNT}",
            blocks.len()
        );
        blocks.truncate(BLOCK_COUNT);
        eprintln!(
            "reconstruction worker_threads={}",
            reconstruction_pool().current_num_threads()
        );

        for (blob_count, block_dir) in blocks {
            let original = load_fixture_columns(&block_dir)?;
            let available = original
                .iter()
                .filter(|sidecar| sidecar.index % 2 == 0)
                .collect::<Vec<_>>();
            assert_eq!(available.len(), (NUMBER_OF_COLUMNS / 2) as usize);

            let warmup = reconstruct_data_column_sidecars(&available)?;
            assert_eq!(warmup, original);

            let mut samples = Vec::with_capacity(SAMPLE_COUNT);
            for _ in 0..SAMPLE_COUNT {
                let started = Instant::now();
                let reconstructed = reconstruct_data_column_sidecars(&available)?;
                samples.push(started.elapsed());
                assert_eq!(reconstructed, original);
            }
            samples.sort_unstable();

            let block = block_dir
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("<unknown>");
            let samples_ms = samples
                .iter()
                .map(|duration| duration.as_secs_f64() * 1_000.0)
                .collect::<Vec<_>>();
            let median_ms = samples[SAMPLE_COUNT / 2].as_secs_f64() * 1_000.0;
            eprintln!(
                "reconstruction block={block} blobs={blob_count} samples_ms={samples_ms:?} \
                 median_ms={median_ms:.3}"
            );
        }

        Ok(())
    }

    fn fixture_blocks_by_blob_count(root: &Path) -> Result<Vec<(usize, PathBuf)>> {
        let mut blocks = Vec::new();
        for entry in fs::read_dir(root)? {
            let block_dir = entry?.path();
            if !block_dir.is_dir() {
                continue;
            }

            let first_column = block_dir.join("column_0.ssz");
            if !first_column.is_file() {
                continue;
            }
            let sidecar = DataColumnSidecar::from_ssz_bytes(&fs::read(&first_column)?)
                .map_err(|err| anyhow!("failed to decode {}: {err:?}", first_column.display()))?;
            let has_every_column = (0..NUMBER_OF_COLUMNS)
                .all(|index| block_dir.join(format!("column_{index}.ssz")).is_file());
            if has_every_column {
                blocks.push((sidecar.column.len(), block_dir));
            }
        }
        blocks.sort_unstable_by(|left, right| {
            right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1))
        });
        Ok(blocks)
    }

    fn load_fixture_columns(block_dir: &Path) -> Result<Vec<DataColumnSidecar>> {
        (0..NUMBER_OF_COLUMNS)
            .map(|index| {
                let path = block_dir.join(format!("column_{index}.ssz"));
                let sidecar = DataColumnSidecar::from_ssz_bytes(&fs::read(&path)?)
                    .map_err(|err| anyhow!("failed to decode {}: {err:?}", path.display()))?;
                ensure!(
                    sidecar.index == index,
                    "{} contains column {}, expected {index}",
                    path.display(),
                    sidecar.index
                );
                Ok(sidecar)
            })
            .collect()
    }

    #[test]
    fn a_partial_execution_response_fills_only_the_blobs_it_returned() {
        let blob = get_sample_blob(&mut StdRng::seed_from_u64(7));
        let (cells, proofs) = compute_cells_and_kzg_proofs(&blob, das_context()).unwrap();
        let returned = BlobAndProofV2 {
            blob,
            proofs: FixedVector::new(proofs.clone()).unwrap(),
        };

        let columns =
            partial_columns_from_execution_blobs(vec![None, Some(returned)], &[3, 100]).unwrap();

        assert_eq!(columns.len(), 2);
        for column in columns {
            let index = column.index as usize;
            assert_eq!(column.cells[0], None);
            assert_eq!(column.cells[1], Some((cells[index].clone(), proofs[index])));
        }
    }
}
