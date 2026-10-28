//! Fulu partial data columns: the cells of one column a peer holds, exchanged through gossipsub's
//! partial messages extension.
//!
//! Spec: https://github.com/ethereum/consensus-specs/blob/master/specs/fulu/partial-columns/p2p-interface.md

use alloy_primitives::B256;
use anyhow::{bail, ensure};
use ream_consensus_misc::{
    beacon_block_header::SignedBeaconBlockHeader,
    constants::beacon::{BLOB_KZG_COMMITMENTS_INDEX, DATA_COLUMN_SIDECAR_KZG_PROOF_DEPTH},
    polynomial_commitments::{kzg_commitment::KZGCommitment, kzg_proof::KZGProof},
};
use ream_merkle::is_valid_merkle_branch;
use ssz_derive::{Decode, Encode};
use ssz_types::{BitList, FixedVector, VariableList, typenum};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

use crate::{
    data_column_sidecar::{Cell, DataColumnSidecar, MaxBlobCommitmentsPerBlock},
    electra::beacon_block::SignedBeaconBlock,
};

/// Version byte of a Fulu partial message group id.
pub const PARTIAL_COLUMNS_VERSION_FULU: u8 = 0;

/// One bit per blob of a block: whether a column's cell for that blob is present.
pub type CellsBitList = BitList<MaxBlobCommitmentsPerBlock>;

/// The part of a data column sidecar shared by all columns of a block.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash)]
pub struct PartialDataColumnHeader {
    pub kzg_commitments: VariableList<KZGCommitment, MaxBlobCommitmentsPerBlock>,
    pub signed_block_header: SignedBeaconBlockHeader,
    pub kzg_commitments_inclusion_proof: FixedVector<B256, typenum::U4>,
}

/// A partial message body: the cells and proofs set in `cells_present_bitmap`, in blob order. The
/// column index is the topic's subnet.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct PartialDataColumnSidecar {
    pub cells_present_bitmap: CellsBitList,
    pub partial_column: VariableList<Cell, MaxBlobCommitmentsPerBlock>,
    pub kzg_proofs: VariableList<KZGProof, MaxBlobCommitmentsPerBlock>,
    pub header: VariableList<PartialDataColumnHeader, typenum::U1>,
}

/// The cells a peer has, and the cells it asks for.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct PartialDataColumnPartsMetadata {
    pub available: CellsBitList,
    pub requests: CellsBitList,
}

/// The partial message group id of `block_root`'s columns.
pub fn partial_column_group_id(block_root: B256) -> Vec<u8> {
    let mut group_id = Vec::with_capacity(1 + B256::len_bytes());
    group_id.push(PARTIAL_COLUMNS_VERSION_FULU);
    group_id.extend_from_slice(block_root.as_slice());
    group_id
}

/// The block root of a Fulu group id, or `None` for another version, which must be ignored.
pub fn parse_partial_column_group_id(group_id: &[u8]) -> Option<B256> {
    match group_id.split_first() {
        Some((&PARTIAL_COLUMNS_VERSION_FULU, root)) if root.len() == B256::len_bytes() => {
            Some(B256::from_slice(root))
        }
        _ => None,
    }
}

impl PartialDataColumnHeader {
    pub fn from_sidecar(sidecar: &DataColumnSidecar) -> Self {
        Self {
            kzg_commitments: sidecar.kzg_commitments.clone(),
            signed_block_header: sidecar.signed_block_header.clone(),
            kzg_commitments_inclusion_proof: sidecar.kzg_commitments_inclusion_proof.clone(),
        }
    }

    pub fn from_block(signed_block: &SignedBeaconBlock) -> anyhow::Result<Self> {
        let proof = signed_block
            .message
            .body
            .data_inclusion_proof(BLOB_KZG_COMMITMENTS_INDEX)?;
        Ok(Self {
            kzg_commitments: signed_block.message.body.blob_kzg_commitments.clone(),
            signed_block_header: signed_block.signed_header(),
            kzg_commitments_inclusion_proof: FixedVector::new(proof)
                .map_err(|err| anyhow::anyhow!("inclusion proof has a wrong depth: {err:?}"))?,
        })
    }

    pub fn block_root(&self) -> B256 {
        self.signed_block_header.message.tree_hash_root()
    }

    /// Spec: `verify_partial_data_column_header_inclusion_proof`.
    pub fn verify_inclusion_proof(&self) -> bool {
        is_valid_merkle_branch(
            self.kzg_commitments.tree_hash_root(),
            &self.kzg_commitments_inclusion_proof,
            DATA_COLUMN_SIDECAR_KZG_PROOF_DEPTH,
            BLOB_KZG_COMMITMENTS_INDEX,
            self.signed_block_header.message.body_root,
        )
    }
}

impl PartialDataColumnSidecar {
    /// The present cells with their blob index and proof, in blob order.
    pub fn cells(&self) -> impl Iterator<Item = (usize, &Cell, &KZGProof)> {
        self.cells_present_bitmap
            .iter()
            .enumerate()
            .filter_map(|(blob_index, present)| present.then_some(blob_index))
            .zip(self.partial_column.iter().zip(self.kzg_proofs.iter()))
            .map(|(blob_index, (cell, proof))| (blob_index, cell, proof))
    }
}

/// The cells of one column held so far, indexed by blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialColumn {
    pub index: u64,
    pub cells: Vec<Option<(Cell, KZGProof)>>,
}

impl PartialColumn {
    pub fn empty(index: u64, blob_count: usize) -> Self {
        Self {
            index,
            cells: vec![None; blob_count],
        }
    }

    pub fn from_sidecar(sidecar: &DataColumnSidecar) -> Self {
        Self {
            index: sidecar.index,
            cells: sidecar
                .column
                .iter()
                .cloned()
                .zip(sidecar.kzg_proofs.iter().copied())
                .map(Some)
                .collect(),
        }
    }

    pub fn is_complete(&self) -> bool {
        self.cells.iter().all(Option::is_some)
    }

    pub fn missing_count(&self) -> usize {
        self.cells.iter().filter(|cell| cell.is_none()).count()
    }

    pub fn bitmap(&self) -> CellsBitList {
        let mut bitmap = CellsBitList::with_capacity(self.cells.len())
            .expect("a block has at most MAX_BLOB_COMMITMENTS_PER_BLOCK blobs");
        for (blob_index, cell) in self.cells.iter().enumerate() {
            if cell.is_some() {
                bitmap
                    .set(blob_index, true)
                    .expect("blob index is within the bitmap");
            }
        }
        bitmap
    }

    /// The wire message carrying the cells set in `wanted`, or all held cells for `None`.
    pub fn to_sidecar(
        &self,
        wanted: Option<&CellsBitList>,
        header: Option<&PartialDataColumnHeader>,
    ) -> PartialDataColumnSidecar {
        let mut bitmap = CellsBitList::with_capacity(self.cells.len())
            .expect("a block has at most MAX_BLOB_COMMITMENTS_PER_BLOCK blobs");
        let mut cells = Vec::new();
        let mut proofs = Vec::new();
        for (blob_index, cell) in self.cells.iter().enumerate() {
            let Some((cell, proof)) = cell else { continue };
            if wanted.is_some_and(|wanted| !wanted.get(blob_index).unwrap_or(false)) {
                continue;
            }
            bitmap
                .set(blob_index, true)
                .expect("blob index is within the bitmap");
            cells.push(cell.clone());
            proofs.push(*proof);
        }
        PartialDataColumnSidecar {
            cells_present_bitmap: bitmap,
            partial_column: VariableList::new(cells).expect("at most one cell per blob"),
            kzg_proofs: VariableList::new(proofs).expect("at most one proof per blob"),
            header: VariableList::new(header.into_iter().cloned().collect())
                .expect("at most one header"),
        }
    }

    /// The full sidecar once every cell is held.
    pub fn to_full_sidecar(&self, header: &PartialDataColumnHeader) -> Option<DataColumnSidecar> {
        let (cells, proofs): (Vec<_>, Vec<_>) = self
            .cells
            .iter()
            .cloned()
            .collect::<Option<Vec<_>>>()?
            .into_iter()
            .unzip();
        Some(DataColumnSidecar {
            index: self.index,
            column: VariableList::new(cells).ok()?,
            kzg_commitments: header.kzg_commitments.clone(),
            kzg_proofs: VariableList::new(proofs).ok()?,
            signed_block_header: header.signed_block_header.clone(),
            kzg_commitments_inclusion_proof: header.kzg_commitments_inclusion_proof.clone(),
        })
    }

    /// The cells of `sidecar` this column lacks, or an error if a held cell differs from the
    /// received one.
    pub fn new_cells(
        &self,
        sidecar: &PartialDataColumnSidecar,
    ) -> anyhow::Result<Vec<(usize, Cell, KZGProof)>> {
        ensure!(
            sidecar.cells_present_bitmap.len() == self.cells.len(),
            "bitmap covers {} blobs, the block has {}",
            sidecar.cells_present_bitmap.len(),
            self.cells.len()
        );
        let mut new_cells = Vec::new();
        for (blob_index, cell, proof) in sidecar.cells() {
            match &self.cells[blob_index] {
                Some((held_cell, held_proof)) => {
                    if held_cell != cell || held_proof != proof {
                        bail!("cell {blob_index} differs from the one already held");
                    }
                }
                None => new_cells.push((blob_index, cell.clone(), *proof)),
            }
        }
        Ok(new_cells)
    }

    /// Adds cells, keeping held ones. Returns how many were added.
    pub fn insert_cells(&mut self, cells: Vec<(usize, Cell, KZGProof)>) -> usize {
        let mut added = 0;
        for (blob_index, cell, proof) in cells {
            if let Some(slot @ None) = self.cells.get_mut(blob_index) {
                *slot = Some((cell, proof));
                added += 1;
            }
        }
        added
    }
}

#[cfg(test)]
mod tests {
    use ssz::{Decode, Encode};

    use super::*;

    fn cell(marker: u8) -> Cell {
        let mut cell = Cell::default();
        cell[0] = marker;
        cell
    }

    #[test]
    fn group_id_round_trips_and_other_versions_are_ignored() {
        let root = B256::repeat_byte(7);
        let group_id = partial_column_group_id(root);
        assert_eq!(group_id.len(), 33);
        assert_eq!(parse_partial_column_group_id(&group_id), Some(root));

        let mut gloas = group_id.clone();
        gloas[0] = 1;
        assert_eq!(parse_partial_column_group_id(&gloas), None);
        assert_eq!(parse_partial_column_group_id(&group_id[..32]), None);
    }

    #[test]
    fn wire_message_carries_only_wanted_cells_and_round_trips() {
        let mut column = PartialColumn::empty(3, 4);
        column.insert_cells(vec![
            (0, cell(10), KZGProof::default()),
            (2, cell(12), KZGProof::default()),
        ]);
        let mut wanted = CellsBitList::with_capacity(4).unwrap();
        wanted.set(2, true).unwrap();
        wanted.set(3, true).unwrap();

        let sidecar = column.to_sidecar(Some(&wanted), None);
        let decoded = PartialDataColumnSidecar::from_ssz_bytes(&sidecar.as_ssz_bytes()).unwrap();

        assert_eq!(decoded, sidecar);
        assert_eq!(
            decoded
                .cells()
                .map(|(index, cell, _)| (index, cell[0]))
                .collect::<Vec<_>>(),
            vec![(2, 12)]
        );
    }

    #[test]
    fn a_held_cell_that_differs_from_the_received_one_is_an_error() {
        let mut column = PartialColumn::empty(0, 2);
        column.insert_cells(vec![(0, cell(1), KZGProof::default())]);
        let mut other = PartialColumn::empty(0, 2);
        other.insert_cells(vec![
            (0, cell(2), KZGProof::default()),
            (1, cell(3), KZGProof::default()),
        ]);

        assert!(column.new_cells(&other.to_sidecar(None, None)).is_err());
    }

    #[test]
    fn a_column_becomes_a_full_sidecar_only_once_every_cell_is_held() {
        let header = PartialDataColumnHeader {
            kzg_commitments: VariableList::new(vec![KZGCommitment([1; 48]); 2]).unwrap(),
            signed_block_header: Default::default(),
            kzg_commitments_inclusion_proof: Default::default(),
        };
        let mut column = PartialColumn::empty(4, 2);
        column.insert_cells(vec![(1, cell(1), KZGProof::default())]);
        assert!(column.to_full_sidecar(&header).is_none());

        column.insert_cells(vec![(0, cell(0), KZGProof::default())]);
        let sidecar = column.to_full_sidecar(&header).unwrap();
        assert_eq!(sidecar.index, 4);
        assert_eq!(sidecar.column[0][0], 0);
        assert_eq!(sidecar.column[1][0], 1);
        assert_eq!(PartialColumn::from_sidecar(&sidecar), column);
    }
}
