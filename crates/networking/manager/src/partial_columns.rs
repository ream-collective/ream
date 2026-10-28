//! Fulu partial columns: validating partial messages, assembling verified cells into columns, and
//! advertising the cells this node holds.
//!
//! Spec: https://github.com/ethereum/consensus-specs/blob/master/specs/fulu/partial-columns/p2p-interface.md

use std::{
    collections::HashMap,
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy_primitives::B256;
use libp2p::PeerId;
use lru::LruCache;
use parking_lot::Mutex;
use ream_chain_beacon::beacon_chain::BeaconChain;
use ream_consensus_beacon::{
    data_column_sidecar::{Cell, ColumnIdentifier, DataColumnSidecar},
    electra::beacon_block::SignedBeaconBlock,
    matrix_entry::partial_columns_from_execution_blobs,
    partial_data_column_sidecar::{
        PartialColumn, PartialDataColumnHeader, PartialDataColumnSidecar,
    },
};
use ream_consensus_misc::{
    misc::compute_start_slot_at_epoch, polynomial_commitments::kzg_proof::KZGProof,
};
use ream_execution_rpc_types::get_blobs::BlobAndProofV2;
use ream_metrics::{
    BEACON_DATA_COLUMNS_FROM_EL_IMPORTED_TOTAL, BEACON_GOSSIP_PENDING_ITEMS_DROPPED_TOTAL,
    BEACON_PARTIAL_DATA_COLUMN_SIDECAR_GOSSIP_VERIFICATION_SECONDS,
    BEACON_PARTIAL_MESSAGE_CELLS_RECEIVED_TOTAL, BEACON_PARTIAL_MESSAGE_COLUMN_COMPLETIONS_TOTAL,
    BEACON_PARTIAL_MESSAGE_USEFUL_CELLS_TOTAL, BEACON_USEFUL_FULL_COLUMNS_RECEIVED_TOTAL,
};
use ream_p2p::gossipsub::beacon::partial::PartialColumnMessage;
use ream_storage::{cache::BeaconCacheDB, tables::field::REDBField};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::{
    block_lookup::PendingGossipItem,
    gossipsub::{
        cross_seed::publish_reconstructed_columns,
        validate::{
            data_column_sidecar::GossipValidatedDataColumn,
            partial_data_column_sidecar::{
                check_partial_structure, check_slot, validate_partial_data_column_header,
                verify_partial_cells,
            },
            result::{DependencyValidationResult, ValidationResult},
        },
        workers::try_forward,
    },
    p2p_sender::P2PSender,
    service::publish_execution_columns,
    timing::{ColumnSource, log_columns_received},
};

/// Blocks whose cells are assembled at once, about four slots' worth with forks.
const MAX_ASSEMBLIES: usize = 32;

/// Blocks whose blobs were fetched from the execution client, so an evicted block that comes back
/// is not fetched again.
const FETCHED_BLOCKS: NonZeroUsize = NonZeroUsize::new(2 * MAX_ASSEMBLIES).unwrap();

/// The Engine API timeout of `engine_getBlobsV3` and `V2`, which bounds the whole fetch.
const EXECUTION_BLOBS_TIMEOUT: Duration = Duration::from_secs(1);

/// The cells of one block's sampled columns, assembled from partial messages, full columns and
/// the execution client.
struct Assembly {
    header: Arc<PartialDataColumnHeader>,
    /// The execution client fetch has ended, so cells still missing are requested from peers.
    local_fetch_settled: bool,
    /// The parent waits on data availability, so completed columns wait in the pending lookups,
    /// as such gossip columns do.
    parent_pending: bool,
    columns: HashMap<u64, Arc<PartialColumn>>,
}

impl Assembly {
    fn message(&self, column: &Arc<PartialColumn>) -> PartialColumnMessage {
        PartialColumnMessage {
            header: self.header.clone(),
            column: column.clone(),
            request_missing: self.local_fetch_settled,
        }
    }
}

pub struct PartialColumns {
    beacon_chain: Arc<BeaconChain>,
    cached_db: Arc<BeaconCacheDB>,
    p2p_sender: P2PSender,
    pending_items: mpsc::Sender<PendingGossipItem>,
    fetch_execution_blobs: bool,
    assemblies: Mutex<HashMap<B256, Assembly>>,
    fetched_blocks: Mutex<LruCache<B256, ()>>,
}

impl PartialColumns {
    pub fn new(
        beacon_chain: Arc<BeaconChain>,
        cached_db: Arc<BeaconCacheDB>,
        p2p_sender: P2PSender,
        pending_items: mpsc::Sender<PendingGossipItem>,
        fetch_execution_blobs: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            beacon_chain,
            cached_db,
            p2p_sender,
            pending_items,
            fetch_execution_blobs,
            assemblies: Mutex::new(HashMap::new()),
            fetched_blocks: Mutex::new(LruCache::new(FETCHED_BLOCKS)),
        })
    }

    /// Validates a partial message, merges its verified cells, and penalizes an invalid sender.
    pub async fn handle_message(
        self: &Arc<Self>,
        peer_id: PeerId,
        column_index: u64,
        block_root: B256,
        sidecar: &PartialDataColumnSidecar,
    ) {
        let timer = BEACON_PARTIAL_DATA_COLUMN_SIDECAR_GOSSIP_VERIFICATION_SECONDS.start_timer();
        let result = self
            .process_message(column_index, block_root, sidecar)
            .await;
        timer.observe_duration();
        match result {
            Ok(ValidationResult::Accept) => {}
            Ok(ValidationResult::Ignore(reason)) => {
                debug!(%block_root, column_index, "Partial data column ignored: {reason}");
            }
            Ok(ValidationResult::Reject(reason)) => {
                info!(%block_root, column_index, %peer_id, "Partial data column rejected: {reason}");
                self.p2p_sender
                    .report_invalid_partial(peer_id, column_index);
            }
            Err(err) => {
                warn!(%block_root, column_index, "Could not validate partial data column: {err:#}")
            }
        }
    }

    async fn process_message(
        self: &Arc<Self>,
        column_index: u64,
        block_root: B256,
        sidecar: &PartialDataColumnSidecar,
    ) -> anyhow::Result<ValidationResult> {
        if let Some(reason) = check_partial_structure(sidecar) {
            return Ok(ValidationResult::Reject(reason));
        }
        let current_time_ms = current_time_ms();
        let header = match (sidecar.header.first(), self.header(&block_root)) {
            (Some(received), Some(validated)) => {
                if *received != *validated {
                    return Ok(ValidationResult::Reject(
                        "Header differs from the validated header of its block".to_string(),
                    ));
                }
                validated
            }
            (Some(received), None) => {
                let parent_pending = match validate_partial_data_column_header(
                    received,
                    block_root,
                    &self.beacon_chain,
                    &self.cached_db,
                    current_time_ms,
                )
                .await?
                {
                    DependencyValidationResult::Accept => false,
                    DependencyValidationResult::ParentPendingAvailability { .. } => true,
                    DependencyValidationResult::Reject(reason) => {
                        return Ok(ValidationResult::Reject(reason));
                    }
                    DependencyValidationResult::Ignore(reason) => {
                        return Ok(ValidationResult::Ignore(reason));
                    }
                    DependencyValidationResult::UnknownParent { .. } => {
                        unreachable!("partial header validation cannot return unknown-parent")
                    }
                };
                self.on_validated_header(Arc::new(received.clone()), parent_pending)
                    .await;
                let Some(header) = self.header(&block_root) else {
                    return Ok(ValidationResult::Ignore(
                        "Block is no longer assembled".to_string(),
                    ));
                };
                header
            }
            (None, Some(validated)) => validated,
            (None, None) => {
                return Ok(ValidationResult::Ignore(
                    "Valid corresponding header has not been seen".to_string(),
                ));
            }
        };
        let cell_count = sidecar.cells_present_bitmap.num_set_bits();
        if cell_count == 0 {
            return Ok(ValidationResult::Accept);
        }
        if let Some(reason) = check_slot(&header, &self.beacon_chain, current_time_ms)? {
            return Ok(ValidationResult::Ignore(reason));
        }
        if sidecar.cells_present_bitmap.len() != header.kzg_commitments.len() {
            return Ok(ValidationResult::Reject(
                "Bitmap length does not match commitments length".to_string(),
            ));
        }
        BEACON_PARTIAL_MESSAGE_CELLS_RECEIVED_TOTAL
            .with_label_values(&[&column_index.to_string()])
            .inc_by(cell_count as u64);
        if self
            .beacon_chain
            .db()
            .column_sidecars_provider()
            .contains(&ColumnIdentifier::new(block_root, column_index))?
        {
            return Ok(ValidationResult::Ignore(
                "Data column sidecar is already stored".to_string(),
            ));
        }
        let Some(column) = self.column(&block_root, column_index) else {
            return Ok(ValidationResult::Ignore(
                "Column is not sampled".to_string(),
            ));
        };
        let new_cells = match column.new_cells(sidecar) {
            Ok(new_cells) => new_cells,
            Err(err) => return Ok(ValidationResult::Reject(err.to_string())),
        };
        if new_cells.is_empty() {
            return Ok(ValidationResult::Accept);
        }
        if !verify_partial_cells(column_index, &header, &new_cells) {
            return Ok(ValidationResult::Reject(
                "Invalid KZG proofs for partial data column cells".to_string(),
            ));
        }
        if let Some((message, completed)) = self.merge_cells(
            &block_root,
            column_index,
            new_cells,
            ColumnSource::PartialMessages,
        ) {
            if let Some(sidecar) = completed {
                self.import_and_publish(block_root, vec![sidecar], ColumnSource::PartialMessages)
                    .await;
            }
            self.p2p_sender.publish_partial_columns(vec![message]);
        }
        Ok(ValidationResult::Accept)
    }

    /// Starts assembling the columns of a gossip block that passed validation.
    pub fn on_block(self: &Arc<Self>, signed_block: &SignedBeaconBlock) {
        if signed_block.message.body.blob_kzg_commitments.is_empty() {
            return;
        }
        let header = match PartialDataColumnHeader::from_block(signed_block) {
            Ok(header) => Arc::new(header),
            Err(err) => {
                warn!("Cannot build the partial column header of a gossip block: {err:#}");
                return;
            }
        };
        let this = self.clone();
        tokio::spawn(async move { this.on_validated_header(header, false).await });
    }

    /// Marks columns obtained whole as complete and advertises them. Returns how many were not
    /// complete yet.
    pub async fn on_full_columns(self: &Arc<Self>, columns: &[DataColumnSidecar]) -> usize {
        let Some(first) = columns.first() else {
            return 0;
        };
        let header = Arc::new(PartialDataColumnHeader::from_sidecar(first));
        let block_root = header.block_root();
        self.on_validated_header(header, false).await;
        let messages = {
            let mut assemblies = self.assemblies.lock();
            let Some(assembly) = assemblies.get_mut(&block_root) else {
                return 0;
            };
            let mut completed = Vec::new();
            for sidecar in columns {
                let Some(column) = assembly.columns.get_mut(&sidecar.index) else {
                    continue;
                };
                if column.is_complete() {
                    continue;
                }
                *column = Arc::new(PartialColumn::from_sidecar(sidecar));
                completed.push(column.clone());
            }
            completed
                .iter()
                .map(|column| assembly.message(column))
                .collect::<Vec<_>>()
        };
        let newly_complete = messages.len();
        self.p2p_sender.publish_partial_columns(messages);
        newly_complete
    }

    /// Counts a full gossip column that partial messages had not completed, and advertises it.
    pub async fn on_gossip_column(self: &Arc<Self>, sidecar: &DataColumnSidecar) {
        if self.on_full_columns(std::slice::from_ref(sidecar)).await > 0 {
            BEACON_USEFUL_FULL_COLUMNS_RECEIVED_TOTAL
                .with_label_values(&[&sidecar.index.to_string()])
                .inc();
        }
    }

    /// Starts assembling a block whose header passed validation, and fetches its blobs from the
    /// execution client once. A full column or block proves the parent is no longer pending.
    async fn on_validated_header(
        self: &Arc<Self>,
        header: Arc<PartialDataColumnHeader>,
        parent_pending: bool,
    ) {
        let block_root = header.block_root();
        if let Some(assembly) = self.assemblies.lock().get_mut(&block_root) {
            assembly.parent_pending &= parent_pending;
            return;
        }
        let sampling = self.beacon_chain.sampling_columns().await;
        let blob_count = header.kzg_commitments.len();
        let fetch = {
            let mut assemblies = self.assemblies.lock();
            if let Some(assembly) = assemblies.get_mut(&block_root) {
                assembly.parent_pending &= parent_pending;
                return;
            }
            let fetched = self.fetched_blocks.lock().put(block_root, ()).is_some();
            evict_oldest(&mut assemblies);
            assemblies.insert(
                block_root,
                Assembly {
                    header: header.clone(),
                    local_fetch_settled: false,
                    parent_pending,
                    columns: sampling
                        .into_iter()
                        .map(|index| (index, Arc::new(PartialColumn::empty(index, blob_count))))
                        .collect(),
                },
            );
            !fetched
        };
        if fetch {
            let this = self.clone();
            tokio::spawn(async move { this.fetch_local_cells(block_root, header).await });
        } else {
            self.settle_local_fetch(block_root);
        }
    }

    /// Takes the cells the execution client holds, then requests the missing ones from peers.
    async fn fetch_local_cells(
        self: Arc<Self>,
        block_root: B256,
        header: Arc<PartialDataColumnHeader>,
    ) {
        if self.fetch_execution_blobs {
            match tokio::time::timeout(
                EXECUTION_BLOBS_TIMEOUT,
                self.beacon_chain.fetch_blobs_from_execution(&header),
            )
            .await
            {
                Ok(Ok(Some(blobs))) => {
                    if let Err(err) = self.merge_execution_blobs(block_root, blobs).await {
                        warn!(%block_root, "Failed to build cells from execution blobs: {err:#}");
                    }
                }
                Ok(Ok(None)) => {}
                Ok(Err(err)) => {
                    warn!(%block_root, "Failed to fetch blobs from the execution client: {err:#}");
                }
                Err(_) => {
                    warn!(%block_root, "Fetching blobs from the execution client timed out");
                }
            }
        }
        self.settle_local_fetch(block_root);
    }

    /// Requests the cells still missing from peers.
    fn settle_local_fetch(&self, block_root: B256) {
        let messages = {
            let mut assemblies = self.assemblies.lock();
            let Some(assembly) = assemblies.get_mut(&block_root) else {
                return;
            };
            assembly.local_fetch_settled = true;
            assembly
                .columns
                .values()
                .map(|column| assembly.message(column))
                .collect()
        };
        self.p2p_sender.publish_partial_columns(messages);
    }

    async fn merge_execution_blobs(
        self: &Arc<Self>,
        block_root: B256,
        blobs: Vec<Option<BlobAndProofV2>>,
    ) -> anyhow::Result<()> {
        let Some(columns) = self
            .assemblies
            .lock()
            .get(&block_root)
            .map(|assembly| assembly.columns.keys().copied().collect::<Vec<u64>>())
        else {
            return Ok(());
        };
        let built = tokio::task::spawn_blocking(move || {
            partial_columns_from_execution_blobs(blobs, &columns)
        })
        .await??;
        let mut completed = Vec::new();
        for column in built {
            let cells = column
                .cells
                .into_iter()
                .enumerate()
                .filter_map(|(blob_index, cell)| {
                    cell.map(|(cell, proof)| (blob_index, cell, proof))
                })
                .collect::<Vec<_>>();
            if let Some((_, Some(sidecar))) = self.merge_cells(
                &block_root,
                column.index,
                cells,
                ColumnSource::ExecutionLayer,
            ) {
                completed.push(sidecar);
            }
        }
        self.import_and_publish(block_root, completed, ColumnSource::ExecutionLayer)
            .await;
        Ok(())
    }

    /// Adds verified or locally built cells to a column. Returns its advertisement and, if they
    /// completed it, the full sidecar; none when no cell was new.
    fn merge_cells(
        &self,
        block_root: &B256,
        column_index: u64,
        cells: Vec<(usize, Cell, KZGProof)>,
        source: ColumnSource,
    ) -> Option<(PartialColumnMessage, Option<DataColumnSidecar>)> {
        let mut assemblies = self.assemblies.lock();
        let assembly = assemblies.get_mut(block_root)?;
        let column = assembly.columns.get_mut(&column_index)?;
        let mut merged = (**column).clone();
        let added = merged.insert_cells(cells);
        if added == 0 {
            return None;
        }
        let completed = merged.to_full_sidecar(&assembly.header);
        if source == ColumnSource::PartialMessages {
            let label = column_index.to_string();
            BEACON_PARTIAL_MESSAGE_USEFUL_CELLS_TOTAL
                .with_label_values(&[&label])
                .inc_by(added as u64);
            if completed.is_some() {
                BEACON_PARTIAL_MESSAGE_COLUMN_COMPLETIONS_TOTAL
                    .with_label_values(&[&label])
                    .inc();
            }
        }
        *column = Arc::new(merged);
        let column = column.clone();
        Some((assembly.message(&column), completed))
    }

    /// Imports completed columns not held yet, and publishes them to peers that take full
    /// columns.
    async fn import_and_publish(
        &self,
        block_root: B256,
        columns: Vec<DataColumnSidecar>,
        source: ColumnSource,
    ) {
        if columns.is_empty() {
            return;
        }
        // A column assembled from gossip cells is stored like a gossip column, and waits in the
        // pending lookups like one while its parent waits on availability. Execution columns keep
        // the execution path's rule of skipping held columns and imported blocks.
        let imported = if source == ColumnSource::ExecutionLayer {
            self.beacon_chain
                .import_missing_columns(block_root, columns)
                .await
        } else if self.parent_pending(&block_root) {
            for column in columns.iter().cloned() {
                let item = PendingGossipItem::Column {
                    column: GossipValidatedDataColumn::new(column),
                };
                if !try_forward(&self.pending_items, item) {
                    debug!(%block_root, "Pending gossip item queue is full, dropping a column");
                    BEACON_GOSSIP_PENDING_ITEMS_DROPPED_TOTAL.inc();
                }
            }
            Ok(columns)
        } else {
            self.beacon_chain
                .import_data_column_sidecars_if(columns.clone(), |_| Ok(()))
                .await
                .map(|()| columns)
        };
        let imported = match imported {
            Ok(imported) if imported.is_empty() => return,
            Ok(imported) => imported,
            Err(err) => {
                warn!(%block_root, "Failed to import columns assembled from cells: {err:#}");
                return;
            }
        };
        if source == ColumnSource::ExecutionLayer {
            BEACON_DATA_COLUMNS_FROM_EL_IMPORTED_TOTAL.inc_by(imported.len() as u64);
            publish_execution_columns(
                imported,
                &self.beacon_chain,
                &self.cached_db,
                &self.p2p_sender,
            )
            .await;
            return;
        }
        let db = self.beacon_chain.db();
        if let Ok(genesis_time) = db.genesis_time_provider().get() {
            log_columns_received(
                genesis_time,
                imported[0].signed_block_header.message.slot,
                imported.iter().map(|column| column.index),
                source,
                None,
            );
        }
        match db.finalized_checkpoint_provider().get() {
            Ok(checkpoint) => {
                publish_reconstructed_columns(
                    imported,
                    compute_start_slot_at_epoch(checkpoint.epoch),
                    &self.cached_db,
                    &self.p2p_sender,
                )
                .await;
            }
            Err(err) => warn!(%block_root, "Cannot publish assembled columns: {err}"),
        }
    }

    fn parent_pending(&self, block_root: &B256) -> bool {
        self.assemblies
            .lock()
            .get(block_root)
            .is_some_and(|assembly| assembly.parent_pending)
    }

    fn header(&self, block_root: &B256) -> Option<Arc<PartialDataColumnHeader>> {
        self.assemblies
            .lock()
            .get(block_root)
            .map(|assembly| assembly.header.clone())
    }

    fn column(&self, block_root: &B256, column_index: u64) -> Option<Arc<PartialColumn>> {
        self.assemblies
            .lock()
            .get(block_root)?
            .columns
            .get(&column_index)
            .cloned()
    }
}

/// Makes room for one more assembly by dropping the one of the lowest slot.
fn evict_oldest(assemblies: &mut HashMap<B256, Assembly>) {
    if assemblies.len() < MAX_ASSEMBLIES {
        return;
    }
    if let Some(oldest) = assemblies
        .iter()
        .min_by_key(|(_, assembly)| assembly.header.signed_block_header.message.slot)
        .map(|(root, _)| *root)
    {
        assemblies.remove(&oldest);
    }
}

fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use ream_consensus_beacon::matrix_entry::{compute_cells_and_kzg_proofs, das_context};
    use ream_consensus_misc::{
        beacon_block_header::SignedBeaconBlockHeader,
        polynomial_commitments::kzg_commitment::KZGCommitment,
    };
    use ream_execution_engine::ExecutionEngine;
    use ream_execution_rpc_types::get_blobs::Blob;
    use ream_network_spec::networks::{beacon_network_spec, initialize_test_network_spec};
    use ream_operation_pool::OperationPool;
    use ream_storage::db::ReamDB;
    use ream_sync_committee_pool::SyncCommitteePool;
    use ssz_types::VariableList;
    use tempfile::TempDir;
    use tokio::sync::mpsc;

    use super::*;

    const COLUMN: u64 = 5;

    struct Node {
        _data_dir: TempDir,
        partial_columns: Arc<PartialColumns>,
        pending_items: mpsc::Receiver<PendingGossipItem>,
        header: PartialDataColumnHeader,
        cell: Cell,
        proof: KZGProof,
    }

    /// A node sampling `COLUMN`, assembling a one-blob block at slot 1.
    async fn assembling_node(
        parent_pending: bool,
        execution_engine: Option<ExecutionEngine>,
    ) -> Node {
        initialize_test_network_spec();
        let data_dir = tempfile::tempdir().unwrap();
        let db = ReamDB::new(data_dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        db.genesis_time_provider().insert(0).unwrap();
        db.finalized_checkpoint_provider()
            .insert(Default::default())
            .unwrap();
        let fetch_execution_blobs = execution_engine.is_some();
        let beacon_chain = Arc::new(BeaconChain::new(
            db,
            Arc::new(OperationPool::default()),
            Arc::new(SyncCommitteePool::default()),
            execution_engine,
            None,
        ));
        beacon_chain.set_sampling_columns([COLUMN]).await;
        let (sender, _receiver) = mpsc::unbounded_channel();
        let (pending_sender, pending_items) = mpsc::channel(4);
        let partial_columns = PartialColumns::new(
            beacon_chain,
            Arc::new(BeaconCacheDB::default()),
            P2PSender(sender),
            pending_sender,
            fetch_execution_blobs,
        );

        let blob = Blob::default();
        let commitment = KZGCommitment(
            das_context()
                .blob_to_kzg_commitment(&blob.to_fixed_bytes())
                .unwrap(),
        );
        let (cells, proofs) = compute_cells_and_kzg_proofs(&blob, das_context()).unwrap();
        let mut signed_block_header = SignedBeaconBlockHeader::default();
        signed_block_header.message.slot = 1;
        let header = PartialDataColumnHeader {
            kzg_commitments: VariableList::new(vec![commitment]).unwrap(),
            signed_block_header,
            kzg_commitments_inclusion_proof: Default::default(),
        };
        partial_columns
            .on_validated_header(Arc::new(header.clone()), parent_pending)
            .await;
        let index = COLUMN as usize;
        Node {
            _data_dir: data_dir,
            partial_columns,
            pending_items,
            header,
            cell: cells[index].clone(),
            proof: proofs[index],
        }
    }

    fn message(cell: Cell, proof: KZGProof) -> PartialDataColumnSidecar {
        let mut column = PartialColumn::empty(COLUMN, 1);
        column.insert_cells(vec![(0, cell, proof)]);
        column.to_sidecar(None, None)
    }

    #[tokio::test]
    async fn a_cell_with_a_bad_proof_is_rejected_and_a_valid_one_completes_the_column() {
        let Node {
            _data_dir,
            partial_columns,
            header,
            cell,
            proof,
            ..
        } = assembling_node(false, None).await;
        let block_root = header.block_root();
        let mut bad_proof = proof;
        bad_proof[0] ^= 1;

        let rejected = partial_columns
            .process_message(COLUMN, block_root, &message(cell.clone(), bad_proof))
            .await
            .unwrap();
        assert!(
            matches!(rejected, ValidationResult::Reject(_)),
            "{rejected:?}"
        );
        assert_eq!(
            partial_columns
                .column(&block_root, COLUMN)
                .unwrap()
                .missing_count(),
            1
        );

        let accepted = partial_columns
            .process_message(COLUMN, block_root, &message(cell, proof))
            .await
            .unwrap();
        assert_eq!(accepted, ValidationResult::Accept);
        assert!(
            partial_columns
                .beacon_chain
                .db()
                .column_sidecars_provider()
                .contains(&ColumnIdentifier::new(block_root, COLUMN))
                .unwrap()
        );
    }

    #[tokio::test]
    async fn a_header_that_differs_from_the_validated_one_is_rejected() {
        let Node {
            _data_dir,
            partial_columns,
            header,
            ..
        } = assembling_node(false, None).await;
        let mut other = header.clone();
        other.kzg_commitments_inclusion_proof[0] = B256::repeat_byte(1);
        let sidecar = PartialColumn::empty(COLUMN, 1).to_sidecar(None, Some(&other));

        let result = partial_columns
            .process_message(COLUMN, header.block_root(), &sidecar)
            .await
            .unwrap();

        assert!(matches!(result, ValidationResult::Reject(_)), "{result:?}");
    }

    #[tokio::test]
    async fn a_column_completed_while_its_parent_is_pending_waits_in_the_pending_lookups() {
        let mut node = assembling_node(true, None).await;
        let block_root = node.header.block_root();

        let result = node
            .partial_columns
            .process_message(COLUMN, block_root, &message(node.cell, node.proof))
            .await
            .unwrap();

        assert_eq!(result, ValidationResult::Accept);
        assert!(matches!(
            node.pending_items.try_recv(),
            Ok(PendingGossipItem::Column { column }) if column.sidecar().index == COLUMN
        ));
        assert!(
            !node
                .partial_columns
                .beacon_chain
                .db()
                .column_sidecars_provider()
                .contains(&ColumnIdentifier::new(block_root, COLUMN))
                .unwrap()
        );
    }

    #[tokio::test]
    async fn an_evicted_block_that_comes_back_is_not_fetched_again() {
        let node = assembling_node(false, None).await;
        let block_root = node.header.block_root();
        node.partial_columns.assemblies.lock().remove(&block_root);

        node.partial_columns
            .on_validated_header(Arc::new(node.header), false)
            .await;

        // A new fetch would settle the assembly only once its spawned task runs.
        assert!(
            node.partial_columns.assemblies.lock()[&block_root].local_fetch_settled,
            "the assembly should request its missing cells without fetching again"
        );
    }

    #[tokio::test]
    async fn an_execution_client_that_never_answers_get_blobs_times_out() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let jwt_dir = tempfile::tempdir().unwrap();
        let jwt_path = jwt_dir.path().join("jwt.hex");
        std::fs::write(&jwt_path, alloy_primitives::hex::encode([1u8; 32])).unwrap();
        let engine = ExecutionEngine::new(url.parse().unwrap(), jwt_path).unwrap();
        let node = assembling_node(false, Some(engine)).await;
        let mut header = node.header;
        header.signed_block_header.message.slot =
            compute_start_slot_at_epoch(beacon_network_spec().fulu_fork_epoch);
        let block_root = header.block_root();

        let fetch = tokio::spawn(
            node.partial_columns
                .clone()
                .fetch_local_cells(block_root, Arc::new(header)),
        );
        // Holds the connection open without answering.
        let _connection = tokio::time::timeout(EXECUTION_BLOBS_TIMEOUT, listener.accept())
            .await
            .expect("the fetch should call the execution client")
            .unwrap();

        tokio::time::timeout(EXECUTION_BLOBS_TIMEOUT * 2, fetch)
            .await
            .expect("the fetch should give up after its timeout")
            .unwrap();
    }
}
