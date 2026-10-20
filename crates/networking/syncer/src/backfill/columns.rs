//! A bounded sidecar pass over the verified block hash chain. One batch owns the frontier;
//! column groups within it download concurrently, so ahead-of-frontier payloads cannot starve it.
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};

use alloy_primitives::B256;
use anyhow::{anyhow, ensure};
use libp2p::PeerId;
use ream_consensus_beacon::{
    data_column_sidecar::{DataColumnSidecar, NUMBER_OF_COLUMNS},
    electra::beacon_block::SignedBeaconBlock,
};
use ream_fork_choice_beacon::store::get_current_slot_from_db;
use ream_metrics::{
    BEACON_BACKFILL_COLUMNS_COMMITTED_TOTAL, BEACON_BACKFILL_PEER_BANS_TOTAL,
    BEACON_BACKFILL_PENDING_BYTES, BEACON_BACKFILL_SIDECAR_FRONTIER_SLOT,
    BEACON_BACKFILL_VERIFY_SECONDS,
};
use ream_network_spec::networks::beacon_network_spec;
use ream_p2p::network::beacon::{
    channel::{P2PCallbackError, P2PCallbackResponse, P2PMessage, P2PRequest},
    network_state::NetworkState,
};
use ream_polynomial_commitments::handlers::verify_data_column_sidecars_kzg_proofs;
use ream_req_resp::{
    beacon::messages::{BeaconResponseMessage, data_column_sidecars::DataColumnsByRootIdentifier},
    error::ReqRespError,
};
use ream_storage::{
    db::{beacon::BeaconDB, beacon_backfill::CommitError},
    tables::{
        beacon::backfill::{BackfillMeta, BackfillMode},
        table::REDBTable,
    },
};
use ssz::Encode;
use tokio::{
    sync::{mpsc, watch},
    task::JoinSet,
    time::{sleep, timeout},
};
use tracing::{info, warn};
use tree_hash::TreeHash;

use super::{BAN_DURATION, PendingBytesReset, scheduler::BackfillConfig};

const MAX_BLOB_BLOCKS: usize = 4;
const MAX_BATCH_SLOTS: u64 = 32;

struct Batch {
    from: u64,
    to: u64,
    blocks: BTreeMap<B256, SignedBeaconBlock>,
    max_bytes: usize,
}

/// Slots without a block or without commitments are crossed only by walking authenticated
/// parents. A missing parent waits for block backfill; it is never treated as a skipped slot.
fn plan_batch(
    db: &BeaconDB,
    meta: &BackfillMeta,
    da_start: u64,
    budget: usize,
) -> anyhow::Result<Option<Batch>> {
    let Some(to) = meta.sidecars.frontier else {
        return Ok(None);
    };
    let floor = da_start.max(meta.blocks.frontier.oldest_block_slot);
    if to <= floor {
        return Ok(None);
    }
    let Some(mut root) = db.canonical_root_before(to)? else {
        return Ok(None);
    };
    let mut from = to;
    let mut blocks = BTreeMap::new();
    let mut max_bytes = 0usize;
    loop {
        let block = db
            .block_provider()
            .get(root)?
            .ok_or_else(|| anyhow!("Missing verified historical block {root}"))?;
        let slot = block.message.slot;
        ensure!(slot < from, "Non-descending historical ancestry");
        if slot < floor {
            from = floor;
            break;
        }
        let batch_start = floor.max(to.saturating_sub(MAX_BATCH_SLOTS));
        if slot < batch_start {
            from = batch_start;
            break;
        }
        let commitments = block.message.body.blob_kzg_commitments.len();
        if commitments > 0 {
            // SSZ: cells + commitments + proofs, fixed offsets, header and inclusion branch.
            let bytes = (commitments * (2048 + 48 + 48) + 512) * NUMBER_OF_COLUMNS as usize;
            if max_bytes + bytes > budget || blocks.len() == MAX_BLOB_BLOCKS {
                ensure!(
                    !blocks.is_empty(),
                    "Column byte budget cannot fit one blob block"
                );
                break;
            }
            max_bytes += bytes;
        }
        from = slot;
        let parent = block.message.parent_root;
        if commitments > 0 {
            blocks.insert(root, block);
        }
        if from == floor || to - from >= MAX_BATCH_SLOTS {
            break;
        }
        root = parent;
    }
    Ok(Some(Batch {
        from,
        to,
        blocks,
        max_bytes,
    }))
}

pub(super) struct ColumnBackfill {
    pub db: BeaconDB,
    pub sender: mpsc::UnboundedSender<P2PMessage>,
    pub network: Arc<NetworkState>,
    pub config: BackfillConfig,
    pub rate_limit: bool,
}

impl ColumnBackfill {
    pub async fn run(self, mut running: watch::Receiver<bool>) {
        let mut banned = HashMap::new();
        let mut requests = HashMap::<PeerId, u64>::new();
        let mut last_log = Instant::now();
        loop {
            if !*running.borrow_and_update() {
                if running.changed().await.is_err() {
                    return;
                }
                continue;
            }
            if let Ok(BackfillMode::Checkpoint(meta)) = self.db.cached_backfill_mode()
                && let Ok(slot) = get_current_slot_from_db(&self.db)
                && meta.sidecars.frontier.is_some_and(|frontier| {
                    frontier
                        <= beacon_network_spec().data_column_retention_start_slot(
                            slot / ream_consensus_misc::constants::beacon::SLOTS_PER_EPOCH,
                        )
                })
            {
                ream_metrics::BEACON_CUSTODY_GROUPS_BACKFILLED.set(NUMBER_OF_COLUMNS as i64);
                info!(frontier_slot = ?meta.sidecars.frontier, "Column backfill complete");
                return;
            }
            // Dropping the batch future drops every callback and aborts its download tasks.
            let active = running.clone();
            let result = tokio::select! {
                biased;
                changed = running.changed() => { if changed.is_err() { return; } continue; },
                result = self.step(&active, &mut banned, &mut requests) => result,
            };
            match result {
                Ok(Some(meta)) => {
                    if last_log.elapsed() >= Duration::from_secs(60) {
                        info!(frontier_slot = ?meta.sidecars.frontier, "Column backfill progress");
                        last_log = Instant::now();
                    }
                }
                Ok(None) => sleep(Duration::from_secs(1)).await,
                Err(err) => {
                    warn!(%err, "Column backfill waiting to retry");
                    sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }

    async fn step(
        &self,
        running: &watch::Receiver<bool>,
        banned: &mut HashMap<PeerId, Instant>,
        requests: &mut HashMap<PeerId, u64>,
    ) -> anyhow::Result<Option<BackfillMeta>> {
        let meta = match self.db.cached_backfill_mode()? {
            BackfillMode::Checkpoint(meta) => meta,
            _ => return Ok(None),
        };
        let epoch = get_current_slot_from_db(&self.db)?
            / ream_consensus_misc::constants::beacon::SLOTS_PER_EPOCH;
        let da_start = beacon_network_spec().data_column_retention_start_slot(epoch);
        let db = self.db.clone();
        let budget = self.config.max_pending_bytes;
        let batch =
            tokio::task::spawn_blocking(move || plan_batch(&db, &meta, da_start, budget)).await??;
        let Some(batch) = batch else {
            return Ok(None);
        };
        BEACON_BACKFILL_SIDECAR_FRONTIER_SLOT.set(batch.to as i64);
        let _pending_reset = PendingBytesReset("columns");
        BEACON_BACKFILL_PENDING_BYTES
            .with_label_values(&["columns"])
            .set(batch.max_bytes as i64);
        let mut retained = BTreeMap::new();
        if !batch.blocks.is_empty() {
            banned.retain(|_, at| at.elapsed() < BAN_DURATION);
            // All 128 columns must have an eligible peer before any payload is downloaded.
            let peers = self
                .network
                .connected_peers()
                .into_iter()
                .filter(|peer| {
                    !banned.contains_key(&peer.peer_id)
                        && peer
                            .status
                            .as_ref()
                            .is_some_and(|status| status.earliest_available_slot <= batch.from)
                })
                .collect::<Vec<_>>();
            let mut groups = BTreeMap::<PeerId, Vec<u64>>::new();
            for index in 0..NUMBER_OF_COLUMNS {
                let Some(peer) = peers
                    .iter()
                    .filter(|peer| peer.custody().custodies_column(index))
                    .min_by_key(|peer| {
                        (
                            groups.len() >= self.config.max_inflight
                                && !groups.contains_key(&peer.peer_id),
                            groups.get(&peer.peer_id).map_or(0, Vec::len),
                            requests.get(&peer.peer_id).copied().unwrap_or_default(),
                        )
                    })
                else {
                    return Ok(None);
                };
                groups.entry(peer.peer_id).or_default().push(index);
            }
            let blocks = Arc::new(batch.blocks.clone());
            let mut tasks = JoinSet::new();
            for peer in groups.keys() {
                let count = requests.entry(*peer).or_default();
                *count = count.saturating_add(1);
            }
            let mut groups = groups.into_iter();
            loop {
                while tasks.len() < self.config.max_inflight {
                    let Some((peer, columns)) = groups.next() else {
                        break;
                    };
                    let sender = self.sender.clone();
                    let blocks = blocks.clone();
                    let from = batch.from;
                    let count = batch.to - batch.from;
                    // The sum of group budgets is the batch budget, independent of concurrency.
                    let limit = batch.max_bytes * columns.len() / NUMBER_OF_COLUMNS as usize;
                    tasks.spawn(async move {
                        let response = receive_columns(
                            sender,
                            peer,
                            from..from + count,
                            columns.clone(),
                            blocks.clone(),
                            limit,
                            false,
                        )
                        .await;
                        (peer, columns, response)
                    });
                }
                let Some(response) = tasks.join_next().await else {
                    break;
                };
                let (peer, columns, response) = response?;
                match response {
                    ColumnResponse::Columns(values) => {
                        self.verify_and_keep(
                            peer,
                            values,
                            blocks.clone(),
                            running,
                            banned,
                            &mut retained,
                        )
                        .await?;
                        // Short range answers prove no skipped columns. Recover exact missing
                        // identifiers by root, preferably from another eligible custody peer.
                        for (root, block) in blocks.iter() {
                            let missing = columns
                                .iter()
                                .copied()
                                .filter(|index| !retained.contains_key(&(*root, *index)))
                                .collect::<Vec<_>>();
                            if missing.is_empty() {
                                continue;
                            }
                            let replacement = peers
                                .iter()
                                .find(|candidate| {
                                    candidate.peer_id != peer
                                        && !banned.contains_key(&candidate.peer_id)
                                        && missing.iter().all(|index| {
                                            candidate.custody().custodies_column(*index)
                                        })
                                })
                                .map(|candidate| candidate.peer_id)
                                .unwrap_or(peer);
                            if banned.contains_key(&replacement) {
                                continue;
                            }
                            let one = Arc::new(BTreeMap::from([(*root, block.clone())]));
                            let limit = (block.message.body.blob_kzg_commitments.len()
                                * (2048 + 48 + 48)
                                + 512)
                                * missing.len();
                            match receive_columns(
                                self.sender.clone(),
                                replacement,
                                batch.from..batch.from + 1,
                                missing,
                                one.clone(),
                                limit,
                                true,
                            )
                            .await
                            {
                                ColumnResponse::Columns(values) => {
                                    self.verify_and_keep(
                                        replacement,
                                        values,
                                        one,
                                        running,
                                        banned,
                                        &mut retained,
                                    )
                                    .await?;
                                }
                                ColumnResponse::Fault(reason) => {
                                    warn!(?replacement, %reason, "Invalid column by-root response");
                                    banned.insert(replacement, Instant::now());
                                    BEACON_BACKFILL_PEER_BANS_TOTAL
                                        .with_label_values(&["invalid_column"])
                                        .inc();
                                }
                                ColumnResponse::Unavailable => {}
                            }
                        }
                    }
                    ColumnResponse::Fault(reason) => {
                        warn!(?peer, %reason, "Banning peer from column backfill");
                        banned.insert(peer, Instant::now());
                        BEACON_BACKFILL_PEER_BANS_TOTAL
                            .with_label_values(&["invalid_column"])
                            .inc();
                    }
                    ColumnResponse::Unavailable => {}
                }
            }
            if retained.len() != batch.blocks.len() * NUMBER_OF_COLUMNS as usize {
                return Ok(None);
            }
        }
        if self.rate_limit {
            super::wait_for_backfill_window(&self.db, running).await?;
        }
        if !*running.borrow() || running.has_changed().is_err() {
            return Ok(None);
        }
        let db = self.db.clone();
        let running = running.clone();
        let from = batch.from;
        let to = batch.to;
        let meta = tokio::task::spawn_blocking(move || -> anyhow::Result<Option<BackfillMeta>> {
            if !*running.borrow() || running.has_changed().is_err() {
                return Ok(None);
            }
            let count = retained.len();
            db.column_sidecars_provider()
                .insert_batch(retained.into_values().collect())?;
            for _ in 0..3 {
                let BackfillMode::Checkpoint(meta) = db.cached_backfill_mode()? else {
                    return Ok(None);
                };
                if meta.sidecars.frontier != Some(to) {
                    return Ok(None);
                }
                match db.commit_sidecar_coverage(meta.revision, from) {
                    Ok(meta) => {
                        BEACON_BACKFILL_COLUMNS_COMMITTED_TOTAL.inc_by(count as u64);
                        BEACON_BACKFILL_SIDECAR_FRONTIER_SLOT.set(from as i64);
                        return Ok(Some(meta));
                    }
                    Err(CommitError::Conflict { .. }) => continue,
                    Err(err) => return Err(err.into()),
                }
            }
            Ok(None)
        })
        .await??;
        Ok(meta)
    }

    async fn verify_and_keep(
        &self,
        peer: PeerId,
        values: Vec<DataColumnSidecar>,
        blocks: Arc<BTreeMap<B256, SignedBeaconBlock>>,
        running: &watch::Receiver<bool>,
        banned: &mut HashMap<PeerId, Instant>,
        retained: &mut BTreeMap<(B256, u64), DataColumnSidecar>,
    ) -> anyhow::Result<()> {
        if self.rate_limit {
            super::wait_for_backfill_window(&self.db, running).await?;
        }
        let active = running.clone();
        let values = tokio::task::spawn_blocking(move || {
            let _verify_timer = BEACON_BACKFILL_VERIFY_SECONDS.start_timer();
            for column in &values {
                if !*active.borrow() || active.has_changed().is_err() {
                    return None;
                }
                let root = column.signed_block_header.message.tree_hash_root();
                let block = blocks.get(&root)?;
                if column.kzg_commitments != block.message.body.blob_kzg_commitments
                    || (!column.verify()
                        || column.signed_block_header != block.signed_header()
                        || !column.verify_inclusion_proof())
                {
                    return None;
                }
            }
            if !verify_data_column_sidecars_kzg_proofs(&values).unwrap_or(false) {
                return None;
            }
            Some(values)
        })
        .await?;
        match values {
            Some(values) => {
                for column in values {
                    retained.insert(
                        (
                            column.signed_block_header.message.tree_hash_root(),
                            column.index,
                        ),
                        column,
                    );
                }
            }
            None if *running.borrow() && running.has_changed().is_ok() => {
                banned.insert(peer, Instant::now());
                BEACON_BACKFILL_PEER_BANS_TOTAL
                    .with_label_values(&["invalid_column"])
                    .inc();
                warn!(?peer, "Invalid historical column proof or header");
            }
            None => {}
        }
        Ok(())
    }
}

enum ColumnResponse {
    Columns(Vec<DataColumnSidecar>),
    Fault(String),
    Unavailable,
}

async fn receive_columns(
    sender: mpsc::UnboundedSender<P2PMessage>,
    peer: PeerId,
    range: std::ops::Range<u64>,
    columns: Vec<u64>,
    blocks: Arc<BTreeMap<B256, SignedBeaconBlock>>,
    limit: usize,
    by_root: bool,
) -> ColumnResponse {
    let (callback, mut receiver) = mpsc::channel(1);
    let request = if by_root {
        let identifiers = blocks
            .keys()
            .map(|root| DataColumnsByRootIdentifier::new(*root, columns.clone()))
            .collect::<Result<Vec<_>, _>>();
        let Ok(identifiers) = identifiers else {
            return ColumnResponse::Unavailable;
        };
        P2PRequest::DataColumnIdentifiers {
            peer_id: peer,
            column_identifiers: identifiers,
            callback,
        }
    } else {
        P2PRequest::DataColumnRange {
            peer_id: peer,
            start: range.start,
            count: range.end - range.start,
            columns: columns.clone(),
            callback,
        }
    };
    if sender.send(P2PMessage::Request(request)).is_err() {
        return ColumnResponse::Unavailable;
    }
    let mut values = Vec::new();
    let mut seen = HashSet::new();
    let mut bytes = 0usize;
    let result = timeout(Duration::from_secs(60), async {
        while let Some(message) = receiver.recv().await {
            match message {
                Ok(P2PCallbackResponse::ResponseMessage(message)) => {
                    let column = match (by_root, message.as_ref()) {
                        (false, BeaconResponseMessage::DataColumnSidecarsByRange(column))
                        | (true, BeaconResponseMessage::DataColumnSidecarsByRoot(column)) => column,
                        _ => return ColumnResponse::Fault("unexpected response type".into()),
                    };
                    let root = column.signed_block_header.message.tree_hash_root();
                    let Some(block) = blocks.get(&root) else {
                        return ColumnResponse::Fault("unrequested block root".into());
                    };
                    if !columns.contains(&column.index) || !seen.insert((root, column.index)) {
                        return ColumnResponse::Fault("unrequested or duplicate column".into());
                    }
                    if !column.verify()
                        || column.kzg_commitments != block.message.body.blob_kzg_commitments
                        || column.signed_block_header != block.signed_header()
                    {
                        return ColumnResponse::Fault(
                            "column does not match verified block".into(),
                        );
                    }
                    let size = column.ssz_bytes_len();
                    if size > limit.saturating_sub(bytes) {
                        return ColumnResponse::Unavailable;
                    }
                    bytes += size;
                    values.push(column.clone());
                }
                Ok(P2PCallbackResponse::EndOfStream) => return ColumnResponse::Columns(values),
                Err(P2PCallbackError::ReqResp(ReqRespError::InvalidData(reason))) => {
                    return ColumnResponse::Fault(reason);
                }
                _ => return ColumnResponse::Unavailable,
            }
        }
        ColumnResponse::Unavailable
    })
    .await;
    result.unwrap_or(ColumnResponse::Unavailable)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use ream_consensus_beacon::{
        data_column_sidecar::get_data_column_sidecars_from_block,
        electra::beacon_block::BeaconBlock,
        matrix_entry::{compute_cells_and_kzg_proofs, das_context},
    };
    use ream_consensus_misc::polynomial_commitments::kzg_commitment::KZGCommitment;
    use ream_execution_rpc_types::get_blobs::Blob;
    use ream_network_spec::networks::initialize_test_network_spec;
    use ream_peer::{ConnectionState, Direction};
    use ream_req_resp::beacon::messages::{meta_data::GetMetaDataV3, status::Status};
    use ream_storage::{
        db::ReamDB,
        tables::{
            beacon::backfill::{
                BlockBackfillState, BlockCoverage, Frontier, Origin, SidecarCoverage,
            },
            field::REDBField,
            table::CustomTable,
        },
    };

    use super::*;

    struct Fixture {
        _dir: tempfile::TempDir,
        db: BeaconDB,
        network: Arc<NetworkState>,
        meta: BackfillMeta,
        columns: Vec<DataColumnSidecar>,
    }

    fn fixture() -> Fixture {
        initialize_test_network_spec();
        let dir = tempfile::tempdir().unwrap();
        let db = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        let base = beacon_network_spec().fulu_fork_epoch
            * ream_consensus_misc::constants::beacon::SLOTS_PER_EPOCH;
        let blob = Blob::default();
        let commitment = KZGCommitment(
            das_context()
                .blob_to_kzg_commitment(&blob.to_fixed_bytes())
                .unwrap(),
        );
        let cells = compute_cells_and_kzg_proofs(&blob, das_context()).unwrap();
        let mut parent = B256::ZERO;
        let mut blocks = Vec::new();
        let mut columns = Vec::new();
        for offset in 0..=4 {
            let mut block = SignedBeaconBlock {
                message: BeaconBlock {
                    slot: base + offset,
                    parent_root: parent,
                    ..Default::default()
                },
                signature: Default::default(),
            };
            if offset == 1 || offset == 3 {
                block
                    .message
                    .body
                    .blob_kzg_commitments
                    .push(commitment)
                    .unwrap();
                columns.extend(
                    get_data_column_sidecars_from_block(&block, vec![cells.clone()]).unwrap(),
                );
            }
            parent = block.message.tree_hash_root();
            db.block_provider().insert(parent, block.clone()).unwrap();
            blocks.push((parent, block));
        }
        db.record_finalized_canonical(parent).unwrap();
        let meta = BackfillMeta {
            revision: 0,
            origin: Origin {
                slot: base + 4,
                root: parent,
                state_root: blocks[4].1.message.state_root,
            },
            blocks: BlockCoverage {
                frontier: Frontier {
                    oldest_block_slot: base,
                    oldest_block_root: blocks[0].0,
                    oldest_block_parent: B256::ZERO,
                },
                state: BlockBackfillState::BlocksComplete,
            },
            sidecars: SidecarCoverage {
                frontier: Some(base + 4),
            },
        };
        let write = db.db.begin_write().unwrap();
        {
            let mut table = write
                .open_table(redb::TableDefinition::<&str, &[u8]>::new(
                    "beacon_bootstrap",
                ))
                .unwrap();
            table.insert("mode", &[1u8][..]).unwrap();
            table
                .insert(
                    "genesis_validators_root",
                    B256::ZERO.as_ssz_bytes().as_slice(),
                )
                .unwrap();
            table
                .insert("backfill_meta", meta.as_ssz_bytes().as_slice())
                .unwrap();
        }
        write.commit().unwrap();
        db.genesis_time_provider().insert(0).unwrap();
        db.time_provider()
            .insert((base + 4) * beacon_network_spec().seconds_per_slot())
            .unwrap();
        let key = discv5::enr::CombinedKey::generate_secp256k1();
        let enr = discv5::Enr::builder().build(&key).unwrap();
        let network = Arc::new(NetworkState {
            local_enr: enr.into(),
            peer_table: Default::default(),
            meta_data: Default::default(),
            status: Default::default(),
            data_dir: dir.path().to_path_buf(),
        });
        let peer = libp2p::identity::Keypair::generate_secp256k1()
            .public()
            .to_peer_id();
        network.upsert_peer(
            peer,
            None,
            ConnectionState::Connected,
            Direction::Outbound,
            None,
        );
        network.update_peer_meta_data(
            peer,
            GetMetaDataV3 {
                custody_group_count: 128,
                ..Default::default()
            },
        );
        network.peer_table.write().get_mut(&peer).unwrap().status = Some(Status::default());
        Fixture {
            _dir: dir,
            db,
            network,
            meta,
            columns,
        }
    }

    fn current(db: &BeaconDB) -> BackfillMeta {
        match db.backfill_mode().unwrap() {
            BackfillMode::Checkpoint(meta) => meta,
            _ => unreachable!(),
        }
    }

    async fn run_step(driver: &ColumnBackfill) -> Option<BackfillMeta> {
        let (_sender, running) = watch::channel(true);
        driver
            .step(&running, &mut HashMap::new(), &mut HashMap::new())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn missing_columns_do_not_advance_then_root_fallback_completes_all_128_columns() {
        let fixture = fixture();
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let complete = Arc::new(AtomicBool::new(false));
        let serve_complete = complete.clone();
        let columns = fixture.columns.clone();
        let server = tokio::spawn(async move {
            while let Some(P2PMessage::Request(request)) = receiver.recv().await {
                let (selected, callback, by_root) = match request {
                    P2PRequest::DataColumnRange {
                        columns: indices,
                        callback,
                        ..
                    } => (
                        columns
                            .iter()
                            .filter(|column| column.index != 127 && indices.contains(&column.index))
                            .cloned()
                            .collect::<Vec<_>>(),
                        callback,
                        false,
                    ),
                    P2PRequest::DataColumnIdentifiers {
                        column_identifiers,
                        callback,
                        ..
                    } => (
                        columns
                            .iter()
                            .filter(|column| {
                                serve_complete.load(Ordering::SeqCst)
                                    && column_identifiers.iter().any(|id| {
                                        id.block_root
                                            == column.signed_block_header.message.tree_hash_root()
                                            && id.columns.contains(&column.index)
                                    })
                            })
                            .cloned()
                            .collect(),
                        callback,
                        true,
                    ),
                    _ => panic!("unexpected request"),
                };
                for column in selected {
                    let response = if by_root {
                        BeaconResponseMessage::DataColumnSidecarsByRoot(column)
                    } else {
                        BeaconResponseMessage::DataColumnSidecarsByRange(column)
                    };
                    if callback
                        .send(Ok(P2PCallbackResponse::ResponseMessage(Arc::new(response))))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                let _ = callback.send(Ok(P2PCallbackResponse::EndOfStream)).await;
            }
        });
        // A crash may publish files before committing coverage. Existing files alone must not
        // advance the frontier; the next pass authenticates downloaded replacements.
        fixture
            .db
            .column_sidecars_provider()
            .insert_batch(vec![fixture.columns[0].clone()])
            .unwrap();
        let driver = ColumnBackfill {
            db: fixture.db.clone(),
            sender,
            network: fixture.network,
            config: BackfillConfig::default(),
            rate_limit: false,
        };
        assert!(run_step(&driver).await.is_none());
        assert_eq!(current(&fixture.db).sidecars, fixture.meta.sidecars);
        complete.store(true, Ordering::SeqCst);
        let committed = run_step(&driver).await.unwrap();
        assert_eq!(
            committed.sidecars.frontier,
            Some(fixture.meta.blocks.frontier.oldest_block_slot)
        );
        assert_eq!(
            committed.earliest_available_slot(fixture.meta.blocks.frontier.oldest_block_slot),
            fixture.meta.blocks.frontier.oldest_block_slot
        );
        for column in fixture.columns {
            let key = ream_consensus_beacon::data_column_sidecar::ColumnIdentifier::new(
                column.signed_block_header.message.tree_hash_root(),
                column.index,
            );
            assert_eq!(
                fixture.db.column_sidecars_provider().get(key).unwrap(),
                Some(column)
            );
        }
        assert!(run_step(&driver).await.is_none());
        server.abort();
    }

    #[tokio::test]
    async fn invalid_proofs_ban_only_the_supplier_and_leave_coverage_unchanged() {
        let fixture = fixture();
        let (sender, _) = mpsc::unbounded_channel();
        let driver = ColumnBackfill {
            db: fixture.db.clone(),
            sender,
            network: fixture.network.clone(),
            config: BackfillConfig::default(),
            rate_limit: false,
        };
        let peer = fixture.network.connected_peers()[0].peer_id;
        let other = PeerId::random();
        let mut banned = HashMap::new();
        let mut retained = BTreeMap::new();
        let mut column = fixture.columns[0].clone();
        column.kzg_proofs[0][0] ^= 1;
        let root = column.signed_block_header.message.tree_hash_root();
        let blocks = Arc::new(BTreeMap::from([(
            root,
            fixture.db.block_provider().get(root).unwrap().unwrap(),
        )]));
        let (_sender, active) = watch::channel(true);
        driver
            .verify_and_keep(
                peer,
                vec![column],
                blocks,
                &active,
                &mut banned,
                &mut retained,
            )
            .await
            .unwrap();
        assert!(banned.contains_key(&peer));
        assert!(!banned.contains_key(&other));
        assert!(retained.is_empty());
        assert_eq!(current(&fixture.db), fixture.meta);
    }

    #[tokio::test]
    async fn pausing_cancels_download_callbacks_without_moving_the_frontier() {
        let fixture = fixture();
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let driver = ColumnBackfill {
            db: fixture.db.clone(),
            sender,
            network: fixture.network,
            config: BackfillConfig::default(),
            rate_limit: false,
        };
        let (running, active) = watch::channel(true);
        let task = tokio::spawn(driver.run(active));
        let callback = match timeout(Duration::from_secs(10), receiver.recv())
            .await
            .unwrap()
            .unwrap()
        {
            P2PMessage::Request(P2PRequest::DataColumnRange { callback, .. }) => callback,
            _ => panic!("expected column range"),
        };
        running.send(false).unwrap();
        timeout(Duration::from_secs(5), callback.closed())
            .await
            .unwrap();
        assert_eq!(current(&fixture.db), fixture.meta);
        drop(running);
        timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
    }

    #[test]
    fn batch_planning_respects_da_boundary_and_the_byte_budget() {
        let fixture = fixture();
        let base = fixture.meta.blocks.frontier.oldest_block_slot;
        let batch = plan_batch(&fixture.db, &fixture.meta, base + 2, 128 * 1024 * 1024)
            .unwrap()
            .unwrap();
        assert_eq!(batch.from, base + 2);
        assert_eq!(batch.blocks.len(), 1);
        assert!(
            plan_batch(&fixture.db, &fixture.meta, base + 4, 128 * 1024 * 1024)
                .unwrap()
                .is_none()
        );
        assert!(plan_batch(&fixture.db, &fixture.meta, base, 1).is_err());
        let mut pending = fixture.meta.clone();
        pending.sidecars.frontier = None;
        assert!(
            plan_batch(&fixture.db, &pending, base, 128 * 1024 * 1024)
                .unwrap()
                .is_none()
        );
    }
}
