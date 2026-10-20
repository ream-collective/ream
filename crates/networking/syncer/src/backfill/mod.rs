//! Backfill of blocks below the checkpoint origin.
//!
//! Runs only while forward sync is idle. Blocks are downloaded backwards from the block
//! frontier, verified without running the state transition and committed straight to the
//! database; fork choice never sees them.
mod columns;
mod download;
pub mod scheduler;

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail};
use download::Response;
use libp2p::PeerId;
use ream_chain_beacon::historical_blocks::{
    ProposerKeys, check_range_response, check_roots_response, verify_proposer_signatures,
};
use ream_consensus_beacon::electra::beacon_block::SignedBeaconBlock;
use ream_consensus_misc::{
    constants::beacon::genesis_validators_root, misc::compute_epoch_at_slot,
};
use ream_executor::ReamExecutor;
use ream_fork_choice_beacon::store::get_current_slot_from_db;
use ream_metrics::{
    BEACON_BACKFILL_BLOCK_FRONTIER_SLOT, BEACON_BACKFILL_BLOCKS_COMMITTED_TOTAL,
    BEACON_BACKFILL_PEER_BANS_TOTAL, BEACON_BACKFILL_PENDING_BYTES, BEACON_BACKFILL_VERIFY_SECONDS,
};
use ream_network_spec::networks::beacon::beacon_network_spec;
use ream_p2p::network::beacon::{channel::P2PMessage, network_state::NetworkState};
use ream_storage::{
    db::{beacon::BeaconDB, beacon_backfill::CommitError},
    tables::{
        beacon::backfill::{BackfillMeta, BackfillMode, BlockBackfillState},
        field::REDBField,
        table::REDBTable,
    },
};
use scheduler::{BackfillConfig, Outcome, Request, RequestKind, Scheduler, Step};
use tokio::{
    sync::{mpsc, watch},
    task::JoinSet,
    time::{MissedTickBehavior, interval, sleep},
};
use tracing::{info, warn};

const TICK_INTERVAL: Duration = Duration::from_secs(1);
const PROGRESS_LOG_INTERVAL: Duration = Duration::from_secs(60);
const ERROR_RETRY_DELAY: Duration = Duration::from_secs(30);
/// How long a peer that sent a provably bad response is not asked for history again.
const BAN_DURATION: Duration = Duration::from_secs(300);
/// Bound on re-reading metadata after a revision conflict within one commit.
const MAX_COMMIT_ATTEMPTS: usize = 3;

type Download = (Request, Response);

/// Starts and pauses the backfill task. Dropping it stops the task.
pub struct BackfillHandle {
    running: watch::Sender<bool>,
}

impl BackfillHandle {
    /// Backfill runs while `running` is true and forward sync has nothing to do.
    pub fn set_running(&self, running: bool) {
        self.running.send_if_modified(|current| {
            let changed = *current != running;
            *current = running;
            changed
        });
    }
}

enum SessionEnd {
    Paused,
    Finished,
}

/// Peers this task may ask. Bans are local: they only stop backfill from asking the peer.
#[derive(Default)]
struct Peers {
    busy: HashSet<PeerId>,
    banned: HashMap<PeerId, Instant>,
    requests: HashMap<PeerId, u64>,
}

impl Peers {
    /// Reserves the least used idle peer whose advertised history reaches `lowest_slot`.
    fn pick(
        &mut self,
        network_state: &NetworkState,
        lowest_slot: u64,
        excluded: &HashSet<PeerId>,
    ) -> Option<PeerId> {
        self.banned
            .retain(|_, banned_at| banned_at.elapsed() < BAN_DURATION);
        let peer_id = network_state
            .connected_peers()
            .into_iter()
            .filter(|peer| {
                peer.status
                    .as_ref()
                    .is_some_and(|status| status.earliest_available_slot <= lowest_slot)
            })
            .map(|peer| peer.peer_id)
            .filter(|peer_id| {
                !self.busy.contains(peer_id)
                    && !self.banned.contains_key(peer_id)
                    && !excluded.contains(peer_id)
            })
            .min_by_key(|peer_id| {
                (
                    self.requests.get(peer_id).copied().unwrap_or_default(),
                    peer_id.to_bytes(),
                )
            })?;
        self.busy.insert(peer_id);
        *self.requests.entry(peer_id).or_default() += 1;
        Some(peer_id)
    }
}

pub struct BackfillSyncer {
    db: BeaconDB,
    p2p_sender: mpsc::UnboundedSender<P2PMessage>,
    network_state: Arc<NetworkState>,
    executor: ReamExecutor,
    config: BackfillConfig,
    rate_limit: bool,
}

impl BackfillSyncer {
    /// Spawns block and column backfill, initially paused. Returns `None` for databases without
    /// checkpoint history, or when both required block and column history are already covered.
    pub fn spawn(
        db: BeaconDB,
        p2p_sender: mpsc::UnboundedSender<P2PMessage>,
        network_state: Arc<NetworkState>,
        executor: ReamExecutor,
    ) -> anyhow::Result<Option<BackfillHandle>> {
        Self::spawn_with_config(
            db,
            p2p_sender,
            network_state,
            executor,
            BackfillConfig::default(),
            true,
        )
    }

    pub fn spawn_with_config(
        db: BeaconDB,
        p2p_sender: mpsc::UnboundedSender<P2PMessage>,
        network_state: Arc<NetworkState>,
        executor: ReamExecutor,
        config: BackfillConfig,
        rate_limit: bool,
    ) -> anyhow::Result<Option<BackfillHandle>> {
        config.validate()?;
        match db.cached_backfill_mode()? {
            BackfillMode::Checkpoint(meta) => {
                BEACON_BACKFILL_BLOCK_FRONTIER_SLOT
                    .set(meta.blocks.frontier.oldest_block_slot as i64);
                ream_metrics::BEACON_BACKFILL_SIDECAR_FRONTIER_SLOT
                    .set(meta.sidecars_available_from() as i64);
                let current_slot = get_current_slot_from_db(&db)?;
                let da_start = beacon_network_spec()
                    .data_column_retention_start_slot(compute_epoch_at_slot(current_slot));
                let columns_complete = meta.sidecars.frontier.is_some_and(|slot| slot <= da_start);
                ream_metrics::BEACON_CUSTODY_GROUPS_BACKFILLED.set(if columns_complete {
                    ream_consensus_beacon::data_column_sidecar::NUMBER_OF_COLUMNS as i64
                } else {
                    0
                });
                if meta.blocks.state != BlockBackfillState::InProgress && columns_complete {
                    return Ok(None);
                }
            }
            BackfillMode::GenesisSynced => return Ok(None),
            BackfillMode::Legacy => {
                warn!(
                    "Database predates backfill metadata: historical blocks will not be \
                     downloaded. Bootstrap again with --purge-db to enable backfill"
                );
                return Ok(None);
            }
        }

        let (running, running_receiver) = watch::channel(false);
        let columns = columns::ColumnBackfill {
            db: db.clone(),
            sender: p2p_sender.clone(),
            network: network_state.clone(),
            config: config.clone(),
            rate_limit,
        };
        let column_running = running_receiver.clone();
        executor.spawn(async move { columns.run(column_running).await });
        let syncer = Self {
            db,
            p2p_sender,
            network_state,
            executor: executor.clone(),
            config,
            rate_limit,
        };
        executor.spawn(async move { syncer.run(running_receiver).await });
        Ok(Some(BackfillHandle { running }))
    }

    async fn run(self, mut running: watch::Receiver<bool>) {
        let _pending_reset = PendingBytesReset("blocks");
        let mut scheduler = None;
        let mut proposer_keys = None;
        let mut peers = Peers::default();

        loop {
            if !*running.borrow_and_update() {
                if running.changed().await.is_err() {
                    return;
                }
                continue;
            }
            let result = self
                .run_session(&mut running, &mut scheduler, &mut proposer_keys, &mut peers)
                .await;
            // Session-owned downloads have been cancelled and drained before reusing peers.
            peers.busy.clear();
            match result {
                Ok(SessionEnd::Finished) => return,
                Ok(SessionEnd::Paused) => info!("Block backfill paused while forward sync runs"),
                Err(err) => {
                    warn!(%err, "Block backfill failed, retrying");
                    if let Some(scheduler) = scheduler.as_mut() {
                        scheduler.pause();
                    }
                    sleep(ERROR_RETRY_DELAY).await;
                }
            }
        }
    }

    fn meta(&self) -> anyhow::Result<BackfillMeta> {
        match self.db.cached_backfill_mode()? {
            BackfillMode::Checkpoint(meta) => Ok(meta),
            mode => bail!("Backfill metadata disappeared: {mode:?}"),
        }
    }

    /// The retention target slides with the clock, so it is never persisted.
    fn target_slot(&self) -> anyhow::Result<u64> {
        let current_slot = get_current_slot_from_db(&self.db)?;
        Ok(beacon_network_spec().backfill_target_slot(compute_epoch_at_slot(current_slot)))
    }

    /// Validator indexes are append-only, so any state at or after the origin names every
    /// historical proposer.
    async fn load_proposer_keys(&self, meta: &BackfillMeta) -> anyhow::Result<Arc<ProposerKeys>> {
        let db = self.db.clone();
        let origin_root = meta.origin.root;
        self.executor
            .spawn_blocking(move || {
                let state = match db.state_provider().get(origin_root)? {
                    Some(state) => state,
                    None => db
                        .state_provider()
                        .get(db.finalized_checkpoint_provider().get()?.root)?
                        .ok_or_else(|| {
                            anyhow!("No state to verify historical proposer signatures against")
                        })?,
                };
                Ok(Arc::new(ProposerKeys::from_state(&state)))
            })
            .await?
    }

    async fn run_session(
        &self,
        running: &mut watch::Receiver<bool>,
        scheduler: &mut Option<Scheduler>,
        proposer_keys: &mut Option<Arc<ProposerKeys>>,
        peers: &mut Peers,
    ) -> anyhow::Result<SessionEnd> {
        let mut downloads = JoinSet::new();
        let result = self
            .drive_session(running, scheduler, proposer_keys, peers, &mut downloads)
            .await;
        downloads.shutdown().await;
        result
    }

    async fn drive_session(
        &self,
        running: &mut watch::Receiver<bool>,
        scheduler: &mut Option<Scheduler>,
        proposer_keys: &mut Option<Arc<ProposerKeys>>,
        peers: &mut Peers,
        downloads: &mut JoinSet<Download>,
    ) -> anyhow::Result<SessionEnd> {
        let meta = self.meta()?;
        if meta.blocks.state != BlockBackfillState::InProgress {
            return Ok(SessionEnd::Finished);
        }
        let proposer_keys = match proposer_keys {
            Some(proposer_keys) => proposer_keys.clone(),
            None => proposer_keys
                .insert(self.load_proposer_keys(&meta).await?)
                .clone(),
        };
        let scheduler = scheduler.get_or_insert_with(|| {
            Scheduler::new(
                self.config.clone(),
                meta.blocks.frontier.clone(),
                beacon_network_spec().oldest_supported_block_slot(),
            )
        });
        if scheduler.frontier() != &meta.blocks.frontier {
            scheduler.reset(meta.blocks.frontier.clone());
        }

        let mut target_slot = self.target_slot()?;
        info!(
            frontier_slot = meta.blocks.frontier.oldest_block_slot,
            target_slot, "Block backfill running"
        );
        let mut tick = interval(TICK_INTERVAL);
        tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut last_progress_log = Instant::now();

        loop {
            // Also check after blocking verification/commit, before doing any more work.
            if running.has_changed().is_err() {
                return Ok(SessionEnd::Finished);
            }
            if !*running.borrow_and_update() {
                scheduler.pause();
                return Ok(SessionEnd::Paused);
            }
            loop {
                if !*running.borrow() {
                    break;
                }
                match scheduler.advance(target_slot) {
                    Step::Commit(blocks) => {
                        if self.rate_limit {
                            wait_for_backfill_window(&self.db, running).await?;
                        }
                        if !*running.borrow() {
                            break;
                        }
                        match self.commit(blocks, target_slot).await? {
                            Some(meta) => {
                                scheduler.on_committed(meta.blocks.frontier.clone());
                                if meta.blocks.state != BlockBackfillState::InProgress {
                                    info!(
                                        frontier_slot = meta.blocks.frontier.oldest_block_slot,
                                        "Block backfill complete"
                                    );
                                    return Ok(SessionEnd::Finished);
                                }
                            }
                            None => {
                                warn!("Historical blocks no longer connect to the frontier");
                                scheduler.reset(self.meta()?.blocks.frontier);
                            }
                        }
                    }
                    Step::Complete => {
                        self.finish(BlockBackfillState::BlocksComplete).await?;
                        info!(
                            frontier_slot = scheduler.frontier().oldest_block_slot,
                            "Block backfill complete"
                        );
                        return Ok(SessionEnd::Finished);
                    }
                    Step::UnsupportedForkBoundary { boundary_slot } => {
                        self.finish(BlockBackfillState::UnsupportedForkBoundary { boundary_slot })
                            .await?;
                        warn!(
                            frontier_slot = scheduler.frontier().oldest_block_slot,
                            boundary_slot,
                            "Block backfill stopped: older blocks belong to an unsupported fork"
                        );
                        return Ok(SessionEnd::Finished);
                    }
                    Step::Wait => break,
                }
            }
            BEACON_BACKFILL_BLOCK_FRONTIER_SLOT.set(scheduler.frontier().oldest_block_slot as i64);
            BEACON_BACKFILL_PENDING_BYTES
                .with_label_values(&["blocks"])
                .set(scheduler.pending_bytes() as i64);
            for (peer_id, reason) in scheduler.take_bans() {
                BEACON_BACKFILL_PEER_BANS_TOTAL
                    .with_label_values(&["invalid_block"])
                    .inc();
                warn!(%peer_id, reason, "Not asking peer for history again for a while");
                peers.banned.insert(peer_id, Instant::now());
            }

            if !*running.borrow() {
                continue;
            }
            let requests = scheduler.next_requests_with_downloads(
                Instant::now(),
                target_slot,
                downloads.len(),
                &mut |slot, excluded| peers.pick(&self.network_state, slot, excluded),
            );
            for request in requests {
                let sender = self.p2p_sender.clone();
                let limit = match request.kind {
                    RequestKind::Range { .. } => self.config.max_response_bytes,
                    RequestKind::Parent { .. } => self.config.frontier_reserve_bytes,
                };
                downloads.spawn(async move {
                    let response = download::receive(&request, sender, limit).await;
                    (request, response)
                });
            }

            tokio::select! {
                biased;
                changed = running.changed() => {
                    if changed.is_err() {
                        return Ok(SessionEnd::Finished);
                    }
                    if !*running.borrow_and_update() {
                        scheduler.pause();
                        return Ok(SessionEnd::Paused);
                    }
                }
                Some(result) = downloads.join_next() => {
                    let (request, download) = result?;
                    peers.busy.remove(&request.peer_id);
                    if !scheduler.is_current(request.id) {
                        continue;
                    }
                    let outcome = self
                        .check(request.kind.clone(), download, proposer_keys.clone(), running.clone())
                        .await?;
                    // A pause during verification must not attribute a late failure to a peer.
                    if !*running.borrow() || running.has_changed().is_err() {
                        continue;
                    }
                    scheduler.on_result(request.id, request.peer_id, outcome, Instant::now());
                }
                _ = tick.tick() => {
                    target_slot = self.target_slot()?;
                    if last_progress_log.elapsed() >= PROGRESS_LOG_INTERVAL {
                        last_progress_log = Instant::now();
                        info!(
                            frontier_slot = scheduler.frontier().oldest_block_slot,
                            target_slot,
                            pending_bytes = scheduler.pending_bytes(),
                            "Block backfill progress"
                        );
                    }
                }
            }
        }
    }

    /// Checks a response against its request and verifies proposer signatures, off the async
    /// runtime.
    async fn check(
        &self,
        kind: RequestKind,
        download: Response,
        proposer_keys: Arc<ProposerKeys>,
        running: watch::Receiver<bool>,
    ) -> anyhow::Result<Outcome> {
        let blocks = match download {
            Response::Blocks(blocks) => blocks,
            Response::Fault(detail) => return Ok(Outcome::Fault(detail)),
            Response::UnsupportedFork => return Ok(Outcome::UnsupportedFork),
            Response::Unavailable => return Ok(Outcome::Unavailable),
            Response::TooLarge => return Ok(Outcome::TooLarge),
        };

        if self.rate_limit {
            wait_for_backfill_window(&self.db, &running).await?;
        }
        Ok(self
            .executor
            .spawn_blocking(move || {
                let _verify_timer = BEACON_BACKFILL_VERIFY_SECONDS.start_timer();
                let rooted = match kind {
                    RequestKind::Range { start_slot, count } => {
                        check_range_response(start_slot, count, blocks)
                    }
                    RequestKind::Parent { root } => check_roots_response(&[root], blocks),
                };
                let rooted = match rooted {
                    Ok(rooted) => rooted,
                    Err(err) => return Outcome::Fault(err.to_string()),
                };
                for block in &rooted {
                    // Blocking workers cannot be aborted once running. Stop cooperatively
                    // between signatures, keeping ownership until all payload memory is freed.
                    if !*running.borrow() || running.has_changed().is_err() {
                        return Outcome::Unavailable;
                    }
                    if let Err(err) = verify_proposer_signatures(
                        &beacon_network_spec(),
                        genesis_validators_root(),
                        &proposer_keys,
                        std::slice::from_ref(block),
                    ) {
                        return Outcome::Fault(err.to_string());
                    }
                }
                Outcome::Blocks(rooted)
            })
            .await?)
    }

    /// Commits blocks whose highest block is the parent of the frontier. A revision conflict
    /// only means other metadata moved: the same blocks are tried again against the new
    /// revision. Returns `None` if they no longer connect.
    async fn commit(
        &self,
        blocks: Vec<(alloy_primitives::B256, SignedBeaconBlock)>,
        target_slot: u64,
    ) -> anyhow::Result<Option<BackfillMeta>> {
        let db = self.db.clone();
        self.executor
            .spawn_blocking(move || {
                for _ in 0..MAX_COMMIT_ATTEMPTS {
                    let BackfillMode::Checkpoint(meta) = db.cached_backfill_mode()? else {
                        bail!("Backfill metadata disappeared");
                    };
                    match db.commit_historical_blocks(meta.revision, &blocks, target_slot) {
                        Ok(meta) => {
                            BEACON_BACKFILL_BLOCKS_COMMITTED_TOTAL.inc_by(blocks.len() as u64);
                            BEACON_BACKFILL_BLOCK_FRONTIER_SLOT
                                .set(meta.blocks.frontier.oldest_block_slot as i64);
                            return Ok(Some(meta));
                        }
                        Err(CommitError::Conflict { .. }) => continue,
                        Err(CommitError::NotConnected) => return Ok(None),
                        Err(err) => return Err(err.into()),
                    }
                }
                bail!("Backfill metadata kept changing during a commit")
            })
            .await?
    }

    async fn finish(&self, state: BlockBackfillState) -> anyhow::Result<()> {
        let db = self.db.clone();
        self.executor
            .spawn_blocking(move || {
                for _ in 0..MAX_COMMIT_ATTEMPTS {
                    let BackfillMode::Checkpoint(meta) = db.cached_backfill_mode()? else {
                        bail!("Backfill metadata disappeared");
                    };
                    match db.set_block_backfill_state(meta.revision, state.clone()) {
                        Ok(_) => return Ok(()),
                        Err(CommitError::Conflict { .. }) => continue,
                        Err(err) => return Err(err.into()),
                    }
                }
                bail!("Backfill metadata kept changing during a commit")
            })
            .await?
    }
}

/// The second half of each slot leaves the head's arrival period available for live work.
async fn wait_for_backfill_window(
    db: &BeaconDB,
    running: &watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let genesis = db.genesis_time_provider().get()?;
    let slot_ms = beacon_network_spec()
        .seconds_per_slot()
        .saturating_mul(1000);
    anyhow::ensure!(slot_ms > 0, "Invalid slot duration");
    loop {
        if !*running.borrow() || running.has_changed().is_err() {
            return Ok(());
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis();
        let elapsed = now.saturating_sub(genesis as u128 * 1000);
        let position = (elapsed % slot_ms as u128) as u64;
        if position >= slot_ms / 2 {
            return Ok(());
        }
        sleep(Duration::from_millis((slot_ms / 2 - position).min(100))).await;
    }
}

struct PendingBytesReset(&'static str);
impl Drop for PendingBytesReset {
    fn drop(&mut self) {
        BEACON_BACKFILL_PENDING_BYTES
            .with_label_values(&[self.0])
            .set(0);
    }
}
