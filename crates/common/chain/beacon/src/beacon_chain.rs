use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use alloy_primitives::B256;
use anyhow::anyhow;
use parking_lot::RwLock;
use ream_consensus_beacon::{
    attestation::Attestation,
    attester_slashing::AttesterSlashing,
    data_column_sidecar::{ColumnIdentifier, DataColumnSidecar, NUMBER_OF_COLUMNS},
    electra::{beacon_block::SignedBeaconBlock, beacon_state::BeaconState},
    matrix_entry::reconstruct_data_column_sidecars,
};
use ream_consensus_misc::{
    beacon_block_header::SignedBeaconBlockHeader, checkpoint::Checkpoint,
    constants::beacon::genesis_validators_root, misc::compute_epoch_at_slot,
};
use ream_events_beacon::{BeaconEvent, BeaconEventSender, event::chain::BlockEvent};
use ream_execution_engine::ExecutionEngine;
use ream_execution_rpc_types::forkchoice_update::ForkchoiceStateV1;
use ream_fork_choice_beacon::{
    data_availability::PendingBlock,
    handlers::{
        OnBlockOutcome, on_attestation, on_attester_slashing, on_block_attestations,
        on_block_with_root, on_gossip_attestation_with_shuffling, on_tick, process_available_block,
        shares_target_shuffling,
    },
    store::Store,
};
use ream_metrics::{
    BEACON_BLOCK_PROCESSING_SECONDS, BEACON_DATA_AVAILABILITY_RECONSTRUCTIONS_RUN_TOTAL,
    BEACON_DATA_AVAILABILITY_RECONSTRUCTIONS_SKIPPED_COMPLETE_TOTAL,
    BEACON_EXECUTION_FORKCHOICE_UPDATE_SECONDS, BEACON_STORE_LOCK_WAIT_SECONDS,
};
use ream_network_spec::networks::beacon_network_spec;
use ream_operation_pool::OperationPool;
use ream_req_resp::beacon::messages::status::Status;
use ream_storage::{
    db::beacon::BeaconDB,
    tables::{
        field::REDBField,
        table::{CustomTable, REDBTable},
    },
};
use ream_sync_committee_pool::SyncCommitteePool;
use tokio::sync::{Mutex, Semaphore, broadcast};
use tracing::{debug, warn};
use tree_hash::TreeHash;

pub const BLOCK_IMPORT_EVENT_CHANNEL_CAPACITY: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "block processing may be pending data availability rather than imported"]
pub enum BlockProcessingOutcome {
    Imported { block_root: B256 },
    PendingAvailability { block_root: B256 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockImportEvent {
    Imported {
        block_root: B256,
    },
    PendingAvailability {
        block_root: B256,
    },
    /// A pending block has enough columns to rebuild its missing required ones. The subscriber
    /// should run `reconstruct_data_columns`, which is too slow to run where the column arrived.
    ReconstructionReady {
        block_root: B256,
    },
}

#[derive(Debug, Clone)]
pub struct CachedHead {
    pub head_root: B256,
    /// Slot of the head block.
    pub head_slot: u64,
    /// Post-state of the head block. Clone the value out of the `Arc` if it must be mutated.
    pub state: Arc<BeaconState>,
    /// Wall-clock slot as tracked by the store.
    pub current_slot: u64,
    pub justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,
}

impl CachedHead {
    /// Whether two snapshots describe the same chain view. The state is not compared: it is a
    /// function of `head_root`.
    fn is_equivalent(&self, other: &Self) -> bool {
        self.head_root == other.head_root
            && self.current_slot == other.current_slot
            && self.justified_checkpoint == other.justified_checkpoint
            && self.finalized_checkpoint == other.finalized_checkpoint
    }
}

/// BeaconChain is the main struct which manages the nodes local beacon chain.
/// Checkpoint state builds that may run at once, as Prysm's `attPreStateRegenSem`.
const CHECKPOINT_STATE_REGEN_PERMITS: usize = 1;

pub struct BeaconChain {
    pub store: Mutex<Store>,
    cached_head: RwLock<Option<CachedHead>>,
    db: BeaconDB,
    operation_pool: Arc<OperationPool>,
    pub execution_engine: Option<ExecutionEngine>,
    pub event_sender: Option<broadcast::Sender<BeaconEvent>>,
    block_import_sender: broadcast::Sender<BlockImportEvent>,
    execution_forkchoice: Mutex<Option<ForkchoiceStateV1>>,
    force_data_availability_checks: bool,
    /// Blocks with a reconstruction announced and not finished, so each is announced once.
    reconstructions: parking_lot::Mutex<HashSet<B256>>,
    /// One lock per checkpoint whose state is being built outside the store lock, so attestations
    /// that need the same checkpoint wait for one build instead of each copying the state
    /// (Prysm's per-checkpoint `Multilock`).
    checkpoint_state_locks: parking_lot::Mutex<HashMap<Checkpoint, Arc<Mutex<()>>>>,
    /// Checkpoint state builds that may run at once. Each copies a state and may run epoch
    /// processing; Prysm also allows one (`attPreStateRegenSem`).
    checkpoint_state_regen: Semaphore,
}

impl BeaconChain {
    /// Creates a new instance of `BeaconChain`.
    pub fn new(
        db: BeaconDB,
        operation_pool: Arc<OperationPool>,
        sync_committee_pool: Arc<SyncCommitteePool>,
        execution_engine: Option<ExecutionEngine>,
        event_sender: Option<broadcast::Sender<BeaconEvent>>,
    ) -> Self {
        let (block_import_sender, _) = broadcast::channel(BLOCK_IMPORT_EVENT_CHANNEL_CAPACITY);

        let read_db = db.clone();
        let read_operation_pool = operation_pool.clone();
        let mut store = Store::new(db, operation_pool, Some(sync_committee_pool));
        if let Err(err) = store.enable_fork_choice_tree() {
            warn!(
                "Could not build the fork choice tree from the database, head lookups will be \
                 slow: {err:#}"
            );
        }
        let cached_head = match Self::compute_cached_head(&store, None) {
            Ok(head) => Some(head),
            Err(err) => {
                debug!("No head to cache yet: {err:#}");
                None
            }
        };

        Self {
            store: Mutex::new(store),
            cached_head: RwLock::new(cached_head),
            db: read_db,
            operation_pool: read_operation_pool,
            execution_engine,
            event_sender,
            block_import_sender,
            execution_forkchoice: Mutex::new(None),
            reconstructions: parking_lot::Mutex::new(HashSet::new()),
            checkpoint_state_locks: parking_lot::Mutex::new(HashMap::new()),
            checkpoint_state_regen: Semaphore::new(CHECKPOINT_STATE_REGEN_PERMITS),
            force_data_availability_checks: false,
        }
    }

    /// Returns the current head snapshot without touching the store lock.
    pub fn head(&self) -> anyhow::Result<CachedHead> {
        self.cached_head
            .read()
            .clone()
            .ok_or_else(|| anyhow!("Head is not available yet: no anchor block in the database"))
    }

    /// Database handle for lock-free reads. redb serves readers from consistent snapshots, so
    /// these never wait for the store lock.
    pub fn db(&self) -> &BeaconDB {
        &self.db
    }

    pub fn operation_pool(&self) -> &Arc<OperationPool> {
        &self.operation_pool
    }

    /// Enables data availability checks independently of the configured Fulu fork epoch.
    /// Intended for test networks that exercise Fulu data flow on an Electra state fixture.
    pub fn force_data_availability_checks(mut self) -> Self {
        self.force_data_availability_checks = true;
        self
    }

    /// Published after the store lock is released, so subscribers can re-enter `process_block`.
    /// Handle `Lagged` by reconciling against the database, or waiting children are stranded.
    pub fn subscribe_block_imports(&self) -> broadcast::Receiver<BlockImportEvent> {
        self.block_import_sender.subscribe()
    }

    pub async fn initialize_execution_forkchoice(&self) {
        self.update_execution_forkchoice(true).await;
    }

    pub async fn process_block(
        &self,
        signed_block: SignedBeaconBlock,
    ) -> anyhow::Result<BlockProcessingOutcome> {
        let block_root = signed_block.message.tree_hash_root();
        let block_processing_timer = BEACON_BLOCK_PROCESSING_SECONDS.start_timer();

        let started = std::time::Instant::now();
        let lock_wait_timer = BEACON_STORE_LOCK_WAIT_SECONDS.start_timer();
        let mut store = self.store.lock().await;
        lock_wait_timer.observe_duration();
        let locked = started.elapsed();

        // A block can reach this point after it was imported. Range sync stores a block's
        // columns before processing the block, and those columns can complete the same block
        // left pending by gossip. Two callers can also wait on the store lock with the same block.
        // Importing it again would repeat the state transition and announce the block twice.
        if store.db.block_provider().contains_key(block_root)?
            && store.db.state_provider().contains_key(block_root)?
        {
            block_processing_timer.stop_and_discard();
            debug!(%block_root, "Block is already imported");
            return Ok(BlockProcessingOutcome::Imported { block_root });
        }

        let network_spec = beacon_network_spec();
        let verify_data_availability = self.force_data_availability_checks
            || is_data_availability_check_required(
                compute_epoch_at_slot(signed_block.message.slot),
                store.get_current_store_epoch()?,
                network_spec.fulu_fork_epoch,
                network_spec.min_epochs_for_data_column_sidecars_requests,
            );
        let outcome = on_block_with_root(
            &mut store,
            &signed_block,
            block_root,
            &self.execution_engine,
            verify_data_availability,
        )
        .await?;
        let on_block_done = started.elapsed();

        if outcome == OnBlockOutcome::PendingAvailability {
            debug!("Block is pending data availability: root={}", block_root);
            let reconstructable = store.data_availability_checker.can_reconstruct(&block_root);
            drop(store);
            self.notify_block_pending_availability(block_root);
            if reconstructable {
                self.notify_reconstruction_ready(block_root);
            }
            return Ok(BlockProcessingOutcome::PendingAvailability { block_root });
        }

        self.process_block_attestations(&mut store, &signed_block, block_root);
        let attestations_done = started.elapsed();
        store.refresh_fork_choice();
        self.publish_cached_head(&store);
        let block_event = self.build_block_event(&store, &signed_block, block_root);
        drop(store);
        let unlocked = started.elapsed();

        self.notify_block_imported(block_root);
        self.publish_block_event(block_event);

        let forkchoice_update_timer = BEACON_EXECUTION_FORKCHOICE_UPDATE_SECONDS.start_timer();
        self.update_execution_forkchoice(true).await;
        forkchoice_update_timer.observe_duration();

        block_processing_timer.observe_duration();
        let done = started.elapsed();
        debug!(
            target: "ream::timing",
            slot = signed_block.message.slot,
            lock_wait_ms = locked.as_millis() as u64,
            on_block_ms = (on_block_done - locked).as_millis() as u64,
            attestations_ms = (attestations_done - on_block_done).as_millis() as u64,
            head_ms = (unlocked - attestations_done).as_millis() as u64,
            forkchoice_updated_ms = (done - unlocked).as_millis() as u64,
            "timing: process block"
        );
        Ok(BlockProcessingOutcome::Imported { block_root })
    }

    pub async fn process_data_column_sidecar(
        &self,
        block_root: B256,
        column_index: u64,
        slot: u64,
    ) -> anyhow::Result<()> {
        let mut store = self.store.lock().await;
        let imported =
            self.process_data_column_sidecar_locked(&mut store, block_root, column_index, slot)?;
        let reconstructable = store.data_availability_checker.can_reconstruct(&block_root);
        drop(store);

        if let Some((imported_block_root, block_event)) = imported {
            self.notify_block_imported(imported_block_root);
            self.publish_block_event(block_event);
            self.update_execution_forkchoice(true).await;
        }
        if reconstructable {
            self.notify_reconstruction_ready(block_root);
        }

        Ok(())
    }

    /// Validate eligibility before staging and again before updating fork choice.
    pub async fn import_data_column_sidecar_if<F>(
        &self,
        sidecar: DataColumnSidecar,
        validate_release: F,
    ) -> anyhow::Result<()>
    where
        F: Fn(&Store) -> anyhow::Result<()> + Send,
    {
        self.import_data_column_sidecars_if(vec![sidecar], validate_release)
            .await
    }

    pub async fn import_data_column_sidecars_if<F>(
        &self,
        columns: Vec<DataColumnSidecar>,
        validate_release: F,
    ) -> anyhow::Result<()>
    where
        F: Fn(&Store) -> anyhow::Result<()> + Send,
    {
        if columns.is_empty() {
            return Ok(());
        }
        {
            let store = self.store.lock().await;
            validate_release(&store)?;
        }
        let identifiers = columns
            .iter()
            .map(|column| {
                (
                    column.signed_block_header.message.tree_hash_root(),
                    column.index,
                    column.signed_block_header.message.slot,
                )
            })
            .collect::<Vec<_>>();
        let provider = self.db.column_sidecars_provider();
        // This task owns staging, publication, flush and rollback even if the caller is cancelled.
        tokio::task::spawn_blocking(move || provider.insert_batch(columns)).await??;
        let mut store = self.store.lock().await;
        validate_release(&store)?;
        let mut imported = Vec::new();
        let mut roots = HashSet::new();
        for (root, index, slot) in identifiers {
            roots.insert(root);
            if let Some(block) =
                self.process_data_column_sidecar_locked(&mut store, root, index, slot)?
            {
                imported.push(block);
            }
        }
        let reconstructable = roots
            .into_iter()
            .filter(|root| store.data_availability_checker.can_reconstruct(root))
            .collect::<Vec<_>>();
        drop(store);
        for (block_root, block_event) in imported {
            self.notify_block_imported(block_root);
            self.publish_block_event(block_event);
            self.update_execution_forkchoice(true).await;
        }
        for block_root in reconstructable {
            self.notify_reconstruction_ready(block_root);
        }
        Ok(())
    }

    fn process_data_column_sidecar_locked(
        &self,
        store: &mut Store,
        block_root: B256,
        column_index: u64,
        slot: u64,
    ) -> anyhow::Result<Option<(B256, Option<BeaconEvent>)>> {
        // Block with available data columns will be stored here, this is
        // a guard check to prevent processing a column for an imported block
        if store.db.block_provider().get(block_root)?.is_some() {
            return Ok(None);
        }

        store
            .data_availability_checker
            .add_column(block_root, column_index, slot);
        let Some(pending) = store.data_availability_checker.take_if_complete(block_root) else {
            return Ok(None);
        };
        Ok(Some(self.import_available_block(store, pending)?))
    }

    fn import_available_block(
        &self,
        store: &mut Store,
        pending: PendingBlock,
    ) -> anyhow::Result<(B256, Option<BeaconEvent>)> {
        let signed_block = pending.signed_block.clone();
        let block_root = signed_block.message.tree_hash_root();
        process_available_block(store, pending, block_root)?;
        self.process_block_attestations(store, &signed_block, block_root);
        store.refresh_fork_choice();
        self.publish_cached_head(store);
        let block_event = self.build_block_event(store, &signed_block, block_root);
        Ok((block_root, block_event))
    }

    /// Returns zero when the beacon block has no known execution payload.
    fn execution_block_hash(db: &BeaconDB, block_root: B256) -> B256 {
        db.block_provider()
            .get(block_root)
            .ok()
            .flatten()
            .map(|block| block.message.body.execution_payload.block_hash)
            .unwrap_or_default()
    }

    /// Translates consensus fork choice into Engine API block hashes.
    fn build_forkchoice_state(&self) -> Option<ForkchoiceStateV1> {
        self.execution_engine.as_ref()?;

        let head = self
            .head()
            .inspect_err(|err| warn!("Failed to read head for forkchoice update: {err}"))
            .ok()?;

        Some(ForkchoiceStateV1 {
            head_block_hash: Self::execution_block_hash(&self.db, head.head_root),
            safe_block_hash: Self::execution_block_hash(&self.db, head.justified_checkpoint.root),
            finalized_block_hash: Self::execution_block_hash(
                &self.db,
                head.finalized_checkpoint.root,
            ),
        })
    }

    /// Updates the execution head without rolling back an accepted consensus import on failure.
    async fn update_execution_forkchoice(&self, allow_initial_update: bool) {
        let Some(execution_engine) = self.execution_engine.as_ref() else {
            return;
        };

        // Recompute after serialization so a delayed import cannot send stale state last.
        let mut last_forkchoice = self.execution_forkchoice.lock().await;
        if last_forkchoice.is_none() && !allow_initial_update {
            return;
        }
        // The cached head is published under the store lock at the end of every writer, so it is
        // as current as anything the store lock would give us, without waiting for it.
        let Some(forkchoice_state) = self.build_forkchoice_state() else {
            return;
        };
        if last_forkchoice.as_ref() == Some(&forkchoice_state) {
            return;
        }

        match execution_engine
            .engine_forkchoice_updated_v3(forkchoice_state, None)
            .await
        {
            Ok(result) => {
                *last_forkchoice = Some(forkchoice_state);
                debug!(
                    "Forkchoice updated: execution engine reported {:?}",
                    result.payload_status.status
                );
            }
            Err(err) => warn!("Failed to update execution engine forkchoice: {err}"),
        }
    }

    fn notify_block_imported(&self, block_root: B256) {
        let _ = self
            .block_import_sender
            .send(BlockImportEvent::Imported { block_root });
    }

    fn notify_block_pending_availability(&self, block_root: B256) {
        let _ = self
            .block_import_sender
            .send(BlockImportEvent::PendingAvailability { block_root });
    }

    /// Announces a reconstruction once per block until `reconstruct_data_columns` finishes it.
    /// An announcement nobody received is not reserved, so a later column announces it again.
    fn notify_reconstruction_ready(&self, block_root: B256) {
        if self.reconstructions.lock().insert(block_root)
            && self
                .block_import_sender
                .send(BlockImportEvent::ReconstructionReady { block_root })
                .is_err()
        {
            self.reconstructions.lock().remove(&block_root);
        }
    }

    /// Pending blocks with enough columns to rebuild the rest, for a subscriber that lagged and
    /// may have missed their `ReconstructionReady`. Reservations of blocks that are no longer
    /// pending are dropped, so lost announcements do not accumulate.
    pub async fn reconstructable_pending_blocks(&self) -> Vec<B256> {
        let store = self.store.lock().await;
        let checker = &store.data_availability_checker;
        self.reconstructions
            .lock()
            .retain(|block_root| checker.pending_block(block_root).is_some());
        checker.reconstructable_block_roots()
    }

    /// Pending blocks that can be reconstructed while no reconstruction is announced or running
    /// for them, reserved for the caller to reconstruct. A reconstruction that gave up after its
    /// retries has released its reservation, so it is picked up here again.
    pub async fn reserve_unannounced_reconstructions(&self) -> Vec<B256> {
        let store = self.store.lock().await;
        let roots = store
            .data_availability_checker
            .reconstructable_block_roots();
        let mut reservations = self.reconstructions.lock();
        roots
            .into_iter()
            .filter(|block_root| reservations.insert(*block_root))
            .collect()
    }

    /// Rebuilds the missing columns of a pending block and imports them before the block.
    /// Returns the rebuilt columns it stored, which the caller must cross-seed (das-core
    /// "Reconstruction and cross-seeding").
    pub async fn reconstruct_data_columns(
        &self,
        block_root: B256,
    ) -> anyhow::Result<Vec<DataColumnSidecar>> {
        let result = self.reconstruct_data_columns_inner(block_root).await;
        self.reconstructions.lock().remove(&block_root);
        result
    }

    async fn reconstruct_data_columns_inner(
        &self,
        block_root: B256,
    ) -> anyhow::Result<Vec<DataColumnSidecar>> {
        let (header, required_columns) = {
            let store = self.store.lock().await;
            let checker = &store.data_availability_checker;
            if !checker.can_reconstruct(&block_root) {
                return Ok(Vec::new());
            }
            let Some(pending) = checker.pending_block(&block_root) else {
                return Ok(Vec::new());
            };
            (
                pending.signed_block.signed_header(),
                checker.required_columns().clone(),
            )
        };
        let provider = self.db.column_sidecars_provider();
        let expected_header = header.clone();
        let recovered = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
            let mut available = Vec::with_capacity(NUMBER_OF_COLUMNS as usize);
            for index in 0..NUMBER_OF_COLUMNS {
                if let Some(sidecar) = provider.get(ColumnIdentifier::new(block_root, index))?
                    && sidecar.signed_block_header == expected_header
                {
                    available.push(sidecar);
                }
            }
            // Gossip often delivers every column before this runs; then there is nothing to
            // rebuild.
            let stored = available
                .iter()
                .map(|sidecar| sidecar.index)
                .collect::<HashSet<_>>();
            if available.len() < (NUMBER_OF_COLUMNS / 2) as usize {
                return Ok(Vec::new());
            }
            if required_columns.is_subset(&stored) {
                BEACON_DATA_AVAILABILITY_RECONSTRUCTIONS_SKIPPED_COMPLETE_TOTAL.inc();
                return Ok(Vec::new());
            }
            BEACON_DATA_AVAILABILITY_RECONSTRUCTIONS_RUN_TOTAL.inc();
            let available = available.iter().collect::<Vec<_>>();
            Ok(reconstruct_data_column_sidecars(&available)?
                .into_iter()
                .filter(|sidecar| {
                    required_columns.contains(&sidecar.index) && !stored.contains(&sidecar.index)
                })
                .collect::<Vec<_>>())
        })
        .await??;

        let recovered_count = recovered.len();
        self.import_data_column_sidecars_if(recovered.clone(), move |store| {
            rebuilt_columns_releasable(store, block_root, &header)
        })
        .await?;
        debug!(%block_root, recovered = recovered_count, "Reconstructed data columns");
        Ok(recovered)
    }

    fn process_block_attestations(
        &self,
        store: &mut Store,
        signed_block: &SignedBeaconBlock,
        block_root: B256,
    ) {
        store
            .operation_pool
            .mark_attestations_included(&signed_block.message.body.attestations);

        for result in
            on_block_attestations(store, block_root, &signed_block.message.body.attestations)
        {
            if let Err(err) = result {
                warn!("Failed to process block attestation through fork choice: {err:?}");
            }
        }
    }

    fn build_block_event(
        &self,
        store: &Store,
        signed_block: &SignedBeaconBlock,
        block_root: B256,
    ) -> Option<BeaconEvent> {
        let finalized_checkpoint = store.db.finalized_checkpoint_provider().get().ok();
        match BlockEvent::from_block(
            signed_block,
            block_root,
            finalized_checkpoint,
            |block_root, epoch| store.get_checkpoint_block(block_root, epoch),
        ) {
            Ok(block_event) => Some(BeaconEvent::Block(block_event)),
            Err(err) => {
                warn!("Failed to build block event after importing {block_root}: {err:?}");
                None
            }
        }
    }

    fn publish_block_event(&self, block_event: Option<BeaconEvent>) {
        if let Some(block_event) = block_event {
            self.event_sender.send_event(block_event);
        }
    }

    pub async fn process_attester_slashing(
        &self,
        attester_slashing: AttesterSlashing,
    ) -> anyhow::Result<()> {
        let mut store = self.store.lock().await;
        on_attester_slashing(&mut store, attester_slashing)?;
        self.publish_cached_head(&store);
        drop(store);
        self.update_execution_forkchoice(false).await;
        Ok(())
    }

    pub async fn process_attestation(
        &self,
        attestation: Attestation,
        is_from_block: bool,
    ) -> anyhow::Result<()> {
        self.prepare_checkpoint_state(attestation.data.target).await;
        let mut store = self.store.lock().await;
        on_attestation(&mut store, attestation, is_from_block)?;
        self.publish_cached_head(&store);
        drop(store);
        self.update_execution_forkchoice(false).await;
        Ok(())
    }

    /// ``process_attestation`` for a gossip attestation whose signature gossip validation verified
    /// for `attester_index`; see ``on_gossip_attestation``.
    pub async fn process_gossip_attestation(
        &self,
        attestation: Attestation,
        attester_index: u64,
    ) -> anyhow::Result<()> {
        let target = attestation.data.target;
        let head = self.head().ok();
        let mut store = self.store.lock().await;
        // When the target checkpoint state is not in memory, read the committee from the head
        // state if it has the same shuffling, as Prysm does; otherwise build the checkpoint state
        // outside the lock. Without a cached head (no anchor block stored yet) there is no
        // shortcut, and the checkpoint state is used as before.
        let shuffling_head = head.filter(|head| {
            !self.db.checkpoint_states_provider().is_in_memory(target)
                && shares_target_shuffling(
                    &store,
                    head.state.get_current_epoch(),
                    head.head_root,
                    target,
                )
                .unwrap_or(false)
        });
        if shuffling_head.is_none() && !self.db.checkpoint_states_provider().is_in_memory(target) {
            drop(store);
            self.prepare_checkpoint_state(target).await;
            store = self.store.lock().await;
        }
        on_gossip_attestation_with_shuffling(
            &mut store,
            attestation,
            attester_index,
            shuffling_head.as_ref().map(|head| head.state.as_ref()),
        )?;
        self.publish_cached_head(&store);
        drop(store);
        self.update_execution_forkchoice(false).await;
        Ok(())
    }

    /// Builds an attestation's target checkpoint state before the store lock is taken.
    ///
    /// The fork choice handlers read the target checkpoint state under the store lock. When it is
    /// not in memory, building it means reading or replaying its block's state, checking the state
    /// root and running epoch processing: up to 15 s on an 8-vCPU mainnet node. Under the store
    /// lock that stalled block import, the slot tick and range sync for as long. Building it here,
    /// on a blocking thread, leaves the handler a lookup of the stored state. Errors are left to
    /// the handler, which looks the state up again under the lock.
    async fn prepare_checkpoint_state(&self, target: Checkpoint) {
        let checkpoint_states = self.db.checkpoint_states_provider();
        if !checkpoint_states.keeps_states() || checkpoint_states.is_in_memory(target) {
            return;
        }
        let checkpoint_lock = self
            .checkpoint_state_locks
            .lock()
            .entry(target)
            .or_default()
            .clone();
        let _checkpoint = checkpoint_lock.lock().await;
        // An attestation that waited here finds the state the first one built.
        if !checkpoint_states.is_in_memory(target) {
            self.build_checkpoint_state(target).await;
        }
        // Waiters keep their own handle; later attestations find the state in memory.
        self.checkpoint_state_locks.lock().remove(&target);
    }

    /// Builds `target`'s checkpoint state on a blocking thread and keeps it in memory.
    async fn build_checkpoint_state(&self, target: Checkpoint) {
        let Ok(_regen) = self.checkpoint_state_regen.acquire().await else {
            return;
        };
        let db = self.db.clone();
        let started = std::time::Instant::now();
        match tokio::task::spawn_blocking(move || {
            db.checkpoint_states_provider().get_shared(target)
        })
        .await
        {
            Ok(Ok(_)) => debug!(
                epoch = target.epoch,
                root = %target.root,
                elapsed_ms = started.elapsed().as_millis() as u64,
                "Prepared attestation target checkpoint state"
            ),
            Ok(Err(err)) => debug!(
                epoch = target.epoch,
                "Could not prepare checkpoint state: {err}"
            ),
            Err(err) => warn!("Checkpoint state build task failed: {err}"),
        }
    }

    pub async fn process_tick(&self, time: u64) -> anyhow::Result<()> {
        let mut store = self.store.lock().await;
        on_tick(&mut store, time)?;
        self.publish_cached_head(&store);
        drop(store);
        self.update_execution_forkchoice(false).await;
        Ok(())
    }

    pub async fn build_status_request(&self) -> anyhow::Result<Status> {
        let head = self.head()?;

        Ok(Status {
            fork_digest: beacon_network_spec().fork_digest(
                beacon_network_spec().current_epoch(),
                genesis_validators_root(),
            ),
            finalized_root: head.finalized_checkpoint.root,
            finalized_epoch: head.finalized_checkpoint.epoch,
            head_root: head.head_root,
            head_slot: head.head_slot,
            earliest_available_slot: match self.db.cached_backfill_mode()? {
                ream_storage::tables::beacon::backfill::BackfillMode::Checkpoint(meta) => meta
                    .sidecars
                    .frontier
                    .unwrap_or_else(|| meta.origin.slot.saturating_add(1))
                    .max(meta.blocks.frontier.oldest_block_slot),
                ream_storage::tables::beacon::backfill::BackfillMode::GenesisSynced => 0,
                // Historical serving policy for legacy databases remains a separate change.
                ream_storage::tables::beacon::backfill::BackfillMode::Legacy => 0,
            },
        })
    }

    /// Recomputes the head snapshot from `store` and swaps it in. Writers call this as their last
    /// step, after the store mutation is committed and while still holding the store guard, which
    /// keeps publications ordered like the mutations.
    fn publish_cached_head(&self, store: &Store) {
        let previous = self.cached_head.read().clone();
        match Self::compute_cached_head(store, previous.as_ref()) {
            Ok(head) => {
                if previous
                    .as_ref()
                    .is_none_or(|previous| !previous.is_equivalent(&head))
                {
                    *self.cached_head.write() = Some(head);
                }
            }
            Err(err) => warn!("Failed to refresh the cached head: {err:#}"),
        }
    }

    /// Reads the head from the store. The state is only reloaded when the head block changed.
    fn compute_cached_head(
        store: &Store,
        previous: Option<&CachedHead>,
    ) -> anyhow::Result<CachedHead> {
        let head_root = store.get_head()?;

        let (state, head_slot) = match previous.filter(|previous| previous.head_root == head_root) {
            Some(previous) => (previous.state.clone(), previous.head_slot),
            None => {
                let state = store
                    .db
                    .state_provider()
                    .get_shared(head_root)?
                    .ok_or_else(|| anyhow!("No beacon state found for head root: {head_root}"))?;
                let head_slot = store
                    .db
                    .block_provider()
                    .get(head_root)?
                    .ok_or_else(|| anyhow!("No beacon block found for head root: {head_root}"))?
                    .message
                    .slot;
                (state, head_slot)
            }
        };

        Ok(CachedHead {
            head_root,
            head_slot,
            state,
            current_slot: store.get_current_slot()?,
            justified_checkpoint: store.db.justified_checkpoint_provider().get()?,
            finalized_checkpoint: store.db.finalized_checkpoint_provider().get()?,
        })
    }
}

/// Check data availability only for blocks within the sidecar retention window.
/// Sidecars for blocks older than roughly 18 days may no longer be available.
pub fn is_data_availability_check_required(
    block_epoch: u64,
    current_epoch: u64,
    fulu_fork_epoch: u64,
    retention_epochs: u64,
) -> bool {
    let boundary_epoch = std::cmp::max(
        fulu_fork_epoch,
        current_epoch.saturating_sub(retention_epochs),
    );

    block_epoch >= boundary_epoch
}

/// Whether columns rebuilt for `block_root` from blocks with `header` may still be stored. The
/// block is normally still pending. Gossip or range sync can also deliver its remaining columns
/// during the rebuild and import it; its rebuilt columns are then stored and cross-seeded all the
/// same, since das-core requires exposing every reconstructed column.
fn rebuilt_columns_releasable(
    store: &Store,
    block_root: B256,
    header: &SignedBeaconBlockHeader,
) -> anyhow::Result<()> {
    let stored_header = match store.data_availability_checker.pending_block(&block_root) {
        Some(pending) => pending.signed_block.signed_header(),
        None => store
            .db
            .block_provider()
            .get(block_root)?
            .ok_or_else(|| anyhow!("block {block_root} is neither pending nor imported"))?
            .signed_header(),
    };
    anyhow::ensure!(
        &stored_header == header,
        "block {block_root} changed while its columns were rebuilt"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use ream_consensus_beacon::{
        data_column_sidecar::{get_data_column_sidecars, get_data_column_sidecars_from_block},
        electra::beacon_block::BeaconBlock,
        matrix_entry::{compute_cells_and_kzg_proofs, das_context},
    };
    use ream_consensus_misc::polynomial_commitments::kzg_commitment::KZGCommitment;
    use ream_execution_rpc_types::get_blobs::Blob;
    use ream_fork_choice_beacon::{
        data_availability::{AvailabilityEntryStatus, DataAvailabilityChecker},
        store::get_forkchoice_store,
    };
    use ream_network_spec::networks::beacon::initialize_test_network_spec;
    use ream_storage::{cache::BeaconCacheDB, db::ReamDB, tables::table::REDBTable};
    use ssz::Decode;

    use super::*;

    fn empty_block_columns(block: &SignedBeaconBlock) -> Vec<DataColumnSidecar> {
        get_data_column_sidecars(
            block.signed_header(),
            block.message.body.blob_kzg_commitments.clone(),
            Default::default(),
            Vec::new(),
        )
        .unwrap()
    }

    fn empty_block() -> SignedBeaconBlock {
        SignedBeaconBlock {
            message: Default::default(),
            signature: Default::default(),
        }
    }

    fn block_with_blob_columns(
        slot: u64,
        parent_root: B256,
        state_root: B256,
    ) -> (SignedBeaconBlock, Vec<DataColumnSidecar>) {
        let blob = Blob::default();
        let commitment = KZGCommitment(
            das_context()
                .blob_to_kzg_commitment(&blob.to_fixed_bytes())
                .expect("test blob should produce a commitment"),
        );
        let mut block = SignedBeaconBlock {
            message: BeaconBlock {
                slot,
                parent_root,
                state_root,
                ..Default::default()
            },
            signature: Default::default(),
        };
        block
            .message
            .body
            .blob_kzg_commitments
            .push(commitment)
            .expect("one commitment should fit");
        let cells_and_proofs = compute_cells_and_kzg_proofs(&blob, das_context())
            .expect("test blob should produce cells and proofs");
        let columns = get_data_column_sidecars_from_block(&block, vec![cells_and_proofs])
            .expect("test block should produce data columns");
        (block, columns)
    }

    fn test_beacon_state() -> BeaconState {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
            "../../../../testing/gossip-validation/tests/assets/sepolia/states/\
             grandparent_state_9552074.ssz_snappy",
        );
        let compressed = std::fs::read(path).expect("test beacon state should be readable");
        let bytes = snap::raw::Decoder::new()
            .decompress_vec(&compressed)
            .expect("test beacon state should decompress");
        BeaconState::from_ssz_bytes(&bytes).expect("test beacon state should decode")
    }

    /// Kept alongside the chain so the directory lives until the test ends.
    fn test_chain() -> (tempfile::TempDir, BeaconChain) {
        let data_dir = tempfile::tempdir().expect("tempdir should be created");
        let beacon_db = ReamDB::new(data_dir.path().to_path_buf())
            .expect("ReamDB should init")
            .init_beacon_db()
            .expect("beacon DB tables should init");
        let chain = BeaconChain::new(
            beacon_db,
            Arc::new(OperationPool::default()),
            Arc::new(SyncCommitteePool::default()),
            None,
            None,
        );
        (data_dir, chain)
    }

    fn test_chain_with_anchor(anchor_state: BeaconState) -> (tempfile::TempDir, BeaconChain, B256) {
        test_chain_with_anchor_and_cache(anchor_state, None)
    }

    fn test_chain_with_anchor_and_cache(
        anchor_state: BeaconState,
        cache: Option<Arc<BeaconCacheDB>>,
    ) -> (tempfile::TempDir, BeaconChain, B256) {
        initialize_test_network_spec();
        let data_dir = tempfile::tempdir().expect("tempdir should be created");
        let mut beacon_db = ReamDB::new(data_dir.path().to_path_buf())
            .expect("ReamDB should init")
            .init_beacon_db()
            .expect("beacon DB tables should init");
        if let Some(cache) = cache {
            beacon_db = beacon_db.with_cache(cache);
        }
        let anchor_block = SignedBeaconBlock {
            message: BeaconBlock {
                slot: anchor_state.slot,
                state_root: anchor_state.tree_hash_root(),
                ..Default::default()
            },
            signature: Default::default(),
        };
        let anchor_root = anchor_block.message.tree_hash_root();
        get_forkchoice_store(anchor_state, anchor_block, beacon_db.clone())
            .expect("anchor should initialize fork choice storage");
        let chain = BeaconChain::new(
            beacon_db,
            Arc::new(OperationPool::default()),
            Arc::new(SyncCommitteePool::default()),
            None,
            None,
        );
        (data_dir, chain, anchor_root)
    }

    #[tokio::test]
    async fn an_announcement_nobody_received_is_announced_again() {
        let (_data_dir, chain) = test_chain();
        let block_root = B256::repeat_byte(1);

        chain.notify_reconstruction_ready(block_root);
        assert!(chain.reconstructions.lock().is_empty());

        let mut events = chain.subscribe_block_imports();
        chain.notify_reconstruction_ready(block_root);
        assert_eq!(
            events.try_recv().unwrap(),
            BlockImportEvent::ReconstructionReady { block_root }
        );
        chain.notify_reconstruction_ready(block_root);
        assert!(events.try_recv().is_err(), "announced once until it runs");
    }

    #[tokio::test]
    async fn a_reconstruction_that_gave_up_is_reserved_again() {
        let mut state = test_beacon_state();
        let (_data_dir, chain, parent_root) = test_chain_with_anchor(state.clone());
        state.slot += 1;
        let (block, columns) =
            block_with_blob_columns(state.slot, parent_root, state.tree_hash_root());
        let root = block.message.tree_hash_root();
        chain
            .store
            .lock()
            .await
            .data_availability_checker
            .insert_pending(root, block, state);
        // An announcement nobody receives is not reserved.
        let _events = chain.subscribe_block_imports();
        chain
            .import_data_column_sidecars_if(
                columns[..(NUMBER_OF_COLUMNS / 2) as usize].to_vec(),
                |_| Ok(()),
            )
            .await
            .unwrap();

        // The announcement holds the reservation, so nothing new is reserved.
        assert!(chain.reconstructions.lock().contains(&root));
        assert!(chain.reserve_unannounced_reconstructions().await.is_empty());

        // A reconstruction that gave up releases it; the block is reserved once again.
        chain.reconstructions.lock().remove(&root);
        assert_eq!(
            chain.reserve_unannounced_reconstructions().await,
            vec![root]
        );
        assert!(chain.reserve_unannounced_reconstructions().await.is_empty());
    }

    #[tokio::test]
    async fn attestation_target_state_is_prepared_without_the_store_lock() {
        let state = test_beacon_state();
        let epoch = compute_epoch_at_slot(state.slot);
        let (_data_dir, chain, anchor_root) =
            test_chain_with_anchor_and_cache(state, Some(Arc::new(BeaconCacheDB::new())));
        let target = Checkpoint {
            epoch,
            root: anchor_root,
        };
        let checkpoint_states = chain.db.checkpoint_states_provider();
        checkpoint_states.prune_before(epoch + 1).unwrap();
        assert!(!checkpoint_states.is_in_memory(target));

        // The store lock stays held: preparing must not wait for it.
        let _store = chain.store.lock().await;
        tokio::time::timeout(
            std::time::Duration::from_secs(60),
            chain.prepare_checkpoint_state(target),
        )
        .await
        .expect("preparing a checkpoint state does not take the store lock");
        assert!(checkpoint_states.is_in_memory(target));
    }

    #[tokio::test]
    async fn a_lagged_subscriber_drops_reservations_of_blocks_no_longer_pending() {
        let (_data_dir, chain) = test_chain();
        let block_root = B256::repeat_byte(1);
        let mut events = chain.subscribe_block_imports();
        chain.notify_reconstruction_ready(block_root);
        for _ in 0..BLOCK_IMPORT_EVENT_CHANNEL_CAPACITY {
            chain.notify_block_imported(B256::ZERO);
        }
        assert!(matches!(
            events.recv().await,
            Err(broadcast::error::RecvError::Lagged(_))
        ));

        // The block left the pending set while its announcement was skipped.
        assert!(chain.reconstructable_pending_blocks().await.is_empty());
        assert!(chain.reconstructions.lock().is_empty());
        chain.notify_reconstruction_ready(block_root);
        assert!(chain.reconstructions.lock().contains(&block_root));
    }

    #[test]
    fn data_availability_boundary_tracks_fulu_and_retention_window() {
        let fulu_epoch = 10;
        let retention_epochs = 100;
        assert!(!is_data_availability_check_required(
            9,
            10,
            fulu_epoch,
            retention_epochs,
        ));
        assert!(is_data_availability_check_required(
            10,
            10,
            fulu_epoch,
            retention_epochs,
        ));

        let current_epoch = fulu_epoch + retention_epochs + 10;
        assert!(!is_data_availability_check_required(
            fulu_epoch + 9,
            current_epoch,
            fulu_epoch,
            retention_epochs,
        ));
        assert!(is_data_availability_check_required(
            fulu_epoch + 10,
            current_epoch,
            fulu_epoch,
            retention_epochs,
        ));
    }

    #[tokio::test]
    async fn reconstruction_completes_before_importing_the_block() {
        let mut state = test_beacon_state();
        let (_data_dir, chain, parent_root) = test_chain_with_anchor(state.clone());
        state.slot += 1;
        let (block, columns) =
            block_with_blob_columns(state.slot, parent_root, state.tree_hash_root());
        let root = block.message.tree_hash_root();
        let provider = chain.db.column_sidecars_provider();
        chain
            .store
            .lock()
            .await
            .data_availability_checker
            .insert_pending(root, block.clone(), state);

        let mut events = chain.subscribe_block_imports();
        chain
            .import_data_column_sidecars_if(
                columns[..(NUMBER_OF_COLUMNS / 2) as usize].to_vec(),
                |_| Ok(()),
            )
            .await
            .unwrap();
        assert_eq!(
            events.recv().await.unwrap(),
            BlockImportEvent::ReconstructionReady { block_root: root }
        );
        assert!(chain.db.block_provider().get(root).unwrap().is_none());
        assert_eq!(
            chain
                .store
                .lock()
                .await
                .data_availability_checker
                .status(&root),
            AvailabilityEntryStatus::PendingBlock
        );

        chain.reconstruct_data_columns(root).await.unwrap();
        assert!(chain.db.block_provider().get(root).unwrap().is_some());
        for index in 0..NUMBER_OF_COLUMNS {
            assert!(
                provider
                    .get(ColumnIdentifier::new(root, index))
                    .unwrap()
                    .is_some()
            );
        }
        assert_eq!(
            events.recv().await.unwrap(),
            BlockImportEvent::Imported { block_root: root }
        );
    }

    #[tokio::test]
    async fn reconstruction_returns_only_the_columns_it_rebuilt() {
        let mut state = test_beacon_state();
        let (_data_dir, chain, parent_root) = test_chain_with_anchor(state.clone());
        state.slot += 1;
        let (block, columns) =
            block_with_blob_columns(state.slot, parent_root, state.tree_hash_root());
        let root = block.message.tree_hash_root();
        chain
            .store
            .lock()
            .await
            .data_availability_checker
            .insert_pending(root, block, state);
        // One column more than half, so a received column is in the rebuilt matrix too.
        let received = (NUMBER_OF_COLUMNS / 2 + 1) as usize;
        chain
            .import_data_column_sidecars_if(columns[..received].to_vec(), |_| Ok(()))
            .await
            .unwrap();

        let rebuilt = chain.reconstruct_data_columns(root).await.unwrap();

        // The caller cross-seeds what is returned, so received columns must not be in it.
        assert_eq!(rebuilt, columns[received..].to_vec());
        assert!(chain.db.block_provider().get(root).unwrap().is_some());
        assert!(
            chain
                .reconstruct_data_columns(root)
                .await
                .unwrap()
                .is_empty(),
            "an imported block has nothing left to rebuild"
        );
    }

    #[tokio::test]
    async fn columns_stored_before_their_block_announce_no_reconstruction() {
        let (_data_dir, chain) = test_chain();
        let block = empty_block();
        let root = block.message.tree_hash_root();
        let mut events = chain.subscribe_block_imports();

        // Range sync stores every column of a block before processing the block. The checker
        // passes half of them partway through the batch, while the block is still unknown.
        chain
            .import_data_column_sidecars_if(empty_block_columns(&block), |_| Ok(()))
            .await
            .unwrap();

        assert!(matches!(
            events.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
        assert!(chain.reconstructions.lock().is_empty());
        assert_eq!(
            chain
                .store
                .lock()
                .await
                .data_availability_checker
                .status(&root),
            AvailabilityEntryStatus::ColumnsOnly
        );
    }

    fn fixture_state() -> BeaconState {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
            "../../../../testing/gossip-validation/tests/assets/sepolia/states/grandparent_state_9552074.ssz_snappy",
        );
        let bytes = snap::raw::Decoder::new()
            .decompress_vec(&std::fs::read(path).unwrap())
            .unwrap();
        <BeaconState as ssz::Decode>::from_ssz_bytes(&bytes).unwrap()
    }

    #[tokio::test]
    async fn rebuilt_columns_of_a_block_imported_during_the_rebuild_are_kept() {
        let (_data_dir, chain) = test_chain();
        let block = empty_block();
        let root = block.message.tree_hash_root();
        let header = block.signed_header();
        let mut other_block = empty_block();
        other_block.message.slot = 1;

        let store = chain.store.lock().await;
        assert!(rebuilt_columns_releasable(&store, root, &header).is_err());

        store
            .db
            .block_provider()
            .insert(root, block.clone())
            .unwrap();
        assert!(rebuilt_columns_releasable(&store, root, &header).is_ok());
        assert!(rebuilt_columns_releasable(&store, root, &other_block.signed_header()).is_err());
    }

    #[tokio::test]
    async fn already_imported_block_is_not_imported_again() {
        let (_data_dir, mut chain) = test_chain();
        let (event_sender, mut beacon_events) = broadcast::channel(16);
        chain.event_sender = Some(event_sender);
        let block = empty_block();
        let root = block.message.tree_hash_root();
        chain
            .db
            .block_provider()
            .insert(root, block.clone())
            .unwrap();
        chain
            .db
            .state_provider()
            .insert(root, fixture_state())
            .unwrap();
        let mut import_events = chain.subscribe_block_imports();

        // The parent state is not stored, so importing the block again would fail.
        assert_eq!(
            chain.process_block(block).await.unwrap(),
            BlockProcessingOutcome::Imported { block_root: root }
        );
        assert!(matches!(
            import_events.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
        assert!(matches!(
            beacon_events.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn late_column_is_stored_after_block_import() {
        let (_data_dir, chain) = test_chain();
        let block = empty_block();
        let root = block.message.tree_hash_root();
        chain
            .db
            .block_provider()
            .insert(root, block.clone())
            .unwrap();
        let sidecar = empty_block_columns(&block).remove(0);

        chain
            .import_data_column_sidecar_if(sidecar.clone(), |_| Ok(()))
            .await
            .unwrap();

        assert_eq!(
            chain
                .db
                .column_sidecars_provider()
                .get(ColumnIdentifier::new(root, sidecar.index))
                .unwrap(),
            Some(sidecar)
        );
    }

    #[tokio::test]
    async fn reconstruction_stores_only_required_custody_columns() {
        let mut state = test_beacon_state();
        let (_data_dir, chain, parent_root) = test_chain_with_anchor(state.clone());
        chain.store.lock().await.data_availability_checker =
            DataAvailabilityChecker::new((0..NUMBER_OF_COLUMNS / 2 + 1).collect());
        state.slot += 1;
        let (block, columns) =
            block_with_blob_columns(state.slot, parent_root, state.tree_hash_root());
        let root = block.message.tree_hash_root();
        chain
            .store
            .lock()
            .await
            .data_availability_checker
            .insert_pending(root, block, state);
        let provider = chain.db.column_sidecars_provider();
        chain
            .import_data_column_sidecars_if(
                columns[..(NUMBER_OF_COLUMNS / 2) as usize].to_vec(),
                |_| Ok(()),
            )
            .await
            .unwrap();

        chain.reconstruct_data_columns(root).await.unwrap();

        assert!(
            provider
                .get(ColumnIdentifier::new(root, NUMBER_OF_COLUMNS / 2))
                .unwrap()
                .is_some()
        );
        assert!(
            provider
                .get(ColumnIdentifier::new(root, NUMBER_OF_COLUMNS / 2 + 1))
                .unwrap()
                .is_none()
        );
    }
}
