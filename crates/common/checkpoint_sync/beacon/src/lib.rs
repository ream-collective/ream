mod anchor_data;
pub mod checkpoint;
pub mod weak_subjectivity;

use std::{fs, path::Path, sync::Arc};

use alloy_primitives::B256;
use anyhow::{anyhow, ensure};
use checkpoint::get_checkpoint_sync_sources;
use ream_consensus_beacon::{
    blob_sidecar::BlobIdentifier,
    electra::{
        beacon_block::{BeaconBlock, SignedBeaconBlock},
        beacon_state::BeaconState,
    },
};
use ream_consensus_misc::checkpoint::Checkpoint;
use ream_execution_rpc_types::get_blobs::BlobAndProofV1;
use ream_fork_choice_beacon::{
    handlers::on_tick,
    store::{Store, get_forkchoice_store},
};
use ream_network_spec::networks::beacon_network_spec;
use ream_operation_pool::OperationPool;
use ream_storage::{
    db::beacon::BeaconDB,
    tables::{
        beacon::backfill::{
            BackfillMeta, BackfillMode, BlockBackfillState, BlockCoverage, Frontier, Origin,
            SidecarCoverage,
        },
        table::{CustomTable, REDBTable},
    },
};
use reqwest::{
    Url,
    header::{ACCEPT, HeaderValue},
};
use ssz::Decode;
use tracing::{info, warn};
use tree_hash::TreeHash;
use weak_subjectivity::{WeakSubjectivityState, verify_state_from_weak_subjectivity_checkpoint};

/// Entry point for checkpoint sync.
pub async fn initialize_db_from_checkpoint(
    db: BeaconDB,
    checkpoint_sync_url: Option<Url>,
    weak_subjectivity_checkpoint: Option<Checkpoint>,
) -> anyhow::Result<WeakSubjectivityState> {
    if db.recover_interrupted_bootstrap()? {
        warn!("Recovered interrupted bootstrap; retrying initialization");
    }
    if db.is_initialized() {
        log_backfill_mode(&db)?;
        warn!("DB is already initialized. Skipping checkpoint sync.");

        if let Some(weak_subjectivity_checkpoint) = &weak_subjectivity_checkpoint {
            let state = canonical_head_state(&db)?;
            db.cache_genesis_validators_root(state.genesis_validators_root)?;
            if !verify_state_from_weak_subjectivity_checkpoint(
                &state,
                weak_subjectivity_checkpoint,
            )? {
                return Ok(WeakSubjectivityState::CheckpointPendingVerification);
            }
        } else {
            return Ok(WeakSubjectivityState::None);
        }
        return Ok(WeakSubjectivityState::CheckpointAlreadyVerified);
    }

    let sources = get_checkpoint_sync_sources(checkpoint_sync_url);
    ensure!(
        !sources.is_empty(),
        "No checkpoint sync source available for network {:?}. Pass --checkpoint-sync-url \
         explicitly, use --genesis-state-path for a fresh local devnet, or use a network with \
         default checkpoint sync sources (mainnet, sepolia, hoodi).",
        beacon_network_spec().network
    );
    info!("Initiating checkpoint sync");
    let (block, state) = fetch_checkpoint_from_sources(&sources).await?;
    let slot = block.message.slot;
    let (anchor_data, sidecar_frontier) = match anchor_data::fetch_anchor_data_from_sources(
        &sources,
        &block,
        state.genesis_time,
    )
    .await
    {
        Ok(data) => (data, Some(slot)),
        Err(err)
            if ream_consensus_misc::misc::compute_epoch_at_slot(slot)
                >= beacon_network_spec().fulu_fork_epoch =>
        {
            warn!(%err, "Anchor columns unavailable from checkpoint providers; scheduling peer recovery after startup");
            (anchor_data::AnchorData::default(), None)
        }
        Err(err) => return Err(err),
    };
    let root = block.message.block_root();
    let meta = BackfillMeta {
        revision: 0,
        origin: Origin {
            slot,
            root,
            state_root: block.message.state_root,
        },
        blocks: BlockCoverage {
            frontier: Frontier {
                oldest_block_slot: slot,
                oldest_block_root: root,
                oldest_block_parent: block.message.parent_root,
            },
            state: BlockBackfillState::InProgress,
        },
        sidecars: SidecarCoverage {
            frontier: sidecar_frontier,
        },
    };
    db.begin_bootstrap()?;
    for blob in anchor_data.blobs {
        db.blobs_and_proofs_provider().insert(
            BlobIdentifier::new(root, blob.index),
            BlobAndProofV1 {
                blob: blob.blob,
                proof: blob.kzg_proof,
            },
        )?;
    }
    db.column_sidecars_provider()
        .insert_batch(anchor_data.columns)?;
    let mut store = get_forkchoice_store(state.clone(), block, db.clone())?;

    let time = beacon_network_spec().min_genesis_time
        + beacon_network_spec().seconds_per_slot() * (slot + 1);
    on_tick(&mut store, time)?;
    db.finish_bootstrap(state.genesis_validators_root, Some(&meta))?;
    info!("Initial sync complete");

    if let Some(weak_subjectivity_checkpoint) = &weak_subjectivity_checkpoint {
        if !verify_state_from_weak_subjectivity_checkpoint(&state, weak_subjectivity_checkpoint)? {
            return Ok(WeakSubjectivityState::CheckpointPendingVerification);
        }
    } else {
        return Ok(WeakSubjectivityState::None);
    }
    Ok(WeakSubjectivityState::CheckpointAlreadyVerified)
}

// Bootstrap the database directly from a local genesis state file (SSZ-encoded BeaconState),
/// skipping checkpoint sync entirely for local devnets (e.g. Kurtosis)
pub fn initialize_db_from_genesis_state(
    db: BeaconDB,
    genesis_state_path: &Path,
) -> anyhow::Result<()> {
    if db.recover_interrupted_bootstrap()? {
        warn!("Recovered interrupted bootstrap; retrying initialization");
    }
    if db.is_initialized() {
        log_backfill_mode(&db)?;
        warn!("DB is already initialized. Skipping genesis bootstrap.");
        return Ok(());
    }

    info!(
        "Bootstrapping from local genesis state: {}",
        genesis_state_path.display()
    );

    let raw_bytes = fs::read(genesis_state_path).map_err(|err| {
        anyhow!(
            "Failed to read genesis state file {}: {err}",
            genesis_state_path.display()
        )
    })?;

    info!("Read {} bytes from genesis.ssz", raw_bytes.len());

    let genesis_state = BeaconState::from_ssz_bytes(&raw_bytes)
        .map_err(|err| anyhow!("Unable to decode genesis state from ssz bytes: {err:?}"))?;

    let genesis_block = BeaconBlock {
        slot: genesis_state.slot,
        proposer_index: 0,
        parent_root: B256::ZERO,
        state_root: genesis_state.tree_hash_root(),
        ..Default::default()
    };

    info!(
        "genesis_time={}, genesis_validators_root={}",
        genesis_state.genesis_time, genesis_state.genesis_validators_root
    );

    // Genesis has no proposer signature.
    let signed_genesis_block = SignedBeaconBlock {
        message: genesis_block,
        signature: Default::default(),
    };
    ensure!(
        genesis_state.slot == 0,
        "Genesis bootstrap requires a slot-zero state"
    );
    db.begin_bootstrap()?;
    let mut store = get_forkchoice_store(genesis_state.clone(), signed_genesis_block, db.clone())?;

    let time = genesis_state.genesis_time
        + beacon_network_spec().seconds_per_slot() * (genesis_state.slot + 1);
    on_tick(&mut store, time)?;

    db.finish_bootstrap(genesis_state.genesis_validators_root, None)?;
    info!("Genesis bootstrap complete");
    Ok(())
}

async fn fetch_checkpoint_from_sources(
    sources: &[Url],
) -> anyhow::Result<(SignedBeaconBlock, BeaconState)> {
    let mut failures = Vec::new();
    for source in sources {
        let result = async {
            let block = fetch_finalized_block(source).await?;
            let state = get_state(source, block.message.slot).await?;
            ensure!(block.message.slot == state.slot, "Checkpoint slot mismatch");
            ensure!(
                block.message.state_root == state.state_root(),
                "Checkpoint state root mismatch"
            );
            Ok::<_, anyhow::Error>((block, state))
        }
        .await;
        match result {
            Ok(pair) => return Ok(pair),
            Err(err) => {
                warn!(%source, %err, "Checkpoint source failed; trying next source");
                failures.push(format!("{source}: {err:#}"));
            }
        }
    }
    anyhow::bail!(
        "No checkpoint source returned a matching block/state: {}",
        failures.join("; ")
    )
}

/// Fetch initial state from trusted RPC
async fn get_state(rpc: &Url, slot: u64) -> anyhow::Result<BeaconState> {
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(15))
        .read_timeout(std::time::Duration::from_secs(120))
        .build()?;
    let state = client
        .get(format!("{rpc}eth/v2/debug/beacon/states/{slot}"))
        .header(ACCEPT, HeaderValue::from_static("application/octet-stream"))
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    BeaconState::from_ssz_bytes(&state)
        .map_err(|err| anyhow!("Unable to decode state from ssz bytes: {err:?}"))
}

/// Fetch initial block from trusted RPC
async fn fetch_finalized_block(rpc: &Url) -> anyhow::Result<SignedBeaconBlock> {
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(15))
        .read_timeout(std::time::Duration::from_secs(120))
        .build()?;
    let raw_bytes = client
        .get(format!("{rpc}eth/v2/beacon/blocks/finalized"))
        .header(ACCEPT, HeaderValue::from_static("application/octet-stream"))
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    SignedBeaconBlock::from_ssz_bytes(&raw_bytes)
        .map_err(|err| anyhow!("Unable to decode block from ssz bytes: {err:?}"))
}

fn log_backfill_mode(db: &BeaconDB) -> anyhow::Result<()> {
    match db.backfill_mode()? {
        BackfillMode::Legacy => warn!(
            "Legacy database: backfill disabled and historical coverage unverified. Use --purge-db to bootstrap with backfill metadata"
        ),
        mode => info!(?mode, "Loaded bootstrap mode"),
    }
    Ok(())
}

/// Used for legacy databases that predate the independent genesis validators root field.
pub fn canonical_head_state(db: &BeaconDB) -> anyhow::Result<BeaconState> {
    let store = Store::new(db.clone(), Arc::new(OperationPool::default()), None);
    let root = store.get_head()?;
    db.state_provider()
        .get(root)?
        .ok_or_else(|| anyhow!("Missing canonical head state for {root}"))
}

pub fn load_genesis_validators_root(db: &BeaconDB) -> anyhow::Result<B256> {
    if let Some(root) = db.genesis_validators_root()? {
        return Ok(root);
    }
    let root = canonical_head_state(db)?.genesis_validators_root;
    db.cache_genesis_validators_root(root)?;
    Ok(root)
}
