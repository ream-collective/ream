use alloy_primitives::B256;
use anyhow::anyhow;
use ream_consensus_beacon::electra::beacon_block::SignedBeaconBlock;
use ream_light_client::{
    finality_update::LightClientFinalityUpdate, header::LightClientHeader,
    optimistic_update::LightClientOptimisticUpdate,
};
use ream_storage::{db::beacon::BeaconDB, tables::table::REDBTable};
use tree_hash::TreeHash;

/// The optimistic update this node computes for a sync aggregate signed at `signature_slot`, as
/// `create_light_client_optimistic_update`: the canonical block at that slot carries the aggregate
/// and its parent is the attested block. `None` when the node has no block at `signature_slot`.
fn local_optimistic_update(
    db: &BeaconDB,
    signature_slot: u64,
) -> anyhow::Result<Option<(LightClientOptimisticUpdate, B256)>> {
    let Some(block_root) = db.slot_index_provider().get(signature_slot)? else {
        return Ok(None);
    };
    let Some(block) = db.block_provider().get(block_root)? else {
        return Ok(None);
    };
    let attested_root = block.message.parent_root;
    let Some(attested_block) = db.block_provider().get(attested_root)? else {
        return Ok(None);
    };
    let update = LightClientOptimisticUpdate {
        attested_header: LightClientHeader::new(&attested_block)?,
        sync_aggregate: block.message.body.sync_aggregate,
        signature_slot,
    };
    Ok(Some((update, attested_root)))
}

/// The finality update this node computes for `signature_slot`, as
/// `create_light_client_finality_update`: the finalized block is the one the attested state
/// names, and the branch proves it in that state.
fn local_finality_update(
    db: &BeaconDB,
    signature_slot: u64,
) -> anyhow::Result<Option<LightClientFinalityUpdate>> {
    let Some((optimistic, attested_root)) = local_optimistic_update(db, signature_slot)? else {
        return Ok(None);
    };
    let Some(attested_state) = db.state_provider().get_shared(attested_root)? else {
        return Ok(None);
    };
    let finalized_root = attested_state.finalized_checkpoint.root;
    let finalized_header = if finalized_root == B256::ZERO {
        LightClientHeader::default()
    } else {
        let Some(finalized_block) = db.block_provider().get(finalized_root)? else {
            return Ok(None);
        };
        finalized_header_of(&finalized_block, finalized_root)?
    };
    Ok(Some(LightClientFinalityUpdate {
        attested_header: optimistic.attested_header,
        finalized_header,
        finality_branch: attested_state
            .finalized_root_inclusion_proof()?
            .try_into()
            .map_err(|err| anyhow!("finality branch has the wrong depth: {err:?}"))?,
        sync_aggregate: optimistic.sync_aggregate,
        signature_slot,
    }))
}

fn finalized_header_of(block: &SignedBeaconBlock, root: B256) -> anyhow::Result<LightClientHeader> {
    anyhow::ensure!(
        block.message.tree_hash_root() == root,
        "stored finalized block {root} has another root"
    );
    LightClientHeader::new(block)
}

/// Runs on a blocking thread: building the finality update can load a state.
pub(crate) async fn local_finality_update_blocking(
    db: BeaconDB,
    signature_slot: u64,
) -> anyhow::Result<Option<LightClientFinalityUpdate>> {
    tokio::task::spawn_blocking(move || local_finality_update(&db, signature_slot)).await?
}

pub(crate) async fn local_optimistic_update_blocking(
    db: BeaconDB,
    signature_slot: u64,
) -> anyhow::Result<Option<LightClientOptimisticUpdate>> {
    tokio::task::spawn_blocking(move || {
        Ok(local_optimistic_update(&db, signature_slot)?.map(|(update, _)| update))
    })
    .await?
}
