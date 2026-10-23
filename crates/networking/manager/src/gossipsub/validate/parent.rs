use std::sync::Arc;

use alloy_primitives::B256;
use anyhow::anyhow;
use ream_chain_beacon::beacon_chain::BeaconChain;
use ream_consensus_beacon::electra::{beacon_block::SignedBeaconBlock, beacon_state::BeaconState};
use ream_storage::{db::beacon::BeaconDB, tables::table::REDBTable};
use tree_hash::TreeHash;

/// A parent block found by [`find_parent`].
pub enum ParentBlock {
    /// The parent is imported. `state` is `None` if the database has the block but not its state.
    Imported {
        block: SignedBeaconBlock,
        state: Option<Arc<BeaconState>>,
    },
    /// The parent passed validation but is waiting for its data columns.
    PendingAvailability {
        block: SignedBeaconBlock,
        state: Arc<BeaconState>,
    },
}

fn load_imported_parent(db: &BeaconDB, parent_root: B256) -> anyhow::Result<Option<ParentBlock>> {
    let Some(block) = db.block_provider().get(parent_root)? else {
        return Ok(None);
    };
    let state = db.state_provider().get_shared(parent_root)?;
    Ok(Some(ParentBlock::Imported { block, state }))
}

/// Looks up `parent_root` among imported blocks, then among blocks pending data availability.
/// Loading can rebuild a state, so it runs on a blocking thread, first without the store lock.
pub async fn find_parent(
    beacon_chain: &BeaconChain,
    parent_root: B256,
) -> anyhow::Result<Option<ParentBlock>> {
    // The importer writes a block and its state in separate transactions, so without the store lock
    // a block can be visible before its state.
    if let Some(parent @ ParentBlock::Imported { state: Some(_), .. }) =
        load_imported_parent_blocking(beacon_chain.db(), parent_root).await?
    {
        return Ok(Some(parent));
    }

    let store = beacon_chain.store.lock().await;
    if let Some(pending) = store.data_availability_checker.pending_block(&parent_root) {
        if pending.signed_block.message.tree_hash_root() != parent_root {
            return Err(anyhow!(
                "pending availability block root does not match lookup key"
            ));
        }
        return Ok(Some(ParentBlock::PendingAvailability {
            block: pending.signed_block.clone(),
            state: Arc::new(pending.post_state.clone()),
        }));
    }
    // Under the store lock an import of the parent has finished or not begun, so its block and
    // state are both visible or both missing. A just-imported state is still in memory.
    load_imported_parent_blocking(&store.db, parent_root).await
}

async fn load_imported_parent_blocking(
    db: &BeaconDB,
    parent_root: B256,
) -> anyhow::Result<Option<ParentBlock>> {
    let db = db.clone();
    tokio::task::spawn_blocking(move || load_imported_parent(&db, parent_root)).await?
}
