use std::sync::Arc;

use actix_web::{HttpResponse, Responder, get, web::Data};
use ream_api_types_beacon::{
    responses::{DataResponse, EXECUTION_OPTIMISTIC},
    sync::SyncStatus,
};
use ream_api_types_common::error::ApiError;
use ream_chain_beacon::beacon_chain::BeaconChain;
use ream_execution_engine::ExecutionEngine;
use tracing::error;

/// Slots the head may trail the clock before the node reports syncing. Empty or late slots leave
/// the head a few slots behind on a synced node; 8 matches Lighthouse VC's synced tier.
const SYNC_TOLERANCE_SLOTS: u64 = 8;

pub async fn calculate_sync_status(
    beacon_chain: &BeaconChain,
    execution_engine: &Option<ExecutionEngine>,
) -> Result<SyncStatus, ApiError> {
    let head = beacon_chain.head().map_err(|err| {
        ApiError::InternalError(format!("Failed to get current slot, error: {err:?}"))
    })?;
    let sync_distance = head.current_slot.saturating_sub(head.head_slot);

    // get el_offline
    let el_offline = match execution_engine {
        Some(execution_engine) => match execution_engine.eth_chain_id().await {
            Ok(_) => false,
            Err(err) => {
                error!("Execution engine is offline or erroring, error: {err:?}");
                true
            }
        },
        None => true,
    };

    Ok(SyncStatus {
        head_slot: head.head_slot,
        sync_distance,
        is_syncing: is_syncing(sync_distance),
        el_offline,
        is_optimistic: EXECUTION_OPTIMISTIC,
    })
}

fn is_syncing(sync_distance: u64) -> bool {
    sync_distance > SYNC_TOLERANCE_SLOTS
}

/// Called by `eth/v1/node/syncing` to get the Node Version.
#[get("/node/syncing")]
pub async fn get_syncing_status(
    beacon_chain: Data<Arc<BeaconChain>>,
    execution_engine: Data<Option<ExecutionEngine>>,
) -> Result<impl Responder, ApiError> {
    let sync_status = calculate_sync_status(&beacon_chain, &execution_engine).await?;

    // `data` is the syncing status itself: wrapping it in another object makes every
    // spec-compliant consumer report the endpoint as unsupported and the node as offline.
    Ok(HttpResponse::Ok().json(DataResponse::new(sync_status)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_few_empty_slots_are_not_syncing() {
        assert!(!is_syncing(0));
        assert!(!is_syncing(2));
        assert!(!is_syncing(SYNC_TOLERANCE_SLOTS));
        assert!(is_syncing(SYNC_TOLERANCE_SLOTS + 1));
    }
}
