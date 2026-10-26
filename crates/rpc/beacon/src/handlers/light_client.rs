use actix_web::{
    HttpRequest, HttpResponse, Responder, get,
    web::{Data, Path, Query},
};
use alloy_primitives::B256;
use ream_api_types_beacon::responses::{
    DataVersionedResponse, ETH_CONSENSUS_VERSION_HEADER, JSON_CONTENT_TYPE, SSZ_CONTENT_TYPE,
    VERSION,
};
use ream_api_types_common::error::ApiError;
use ream_consensus_misc::constants::beacon::{EPOCHS_PER_SYNC_COMMITTEE_PERIOD, SLOTS_PER_EPOCH};
use ream_light_client::{
    bootstrap::LightClientBootstrap, finality_update::LightClientFinalityUpdate,
    optimistic_update::LightClientOptimisticUpdate, update::LightClientUpdate,
};
use ream_network_manager::gossipsub::validate::light_client_local::{
    local_finality_update, local_optimistic_update,
};
use ream_storage::{db::beacon::BeaconDB, tables::table::REDBTable};
use ssz::Encode;
use tree_hash::TreeHash;

pub const MAX_REQUEST_LIGHT_CLIENT_UPDATES: u64 = 128;

#[get("/beacon/light_client/bootstrap/{block_root}")]
pub async fn get_light_client_bootstrap(
    db: Data<BeaconDB>,
    block_root: Path<B256>,
) -> Result<impl Responder, ApiError> {
    let block_root = block_root.into_inner();
    let beacon_block = db
        .block_provider()
        .get(block_root)
        .map_err(|err| {
            ApiError::InternalError(format!("Failed to get block by block_root, error: {err:?}"))
        })?
        .ok_or_else(|| {
            ApiError::NotFound(format!("Failed to find `beacon block` from {block_root:?}"))
        })?;

    let beacon_state = db
        .state_provider()
        .get(block_root)
        .map_err(|err| {
            ApiError::InternalError(format!(
                "Failed to get beacon_state from block_root, error: {err:?}"
            ))
        })?
        .ok_or(ApiError::NotFound(format!(
            "Failed to find `beacon_state` from {block_root:?}"
        )))?;

    let light_client_bootstrap =
        LightClientBootstrap::new(&beacon_state, &beacon_block).map_err(|err| {
            ApiError::InternalError(format!(
                "Failed to create light client bootstrap, error: {err:?}"
            ))
        })?;

    Ok(HttpResponse::Ok().json(DataVersionedResponse::new(light_client_bootstrap)))
}

#[get("/beacon/light_client/updates")]
pub async fn get_light_client_updates(
    db: Data<BeaconDB>,
    start_period: Query<u64>,
    count: Query<u64>,
) -> Result<impl Responder, ApiError> {
    let start_period: u64 = start_period.into_inner();
    let count = std::cmp::min(count.into_inner(), MAX_REQUEST_LIGHT_CLIENT_UPDATES);

    let mut updates = Vec::new();

    for period in start_period..start_period + count {
        let slot = period * EPOCHS_PER_SYNC_COMMITTEE_PERIOD * SLOTS_PER_EPOCH;
        let block_root = db
            .slot_index_provider()
            .get(slot)
            .map_err(|err| {
                ApiError::InternalError(format!(
                    "Failed to get block root for slot, error: {err:?}"
                ))
            })?
            .ok_or_else(|| {
                ApiError::NotFound(format!(
                    "No block root found for slot {slot} (period {start_period})",
                ))
            })?;

        let block = db
            .block_provider()
            .get(block_root)
            .map_err(|err| {
                ApiError::InternalError(format!(
                    "Failed to get block from block_root, error: {err:?}"
                ))
            })?
            .ok_or(ApiError::NotFound(format!(
                "Failed to find block from {block_root:?}"
            )))?;

        let state = db
            .state_provider()
            .get(block_root)
            .map_err(|err| {
                ApiError::InternalError(format!(
                    "Failed to get state from block_root, error: {err:?}"
                ))
            })?
            .ok_or(ApiError::NotFound(format!(
                "Failed to find state from {block_root:?}"
            )))?;

        let attested_block = db
            .block_provider()
            .get(block.message.parent_root)
            .map_err(|err| {
                ApiError::InternalError(format!(
                    "Failed to get attested_block from block.message.parent_root, error: {err:?}"
                ))
            })?
            .ok_or(ApiError::NotFound(format!(
                "Failed to find attested_block from {:?}",
                block.message.parent_root
            )))?;

        let attested_block_root = attested_block.message.tree_hash_root();
        let attested_state = db
            .state_provider()
            .get(attested_block_root)
            .map_err(|err| {
                ApiError::InternalError(format!(
                    "Failed to get attested_state from attested_block_root, error: {err:?}"
                ))
            })?
            .ok_or(ApiError::NotFound(format!(
                "Failed to find attested_state from {attested_block_root:?}"
            )))?;

        let finalized_block = db
            .block_provider()
            .get(attested_state.finalized_checkpoint.root)
            .map_err(|err| {
                ApiError::InternalError(format!(
                    "Failed to get finalized_block from attested_state.finalized_checkpoint.root, error: {err:?}"
                ))
            })?
            .ok_or(ApiError::NotFound(format!(
                "Failed to find finalized_block from {:?}",attested_state.finalized_checkpoint.root
            )))?;

        updates.push(
            LightClientUpdate::new(
                state,
                block,
                attested_state,
                attested_block,
                Some(finalized_block),
            )
            .map_err(|err| {
                ApiError::InternalError(format!(
                    "Failed to create light client bootstrap, error: {err:?}"
                ))
            })?,
        );
    }
    if updates.len() > (count as usize) {
        return Err(ApiError::NotFound(
            "No light client updates found in requested range".into(),
        ));
    }
    Ok(HttpResponse::Ok().json(DataVersionedResponse::new(updates)))
}

/// The slot of the newest block, whose sync aggregate signs the latest light client updates.
fn latest_slot(db: &BeaconDB) -> Result<u64, ApiError> {
    db.slot_index_provider()
        .get_highest_slot()
        .map_err(|err| {
            ApiError::InternalError(format!("Failed to get latest slot, error: {err:?}"))
        })?
        .ok_or_else(|| ApiError::NotFound("Light client update unavailable".into()))
}

/// The update `build` makes for the newest block, the same one gossip validation computes, built
/// on a blocking thread because the finality update can load a state.
async fn latest_update<T: Send + 'static>(
    db: &BeaconDB,
    build: fn(&BeaconDB, u64) -> anyhow::Result<Option<T>>,
) -> Result<T, ApiError> {
    let db = db.clone();
    let slot = latest_slot(&db)?;
    tokio::task::spawn_blocking(move || build(&db, slot))
        .await
        .map_err(|err| ApiError::InternalError(format!("Light client update task failed: {err}")))?
        .map_err(|err| {
            ApiError::InternalError(format!("Failed to build light client update: {err:?}"))
        })?
        .ok_or_else(|| ApiError::NotFound("Light client update unavailable".into()))
}

fn respond<T: Encode + serde::Serialize>(http_request: &HttpRequest, update: T) -> HttpResponse {
    match http_request
        .headers()
        .get("accept")
        .and_then(|header| header.to_str().ok())
    {
        Some(SSZ_CONTENT_TYPE) => HttpResponse::Ok()
            .content_type(SSZ_CONTENT_TYPE)
            .insert_header((ETH_CONSENSUS_VERSION_HEADER, VERSION))
            .body(update.as_ssz_bytes()),
        _ => HttpResponse::Ok()
            .content_type(JSON_CONTENT_TYPE)
            .insert_header((ETH_CONSENSUS_VERSION_HEADER, VERSION))
            .json(DataVersionedResponse::new(update)),
    }
}

#[get("/beacon/light_client/finality_update")]
pub async fn get_light_client_finality_update(
    db: Data<BeaconDB>,
    http_request: HttpRequest,
) -> Result<impl Responder, ApiError> {
    let update = latest_update(&db, local_finality_update).await?;
    Ok(respond::<LightClientFinalityUpdate>(&http_request, update))
}

#[get("/beacon/light_client/optimistic_update")]
pub async fn get_light_client_optimistic_update(
    db: Data<BeaconDB>,
    http_request: HttpRequest,
) -> Result<impl Responder, ApiError> {
    let update = latest_update(&db, local_optimistic_update).await?;
    Ok(respond::<LightClientOptimisticUpdate>(
        &http_request,
        update,
    ))
}
