use std::sync::Arc;

use actix_web::{
    HttpResponse, Responder, get,
    web::{Data, Path, Query},
};
use alloy_primitives::B256;
use ream_api_types_beacon::{
    query::{ParentRootQuery, SlotQuery},
    responses::BeaconResponse,
};
use ream_api_types_common::{error::ApiError, id::ID};
use ream_chain_beacon::beacon_chain::BeaconChain;
use ream_consensus_misc::beacon_block_header::SignedBeaconBlockHeader;
use ream_storage::{db::beacon::BeaconDB, tables::table::REDBTable};
use serde::{Deserialize, Serialize};
use tree_hash::TreeHash;

use super::block::{canonical_block_root_at_slot, get_beacon_block_from_id};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HeaderData {
    root: B256,
    canonical: bool,
    header: SignedBeaconBlockHeader,
}

impl HeaderData {
    pub fn new(root: B256, canonical: bool, header: SignedBeaconBlockHeader) -> Self {
        Self {
            root,
            canonical,
            header,
        }
    }
}

/// Called using `/eth/v1/beacon/headers`
/// Optional paramaters `slot` and/or `parent_root`
#[get("/beacon/headers")]
pub async fn get_headers(
    db: Data<BeaconDB>,
    beacon_chain: Data<Arc<BeaconChain>>,
    slot: Query<SlotQuery>,
    parent_root: Query<ParentRootQuery>,
) -> Result<impl Responder, ApiError> {
    let (header, root) = match (slot.slot, parent_root.parent_root) {
        (None, None) => get_header_from_slot(None, &db, &beacon_chain).await?,
        (None, Some(parent_root)) => {
            // get parent block to have access to `slot`
            let parent_block = db
                .block_provider()
                .get(parent_root)
                .map_err(|err| {
                    ApiError::InternalError(format!("Failed to get headers, error: {err:?}"))
                })?
                .ok_or_else(|| ApiError::NotFound(String::from("Unable to fetch parent block")))?;

            // fetch block header at `slot+1`
            let (child_header, child_block_root) =
                get_header_from_slot(Some(parent_block.message.slot + 1), &db, &beacon_chain)
                    .await?;

            if child_header.message.parent_root != parent_root {
                Err(ApiError::NotFound(format!(
                    "Header with parent root :{parent_root:?}"
                )))?;
            }

            (child_header, child_block_root)
        }
        (Some(slot), None) => get_header_from_slot(Some(slot), &db, &beacon_chain).await?,
        (Some(slot), Some(parent_root)) => {
            let (header, root) = get_header_from_slot(Some(slot), &db, &beacon_chain).await?;
            if header.message.parent_root == parent_root {
                (header, root)
            } else {
                return Err(ApiError::NotFound(format!(
                    "Header at slot: {slot} with parent root: {parent_root:?} not found"
                )))?;
            }
        }
    };

    let canonical = is_canonical(root, header.message.slot, &db, &beacon_chain)?;
    Ok(HttpResponse::Ok().json(BeaconResponse::new(HeaderData::new(
        root, canonical, header,
    ))))
}

/// Called using `/eth/v1/beacon/headers/{block_id}`
#[get("/beacon/headers/{block_id}")]
pub async fn get_headers_from_block(
    block_id: Path<ID>,
    db: Data<BeaconDB>,
    beacon_chain: Data<Arc<BeaconChain>>,
) -> Result<impl Responder, ApiError> {
    let block = get_beacon_block_from_id(block_id.into_inner(), &db, &beacon_chain).await?;
    let header = block.signed_header();
    let root = header.message.tree_hash_root();
    let canonical = is_canonical(root, header.message.slot, &db, &beacon_chain)?;

    Ok(HttpResponse::Ok().json(BeaconResponse::new(HeaderData::new(
        root, canonical, header,
    ))))
}

fn is_canonical(
    root: B256,
    slot: u64,
    db: &BeaconDB,
    beacon_chain: &BeaconChain,
) -> Result<bool, ApiError> {
    Ok(canonical_block_root_at_slot(slot, db, beacon_chain)? == Some(root))
}

pub async fn get_header_from_slot(
    slot: Option<u64>,
    db: &BeaconDB,
    beacon_chain: &BeaconChain,
) -> Result<(SignedBeaconBlockHeader, B256), ApiError> {
    // Without a slot, the head.
    let block_id = slot.map_or(ID::Head, ID::Slot);
    let beacon_block = get_beacon_block_from_id(block_id, db, beacon_chain).await?;

    let header = beacon_block.signed_header();
    let root = header.message.tree_hash_root();

    Ok((header, root))
}
