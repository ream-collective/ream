use std::{
    collections::HashSet,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use actix_web::{
    HttpRequest, HttpResponse, Responder, get, post,
    web::{Data, Json, Path, Payload, Query},
};
use alloy_primitives::B256;
use anyhow::{anyhow, ensure};
use futures::StreamExt;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use ream_api_types_beacon::{
    block::{BroadcastValidation, SignedBlockContents},
    id::ValidatorID,
    responses::{
        BeaconResponse, BeaconVersionedResponse, DataResponse, ETH_CONSENSUS_VERSION_HEADER,
        RootResponse, SSZ_CONTENT_TYPE,
    },
};
use ream_api_types_common::{error::ApiError, id::ID};
use ream_chain_beacon::beacon_chain::{BeaconChain, BlockProcessingOutcome};
use ream_consensus_beacon::{
    data_column_sidecar::{DataColumnSidecar, get_data_column_sidecars_from_block},
    electra::{
        beacon_block::{BeaconBlock, SignedBeaconBlock},
        beacon_block_body::BeaconBlockBody,
        beacon_state::BeaconState,
        blinded_beacon_block::SignedBlindedBeaconBlock,
    },
    genesis::Genesis,
    matrix_entry::{compute_cells_and_kzg_proofs, das_context},
};
use ream_consensus_misc::{
    constants::beacon::{
        GENESIS_SLOT, WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA, genesis_validators_root,
    },
    polynomial_commitments::kzg_commitment::KZGCommitment,
};
use ream_execution_rpc_types::get_blobs::Blob;
use ream_network_manager::p2p_sender::P2PSender;
use ream_network_spec::networks::beacon_network_spec;
use ream_p2p::{
    gossipsub::beacon::topics::{GossipTopic, GossipTopicKind},
    network::beacon::channel::GossipMessage,
};
use ream_storage::{
    cache::{AddressSlotIdentifier, BeaconCacheDB},
    db::beacon::BeaconDB,
    tables::{beacon::column_sidecars::ColumnSidecarsTable, field::REDBField, table::REDBTable},
};
use ream_validator_beacon::builder::builder_client::BuilderClient;
use serde::{Deserialize, Serialize};
use ssz::{Decode, Encode};
use tracing::{error, info, warn};
use tree_hash::TreeHash;

use crate::handlers::{representation::checkpoint_response, state::get_state_by_block_root};

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct BlockRewards {
    #[serde(with = "serde_utils::quoted_u64")]
    pub proposer_index: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub total: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub attestations: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub sync_aggregate: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub proposer_slashings: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub attester_slashings: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ValidatorSyncCommitteeReward {
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub reward: u64,
}

pub async fn get_block_root_from_id(
    block_id: ID,
    db: &BeaconDB,
    beacon_chain: &BeaconChain,
) -> Result<B256, ApiError> {
    let block_root = match block_id {
        ID::Finalized => {
            let finalized_checkpoint = db.finalized_checkpoint_provider().get().map_err(|err| {
                ApiError::InternalError(format!(
                    "Failed to get block by block_root, error: {err:?}"
                ))
            })?;

            Ok(Some(finalized_checkpoint.root))
        }
        ID::Justified => {
            let justified_checkpoint = db.justified_checkpoint_provider().get().map_err(|err| {
                ApiError::InternalError(format!(
                    "Failed to get block by block_root, error: {err:?}"
                ))
            })?;

            Ok(Some(justified_checkpoint.root))
        }
        ID::Head => Ok(Some(
            beacon_chain
                .head()
                .map_err(|err| {
                    ApiError::InternalError(format!("Failed to get head, error: {err:?}"))
                })?
                .head_root,
        )),
        ID::Genesis => db.slot_index_provider().get(GENESIS_SLOT),
        ID::Slot(slot) => db.slot_index_provider().get(slot),
        ID::Root(root) => Ok(Some(root)),
    }
    .map_err(|err| {
        ApiError::InternalError(format!("Failed to get block by block_root, error: {err:?}"))
    })?
    .ok_or_else(|| ApiError::NotFound(format!("Failed to find `block_root` from {block_id:?}")))?;

    Ok(block_root)
}

/// What a slashing pays the proposer, who is also the whistleblower: the whole whistleblower
/// reward. A validator already slashed earlier in the block pays nothing.
fn slashing_reward(beacon_state: &BeaconState, index: u64, slashed: &mut HashSet<u64>) -> u64 {
    let Some(validator) = beacon_state.validators.get(index as usize) else {
        return 0;
    };
    if !validator.is_slashable_validator(beacon_state.get_current_epoch()) || !slashed.insert(index)
    {
        return 0;
    }
    validator.effective_balance / WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA
}

fn get_proposer_slashing_rewards(
    beacon_state: &BeaconState,
    beacon_block: &SignedBeaconBlock,
    slashed: &mut HashSet<u64>,
) -> u64 {
    beacon_block
        .message
        .body
        .proposer_slashings
        .iter()
        .map(|slashing| {
            slashing_reward(
                beacon_state,
                slashing.signed_header_1.message.proposer_index,
                slashed,
            )
        })
        .sum()
}

fn get_attester_slashing_rewards(
    beacon_state: &BeaconState,
    beacon_block: &SignedBeaconBlock,
    slashed: &mut HashSet<u64>,
) -> u64 {
    let mut reward = 0;
    for attester_slashing in &beacon_block.message.body.attester_slashings {
        if let Ok((indices_1, indices_2)) =
            beacon_state.get_slashable_attester_indices(attester_slashing)
        {
            let mut indices: Vec<u64> = (&indices_1 & &indices_2).into_iter().collect();
            indices.sort_unstable();
            for index in indices {
                reward += slashing_reward(beacon_state, index, slashed);
            }
        }
    }
    reward
}

/// The block's pre-state: the parent's post-state advanced to the block's slot.
fn get_block_pre_state(
    db: &BeaconDB,
    beacon_block: &SignedBeaconBlock,
) -> Result<BeaconState, ApiError> {
    let parent_root = beacon_block.message.parent_root;
    let mut beacon_state = db
        .state_provider()
        .get(parent_root)
        .map_err(|err| ApiError::InternalError(format!("Failed to get parent state: {err:?}")))?
        .ok_or_else(|| ApiError::NotFound(format!("No state for parent block {parent_root}")))?;
    if beacon_state.slot < beacon_block.message.slot {
        beacon_state
            .process_slots(beacon_block.message.slot)
            .map_err(|err| {
                ApiError::InternalError(format!("Failed to advance the parent state: {err}"))
            })?;
    }
    Ok(beacon_state)
}

pub async fn get_beacon_block_from_id(
    block_id: ID,
    db: &BeaconDB,
    beacon_chain: &BeaconChain,
) -> Result<SignedBeaconBlock, ApiError> {
    let block_root = get_block_root_from_id(block_id, db, beacon_chain).await?;

    db.block_provider()
        .get(block_root)
        .map_err(|err| {
            ApiError::InternalError(format!("Failed to get block by block_root, error: {err:?}"))
        })?
        .ok_or_else(|| {
            ApiError::NotFound(format!("Failed to find `beacon block` from {block_root:?}"))
        })
}

/// Called by `/genesis` to get the Genesis Config of Beacon Chain.
#[get("/beacon/genesis")]
pub async fn get_genesis(beacon_chain: Data<Arc<BeaconChain>>) -> Result<impl Responder, ApiError> {
    let head = beacon_chain
        .head()
        .map_err(|err| ApiError::InternalError(format!("Failed to get head: {err:?}")))?;
    Ok(HttpResponse::Ok().json(DataResponse::new(genesis_from_state(&head.state))))
}

/// Validator clients build their slot clock from `genesis_time`, so it must be the chain's
/// genesis time. `MIN_GENESIS_TIME` is only the earliest time genesis could have happened.
fn genesis_from_state(state: &BeaconState) -> Genesis {
    Genesis {
        genesis_time: state.genesis_time,
        genesis_validators_root: state.genesis_validators_root,
        genesis_fork_version: beacon_network_spec().genesis_fork_version,
    }
}

/// Called by `/eth/v2/beacon/blocks/{block_id}/attestations` to get block attestations
#[get("/beacon/blocks/{block_id}/attestations")]
pub async fn get_block_attestations(
    db: Data<BeaconDB>,
    beacon_chain: Data<Arc<BeaconChain>>,
    block_id: Path<ID>,
) -> Result<impl Responder, ApiError> {
    let beacon_block = get_beacon_block_from_id(block_id.into_inner(), &db, &beacon_chain).await?;

    Ok(HttpResponse::Ok().json(BeaconVersionedResponse::new(
        beacon_block.message.body.attestations,
    )))
}

/// Called by `/blocks/<block_id>/root` to get the Tree hash of the Block.
#[get("/beacon/blocks/{block_id}/root")]
pub async fn get_block_root(
    db: Data<BeaconDB>,
    beacon_chain: Data<Arc<BeaconChain>>,
    block_id: Path<ID>,
) -> Result<impl Responder, ApiError> {
    let block_root = get_block_root_from_id(block_id.into_inner(), &db, &beacon_chain).await?;

    Ok(HttpResponse::Ok().json(BeaconResponse::new(RootResponse::new(block_root))))
}

/// Block, and its post-state, for a block id. A root here is a block root, not a state root.
async fn get_block_and_state_from_id(
    block_id: ID,
    db: &BeaconDB,
    beacon_chain: &BeaconChain,
) -> Result<(SignedBeaconBlock, BeaconState), ApiError> {
    let block_root = get_block_root_from_id(block_id.clone(), db, beacon_chain).await?;
    let beacon_block = get_beacon_block_from_id(ID::Root(block_root), db, beacon_chain).await?;
    let beacon_state = get_state_by_block_root(db, block_root)?;
    Ok((beacon_block, beacon_state))
}

/// Standard path of the block rewards endpoint.
#[get("/beacon/rewards/blocks/{block_id}")]
pub async fn get_rewards_blocks(
    db: Data<BeaconDB>,
    beacon_chain: Data<Arc<BeaconChain>>,
    block_id: Path<ID>,
) -> Result<impl Responder, ApiError> {
    block_rewards(block_id.into_inner(), &db, &beacon_chain).await
}

/// Called by `/beacon/blocks/{block_id}/rewards` to get the block rewards response
#[get("/beacon/blocks/{block_id}/rewards")]
pub async fn get_block_rewards(
    db: Data<BeaconDB>,
    beacon_chain: Data<Arc<BeaconChain>>,
    block_id: Path<ID>,
) -> Result<impl Responder, ApiError> {
    block_rewards(block_id.into_inner(), &db, &beacon_chain).await
}

async fn block_rewards(
    block_id: ID,
    db: &BeaconDB,
    beacon_chain: &BeaconChain,
) -> Result<HttpResponse, ApiError> {
    let beacon_block = get_beacon_block_from_id(block_id, db, beacon_chain).await?;
    let beacon_state = get_block_pre_state(db, &beacon_block)?;

    // Same order as `process_operations`.
    let mut slashed = HashSet::new();
    let proposer_slashing_reward =
        get_proposer_slashing_rewards(&beacon_state, &beacon_block, &mut slashed);
    let attester_slashing_reward =
        get_attester_slashing_rewards(&beacon_state, &beacon_block, &mut slashed);
    let attestation_reward = beacon_state
        .attestations_proposer_reward(&beacon_block.message.body.attestations)
        .map_err(|err| {
            ApiError::InternalError(format!("Failed to compute attestation rewards: {err}"))
        })?;
    let (_, proposer_reward) = beacon_state.get_proposer_and_participant_rewards();

    let sync_aggregate_reward = beacon_block
        .message
        .body
        .sync_aggregate
        .sync_committee_bits
        .num_set_bits() as u64
        * proposer_reward;

    let total = attestation_reward
        + sync_aggregate_reward
        + proposer_slashing_reward
        + attester_slashing_reward;

    let response = BlockRewards {
        proposer_index: beacon_block.message.proposer_index,
        total,
        attestations: attestation_reward,
        sync_aggregate: sync_aggregate_reward,
        proposer_slashings: proposer_slashing_reward,
        attester_slashings: attester_slashing_reward,
    };

    Ok(HttpResponse::Ok().json(BeaconResponse::new(response)))
}

/// Called by `/blocks/<block_id>` to get the Beacon Block.
#[get("/beacon/blocks/{block_id}")]
pub async fn get_block_from_id(
    request: HttpRequest,
    db: Data<BeaconDB>,
    beacon_chain: Data<Arc<BeaconChain>>,
    block_id: Path<ID>,
) -> Result<impl Responder, ApiError> {
    let beacon_block = get_beacon_block_from_id(block_id.into_inner(), &db, &beacon_chain).await?;

    Ok(checkpoint_response(
        &request,
        beacon_block.message.slot,
        beacon_block,
    ))
}

#[post("/beacon/rewards/sync_committee/{block_id}")]
pub async fn post_sync_committee_rewards(
    db: Data<BeaconDB>,
    beacon_chain: Data<Arc<BeaconChain>>,
    block_id: Path<ID>,
    validators: Json<Vec<ValidatorID>>,
) -> Result<impl Responder, ApiError> {
    let (beacon_block, beacon_state) =
        get_block_and_state_from_id(block_id.into_inner(), &db, &beacon_chain).await?;

    let sync_committee_rewards_map =
        match beacon_state.compute_sync_committee_rewards(&beacon_block) {
            Ok(rewards) => rewards,
            Err(err) => {
                error!("Failed to compute sync committee rewards, error: {err:?}");
                return Err(ApiError::InternalError(format!(
                    "Failed to compute sync committee rewards, error: {err:?}"
                )));
            }
        };
    let sync_committee_rewards: Vec<ValidatorSyncCommitteeReward> = sync_committee_rewards_map
        .into_iter()
        .map(|(validator_index, reward)| ValidatorSyncCommitteeReward {
            validator_index,
            reward,
        })
        .collect();

    let reward_data = if sync_committee_rewards.is_empty() {
        None
    } else if validators.is_empty() {
        Some(sync_committee_rewards)
    } else {
        Some(
            sync_committee_rewards
                .into_iter()
                .filter(|reward| {
                    validators.iter().any(|validator| match validator {
                        ValidatorID::Index(index) => *index == reward.validator_index,
                        ValidatorID::Address(pubkey) => {
                            match beacon_state.validators.get(reward.validator_index as usize) {
                                Some(validator) => validator.public_key == *pubkey,
                                None => false,
                            }
                        }
                    })
                })
                .collect::<Vec<ValidatorSyncCommitteeReward>>(),
        )
    };

    Ok(HttpResponse::Ok().json(BeaconResponse::new(reward_data)))
}

#[get("/beacon/blind_block/{block_id}")]
pub async fn get_blind_block(
    http_request: HttpRequest,
    db: Data<BeaconDB>,
    beacon_chain: Data<Arc<BeaconChain>>,
    block_id: Path<ID>,
) -> Result<impl Responder, ApiError> {
    let beacon_block = get_beacon_block_from_id(block_id.into_inner(), &db, &beacon_chain).await?;
    let blinded_beacon_block = beacon_block.as_signed_blinded_beacon_block();
    match http_request
        .headers()
        .get(SSZ_CONTENT_TYPE)
        .and_then(|header| header.to_str().ok())
    {
        Some(SSZ_CONTENT_TYPE) => Ok(HttpResponse::Ok()
            .content_type(SSZ_CONTENT_TYPE)
            .body(blinded_beacon_block.as_ssz_bytes())),
        _ => Ok(HttpResponse::Ok().json(BeaconVersionedResponse::new(blinded_beacon_block))),
    }
}

#[derive(Debug, Deserialize)]
pub struct BroadcastValidationQuery {
    #[serde(default)]
    pub broadcast_validation: BroadcastValidation,
}

async fn validate_block_for_broadcast(
    beacon_chain: &BeaconChain,
    block: &SignedBeaconBlock,
    validation_level: &BroadcastValidation,
    cached_db: &BeaconCacheDB,
) -> Result<(), String> {
    match validation_level {
        BroadcastValidation::Gossip => {
            // Lightweight gossip validation
            validate_gossip_level(beacon_chain, block, cached_db).await
        }
        BroadcastValidation::Consensus => {
            // Full consensus validation
            validate_consensus_level(beacon_chain, block, cached_db).await
        }
        BroadcastValidation::ConsensusAndEquivocation => {
            // Consensus + equivocation check
            validate_consensus_level(beacon_chain, block, cached_db).await?;
            check_equivocation(beacon_chain, block).await
        }
    }
}

async fn validate_gossip_level(
    beacon_chain: &BeaconChain,
    block: &SignedBeaconBlock,
    cached_db: &BeaconCacheDB,
) -> Result<(), String> {
    // Catch the fork-choice store up to wall-clock time before checking whether the block is from
    // the future. Do not tick to the block slot itself; future blocks must remain future.
    process_tick_now(beacon_chain)
        .await
        .map_err(|err| format!("Failed to process current slot tick: {err}"))?;

    let store = beacon_chain.store.lock().await;

    // Check slot not in future
    let current_slot = store
        .get_current_slot()
        .map_err(|err| format!("Failed to get current slot: {err}"))?;
    if block.message.slot > current_slot {
        return Err("Block is from a future slot".to_string());
    }

    // Check parent exists
    let parent_state = store
        .db
        .state_provider()
        .get(block.message.parent_root)
        .map_err(|err| format!("Failed to get parent state: {err}"))?
        .ok_or_else(|| "Parent state not found".to_string())?;

    // Verify signature
    if !parent_state
        .verify_block_header_signature(&block.signed_header())
        .map_err(|err| format!("Signature verification error: {err}"))?
    {
        return Err("Invalid block signature".to_string());
    }

    // Check for duplicate (using BeaconCacheDB)
    let validator = parent_state
        .validators
        .get(block.message.proposer_index as usize)
        .ok_or_else(|| "Validator not found".to_string())?;

    if cached_db
        .seen_proposer_signature
        .read()
        .await
        .contains(&AddressSlotIdentifier {
            address: validator.public_key.clone(),
            slot: block.message.slot,
        })
    {
        return Err("Block already seen from this proposer".to_string());
    }

    Ok(())
}

async fn validate_consensus_level(
    beacon_chain: &BeaconChain,
    block: &SignedBeaconBlock,
    cached_db: &BeaconCacheDB,
) -> Result<(), String> {
    // First do gossip checks
    validate_gossip_level(beacon_chain, block, cached_db).await?;

    let store = beacon_chain.store.lock().await;
    let state = store
        .db
        .state_provider()
        .get(block.message.parent_root)
        .map_err(|err| format!("Failed to get parent state: {err}"))?
        .ok_or_else(|| "Parent state not found".to_string())?;

    // Check proposer index
    let expected_proposer = state
        .get_beacon_proposer_index(Some(block.message.slot))
        .map_err(|err| format!("Failed to get proposer index: {err}"))?;
    if expected_proposer != block.message.proposer_index {
        let got = block.message.proposer_index;
        return Err(format!(
            "Invalid proposer index: expected {expected_proposer}, got {got}"
        ));
    }

    // Check execution payload timestamp
    let expected_timestamp = state.compute_timestamp_at_slot(block.message.slot);
    if block.message.body.execution_payload.timestamp != expected_timestamp {
        let got = block.message.body.execution_payload.timestamp;
        return Err(format!(
            "Invalid execution payload timestamp: expected {expected_timestamp}, got {got}"
        ));
    }

    Ok(())
}

async fn check_equivocation(
    beacon_chain: &BeaconChain,
    block: &SignedBeaconBlock,
) -> Result<(), String> {
    let store = beacon_chain.store.lock().await;
    let block_root = block.message.tree_hash_root();

    // Check if another block exists with same slot/proposer but different root
    // This is simplified - production would need more sophisticated tracking
    if let Ok(Some(existing_block)) = store.db.block_provider().get(block_root)
        && existing_block.message.slot == block.message.slot
        && existing_block.message.proposer_index == block.message.proposer_index
        && existing_block.message.tree_hash_root() != block_root
    {
        return Err("Equivocation detected".to_string());
    }

    Ok(())
}

/// Validates the Eth-Consensus-Version header
fn validate_consensus_version_header(http_request: &HttpRequest) -> Result<(), ApiError> {
    let consensus_version = http_request
        .headers()
        .get(ETH_CONSENSUS_VERSION_HEADER)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            ApiError::BadRequest(format!(
                "Missing required header: {ETH_CONSENSUS_VERSION_HEADER}"
            ))
        })?;

    let valid_versions = [
        "phase0",
        "altair",
        "bellatrix",
        "capella",
        "deneb",
        "electra",
        "fulu",
    ];
    if !valid_versions.contains(&consensus_version) {
        let valid_list = valid_versions.join(", ");
        return Err(ApiError::BadRequest(format!(
            "Invalid consensus version: {consensus_version}. Must be one of: {valid_list}"
        )));
    }

    Ok(())
}

/// Reads and accumulates SSZ payload from the request stream
async fn read_ssz_payload(payload: Payload) -> Result<actix_web::web::Bytes, ApiError> {
    let mut body = actix_web::web::BytesMut::new();
    let mut stream = payload.into_inner();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk
            .map_err(|err| ApiError::BadRequest(format!("Failed to read request body: {err}")))?;
        body.extend_from_slice(&chunk);
    }
    Ok(body.freeze())
}

/// Publishes a validated block to the network and processes it
async fn publish_and_process_block(
    signed_block: SignedBeaconBlock,
    blobs: Vec<Blob>,
    beacon_chain: Data<Arc<BeaconChain>>,
    p2p_sender: Data<Arc<P2PSender>>,
) -> Result<HttpResponse, ApiError> {
    process_tick_now(beacon_chain.as_ref())
        .await
        .map_err(|err| {
            ApiError::InternalError(format!("Failed to process current slot tick: {err}"))
        })?;

    // Broadcast via P2P
    let fork_digest = beacon_network_spec().fork_digest(
        beacon_network_spec().current_epoch(),
        genesis_validators_root(),
    );
    let topic = GossipTopic {
        fork: fork_digest,
        kind: GossipTopicKind::BeaconBlock,
    };

    p2p_sender.send_gossip(GossipMessage {
        topic,
        data: signed_block.as_ssz_bytes(),
    });

    broadcast_data_column_sidecars(
        signed_block.clone(),
        blobs,
        beacon_chain.as_ref(),
        p2p_sender.as_ref(),
    )
    .await;

    // Integrate into state (after broadcast)
    let integration_success = match beacon_chain.process_block(signed_block.clone()).await {
        Ok(BlockProcessingOutcome::Imported { .. }) => true,
        Ok(BlockProcessingOutcome::PendingAvailability { block_root }) => {
            warn!("Published block {block_root} is pending data availability");
            false
        }
        Err(err) => {
            if err.to_string().contains("already known")
                || err.to_string().contains("ALREADY_KNOWN")
            {
                warn!("Block already known, ignoring: {err}");
                return Ok(HttpResponse::Ok().finish());
            }
            error!("Failed to integrate block into state: {err}");
            false
        }
    };

    if integration_success {
        Ok(HttpResponse::Ok().finish())
    } else {
        Ok(HttpResponse::Accepted().finish())
    }
}

fn build_and_store_data_column_sidecars(
    signed_block: &SignedBeaconBlock,
    block_root: B256,
    blobs: Vec<Blob>,
    column_sidecars_provider: &ColumnSidecarsTable,
) -> anyhow::Result<Vec<DataColumnSidecar>> {
    let commitment_count = signed_block.message.body.blob_kzg_commitments.len();
    ensure!(
        blobs.len() == commitment_count,
        "{} blobs for {commitment_count} commitments",
        blobs.len()
    );
    let cells_and_kzg_proofs = blobs
        .iter()
        .enumerate()
        .map(|(index, blob)| {
            compute_cells_and_kzg_proofs(blob, das_context()).map_err(|err| {
                anyhow!("Failed to compute cells/KZG proofs for blob {index}: {err}")
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let sidecars = get_data_column_sidecars_from_block(signed_block, cells_and_kzg_proofs)
        .map_err(|err| {
            anyhow!("Failed to build data column sidecars for block {block_root:?}: {err}")
        })?;

    column_sidecars_provider
        .insert_batch(sidecars.clone())
        .map_err(|err| {
            anyhow!("Failed to store own data columns for block {block_root:?}: {err}")
        })?;

    Ok(sidecars)
}

/// Builds and gossips `DataColumnSidecar`s for a just-broadcast block, if it carries blobs.
async fn broadcast_data_column_sidecars(
    signed_block: SignedBeaconBlock,
    published_blobs: Vec<Blob>,
    beacon_chain: &BeaconChain,
    p2p_sender: &P2PSender,
) {
    let commitment_count = signed_block.message.body.blob_kzg_commitments.len();
    if commitment_count == 0 {
        return;
    }

    let block_root = signed_block.message.tree_hash_root();
    // Blobs sent with the block were checked against its commitments; without them, those kept
    // when this node produced the block are used.
    let blobs = if published_blobs.is_empty() {
        match beacon_chain.produced_blobs(block_root) {
            Some(blobs) => blobs,
            None => {
                warn!("Skipping data column sidecar broadcast for block {block_root:?}: no blobs");
                return;
            }
        }
    } else {
        published_blobs
    };
    let column_sidecars_provider = beacon_chain.db().column_sidecars_provider();

    let sidecars = match tokio::task::spawn_blocking(move || {
        build_and_store_data_column_sidecars(
            &signed_block,
            block_root,
            blobs,
            &column_sidecars_provider,
        )
    })
    .await
    {
        Ok(Ok(sidecars)) => sidecars,
        Ok(Err(err)) => {
            warn!("Skipping data column sidecar broadcast for block {block_root:?}: {err}");
            return;
        }
        Err(err) => {
            error!("Data column sidecar task for block {block_root:?} panicked: {err}");
            return;
        }
    };

    let fork_digest = beacon_network_spec().fork_digest(
        beacon_network_spec().current_epoch(),
        genesis_validators_root(),
    );
    for sidecar in sidecars {
        let topic = GossipTopic {
            fork: fork_digest,
            kind: GossipTopicKind::DataColumnSidecar(sidecar.compute_subnet()),
        };
        p2p_sender.send_gossip(GossipMessage {
            topic,
            data: sidecar.as_ssz_bytes(),
        });
    }
}

async fn process_tick_now(beacon_chain: &BeaconChain) -> Result<(), String> {
    let now = current_unix_time_ceil_secs()?;
    beacon_chain
        .process_tick(now)
        .await
        .map_err(|err| err.to_string())
}

fn current_unix_time_ceil_secs() -> Result<u64, String> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| err.to_string())?;
    Ok(duration.as_secs() + u64::from(duration.subsec_nanos() > 0))
}

/// POST /eth/v2/beacon/blocks
/// Publishes a signed beacon block to the beacon network
#[post("/beacon/blocks")]
pub async fn post_beacon_block(
    http_request: HttpRequest,
    payload: Payload,
    query: Query<BroadcastValidationQuery>,
    beacon_chain: Data<Arc<BeaconChain>>,
    p2p_sender: Data<Arc<P2PSender>>,
    cached_db: Data<Arc<BeaconCacheDB>>,
) -> Result<impl Responder, ApiError> {
    validate_consensus_version_header(&http_request)?;

    let is_json = http_request
        .headers()
        .get(actix_web::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/json"));
    let body = read_ssz_payload(payload).await?;
    let (signed_block, blobs) = decode_published_block(&body, is_json)?;
    let commitments = signed_block.message.body.blob_kzg_commitments.to_vec();
    let blobs = tokio::task::spawn_blocking(move || {
        check_published_blobs(&blobs, &commitments).map(|()| blobs)
    })
    .await
    .map_err(|err| ApiError::InternalError(format!("Blob check task failed: {err}")))??;

    // Validate based on broadcast_validation level
    validate_block_for_broadcast(
        beacon_chain.as_ref(),
        &signed_block,
        &query.broadcast_validation,
        cached_db.as_ref(),
    )
    .await
    .map_err(|err| ApiError::BadRequest(format!("Block validation failed: {err}")))?;

    publish_and_process_block(signed_block, blobs, beacon_chain, p2p_sender).await
}

/// The block and blobs of a published block. Deneb and later send `SignedBlockContents`, as SSZ
/// or JSON. A bare signed block, as Ream's validator client sends, is accepted too; its blobs
/// then come from the cache filled when the block was produced.
fn decode_published_block(
    body: &[u8],
    is_json: bool,
) -> Result<(SignedBeaconBlock, Vec<Blob>), ApiError> {
    let contents = if is_json {
        serde_json::from_slice::<SignedBlockContents>(body)
            .map_err(|err| err.to_string())
            .or_else(|contents_err| {
                serde_json::from_slice::<SignedBeaconBlock>(body)
                    .map(|signed_block| SignedBlockContents {
                        signed_block,
                        kzg_proofs: vec![],
                        blobs: vec![],
                    })
                    .map_err(|err| format!("{contents_err}; as a bare block: {err}"))
            })
    } else {
        SignedBlockContents::from_ssz_bytes(body)
            .map_err(|err| format!("{err:?}"))
            .or_else(|contents_err| {
                SignedBeaconBlock::from_ssz_bytes(body)
                    .map(|signed_block| SignedBlockContents {
                        signed_block,
                        kzg_proofs: vec![],
                        blobs: vec![],
                    })
                    .map_err(|err| format!("{contents_err}; as a bare block: {err:?}"))
            })
    }
    .map_err(|err| ApiError::BadRequest(format!("Failed to decode block: {err}")))?;
    Ok((contents.signed_block, contents.blobs))
}

/// Checks that blobs published with a block are those of its commitments, so the columns built
/// from them are valid. A block published without blobs passes.
fn check_published_blobs(blobs: &[Blob], commitments: &[KZGCommitment]) -> Result<(), ApiError> {
    if blobs.is_empty() {
        return Ok(());
    }
    if blobs.len() != commitments.len() {
        return Err(ApiError::BadRequest(format!(
            "{} blobs for {} commitments",
            blobs.len(),
            commitments.len()
        )));
    }
    blobs
        .par_iter()
        .zip(commitments)
        .enumerate()
        .try_for_each(|(index, (blob, commitment))| {
            let computed = das_context()
                .blob_to_kzg_commitment(&blob.to_fixed_bytes())
                .map_err(|err| ApiError::BadRequest(format!("Invalid blob {index}: {err:?}")))?;
            if computed != commitment.0 {
                return Err(ApiError::BadRequest(format!(
                    "Blob {index} does not match its commitment"
                )));
            }
            Ok(())
        })
}

/// POST /eth/v2/beacon/blinded_blocks
/// Publishes a signed blinded beacon block to the beacon network.
#[post("/beacon/blinded_blocks")]
pub async fn post_blinded_beacon_block(
    http_request: HttpRequest,
    payload: Payload,
    query: Query<BroadcastValidationQuery>,
    beacon_chain: Data<Arc<BeaconChain>>,
    p2p_sender: Data<Arc<P2PSender>>,
    cached_db: Data<Arc<BeaconCacheDB>>,
    builder_client: Data<Option<Arc<BuilderClient>>>,
) -> Result<impl Responder, ApiError> {
    validate_consensus_version_header(&http_request)?;

    let body = read_ssz_payload(payload).await?;

    let signed_blinded_block = SignedBlindedBeaconBlock::from_ssz_bytes(&body).map_err(|err| {
        ApiError::BadRequest(format!("Failed to decode SSZ blinded block: {err:?}"))
    })?;

    let slot = signed_blinded_block.message.slot;
    let block_root = signed_blinded_block.message.tree_hash_root();

    let builder = builder_client.get_ref().as_ref().ok_or_else(|| {
        ApiError::InternalError("Builder client not available for unblinding blocks".into())
    })?;

    // Call the builder to get the execution payload and blobs
    let execution_payload_and_blobs = builder
        .get_blinded_blocks(signed_blinded_block.clone())
        .await
        .map_err(|err| {
            ApiError::InternalError(format!(
                "Failed to get execution payload from builder: {err}"
            ))
        })?;

    info!(
        "Reconstructing full signed block from blinded block: slot={slot}, block_root={block_root:?}, source=builder",
    );

    // Construct the full SignedBeaconBlock from the blinded block and execution payload
    let signed_block = SignedBeaconBlock {
        message: BeaconBlock {
            slot: signed_blinded_block.message.slot,
            proposer_index: signed_blinded_block.message.proposer_index,
            parent_root: signed_blinded_block.message.parent_root,
            state_root: signed_blinded_block.message.state_root,
            body: BeaconBlockBody {
                randao_reveal: signed_blinded_block.message.body.randao_reveal.clone(),
                eth1_data: signed_blinded_block.message.body.eth1_data.clone(),
                graffiti: signed_blinded_block.message.body.graffiti,
                proposer_slashings: signed_blinded_block.message.body.proposer_slashings.clone(),
                attester_slashings: signed_blinded_block.message.body.attester_slashings.clone(),
                attestations: signed_blinded_block.message.body.attestations.clone(),
                deposits: signed_blinded_block.message.body.deposits.clone(),
                voluntary_exits: signed_blinded_block.message.body.voluntary_exits.clone(),
                sync_aggregate: signed_blinded_block.message.body.sync_aggregate.clone(),
                execution_payload: execution_payload_and_blobs.execution_payload,
                bls_to_execution_changes: signed_blinded_block
                    .message
                    .body
                    .bls_to_execution_changes
                    .clone(),
                blob_kzg_commitments: signed_blinded_block
                    .message
                    .body
                    .blob_kzg_commitments
                    .clone(),
                execution_requests: signed_blinded_block.message.body.execution_requests.clone(),
            },
        },
        signature: signed_blinded_block.signature.clone(),
    };

    // Validate the reconstructed full block
    validate_block_for_broadcast(
        beacon_chain.as_ref(),
        &signed_block,
        &query.broadcast_validation,
        cached_db.as_ref(),
    )
    .await
    .map_err(|err| ApiError::BadRequest(format!("Block validation failed: {err}")))?;

    info!("Publishing assembled block from blinded block: slot={slot}, block_root={block_root:?}",);

    publish_and_process_block(signed_block, vec![], beacon_chain, p2p_sender).await
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use ream_network_spec::networks::initialize_test_network_spec;
    use ream_operation_pool::OperationPool;
    use ream_storage::{db::ReamDB, tables::table::REDBTable};
    use ream_sync_committee_pool::SyncCommitteePool;
    use ssz::Decode;
    use tempdir::TempDir;

    use super::*;

    fn sepolia_block() -> SignedBeaconBlock {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
            "../../../testing/gossip-validation/tests/assets/sepolia/blocks/child_9552076.ssz_snappy",
        );
        let bytes = snap::raw::Decoder::new()
            .decompress_vec(&std::fs::read(path).unwrap())
            .unwrap();
        SignedBeaconBlock::from_ssz_bytes(&bytes).unwrap()
    }

    #[test]
    fn published_blobs_must_match_the_block_commitments() {
        let commitment = |blob: &Blob| {
            KZGCommitment(
                das_context()
                    .blob_to_kzg_commitment(&blob.to_fixed_bytes())
                    .unwrap(),
            )
        };
        let mut blob = Blob::default();
        blob.inner[31] = 1;
        let other = Blob::default();

        assert!(check_published_blobs(&[], &[commitment(&blob)]).is_ok());
        assert!(check_published_blobs(&[blob.clone()], &[commitment(&blob)]).is_ok());
        assert!(matches!(
            check_published_blobs(&[blob.clone()], &[commitment(&other)]),
            Err(ApiError::BadRequest(_))
        ));
        assert!(matches!(
            check_published_blobs(&[blob.clone(), other.clone()], &[commitment(&blob)]),
            Err(ApiError::BadRequest(_))
        ));
    }

    /// Lighthouse's validator client publishes `SignedBlockContents` as SSZ.
    #[test]
    fn published_blocks_decode_as_contents_or_bare_blocks() {
        let signed_block = sepolia_block();
        let contents = SignedBlockContents {
            signed_block: signed_block.clone(),
            kzg_proofs: vec![],
            blobs: vec![Blob::default()],
        };

        for (body, is_json) in [
            (contents.as_ssz_bytes(), false),
            (serde_json::to_vec(&contents).unwrap(), true),
        ] {
            let (block, blobs) = decode_published_block(&body, is_json).unwrap();
            assert_eq!(block, signed_block);
            assert_eq!(blobs, vec![Blob::default()]);
        }
        for (body, is_json) in [
            (signed_block.as_ssz_bytes(), false),
            (serde_json::to_vec(&signed_block).unwrap(), true),
        ] {
            let (block, blobs) = decode_published_block(&body, is_json).unwrap();
            assert_eq!(block, signed_block);
            assert!(blobs.is_empty());
        }
        assert!(decode_published_block(b"{}", true).is_err());
        assert!(decode_published_block(&[0; 8], false).is_err());
    }

    #[test]
    fn genesis_time_is_the_chain_genesis_not_min_genesis_time() {
        initialize_test_network_spec();
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
            "../../../testing/gossip-validation/tests/assets/sepolia/states/\
             grandparent_state_9552074.ssz_snappy",
        );
        let compressed = std::fs::read(path).expect("reads fixture state");
        let bytes = snap::raw::Decoder::new()
            .decompress_vec(&compressed)
            .expect("decompresses fixture state");
        let state = BeaconState::from_ssz_bytes(&bytes).expect("decodes fixture state");

        let genesis = genesis_from_state(&state);

        // Sepolia: MIN_GENESIS_TIME 1655647200, genesis 1655733600.
        assert_eq!(genesis.genesis_time, 1_655_733_600);
        assert_eq!(
            genesis.genesis_validators_root,
            state.genesis_validators_root
        );
    }

    fn fixture_state() -> BeaconState {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
            "../../../testing/gossip-validation/tests/assets/sepolia/states/\
             grandparent_state_9552074.ssz_snappy",
        );
        let compressed = std::fs::read(path).expect("reads fixture state");
        let bytes = snap::raw::Decoder::new()
            .decompress_vec(&compressed)
            .expect("decompresses fixture state");
        BeaconState::from_ssz_bytes(&bytes).expect("decodes fixture state")
    }

    #[tokio::test]
    async fn rewards_resolve_a_block_root_as_a_block_id() {
        let temp_dir = TempDir::new("ream_rpc_beacon_block").expect("creates temp directory");
        let db = ReamDB::new(temp_dir.path().to_path_buf())
            .expect("creates database")
            .init_beacon_db()
            .expect("initializes beacon database");
        let state = fixture_state();
        let mut block = SignedBeaconBlock {
            message: Default::default(),
            signature: Default::default(),
        };
        block.message.slot = state.slot;
        block.message.state_root = state.tree_hash_root();
        let block_root = block.message.tree_hash_root();
        db.block_provider().insert(block_root, block).unwrap();
        db.state_provider().insert(block_root, state).unwrap();
        let beacon_chain = BeaconChain::new(
            db.clone(),
            Arc::new(OperationPool::default()),
            Arc::new(SyncCommitteePool::default()),
            None,
            None,
        );

        let (_, state) = get_block_and_state_from_id(ID::Root(block_root), &db, &beacon_chain)
            .await
            .expect("block root resolves to the block's post-state");

        assert_eq!(state.slot, fixture_state().slot);
    }
}
