use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use actix_web::{
    HttpResponse, Responder, get, post,
    web::{Data, Json, Path, Query},
};
use alloy_primitives::{Address, B256, aliases::B32};
use ream_api_types_beacon::{
    block::{FullBlockData, ProduceBlockData, ProduceBlockResponse},
    committee::{BeaconCommitteeSubscription, SyncCommitteeSubscription},
    id::ValidatorID,
    query::{AttestationQuery, IdQuery, StatusQuery, SyncCommitteeContributionQuery},
    request::ValidatorsPostRequest,
    responses::{BeaconResponse, DataResponse, DataVersionedResponse},
    validator::{ValidatorBalance, ValidatorData, ValidatorStatus},
};
use ream_api_types_common::{error::ApiError, id::ID};
use ream_bls::{BLSSignature, PublicKey, traits::Verifiable};
use ream_chain_beacon::beacon_chain::BeaconChain;
use ream_consensus_beacon::{
    attestation::Attestation,
    attester_slashing::AttesterSlashing,
    beacon_committee_selection::BeaconCommitteeSelection,
    blob_sidecar::BlobIdentifier,
    bls_to_execution_change::SignedBLSToExecutionChange,
    electra::{
        beacon_block::BeaconBlock,
        beacon_block_body::BeaconBlockBody,
        beacon_state::{BeaconState, fork_name_at_epoch},
        blinded_beacon_block::BlindedBeaconBlock,
        blinded_beacon_block_body::BlindedBeaconBlockBody,
    },
    proposer_slashing::ProposerSlashing,
    sync_aggregate::SyncAggregate,
    sync_committe_selection::SyncCommitteeSelection,
    voluntary_exit::SignedVoluntaryExit,
};
use ream_consensus_misc::{
    attestation_data::AttestationData,
    checkpoint::Checkpoint,
    constants::beacon::{
        DOMAIN_RANDAO, MAX_COMMITTEES_PER_SLOT, PROPOSER_REWARD_QUOTIENT, SLOTS_PER_EPOCH,
        SYNC_COMMITTEE_PROPOSER_REWARD_QUOTIENT, SYNC_COMMITTEE_SIZE,
        WHISTLEBLOWER_REWARD_QUOTIENT, genesis_validators_root,
    },
    deposit::Deposit,
    fork_name::ForkName,
    misc::{
        compute_domain, compute_epoch_at_slot, compute_signing_root, compute_start_slot_at_epoch,
    },
    polynomial_commitments::{kzg_commitment::KZGCommitment, kzg_proof::KZGProof},
    validator::Validator,
};
use ream_events_beacon::{
    BeaconEvent, contribution_and_proof::SignedContributionAndProof,
    event::sync_committee::ContributionAndProofEvent,
};
use ream_execution_engine::{ExecutionEngine, engine_trait::ExecutionApi};
use ream_execution_rpc_types::{
    execution_payload::WithdrawalV1,
    forkchoice_update::{ForkchoiceStateV1, PayloadAttributesV3},
    get_payload::Payload,
};
use ream_fork_choice_beacon::store::Store;
use ream_network_manager::{
    gossipsub::validate::{
        aggregate_and_proof::validate_aggregate_and_proof, result::ValidationResult,
        sync_committee_contribution_and_proof::validate_sync_committee_contribution_and_proof,
    },
    p2p_sender::P2PSender,
};
use ream_network_spec::networks::beacon_network_spec;
use ream_operation_pool::OperationPool;
use ream_p2p::{
    gossipsub::beacon::topics::{GossipTopic, GossipTopicKind},
    network::beacon::channel::GossipMessage,
};
use ream_storage::{cache::BeaconCacheDB, db::beacon::BeaconDB, tables::table::REDBTable};
use ream_sync_committee_pool::SyncCommitteePool;
use ream_validator_beacon::{
    aggregate_and_proof::SignedAggregateAndProof,
    attestation::compute_subnet_for_attestation,
    builder::{
        builder_bid::SignedBuilderBid, builder_client::BuilderClient,
        validator_registration::SignedValidatorRegistrationV1,
    },
    constants::SYNC_COMMITTEE_SUBNET_COUNT,
    execution_requests::get_execution_requests,
};
use serde::Serialize;
use ssz::Encode;
use ssz_types::{
    VariableList,
    typenum::{U1, U8, U16},
};
use tokio::sync::broadcast;
use tracing::{debug, warn};
use tree_hash::TreeHash;

use super::{duties::head_chain_block_root, state::get_state_from_id};

///  For slots in Electra and later, this AttestationData must have a committee_index of 0.
const ELECTRA_COMMITTEE_INDEX: u64 = 0;
const MAX_VALIDATOR_COUNT: usize = 100;

fn build_validator_balances(
    validators: &[(Validator, u64)],
    filter_ids: Option<&Vec<ValidatorID>>,
) -> Vec<ValidatorBalance> {
    // Turn the optional Vec<ValidatorID> into an optional HashSet for O(1) lookups
    let filtered_ids = filter_ids.map(|ids| ids.iter().collect::<HashSet<_>>());

    validators
        .iter()
        .enumerate()
        .filter(|(idx, (validator, _))| match &filtered_ids {
            Some(ids) => {
                ids.contains(&ValidatorID::Index(*idx as u64))
                    || ids.contains(&ValidatorID::Address(validator.public_key.clone()))
            }
            None => true,
        })
        .map(|(idx, (_, balance))| ValidatorBalance {
            index: idx as u64,
            balance: *balance,
        })
        .collect()
}

#[get("/beacon/states/{state_id}/validators/{validator_id}")]
pub async fn get_validator_from_state(
    db: Data<BeaconDB>,
    param: Path<(ID, ValidatorID)>,
) -> Result<impl Responder, ApiError> {
    let (state_id, validator_id) = param.into_inner();
    let state = get_state_from_id(state_id, &db).await?;

    let (index, validator) = {
        match &validator_id {
            ValidatorID::Index(i) => match state.validators.get(*i as usize) {
                Some(validator) => (*i as usize, validator.to_owned()),
                None => {
                    return Err(ApiError::NotFound(format!(
                        "Validator not found for index: {i}"
                    )));
                }
            },
            ValidatorID::Address(public_key) => {
                match find_validator_by_public_key(&state, public_key) {
                    Some((i, validator)) => (i, validator.to_owned()),
                    None => {
                        return Err(ApiError::NotFound(format!(
                            "Validator not found for public_key: {public_key:?}"
                        )))?;
                    }
                }
            }
        }
    };

    let balance = state.balances.get(index).ok_or(ApiError::NotFound(format!(
        "Validator not found for index: {index}"
    )))?;

    let status = validator_status(&validator, &db).await?;

    Ok(
        HttpResponse::Ok().json(BeaconResponse::new(ValidatorData::new(
            index as u64,
            *balance,
            status,
            validator,
        ))),
    )
}

pub async fn validator_status(
    validator: &Validator,
    db: &BeaconDB,
) -> Result<ValidatorStatus, ApiError> {
    let highest_slot = db
        .slot_index_provider()
        .get_highest_slot()
        .map_err(|err| {
            ApiError::InternalError(format!("Failed to get_highest_slot, error: {err:?}"))
        })?
        .ok_or(ApiError::NotFound(
            "Failed to find highest slot".to_string(),
        ))?;
    let state = get_state_from_id(ID::Slot(highest_slot), db).await?;
    let current_epoch = state.get_current_epoch();

    // Check if validator is pending (not yet activated)
    if validator.activation_epoch > current_epoch {
        Ok(ValidatorStatus::Pending)
    }
    // Check if validator has exited
    else if validator.exit_epoch <= current_epoch {
        Ok(ValidatorStatus::Offline)
    }
    // Validator is active
    else {
        Ok(ValidatorStatus::ActiveOngoing)
    }
}

/// Helper function to find validator by public key in state
fn find_validator_by_public_key<'a>(
    state: &'a BeaconState,
    public_key: &PublicKey,
) -> Option<(usize, &'a Validator)> {
    state
        .validators
        .iter()
        .enumerate()
        .find(|(_, v)| v.public_key == *public_key)
}

#[get("/beacon/states/{state_id}/validators")]
pub async fn get_validators_from_state(
    db: Data<BeaconDB>,
    state_id: Path<ID>,
    id_query: Query<IdQuery>,
    status_query: Query<StatusQuery>,
) -> Result<impl Responder, ApiError> {
    if let Some(validator_ids) = &id_query.id
        && validator_ids.len() >= MAX_VALIDATOR_COUNT
    {
        return Err(ApiError::TooManyValidatorsIds);
    }

    let state = get_state_from_id(state_id.into_inner(), &db).await?;
    let mut validators_data = Vec::new();
    let mut validator_indices_to_process = Vec::new();

    // First, collect all the validator indices we need to process
    if let Some(validator_ids) = &id_query.id {
        for validator_id in validator_ids {
            let (index, _) = {
                match validator_id {
                    ValidatorID::Index(i) => match state.validators.get(*i as usize) {
                        Some(validator) => (*i as usize, validator.to_owned()),
                        None => {
                            return Err(ApiError::NotFound(format!(
                                "Validator not found for index: {i}"
                            )))?;
                        }
                    },
                    ValidatorID::Address(public_key) => {
                        match find_validator_by_public_key(&state, public_key) {
                            Some((i, validator)) => (i, validator.to_owned()),
                            None => {
                                return Err(ApiError::NotFound(format!(
                                    "Validator not found for public_key: {public_key:?}"
                                )))?;
                            }
                        }
                    }
                }
            };
            validator_indices_to_process.push(index);
        }
    } else {
        validator_indices_to_process = (0..state.validators.len()).collect();
    }

    for index in validator_indices_to_process {
        let validator = &state.validators[index];

        let status = validator_status(validator, &db).await?;

        if status_query.has_status() && !status_query.contains_status(&status) {
            continue;
        }

        let balance = state.balances.get(index).ok_or(ApiError::NotFound(format!(
            "Validator not found for index: {index}"
        )))?;

        validators_data.push(ValidatorData::new(
            index as u64,
            *balance,
            status,
            validator.clone(),
        ));
    }

    Ok(HttpResponse::Ok().json(BeaconResponse::new(validators_data)))
}

#[post("/beacon/states/{state_id}/validators")]
pub async fn post_validators_from_state(
    db: Data<BeaconDB>,
    state_id: Path<ID>,
    request: Json<ValidatorsPostRequest>,
) -> Result<impl Responder, ApiError> {
    let ValidatorsPostRequest { ids, statuses, .. } = request.into_inner();
    let status_query = StatusQuery { status: statuses };

    let state = get_state_from_id(state_id.into_inner(), &db).await?;
    let mut validators_data = Vec::new();
    let mut validator_indices_to_process = Vec::new();

    // First, collect all the validator indices we need to process
    if let Some(validator_ids) = &ids {
        for validator_id in validator_ids {
            let (index, _) = {
                match validator_id {
                    ValidatorID::Index(i) => match state.validators.get(*i as usize) {
                        Some(validator) => (*i as usize, validator.to_owned()),
                        None => {
                            return Err(ApiError::NotFound(format!(
                                "Validator not found for index: {i}"
                            )))?;
                        }
                    },
                    ValidatorID::Address(public_key) => {
                        match find_validator_by_public_key(&state, public_key) {
                            Some((i, validator)) => (i, validator.to_owned()),
                            None => {
                                return Err(ApiError::NotFound(format!(
                                    "Validator not found for public_key: {public_key:?}"
                                )))?;
                            }
                        }
                    }
                }
            };
            validator_indices_to_process.push(index);
        }
    } else {
        validator_indices_to_process = (0..state.validators.len()).collect();
    }

    for index in validator_indices_to_process {
        let validator = &state.validators[index];

        let status = validator_status(validator, &db).await?;

        if status_query.has_status() && !status_query.contains_status(&status) {
            continue;
        }

        let balance = state.balances.get(index).ok_or(ApiError::NotFound(format!(
            "Validator not found for index: {index}"
        )))?;

        validators_data.push(ValidatorData::new(
            index as u64,
            *balance,
            status,
            validator.clone(),
        ));
    }

    Ok(HttpResponse::Ok().json(BeaconResponse::new(validators_data)))
}

#[derive(Debug, Serialize)]
struct ValidatorIdentity {
    #[serde(with = "serde_utils::quoted_u64")]
    index: u64,
    public_key: PublicKey,
    #[serde(with = "serde_utils::quoted_u64")]
    activation_epoch: u64,
}

#[post("/beacon/states/{state_id}/validator_identities")]
pub async fn post_validator_identities_from_state(
    db: Data<BeaconDB>,
    state_id: Path<ID>,
    validator_ids: Json<Vec<ValidatorID>>,
) -> Result<impl Responder, ApiError> {
    let state = get_state_from_id(state_id.into_inner(), &db).await?;

    let validator_ids_set: HashSet<ValidatorID> = validator_ids.into_inner().into_iter().collect();

    let validator_identities: Vec<ValidatorIdentity> = state
        .validators
        .iter()
        .enumerate()
        .filter_map(|(index, validator)| {
            if validator_ids_set.contains(&ValidatorID::Index(index as u64))
                || validator_ids_set.contains(&ValidatorID::Address(validator.public_key.clone()))
            {
                Some(ValidatorIdentity {
                    index: index as u64,
                    public_key: validator.public_key.clone(),
                    activation_epoch: validator.activation_epoch,
                })
            } else {
                None
            }
        })
        .collect();

    Ok(HttpResponse::Ok().json(BeaconResponse::new(validator_identities)))
}

#[get("/beacon/states/{state_id}/validator_balances")]
pub async fn get_validator_balances_from_state(
    state_id: Path<ID>,
    query: Query<IdQuery>,
    db: Data<BeaconDB>,
) -> Result<impl Responder, ApiError> {
    let state = get_state_from_id(state_id.into_inner(), &db).await?;
    Ok(
        HttpResponse::Ok().json(BeaconResponse::new(build_validator_balances(
            &state
                .validators
                .iter()
                .cloned()
                .zip(state.balances.into_iter())
                .collect::<Vec<_>>(),
            query.id.as_ref(),
        ))),
    )
}

#[post("/beacon/states/{state_id}/validator_balances")]
pub async fn post_validator_balances_from_state(
    state_id: Path<ID>,
    body: Json<IdQuery>,
    db: Data<BeaconDB>,
) -> Result<impl Responder, ApiError> {
    let state = get_state_from_id(state_id.into_inner(), &db).await?;
    Ok(
        HttpResponse::Ok().json(BeaconResponse::new(build_validator_balances(
            &state
                .validators
                .iter()
                .cloned()
                .zip(state.balances.into_iter())
                .collect::<Vec<_>>(),
            body.id.as_ref(),
        ))),
    )
}

#[derive(Debug, Serialize)]
pub struct ValidatorLivenessData {
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: u64,
    pub is_live: bool,
}

impl ValidatorLivenessData {
    pub fn new(index: u64, is_live: bool) -> Self {
        Self { index, is_live }
    }
}

#[post("/validator/liveness/{epoch}")]
pub async fn post_validator_liveness(
    beacon_chain: Data<Arc<BeaconChain>>,
    epoch: Path<u64>,
    validator_indices: Json<Vec<String>>,
) -> Result<impl Responder, ApiError> {
    let epoch = epoch.into_inner();
    let head = beacon_chain
        .head()
        .map_err(|err| ApiError::InternalError(format!("Failed to get head: {err:?}")))?;
    validate_liveness_epoch(epoch, compute_epoch_at_slot(head.current_slot))?;

    let mut liveness_data = Vec::new();
    for validator_index in validator_indices.into_inner() {
        let validator_index: u64 = validator_index
            .parse()
            .map_err(|err| ApiError::BadRequest(format!("Invalid validator index: {err:?}")))?;
        if (validator_index as usize) < head.state.validators.len() {
            liveness_data.push(ValidatorLivenessData::new(
                validator_index,
                is_live(&head.state, validator_index as usize, epoch),
            ));
        }
    }

    Ok(HttpResponse::Ok().json(BeaconResponse::new(liveness_data)))
}

/// Liveness is answered for the previous, current and next epoch, as Lighthouse does; the next
/// epoch keeps a validator client whose clock is slightly ahead from failing at the boundary.
fn validate_liveness_epoch(epoch: u64, current_epoch: u64) -> Result<(), ApiError> {
    let (first, last) = (
        current_epoch.saturating_sub(1),
        current_epoch.saturating_add(1),
    );
    if epoch < first || epoch > last {
        return Err(ApiError::BadRequest(format!(
            "Liveness is only known for epochs {first} to {last}"
        )));
    }
    Ok(())
}

/// Whether the head state records an attestation by the validator for `epoch`. The state at the
/// start of an epoch has not seen any of its attestations yet, so the head state is used.
fn is_live(head_state: &BeaconState, validator_index: usize, epoch: u64) -> bool {
    let state_epoch = head_state.get_current_epoch();
    let participation = if epoch == state_epoch {
        &head_state.current_epoch_participation
    } else if epoch + 1 == state_epoch {
        &head_state.previous_epoch_participation
    } else {
        return false;
    };
    participation
        .get(validator_index)
        .is_some_and(|flags| *flags > 0)
}

fn validator_api_is_syncing(current_slot: u64, head_slot: u64) -> bool {
    const SYNC_TOLERANCE_EPOCHS: u64 = 2;

    current_slot.saturating_sub(head_slot) > SYNC_TOLERANCE_EPOCHS * SLOTS_PER_EPOCH
}

/// Source checkpoint for an attestation in `target_epoch`, built on a head state in
/// `state_epoch`. A head state from an earlier epoch has not run the epoch transition yet, so its
/// justification is the head block's pulled-up (unrealized) one.
fn attestation_source(
    state_epoch: u64,
    previous_justified: Checkpoint,
    current_justified: Checkpoint,
    target_epoch: u64,
    unrealized_justification: Option<Checkpoint>,
) -> Checkpoint {
    if target_epoch + 1 == state_epoch {
        previous_justified
    } else if target_epoch > state_epoch {
        unrealized_justification.unwrap_or(current_justified)
    } else {
        current_justified
    }
}

#[get("/validator/attestation_data")]
pub async fn get_attestation_data(
    db: Data<BeaconDB>,
    beacon_chain: Data<Arc<BeaconChain>>,
    query: Query<AttestationQuery>,
) -> Result<impl Responder, ApiError> {
    let head = beacon_chain
        .head()
        .map_err(|err| ApiError::InternalError(format!("Failed to get head root: {err:?}")))?;
    if validator_api_is_syncing(head.current_slot, head.head_slot) {
        return Err(ApiError::UnderSyncing);
    }

    let slot = query.slot;
    let current_slot = head.current_slot;

    if slot > current_slot + 1 {
        return Err(ApiError::InvalidParameter(format!(
            "Slot {slot:?} is too far ahead of the current slot {current_slot:?}"
        )));
    }

    let head_root = head.head_root;
    let state = &head.state;

    let beacon_block_root = if slot >= state.slot {
        head_root
    } else {
        head_chain_block_root(&db, head_root, state, slot)?
    };

    let target_epoch = compute_epoch_at_slot(slot);
    let unrealized_justification = if target_epoch > state.get_current_epoch() {
        db.unrealized_justifications_provider()
            .get(head_root)
            .map_err(|err| {
                ApiError::InternalError(format!(
                    "Failed to get unrealized justification, error: {err:?}"
                ))
            })?
    } else {
        None
    };
    let source_checkpoint = attestation_source(
        state.get_current_epoch(),
        state.previous_justified_checkpoint,
        state.current_justified_checkpoint,
        target_epoch,
        unrealized_justification,
    );
    let target_slot = compute_start_slot_at_epoch(target_epoch);
    let target_root = if state.slot <= target_slot {
        beacon_block_root
    } else {
        head_chain_block_root(&db, head_root, state, target_slot)?
    };
    let target_checkpoint = Checkpoint {
        epoch: target_epoch,
        root: target_root,
    };

    Ok(HttpResponse::Ok().json(DataResponse::new(AttestationData {
        slot,
        index: ELECTRA_COMMITTEE_INDEX,
        beacon_block_root,
        source: source_checkpoint,
        target: target_checkpoint,
    })))
}

/// For the initial stage, this endpoint returns a 501 as DVT support is not planned.
#[post("/validator/sync_committee_selections")]
pub async fn post_sync_committee_selections(
    _selections: Json<SyncCommitteeSelection>,
) -> Result<impl Responder, ApiError> {
    Ok(HttpResponse::NotImplemented())
}

/// For the initial stage, this endpoint returns a 501 as DVT support is not planned.
#[post("/validator/beacon_committee_selections")]
pub async fn post_beacon_committee_selections(
    _selections: Json<Vec<BeaconCommitteeSelection>>,
) -> Result<impl Responder, ApiError> {
    Ok(HttpResponse::NotImplemented())
}

#[get("/validator/sync_committee_contribution")]
pub async fn get_sync_committee_contribution(
    db: Data<BeaconDB>,
    operation_pool: Data<Arc<OperationPool>>,
    sync_committee_pool: Data<Arc<SyncCommitteePool>>,
    query: Query<SyncCommitteeContributionQuery>,
) -> Result<impl Responder, ApiError> {
    let store = Store::new(db.get_ref().clone(), operation_pool.get_ref().clone(), None);

    if store.is_syncing_for_validator_api().map_err(|err| {
        ApiError::InternalError(format!("Failed to check syncing status, err: {err:?}"))
    })? {
        return Err(ApiError::UnderSyncing);
    }

    let slot = query.slot;
    let subcommittee_index = query.subcommittee_index;
    let beacon_block_root = query.beacon_block_root;

    // Validate subcommittee index
    if subcommittee_index >= SYNC_COMMITTEE_SUBNET_COUNT {
        return Err(ApiError::InvalidParameter(format!(
            "Invalid subcommittee_index: {subcommittee_index}, must be less than {SYNC_COMMITTEE_SUBNET_COUNT}"
        )));
    }

    let current_slot = store.get_current_slot().map_err(|err| {
        ApiError::InternalError(format!("Failed to get current slot, err: {err:?}"))
    })?;

    // Validate slot is not too far in the future
    if slot > current_slot + 1 {
        return Err(ApiError::InvalidParameter(format!(
            "Slot {slot:?} is too far ahead of the current slot {current_slot:?}"
        )));
    }

    // Validate beacon block exists
    db.block_provider()
        .get(beacon_block_root)
        .map_err(|err| ApiError::InternalError(format!("Failed to get beacon block: {err:?}")))?
        .ok_or_else(|| {
            ApiError::NotFound(format!("Beacon block root {beacon_block_root:?} not found"))
        })?;

    // Check if block is fully verified (not optimistic)
    // TODO: Add optimistic sync check when execution layer integration is complete
    // For now, we assume all blocks in fork choice are fully verified

    // Try to get the best (highest-participation) sync committee contribution from the pool
    // Per spec: return 404 if no contribution is available
    let sync_committee_contribution = sync_committee_pool
        .get_best_sync_committee_contribution(slot, beacon_block_root, subcommittee_index)
        .ok_or_else(|| {
            ApiError::NotFound(format!(
                "No sync committee contribution available for beacon block root {beacon_block_root:?}"
            ))
        })?;

    Ok(HttpResponse::Ok().json(DataResponse::new(sync_committee_contribution)))
}

#[post("/validator/aggregate_and_proofs")]
pub async fn post_aggregate_and_proofs_v2(
    beacon_chain: Data<Arc<BeaconChain>>,
    cached_db: Data<Arc<BeaconCacheDB>>,
    p2p_sender: Data<Arc<P2PSender>>,
    aggregates: Json<Vec<SignedAggregateAndProof>>,
) -> Result<impl Responder, ApiError> {
    let mut failures = vec![];
    for (index, signed_aggregate) in aggregates.into_inner().into_iter().enumerate() {
        match validate_aggregate_and_proof(&signed_aggregate, &beacon_chain, &cached_db).await {
            Ok(ValidationResult::Accept) => {}
            Ok(ValidationResult::Ignore(reason)) => {
                debug!("Aggregate and proof {index} not published: {reason}");
                continue;
            }
            Ok(ValidationResult::Reject(reason)) => {
                failures.push(IndexedFailure {
                    index,
                    message: reason,
                });
                continue;
            }
            Err(err) => {
                failures.push(IndexedFailure {
                    index,
                    message: err.to_string(),
                });
                continue;
            }
        }

        p2p_sender.send_gossip(GossipMessage {
            topic: GossipTopic {
                fork: current_fork_digest(),
                kind: GossipTopicKind::AggregateAndProof,
            },
            data: signed_aggregate.as_ssz_bytes(),
        });
        if let Err(err) = beacon_chain
            .import_aggregate(signed_aggregate.message.aggregate)
            .await
        {
            warn!("Failed to import published aggregate {index}: {err}");
        }
    }

    if !failures.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "code": 400,
            "message": "some failures",
            "failures": failures
        })));
    }
    Ok(HttpResponse::Ok().finish())
}

fn current_fork_digest() -> B32 {
    beacon_network_spec().fork_digest(
        beacon_network_spec().current_epoch(),
        genesis_validators_root(),
    )
}

#[post("/validator/beacon_committee_subscriptions")]
pub async fn post_beacon_committee_subscriptions(
    beacon_chain: Data<Arc<BeaconChain>>,
    subscriptions: Json<Vec<BeaconCommitteeSubscription>>,
    p2p_sender: Data<Arc<P2PSender>>,
) -> Result<impl Responder, ApiError> {
    let head = beacon_chain
        .head()
        .map_err(|err| ApiError::InternalError(format!("Failed to get head: {err:?}")))?;
    // Subnet to the last slot it is needed for. Only aggregators join a subnet: everyone else
    // publishes to it without subscribing. The node keeps peers on both.
    let mut subnets: HashMap<u64, u64> = HashMap::new();
    let mut duty_subnets: HashMap<u64, u64> = HashMap::new();

    for sub in subscriptions.into_inner() {
        if sub.committees_at_slot > MAX_COMMITTEES_PER_SLOT {
            return Err(ApiError::BadRequest(
                "Committees at a slot should be less than the maximum committees per slot".into(),
            ));
        }

        if sub.committee_index >= sub.committees_at_slot {
            return Err(ApiError::BadRequest(
                "Committee index cannot be more than the committees in a slot".into(),
            ));
        }

        // The head state fixes committees up to the next epoch; later duties are not checked.
        if head
            .state
            .determines_committees_of(compute_epoch_at_slot(sub.slot))
        {
            let committee_members = head
                .state
                .get_beacon_committee(sub.slot, sub.committee_index)
                .map_err(|err| {
                    ApiError::InternalError(format!("Failed to get committee: {err}"))
                })?;
            if !committee_members.contains(&sub.validator_index) {
                return Err(ApiError::BadRequest(
                    "Validator not part of the committee".into(),
                ));
            }
        }

        let subnet_id =
            compute_subnet_for_attestation(sub.committees_at_slot, sub.slot, sub.committee_index);
        let until_slot = duty_subnets.entry(subnet_id).or_insert(sub.slot);
        *until_slot = (*until_slot).max(sub.slot);
        if !sub.is_aggregator {
            continue;
        }
        let until_slot = subnets.entry(subnet_id).or_insert(sub.slot);
        *until_slot = (*until_slot).max(sub.slot);
    }
    if !duty_subnets.is_empty() {
        p2p_sender.attestation_duty_subnets(duty_subnets);
    }

    let fork = beacon_network_spec().fork_digest(
        beacon_network_spec().current_epoch(),
        genesis_validators_root(),
    );
    for (subnet_id, until_slot) in subnets {
        let topic = GossipTopic {
            fork,
            kind: GossipTopicKind::BeaconAttestation(subnet_id),
        };
        p2p_sender.subscribe_for_duty(topic, until_slot);
    }

    Ok(HttpResponse::Ok().finish())
}

#[post("/validator/sync_committee_subscriptions")]
pub async fn post_sync_committee_subscriptions(
    beacon_chain: Data<Arc<BeaconChain>>,
    subscriptions: Json<Vec<SyncCommitteeSubscription>>,
    p2p_sender: Data<Arc<P2PSender>>,
) -> Result<impl Responder, ApiError> {
    let subscriptions = subscriptions.into_inner();
    if subscriptions.is_empty() {
        return Err(ApiError::BadRequest("Empty request body".to_string()));
    }

    let head = beacon_chain
        .head()
        .map_err(|err| ApiError::InternalError(format!("Failed to get head: {err:?}")))?;
    let current_epoch = compute_epoch_at_slot(head.current_slot);
    let subcommittee_size = SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT;

    // Subnet to the last slot it is needed for.
    let mut subnets: HashMap<u64, u64> = HashMap::new();
    for subscription in subscriptions {
        if head
            .state
            .validators
            .get(subscription.validator_index as usize)
            .is_none()
        {
            return Err(ApiError::BadRequest(format!(
                "Validator index {} not found",
                subscription.validator_index
            )));
        }

        // `until_epoch` is exclusive.
        if subscription.until_epoch <= current_epoch {
            return Err(ApiError::BadRequest(format!(
                "until_epoch {} must be greater than current epoch {current_epoch}",
                subscription.until_epoch
            )));
        }
        let until_slot = compute_start_slot_at_epoch(subscription.until_epoch) - 1;

        // `sync_committee_indices` are positions in the sync committee, 128 per subnet.
        for index in subscription.sync_committee_indices {
            if index >= SYNC_COMMITTEE_SIZE {
                return Err(ApiError::BadRequest(format!(
                    "Sync committee index {index} is out of range"
                )));
            }
            let entry = subnets
                .entry(index / subcommittee_size)
                .or_insert(until_slot);
            *entry = (*entry).max(until_slot);
        }
    }

    let fork = beacon_network_spec().fork_digest(
        beacon_network_spec().current_epoch(),
        genesis_validators_root(),
    );
    for (subnet_id, until_slot) in subnets {
        let topic = GossipTopic {
            fork,
            kind: GossipTopicKind::SyncCommittee(subnet_id),
        };
        p2p_sender.subscribe_for_duty(topic, until_slot);
    }

    Ok(HttpResponse::Ok().finish())
}

/// Verify validator registration signature
fn verify_validator_registration_signature(
    signed_registration: &SignedValidatorRegistrationV1,
) -> Result<bool, ApiError> {
    use ream_validator_beacon::builder::DOMAIN_APPLICATION_BUILDER;

    let domain = compute_domain(
        DOMAIN_APPLICATION_BUILDER,
        Some(beacon_network_spec().genesis_fork_version),
        None,
    );
    let signing_root = compute_signing_root(signed_registration.message.clone(), domain);

    signed_registration
        .signature
        .verify(
            &signed_registration.message.public_key,
            signing_root.as_ref(),
        )
        .map_err(|err| ApiError::InternalError(format!("Signature verification failed: {err:?}")))
}

#[post("/validator/register_validator")]
pub async fn post_register_validator(
    db: Data<BeaconDB>,
    builder_client: Data<
        Option<Arc<ream_validator_beacon::builder::builder_client::BuilderClient>>,
    >,
    registrations: Json<Vec<SignedValidatorRegistrationV1>>,
) -> Result<impl Responder, ApiError> {
    let registrations = registrations.into_inner();

    if registrations.is_empty() {
        return Err(ApiError::BadRequest("Empty request body".to_string()));
    }

    // Get the current state once for all validator status checks
    let highest_slot = db
        .slot_index_provider()
        .get_highest_slot()
        .map_err(|err| {
            ApiError::InternalError(format!("Failed to get_highest_slot, error: {err:?}"))
        })?
        .ok_or(ApiError::NotFound(
            "Failed to find highest slot".to_string(),
        ))?;
    let state = get_state_from_id(ID::Slot(highest_slot), &db).await?;
    let current_epoch = state.get_current_epoch();

    for registration in registrations {
        // Verify signature
        let signature_valid = verify_validator_registration_signature(&registration)?;
        if !signature_valid {
            continue;
        }

        // Check if validator is active or pending (not exited or unknown)
        let is_valid = if let Some((_index, validator)) =
            find_validator_by_public_key(&state, &registration.message.public_key)
        {
            let is_pending = validator.activation_epoch > current_epoch;
            let is_active =
                validator.activation_epoch <= current_epoch && current_epoch < validator.exit_epoch;
            is_pending || is_active
        } else {
            false
        };

        if !is_valid {
            continue;
        }

        // Forward immediately to builder if available
        if let Some(client) = builder_client.get_ref().as_ref() {
            client
                .register_validator(registration)
                .await
                .map_err(|err| {
                    ApiError::InternalError(format!("Failed to forward to builder: {err}"))
                })?;
        }
    }

    Ok(HttpResponse::Ok().body("Validator registrations have been received."))
}

#[derive(Clone, Debug, Serialize)]
struct IndexedFailure {
    index: usize,
    message: String,
}

#[post("/validator/contribution_and_proofs")]
pub async fn post_contribution_and_proofs(
    beacon_chain: Data<Arc<BeaconChain>>,
    cached_db: Data<Arc<BeaconCacheDB>>,
    p2p_sender: Data<Arc<P2PSender>>,
    operation_pool: Data<Arc<OperationPool>>,
    event_sender: Data<broadcast::Sender<BeaconEvent>>,
    contributions: Json<Vec<SignedContributionAndProof>>,
) -> Result<impl Responder, ApiError> {
    let mut failures = vec![];
    for (index, signed_contribution_and_proof) in contributions.into_inner().into_iter().enumerate()
    {
        match validate_sync_committee_contribution_and_proof(
            &beacon_chain,
            &cached_db,
            &signed_contribution_and_proof,
        )
        .await
        {
            Ok(ValidationResult::Accept) => {}
            Ok(ValidationResult::Ignore(reason)) => {
                debug!("Contribution and proof {index} not published: {reason}");
                continue;
            }
            Ok(ValidationResult::Reject(reason)) => {
                failures.push(IndexedFailure {
                    index,
                    message: reason,
                });
                continue;
            }
            Err(err) => {
                failures.push(IndexedFailure {
                    index,
                    message: err.to_string(),
                });
                continue;
            }
        }

        p2p_sender.send_gossip(GossipMessage {
            topic: GossipTopic {
                fork: current_fork_digest(),
                kind: GossipTopicKind::SyncCommitteeContributionAndProof,
            },
            data: signed_contribution_and_proof.as_ssz_bytes(),
        });
        let contribution = &signed_contribution_and_proof.message.contribution;
        operation_pool.insert_sync_contribution(
            contribution.slot,
            contribution.beacon_block_root,
            contribution.subcommittee_index,
            contribution.aggregation_bits.clone(),
            contribution.signature.clone(),
        );
        let _ = event_sender.send(BeaconEvent::ContributionAndProof(
            ContributionAndProofEvent {
                message: signed_contribution_and_proof.message,
                signature: signed_contribution_and_proof.signature,
            },
        ));
    }

    if !failures.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "code": 400,
            "message": "some failures",
            "failures": failures
        })));
    }
    Ok(HttpResponse::Ok().finish())
}

#[derive(serde::Deserialize)]
struct BlockQuery {
    randao_reveal: BLSSignature,
    graffiti: Option<B256>,
    skip_randao_verification: Option<bool>,
    builder_boost_factor: Option<u64>,
}

fn verify_randao_reveal(
    state: &BeaconState,
    epoch: u64,
    randao_reveal: &BLSSignature,
    skip_randao_verification: bool,
    proposer_public_key: &PublicKey,
) -> Result<(), ApiError> {
    if skip_randao_verification {
        if !randao_reveal.is_infinity() {
            return Err(ApiError::BadRequest(
                "If randao verification is skipped then the randao reveal must be equal to point at infinity".into(),
            ));
        }
    } else {
        let randao_proof_domain = state.get_domain(DOMAIN_RANDAO, Some(epoch));
        let randao_proof_signing_root = compute_signing_root(epoch, randao_proof_domain);
        if !randao_reveal
            .verify(proposer_public_key, randao_proof_signing_root.as_ref())
            .map_err(|err| {
                ApiError::InternalError(format!("Failed due to internal error: {err}"))
            })?
        {
            return Err(ApiError::BadRequest(
                "Randao reveal verification failed".to_string(),
            ));
        }
    }
    Ok(())
}

fn calculate_consensus_block_value(
    state: &BeaconState,
    attestations: &VariableList<Attestation, U8>,
    proposer_slashings: &VariableList<ProposerSlashing, U16>,
    attester_slashings: &VariableList<AttesterSlashing, U1>,
    sync_aggregate: &SyncAggregate,
) -> Result<u64, ApiError> {
    let mut total_reward = 0u64;

    // Calculate attestation rewards
    for attestation in attestations {
        if let Ok(attesting_indices) = state.get_attesting_indices(attestation) {
            let total_participating_balance: u64 = attesting_indices
                .iter()
                .filter_map(|&idx| {
                    state
                        .validators
                        .get(idx as usize)
                        .map(|v| v.effective_balance)
                })
                .sum();

            let proposer_reward = total_participating_balance
                .saturating_div(SLOTS_PER_EPOCH.saturating_mul(PROPOSER_REWARD_QUOTIENT));

            total_reward = total_reward.saturating_add(proposer_reward);
        }
    }

    // Calculate proposer slashing rewards
    for proposer_slashing in proposer_slashings {
        let index = proposer_slashing.signed_header_1.message.proposer_index;
        if let Some(validator) = state.validators.get(index as usize) {
            total_reward = total_reward.saturating_add(
                validator
                    .effective_balance
                    .saturating_div(WHISTLEBLOWER_REWARD_QUOTIENT),
            );
        }
    }

    // Calculate attester slashing rewards
    let current_epoch = state.get_current_epoch();
    for attester_slashing in attester_slashings {
        if let Ok((attestation_indices_1, attestation_indices_2)) =
            state.get_slashable_attester_indices(attester_slashing)
        {
            let slashed_indices: HashSet<_> = attestation_indices_1
                .intersection(&attestation_indices_2)
                .copied()
                .collect();

            for index in slashed_indices {
                if let Some(validator) = state.validators.get(index as usize)
                    && validator.is_slashable_validator(current_epoch)
                {
                    total_reward = total_reward.saturating_add(
                        validator
                            .effective_balance
                            .saturating_div(WHISTLEBLOWER_REWARD_QUOTIENT),
                    );
                }
            }
        }
    }

    // Calculate sync committee rewards
    if !sync_aggregate.sync_committee_bits.is_empty() {
        let (_, base_proposer_reward) = state.get_proposer_and_participant_rewards();
        let participating_count = sync_aggregate.sync_committee_bits.num_set_bits() as u64;
        let sync_reward = (participating_count.saturating_mul(base_proposer_reward))
            .saturating_div(SYNC_COMMITTEE_PROPOSER_REWARD_QUOTIENT);

        total_reward = total_reward.saturating_add(sync_reward);
    }

    Ok(total_reward)
}

async fn get_local_execution_payload(
    execution_engine: &ExecutionEngine,
    fork_name: ForkName,
    forkchoice_state: ForkchoiceStateV1,
    payload_attribute: PayloadAttributesV3,
) -> Result<(Payload, u64), ApiError> {
    let result = execution_engine
        .engine_forkchoice_updated_v3(
            ForkchoiceStateV1 {
                head_block_hash: forkchoice_state.head_block_hash,
                safe_block_hash: forkchoice_state.safe_block_hash,
                finalized_block_hash: forkchoice_state.finalized_block_hash,
            },
            Some(PayloadAttributesV3 {
                timestamp: payload_attribute.timestamp,
                prev_randao: payload_attribute.prev_randao,
                suggested_fee_recipient: payload_attribute.suggested_fee_recipient,
                withdrawals: payload_attribute.withdrawals.clone(),
                parent_beacon_block_root: payload_attribute.parent_beacon_block_root,
            }),
        )
        .await
        .map_err(|err| ApiError::InternalError(format!("Failed to update forkchoice: {err}")))?;

    let payload_id = result.payload_id.ok_or_else(|| {
        ApiError::InternalError("No payload id returned from forkchoice update".into())
    })?;

    let payload = execution_engine
        .engine_get_payload(&fork_name, payload_id)
        .await
        .map_err(|err| ApiError::InternalError(format!("Failed to get payload: {err}")))?;

    let execution_value: u64 = (*payload.block_value())
        .try_into()
        .map_err(|err| ApiError::InternalError(format!("Block value too large: {err}")))?;

    Ok((payload, execution_value))
}

async fn compare_builder_vs_local(
    builder_client: Option<&Arc<BuilderClient>>,
    parent_hash: B256,
    proposer_public_key: &PublicKey,
    slot: u64,
    local_execution_value: u64,
    builder_boost_factor: u64,
) -> Result<(bool, Option<SignedBuilderBid>, u64), ApiError> {
    if let Some(builder) = builder_client {
        match builder
            .get_builder_header(parent_hash, proposer_public_key, slot)
            .await
        {
            Ok(bid) => {
                let builder_value_u256 = bid.message.value;
                let builder_value_u64: u64 = match builder_value_u256.try_into() {
                    Ok(value) => value,
                    Err(err) => {
                        tracing::warn!(
                            "Builder bid value too large to fit in u64: {err:?}, falling back to local execution"
                        );
                        return Ok((false, None, 0));
                    }
                };
                let boosted_builder_value = builder_value_u64
                    .saturating_mul(builder_boost_factor)
                    .saturating_div(100);

                let use_builder = boosted_builder_value > local_execution_value;
                Ok((use_builder, Some(bid), builder_value_u64))
            }
            Err(err) => {
                tracing::warn!(
                    "Failed to get builder header: {err:?}, falling back to local execution"
                );
                Ok((false, None, 0))
            }
        }
    } else {
        Ok((false, None, 0))
    }
}

#[get("/validator/blocks/{slot}")]
pub async fn get_blocks_v3(
    path: Path<u64>,
    query: Query<BlockQuery>,
    db: Data<BeaconDB>,
    operation_pool: Data<Arc<OperationPool>>,
    beacon_chain: Data<Arc<BeaconChain>>,
    execution_engine: Data<Option<ExecutionEngine>>,
    builder_client: Data<Option<Arc<BuilderClient>>>,
) -> Result<impl Responder, ApiError> {
    let slot = path.into_inner();
    let query_params = query.into_inner();
    let randao_reveal = query_params.randao_reveal;
    let graffiti = query_params.graffiti.unwrap_or_default();
    let skip_randao_verification = query_params.skip_randao_verification.unwrap_or(false);
    let builder_boost_factor = query_params.builder_boost_factor.unwrap_or(100);

    let head = beacon_chain
        .head()
        .map_err(|err| ApiError::InternalError(format!("Failed to get head root: {err:?}")))?;
    let mut state = head.state.as_ref().clone();

    let current_slot = state.slot;

    if slot < current_slot {
        return Err(ApiError::BadRequest(
            "Current slot is greater than requested slot".into(),
        ));
    }

    // Process slots to get state at the requested slot.
    state
        .process_slots(slot)
        .map_err(|err| ApiError::InternalError(format!("Failed to process slots: {err}")))?;

    let proposer_index = state.get_beacon_proposer_index(Some(slot)).map_err(|err| {
        ApiError::InternalError(format!(
            "Failed to get the proposer index for slot {slot}: {err}",
        ))
    })?;

    let Some(proposer) = state.validators.get(proposer_index as usize) else {
        return Err(ApiError::ValidatorNotFound(format!("{proposer_index}")));
    };

    let proposer_public_key = proposer.public_key.clone();
    let epoch = compute_epoch_at_slot(slot);
    let fork_name = fork_name_at_epoch(epoch);

    verify_randao_reveal(
        &state,
        epoch,
        &randao_reveal,
        skip_randao_verification,
        &proposer_public_key,
    )?;

    let fee_recipient = operation_pool
        .get_proposer_preparation(proposer_index)
        .unwrap_or(Address::ZERO);

    let (withdrawals, _) = state.get_expected_withdrawals().map_err(|err| {
        ApiError::InternalError(format!("Failed to get expected withdrawals: {err}"))
    })?;

    let forkchoice_state = beacon_chain.forkchoice_state_for(&head);

    let payload_attribute = PayloadAttributesV3 {
        timestamp: state.compute_timestamp_at_slot(slot),
        prev_randao: state.get_randao_mix(epoch),
        suggested_fee_recipient: fee_recipient,
        withdrawals: withdrawals
            .into_iter()
            .map(WithdrawalV1::from)
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|err| {
                ApiError::InternalError(format!(
                    "Failed to convert withdrawals to VariableList: {err:?}"
                ))
            })?,
        parent_beacon_block_root: state.latest_block_header.tree_hash_root(),
    };

    let Some(execution_engine) = execution_engine.get_ref().as_ref() else {
        return Err(ApiError::InternalError(
            "Execution engine not available".into(),
        ));
    };

    let (local_payload, local_execution_value) = get_local_execution_payload(
        execution_engine,
        fork_name,
        forkchoice_state,
        payload_attribute,
    )
    .await?;

    let builder_client_ref = builder_client.get_ref().as_ref();
    let (use_builder, builder_bid, builder_value) = compare_builder_vs_local(
        builder_client_ref,
        state.latest_execution_payload_header.block_hash,
        &proposer_public_key,
        slot,
        local_execution_value,
        builder_boost_factor,
    )
    .await?;

    let proposer_slashings: VariableList<ProposerSlashing, U16> = operation_pool
        .get_all_proposer_slahsings()
        .try_into()
        .unwrap_or_default();
    let attester_slashings: VariableList<AttesterSlashing, U1> = operation_pool
        .get_all_attester_slashings()
        .try_into()
        .unwrap_or_default();
    let attestations: VariableList<Attestation, U8> = operation_pool
        .get_attestations_for_block(&state)
        .try_into()
        .unwrap_or_default();
    let deposits: VariableList<Deposit, U16> = operation_pool
        .get_all_deposits()
        .try_into()
        .unwrap_or_default();
    let voluntary_exits: VariableList<SignedVoluntaryExit, U16> = operation_pool
        .get_signed_voluntary_exits()
        .try_into()
        .unwrap_or_default();
    let mut sync_aggregate = operation_pool
        .get_sync_aggregate(
            slot.saturating_sub(1),
            state.latest_block_header.tree_hash_root(),
        )
        .unwrap_or_default();
    if sync_aggregate.sync_committee_bits.num_set_bits() == 0 {
        sync_aggregate.sync_committee_signature = BLSSignature::infinity();
    }
    let bls_to_execution_changes: VariableList<SignedBLSToExecutionChange, U16> = operation_pool
        .get_signed_bls_to_execution_changes()
        .try_into()
        .unwrap_or_default();

    let common_block_body_fields = (
        randao_reveal,
        state.eth1_data.clone(),
        graffiti,
        proposer_slashings.clone(),
        attester_slashings.clone(),
        attestations.clone(),
        deposits,
        voluntary_exits,
        sync_aggregate.clone(),
        bls_to_execution_changes,
    );

    let consensus_block_value = calculate_consensus_block_value(
        &state,
        &attestations,
        &proposer_slashings,
        &attester_slashings,
        &sync_aggregate,
    )?;

    if use_builder {
        let builder_bid = builder_bid.expect("Builder bid should exist when use_builder is true");

        let blinded_beacon_block_body = BlindedBeaconBlockBody {
            randao_reveal: common_block_body_fields.0,
            eth1_data: common_block_body_fields.1,
            graffiti: common_block_body_fields.2,
            proposer_slashings: common_block_body_fields.3,
            attester_slashings: common_block_body_fields.4,
            attestations: common_block_body_fields.5,
            deposits: common_block_body_fields.6,
            voluntary_exits: common_block_body_fields.7,
            sync_aggregate: common_block_body_fields.8,
            execution_payload_header: builder_bid.message.header,
            bls_to_execution_changes: common_block_body_fields.9,
            blob_kzg_commitments: builder_bid.message.blob_kzg_commitments,
            execution_requests: builder_bid.message.execution_requests,
        };

        let blinded_block = BlindedBeaconBlock {
            slot,
            proposer_index,
            parent_root: state.latest_block_header.tree_hash_root(),
            state_root: state.tree_hash_root(),
            body: blinded_beacon_block_body,
        };

        let response = ProduceBlockResponse {
            version: fork_name.to_string(),
            execution_payload_blinded: true,
            execution_payload_value: builder_value,
            consensus_block_value,
            data: ProduceBlockData::Blinded(blinded_block),
        };

        return Ok(HttpResponse::Ok()
            .insert_header(("Eth-Consensus-Version", fork_name.to_string()))
            .insert_header(("Eth-Execution-Payload-Blinded", "true"))
            .insert_header((
                "Eth-Execution-Payload-Value",
                response.execution_payload_value.to_string(),
            ))
            .insert_header((
                "Eth-Consensus-Block-Value",
                consensus_block_value.to_string(),
            ))
            .json(response));
    }

    let execution_payload = local_payload.to_execution_payload();

    let blob_kzg_commitments: Vec<KZGCommitment> = local_payload.blobs_bundle().get_commitments();

    let kzg_proofs: Vec<KZGProof> = local_payload.blobs_bundle().get_proofs();

    if blob_kzg_commitments.len() != kzg_proofs.len() {
        return Err(ApiError::InternalError(
            "Mismatch between blob commitments and KZG proofs".into(),
        ));
    }

    let execution_requests =
        get_execution_requests(local_payload.execution_requests().clone()).unwrap_or_default();

    let block_body = BeaconBlockBody {
        randao_reveal: common_block_body_fields.0,
        eth1_data: common_block_body_fields.1,
        graffiti: common_block_body_fields.2,
        proposer_slashings: common_block_body_fields.3,
        attester_slashings: common_block_body_fields.4,
        attestations: common_block_body_fields.5,
        deposits: common_block_body_fields.6,
        voluntary_exits: common_block_body_fields.7,
        sync_aggregate: common_block_body_fields.8,
        execution_payload,
        bls_to_execution_changes: common_block_body_fields.9,
        blob_kzg_commitments: blob_kzg_commitments.clone().try_into().unwrap_or_default(),
        execution_requests,
    };

    let mut block = BeaconBlock {
        slot,
        proposer_index,
        parent_root: state.latest_block_header.tree_hash_root(),
        state_root: B256::default(),
        body: block_body,
    };
    let mut post_state = state.clone();
    post_state
        .process_block(&block, &Option::<ExecutionEngine>::None)
        .await
        .map_err(|err| {
            ApiError::InternalError(format!("Failed to compute post-state root: {err}"))
        })?;
    block.state_root = post_state.tree_hash_root();

    let blob_versioned_hashes: Vec<B256> = blob_kzg_commitments
        .iter()
        .map(|c| c.calculate_versioned_hash())
        .collect();

    let blobs_and_proofs = execution_engine
        .clone()
        .engine_get_blobs_v1(blob_versioned_hashes)
        .await
        .map_err(|err| {
            ApiError::InternalError(format!(
                "Failed to fetch blobs from execution engine: {err}"
            ))
        })?;

    if blobs_and_proofs.len() != blob_kzg_commitments.len() {
        return Err(ApiError::InternalError(
            "Blob count does not match commitments".to_string(),
        ));
    }

    let block_root = block.tree_hash_root();
    let blobs_and_proofs_provider = db.blobs_and_proofs_provider();
    let mut blobs = Vec::with_capacity(blobs_and_proofs.len());
    let mut cached_blobs = Vec::with_capacity(blobs_and_proofs.len());
    for (index, bap) in blobs_and_proofs.into_iter().enumerate() {
        let blob_and_proof = bap.expect(
            "Missing blob and proof from execution engine: expected BlobAndProofV1, got None",
        );

        cached_blobs.push((
            BlobIdentifier::new(block_root, index as u64),
            blob_and_proof.clone(),
        ));

        blobs.push(blob_and_proof.blob);
    }

    match tokio::task::spawn_blocking(move || blobs_and_proofs_provider.insert_batch(cached_blobs))
        .await
    {
        Ok(Ok(())) => {}
        Ok(Err(err)) => tracing::error!("Failed to cache blobs for block {block_root:?}: {err}"),
        Err(err) => tracing::error!("Blob cache task failed for block {block_root:?}: {err}"),
    }

    let response = ProduceBlockResponse {
        version: fork_name.to_string(),
        execution_payload_blinded: false,
        execution_payload_value: local_execution_value,
        consensus_block_value,
        data: ProduceBlockData::Full(FullBlockData {
            block,
            kzg_proofs,
            blobs,
        }),
    };

    Ok(HttpResponse::Ok()
        .insert_header(("Eth-Consensus-Version", fork_name.to_string()))
        .insert_header(("Eth-Execution-Payload-Blinded", "false"))
        .insert_header((
            "Eth-Execution-Payload-Value",
            local_execution_value.to_string(),
        ))
        .insert_header((
            "Eth-Consensus-Block-Value",
            consensus_block_value.to_string(),
        ))
        .json(response))
}

#[get("/validator/aggregate_attestation")]
pub async fn get_aggregate_attestation(
    opertation_pool: Data<Arc<OperationPool>>,
    attestation_query: Query<AttestationQuery>,
) -> Result<impl Responder, ApiError> {
    let (Some(committee_index), Some(attestation_data_root)) = (
        attestation_query.committee_index,
        attestation_query.attestation_data_root,
    ) else {
        return Err(ApiError::BadRequest(
            "committee_index and attestation_data_root are required".to_string(),
        ));
    };
    let aggregated_attestation = opertation_pool
        .get_aggregate_attestation(
            attestation_query.slot,
            committee_index,
            attestation_data_root,
        )
        .ok_or_else(|| ApiError::NotFound(String::from("No attestations found")))?;

    Ok(HttpResponse::Ok().json(DataVersionedResponse::new(aggregated_attestation)))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use alloy_primitives::B256;
    use ream_consensus_misc::checkpoint::Checkpoint;
    use ssz::Decode;

    use super::*;

    fn checkpoint(epoch: u64) -> Checkpoint {
        Checkpoint {
            epoch,
            root: B256::repeat_byte(epoch as u8),
        }
    }

    #[test]
    fn attestation_source_uses_pulled_up_justification_in_a_new_epoch() {
        // Head state in epoch 10 justified 8; its pulled-up justification is 9.
        let (previous, current, unrealized) = (checkpoint(7), checkpoint(8), Some(checkpoint(9)));

        assert_eq!(
            attestation_source(10, previous, current, 11, unrealized),
            checkpoint(9)
        );
        assert_eq!(
            attestation_source(10, previous, current, 11, None),
            checkpoint(8)
        );
        assert_eq!(
            attestation_source(10, previous, current, 10, unrealized),
            checkpoint(8)
        );
        assert_eq!(
            attestation_source(10, previous, current, 9, unrealized),
            checkpoint(7)
        );
    }

    fn sepolia_state() -> BeaconState {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
            "../../../testing/gossip-validation/tests/assets/sepolia/states/\
             grandparent_state_9552074.ssz_snappy",
        );
        let bytes = snap::raw::Decoder::new()
            .decompress_vec(&std::fs::read(path).unwrap())
            .unwrap();
        BeaconState::from_ssz_bytes(&bytes).unwrap()
    }

    #[test]
    fn liveness_accepts_the_previous_current_and_next_epoch() {
        for epoch in [9, 10, 11] {
            assert!(validate_liveness_epoch(epoch, 10).is_ok());
        }
        for epoch in [0, 8, 12, u64::MAX] {
            assert!(matches!(
                validate_liveness_epoch(epoch, 10),
                Err(ApiError::BadRequest(_))
            ));
        }
        assert!(validate_liveness_epoch(0, 0).is_ok());
    }

    #[test]
    fn liveness_reads_the_head_state_participation() {
        let state = sepolia_state();
        let epoch = state.get_current_epoch();
        let live = state
            .previous_epoch_participation
            .iter()
            .position(|flags| *flags > 0)
            .unwrap();
        let idle = state
            .previous_epoch_participation
            .iter()
            .position(|flags| *flags == 0)
            .unwrap();

        assert!(is_live(&state, live, epoch - 1));
        assert!(!is_live(&state, idle, epoch - 1));
        assert_eq!(
            is_live(&state, live, epoch),
            state.current_epoch_participation[live] > 0
        );
        assert!(!is_live(&state, live, epoch + 1));
        assert!(!is_live(&state, live, epoch - 2));
        assert!(!is_live(&state, state.validators.len(), epoch - 1));
    }

    #[test]
    fn cached_head_sync_check_preserves_the_two_epoch_tolerance() {
        assert!(!validator_api_is_syncing(100, 36));
        assert!(validator_api_is_syncing(101, 36));
        assert!(!validator_api_is_syncing(36, 100));
    }
}
