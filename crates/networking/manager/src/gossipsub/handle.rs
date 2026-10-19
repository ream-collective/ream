use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::ensure;
pub use libp2p::gossipsub::{Message, MessageAcceptance};
use ream_chain_beacon::beacon_chain::{BeaconChain, BlockProcessingOutcome};
use ream_consensus_beacon::{
    blob_sidecar::BlobIdentifier, data_column_sidecar::DATA_COLUMN_SIDECAR_SUBNET_COUNT,
    electra::beacon_block::SignedBeaconBlock, single_attestation::SingleAttestation,
};
use ream_consensus_misc::{
    constants::beacon::{MIN_ATTESTATION_INCLUSION_DELAY, genesis_validators_root},
    misc::compute_epoch_at_slot,
};
use ream_execution_rpc_types::get_blobs::BlobAndProofV1;
use ream_network_spec::networks::beacon_network_spec;
use ream_p2p::gossipsub::beacon::{
    configurations::GossipsubConfig,
    message::GossipsubMessage,
    topics::{GossipTopic, GossipTopicKind},
};
use ream_storage::{cache::BeaconCacheDB, tables::table::CustomTable};
use ream_validator_beacon::{
    attestation::single_attestation_to_attestation, blob_sidecars::compute_subnet_for_blob_sidecar,
    constants::SYNC_COMMITTEE_SUBNET_COUNT,
};
use tracing::{debug, error, info, trace, warn};
use tree_hash::TreeHash;

use crate::{
    block_lookup::{PendingGossipItem, import_validated_data_column},
    gossipsub::validate::{
        aggregate_and_proof::validate_aggregate_and_proof,
        attester_slashing::validate_attester_slashing,
        beacon_attestation::validate_beacon_attestation,
        beacon_block::validate_gossip_beacon_block,
        blob_sidecar::validate_blob_sidecar,
        bls_to_execution_change::validate_bls_to_execution_change,
        data_column_sidecar::validate_data_column_sidecar_full,
        light_client_finality_update::validate_light_client_finality_update,
        light_client_optimistic_update::validate_light_client_optimistic_update,
        proposer_slashing::validate_proposer_slashing,
        result::{DependencyValidationResult, ValidationResult},
        sync_committee::validate_sync_committee,
        sync_committee_contribution_and_proof::validate_sync_committee_contribution_and_proof,
        voluntary_exit::validate_voluntary_exit,
    },
};

pub struct UnknownParentGossipBlock {
    pub parent_root: alloy_primitives::B256,
    pub block: SignedBeaconBlock,
}

pub fn init_gossipsub_config_with_topics(history_length: Option<usize>) -> GossipsubConfig {
    let mut gossipsub_config = history_length.map_or_else(
        GossipsubConfig::default,
        GossipsubConfig::with_history_length,
    );
    let fork_digest = beacon_network_spec().fork_digest(
        beacon_network_spec().current_epoch(),
        genesis_validators_root(),
    );

    let mut topics = vec![
        GossipTopic {
            fork: fork_digest,
            kind: GossipTopicKind::BeaconBlock,
        },
        GossipTopic {
            fork: fork_digest,
            kind: GossipTopicKind::AggregateAndProof,
        },
        GossipTopic {
            fork: fork_digest,
            kind: GossipTopicKind::VoluntaryExit,
        },
        GossipTopic {
            fork: fork_digest,
            kind: GossipTopicKind::ProposerSlashing,
        },
        GossipTopic {
            fork: fork_digest,
            kind: GossipTopicKind::AttesterSlashing,
        },
        GossipTopic {
            fork: fork_digest,
            kind: GossipTopicKind::SyncCommitteeContributionAndProof,
        },
        GossipTopic {
            fork: fork_digest,
            kind: GossipTopicKind::BlsToExecutionChange,
        },
        GossipTopic {
            fork: fork_digest,
            kind: GossipTopicKind::LightClientFinalityUpdate,
        },
        GossipTopic {
            fork: fork_digest,
            kind: GossipTopicKind::LightClientOptimisticUpdate,
        },
    ];

    // Subnets
    for subnet_id in 0..beacon_network_spec().attestation_subnet_count {
        topics.push(GossipTopic {
            fork: fork_digest,
            kind: GossipTopicKind::BeaconAttestation(subnet_id),
        });
    }

    for subnet_id in 0..SYNC_COMMITTEE_SUBNET_COUNT {
        topics.push(GossipTopic {
            fork: fork_digest,
            kind: GossipTopicKind::SyncCommittee(subnet_id),
        });
    }

    if subscribes_to_blob_sidecars(beacon_network_spec().current_epoch()) {
        for subnet_id in 0..beacon_network_spec().blob_sidecar_subnet_count_electra {
            topics.push(GossipTopic {
                fork: fork_digest,
                kind: GossipTopicKind::BlobSidecar(subnet_id),
            });
        }
    }

    for subnet_id in 0..DATA_COLUMN_SIDECAR_SUBNET_COUNT {
        topics.push(GossipTopic {
            fork: fork_digest,
            kind: GossipTopicKind::DataColumnSidecar(subnet_id),
        });
    }

    gossipsub_config.set_topics(topics);

    gossipsub_config
}

/// Fulu deprecates the `blob_sidecar_{subnet_id}` topics: blob data travels as data columns from
/// FULU_FORK_EPOCH on (consensus-specs v1.7.0-alpha.11, fulu/p2p-interface.md).
fn subscribes_to_blob_sidecars(epoch: u64) -> bool {
    epoch < beacon_network_spec().fulu_fork_epoch
}

async fn import_gossip_attestation(
    beacon_chain: &BeaconChain,
    single_attestation: &SingleAttestation,
) -> anyhow::Result<()> {
    // Nothing here needs the store lock: the head snapshot is published by the writers and the
    // operation pool is independently synchronized.
    let head = beacon_chain.head()?;
    // Validation accepted the attestation against a head at most this old, so the head state
    // fixes its committee without being advanced.
    ensure!(
        head.state
            .determines_committees_of(compute_epoch_at_slot(single_attestation.data.slot)),
        "Head state is too far behind to compute the attestation's committee"
    );
    let attestation = single_attestation_to_attestation(single_attestation, &head.state)?;

    beacon_chain
        .operation_pool()
        .insert_attestation(attestation.clone(), single_attestation.committee_index);

    let should_process_attestation =
        head.current_slot >= single_attestation.data.slot + MIN_ATTESTATION_INCLUSION_DELAY;

    if should_process_attestation {
        beacon_chain
            .process_gossip_attestation(attestation, single_attestation.attester_index)
            .await?;
    }

    Ok(())
}

fn message_acceptance(validation_result: &ValidationResult) -> MessageAcceptance {
    match validation_result {
        ValidationResult::Accept => MessageAcceptance::Accept,
        ValidationResult::Reject(_) => MessageAcceptance::Reject,
        ValidationResult::Ignore(_) => MessageAcceptance::Ignore,
    }
}

/// Acceptance for the topics whose handler only reports a validation result. Gossipsub forwards a
/// message only when it is reported as ACCEPT, so a valid message must be reported as ACCEPT.
/// Rejections are still reported as IGNORE on these topics, so a validation bug here cannot get
/// honest peers penalized.
fn accepted_message_acceptance(validation_result: &ValidationResult) -> MessageAcceptance {
    match validation_result {
        ValidationResult::Accept => MessageAcceptance::Accept,
        ValidationResult::Reject(_) | ValidationResult::Ignore(_) => MessageAcceptance::Ignore,
    }
}

fn dependency_message_acceptance(
    validation_result: &DependencyValidationResult<impl Sized>,
) -> MessageAcceptance {
    match validation_result {
        DependencyValidationResult::Accept => MessageAcceptance::Accept,
        DependencyValidationResult::Reject(_) => MessageAcceptance::Reject,
        DependencyValidationResult::Ignore(_) => MessageAcceptance::Ignore,
        DependencyValidationResult::UnknownParent { .. } => MessageAcceptance::Ignore,
        // Fully validated messages should propagate even while their local import is deferred.
        DependencyValidationResult::ParentPendingAvailability { .. } => MessageAcceptance::Accept,
    }
}

/// Dispatches a gossipsub message to its appropriate handler. `on_valid_block` gets each block
/// that passed gossip validation, before its import starts.
pub async fn handle_gossipsub_message(
    message: Message,
    beacon_chain: &BeaconChain,
    cached_db: &BeaconCacheDB,
    pending_item: &mut Option<PendingGossipItem>,
    unknown_parent_block: &mut Option<UnknownParentGossipBlock>,
    on_valid_block: impl FnOnce(&SignedBeaconBlock),
) -> MessageAcceptance {
    match GossipsubMessage::decode(&message.topic, &message.data) {
        Ok(gossip_message) => match gossip_message {
            GossipsubMessage::BeaconBlock(signed_block) => {
                debug!(
                    "Beacon block received over gossipsub: slot: {}, root: {}",
                    signed_block.message.slot,
                    signed_block.message.block_root()
                );

                let tick_time = {
                    let duration = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("System time is before UNIX epoch");
                    duration.as_secs() + u64::from(duration.subsec_nanos() > 0)
                };
                if let Err(err) = beacon_chain.process_tick(tick_time).await {
                    warn!("Failed to process gossipsub tick before block validation: {err}");
                    return MessageAcceptance::Ignore;
                }

                let validation_result = match validate_gossip_beacon_block(
                    beacon_chain,
                    cached_db,
                    &signed_block,
                )
                .await
                {
                    Ok(result) => result,
                    Err(err) => {
                        warn!("Failed to validate gossipsub beacon block: {err}");
                        return MessageAcceptance::Ignore;
                    }
                };

                let acceptance = dependency_message_acceptance(&validation_result);
                match validation_result {
                    DependencyValidationResult::Accept => {
                        on_valid_block(&signed_block);
                        match beacon_chain.process_block(*signed_block).await {
                            Ok(BlockProcessingOutcome::Imported { .. }) => {}
                            Ok(BlockProcessingOutcome::PendingAvailability { .. }) => {}
                            Err(err) => {
                                error!("Failed to process gossipsub beacon block: {err}");
                            }
                        }
                    }
                    DependencyValidationResult::Ignore(reason) => {
                        warn!("Ignoring gossipsub beacon block: {reason}");
                    }
                    DependencyValidationResult::Reject(reason) => {
                        warn!("Rejecting gossipsub beacon block: {reason}");
                    }
                    DependencyValidationResult::UnknownParent { parent_root } => {
                        *unknown_parent_block = Some(UnknownParentGossipBlock {
                            parent_root,
                            block: *signed_block,
                        });
                    }
                    DependencyValidationResult::ParentPendingAvailability {
                        parent_root: _,
                        validated,
                    } => {
                        *pending_item = Some(PendingGossipItem::Block { block: validated });
                    }
                }
                acceptance
            }
            GossipsubMessage::BeaconAttestation((single_attestation, subnet_id)) => {
                trace!(
                    "Beacon Attestation received over gossipsub: root: {}",
                    single_attestation.tree_hash_root()
                );

                let validation_result = match validate_beacon_attestation(
                    &single_attestation,
                    beacon_chain,
                    subnet_id,
                    cached_db,
                )
                .await
                {
                    Ok(validation_result) => validation_result,
                    Err(err) => {
                        trace!("Could not validate attestation: {err}");
                        return MessageAcceptance::Ignore;
                    }
                };

                let acceptance = message_acceptance(&validation_result);
                match validation_result {
                    ValidationResult::Accept => {
                        if let Err(err) =
                            import_gossip_attestation(beacon_chain, &single_attestation).await
                        {
                            warn!("Failed to import gossipsub beacon attestation: {err}");
                        }
                    }
                    ValidationResult::Reject(reason) => {
                        info!("Attestation rejected: {reason}");
                    }
                    ValidationResult::Ignore(reason) => {
                        debug!("Attestation ignored: {reason}");
                    }
                }
                acceptance
            }
            GossipsubMessage::BlsToExecutionChange(signed_bls_to_execution_change) => {
                debug!(
                    "BLS to Execution Change received over gossipsub: root: {}",
                    signed_bls_to_execution_change.tree_hash_root()
                );

                match validate_bls_to_execution_change(
                    &signed_bls_to_execution_change,
                    beacon_chain,
                    cached_db,
                )
                .await
                {
                    Ok(validation_result) => {
                        let acceptance = accepted_message_acceptance(&validation_result);
                        match validation_result {
                            ValidationResult::Accept => {}
                            ValidationResult::Reject(reason) => {
                                info!("BLS to Execution Change rejected: {reason}");
                            }
                            ValidationResult::Ignore(reason) => {
                                debug!("BLS to Execution Change ignored: {reason}");
                            }
                        }
                        acceptance
                    }
                    Err(err) => {
                        error!("Could not validate BLS to Execution Change: {err}");
                        MessageAcceptance::Ignore
                    }
                }
            }
            GossipsubMessage::AggregateAndProof(aggregate_and_proof) => {
                debug!(
                    "Aggregate And Proof received over gossipsub: root: {}",
                    aggregate_and_proof.tree_hash_root()
                );

                match validate_aggregate_and_proof(&aggregate_and_proof, beacon_chain, cached_db)
                    .await
                {
                    Ok(validation_result) => {
                        let acceptance = accepted_message_acceptance(&validation_result);
                        match validation_result {
                            ValidationResult::Accept => {}
                            ValidationResult::Reject(reason) => {
                                info!("Aggregate and proof rejected: {reason}");
                            }
                            ValidationResult::Ignore(reason) => {
                                debug!("Aggregate and proof ignored: {reason}");
                            }
                        }
                        acceptance
                    }
                    Err(err) => {
                        error!("Could not validate aggregate and proof: {err}");
                        MessageAcceptance::Ignore
                    }
                }
            }
            GossipsubMessage::SyncCommittee((sync_committee, subnet_id)) => {
                trace!(
                    "Sync Committee received over gossipsub: root: {}",
                    sync_committee.tree_hash_root()
                );

                match validate_sync_committee(&sync_committee, beacon_chain, subnet_id, cached_db)
                    .await
                {
                    Ok(validation_result) => {
                        let acceptance = accepted_message_acceptance(&validation_result);
                        match validation_result {
                            ValidationResult::Accept => {}
                            ValidationResult::Reject(reason) => {
                                info!("Sync committee message rejected: {reason}");
                            }
                            ValidationResult::Ignore(reason) => {
                                trace!("Sync committee message ignored: {reason}");
                            }
                        }
                        acceptance
                    }
                    Err(err) => {
                        error!("Could not validate sync committee message: {err}");
                        MessageAcceptance::Ignore
                    }
                }
            }
            GossipsubMessage::SyncCommitteeContributionAndProof(signed_contribution_and_proof) => {
                debug!(
                    "Sync Committee Contribution And Proof received over gossipsub: root: {}",
                    signed_contribution_and_proof.tree_hash_root()
                );

                match validate_sync_committee_contribution_and_proof(
                    beacon_chain,
                    cached_db,
                    &signed_contribution_and_proof,
                )
                .await
                {
                    Ok(validation_result) => {
                        let acceptance = accepted_message_acceptance(&validation_result);
                        match validation_result {
                            ValidationResult::Accept => {}

                            ValidationResult::Reject(reason) => {
                                info!("Sync committee contribution and proof rejected: {reason}");
                            }
                            ValidationResult::Ignore(reason) => {
                                debug!("Sync committee contribution and proof ignored: {reason}");
                            }
                        }
                        acceptance
                    }
                    Err(err) => {
                        error!("Could not validate sync committee contribution and proof: {err}");
                        MessageAcceptance::Ignore
                    }
                }
            }
            GossipsubMessage::AttesterSlashing(attester_slashing) => {
                debug!(
                    "Attester Slashing received over gossipsub: root: {}",
                    attester_slashing.tree_hash_root()
                );

                match validate_attester_slashing(&attester_slashing, beacon_chain, cached_db).await
                {
                    Ok(validation_result) => {
                        let acceptance = accepted_message_acceptance(&validation_result);
                        match validation_result {
                            ValidationResult::Accept => {
                                if let Err(err) = beacon_chain
                                    .process_attester_slashing(*attester_slashing)
                                    .await
                                {
                                    error!("Failed to process gossipsub attester slashing: {err}");
                                }
                            }
                            ValidationResult::Reject(reason) => {
                                info!("Attester slashing rejected: {reason}");
                            }
                            ValidationResult::Ignore(reason) => {
                                debug!("Attester slashing ignored: {reason}");
                            }
                        }
                        acceptance
                    }
                    Err(err) => {
                        error!("Could not validate attester slashing: {err}");
                        MessageAcceptance::Ignore
                    }
                }
            }
            GossipsubMessage::ProposerSlashing(proposer_slashing) => {
                debug!(
                    "Proposer Slashing received over gossipsub: root: {}",
                    proposer_slashing.tree_hash_root()
                );

                match validate_proposer_slashing(&proposer_slashing, beacon_chain, cached_db).await
                {
                    Ok(validation_result) => {
                        let acceptance = accepted_message_acceptance(&validation_result);
                        match validation_result {
                            ValidationResult::Accept => {}
                            ValidationResult::Reject(reason) => {
                                info!("Proposer slashing rejected: {reason}");
                            }
                            ValidationResult::Ignore(reason) => {
                                debug!("Proposer slashing ignored: {reason}");
                            }
                        }
                        acceptance
                    }
                    Err(err) => {
                        error!("Could not validate proposer slashing: {err}");
                        MessageAcceptance::Ignore
                    }
                }
            }
            GossipsubMessage::BlobSidecar(blob_sidecar) => {
                debug!(
                    "Blob Sidecar received over gossipsub: root: {}",
                    blob_sidecar.tree_hash_root()
                );
                match validate_blob_sidecar(
                    beacon_chain,
                    &blob_sidecar,
                    compute_subnet_for_blob_sidecar(blob_sidecar.index),
                    cached_db,
                )
                .await
                {
                    Ok(validation_result) => {
                        let acceptance = accepted_message_acceptance(&validation_result);
                        match validation_result {
                            ValidationResult::Accept => {
                                let provider = beacon_chain.db().blobs_and_proofs_provider();
                                let insert_result = tokio::task::spawn_blocking(move || {
                                    provider.insert(
                                        BlobIdentifier::new(
                                            blob_sidecar
                                                .signed_block_header
                                                .message
                                                .tree_hash_root(),
                                            blob_sidecar.index,
                                        ),
                                        BlobAndProofV1 {
                                            blob: blob_sidecar.blob,
                                            proof: blob_sidecar.kzg_proof,
                                        },
                                    )
                                })
                                .await;
                                match insert_result {
                                    Ok(Ok(())) => {}
                                    Ok(Err(err)) => error!("Failed to insert blob_sidecar: {err}"),
                                    Err(err) => error!("Blob persistence task failed: {err}"),
                                }
                            }
                            ValidationResult::Reject(reason) => {
                                info!("Blob_sidecar rejected: {reason}");
                            }
                            ValidationResult::Ignore(reason) => {
                                debug!("Blob_sidecar ignored: {reason}");
                            }
                        }
                        acceptance
                    }
                    Err(err) => {
                        error!("Could not validate blob_sidecar: {err}");
                        MessageAcceptance::Ignore
                    }
                }
            }
            GossipsubMessage::DataColumnSidecar(data_column_sidecar) => {
                debug!(
                    "Data Column Sidecar received over gossipsub: index: {}, root: {}",
                    data_column_sidecar.index,
                    data_column_sidecar
                        .signed_block_header
                        .message
                        .tree_hash_root()
                );

                // Extract subnet_id from the gossip topic
                let subnet_id = match GossipTopic::from_topic_hash(&message.topic) {
                    Ok(topic) => match topic.kind {
                        GossipTopicKind::DataColumnSidecar(id) => id,
                        _ => {
                            error!("Unexpected topic kind for data column sidecar");
                            return MessageAcceptance::Ignore;
                        }
                    },
                    Err(err) => {
                        error!("Failed to parse topic for data column sidecar: {err}");
                        return MessageAcceptance::Ignore;
                    }
                };

                let current_time_ms = match SystemTime::now().duration_since(UNIX_EPOCH) {
                    Ok(duration) => u64::try_from(duration.as_millis()).unwrap_or(u64::MAX),
                    Err(err) => {
                        error!("Failed to get current time for data column validation: {err}");
                        return MessageAcceptance::Ignore;
                    }
                };

                let validation_result = match validate_data_column_sidecar_full(
                    &data_column_sidecar,
                    beacon_chain,
                    current_time_ms,
                    subnet_id,
                    cached_db,
                )
                .await
                {
                    Ok(validation_result) => validation_result,
                    Err(err) => {
                        error!("Could not validate data_column_sidecar: {err}");
                        return MessageAcceptance::Ignore;
                    }
                };

                let acceptance = dependency_message_acceptance(&validation_result);
                match validation_result {
                    DependencyValidationResult::Accept => {
                        if let Err(err) =
                            import_validated_data_column(beacon_chain, *data_column_sidecar).await
                        {
                            error!("Failed to import data_column_sidecar: {err}");
                        }
                    }
                    DependencyValidationResult::Reject(reason) => {
                        info!("Data column sidecar rejected: {reason}");
                    }
                    DependencyValidationResult::Ignore(reason) => {
                        debug!("Data column sidecar ignored: {reason}");
                    }
                    DependencyValidationResult::UnknownParent { .. } => {
                        unreachable!("data column validation cannot return unknown-parent")
                    }
                    DependencyValidationResult::ParentPendingAvailability {
                        parent_root: _,
                        validated,
                    } => {
                        *pending_item = Some(PendingGossipItem::Column { column: validated });
                    }
                }
                acceptance
            }
            GossipsubMessage::LightClientFinalityUpdate(light_client_finality_update) => {
                debug!(
                    "Light Client Finality Update received over gossipsub: root: {}",
                    light_client_finality_update.tree_hash_root()
                );

                match validate_light_client_finality_update(
                    &light_client_finality_update,
                    beacon_chain,
                    cached_db,
                )
                .await
                {
                    Ok(validation_result) => {
                        let acceptance = accepted_message_acceptance(&validation_result);
                        match validation_result {
                            ValidationResult::Accept => {}
                            ValidationResult::Reject(reason) => {
                                info!("Light client finality update rejected: {reason}");
                            }
                            ValidationResult::Ignore(reason) => {
                                debug!("Light client finality update ignored: {reason}");
                            }
                        }
                        acceptance
                    }
                    Err(err) => {
                        error!("Could not validate light client finality update: {err}");
                        MessageAcceptance::Ignore
                    }
                }
            }
            GossipsubMessage::LightClientOptimisticUpdate(light_client_optimistic_update) => {
                debug!(
                    "Light Client Optimistic Update received over gossipsub: root: {}",
                    light_client_optimistic_update.tree_hash_root()
                );

                match validate_light_client_optimistic_update(
                    &light_client_optimistic_update,
                    beacon_chain,
                    cached_db,
                )
                .await
                {
                    Ok(validation_result) => {
                        let acceptance = accepted_message_acceptance(&validation_result);
                        match validation_result {
                            ValidationResult::Accept => {}
                            ValidationResult::Ignore(reason) => {
                                debug!("Light client optimistic update ignored: {reason}");
                            }
                            ValidationResult::Reject(reason) => {
                                info!("Light client optimistic update rejected: {reason}");
                            }
                        }
                        acceptance
                    }
                    Err(err) => {
                        error!("Could not validate light client optimistic update: {err}");
                        MessageAcceptance::Ignore
                    }
                }
            }
            GossipsubMessage::VoluntaryExit(voluntary_exit) => {
                debug!(
                    "Voluntary Exit received over gossipsub: root: {}",
                    voluntary_exit.tree_hash_root()
                );

                match validate_voluntary_exit(&voluntary_exit, beacon_chain, cached_db).await {
                    Ok(validation_result) => {
                        let acceptance = accepted_message_acceptance(&validation_result);
                        match validation_result {
                            ValidationResult::Accept => {}
                            ValidationResult::Reject(reason) => {
                                info!("voluntary_exit rejected: {reason}");
                            }
                            ValidationResult::Ignore(reason) => {
                                debug!("voluntary_exit ignored: {reason}");
                            }
                        }
                        acceptance
                    }
                    Err(err) => {
                        error!("Could not validate voluntary_exit: {err}");
                        MessageAcceptance::Ignore
                    }
                }
            }
        },
        Err(err) => {
            trace!("Failed to decode gossip message: {err:?}");
            MessageAcceptance::Reject
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use libp2p::gossipsub::TopicHash;
    use ream_consensus_beacon::data_column_sidecar::{Cell, DataColumnSidecar};
    use ream_consensus_misc::{
        beacon_block_header::SignedBeaconBlockHeader,
        constants::beacon::FULU_FORK_EPOCH,
        polynomial_commitments::{kzg_commitment::KZGCommitment, kzg_proof::KZGProof},
    };
    use ream_network_spec::networks::initialize_test_network_spec;
    use ream_operation_pool::OperationPool;
    use ream_storage::db::ReamDB;
    use ream_sync_committee_pool::SyncCommitteePool;
    use ssz::Encode;
    use ssz_types::{FixedVector, VariableList};
    use tempfile::TempDir;

    use super::*;

    /// Kept alongside the chain so the dir isn't dropped (and cleaned up) until the test ends.
    fn test_beacon_chain() -> (TempDir, BeaconChain) {
        let data_dir = tempfile::tempdir().expect("tempdir should be created");
        let beacon_db = ReamDB::new(data_dir.path().to_path_buf())
            .expect("ReamDB should init")
            .init_beacon_db()
            .expect("beacon DB tables should init");
        let beacon_chain = BeaconChain::new(
            beacon_db,
            Arc::new(OperationPool::default()),
            Arc::new(SyncCommitteePool::default()),
            None,
            None,
        );
        (data_dir, beacon_chain)
    }

    fn sidecar_with_index(index: u64) -> DataColumnSidecar {
        DataColumnSidecar {
            index,
            column: VariableList::new(vec![Cell::default()]).expect("single-entry list fits"),
            kzg_commitments: VariableList::new(vec![KZGCommitment::empty_for_testing()])
                .expect("single-entry list fits"),
            kzg_proofs: VariableList::new(vec![KZGProof::default()])
                .expect("single-entry list fits"),
            signed_block_header: SignedBeaconBlockHeader::default(),
            kzg_commitments_inclusion_proof: FixedVector::default(),
        }
    }

    #[tokio::test]
    async fn data_column_sidecar_wrong_subnet_is_rejected_and_reported() {
        initialize_test_network_spec();
        let (_data_dir, beacon_chain) = test_beacon_chain();
        let cached_db = BeaconCacheDB::default();

        // Subnet 5 (index % 128) delivered on topic subnet 6 - a mismatch rejected early.
        let sidecar = sidecar_with_index(5);
        let topic: TopicHash = GossipTopic {
            // Must be the real digest: `decode` rejects any topic whose fork doesn't match.
            fork: beacon_network_spec().fork_digest(FULU_FORK_EPOCH, genesis_validators_root()),
            kind: GossipTopicKind::DataColumnSidecar(6),
        }
        .into();
        let message = Message {
            source: None,
            data: sidecar.as_ssz_bytes(),
            sequence_number: None,
            topic,
        };
        let mut pending_item = None;
        let mut unknown_parent_block = None;
        let acceptance = handle_gossipsub_message(
            message,
            &beacon_chain,
            &cached_db,
            &mut pending_item,
            &mut unknown_parent_block,
            |_| {},
        )
        .await;

        assert!(
            matches!(acceptance, MessageAcceptance::Reject),
            "expected Reject, got {acceptance:?}"
        );
    }

    #[test]
    fn blob_sidecar_topics_end_at_fulu() {
        initialize_test_network_spec();
        let fulu_fork_epoch = beacon_network_spec().fulu_fork_epoch;
        assert!(subscribes_to_blob_sidecars(fulu_fork_epoch - 1));
        assert!(!subscribes_to_blob_sidecars(fulu_fork_epoch));
        assert!(!subscribes_to_blob_sidecars(fulu_fork_epoch + 1));
    }

    #[test]
    fn only_a_passed_validation_is_forwarded_on_report_only_topics() {
        assert!(matches!(
            accepted_message_acceptance(&ValidationResult::Accept),
            MessageAcceptance::Accept
        ));
        assert!(matches!(
            accepted_message_acceptance(&ValidationResult::Ignore("seen".to_string())),
            MessageAcceptance::Ignore
        ));
        assert!(matches!(
            accepted_message_acceptance(&ValidationResult::Reject("invalid".to_string())),
            MessageAcceptance::Ignore
        ));
    }
}
