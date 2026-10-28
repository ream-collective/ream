use std::sync::Arc;

use libp2p::{PeerId, swarm::ConnectionId};
use ream_consensus_beacon::{blob_sidecar::BlobIdentifier, data_column_sidecar::ColumnIdentifier};
use ream_consensus_misc::misc::compute_epoch_at_slot;
use ream_fork_choice_beacon::store::get_current_slot_from_db;
use ream_network_spec::networks::beacon::beacon_network_spec;
use ream_p2p::network::beacon::network_state::NetworkState;
use ream_req_resp::beacon::messages::{
    BeaconRequestMessage, BeaconResponseMessage,
    blob_sidecars::{BlobSidecarsByRangeV1Request, BlobSidecarsByRootV1Request},
    blocks::{BeaconBlocksByRangeV2Request, BeaconBlocksByRootV2Request},
    data_column_sidecars::{DataColumnSidecarsByRangeV1Request, DataColumnSidecarsByRootV1Request},
};
use ream_storage::{
    db::beacon::BeaconDB,
    tables::{
        beacon::backfill::BackfillMode,
        table::{CustomTable, REDBTable},
    },
};
use tracing::{info, trace, warn};

use crate::p2p_sender::P2PSender;

/// Whether `[start_slot, end_slot)` reaches into blocks we are required to serve but have not
/// backfilled yet. An empty answer there would wrongly read as skipped slots.
///
/// Databases without backfill metadata make no coverage promise and keep answering with
/// whatever they hold.
fn requests_missing_blocks(
    mode: &BackfillMode,
    start_slot: u64,
    end_slot: u64,
    retention_start_slot: u64,
) -> bool {
    let BackfillMode::Checkpoint(meta) = mode else {
        return false;
    };
    start_slot.max(retention_start_slot) < end_slot.min(meta.blocks.frontier.oldest_block_slot)
}

/// Whether `[start_slot, end_slot)` reaches into slots inside the sidecar retention window for
/// which we have not confirmed every required data column.
fn requests_missing_data_columns(
    mode: &BackfillMode,
    start_slot: u64,
    end_slot: u64,
    retention_start_slot: u64,
) -> bool {
    let BackfillMode::Checkpoint(meta) = mode else {
        return false;
    };
    start_slot.max(retention_start_slot) < end_slot.min(meta.sidecars_available_from())
}

pub async fn handle_req_resp_message(
    peer_id: PeerId,
    stream_id: u64,
    connection_id: ConnectionId,
    message: BeaconRequestMessage,
    p2p_sender: &P2PSender,
    ream_db: &BeaconDB,
    network_state: Arc<NetworkState>,
) {
    match message {
        BeaconRequestMessage::Status(status) => {
            trace!(
                ?peer_id,
                ?stream_id,
                ?connection_id,
                ?status,
                "Received Status request"
            );

            p2p_sender.send_response(
                peer_id,
                connection_id,
                stream_id,
                BeaconResponseMessage::Status(network_state.status.read().clone()),
            );

            p2p_sender.send_end_of_stream_response(peer_id, connection_id, stream_id);
        }
        BeaconRequestMessage::BeaconBlocksByRange(BeaconBlocksByRangeV2Request {
            start_slot,
            count,
            ..
        }) => {
            let max_request_blocks = beacon_network_spec().max_request_blocks;
            if count > max_request_blocks {
                p2p_sender.send_invalid_request(
                    peer_id,
                    connection_id,
                    stream_id,
                    &format!("Requested count {count} exceeds maximum {max_request_blocks}"),
                );
                return;
            }
            let Some(end_slot_exclusive) = start_slot.checked_add(count) else {
                p2p_sender.send_invalid_request(
                    peer_id,
                    connection_id,
                    stream_id,
                    &format!("start_slot {start_slot} + count {count} overflows"),
                );
                return;
            };

            let mode = match ream_db.cached_backfill_mode() {
                Ok(mode) => mode,
                Err(err) => {
                    p2p_sender.send_error_response(
                        peer_id,
                        connection_id,
                        stream_id,
                        &format!("Failed to read backfill metadata: {err:?}"),
                    );
                    return;
                }
            };
            let current_epoch = match get_current_slot_from_db(ream_db) {
                Ok(current_slot) => compute_epoch_at_slot(current_slot),
                Err(err) => {
                    p2p_sender.send_error_response(
                        peer_id,
                        connection_id,
                        stream_id,
                        &format!("Failed to read current slot: {err:?}"),
                    );
                    return;
                }
            };
            if requests_missing_blocks(
                &mode,
                start_slot,
                end_slot_exclusive,
                beacon_network_spec().backfill_target_slot(current_epoch),
            ) {
                p2p_sender.send_resource_unavailable(
                    peer_id,
                    connection_id,
                    stream_id,
                    "Requested blocks are not backfilled yet",
                );
                return;
            }

            let head = network_state.status.read().head_root;
            let head = if head == alloy_primitives::B256::ZERO {
                match &mode {
                    BackfillMode::Checkpoint(meta) => meta.origin.root,
                    _ => head,
                }
            } else {
                head
            };
            let roots = match ream_db.canonical_roots_in_range(head, start_slot, end_slot_exclusive)
            {
                Ok(roots) => roots,
                Err(err) => {
                    p2p_sender.send_error_response(
                        peer_id,
                        connection_id,
                        stream_id,
                        &format!("Failed to read canonical history: {err:?}"),
                    );
                    return;
                }
            };
            for (_slot, block_root) in roots {
                let Ok(Some(block)) = ream_db.block_provider().get(block_root) else {
                    trace!("No block found for root {block_root}");
                    p2p_sender.send_error_response(
                        peer_id,
                        connection_id,
                        stream_id,
                        &format!("No block found for root {block_root}"),
                    );
                    return;
                };

                p2p_sender.send_response(
                    peer_id,
                    connection_id,
                    stream_id,
                    BeaconResponseMessage::BeaconBlocksByRange(block),
                );
            }

            p2p_sender.send_end_of_stream_response(peer_id, connection_id, stream_id);
        }
        BeaconRequestMessage::BeaconBlocksByRoot(BeaconBlocksByRootV2Request { inner }) => {
            for block_root in inner {
                // A responder skips roots it does not have; the request carries no slot to
                // judge them by.
                let block = match ream_db.block_provider().get(block_root) {
                    Ok(Some(block)) => block,
                    Ok(None) => {
                        trace!("No block found for root {block_root}");
                        continue;
                    }
                    Err(err) => {
                        p2p_sender.send_error_response(
                            peer_id,
                            connection_id,
                            stream_id,
                            &format!("Failed to read block {block_root}: {err:?}"),
                        );
                        return;
                    }
                };

                p2p_sender.send_response(
                    peer_id,
                    connection_id,
                    stream_id,
                    BeaconResponseMessage::BeaconBlocksByRoot(block),
                );
            }

            p2p_sender.send_end_of_stream_response(peer_id, connection_id, stream_id);
        }
        BeaconRequestMessage::BlobSidecarsByRange(BlobSidecarsByRangeV1Request {
            start_slot,
            count,
        }) => {
            let max_request_blocks = beacon_network_spec().max_request_blocks_deneb;
            if count > max_request_blocks {
                p2p_sender.send_invalid_request(
                    peer_id,
                    connection_id,
                    stream_id,
                    &format!("Requested count {count} exceeds maximum {max_request_blocks}"),
                );
                return;
            }
            let Some(end_slot_exclusive) = start_slot.checked_add(count) else {
                p2p_sender.send_invalid_request(
                    peer_id,
                    connection_id,
                    stream_id,
                    &format!("start_slot {start_slot} + count {count} overflows"),
                );
                return;
            };

            for slot in start_slot..end_slot_exclusive {
                let block_root = match ream_db.slot_index_provider().get(slot) {
                    Ok(Some(block_root)) => block_root,
                    Ok(None) => {
                        trace!("No block root found for slot {slot}");
                        continue;
                    }
                    Err(err) => {
                        p2p_sender.send_error_response(
                            peer_id,
                            connection_id,
                            stream_id,
                            &format!("Failed to read slot index for slot {slot}: {err:?}"),
                        );
                        return;
                    }
                };
                let Ok(Some(block)) = ream_db.block_provider().get(block_root) else {
                    trace!("No block found for root {block_root}");
                    p2p_sender.send_error_response(
                        peer_id,
                        connection_id,
                        stream_id,
                        &format!("No block found for root {block_root}"),
                    );
                    return;
                };

                for index in 0..block.message.body.blob_kzg_commitments.len() {
                    let Ok(Some(blob_and_proof)) = ream_db
                        .blobs_and_proofs_provider()
                        .get(BlobIdentifier::new(block_root, index as u64))
                    else {
                        trace!(
                            "No blob and proof found for block root {block_root} and index {index}"
                        );
                        p2p_sender.send_error_response(
                            peer_id,
                            connection_id,
                            stream_id,
                            &format!("No blob and proof found for block root {block_root} and index {index}"),
                        );
                        return;
                    };

                    let blob_sidecar = match block.blob_sidecar(blob_and_proof, index as u64) {
                        Ok(blob_sidecar) => blob_sidecar,
                        Err(err) => {
                            info!(
                                "Failed to create blob sidecar for block root {block_root} and index {index}: {err}"
                            );
                            p2p_sender.send_error_response(
                                peer_id,
                                connection_id,
                                stream_id,
                                &format!("Failed to create blob sidecar: {err}"),
                            );
                            return;
                        }
                    };

                    p2p_sender.send_response(
                        peer_id,
                        connection_id,
                        stream_id,
                        BeaconResponseMessage::BlobSidecarsByRange(blob_sidecar),
                    );
                }
            }

            p2p_sender.send_end_of_stream_response(peer_id, connection_id, stream_id);
        }
        BeaconRequestMessage::BlobSidecarsByRoot(BlobSidecarsByRootV1Request { inner }) => {
            for blob_identifier in inner {
                let Ok(Some(blob_and_proof)) =
                    ream_db.blobs_and_proofs_provider().get(blob_identifier)
                else {
                    trace!("No blob and proof found for identifier {blob_identifier:?}");
                    p2p_sender.send_error_response(
                        peer_id,
                        connection_id,
                        stream_id,
                        &format!("No blob and proof found for identifier {blob_identifier:?}"),
                    );
                    return;
                };

                let Ok(Some(block)) = ream_db.block_provider().get(blob_identifier.block_root)
                else {
                    trace!("No block found for root {}", blob_identifier.block_root);
                    p2p_sender.send_error_response(
                        peer_id,
                        connection_id,
                        stream_id,
                        &format!("No block found for root {}", blob_identifier.block_root),
                    );
                    return;
                };

                let blob_sidecar = match block.blob_sidecar(blob_and_proof, blob_identifier.index) {
                    Ok(blob_sidecar) => blob_sidecar,
                    Err(err) => {
                        info!(
                            "Failed to create blob sidecar for identifier {blob_identifier:?}: {err}"
                        );
                        p2p_sender.send_error_response(
                            peer_id,
                            connection_id,
                            stream_id,
                            &format!("Failed to create blob sidecar: {err}"),
                        );
                        return;
                    }
                };

                p2p_sender.send_response(
                    peer_id,
                    connection_id,
                    stream_id,
                    BeaconResponseMessage::BlobSidecarsByRoot(blob_sidecar),
                );
            }
            p2p_sender.send_end_of_stream_response(peer_id, connection_id, stream_id);
        }
        BeaconRequestMessage::DataColumnSidecarsByRange(DataColumnSidecarsByRangeV1Request {
            start_slot,
            count,
            columns,
        }) => {
            let max_request_blocks = beacon_network_spec().max_request_blocks_deneb;
            if count > max_request_blocks {
                p2p_sender.send_invalid_request(
                    peer_id,
                    connection_id,
                    stream_id,
                    &format!("Requested count {count} exceeds maximum {max_request_blocks}"),
                );
                return;
            }
            let Some(end_slot_exclusive) = start_slot.checked_add(count) else {
                p2p_sender.send_invalid_request(
                    peer_id,
                    connection_id,
                    stream_id,
                    &format!("start_slot {start_slot} + count {count} overflows"),
                );
                return;
            };

            let mode = match ream_db.cached_backfill_mode() {
                Ok(mode) => mode,
                Err(err) => {
                    p2p_sender.send_error_response(
                        peer_id,
                        connection_id,
                        stream_id,
                        &format!("Failed to read backfill metadata: {err:?}"),
                    );
                    return;
                }
            };
            let current_epoch = match get_current_slot_from_db(ream_db) {
                Ok(current_slot) => compute_epoch_at_slot(current_slot),
                Err(err) => {
                    p2p_sender.send_error_response(
                        peer_id,
                        connection_id,
                        stream_id,
                        &format!("Failed to read current slot: {err:?}"),
                    );
                    return;
                }
            };
            if requests_missing_data_columns(
                &mode,
                start_slot,
                end_slot_exclusive,
                beacon_network_spec().data_column_retention_start_slot(current_epoch),
            ) {
                p2p_sender.send_resource_unavailable(
                    peer_id,
                    connection_id,
                    stream_id,
                    "Requested data column sidecars are not available yet",
                );
                return;
            }

            let head = network_state.status.read().head_root;
            let head = if head == alloy_primitives::B256::ZERO {
                match &mode {
                    BackfillMode::Checkpoint(meta) => meta.origin.root,
                    _ => head,
                }
            } else {
                head
            };
            let roots = match ream_db.canonical_roots_in_range(head, start_slot, end_slot_exclusive)
            {
                Ok(roots) => roots,
                Err(err) => {
                    p2p_sender.send_error_response(
                        peer_id,
                        connection_id,
                        stream_id,
                        &format!("Failed to read canonical history: {err:?}"),
                    );
                    return;
                }
            };
            for (_slot, block_root) in roots {
                for &column_index in &columns {
                    let column_identifier = ColumnIdentifier::new(block_root, column_index);
                    let Ok(Some(column_sidecar)) =
                        ream_db.column_sidecars_provider().get(column_identifier)
                    else {
                        trace!(
                            "No column sidecar found for block root {block_root} and index {column_index}"
                        );
                        continue;
                    };

                    p2p_sender.send_response(
                        peer_id,
                        connection_id,
                        stream_id,
                        BeaconResponseMessage::DataColumnSidecarsByRange(column_sidecar),
                    );
                }
            }

            p2p_sender.send_end_of_stream_response(peer_id, connection_id, stream_id);
        }
        BeaconRequestMessage::DataColumnSidecarsByRoot(DataColumnSidecarsByRootV1Request {
            inner,
        }) => {
            for identifier in inner {
                for &column_index in &identifier.columns {
                    let column_identifier =
                        ColumnIdentifier::new(identifier.block_root, column_index);
                    let Ok(Some(column_sidecar)) =
                        ream_db.column_sidecars_provider().get(column_identifier)
                    else {
                        trace!(
                            "No column sidecar found for block root {} and index {column_index}",
                            identifier.block_root
                        );
                        continue;
                    };

                    p2p_sender.send_response(
                        peer_id,
                        connection_id,
                        stream_id,
                        BeaconResponseMessage::DataColumnSidecarsByRoot(column_sidecar),
                    );
                }
            }

            p2p_sender.send_end_of_stream_response(peer_id, connection_id, stream_id);
        }
        _ => warn!("This message shouldn't be handled in the network manager: {message:?}"),
    };
}

#[cfg(test)]
mod tests {
    use alloy_primitives::B256;
    use ream_consensus_beacon::electra::{
        beacon_block::{BeaconBlock, SignedBeaconBlock},
        beacon_state::BeaconState,
    };
    use ream_network_spec::networks::initialize_test_network_spec;
    use ream_p2p::network::beacon::channel::P2PMessage;
    use ream_req_resp::{
        handler::RespMessage, inbound_protocol::ResponseCode, messages::ResponseMessage,
    };
    use ream_storage::{
        db::ReamDB,
        tables::{
            beacon::backfill::{
                BackfillMeta, BlockBackfillState, BlockCoverage, Frontier, Origin, SidecarCoverage,
            },
            field::REDBField,
        },
    };
    use tokio::sync::mpsc;
    use tree_hash::TreeHash;

    use super::*;

    fn serving_db() -> (tempfile::TempDir, BeaconDB, B256, Arc<NetworkState>) {
        initialize_test_network_spec();
        let dir = tempfile::tempdir().unwrap();
        let db = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        db.begin_bootstrap().unwrap();
        let state = BeaconState {
            slot: beacon_network_spec().fulu_fork_epoch
                * ream_consensus_misc::constants::beacon::SLOTS_PER_EPOCH
                + 640,
            genesis_time: Default::default(),
            genesis_validators_root: Default::default(),
            fork: ream_consensus_misc::fork::Fork {
                previous_version: Default::default(),
                current_version: Default::default(),
                epoch: 0,
            },
            latest_block_header: Default::default(),
            block_roots: Default::default(),
            state_roots: Default::default(),
            historical_roots: Default::default(),
            eth1_data: Default::default(),
            eth1_data_votes: Default::default(),
            eth1_deposit_index: Default::default(),
            validators: Default::default(),
            balances: Default::default(),
            randao_mixes: Default::default(),
            slashings: Default::default(),
            previous_epoch_participation: Default::default(),
            current_epoch_participation: Default::default(),
            justification_bits: Default::default(),
            previous_justified_checkpoint: Default::default(),
            current_justified_checkpoint: Default::default(),
            finalized_checkpoint: Default::default(),
            inactivity_scores: Default::default(),
            current_sync_committee: Arc::new(
                ream_consensus_beacon::sync_committee::SyncCommittee {
                    public_keys: Default::default(),
                    aggregate_public_key: Default::default(),
                },
            ),
            next_sync_committee: Arc::new(ream_consensus_beacon::sync_committee::SyncCommittee {
                public_keys: Default::default(),
                aggregate_public_key: Default::default(),
            }),
            latest_execution_payload_header: Default::default(),
            next_withdrawal_index: Default::default(),
            next_withdrawal_validator_index: Default::default(),
            historical_summaries: Default::default(),
            deposit_requests_start_index: Default::default(),
            deposit_balance_to_consume: Default::default(),
            exit_balance_to_consume: Default::default(),
            earliest_exit_epoch: Default::default(),
            consolidation_balance_to_consume: Default::default(),
            earliest_consolidation_epoch: Default::default(),
            pending_deposits: Default::default(),
            pending_partial_withdrawals: Default::default(),
            pending_consolidations: Default::default(),
            proposer_lookahead: Default::default(),
            caches: Default::default(),
        };
        let mut block = SignedBeaconBlock {
            message: BeaconBlock::default(),
            signature: Default::default(),
        };
        block.message.slot = state.slot;
        block.message.state_root = state.tree_hash_root();
        let root = block.message.tree_hash_root();
        let mut meta = match checkpoint(640, Some(640)) {
            BackfillMode::Checkpoint(meta) => meta,
            _ => unreachable!(),
        };
        meta.origin.slot = state.slot;
        meta.blocks.frontier.oldest_block_slot = state.slot;
        meta.sidecars.frontier = Some(state.slot);
        meta.origin.root = root;
        meta.origin.state_root = block.message.state_root;
        meta.blocks.frontier.oldest_block_root = root;
        meta.blocks.frontier.oldest_block_parent = block.message.parent_root;
        db.block_provider().insert(root, block).unwrap();
        db.state_provider().insert(root, state.clone()).unwrap();
        db.slot_index_provider().insert(state.slot, root).unwrap();
        db.genesis_time_provider().insert(0).unwrap();
        db.time_provider()
            .insert(state.slot * beacon_network_spec().seconds_per_slot())
            .unwrap();
        db.finish_bootstrap(state.genesis_validators_root, Some(&meta))
            .unwrap();
        let enr = discv5::Enr::builder()
            .build(&enr::CombinedKey::generate_secp256k1())
            .unwrap();
        let network = Arc::new(NetworkState {
            local_enr: enr.into(),
            peer_table: Default::default(),
            meta_data: Default::default(),
            status: Default::default(),
            data_dir: dir.path().to_path_buf(),
        });
        (dir, db, root, network)
    }

    async fn serve(
        db: &BeaconDB,
        network: Arc<NetworkState>,
        request: BeaconRequestMessage,
    ) -> Vec<RespMessage> {
        let (sender, mut receiver) = mpsc::unbounded_channel();
        handle_req_resp_message(
            PeerId::random(),
            7,
            ConnectionId::new_unchecked(1),
            request,
            &P2PSender(sender),
            db,
            network,
        )
        .await;
        let mut responses = Vec::new();
        while let Ok(message) = receiver.try_recv() {
            let P2PMessage::Response(response) = message else {
                panic!("expected response")
            };
            assert_eq!(response.stream_id, 7);
            responses.push(*response.message);
        }
        responses
    }

    #[tokio::test]
    async fn range_handlers_report_missing_history_and_allow_covered_ranges() {
        let (_dir, db, root, network) = serving_db();
        let slot = db.block_provider().get(root).unwrap().unwrap().message.slot;
        for request in [
            BeaconRequestMessage::BeaconBlocksByRange(BeaconBlocksByRangeV2Request::new(
                slot - 1,
                2,
            )),
            BeaconRequestMessage::DataColumnSidecarsByRange(DataColumnSidecarsByRangeV1Request {
                start_slot: slot - 1,
                count: 2,
                columns: vec![0].try_into().unwrap(),
            }),
        ] {
            let responses = serve(&db, network.clone(), request).await;
            assert_eq!(responses.len(), 1);
            assert!(matches!(&responses[0], RespMessage::Error(_)));
            assert_eq!(
                responses[0].as_response_code(),
                Some(ResponseCode::ResourceUnavailable)
            );
        }
        let responses = serve(
            &db,
            network,
            BeaconRequestMessage::BeaconBlocksByRange(BeaconBlocksByRangeV2Request::new(slot, 1)),
        )
        .await;
        assert!(matches!(
            responses.as_slice(),
            [RespMessage::Response(_), RespMessage::EndOfStream]
        ));
    }

    #[tokio::test]
    async fn blocks_by_root_skips_unknown_roots_and_continues_to_known_blocks() {
        let (_dir, db, root, network) = serving_db();
        let responses = serve(
            &db,
            network,
            BeaconRequestMessage::BeaconBlocksByRoot(BeaconBlocksByRootV2Request::new(vec![
                B256::ZERO,
                root,
                B256::repeat_byte(9),
            ])),
        )
        .await;
        assert_eq!(responses.len(), 2);
        let RespMessage::Response(response) = &responses[0] else {
            panic!("expected known block")
        };
        let ResponseMessage::Beacon(response) = response.as_ref() else {
            panic!("expected beacon response")
        };
        let BeaconResponseMessage::BeaconBlocksByRoot(block) = response.as_ref() else {
            panic!("expected block by root")
        };
        assert_eq!(block.message.tree_hash_root(), root);
        assert!(matches!(responses[1], RespMessage::EndOfStream));
    }

    /// Origin at slot 640, blocks backfilled down to `block_frontier`.
    fn checkpoint(block_frontier: u64, sidecar_frontier: Option<u64>) -> BackfillMode {
        BackfillMode::Checkpoint(BackfillMeta {
            revision: 0,
            origin: Origin {
                slot: 640,
                root: B256::repeat_byte(1),
                state_root: B256::repeat_byte(2),
            },
            blocks: BlockCoverage {
                frontier: Frontier {
                    oldest_block_slot: block_frontier,
                    oldest_block_root: B256::repeat_byte(3),
                    oldest_block_parent: B256::repeat_byte(4),
                },
                state: BlockBackfillState::InProgress,
            },
            sidecars: SidecarCoverage {
                frontier: sidecar_frontier,
            },
        })
    }

    #[test]
    fn block_ranges_below_the_frontier_inside_retention_are_unavailable() {
        let mode = checkpoint(400, Some(640));
        let retention_start = 200;

        // Entirely backfilled or live.
        assert!(!requests_missing_blocks(&mode, 400, 432, retention_start));
        assert!(!requests_missing_blocks(&mode, 640, 672, retention_start));
        // Touches a slot below the frontier that we are required to serve.
        assert!(requests_missing_blocks(&mode, 399, 431, retention_start));
        assert!(requests_missing_blocks(&mode, 200, 232, retention_start));
        assert!(requests_missing_blocks(&mode, 190, 201, retention_start));
        // Entirely older than the retention window: answering with what we hold is allowed.
        assert!(!requests_missing_blocks(&mode, 100, 200, retention_start));
        // Backfill reached the retention target.
        assert!(!requests_missing_blocks(
            &checkpoint(200, Some(640)),
            200,
            232,
            retention_start
        ));
        assert!(!requests_missing_blocks(&mode, 500, 500, retention_start));
    }

    #[test]
    fn data_column_ranges_without_confirmed_coverage_are_unavailable() {
        let retention_start = 320;

        // Blocks are backfilled to 400 but sidecars only cover the origin.
        let mode = checkpoint(400, Some(640));
        assert!(requests_missing_data_columns(
            &mode,
            608,
            640,
            retention_start
        ));
        assert!(requests_missing_data_columns(
            &mode,
            300,
            330,
            retention_start
        ));
        assert!(!requests_missing_data_columns(
            &mode,
            640,
            672,
            retention_start
        ));
        // Older than the retention window.
        assert!(!requests_missing_data_columns(
            &mode,
            200,
            320,
            retention_start
        ));

        // The anchor itself is still being recovered.
        let pending = checkpoint(640, None);
        assert!(requests_missing_data_columns(
            &pending,
            640,
            641,
            retention_start
        ));
        assert!(!requests_missing_data_columns(
            &pending,
            641,
            672,
            retention_start
        ));

        // The origin has left the retention window, or Fulu is not active.
        assert!(!requests_missing_data_columns(&pending, 600, 672, 641));
        assert!(!requests_missing_data_columns(&pending, 600, 672, u64::MAX));
    }

    #[test]
    fn databases_without_backfill_metadata_keep_answering_with_what_they_hold() {
        for mode in [BackfillMode::GenesisSynced, BackfillMode::Legacy] {
            assert!(!requests_missing_blocks(&mode, 0, 64, 0));
            assert!(!requests_missing_data_columns(&mode, 0, 64, 0));
        }
    }
}
