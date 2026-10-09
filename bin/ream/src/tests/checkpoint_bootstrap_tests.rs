use libp2p::{PeerId, swarm::ConnectionId};
use ream_bls::traits::{Signable, Verifiable};
use ream_consensus_misc::{constants::beacon::DOMAIN_BEACON_PROPOSER, misc::compute_signing_root};
use ream_network_manager::{p2p_sender::P2PSender, req_resp::handle_req_resp_message};
use ream_p2p::network::beacon::{channel::P2PMessage, network_state::NetworkState};
use ream_req_resp::{
    beacon::messages::{
        BeaconRequestMessage, BeaconResponseMessage, blocks::BeaconBlocksByRootV2Request,
    },
    handler::RespMessage,
    messages::ResponseMessage,
};
use ream_storage::tables::beacon::backfill::BackfillMode;
use ssz::Encode;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::mpsc,
};

use super::*;

#[tokio::test]
async fn checkpoint_bootstrap_preserves_anchor_signature() {
    initialize_beacon_e2e_network_spec(beacon_e2e_dev_spec());
    let (mut state, mut anchor) = build_dev_genesis(&beacon_e2e_public_keys());
    state.slot = SLOTS_PER_EPOCH;
    anchor.message.slot = state.slot;
    anchor.message.state_root = state.tree_hash_root();
    let signing_root = compute_signing_root(
        &anchor.message,
        state.get_domain(DOMAIN_BEACON_PROPOSER, Some(state.get_current_epoch())),
    );
    let proposer = &state.validators[anchor.message.proposer_index as usize].public_key;
    anchor.signature = PrivateKey {
        inner: indexed_private_key(anchor.message.proposer_index as usize),
    }
    .sign(signing_root.as_slice())
    .unwrap();
    assert_ne!(anchor.signature, BLSSignature::default());

    let anchor_root = anchor.message.tree_hash_root();
    // Serve the signed anchor and state. No DA request is needed without commitments.
    let responses = [
        (
            "/eth/v2/beacon/blocks/finalized".to_owned(),
            anchor.as_ssz_bytes(),
        ),
        (
            format!("/eth/v2/debug/beacon/states/{}", state.slot),
            state.as_ssz_bytes(),
        ),
    ];
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let server = tokio::spawn(async move {
        for (path, body) in responses {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let byte = socket.read_u8().await.unwrap();
                request.push(byte);
                assert!(request.len() < 16 * 1024);
            }
            assert!(
                String::from_utf8(request)
                    .unwrap()
                    .starts_with(&format!("GET {path} HTTP/1.1\r\n"))
            );
            socket
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            socket.write_all(&body).await.unwrap();
        }
    });

    let db = create_beacon_test_node_db("checkpoint_anchor_signature", 1);
    let beacon_db = db.init_beacon_db().unwrap();
    timeout(
        Duration::from_secs(30),
        crate::initialize_db_from_checkpoint(beacon_db.clone(), Some(url), None),
    )
    .await
    .unwrap()
    .unwrap();
    server.await.unwrap();

    // Reopen the database to verify that the signature is persisted.
    let data_dir = beacon_db.data_dir.clone();
    drop(beacon_db);
    drop(db);
    let db = ReamDB::new(data_dir.clone()).unwrap();
    let beacon_db = db.init_beacon_db().unwrap();
    let stored = beacon_db
        .block_provider()
        .get(anchor_root)
        .unwrap()
        .unwrap();
    assert_eq!(stored, anchor);
    assert_eq!(
        beacon_db.genesis_validators_root().unwrap(),
        Some(state.genesis_validators_root)
    );
    let BackfillMode::Checkpoint(meta) = beacon_db.backfill_mode().unwrap() else {
        panic!("expected checkpoint metadata");
    };
    assert_eq!(meta.origin.root, anchor_root);
    assert_eq!(meta.origin.state_root, state.tree_hash_root());
    assert_eq!(meta.blocks.frontier.oldest_block_root, anchor_root);
    assert_eq!(meta.sidecars.frontier, Some(state.slot));
    assert!(!beacon_db.bootstrap_in_progress().unwrap());
    assert!(
        stored
            .signature
            .verify(proposer, signing_root.as_slice())
            .unwrap()
    );
    assert_eq!(
        beacon_db
            .finalized_checkpoint_provider()
            .get()
            .unwrap()
            .root,
        anchor_root
    );
    assert_eq!(
        beacon_db.state_provider().get(anchor_root).unwrap(),
        Some(state)
    );

    let enr = discv5::Enr::builder()
        .build(&discv5::enr::CombinedKey::generate_secp256k1())
        .unwrap();
    let network_state = Arc::new(NetworkState {
        local_enr: enr.into(),
        peer_table: Default::default(),
        meta_data: Default::default(),
        status: Default::default(),
        data_dir,
    });
    let (sender, mut receiver) = mpsc::unbounded_channel();
    handle_req_resp_message(
        PeerId::random(),
        0,
        ConnectionId::new_unchecked(0),
        BeaconRequestMessage::BeaconBlocksByRoot(BeaconBlocksByRootV2Request::new(vec![
            anchor_root,
        ])),
        &P2PSender(sender),
        &beacon_db,
        network_state,
    )
    .await;
    let P2PMessage::Response(response) = receiver.try_recv().unwrap() else {
        panic!("expected a blocks-by-root response");
    };
    let RespMessage::Response(message) = *response.message else {
        panic!("expected a block response, not an error or end of stream");
    };
    let ResponseMessage::Beacon(message) = *message else {
        panic!("expected a beacon response");
    };
    let BeaconResponseMessage::BeaconBlocksByRoot(served) = message.as_ref() else {
        panic!("expected a signed beacon block");
    };
    assert_eq!(served, &anchor);
    let P2PMessage::Response(response) = receiver.try_recv().unwrap() else {
        panic!("expected an end-of-stream response");
    };
    assert!(matches!(*response.message, RespMessage::EndOfStream));
}

#[test]
fn genesis_bootstrap_keeps_unsigned_anchor() {
    initialize_beacon_e2e_network_spec(beacon_e2e_dev_spec());
    let (state, _) = build_dev_genesis(&beacon_e2e_public_keys());
    let db = create_beacon_test_node_db("genesis_anchor_signature", 1);
    let beacon_db = db.init_beacon_db().unwrap();
    let state_path = temp_dir().join(format!(
        "ream_genesis_anchor_{}.ssz",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::write(&state_path, state.as_ssz_bytes()).unwrap();
    let result = crate::initialize_db_from_genesis_state(beacon_db.clone(), &state_path);
    fs::remove_file(state_path).unwrap();
    result.unwrap();
    assert_eq!(
        beacon_db.backfill_mode().unwrap(),
        BackfillMode::GenesisSynced
    );
    assert_eq!(
        beacon_db.genesis_validators_root().unwrap(),
        Some(state.genesis_validators_root)
    );

    let expected = SignedBeaconBlock {
        message: BeaconBlock {
            slot: state.slot,
            state_root: state.tree_hash_root(),
            ..Default::default()
        },
        signature: BLSSignature::default(),
    };
    let root = expected.message.tree_hash_root();
    assert_eq!(
        beacon_db.block_provider().get(root).unwrap(),
        Some(expected)
    );
    assert_eq!(
        beacon_db
            .finalized_checkpoint_provider()
            .get()
            .unwrap()
            .root,
        root
    );
    assert_eq!(beacon_db.state_provider().get(root).unwrap(), Some(state));
}

#[test]
fn interrupted_bootstrap_retries_instead_of_becoming_legacy() {
    initialize_beacon_e2e_network_spec(beacon_e2e_dev_spec());
    let (state, mut block) = build_dev_genesis(&beacon_e2e_public_keys());
    let db = create_beacon_test_node_db("interrupted_bootstrap", 1);
    let beacon_db = db.init_beacon_db().unwrap();
    let path = beacon_db.data_dir.join("genesis.ssz");
    fs::write(&path, state.as_ssz_bytes()).unwrap();
    beacon_db.begin_bootstrap().unwrap();
    block.message.slot = 64;
    let partial_root = block.message.tree_hash_root();
    beacon_db
        .block_provider()
        .insert(partial_root, block)
        .unwrap();
    assert!(!beacon_db.is_initialized());
    assert!(beacon_db.backfill_mode().is_err());
    let data_dir = beacon_db.data_dir.clone();
    drop(beacon_db);
    drop(db);
    let db = ReamDB::new(data_dir).unwrap();
    let beacon_db = db.init_beacon_db().unwrap();
    crate::initialize_db_from_genesis_state(beacon_db.clone(), &path).unwrap();
    assert_eq!(
        beacon_db.backfill_mode().unwrap(),
        BackfillMode::GenesisSynced
    );
    assert!(beacon_db.is_initialized());
    assert!(
        beacon_db
            .block_provider()
            .get(partial_root)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        beacon_db.genesis_validators_root().unwrap(),
        Some(state.genesis_validators_root)
    );
    fs::remove_file(&path).unwrap();
    // A completed slot-zero genesis must not attempt to bootstrap again.
    crate::initialize_db_from_genesis_state(beacon_db, &path).unwrap();
}

#[test]
fn legacy_bootstrap_preserves_data_and_reads_canonical_head_gvr() {
    initialize_beacon_e2e_network_spec(beacon_e2e_dev_spec());
    let (state, block) = build_dev_genesis(&beacon_e2e_public_keys());
    let db = create_beacon_test_node_db("legacy_bootstrap", 1);
    let beacon_db = db.init_beacon_db().unwrap();
    get_forkchoice_store(state.clone(), block.clone(), beacon_db.clone()).unwrap();
    assert_eq!(beacon_db.backfill_mode().unwrap(), BackfillMode::Legacy);
    assert!(!beacon_db.recover_interrupted_bootstrap().unwrap());
    assert!(beacon_db.begin_bootstrap().is_err());
    // An unrelated higher-slot block has no state. Highest slot is not canonical head.
    let mut unrelated = block.clone();
    unrelated.message.slot = 96;
    beacon_db
        .block_provider()
        .insert(unrelated.message.tree_hash_root(), unrelated)
        .unwrap();
    assert_eq!(
        ream_checkpoint_sync_beacon::load_genesis_validators_root(&beacon_db).unwrap(),
        state.genesis_validators_root
    );
    assert_eq!(
        beacon_db
            .block_provider()
            .get(block.message.tree_hash_root())
            .unwrap(),
        Some(block.clone())
    );
    let data_dir = beacon_db.data_dir.clone();
    drop(beacon_db);
    drop(db);
    let db = ReamDB::new(data_dir).unwrap();
    let beacon_db = db.init_beacon_db().unwrap();
    assert_eq!(beacon_db.backfill_mode().unwrap(), BackfillMode::Legacy);
    assert_eq!(
        beacon_db.genesis_validators_root().unwrap(),
        Some(state.genesis_validators_root)
    );
    // The persisted identity must work even when fork choice cannot load its state.
    assert!(
        beacon_db
            .state_provider()
            .remove(block.message.tree_hash_root())
            .unwrap()
            .is_some()
    );
    assert_eq!(
        ream_checkpoint_sync_beacon::load_genesis_validators_root(&beacon_db).unwrap(),
        state.genesis_validators_root
    );
}

// Network configuration is a process-wide OnceLock. Run this scenario in a child test
// process so activating Fulu cannot change the pre-Fulu fixtures used by other tests.
#[test]
fn checkpoint_bootstrap_post_fulu_allows_pending_anchor_columns() {
    const CHILD: &str = "REAM_POST_FULU_BOOTSTRAP_TEST";
    if std::env::var_os(CHILD).is_none() {
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "tests::checkpoint_bootstrap_tests::checkpoint_bootstrap_post_fulu_allows_pending_anchor_columns", "--nocapture"])
            .env(CHILD, "1")
            .status().unwrap();
        assert!(status.success());
        return;
    }
    let mut spec = (*beacon_e2e_dev_spec()).clone();
    spec.fulu_fork_epoch = 0;
    initialize_beacon_e2e_network_spec(Arc::new(spec));
    let (mut state, mut anchor) = build_dev_genesis(&beacon_e2e_public_keys());
    state.slot = SLOTS_PER_EPOCH;
    anchor.message.slot = state.slot;
    anchor.message.state_root = state.tree_hash_root();
    let blob = ream_mock_execution_engine::block_generator::sample_blob_and_commitment(1).unwrap();
    // The helper returns the same Blob type used by the Beacon API.
    anchor
        .message
        .body
        .blob_kzg_commitments
        .push(blob.1)
        .unwrap();
    let root = anchor.message.tree_hash_root();
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        // Missing HTTP blobs must not prevent checkpoint startup.
        for available in [false, true] {
            let db = create_beacon_test_node_db(if available { "anchor_available" } else { "anchor_pending" }, 1);
            let beacon_db = db.init_beacon_db().unwrap();
            let responses = vec![
                ("/eth/v2/beacon/blocks/finalized".to_string(), 200, anchor.as_ssz_bytes()),
                (format!("/eth/v2/debug/beacon/states/{}", state.slot), 200, state.as_ssz_bytes()),
                (format!("/eth/v1/beacon/blobs/{root}"), if available { 200 } else { 404 }, if available { serde_json::to_vec(&serde_json::json!({"data": [&blob.0]})).unwrap() } else { b"unavailable".to_vec() }),
            ];
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}/", listener.local_addr().unwrap()).parse().unwrap();
            let server = tokio::spawn(async move {
                for (path, status, body) in responses {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let mut request = Vec::new();
                    while !request.ends_with(b"\r\n\r\n") { request.push(socket.read_u8().await.unwrap()); }
                    assert!(String::from_utf8(request).unwrap().starts_with(&format!("GET {path} HTTP/1.1")));
                    socket.write_all(format!("HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes()).await.unwrap();
                    socket.write_all(&body).await.unwrap();
                }
            });
            let result = timeout(Duration::from_secs(60), crate::initialize_db_from_checkpoint(beacon_db.clone(), Some(url), None)).await.unwrap();
            server.await.unwrap();
            result.unwrap();
            assert!(beacon_db.is_initialized());
            let path = beacon_db.data_dir.clone();
            drop(beacon_db);
            drop(db);
            let db = ReamDB::new(path).unwrap();
            let beacon_db = db.init_beacon_db().unwrap();
            let BackfillMode::Checkpoint(meta) = beacon_db.backfill_mode().unwrap() else { panic!("missing checkpoint metadata"); };
            assert_eq!(meta.sidecars.frontier, available.then_some(anchor.message.slot));
            assert_eq!(beacon_db.pending_anchor_root().unwrap(), (!available).then_some(root));
            for index in 0..128 {
                let column = beacon_db.column_sidecars_provider().get(ColumnIdentifier::new(root, index)).unwrap();
                assert_eq!(column.is_some(), available);
                if let Some(column) = column { assert_eq!(column.signed_block_header, anchor.signed_header()); assert!(column.verify_inclusion_proof()); }
            }
        }
    });
}

#[tokio::test]
async fn initialized_database_without_ws_does_not_require_fork_choice_state() {
    initialize_beacon_e2e_network_spec(beacon_e2e_dev_spec());
    let (state, block) = build_dev_genesis(&beacon_e2e_public_keys());
    let db = create_beacon_test_node_db("restart_without_ws", 1);
    let beacon_db = db.init_beacon_db().unwrap();
    let root = block.message.tree_hash_root();
    get_forkchoice_store(state, block, beacon_db.clone()).unwrap();
    // A missing state would make canonical_head_state fail. Without WS there is no
    // reason to query it here; Legacy GVR recovery is a separate startup operation.
    beacon_db.state_provider().remove(root).unwrap();
    assert!(ream_checkpoint_sync_beacon::canonical_head_state(&beacon_db).is_err());
    assert!(
        crate::initialize_db_from_checkpoint(beacon_db, None, None)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn pending_anchor_recovers_from_partial_peer_responses_after_restart() {
    use ream_chain_beacon::beacon_chain::BeaconChain;
    use ream_consensus_beacon::{
        data_column_sidecar::get_data_column_sidecars_from_block,
        matrix_entry::{compute_cells_and_kzg_proofs, das_context},
    };
    use ream_network_manager::data_availability_fetch::{
        ColumnFetchOutcome, fetch_missing_columns,
    };
    use ream_p2p::network::beacon::channel::{P2PCallbackResponse, P2PRequest};
    use ream_storage::tables::beacon::backfill::{
        BackfillMeta, BlockBackfillState, BlockCoverage, Frontier, Origin, SidecarCoverage,
    };

    initialize_beacon_e2e_network_spec(beacon_e2e_dev_spec());
    let (mut state, mut anchor) = build_dev_genesis(&beacon_e2e_public_keys());
    initialize_beacon_e2e_genesis_root(state.genesis_validators_root);
    state.slot = SLOTS_PER_EPOCH;
    anchor.message.slot = state.slot;
    anchor.message.state_root = state.tree_hash_root();
    let (blob, commitment) =
        ream_mock_execution_engine::block_generator::sample_blob_and_commitment(9).unwrap();
    anchor
        .message
        .body
        .blob_kzg_commitments
        .push(commitment)
        .unwrap();
    let root = anchor.message.tree_hash_root();
    let columns = get_data_column_sidecars_from_block(
        &anchor,
        vec![compute_cells_and_kzg_proofs(&blob, das_context()).unwrap()],
    )
    .unwrap();
    let db = create_beacon_test_node_db("pending_anchor_peer", 1);
    let beacon_db = db.init_beacon_db().unwrap();
    beacon_db.begin_bootstrap().unwrap();
    get_forkchoice_store(state.clone(), anchor.clone(), beacon_db.clone()).unwrap();
    beacon_db
        .finish_bootstrap(
            state.genesis_validators_root,
            Some(&BackfillMeta {
                revision: 0,
                origin: Origin {
                    slot: state.slot,
                    root,
                    state_root: anchor.message.state_root,
                },
                blocks: BlockCoverage {
                    frontier: Frontier {
                        oldest_block_slot: state.slot,
                        oldest_block_root: root,
                        oldest_block_parent: anchor.message.parent_root,
                    },
                    state: BlockBackfillState::InProgress,
                },
                sidecars: SidecarCoverage { frontier: None },
            }),
        )
        .unwrap();
    let path = beacon_db.data_dir.clone();
    drop(beacon_db);
    drop(db);
    let db = ReamDB::new(path).unwrap();
    let beacon_db = db.init_beacon_db().unwrap();
    let other_handle = db.init_beacon_db().unwrap();
    assert_eq!(other_handle.pending_anchor_root().unwrap(), Some(root));
    fs::write(
        beacon_db
            .data_dir
            .join(format!("beacon_columns/{root}_0.ssz_snappy")),
        b"truncated old file",
    )
    .unwrap();
    let chain = Arc::new(BeaconChain::new(
        beacon_db.clone(),
        Default::default(),
        Default::default(),
        None,
        None,
    ));
    assert_eq!(
        chain
            .build_status_request()
            .await
            .unwrap()
            .earliest_available_slot,
        state.slot + 1
    );
    let (sender, mut receiver) = mpsc::unbounded_channel();
    let sender = P2PSender(sender);
    let mut invalid = columns[0].clone();
    invalid.signed_block_header.message.slot += 1;
    for (response_columns, expected) in [
        (vec![invalid], ColumnFetchOutcome::Retryable),
        (columns[..64].to_vec(), ColumnFetchOutcome::Incomplete),
        (columns[64..].to_vec(), ColumnFetchOutcome::Complete),
    ] {
        let chain = chain.clone();
        let sender = sender.clone();
        let fetch = tokio::spawn(async move {
            fetch_missing_columns(&chain, &sender, root, PeerId::random()).await
        });
        let P2PMessage::Request(P2PRequest::DataColumnIdentifiers {
            callback,
            column_identifiers,
            ..
        }) = timeout(Duration::from_secs(10), receiver.recv())
            .await
            .unwrap()
            .unwrap()
        else {
            panic!("expected anchor request");
        };
        assert_eq!(column_identifiers.len(), 1);
        for column in response_columns {
            callback
                .send(Ok(P2PCallbackResponse::ResponseMessage(Arc::new(
                    BeaconResponseMessage::DataColumnSidecarsByRoot(column),
                ))))
                .await
                .unwrap();
        }
        callback
            .send(Ok(P2PCallbackResponse::EndOfStream))
            .await
            .unwrap();
        assert_eq!(
            timeout(Duration::from_secs(30), fetch)
                .await
                .unwrap()
                .unwrap(),
            expected
        );
        assert_eq!(
            beacon_db.pending_anchor_root().unwrap(),
            if expected == ColumnFetchOutcome::Complete {
                None
            } else {
                Some(root)
            }
        );
    }
    assert_eq!(
        chain
            .build_status_request()
            .await
            .unwrap()
            .earliest_available_slot,
        state.slot
    );
    let BackfillMode::Checkpoint(meta) = beacon_db.backfill_mode().unwrap() else {
        panic!("missing metadata");
    };
    assert_eq!(meta.revision, 1);
    assert_eq!(other_handle.pending_anchor_root().unwrap(), None);
}

#[tokio::test]
async fn parked_anchor_expires_using_actual_genesis_without_peer_changes() {
    use std::time::Instant;

    use ream_chain_beacon::beacon_chain::BeaconChain;
    use ream_network_manager::data_availability_fetch::{
        ColumnFetchOutcome, ColumnFetchTracker, NO_COLUMN_PEER_TIMEOUT, pending_anchor_for_recovery,
    };
    use ream_storage::tables::beacon::backfill::{
        BackfillMeta, BlockBackfillState, BlockCoverage, Frontier, Origin, SidecarCoverage,
    };

    initialize_beacon_e2e_network_spec(beacon_e2e_dev_spec());
    let spec = ream_network_spec::networks::beacon_network_spec();
    let (mut state, mut anchor) = build_dev_genesis(&beacon_e2e_public_keys());
    state.genesis_time = spec.min_genesis_time + 2 * SLOTS_PER_EPOCH * spec.seconds_per_slot();
    state.slot = SLOTS_PER_EPOCH;
    anchor.message.slot = state.slot;
    anchor.message.state_root = state.tree_hash_root();
    anchor
        .message
        .body
        .blob_kzg_commitments
        .push(
            ream_mock_execution_engine::block_generator::sample_blob_and_commitment(9)
                .unwrap()
                .1,
        )
        .unwrap();
    let root = anchor.message.tree_hash_root();
    let db = create_beacon_test_node_db("parked_anchor_expiry", 1);
    let beacon_db = db.init_beacon_db().unwrap();
    beacon_db.begin_bootstrap().unwrap();
    get_forkchoice_store(state.clone(), anchor.clone(), beacon_db.clone()).unwrap();
    beacon_db
        .finish_bootstrap(
            state.genesis_validators_root,
            Some(&BackfillMeta {
                revision: 0,
                origin: Origin {
                    slot: state.slot,
                    root,
                    state_root: anchor.message.state_root,
                },
                blocks: BlockCoverage {
                    frontier: Frontier {
                        oldest_block_slot: state.slot,
                        oldest_block_root: root,
                        oldest_block_parent: anchor.message.parent_root,
                    },
                    state: BlockBackfillState::InProgress,
                },
                sidecars: SidecarCoverage { frontier: None },
            }),
        )
        .unwrap();

    let chain = BeaconChain::new(
        beacon_db.clone(),
        Default::default(),
        Default::default(),
        None,
        None,
    );
    let mut tracker = ColumnFetchTracker::default();
    let peer = PeerId::random();
    let now = Instant::now();
    tracker.enqueue(root);
    assert_eq!(tracker.next_fetch(&[peer], now), Some((root, peer)));
    tracker.finish(root, peer, ColumnFetchOutcome::Incomplete, now);
    assert_eq!(
        tracker.next_fetch(&[peer], now + NO_COLUMN_PEER_TIMEOUT),
        None
    );
    assert!(!tracker.enqueue(root));

    // Exactly at the retention boundary: still required. Using min_genesis_time
    // would put the chain two epochs ahead and incorrectly finish recovery.
    let boundary_slot = (1 + spec.min_epochs_for_data_column_sidecars_requests) * SLOTS_PER_EPOCH;
    for (slot, expected) in [
        (boundary_slot, Some(root)),
        (boundary_slot + SLOTS_PER_EPOCH, None),
    ] {
        beacon_db
            .time_provider()
            .insert(state.genesis_time + slot * spec.seconds_per_slot())
            .unwrap();
        let current_slot = chain.store.lock().await.get_current_slot().unwrap();
        assert_eq!(current_slot, slot);
        let pending = pending_anchor_for_recovery(&chain, current_slot)
            .await
            .unwrap();
        assert_eq!(pending, expected);
        assert_eq!(beacon_db.pending_anchor_root().unwrap(), expected);
        tracker.retain_pending(&pending.into_iter().collect::<Vec<_>>());
    }
    assert_eq!(tracker.tracked_count(), 0);
}
