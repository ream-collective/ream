use std::{
    collections::HashMap,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::sleep,
};

use libp2p::PeerId;
use ream_bls::traits::Signable;
use ream_consensus_misc::{
    constants::beacon::DOMAIN_BEACON_PROPOSER,
    misc::{compute_domain, compute_epoch_at_slot, compute_signing_root},
};
use ream_p2p::network::beacon::{
    channel::{P2PCallbackResponse, P2PMessage, P2PRequest},
    network_state::NetworkState,
};
use ream_peer::{ConnectionState, Direction};
use ream_req_resp::beacon::messages::{BeaconResponseMessage, status::Status};
use ream_storage::{
    db::beacon::BeaconDB,
    tables::beacon::backfill::{
        BackfillMeta, BackfillMode, BlockBackfillState, BlockCoverage, Frontier, Origin,
        SidecarCoverage,
    },
};
use ream_syncer::backfill::BackfillSyncer;
use tokio::sync::mpsc;

use super::*;

fn backfill_meta(db: &BeaconDB) -> BackfillMeta {
    match db.backfill_mode().expect("readable backfill metadata") {
        BackfillMode::Checkpoint(meta) => meta,
        mode => panic!("unexpected backfill mode {mode:?}"),
    }
}

/// A checkpoint node whose only block is the anchor downloads every block below it from its
/// peers, verifies the proposer signatures and commits them down to genesis, without touching
/// fork choice.
#[test]
fn backfill_commits_verified_history_down_to_genesis_only_while_running() {
    initialize_beacon_e2e_network_spec(beacon_e2e_dev_spec());
    let (genesis_state, genesis_block) = build_dev_genesis(&beacon_e2e_public_keys());
    initialize_beacon_e2e_genesis_root(genesis_state.genesis_validators_root);

    // A signed hash chain from genesis to the anchor, with skipped slots, including a whole
    // epoch and the slot directly below the anchor.
    let anchor_slot = 4 * SLOTS_PER_EPOCH + 5;
    let mut anchor_state = genesis_state.clone();
    anchor_state.slot = anchor_slot;
    let mut blocks = vec![genesis_block.clone()];
    let mut parent_root = genesis_block.message.tree_hash_root();
    for slot in 1..=anchor_slot {
        let skipped = slot % 7 == 3
            || (2 * SLOTS_PER_EPOCH..3 * SLOTS_PER_EPOCH).contains(&slot)
            || slot == anchor_slot - 1;
        if skipped {
            continue;
        }
        let mut block = genesis_block.clone();
        block.message.slot = slot;
        block.message.proposer_index = slot % BEACON_E2E_VALIDATOR_COUNT as u64;
        block.message.parent_root = parent_root;
        if slot == anchor_slot {
            block.message.state_root = anchor_state.tree_hash_root();
        }
        let domain = compute_domain(
            DOMAIN_BEACON_PROPOSER,
            Some(beacon_e2e_dev_spec().current_fork_version(compute_epoch_at_slot(slot))),
            Some(genesis_state.genesis_validators_root),
        );
        parent_root = block.message.tree_hash_root();
        block.signature = PrivateKey {
            inner: indexed_private_key(block.message.proposer_index as usize),
        }
        .sign(compute_signing_root(parent_root, domain).as_slice())
        .expect("signing succeeds");
        blocks.push(block);
    }
    let anchor = blocks.last().expect("anchor").clone();
    let anchor_root = anchor.message.tree_hash_root();

    let db = create_beacon_test_node_db("backfill_blocks", 1);
    let beacon_db = db.init_beacon_db().expect("beacon database");
    beacon_db.begin_bootstrap().expect("fresh database");
    get_forkchoice_store(anchor_state.clone(), anchor.clone(), beacon_db.clone())
        .expect("fork choice store");
    beacon_db
        .finish_bootstrap(
            genesis_state.genesis_validators_root,
            Some(&BackfillMeta {
                revision: 0,
                origin: Origin {
                    slot: anchor_slot,
                    root: anchor_root,
                    state_root: anchor.message.state_root,
                },
                blocks: BlockCoverage {
                    frontier: Frontier {
                        oldest_block_slot: anchor_slot,
                        oldest_block_root: anchor_root,
                        oldest_block_parent: anchor.message.parent_root,
                    },
                    state: BlockBackfillState::InProgress,
                },
                sidecars: SidecarCoverage {
                    frontier: Some(anchor_slot),
                },
            }),
        )
        .expect("bootstrap completes");
    let finalized_before = beacon_db
        .finalized_checkpoint_provider()
        .get()
        .expect("finalized checkpoint");
    let highest_slot_before = beacon_db.slot_index_provider().get_highest_slot().unwrap();

    // Two connected peers that advertise full history.
    let enr = discv5::Enr::builder()
        .build(&discv5::enr::CombinedKey::generate_secp256k1())
        .expect("valid enr");
    let network_state = Arc::new(NetworkState {
        local_enr: enr.into(),
        peer_table: Default::default(),
        meta_data: Default::default(),
        status: Default::default(),
        data_dir: beacon_db.data_dir.clone(),
    });
    for _ in 0..2 {
        let peer_id = PeerId::random();
        network_state.upsert_peer(
            peer_id,
            None,
            ConnectionState::Connected,
            Direction::Outbound,
            None,
        );
        network_state
            .peer_table
            .write()
            .get_mut(&peer_id)
            .expect("peer was inserted")
            .status = Some(Status::default());
    }

    // The peers answer range and root requests from the chain built above.
    let executor = ReamExecutor::new().expect("executor should start");
    let (p2p_sender, mut p2p_receiver) = mpsc::unbounded_channel();
    let requested_ranges = Arc::new(Mutex::new(Vec::new()));
    let served = blocks.clone();
    let recorded_ranges = requested_ranges.clone();
    let hold_responses = Arc::new(AtomicBool::new(true));
    let hold = hold_responses.clone();
    let (held_sender, mut held_receiver) = mpsc::unbounded_channel();
    executor.spawn(async move {
        while let Some(message) = p2p_receiver.recv().await {
            let (response, callback) = match message {
                P2PMessage::Request(P2PRequest::BlockRange {
                    start,
                    count,
                    callback,
                    ..
                }) => {
                    recorded_ranges
                        .lock()
                        .expect("lock is not poisoned")
                        .push((start, count));
                    let response = served
                        .iter()
                        .filter(|block| (start..start + count).contains(&block.message.slot))
                        .cloned()
                        .map(BeaconResponseMessage::BeaconBlocksByRange)
                        .collect::<Vec<_>>();
                    (response, callback)
                }
                P2PMessage::Request(P2PRequest::BlockRoots {
                    roots, callback, ..
                }) => {
                    let response = served
                        .iter()
                        .filter(|block| roots.contains(&block.message.tree_hash_root()))
                        .cloned()
                        .map(BeaconResponseMessage::BeaconBlocksByRoot)
                        .collect::<Vec<_>>();
                    (response, callback)
                }
                _ => continue,
            };
            if hold.load(Ordering::SeqCst) {
                held_sender.send(callback).unwrap();
                continue;
            }
            for message in response {
                let _ = callback
                    .send(Ok(P2PCallbackResponse::ResponseMessage(Arc::new(message))))
                    .await;
            }
            let _ = callback.send(Ok(P2PCallbackResponse::EndOfStream)).await;
        }
    });

    let backfill = BackfillSyncer::spawn(
        beacon_db.clone(),
        p2p_sender.clone(),
        network_state.clone(),
        executor.clone(),
    )
    .expect("backfill metadata is readable")
    .expect("a checkpoint database has history to backfill");

    // Nothing is requested or committed until forward sync reports it is idle.
    sleep(Duration::from_millis(500));
    assert!(
        requested_ranges
            .lock()
            .expect("lock is not poisoned")
            .is_empty()
    );
    assert_eq!(
        backfill_meta(&beacon_db).blocks.frontier.oldest_block_slot,
        anchor_slot
    );

    backfill.set_running(true);
    // Pause with a real driver download waiting for a response. Its callback must close;
    // the old response must never be verified or attributed to a peer after resume.
    let pause_deadline = Instant::now() + Duration::from_secs(10);
    let held_callback = loop {
        if let Ok(callback) = held_receiver.try_recv() {
            break callback;
        }
        assert!(
            Instant::now() < pause_deadline,
            "no backfill request started"
        );
        sleep(Duration::from_millis(10));
    };
    backfill.set_running(false);
    while !held_callback.is_closed() {
        assert!(
            Instant::now() < pause_deadline,
            "paused download was not cancelled"
        );
        sleep(Duration::from_millis(10));
    }
    assert_eq!(
        backfill_meta(&beacon_db).blocks.frontier.oldest_block_slot,
        anchor_slot
    );
    assert!(
        held_callback
            .try_send(Ok(P2PCallbackResponse::EndOfStream))
            .is_err()
    );
    hold_responses.store(false, Ordering::SeqCst);
    backfill.set_running(true);
    let deadline = Instant::now() + Duration::from_secs(120);
    while backfill_meta(&beacon_db).blocks.state == BlockBackfillState::InProgress {
        assert!(Instant::now() < deadline, "backfill did not complete");
        sleep(Duration::from_millis(100));
    }

    let meta = backfill_meta(&beacon_db);
    assert_eq!(meta.blocks.state, BlockBackfillState::BlocksComplete);
    assert_eq!(
        meta.blocks.frontier,
        Frontier {
            oldest_block_slot: 0,
            oldest_block_root: genesis_block.message.tree_hash_root(),
            oldest_block_parent: genesis_block.message.parent_root,
        }
    );
    assert_eq!(meta.origin.root, anchor_root);
    assert_eq!(meta.sidecars.frontier, Some(anchor_slot));

    // Every block of the chain is stored and indexed; skipped slots stay empty.
    let by_slot = blocks
        .iter()
        .map(|block| (block.message.slot, block))
        .collect::<HashMap<_, _>>();
    for slot in 0..=anchor_slot {
        let indexed = beacon_db.slot_index_provider().get(slot).unwrap();
        match by_slot.get(&slot) {
            Some(block) => {
                let root = block.message.tree_hash_root();
                assert_eq!(indexed, Some(root), "slot {slot}");
                assert_eq!(
                    beacon_db.block_provider().get(root).unwrap().as_ref(),
                    Some(*block)
                );
                // Historical blocks carry no state; only the anchor has one.
                assert_eq!(
                    beacon_db.state_provider().get(root).unwrap().is_some(),
                    slot == anchor_slot
                );
            }
            None => assert_eq!(indexed, None, "slot {slot}"),
        }
    }

    // Fork choice did not move.
    assert_eq!(
        beacon_db.finalized_checkpoint_provider().get().unwrap(),
        finalized_before
    );
    assert_eq!(
        beacon_db.slot_index_provider().get_highest_slot().unwrap(),
        highest_slot_before
    );

    // No request reached above the anchor.
    assert!(
        requested_ranges
            .lock()
            .expect("lock is not poisoned")
            .iter()
            .all(|(start, count)| start + count <= anchor_slot)
    );

    // A finished backfill is not started again after a restart.
    assert!(
        BackfillSyncer::spawn(beacon_db.clone(), p2p_sender, network_state, executor)
            .expect("backfill metadata is readable")
            .is_none()
    );
}
