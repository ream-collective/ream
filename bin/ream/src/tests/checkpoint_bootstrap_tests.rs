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
    // Serve the three requests made by pre-Fulu checkpoint bootstrap, using SSZ
    // for the signed block/state and an empty blob-sidecar response.
    let responses = [
        (
            "/eth/v2/beacon/blocks/finalized".to_owned(),
            anchor.as_ssz_bytes(),
        ),
        (
            format!("/eth/v1/beacon/blob_sidecars/{anchor_root}"),
            br#"{"data":[]}"#.to_vec(),
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
